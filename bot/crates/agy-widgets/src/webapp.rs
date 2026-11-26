//! Dual In-Telegram Widget Engine: Telegram WebApp HMAC auth, Rich Card renderer, and Axum WebApp router.

use std::collections::{BTreeMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use agy_core::error::{BridgeError, Result};
use agy_core::security::{KeyedTokenBucket, DEFAULT_MAX_BUCKET_KEYS};
use agy_core::tg::{InlineKeyboardButton, InlineKeyboardMarkup};
use agy_render::{esc, md_cell_with_fallback, md_text, PremiumState};
use axum::body::{to_bytes, Body};
use axum::extract::{Path, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use tracing::{error, warn};

use crate::spec::{WIDGET_CACHE_TIME_DEFAULT, WIDGET_QUERY_DATA_LIMIT};
use crate::store::{DataPatch, WebAppWidgetRecord, WidgetStore};

type HmacSha256 = Hmac<Sha256>;

/// Boxed `Send` future alias used by object-safe [`WidgetBridge`] methods.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Dynamic bot token provider callback.
pub type TokenProvider = Arc<dyn Fn() -> String + Send + Sync>;

/// Dynamic allowlisted user-ID set provider callback.
pub type AllowedUidsProvider = Arc<dyn Fn() -> HashSet<i64> + Send + Sync>;

/// Content-Security-Policy header applied to `/w/{wid}` WebApp HTML shell responses.
pub const WEBAPP_CSP_HEADER: &str = "default-src 'self' 'unsafe-inline' data: blob: https://telegram.org; connect-src 'self'; frame-src 'self' blob: data:; frame-ancestors 'self' https://web.telegram.org https://*.telegram.org https://t.me;";

/// Maximum JSON request body size accepted on `/api/w/{wid}/*` endpoints (16 KiB).
pub const WEBAPP_API_MAX_BYTES: usize = 16_384;

/// Default maximum `auth_date` age accepted for Telegram WebApp `initData` (24 hours).
pub const DEFAULT_INIT_DATA_MAX_AGE_SECS: u64 = 86_400;

/// Verified Telegram WebApp `initData` payload returned by [`verify_webapp_init_data`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedInitData {
    pub user: Value,
    pub uid: i64,
    pub auth_date: i64,
    pub query_id: Option<String>,
    pub chat_type: Option<String>,
}

fn current_unix_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// Verify Telegram WebApp `initData` HMAC-SHA256 signature, freshness, duplicate keys, and allowlisted `user.id`.
pub fn verify_webapp_init_data(
    init_data: &str,
    bot_token: &str,
    allowed_uids: &HashSet<i64>,
    max_age_secs: u64,
) -> Result<VerifiedInitData> {
    verify_webapp_init_data_at(
        init_data,
        bot_token,
        allowed_uids,
        max_age_secs,
        current_unix_secs(),
    )
}

/// Deterministic timestamp variant of [`verify_webapp_init_data`] for unit testing.
pub fn verify_webapp_init_data_at(
    init_data: &str,
    bot_token: &str,
    allowed_uids: &HashSet<i64>,
    max_age_secs: u64,
    now_secs: i64,
) -> Result<VerifiedInitData> {
    if init_data.trim().is_empty() {
        return Err(BridgeError::Auth("empty WebApp initData".to_string()));
    }
    if bot_token.is_empty() {
        return Err(BridgeError::Auth("empty bot token".to_string()));
    }

    let mut params: BTreeMap<String, String> = BTreeMap::new();
    for seg in init_data.split('&') {
        if seg.is_empty() {
            continue;
        }
        let Some((k, v)) = url::form_urlencoded::parse(seg.as_bytes()).next() else {
            return Err(BridgeError::Auth("malformed initData query".to_string()));
        };
        if params.insert(k.into_owned(), v.into_owned()).is_some() {
            return Err(BridgeError::Auth(
                "duplicate initData parameter".to_string(),
            ));
        }
    }
    if params.is_empty() {
        return Err(BridgeError::Auth("empty initData parameters".to_string()));
    }

    let received_hash = params
        .get("hash")
        .ok_or_else(|| BridgeError::Auth("missing initData hash".to_string()))?;
    if received_hash.len() != 64 || !received_hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(BridgeError::Auth("malformed initData hash".to_string()));
    }
    let received_bytes = hex::decode(received_hash)
        .map_err(|_| BridgeError::Auth("invalid initData hash hex".to_string()))?;

    let raw_auth_date = params
        .get("auth_date")
        .ok_or_else(|| BridgeError::Auth("missing auth_date".to_string()))?;
    if raw_auth_date.is_empty() || !raw_auth_date.bytes().all(|b| b.is_ascii_digit()) {
        return Err(BridgeError::Auth("invalid auth_date".to_string()));
    }
    let auth_date = raw_auth_date
        .parse::<i64>()
        .map_err(|_| BridgeError::Auth("invalid auth_date range".to_string()))?;
    let max_age_i64 = i64::try_from(max_age_secs).unwrap_or(i64::MAX);
    if auth_date <= 0 || now_secs.saturating_sub(auth_date) > max_age_i64 {
        return Err(BridgeError::Auth(
            "expired or non-positive auth_date".to_string(),
        ));
    }

    let data_check_string = params
        .iter()
        .filter(|(k, _)| k.as_str() != "hash")
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("\n");

    let mut secret_mac = HmacSha256::new_from_slice(b"WebAppData")
        .map_err(|_| BridgeError::Internal("HMAC key init failed".to_string()))?;
    secret_mac.update(bot_token.as_bytes());
    let secret_key = secret_mac.finalize().into_bytes();

    let mut sig_mac = HmacSha256::new_from_slice(&secret_key)
        .map_err(|_| BridgeError::Internal("HMAC secret init failed".to_string()))?;
    sig_mac.update(data_check_string.as_bytes());
    let expected_bytes = sig_mac.finalize().into_bytes();

    if expected_bytes.as_slice().ct_eq(&received_bytes).unwrap_u8() != 1 {
        return Err(BridgeError::Auth(
            "initData signature mismatch".to_string(),
        ));
    }

    let raw_user = params
        .get("user")
        .filter(|s| !s.is_empty())
        .ok_or_else(|| BridgeError::Auth("missing user payload".to_string()))?;
    let user: Value = serde_json::from_str(raw_user)
        .map_err(|_| BridgeError::Auth("malformed user JSON".to_string()))?;
    let user_obj = user
        .as_object()
        .ok_or_else(|| BridgeError::Auth("user payload must be an object".to_string()))?;

    let uid = match user_obj.get("id") {
        Some(Value::Number(n)) => n.as_i64(),
        Some(Value::String(s)) => s.trim().parse::<i64>().ok(),
        _ => None,
    }
    .ok_or_else(|| BridgeError::Auth("invalid numeric user.id".to_string()))?;

    if !allowed_uids.contains(&uid) {
        return Err(BridgeError::PermissionDenied(format!(
            "user {uid} is not allowlisted"
        )));
    }

    Ok(VerifiedInitData {
        user,
        uid,
        auth_date,
        query_id: params.get("query_id").cloned(),
        chat_type: params.get("chat_type").cloned(),
    })
}

// --------------------------------------------------------------------------- In-Bubble Rich Card renderer

fn safe_parse_json(raw: Option<&str>) -> (Option<Value>, Option<String>) {
    let Some(s) = raw else {
        return (None, None);
    };
    if s.is_empty() {
        return (None, None);
    }
    match serde_json::from_str::<Value>(s) {
        Ok(v) => (Some(v), None),
        Err(_) => (None, Some(s.to_string())),
    }
}

fn value_as_nonempty_str(v: Option<&Value>) -> Option<String> {
    match v? {
        Value::Null => None,
        Value::String(s) if s.is_empty() => None,
        Value::String(s) => Some(s.clone()),
        Value::Bool(true) => Some("True".to_string()),
        Value::Bool(false) => Some("False".to_string()),
        other => Some(other.to_string()),
    }
}

fn value_is_truthy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_f64().is_some_and(|x| x != 0.0),
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Object(m)) => !m.is_empty(),
    }
}

fn value_as_i64(v: Option<&Value>) -> Option<i64> {
    match v? {
        Value::Number(n) => n.as_i64().or_else(|| n.as_f64().map(|f| f as i64)),
        Value::String(s) => s.trim().parse::<i64>().ok(),
        _ => None,
    }
}

fn trunc_chars(s: &str, max_chars: usize) -> String {
    s.chars().take(max_chars).collect()
}

fn checked_cb_btn(text: impl Into<String>, data: String) -> Result<InlineKeyboardButton> {
    if data.len() > 64 {
        return Err(BridgeError::Validation(format!(
            "callback_data exceeds 64 UTF-8 bytes ({} bytes): {data:?}",
            data.len()
        )));
    }
    Ok(InlineKeyboardButton::callback(text, data))
}

fn normalize_skills_tab(raw: &str) -> &'static str {
    match raw.trim().to_ascii_lowercase().as_str() {
        "installed" | "inst" => "inst",
        "skillport" | "sp" => "sp",
        "catalog" | "cat" => "cat",
        _ => "inst",
    }
}

fn is_valid_skills_tab_alias(raw: &str) -> bool {
    matches!(
        raw.trim().to_ascii_lowercase().as_str(),
        "installed" | "inst" | "skillport" | "sp" | "catalog" | "cat"
    )
}

/// Render an In-Bubble Rich Markdown Card and `InlineKeyboardMarkup` for a WebApp widget record.
pub fn render_in_bubble_widget(
    rec: &WebAppWidgetRecord,
    webapp_url: Option<&str>,
    tab: Option<&str>,
    premium: &PremiumState,
) -> Result<(String, InlineKeyboardMarkup)> {
    let wid = rec.wid.as_str();
    let handler = rec
        .handler
        .as_deref()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let caption = rec.caption.as_deref().unwrap_or("").trim();

    let (cd_obj, cd_raw) = safe_parse_json(rec.chat_data.as_deref());
    let (pd_obj, pd_raw) = safe_parse_json(rec.public_data.as_deref());

    let mut rows: Vec<Vec<InlineKeyboardButton>> = Vec::new();
    if let Some(u) = webapp_url {
        if u.starts_with("https://") {
            let mut btn = InlineKeyboardButton::web_app_btn("باز کردن ویجت", u).with_style("primary");
            if premium.active() {
                let cid = premium
                    .ids()
                    .get("skills")
                    .map(String::as_str)
                    .unwrap_or("5472164874886846699");
                btn = btn.with_icon(cid);
            }
            rows.push(vec![btn]);
        }
    }

    let empty_map = Map::new();
    let state_obj: &Map<String, Value> = cd_obj
        .as_ref()
        .and_then(Value::as_object)
        .or_else(|| pd_obj.as_ref().and_then(Value::as_object))
        .unwrap_or(&empty_map);

    if handler == "skills" {
        let rec_tab = rec.tab.as_deref().unwrap_or("").trim();
        let raw_tab = if let Some(t) = tab {
            t.to_string()
        } else if is_valid_skills_tab_alias(rec_tab) {
            rec_tab.to_string()
        } else {
            value_as_nonempty_str(state_obj.get("tab")).unwrap_or_else(|| "inst".to_string())
        };
        let cur_tab = normalize_skills_tab(&raw_tab);
        let tab_label = match cur_tab {
            "sp" => "SkillPort",
            "cat" => "Catalog",
            _ => "Installed",
        };

        let items: &[Value] = state_obj
            .get("items")
            .and_then(Value::as_array)
            .or_else(|| {
                if cur_tab == "inst" {
                    state_obj.get("installed").and_then(Value::as_array)
                } else {
                    state_obj.get("results").and_then(Value::as_array)
                }
            })
            .map(Vec::as_slice)
            .unwrap_or(&[]);

        let per = 6usize;
        let pages = items.len().div_ceil(per).max(1);
        let raw_page = value_as_i64(state_obj.get("page")).unwrap_or(0);
        let page = usize::try_from(raw_page.max(0))
            .unwrap_or(0)
            .min(pages - 1);
        let start = page * per;
        let end = (start + per).min(items.len());
        let visible = &items[start..end];

        let title = if caption.is_empty() {
            "Skills Manager"
        } else {
            caption
        };
        let mut lines = vec![
            format!("### {} {}", premium.md("skills"), md_text(title)),
            format!(
                "> Tab: **{tab_label}** · **{}** skill{} · page **{}/{pages}**",
                items.len(),
                if items.len() == 1 { "" } else { "s" },
                page + 1
            ),
            String::new(),
            "| Skill | State | Detail |".to_string(),
            "|---|---|---|".to_string(),
        ];

        if visible.is_empty() {
            lines.push("| _none_ | - | Open widget to search/install |".to_string());
        } else {
            for it in visible {
                let (nm, st_val, det) = if let Some(obj) = it.as_object() {
                    let nm = value_as_nonempty_str(obj.get("name"))
                        .or_else(|| value_as_nonempty_str(obj.get("slug")))
                        .or_else(|| value_as_nonempty_str(obj.get("id")))
                        .unwrap_or_else(|| "-".to_string());
                    let is_in = if let Some(inst_v) = obj.get("installed") {
                        value_is_truthy(Some(inst_v))
                    } else {
                        cur_tab == "inst"
                    };
                    let raw_st = value_as_nonempty_str(obj.get("state")).map(|s| {
                        if s == "✅ installed" {
                            "● installed".to_string()
                        } else {
                            s
                        }
                    });
                    let st_val = raw_st.unwrap_or_else(|| {
                        if is_in {
                            "● installed".to_string()
                        } else {
                            value_as_nonempty_str(obj.get("source"))
                                .unwrap_or_else(|| "available".to_string())
                        }
                    });
                    let det_full = value_as_nonempty_str(obj.get("desc"))
                        .or_else(|| value_as_nonempty_str(obj.get("description")))
                        .or_else(|| value_as_nonempty_str(obj.get("summary")))
                        .unwrap_or_else(|| "-".to_string());
                    (nm, st_val, trunc_chars(&det_full, 42))
                } else {
                    let nm = value_as_nonempty_str(Some(it)).unwrap_or_else(|| "-".to_string());
                    let st_val = if cur_tab == "inst" {
                        "● installed".to_string()
                    } else {
                        "available".to_string()
                    };
                    (nm, st_val, "-".to_string())
                };
                lines.push(format!(
                    "| {} | {} | {} |",
                    md_cell_with_fallback(&nm, "-"),
                    md_cell_with_fallback(&st_val, "-"),
                    md_cell_with_fallback(&det, "-")
                ));
            }
        }

        rows.push(vec![
            checked_cb_btn(
                if cur_tab == "inst" {
                    "• Installed"
                } else {
                    "Installed"
                },
                format!("wact:{wid}:sk:t:inst"),
            )?,
            checked_cb_btn(
                if cur_tab == "sp" {
                    "• SkillPort"
                } else {
                    "SkillPort"
                },
                format!("wact:{wid}:sk:t:sp"),
            )?,
        ]);
        rows.push(vec![
            checked_cb_btn("‹", format!("wact:{wid}:sk:p:prev"))?,
            checked_cb_btn("Refresh", format!("wact:{wid}:sk:ref"))?,
            checked_cb_btn("›", format!("wact:{wid}:sk:p:next"))?,
        ]);
        return Ok((lines.join("\n"), InlineKeyboardMarkup::new(rows)));
    }

    if handler == "mcp" {
        let servers: &[Value] = state_obj
            .get("servers")
            .and_then(Value::as_array)
            .or_else(|| state_obj.get("items").and_then(Value::as_array))
            .map(Vec::as_slice)
            .unwrap_or(&[]);

        let mut enabled_cnt = 0usize;
        let mut parsed_srvs: Vec<(String, String, bool)> = Vec::with_capacity(servers.len());
        for (idx, s) in servers.iter().enumerate() {
            let (nm, tp, on) = if let Some(obj) = s.as_object() {
                let nm = value_as_nonempty_str(obj.get("name"))
                    .unwrap_or_else(|| format!("mcp-{idx}"));
                let tp =
                    value_as_nonempty_str(obj.get("type")).unwrap_or_else(|| "stdio".to_string());
                let on = if let Some(en) = obj.get("enabled") {
                    value_is_truthy(Some(en))
                } else {
                    value_as_nonempty_str(obj.get("status"))
                        .is_some_and(|st| st.eq_ignore_ascii_case("enabled"))
                };
                (nm, tp, on)
            } else {
                let nm = value_as_nonempty_str(Some(s)).unwrap_or_else(|| format!("mcp-{idx}"));
                (nm, "stdio".to_string(), false)
            };
            if on {
                enabled_cnt += 1;
            }
            parsed_srvs.push((nm, tp, on));
        }

        let title = if caption.is_empty() {
            "MCP Servers"
        } else {
            caption
        };
        let mut lines = vec![
            format!("### {} {}", premium.md("mcp"), md_text(title)),
            format!("> **{enabled_cnt}/{}** enabled", parsed_srvs.len()),
            String::new(),
            "| Server | Type | State |".to_string(),
            "|---|---|---|".to_string(),
        ];

        if parsed_srvs.is_empty() {
            lines.push("| _none_ | - | No servers |".to_string());
        } else {
            for (nm, tp, on) in parsed_srvs.iter().take(16) {
                let st_txt = if *on { "● on" } else { "○ off" };
                lines.push(format!(
                    "| {} | `{}` | {st_txt} |",
                    md_cell_with_fallback(nm, "-"),
                    md_cell_with_fallback(tp, "-")
                ));
            }
        }

        let mut t_btns = Vec::new();
        for (idx, (nm, _, on)) in parsed_srvs.iter().take(8).enumerate() {
            let label = format!("{} {}", if *on { "●" } else { "○" }, trunc_chars(nm, 18));
            t_btns.push(checked_cb_btn(label, format!("wact:{wid}:mcp:t:{idx}"))?);
        }
        for chunk in t_btns.chunks(2) {
            rows.push(chunk.to_vec());
        }
        rows.push(vec![checked_cb_btn("Refresh", format!("wact:{wid}:mcp:ref"))?]);
        return Ok((lines.join("\n"), InlineKeyboardMarkup::new(rows)));
    }

    if handler == "models" {
        let title = if caption.is_empty() {
            "Models & Reasoning"
        } else {
            caption
        };
        let cur_model = value_as_nonempty_str(state_obj.get("model")).unwrap_or_default();
        let models_list: &[Value] = state_obj
            .get("models")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or(&[]);

        let mut model_label =
            value_as_nonempty_str(state_obj.get("model_name")).unwrap_or_default();
        if model_label.is_empty() && !cur_model.is_empty() {
            for m in models_list {
                if let Some(obj) = m.as_object() {
                    if value_as_nonempty_str(obj.get("id")).as_deref() == Some(cur_model.as_str()) {
                        model_label = value_as_nonempty_str(obj.get("name"))
                            .unwrap_or_else(|| cur_model.clone());
                        break;
                    }
                }
            }
        }
        if model_label.is_empty() {
            model_label = if cur_model.is_empty() {
                "Default".to_string()
            } else {
                cur_model.clone()
            };
        }

        let mode = value_as_nonempty_str(state_obj.get("mode")).unwrap_or_else(|| "auto".to_string());
        let effort =
            value_as_nonempty_str(state_obj.get("effort")).unwrap_or_else(|| "default".to_string());
        let stream_m = value_as_nonempty_str(state_obj.get("stream_mode"))
            .or_else(|| value_as_nonempty_str(state_obj.get("stream")))
            .unwrap_or_else(|| "semi".to_string());

        let lines = [
            format!("### {} {}", premium.md("model"), md_text(title)),
            String::new(),
            "| Setting | Value |".to_string(),
            "|---|---|".to_string(),
            format!(
                "| Model | `{}` |",
                md_cell_with_fallback(&trunc_chars(&model_label, 36), "-")
            ),
            format!("| Mode | `{}` |", md_cell_with_fallback(&mode, "-")),
            format!("| Effort | `{}` |", md_cell_with_fallback(&effort, "-")),
            format!("| Stream | `{}` |", md_cell_with_fallback(&stream_m, "-")),
        ];

        let mut row1 = vec![checked_cb_btn(
            if cur_model.is_empty() {
                "• Default"
            } else {
                "Default"
            },
            format!("wact:{wid}:mdl:def"),
        )?];
        for (idx, m) in models_list.iter().take(2).enumerate() {
            let (mid, mname) = if let Some(obj) = m.as_object() {
                let mid = value_as_nonempty_str(obj.get("id"))
                    .or_else(|| value_as_nonempty_str(obj.get("name")))
                    .unwrap_or_default();
                let mname = value_as_nonempty_str(obj.get("name")).unwrap_or_else(|| {
                    if mid.is_empty() {
                        format!("Model {}", idx + 1)
                    } else {
                        mid.clone()
                    }
                });
                (mid, mname)
            } else {
                let s = value_as_nonempty_str(Some(m)).unwrap_or_default();
                (s.clone(), s)
            };
            let is_cur = !cur_model.is_empty() && cur_model == mid;
            let btn_lbl = format!("{}{}", if is_cur { "• " } else { "" }, trunc_chars(&mname, 18));
            let by_id = format!("wact:{wid}:mdl:sid:{mid}");
            let cb = if !mid.is_empty() && by_id.len() <= 64 { by_id } else { format!("wact:{wid}:mdl:s:{idx}") };
            row1.push(checked_cb_btn(btn_lbl, cb)?);
        }
        rows.push(row1);

        let mut row2 = Vec::new();
        for e in ["default", "high", "max"] {
            let txt = if effort == e {
                format!("• {e}")
            } else {
                e.to_string()
            };
            row2.push(checked_cb_btn(txt, format!("wact:{wid}:mdl:e:{e}"))?);
        }
        row2.push(checked_cb_btn("Refresh", format!("wact:{wid}:mdl:ref"))?);
        rows.push(row2);

        return Ok((lines.join("\n"), InlineKeyboardMarkup::new(rows)));
    }

    if handler == "memory" {
        let items: &[Value] = state_obj
            .get("items")
            .and_then(Value::as_array)
            .or_else(|| state_obj.get("memories").and_then(Value::as_array))
            .map(Vec::as_slice)
            .unwrap_or(&[]);

        let raw_filter = value_as_nonempty_str(state_obj.get("type"))
            .or_else(|| value_as_nonempty_str(state_obj.get("filter")))
            .unwrap_or_else(|| "all".to_string())
            .trim()
            .to_ascii_lowercase();
        let cur_filter = match raw_filter.as_str() {
            "all" | "decision" | "preference" | "fact" | "insight" => raw_filter,
            _ => "all".to_string(),
        };
        let total = value_as_i64(state_obj.get("total"))
            .unwrap_or_else(|| i64::try_from(items.len()).unwrap_or(0));
        let h24 = value_as_i64(state_obj.get("recent_24h"))
            .or_else(|| value_as_i64(state_obj.get("last_24h")))
            .or_else(|| value_as_i64(state_obj.get("h24")))
            .unwrap_or(0);

        let title = if caption.is_empty() {
            "AI Memory"
        } else {
            caption
        };
        let mut lines = vec![
            format!("### {} {}", premium.md("doc"), md_text(title)),
            format!("> Total: **{total}** · 24h: **{h24}** · Filter: **{cur_filter}**"),
            String::new(),
            "| ID | Type | Title |".to_string(),
            "|---|---|---|".to_string(),
        ];

        if items.is_empty() {
            lines.push("| - | - | No memories found |".to_string());
        } else {
            for it in items.iter().take(10) {
                let (mid, mtp, mtl) = if let Some(obj) = it.as_object() {
                    let mid = trunc_chars(
                        &value_as_nonempty_str(obj.get("id")).unwrap_or_else(|| "-".to_string()),
                        10,
                    );
                    let mtp =
                        value_as_nonempty_str(obj.get("type")).unwrap_or_else(|| "fact".to_string());
                    let content = obj.get("content").and_then(Value::as_object);
                    let mtl_full = value_as_nonempty_str(obj.get("title"))
                        .or_else(|| content.and_then(|c| value_as_nonempty_str(c.get("title"))))
                        .or_else(|| value_as_nonempty_str(obj.get("summary")))
                        .unwrap_or_else(|| "-".to_string());
                    (mid, mtp, trunc_chars(&mtl_full, 40))
                } else {
                    let raw_s = value_as_nonempty_str(Some(it)).unwrap_or_default();
                    ("-".to_string(), "fact".to_string(), trunc_chars(&raw_s, 40))
                };
                lines.push(format!(
                    "| `{}` | `{}` | {} |",
                    md_cell_with_fallback(&mid, "-"),
                    md_cell_with_fallback(&mtp, "-"),
                    md_cell_with_fallback(&mtl, "-")
                ));
            }
        }

        let mut f_row = Vec::new();
        for f in ["all", "decision", "preference", "fact"] {
            let txt = if cur_filter == f {
                format!("• {f}")
            } else {
                f.to_string()
            };
            f_row.push(checked_cb_btn(txt, format!("wact:{wid}:mem:f:{f}"))?);
        }
        rows.push(f_row);
        rows.push(vec![checked_cb_btn("Refresh", format!("wact:{wid}:mem:ref"))?]);
        return Ok((lines.join("\n"), InlineKeyboardMarkup::new(rows)));
    }

    // Custom / generic HTML widget fallback
    let title = if !caption.is_empty() {
        caption
    } else {
        rec.slug
            .as_deref()
            .filter(|s| !s.is_empty())
            .unwrap_or("Interactive Widget")
    };
    let mut lines = vec![
        format!("### {} {}", premium.md("status"), md_text(title)),
        String::new(),
    ];

    let mut summary_items: Vec<(String, String)> = Vec::new();
    for obj_opt in [&pd_obj, &cd_obj] {
        if let Some(Value::Object(map)) = obj_opt {
            for (k, v) in map {
                let mut val_s = match v {
                    Value::Object(_) | Value::Array(_) => {
                        serde_json::to_string(v).unwrap_or_else(|_| v.to_string())
                    }
                    Value::String(s) => s.clone(),
                    Value::Null => "None".to_string(),
                    Value::Bool(b) => {
                        if *b {
                            "True".to_string()
                        } else {
                            "False".to_string()
                        }
                    }
                    Value::Number(n) => n.to_string(),
                };
                if val_s.chars().count() > 80 {
                    val_s = format!("{}...", trunc_chars(&val_s, 77));
                }
                summary_items.push((k.clone(), val_s));
            }
        }
    }

    if !summary_items.is_empty() {
        lines.push("| Key | Value |".to_string());
        lines.push("|---|---|".to_string());
        for (k, v) in summary_items.iter().take(12) {
            lines.push(format!(
                "| {} | `{}` |",
                md_cell_with_fallback(k, "-"),
                md_cell_with_fallback(v, "-")
            ));
        }
    } else {
        let mut snippet: Option<String> = None;
        for v in [&pd_obj, &cd_obj].into_iter().flatten() {
            let non_empty = match v {
                Value::Null => false,
                Value::String(s) => !s.is_empty(),
                Value::Array(a) => !a.is_empty(),
                Value::Object(m) => !m.is_empty(),
                _ => true,
            };
            if non_empty {
                snippet = Some(match v {
                    Value::Object(_) | Value::Array(_) => {
                        serde_json::to_string(v).unwrap_or_else(|_| v.to_string())
                    }
                    Value::String(s) => s.clone(),
                    other => other.to_string(),
                });
                break;
            }
        }
        if snippet.is_none() {
            for s in [&pd_raw, &cd_raw].into_iter().flatten() {
                if !s.is_empty() {
                    snippet = Some(s.clone());
                    break;
                }
            }
        }

        if let Some(snip) = snippet {
            let clean = trunc_chars(&md_text(&snip), 280).replace('`', "'");
            lines.push(format!("> `{clean}`"));
        } else {
            lines.push("> Interactive widget ready — open below or tap refresh.".to_string());
        }
    }

    rows.push(vec![checked_cb_btn("بروزرسانی", format!("wact:{wid}:refresh"))?]);
    Ok((lines.join("\n"), InlineKeyboardMarkup::new(rows)))
}

/// Convenience helper to render an in-bubble card directly from `(wid, kind, caption, state)`.
pub fn render_in_bubble_widget_from_state(
    wid: &str,
    kind: &str,
    caption: Option<&str>,
    state: &Value,
    webapp_url: Option<&str>,
    tab: Option<&str>,
    premium: &PremiumState,
) -> Result<(String, InlineKeyboardMarkup)> {
    let cd = serde_json::to_string(state)
        .map_err(|e| BridgeError::json("serialize in-bubble state", e))?;
    let rec = WebAppWidgetRecord {
        wid: wid.to_string(),
        handler: Some(kind.to_string()),
        caption: caption.map(str::to_string),
        chat_data: Some(cd),
        tab: tab.map(str::to_string),
        ..Default::default()
    };
    render_in_bubble_widget(&rec, webapp_url, tab, premium)
}

// --------------------------------------------------------------------------- WebApp HTML shell

/// Unauthenticated WebApp HTML shell served at `GET /w/{wid}` (zero embedded state or secrets).
pub const WEBAPP_SHELL_HTML: &str = r####"<!DOCTYPE html>
<html lang="fa" dir="auto">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>Telegram Widget</title>
<script src="https://telegram.org/js/telegram-web-app.js"></script>
<style>
:root {
  color-scheme: light dark;
  --tg-theme-bg-color: #ffffff;
  --tg-theme-text-color: #000000;
  --tg-theme-hint-color: #8e8e93;
  --tg-theme-link-color: #007aff;
  --tg-theme-button-color: #007aff;
  --tg-theme-button-text-color: #ffffff;
  --tg-theme-secondary-bg-color: #f2f2f7;
  --tg-theme-header-bg-color: #f9f9fb;
  --tg-theme-section-bg-color: #ffffff;
  --tg-theme-section-header-text-color: #6d6d72;
  --tg-theme-subtitle-text-color: #8e8e93;
  --tg-theme-destructive-text-color: #ff3b30;
  --tg-theme-accent-text-color: #007aff;
  --tg-theme-section-separator-color: rgba(60,60,67,0.18);
}
html[data-theme="dark"] {
  --tg-theme-bg-color: #1c1c1e;
  --tg-theme-text-color: #ffffff;
  --tg-theme-hint-color: #98989d;
  --tg-theme-link-color: #0a84ff;
  --tg-theme-button-color: #0a84ff;
  --tg-theme-button-text-color: #ffffff;
  --tg-theme-secondary-bg-color: #000000;
  --tg-theme-header-bg-color: #2c2c2e;
  --tg-theme-section-bg-color: #2c2c2e;
  --tg-theme-section-header-text-color: #98989d;
  --tg-theme-subtitle-text-color: #98989d;
  --tg-theme-destructive-text-color: #ff453a;
  --tg-theme-accent-text-color: #0a84ff;
  --tg-theme-section-separator-color: rgba(255,255,255,0.14);
}
* { box-sizing: border-box; }
body {
  margin: 0;
  padding: 12px 12px calc(16px + env(safe-area-inset-bottom, 0px));
  min-height: 100vh;
  background: var(--tg-theme-secondary-bg-color);
  color: var(--tg-theme-text-color);
  font-family: -apple-system, BlinkMacSystemFont, "SF Pro Text", system-ui, sans-serif;
}
.shell {
  max-width: 600px;
  margin: 0 auto;
}
.banner {
  background: var(--tg-theme-section-bg-color);
  border: 1px solid var(--tg-theme-section-separator-color);
  border-radius: 14px;
  padding: 14px 16px;
  font-size: 13px;
  line-height: 1.5;
  text-align: center;
  color: var(--tg-theme-hint-color);
}
.banner.err {
  color: var(--tg-theme-destructive-text-color);
}
.frame-wrap {
  width: 100%;
  margin: 0 auto;
  background: var(--tg-theme-bg-color);
  border-radius: 16px;
  overflow: hidden;
  border: 1px solid var(--tg-theme-section-separator-color);
}
#wframe {
  display: block;
  width: 100%;
  height: 240px;
  border: 0;
  background: transparent;
}
</style>
</head>
<body>
<div id="shell" class="shell">
  <div id="banner" class="banner">در حال بارگذاری ویجت...</div>
  <div id="frame-wrap" class="frame-wrap" hidden>
    <iframe id="wframe" sandbox="allow-scripts allow-same-origin" title="Telegram Widget"></iframe>
  </div>
</div>
<script>
(function() {
  var pathname = (window.location && window.location.pathname) ? window.location.pathname : "";
  var match = pathname.match(/^(.*)\/w\/([^/]+)\/?$/);
  var prefix = match ? match[1] : "";
  var wid = match ? decodeURIComponent(match[2]) : "";
  var apiBase = prefix + "/api/w/" + encodeURIComponent(wid);

  var tg = (window.Telegram && window.Telegram.WebApp) ? window.Telegram.WebApp : null;
  var bannerEl = document.getElementById("banner");
  var wrapEl = document.getElementById("frame-wrap");
  var frame = document.getElementById("wframe");

  function showMsg(msg, isErr) {
    if (!bannerEl) return;
    bannerEl.textContent = msg;
    bannerEl.className = "banner" + (isErr ? " err" : "");
    bannerEl.hidden = false;
  }

  var FALLBACK_THEMES = {
    light: {
      bg_color: "#ffffff", text_color: "#000000", hint_color: "#8e8e93",
      link_color: "#007aff", button_color: "#007aff", button_text_color: "#ffffff",
      secondary_bg_color: "#f2f2f7", header_bg_color: "#f9f9fb",
      section_bg_color: "#ffffff", section_header_text_color: "#6d6d72",
      subtitle_text_color: "#8e8e93", destructive_text_color: "#ff3b30",
      accent_text_color: "#007aff", section_separator_color: "rgba(60,60,67,0.18)"
    },
    dark: {
      bg_color: "#1c1c1e", text_color: "#ffffff", hint_color: "#98989d",
      link_color: "#0a84ff", button_color: "#0a84ff", button_text_color: "#ffffff",
      secondary_bg_color: "#000000", header_bg_color: "#2c2c2e",
      section_bg_color: "#2c2c2e", section_header_text_color: "#98989d",
      subtitle_text_color: "#98989d", destructive_text_color: "#ff453a",
      accent_text_color: "#0a84ff", section_separator_color: "rgba(255,255,255,0.14)"
    }
  };

  function getThemeState() {
    var scheme = "light";
    if (tg && tg.colorScheme === "dark") {
      scheme = "dark";
    } else if (tg && tg.colorScheme === "light") {
      scheme = "light";
    } else if (window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches) {
      scheme = "dark";
    }
    var params = Object.assign({}, FALLBACK_THEMES[scheme]);
    if (tg && tg.themeParams && typeof tg.themeParams === "object") {
      for (var k in tg.themeParams) {
        if (Object.prototype.hasOwnProperty.call(tg.themeParams, k) && tg.themeParams[k]) {
          params[k] = tg.themeParams[k];
        }
      }
    }
    return { scheme: scheme, params: params };
  }

  function applyThemeToDoc(doc, st) {
    if (!doc || !doc.documentElement) return;
    doc.documentElement.setAttribute("data-theme", st.scheme);
    doc.documentElement.style.colorScheme = st.scheme;
    for (var k in st.params) {
      if (Object.prototype.hasOwnProperty.call(st.params, k) && st.params[k]) {
        doc.documentElement.style.setProperty("--tg-theme-" + k.replace(/_/g, "-"), st.params[k]);
      }
    }
  }

  var initialTheme = getThemeState();
  applyThemeToDoc(document, initialTheme);

  if (tg) {
    try { if (typeof tg.ready === "function") tg.ready(); } catch (e) {}
    try { if (typeof tg.expand === "function") tg.expand(); } catch (e) {}
  }

  var initData = (tg && typeof tg.initData === "string") ? tg.initData : "";
  if (!initData) {
    showMsg("این ویجت فقط داخل ربات تلگرام (@your_agy_bot) اجرا می‌شود.", true);
    return;
  }

  var listeners = {};
  var watchTimer = null;
  var cacheTimeSec = 30;
  var fixedHeight = null;

  function emit(ev, data) {
    var arr = listeners[ev] || [];
    for (var i = 0; i < arr.length; i++) {
      try { arr[i](data); } catch (e) {}
    }
  }

  function makeErr(code, msg) {
    var err = new Error(msg || code || "Request failed");
    err.code = code || "FAILED";
    err.name = err.code;
    return err;
  }

  function postJson(url, payload) {
    return fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    }).then(function(resp) {
      return resp.json().catch(function() { return {}; }).then(function(body) {
        if (!resp.ok || !body || body.ok === false) {
          var code = resp.status === 429 ? "RATE_LIMITED" :
            (resp.status === 400 ? "BAD_REQUEST" :
            (resp.status === 403 ? "REJECTED" : "FAILED"));
          throw makeErr(code, (body && body.error) || ("HTTP " + resp.status));
        }
        return body;
      });
    });
  }

  function syncSize() {
    if (!frame) return;
    if (fixedHeight && fixedHeight >= 50 && fixedHeight <= 600) {
      frame.style.height = fixedHeight + "px";
      return;
    }
    try {
      var doc = frame.contentDocument;
      var b = doc && doc.body;
      var de = doc && doc.documentElement;
      if (b) {
        var h = Math.max(120, Math.min(600, Math.max(b.scrollHeight || 0, de ? de.scrollHeight : 0, 160)));
        frame.style.height = h + "px";
      }
    } catch (e) {}
  }

  var tgHaptic = (tg && tg.HapticFeedback) ? tg.HapticFeedback : null;
  var hapticBridge = {
    impactOccurred: function(s) {
      try { if (tgHaptic && tgHaptic.impactOccurred) tgHaptic.impactOccurred(s || "light"); } catch (e) {}
      return hapticBridge;
    },
    notificationOccurred: function(t) {
      try { if (tgHaptic && tgHaptic.notificationOccurred) tgHaptic.notificationOccurred(t || "success"); } catch (e) {}
      return hapticBridge;
    },
    selectionChanged: function() {
      try { if (tgHaptic && tgHaptic.selectionChanged) tgHaptic.selectionChanged(); } catch (e) {}
      return hapticBridge;
    }
  };

  var api = {
    profile: 1,
    isProfileAtLeast: function(n) { return 1 >= Number(n || 0); },
    colorScheme: initialTheme.scheme,
    themeParams: Object.assign({}, initialTheme.params),
    isActive: true,
    isPreview: false,
    isForward: false,
    chatType: (tg && tg.initDataUnsafe && tg.initDataUnsafe.chat_type) || "private",
    viewer: null,
    publicData: null,
    chatData: null,
    richState: null,
    contentSafeAreaInset: (tg && tg.contentSafeAreaInset)
      ? Object.assign({ top: 0, right: 0, bottom: 0, left: 0, cornerLeft: 0, cornerRight: 0 }, tg.contentSafeAreaInset)
      : { top: 0, right: 0, bottom: 0, left: 0, cornerLeft: 0, cornerRight: 0 },
    HapticFeedback: hapticBridge,
    wallet: null,
    watchPublicData: function() {
      if (watchTimer !== null) return;
      var ms = Math.max(5, Number(cacheTimeSec || 30)) * 1000;
      watchTimer = setInterval(function() {
        postJson(apiBase + "/state", { initData: initData }).then(function(d) {
          if (d.cacheTime) cacheTimeSec = Number(d.cacheTime) || cacheTimeSec;
          var pdChanged = d.publicData !== undefined && d.publicData !== api.publicData;
          var cdChanged = d.chatData !== undefined && d.chatData !== api.chatData;
          if (pdChanged) api.publicData = d.publicData;
          if (cdChanged) api.chatData = d.chatData;
          if (pdChanged) emit("publicDataChanged");
          if (cdChanged) emit("chatDataChanged");
        }).catch(function() {});
      }, ms);
    },
    unwatchPublicData: function() {
      if (watchTimer !== null) {
        clearInterval(watchTimer);
        watchTimer = null;
      }
    },
    request: function(data, opts) {
      var payload = {
        initData: initData,
        data: String(data == null ? "" : data),
        opts: opts || null
      };
      return postJson(apiBase + "/query", payload).then(function(d) {
        var cdChanged = d.chatData !== undefined && d.chatData !== api.chatData;
        var pdChanged = d.publicData !== undefined && d.publicData !== api.publicData;
        if (cdChanged) api.chatData = d.chatData;
        if (pdChanged) api.publicData = d.publicData;
        if (cdChanged) emit("chatDataChanged");
        if (pdChanged) emit("publicDataChanged");
        setTimeout(syncSize, 40);
        return { result: d.result };
      });
    },
    callAction: function(action, payload) {
      var body = {
        initData: initData,
        action: String(action == null ? "" : action),
        payload: (payload && typeof payload === "object") ? payload : {}
      };
      return postJson(apiBase + "/action", body).then(function(d) {
        var cdChanged = d.chatData !== undefined && d.chatData !== api.chatData;
        var pdChanged = d.publicData !== undefined && d.publicData !== api.publicData;
        var rsChanged = d.richState !== undefined;
        if (cdChanged) api.chatData = d.chatData;
        if (pdChanged) api.publicData = d.publicData;
        if (rsChanged) api.richState = d.richState;
        if (cdChanged) emit("chatDataChanged");
        if (pdChanged) emit("publicDataChanged");
        if (rsChanged) emit("richStateChanged");
        setTimeout(syncSize, 40);
        return {
          result: d.result,
          richState: d.richState !== undefined ? d.richState : api.richState,
          chatData: d.chatData,
          publicData: d.publicData
        };
      });
    },
    copyText: function(text) {
      var s = String(text == null ? "" : text);
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(s).catch(function() {});
        return;
      }
      try {
        var ta = document.createElement("textarea");
        ta.value = s;
        ta.style.position = "fixed";
        ta.style.opacity = "0";
        document.body.appendChild(ta);
        ta.select();
        document.execCommand("copy");
        document.body.removeChild(ta);
      } catch (e) {}
    },
    openLink: function(url) {
      var u = String(url || "");
      if (tg && typeof tg.openLink === "function") {
        tg.openLink(u);
      } else {
        window.open(u, "_blank", "noopener");
      }
    },
    openTelegramLink: function(url) {
      var u = String(url || "");
      if (tg && typeof tg.openTelegramLink === "function") {
        tg.openTelegramLink(u);
      } else {
        window.open(u, "_blank", "noopener");
      }
    },
    setResizeAnchor: function() {},
    ready: function() {
      setTimeout(syncSize, 20);
    },
    onEvent: function(ev, cb) {
      if (typeof cb !== "function") return;
      if (!listeners[ev]) listeners[ev] = [];
      listeners[ev].push(cb);
    },
    offEvent: function(ev, cb) {
      if (!listeners[ev]) return;
      listeners[ev] = listeners[ev].filter(function(f) { return f !== cb; });
    }
  };
  window.TelegramWidget = api;

  if (tg && typeof tg.onEvent === "function") {
    tg.onEvent("themeChanged", function() {
      var next = getThemeState();
      api.colorScheme = next.scheme;
      api.themeParams = Object.assign({}, next.params);
      applyThemeToDoc(document, next);
      try {
        if (frame && frame.contentDocument) applyThemeToDoc(frame.contentDocument, next);
      } catch (e) {}
      emit("themeChanged", { colorScheme: api.colorScheme, themeParams: api.themeParams });
    });
  }

  postJson(apiBase + "/init", { initData: initData }).then(function(d) {
    api.viewer = d.viewer || null;
    api.chatData = d.chatData !== undefined ? d.chatData : null;
    api.publicData = d.publicData !== undefined ? d.publicData : null;
    api.richState = d.richState !== undefined ? d.richState : null;
    cacheTimeSec = Number(d.cacheTime || 30) || 30;
    fixedHeight = d.height ? Number(d.height) : null;
    if (d.width && Number(d.width) >= 200 && Number(d.width) <= 600) {
      wrapEl.style.maxWidth = Number(d.width) + "px";
    }
    if (d.caption) {
      document.title = String(d.caption);
    }
    var inject = "<style>html,body{margin:0;padding:0;background:transparent;}</style>" +
      "<script>window.TelegramWidget=window.parent.TelegramWidget;<" + "/script>";
    var rawHtml = String(d.html || "");
    var docHtml = /<head\b[^>]*>/i.test(rawHtml)
      ? rawHtml.replace(/<head\b[^>]*>/i, function(m) { return m + inject; })
      : "<!DOCTYPE html><html><head><meta charset=\"utf-8\">" + inject + "</head><body>" + rawHtml + "</body></html>";

    bannerEl.hidden = true;
    wrapEl.hidden = false;
    var fdoc = frame.contentDocument || (frame.contentWindow && frame.contentWindow.document);
    fdoc.open();
    fdoc.write(docHtml);
    fdoc.close();
    applyThemeToDoc(fdoc, getThemeState());
    setTimeout(syncSize, 40);
    setTimeout(syncSize, 250);
  }).catch(function(e) {
    showMsg("خطا در بارگذاری ویجت: " + (e && e.message ? e.message : "Unauthorized"), true);
  });
})();
</script>
</body>
</html>
"####;

// --------------------------------------------------------------------------- Bridge trait & Axum router

/// Response returned by [`WidgetBridge::query_widget`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BridgeQueryResponse {
    pub result: Value,
    pub chat_data: Option<Value>,
    pub public_data: Option<Value>,
}

/// Response returned by [`WidgetBridge::call_action`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeActionResponse {
    pub ok: bool,
    pub status: u16,
    pub error: Option<String>,
    pub result: Value,
    pub chat_data: Option<Value>,
    pub public_data: Option<Value>,
    pub rich_state: Option<Value>,
}

impl Default for BridgeActionResponse {
    fn default() -> Self {
        Self {
            ok: true,
            status: 200,
            error: None,
            result: Value::Null,
            chat_data: None,
            public_data: None,
            rich_state: None,
        }
    }
}

impl BridgeActionResponse {
    /// Construct a successful action response.
    pub fn ok(result: Value) -> Self {
        Self {
            ok: true,
            status: 200,
            error: None,
            result,
            chat_data: None,
            public_data: None,
            rich_state: None,
        }
    }

    /// Construct a rejected action response (e.g., 403 Permission denied) without mutating stored state.
    pub fn rejected(status: u16, error: impl Into<String>) -> Self {
        Self {
            ok: false,
            status,
            error: Some(error.into()),
            result: Value::Null,
            chat_data: None,
            public_data: None,
            rich_state: None,
        }
    }
}

/// Async bridge connecting the Axum WebApp server to bot query/action/state handlers.
pub trait WidgetBridge: Send + Sync {
    /// Whether `/api/w/{wid}/action` is supported (returning `false` yields HTTP 501 `actions_unsupported`).
    fn supports_actions(&self) -> bool {
        true
    }

    /// Dispatch a `TelegramWidget.request(data)` query.
    fn query_widget<'a>(
        &'a self,
        wid: &'a str,
        kind: &'a str,
        data: &'a str,
        uid: i64,
        chat_id: Option<i64>,
    ) -> BoxFuture<'a, Result<BridgeQueryResponse>>;

    /// Dispatch a `TelegramWidget.request(data, opts)` query (defaults to [`Self::query_widget`]).
    fn query_widget_with_opts<'a>(
        &'a self,
        wid: &'a str,
        kind: &'a str,
        data: &'a str,
        opts: Option<&'a Value>,
        uid: i64,
        chat_id: Option<i64>,
    ) -> BoxFuture<'a, Result<BridgeQueryResponse>> {
        let _ = opts;
        self.query_widget(wid, kind, data, uid, chat_id)
    }

    /// Dispatch a `TelegramWidget.callAction(action, payload)` invocation.
    fn call_action<'a>(
        &'a self,
        wid: &'a str,
        kind: &'a str,
        action: &'a str,
        payload: &'a Value,
        uid: i64,
        chat_id: Option<i64>,
    ) -> BoxFuture<'a, Result<BridgeActionResponse>>;

    /// Fetch live `richState` for `/api/w/{wid}/init`.
    fn get_rich_state<'a>(
        &'a self,
        wid: &'a str,
        kind: &'a str,
        uid: i64,
        chat_id: Option<i64>,
    ) -> BoxFuture<'a, Result<Option<Value>>>;

    /// Optional callback invoked after `/query` or `/action` commits state changes.
    fn on_state_changed<'a>(&'a self, _wid: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(async {})
    }
}

/// Shared state injected into the Axum WebApp router.
#[derive(Clone)]
pub struct WebAppState {
    pub store: Arc<WidgetStore>,
    pub bridge: Arc<dyn WidgetBridge>,
    pub bot_token: TokenProvider,
    pub allowed_uids: AllowedUidsProvider,
    pub max_age_secs: u64,
    /// Per-UID token-bucket limiter guarding authenticated `/api/w/*` widget API calls.
    pub api_uid_rl: Arc<KeyedTokenBucket<i64>>,
}

impl WebAppState {
    /// Construct [`WebAppState`] with static bot token and allowlisted UIDs.
    pub fn new(
        bot_token: impl Into<String>,
        allowed_uids: HashSet<i64>,
        store: Arc<WidgetStore>,
        bridge: Arc<dyn WidgetBridge>,
    ) -> Self {
        let token = bot_token.into();
        Self {
            store,
            bridge,
            bot_token: Arc::new(move || token.clone()),
            allowed_uids: Arc::new(move || allowed_uids.clone()),
            max_age_secs: DEFAULT_INIT_DATA_MAX_AGE_SECS,
            api_uid_rl: Arc::new(KeyedTokenBucket::new(120, 30, DEFAULT_MAX_BUCKET_KEYS)),
        }
    }

    /// Construct [`WebAppState`] with dynamic token and allowlisted UIDs providers.
    pub fn with_providers(
        bot_token: TokenProvider,
        allowed_uids: AllowedUidsProvider,
        store: Arc<WidgetStore>,
        bridge: Arc<dyn WidgetBridge>,
    ) -> Self {
        Self {
            store,
            bridge,
            bot_token,
            allowed_uids,
            max_age_secs: DEFAULT_INIT_DATA_MAX_AGE_SECS,
            api_uid_rl: Arc::new(KeyedTokenBucket::new(120, 30, DEFAULT_MAX_BUCKET_KEYS)),
        }
    }

    /// Override per-UID `/api/w/*` rate limit (requests/min; `0` disables).
    pub fn with_api_uid_rate_limit(mut self, rate_per_min: u32) -> Self {
        let burst = if rate_per_min == 0 {
            0
        } else {
            (rate_per_min / 4).clamp(15, 120)
        };
        self.api_uid_rl = Arc::new(KeyedTokenBucket::new(
            rate_per_min,
            burst,
            DEFAULT_MAX_BUCKET_KEYS,
        ));
        self
    }

    /// Override `initData` maximum age in seconds.
    pub fn with_max_age_secs(mut self, max_age_secs: u64) -> Self {
        self.max_age_secs = max_age_secs;
        self
    }
}

fn json_err(status: StatusCode, error: &str) -> Response {
    (status, Json(json!({ "ok": false, "error": error }))).into_response()
}

fn serialize_data_for_compare(val: &Value) -> Option<String> {
    match val {
        Value::Null => None,
        Value::String(s) if s.is_empty() => None,
        Value::String(s) => Some(s.clone()),
        Value::Object(_) | Value::Array(_) => serde_json::to_string(val).ok(),
        other => Some(other.to_string()),
    }
}

fn json_val_to_patch(val: &Value) -> DataPatch<'_> {
    match val {
        Value::Null => DataPatch::Clear,
        Value::String(s) if s.is_empty() => DataPatch::Clear,
        other => DataPatch::Set(other.into()),
    }
}

async fn parse_auth_body(
    state: &WebAppState,
    headers: &HeaderMap,
    body: Body,
) -> std::result::Result<(Map<String, Value>, VerifiedInitData), (StatusCode, &'static str)> {
    if let Some(cl_val) = headers.get(header::CONTENT_LENGTH) {
        if let Ok(cl_str) = cl_val.to_str() {
            if let Ok(cl) = cl_str.trim().parse::<usize>() {
                if cl > WEBAPP_API_MAX_BYTES {
                    return Err((StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large"));
                }
            }
        }
    }

    let bytes = to_bytes(body, WEBAPP_API_MAX_BYTES)
        .await
        .map_err(|_| (StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large"))?;

    let val: Value = serde_json::from_slice(&bytes)
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid_json"))?;
    let Value::Object(obj) = val else {
        return Err((StatusCode::BAD_REQUEST, "invalid_json"));
    };

    let init_data = obj
        .get("initData")
        .and_then(Value::as_str)
        .unwrap_or("");
    let token = (state.bot_token)();
    let allowed = (state.allowed_uids)();

    let verified = verify_webapp_init_data(init_data, &token, &allowed, state.max_age_secs)
        .map_err(|_| (StatusCode::FORBIDDEN, "unauthorized"))?;

    let rl = state.api_uid_rl.check(verified.uid, 1);
    if !rl.allowed {
        warn!(uid = verified.uid, retry_after = rl.retry_after_secs, "webapp per-UID API rate limit exceeded");
        return Err((StatusCode::TOO_MANY_REQUESTS, "rate_limited"));
    }

    Ok((obj, verified))
}

async fn persist_and_notify(
    state: &WebAppState,
    wid: &str,
    rec: &WebAppWidgetRecord,
    chat_data: Option<Value>,
    public_data: Option<Value>,
) -> (Value, Value) {
    let fresh = state
        .store
        .get_webapp_widget(wid)
        .unwrap_or_else(|| rec.clone());

    let chat_data_out = match &chat_data {
        Some(v) => v.clone(),
        None => match &fresh.chat_data {
            Some(s) => Value::String(s.clone()),
            None => Value::Null,
        },
    };
    let public_data_out = match &public_data {
        Some(v) => v.clone(),
        None => match &fresh.public_data {
            Some(s) => Value::String(s.clone()),
            None => Value::Null,
        },
    };

    let cd_patch = match &chat_data {
        Some(v) if serialize_data_for_compare(v) != fresh.chat_data => json_val_to_patch(v),
        _ => DataPatch::Unchanged,
    };
    let pd_patch = match &public_data {
        Some(v) if serialize_data_for_compare(v) != fresh.public_data => json_val_to_patch(v),
        _ => DataPatch::Unchanged,
    };

    if !matches!(cd_patch, DataPatch::Unchanged) || !matches!(pd_patch, DataPatch::Unchanged) {
        if let Err(err) = state
            .store
            .update_webapp_widget_state(wid, cd_patch, pd_patch, None)
        {
            warn!(wid = %wid, error = %err, "webapp state update skipped");
        }
    }

    state.bridge.on_state_changed(wid).await;
    (chat_data_out, public_data_out)
}

async fn handle_healthz() -> impl IntoResponse {
    Json(json!({ "ok": true, "service": "agy-telegram-webapp" }))
}

async fn handle_widget_shell(
    State(state): State<WebAppState>,
    Path(wid): Path<String>,
) -> Response {
    if state.store.get_webapp_widget(&wid).is_none() {
        return (StatusCode::NOT_FOUND, "Widget not found").into_response();
    }
    let mut resp = Html(WEBAPP_SHELL_HTML).into_response();
    let headers = resp.headers_mut();
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(WEBAPP_CSP_HEADER),
    );
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store"),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    resp
}

async fn handle_widget_init(
    State(state): State<WebAppState>,
    Path(wid): Path<String>,
    req: Request,
) -> Response {
    let (headers, body) = req.into_parts();
    let (_body_obj, auth) = match parse_auth_body(&state, &headers.headers, body).await {
        Ok(v) => v,
        Err((status, err)) => return json_err(status, err),
    };

    let Some(rec) = state.store.get_webapp_widget(&wid) else {
        return json_err(StatusCode::NOT_FOUND, "not_found");
    };

    let kind = rec.handler.as_deref().unwrap_or("");
    let rich_state = match state
        .bridge
        .get_rich_state(&wid, kind, auth.uid, rec.chat_id)
        .await
    {
        Ok(rs) => rs,
        Err(err) => {
            warn!(wid = %wid, error = %err, "get_rich_state failed");
            None
        }
    };

    let widget_html = rec.html.unwrap_or_else(|| {
        let shared_ref = rec
            .shared_widget_id
            .as_deref()
            .or(rec.slug.as_deref())
            .unwrap_or(&wid);
        format!(
            r#"<div style="padding:14px;font-family:-apple-system,system-ui,sans-serif;color:var(--tg-theme-text-color)">Shared widget: {}</div>"#,
            esc(shared_ref)
        )
    });

    Json(json!({
        "ok": true,
        "html": widget_html,
        "caption": rec.caption,
        "width": rec.width,
        "height": rec.height,
        "chatData": rec.chat_data,
        "publicData": rec.public_data,
        "richState": rich_state,
        "cacheTime": if rec.cache_time > 0 { rec.cache_time } else { WIDGET_CACHE_TIME_DEFAULT },
        "viewer": auth.user,
    }))
    .into_response()
}

async fn handle_widget_query(
    State(state): State<WebAppState>,
    Path(wid): Path<String>,
    req: Request,
) -> Response {
    let (headers, body) = req.into_parts();
    let (body_obj, auth) = match parse_auth_body(&state, &headers.headers, body).await {
        Ok(v) => v,
        Err((status, err)) => return json_err(status, err),
    };

    let Some(rec) = state.store.get_webapp_widget(&wid) else {
        return json_err(StatusCode::NOT_FOUND, "not_found");
    };

    let Some(Value::String(data)) = body_obj.get("data") else {
        return json_err(StatusCode::BAD_REQUEST, "invalid_query_data");
    };
    if data.is_empty() || data.len() > WIDGET_QUERY_DATA_LIMIT {
        return json_err(StatusCode::BAD_REQUEST, "invalid_query_data");
    }

    let opts = match body_obj.get("opts") {
        None | Some(Value::Null) => None,
        Some(v @ Value::Object(_)) => Some(v),
        Some(_) => return json_err(StatusCode::BAD_REQUEST, "invalid_opts"),
    };

    let kind = rec.handler.as_deref().unwrap_or("");
    let res = match state
        .bridge
        .query_widget_with_opts(&wid, kind, data, opts, auth.uid, rec.chat_id)
        .await
    {
        Ok(r) => r,
        Err(err) => {
            error!(wid = %wid, error = %err, "webapp query dispatch failed");
            return json_err(StatusCode::INTERNAL_SERVER_ERROR, "dispatch_failed");
        }
    };

    let (chat_data_out, public_data_out) =
        persist_and_notify(&state, &wid, &rec, res.chat_data, res.public_data).await;

    Json(json!({
        "ok": true,
        "result": res.result,
        "chatData": chat_data_out,
        "publicData": public_data_out,
    }))
    .into_response()
}

async fn handle_widget_action(
    State(state): State<WebAppState>,
    Path(wid): Path<String>,
    req: Request,
) -> Response {
    let (headers, body) = req.into_parts();
    let (body_obj, auth) = match parse_auth_body(&state, &headers.headers, body).await {
        Ok(v) => v,
        Err((status, err)) => return json_err(status, err),
    };

    let Some(rec) = state.store.get_webapp_widget(&wid) else {
        return json_err(StatusCode::NOT_FOUND, "not_found");
    };

    let Some(Value::String(action)) = body_obj.get("action") else {
        return json_err(StatusCode::BAD_REQUEST, "invalid_action");
    };
    if action.trim().is_empty() || action.len() > WIDGET_QUERY_DATA_LIMIT {
        return json_err(StatusCode::BAD_REQUEST, "invalid_action");
    }

    let payload = match body_obj.get("payload") {
        None | Some(Value::Null) => json!({}),
        Some(v @ Value::Object(_)) => v.clone(),
        Some(_) => return json_err(StatusCode::BAD_REQUEST, "invalid_payload"),
    };

    if !state.bridge.supports_actions() {
        return json_err(StatusCode::NOT_IMPLEMENTED, "actions_unsupported");
    }

    let kind = rec.handler.as_deref().unwrap_or("");
    let res = match state
        .bridge
        .call_action(&wid, kind, action, &payload, auth.uid, rec.chat_id)
        .await
    {
        Ok(r) => r,
        Err(err) => {
            error!(wid = %wid, action = %action, error = %err, "webapp action dispatch failed");
            return json_err(StatusCode::INTERNAL_SERVER_ERROR, "action_failed");
        }
    };

    if !res.ok {
        let code = StatusCode::from_u16(res.status)
            .ok()
            .filter(|c| c.is_client_error() || c.is_server_error())
            .unwrap_or(StatusCode::BAD_REQUEST);
        return json_err(code, res.error.as_deref().unwrap_or("rejected"));
    }

    let (chat_data_out, public_data_out) =
        persist_and_notify(&state, &wid, &rec, res.chat_data, res.public_data).await;

    Json(json!({
        "ok": true,
        "result": res.result,
        "chatData": chat_data_out,
        "publicData": public_data_out,
        "richState": res.rich_state,
    }))
    .into_response()
}

async fn handle_widget_state(
    State(state): State<WebAppState>,
    Path(wid): Path<String>,
    req: Request,
) -> Response {
    let (headers, body) = req.into_parts();
    let (_body_obj, _auth) = match parse_auth_body(&state, &headers.headers, body).await {
        Ok(v) => v,
        Err((status, err)) => return json_err(status, err),
    };

    let Some(rec) = state.store.get_webapp_widget(&wid) else {
        return json_err(StatusCode::NOT_FOUND, "not_found");
    };

    Json(json!({
        "ok": true,
        "chatData": rec.chat_data,
        "publicData": rec.public_data,
        "cacheTime": if rec.cache_time > 0 { rec.cache_time } else { WIDGET_CACHE_TIME_DEFAULT },
    }))
    .into_response()
}

async fn security_headers_middleware(req: Request, next: Next) -> Response {
    let is_api = req.uri().path().starts_with("/api/");
    let mut resp = next.run(req).await;
    let hdrs = resp.headers_mut();
    hdrs.entry(header::X_CONTENT_TYPE_OPTIONS)
        .or_insert_with(|| HeaderValue::from_static("nosniff"));
    hdrs.entry(header::REFERRER_POLICY)
        .or_insert_with(|| HeaderValue::from_static("no-referrer"));
    hdrs.entry(header::HeaderName::from_static("permissions-policy"))
        .or_insert_with(|| {
            HeaderValue::from_static("camera=(), microphone=(), geolocation=(), payment=()")
        });
    hdrs.entry(header::HeaderName::from_static("x-permitted-cross-domain-policies"))
        .or_insert_with(|| HeaderValue::from_static("none"));
    if is_api {
        hdrs.entry(header::CACHE_CONTROL)
            .or_insert_with(|| HeaderValue::from_static("no-store"));
    }
    resp
}

/// Build the Axum router serving the WebApp HTML shell and authenticated widget JSON API.
pub fn build_webapp_router(state: WebAppState) -> Router {
    Router::new()
        .route("/healthz", get(handle_healthz))
        .route("/w/{wid}", get(handle_widget_shell))
        .route("/api/w/{wid}/init", post(handle_widget_init))
        .route("/api/w/{wid}/query", post(handle_widget_query))
        .route("/api/w/{wid}/action", post(handle_widget_action))
        .route("/api/w/{wid}/state", post(handle_widget_state))
        .layer(middleware::from_fn(security_headers_middleware))
        .with_state(state)
}
