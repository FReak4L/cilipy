//! WebApp (`TelegramWidget` HTTP/HMAC bridge) and interactive widget query/action dispatch.
//!
//! Connects [`agy_widgets::WidgetBridge`] and Bot API 10.4 `widget_query` /
//! `shared_widget_query` events to `BotCtx` (`skills`, `mcp`, `models`, `memory`,
//! `sys`, `settings`, `sessions`, `net`, `cron`, `kv`/`counter`, `poll`, `ask`).
//! Enforces strict pre-mutation ACL checks before touching files or state.

use std::collections::{BTreeMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use tracing::{info, warn};

use agy_core::error::{BridgeError, Result};
use agy_core::store::UserState;
use agy_core::tg::{TonWalletCard, User};
use agy_ext::engines::ModelInfo;
use agy_ext::mcp_config::{
    get_mcp_server, list_mcp_servers, remove_mcp_server, toggle_mcp_server, update_mcp_server,
    McpServerUpdate, MASKED_SECRET,
};
use agy_ext::memory::{memory_add, memory_overview, memory_remove, VALID_MEMORY_TYPES};
use agy_ext::skills::{
    delete_installed_skill, install_catalog_skill, install_skillport_skill, list_installed_skills,
    list_skillport_skills, search_catalog_skills,
};
use agy_render::md_cell;
use agy_widgets::spec::{encode_widget_data, WidgetData, BUILTIN_WIDGET_KINDS};
use agy_widgets::store::{DataPatch, WidgetStore};
use agy_widgets::webapp::{BridgeActionResponse, BridgeQueryResponse, WidgetBridge};

use crate::ctx::BotCtx;
use crate::jobs::{effective_stream_mode, JobRequest};

/// Default byte budget for compact `chatData` synced onto native Telegram widgets.
pub const COMPACT_CHAT_DATA_MAX_BYTES: usize = 920;

const EFFORTS: &[&str] = &["default", "low", "medium", "high", "xhigh", "max"];
const MODES: &[&str] = &["auto", "accept-edits", "plan"];
const RENDERS: &[&str] = &["rich", "html", "plain"];
const STREAM_MODES: &[&str] = &["semi", "live", "off"];

const PANEL_RICH_KINDS: &[&str] = &[
    "sys", "status", "settings", "sessions", "net", "cron", "panel", "dash",
];

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Result of applying a local `poll_vote` / `vote` or `kv` / `counter` state mutation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WidgetDataActionOutcome {
    pub ok: bool,
    pub result: Value,
    pub chat_data: Option<Value>,
    pub public_data: Option<Value>,
}

/// Concrete [`WidgetBridge`] implementation backed by [`BotCtx`].
pub struct BotWebAppBridge {
    ctx: Arc<BotCtx>,
}

impl BotWebAppBridge {
    /// Wrap a shared [`BotCtx`] in an `Arc<BotWebAppBridge>`.
    pub fn new(ctx: Arc<BotCtx>) -> Arc<Self> {
        Arc::new(Self { ctx })
    }
}

fn now_unix_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

fn truncate_chars(s: &str, max_chars: usize, suffix: &str) -> String {
    if s.chars().count() <= max_chars {
        return s.to_string();
    }
    let keep = max_chars.saturating_sub(suffix.chars().count());
    let prefix: String = s.chars().take(keep).collect();
    format!("{prefix}{suffix}")
}

/// Safely extract an `i64` from an optional JSON value (rejecting booleans).
pub fn safe_i64(val: Option<&Value>, default: i64) -> i64 {
    match val {
        Some(Value::Number(n)) => n
            .as_i64()
            .or_else(|| n.as_u64().and_then(|u| i64::try_from(u).ok()))
            .or_else(|| n.as_f64().map(|f| f as i64))
            .unwrap_or(default),
        Some(Value::String(s)) => s.trim().parse::<i64>().unwrap_or(default),
        _ => default,
    }
}

/// Parse the first non-empty JSON object from `(cur_chat_data, cur_public_data)`.
pub fn parse_cur_state(
    cur_chat_data: Option<&str>,
    cur_public_data: Option<&str>,
) -> Map<String, Value> {
    for raw in [cur_chat_data, cur_public_data].into_iter().flatten() {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(Value::Object(map)) = serde_json::from_str::<Value>(trimmed) {
            return map;
        }
    }
    Map::new()
}

fn compact_json_len(val: &Value) -> usize {
    serde_json::to_string(val).map(|s| s.len()).unwrap_or(usize::MAX)
}

/// Trim a widget state JSON object so its compact UTF-8 encoding stays `<= max_bytes`.
pub fn compact_widget_cd(data: &Value, max_bytes: usize) -> Value {
    let mut out = match data {
        Value::Object(m) => Value::Object(m.clone()),
        _ => return json!({}),
    };
    if compact_json_len(&out) <= max_bytes {
        return out;
    }

    if let Some(map) = out.as_object_mut() {
        for v in map.values_mut() {
            if let Some(arr) = v.as_array_mut() {
                for item in arr.iter_mut() {
                    if let Some(obj) = item.as_object_mut() {
                        for sk in ["desc", "description", "summary", "title"] {
                            if let Some(Value::String(text)) = obj.get_mut(sk) {
                                if text.chars().count() > 42 {
                                    *text = truncate_chars(text, 42, "...");
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    if compact_json_len(&out) <= max_bytes {
        return out;
    }

    while compact_json_len(&out) > max_bytes {
        let biggest_key = out
            .as_object()
            .and_then(|map| {
                map.iter()
                    .filter(|(_, v)| v.as_array().is_some_and(|a| !a.is_empty()))
                    .max_by_key(|(_, v)| compact_json_len(v))
                    .map(|(k, _)| k.clone())
            });
        let Some(key) = biggest_key else {
            break;
        };
        if let Some(arr) = out.get_mut(&key).and_then(Value::as_array_mut) {
            arr.pop();
        }
    }

    if compact_json_len(&out) > max_bytes {
        if let Some(map) = out.as_object_mut() {
            let keys: Vec<String> = map.keys().cloned().collect();
            for k in keys {
                if compact_json_len(&Value::Object(map.clone())) <= max_bytes {
                    break;
                }
                match map.get(&k) {
                    Some(Value::String(s)) if s.chars().count() > 32 => {
                        let clipped = truncate_chars(s, 32, "...");
                        map.insert(k, Value::String(clipped));
                    }
                    Some(Value::Object(sub)) if !sub.is_empty() => {
                        map.insert(k, Value::Object(Map::new()));
                    }
                    _ => {}
                }
            }
        }
    }

    out
}

fn normalize_skill_tab(tab: Option<&str>) -> &'static str {
    match tab.unwrap_or("inst").trim().to_ascii_lowercase().as_str() {
        "skillport" | "sp" => "sp",
        "catalog" | "cat" => "cat",
        _ => "inst",
    }
}

fn build_skills_states(
    ctx: &Arc<BotCtx>,
    uid: i64,
    tab: Option<&str>,
    q: &str,
    page: i64,
) -> (Value, Value) {
    let cur_tab = normalize_skill_tab(tab);
    let q_clean = q.trim();
    let ql = q_clean.to_ascii_lowercase();
    let can_manage = ctx.has_perm(uid, "skills_manage");

    let installed_all = list_installed_skills(&ctx.skills_dir()).unwrap_or_default();
    let skillport_all = list_skillport_skills(
        None,
        None,
        &ctx.cfg.skillport_skills_dir,
        &ctx.skills_dir(),
    )
    .unwrap_or_default();
    let catalog_count = search_catalog_skills(
        "",
        None,
        100_000,
        &ctx.cfg.skills_catalog_json,
        &ctx.skills_dir(),
    )
    .map(|v| v.len())
    .unwrap_or(0);

    let items: Vec<Value> = match cur_tab {
        "inst" => installed_all
            .iter()
            .filter(|s| {
                ql.is_empty()
                    || format!("{} {} {}", s.name, s.description, s.category)
                        .to_ascii_lowercase()
                        .contains(&ql)
            })
            .map(|s| {
                json!({
                    "id": s.name,
                    "slug": s.name,
                    "name": s.name,
                    "desc": truncate_chars(&s.description, 120, ""),
                    "installed": true,
                    "source": "installed",
                })
            })
            .collect(),
        "sp" => {
            let list = if q_clean.is_empty() {
                skillport_all.clone()
            } else {
                list_skillport_skills(
                    None,
                    Some(q_clean),
                    &ctx.cfg.skillport_skills_dir,
                    &ctx.skills_dir(),
                )
                .unwrap_or_default()
            };
            list.into_iter()
                .map(|s| {
                    json!({
                        "id": s.id,
                        "slug": s.name,
                        "name": s.name,
                        "namespace": s.namespace,
                        "desc": truncate_chars(&s.description, 120, ""),
                        "installed": s.installed,
                        "source": "skillport",
                    })
                })
                .collect()
        }
        _ => search_catalog_skills(
            q_clean,
            None,
            24,
            &ctx.cfg.skills_catalog_json,
            &ctx.skills_dir(),
        )
        .unwrap_or_default()
        .into_iter()
        .map(|s| {
            json!({
                "id": s.id,
                "slug": if s.slug.is_empty() { s.name.clone() } else { s.slug },
                "name": s.name,
                "repo": s.repo,
                "desc": truncate_chars(&s.description, 120, ""),
                "installed": s.installed,
                "source": "catalog",
            })
        })
        .collect(),
    };

    let per = 6usize;
    let pages = items.len().div_ceil(per).max(1) as i64;
    let cur_page = page.clamp(0, pages - 1);

    let slim_items: Vec<Value> = items
        .iter()
        .map(|it| {
            let desc = it
                .get("desc")
                .and_then(Value::as_str)
                .unwrap_or("");
            json!({
                "id": it.get("id").cloned().unwrap_or(Value::Null),
                "slug": it.get("slug").cloned().unwrap_or(Value::Null),
                "name": it.get("name").cloned().unwrap_or(Value::Null),
                "source": it.get("source").cloned().unwrap_or(Value::Null),
                "installed": it.get("installed").cloned().unwrap_or(json!(false)),
                "desc": truncate_chars(desc, 36, ""),
            })
        })
        .collect();

    let rich_state = json!({
        "tab": cur_tab,
        "q": q_clean,
        "page": cur_page,
        "can_manage": can_manage,
        "counts": {
            "installed": installed_all.len(),
            "skillport": skillport_all.len(),
            "catalog": catalog_count,
        },
        "items": items,
    });

    let compact_cd = compact_widget_cd(
        &json!({
            "tab": cur_tab,
            "q": q_clean,
            "page": cur_page,
            "can_manage": can_manage,
            "items": slim_items,
        }),
        COMPACT_CHAT_DATA_MAX_BYTES,
    );

    (compact_cd, rich_state)
}

fn build_mcp_states(ctx: &Arc<BotCtx>, uid: i64) -> (Value, Value) {
    let mut srvs = list_mcp_servers(&ctx.cfg.mcp_config_path).unwrap_or_default();
    srvs.sort_by(|a, b| a.name.cmp(&b.name));
    let can_manage = ctx.has_perm(uid, "mcp_manage");

    let mut srv_values = Vec::with_capacity(srvs.len());
    let mut configs = Map::new();
    let mut slim_srvs = Vec::with_capacity(srvs.len());

    for s in &srvs {
        slim_srvs.push(json!({
            "name": s.name,
            "type": s.server_type,
            "enabled": s.enabled,
        }));
        let val = serde_json::to_value(s).unwrap_or_else(|_| {
            json!({
                "name": s.name,
                "type": s.server_type,
                "enabled": s.enabled,
            })
        });
        configs.insert(s.name.clone(), val.clone());
        srv_values.push(val);
    }

    let rich_state = json!({
        "can_manage": can_manage,
        "servers": srv_values,
        "configs": Value::Object(configs),
    });

    let compact_cd = compact_widget_cd(
        &json!({
            "can_manage": can_manage,
            "servers": slim_srvs,
        }),
        COMPACT_CHAT_DATA_MAX_BYTES,
    );

    (compact_cd, rich_state)
}

fn build_models_states(ctx: &Arc<BotCtx>, uid: i64) -> (Value, Value) {
    let u = ctx.store.get_user(uid);
    let models: Vec<ModelInfo> = ctx.models_for_user(uid).1;
    let slim_models: Vec<Value> = models
        .iter()
        .map(|m| {
            let name = if m.name.is_empty() {
                m.id.as_str()
            } else {
                m.name.as_str()
            };
            json!({ "id": m.id, "name": name })
        })
        .collect();

    let rich_state = json!({
        "model": u.model.as_deref().unwrap_or(""),
        "model_name": ctx.model_label(u.model.as_deref()),
        "effort": u.effort.as_deref().filter(|s| !s.is_empty()).unwrap_or("default"),
        "mode": u.mode.as_deref().filter(|s| !s.is_empty()).unwrap_or("auto"),
        "stream_mode": effective_stream_mode(&u),
        "models": slim_models,
    });

    let compact_cd = compact_widget_cd(&rich_state, COMPACT_CHAT_DATA_MAX_BYTES);
    (compact_cd, rich_state)
}

async fn build_memory_states(
    ctx: &Arc<BotCtx>,
    q: &str,
    mem_type: &str,
) -> (Value, Value) {
    let mt_raw = mem_type.trim().to_ascii_lowercase();
    let mt = if VALID_MEMORY_TYPES.contains(&mt_raw.as_str()) {
        mt_raw.as_str()
    } else {
        "all"
    };
    let q_clean = q.trim();
    let bin = ctx.cfg.ai_memory_mcp_bin.to_string_lossy().into_owned();
    let ov = memory_overview(
        &bin,
        q_clean,
        if mt == "all" { None } else { Some(mt) },
        8,
    )
    .await;

    let slim_items: Vec<Value> = ov
        .items
        .iter()
        .take(8)
        .map(|it| {
            let mtype = if it.mtype.is_empty() {
                "fact"
            } else {
                it.mtype.as_str()
            };
            json!({
                "id": truncate_chars(&it.id, 12, ""),
                "type": mtype,
                "title": truncate_chars(&it.title, 60, ""),
            })
        })
        .collect();

    let rich_state = json!({
        "type": mt,
        "q": q_clean,
        "total": ov.total,
        "recent_24h": ov.recent_24h,
        "types": ov.types,
        "items": ov.items,
        "error": ov.error,
    });

    let compact_cd = compact_widget_cd(
        &json!({
            "type": mt,
            "q": q_clean,
            "total": ov.total,
            "recent_24h": ov.recent_24h,
            "items": slim_items,
        }),
        COMPACT_CHAT_DATA_MAX_BYTES,
    );

    (compact_cd, rich_state)
}

/// Build `(compact_chat_data, rich_state)` for any of the 4 official built-in widgets.
pub async fn build_widget_states(
    ctx: &Arc<BotCtx>,
    kind: &str,
    uid: i64,
    tab: Option<&str>,
    q: &str,
    page: i64,
    mem_type: &str,
) -> Result<(Value, Value)> {
    match kind.trim().to_ascii_lowercase().as_str() {
        "skills" => Ok(build_skills_states(ctx, uid, tab, q, page)),
        "mcp" => Ok(build_mcp_states(ctx, uid)),
        "models" => Ok(build_models_states(ctx, uid)),
        "memory" => Ok(build_memory_states(ctx, q, mem_type).await),
        "telemetry" => Ok(Box::pin(crate::handlers_telemetry::build_telemetry_widget_states(ctx, uid, false)).await),
        other => Err(BridgeError::Validation(format!(
            "Unknown built-in widget kind: {other:?}"
        ))),
    }
}

fn build_settings_state(ctx: &Arc<BotCtx>, uid: i64, u: &UserState) -> Value {
    json!({
        "model": u.model.as_deref().unwrap_or(""),
        "model_name": ctx.model_label(u.model.as_deref()),
        "effort": u.effort.as_deref().filter(|s| !s.is_empty()).unwrap_or("default"),
        "mode": u.mode.as_deref().filter(|s| !s.is_empty()).unwrap_or("auto"),
        "stream": u.stream,
        "stream_mode": effective_stream_mode(u),
        "render": u.render,
        "trace": u.trace,
        "cwd": u.cwd,
        "agent": u.agent,
        "skip_permissions": u.skip_permissions,
        "can_root_access": ctx.has_perm(uid, "root_access"),
        "can_sandbox_exec": ctx.has_perm(uid, "root_access") || ctx.has_perm(uid, "sandbox_exec"),
    })
}

fn build_sessions_state(ctx: &Arc<BotCtx>, uid: i64, u: &UserState) -> Value {
    let active = ctx.jobs.active_job_info(uid).map(|info| {
        json!({
            "req_id": info.req_id,
            "chat_id": info.chat_id,
            "prompt": truncate_chars(&info.prompt, 120, "..."),
            "elapsed_s": info.started.elapsed().as_secs(),
        })
    });
    json!({
        "conversation_id": u.conversation_id,
        "history": u.history,
        "active_job": active,
    })
}

fn build_net_state(ctx: &Arc<BotCtx>) -> Value {
    let pool_snap = ctx.pool.snapshot();
    let health_snap = ctx.health.snapshot();
    json!({
        "mode": pool_snap.mode,
        "active_healthy": pool_snap.active_healthy,
        "total_rebuilds": pool_snap.total_rebuilds,
        "routes": pool_snap.routes,
        "polling": {
            "mode": health_snap.mode,
            "stall_s": health_snap.stall_s,
            "updates": health_snap.updates,
            "poll_failures": health_snap.poll_failures,
            "total_poll_failures": health_snap.total_poll_failures,
        },
    })
}

fn build_cron_state(ctx: &Arc<BotCtx>) -> Value {
    json!({
        "summary": ctx.cron.summary_json(),
        "jobs": ctx.cron.list_jobs(),
    })
}

fn build_sys_state(ctx: &Arc<BotCtx>, uid: i64) -> Value {
    let mut base = ctx.sys_snapshot(uid);
    if let Some(map) = base.as_object_mut() {
        map.insert("active_jobs".to_string(), json!(ctx.jobs.active_count()));
        map.insert("user_busy".to_string(), json!(ctx.jobs.is_user_busy(uid)));
        if let Some(mh) = ctx.cron.cached_mcp_health() {
            map.insert("mcp_health".to_string(), json!(mh));
        }
        if let Some(mc) = ctx.cron.cached_memory_summary() {
            map.insert("memory_cache".to_string(), json!(mc));
        }
        map.insert("cron".to_string(), ctx.cron.summary_json());
    }
    base
}

/// Build rich state for a built-in widget kind (`skills`, `mcp`, `models`, `memory`)
/// or panel subsystem (`sys`, `status`, `settings`, `sessions`, `net`, `cron`, `panel`, `dash`).
pub async fn build_rich_state(
    ctx: &Arc<BotCtx>,
    kind: Option<&str>,
    uid: i64,
) -> Result<Value> {
    let k = kind.unwrap_or("panel").trim().to_ascii_lowercase();
    let eff = if k.is_empty() { "panel" } else { k.as_str() };

    if BUILTIN_WIDGET_KINDS.contains(&eff) {
        let (_, rich) = build_widget_states(ctx, eff, uid, None, "", 0, "all").await?;
        return Ok(rich);
    }

    match eff {
        "sys" | "status" => {
            if !ctx.has_perm(uid, "status_net") {
                return Ok(json!({ "ok": false, "denied": true, "perm": "status_net" }));
            }
            Ok(build_sys_state(ctx, uid))
        }
        "settings" => {
            if !ctx.has_perm(uid, "settings_access") {
                return Ok(json!({ "ok": false, "denied": true, "perm": "settings_access" }));
            }
            let u = ctx.store.get_user(uid);
            Ok(build_settings_state(ctx, uid, &u))
        }
        "sessions" => {
            if !ctx.has_perm(uid, "dashboard_access") {
                return Ok(json!({ "ok": false, "denied": true, "perm": "dashboard_access" }));
            }
            let u = ctx.store.get_user(uid);
            Ok(build_sessions_state(ctx, uid, &u))
        }
        "net" => {
            if !ctx.has_perm(uid, "status_net") {
                return Ok(json!({ "ok": false, "denied": true, "perm": "status_net" }));
            }
            Ok(build_net_state(ctx))
        }
        "cron" => {
            if !ctx.has_perm(uid, "status_net") {
                return Ok(json!({ "ok": false, "denied": true, "perm": "status_net" }));
            }
            Ok(build_cron_state(ctx))
        }
        "panel" | "dash" => {
            if !ctx.has_perm(uid, "dashboard_access") {
                return Ok(json!({ "ok": false, "denied": true, "perm": "dashboard_access" }));
            }
            let u = ctx.store.get_user(uid);
            let mut out = json!({ "uid": uid });
            if let Some(map) = out.as_object_mut() {
                if ctx.has_perm(uid, "status_net") {
                    map.insert("sys".into(), build_sys_state(ctx, uid));
                    map.insert("net".into(), build_net_state(ctx));
                    map.insert("cron".into(), build_cron_state(ctx));
                }
                if ctx.has_perm(uid, "settings_access") {
                    map.insert("settings".into(), build_settings_state(ctx, uid, &u));
                }
                map.insert("sessions".into(), build_sessions_state(ctx, uid, &u));
                if ctx.has_perm(uid, "models_switch") {
                    map.insert("models".into(), build_models_states(ctx, uid).1);
                }
                if ctx.has_perm(uid, "mcp_manage") {
                    map.insert("mcp".into(), build_mcp_states(ctx, uid).1);
                }
                if ctx.has_perm(uid, "skills_manage") {
                    map.insert("skills".into(), build_skills_states(ctx, uid, None, "", 0).1);
                }
            }
            Ok(out)
        }
        _ => Ok(Value::Null),
    }
}

fn resolve_vote_option_and_count(
    ctx: &Arc<BotCtx>,
    wid: &str,
    action_data: &Value,
    chat_data_raw: Option<&str>,
    public_data_raw: Option<&str>,
) -> Result<(usize, usize)> {
    let idx_val = action_data
        .get("idx")
        .or_else(|| action_data.get("option"))
        .or_else(|| action_data.get("choice"))
        .or_else(|| action_data.get("index"));

    let option_idx = match idx_val {
        Some(Value::Number(n)) => n
            .as_u64()
            .and_then(|u| usize::try_from(u).ok())
            .ok_or_else(|| BridgeError::Validation("Invalid negative or overflow vote index".to_string()))?,
        Some(Value::String(s)) => s
            .trim()
            .parse::<usize>()
            .map_err(|_| BridgeError::Validation(format!("Invalid vote index: {s:?}")))?,
        _ => {
            if let Some(cmd) = action_data.as_str().or_else(|| action_data.get("cmd").and_then(Value::as_str)) {
                let tail = cmd
                    .strip_prefix("poll:vote:")
                    .or_else(|| cmd.strip_prefix("vote:"))
                    .unwrap_or(cmd);
                tail.trim()
                    .parse::<usize>()
                    .map_err(|_| BridgeError::Validation(format!("Invalid vote command: {cmd:?}")))?
            } else {
                return Err(BridgeError::Validation("Missing vote option index".to_string()));
            }
        }
    };

    let explicit_count = action_data
        .get("num_options")
        .and_then(Value::as_u64)
        .and_then(|u| usize::try_from(u).ok())
        .or_else(|| {
            action_data
                .get("options")
                .or_else(|| action_data.get("opts"))
                .and_then(Value::as_array)
                .map(Vec::len)
        });

    let existing_opts_count = || -> Option<usize> {
        let resolved_id = ctx
            .widgets
            .resolve_widget_id(wid)
            .unwrap_or_else(|| wid.to_string());
        if let Some(v) = ctx.widgets.snapshot().votes.get(&resolved_id) {
            if !v.opts.is_empty() {
                return Some(v.opts.len());
            }
        }
        let st = parse_cur_state(public_data_raw, chat_data_raw);
        st.get("opts")
            .or_else(|| st.get("options"))
            .and_then(Value::as_array)
            .map(Vec::len)
            .filter(|&n| n > 0)
    };

    let num_options = explicit_count
        .or_else(existing_opts_count)
        .unwrap_or_else(|| option_idx.saturating_add(1).max(2));

    Ok((option_idx, num_options))
}

fn build_kv_query_string(action_data: &Value) -> Result<String> {
    if let Some(raw) = action_data.as_str() {
        return Ok(raw.to_string());
    }
    if let Some(cmd) = action_data
        .get("cmd")
        .or_else(|| action_data.get("query"))
        .or_else(|| action_data.get("data"))
        .and_then(Value::as_str)
    {
        return Ok(cmd.to_string());
    }
    let op = action_data
        .get("op")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let act = action_data
        .get("action")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let key = action_data.get("key").and_then(Value::as_str).unwrap_or("");

    if act == "counter" || op == "inc" || op == "dec" || op == "reset" {
        return match op.as_str() {
            "dec" => Ok("counter:dec".to_string()),
            "reset" => Ok("counter:reset".to_string()),
            "inc" | "" => Ok("counter:inc".to_string()),
            other => Err(BridgeError::Validation(format!(
                "Unsupported counter op: {other:?}"
            ))),
        };
    }

    if matches!(op.as_str(), "del" | "delete" | "unset") && !key.is_empty() {
        return Ok(format!("kv:del:{key}"));
    }
    if op == "get" {
        return Ok("kv:get".to_string());
    }
    if !key.is_empty() {
        let val_str = match action_data.get("value") {
            Some(Value::String(s)) => s.clone(),
            Some(Value::Null) | None => {
                if op == "del" {
                    return Ok(format!("kv:del:{key}"));
                }
                String::new()
            }
            Some(other) => other.to_string(),
        };
        return Ok(format!("kv:set:{key}={val_str}"));
    }

    Err(BridgeError::Validation(
        "Missing kv key/value or command string".to_string(),
    ))
}

fn sync_shared_poll_state(ctx: &Arc<BotCtx>, wid: &str, pd_val: &Value) {
    let encoded = match encode_widget_data(Some(WidgetData::Value(pd_val)), true) {
        Ok(Some(s)) => s,
        _ => return,
    };
    let vote_key = ctx
        .widgets
        .get_webapp_widget(wid)
        .and_then(|r| r.shared_widget_id)
        .unwrap_or_else(|| wid.to_string());

    if ctx.widgets.get_shared(&vote_key).is_some()
        || ctx
            .widgets
            .get_webapp_widget(wid)
            .is_some_and(|r| r.is_shared)
    {
        let _ = ctx
            .widgets
            .update_shared_state(&vote_key, Some(WidgetData::Str(&encoded)), None);
        for target_wid in ctx.widgets.find_shared_targets(&vote_key) {
            let _ = ctx.widgets.update_webapp_widget_state(
                &target_wid,
                DataPatch::Unchanged,
                DataPatch::Set(WidgetData::Str(&encoded)),
                None,
            );
        }
    } else if ctx.widgets.get_webapp_widget(wid).is_some() {
        let _ = ctx.widgets.update_webapp_widget_state(
            wid,
            DataPatch::Unchanged,
            DataPatch::Set(WidgetData::Str(&encoded)),
            None,
        );
    }
}

/// Apply `vote` / `poll_vote` or `kv` / `counter` state mutations, persisting updated
/// state into [`WidgetStore`] and returning the bumped `(chat_data, public_data)`.
pub fn apply_widget_data_action(
    ctx: &Arc<BotCtx>,
    wid: &str,
    uid: i64,
    chat_data_raw: Option<&str>,
    public_data_raw: Option<&str>,
    action_data: &Value,
) -> Result<WidgetDataActionOutcome> {
    let act_raw = action_data
        .get("action")
        .and_then(Value::as_str)
        .or_else(|| action_data.as_str())
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();

    let is_vote = matches!(act_raw.as_str(), "vote" | "poll_vote" | "poll")
        || act_raw.starts_with("vote:")
        || act_raw.starts_with("poll:");

    if is_vote {
        let (option_idx, num_options) =
            resolve_vote_option_and_count(ctx, wid, action_data, chat_data_raw, public_data_raw)?;
        let vote_res = ctx.widgets.record_vote(wid, uid, option_idx, num_options)?;
        let pd_val = serde_json::to_value(&vote_res)
            .map_err(|e| BridgeError::json("serialize vote result", e))?;
        sync_shared_poll_state(ctx, wid, &pd_val);
        return Ok(WidgetDataActionOutcome {
            ok: true,
            result: pd_val.clone(),
            chat_data: None,
            public_data: Some(pd_val),
        });
    }

    let kv_cmd = build_kv_query_string(action_data)?;
    let cur = chat_data_raw.or(public_data_raw);
    let (encoded, obj) = WidgetStore::apply_kv_mutation(cur.map(WidgetData::Str), &kv_cmd)?;

    if ctx.widgets.get_webapp_widget(wid).is_some() {
        let _ = ctx.widgets.update_webapp_widget_state(
            wid,
            DataPatch::Set(WidgetData::Str(&encoded)),
            DataPatch::Unchanged,
            None,
        );
    }

    Ok(WidgetDataActionOutcome {
        ok: true,
        result: obj.clone(),
        chat_data: Some(obj),
        public_data: None,
    })
}

async fn enqueue_widget_prompt(
    ctx: &Arc<BotCtx>,
    uid: i64,
    chat_id: i64,
    from_user: &User,
    text: String,
) -> bool {
    let req = JobRequest::new(uid, chat_id, from_user.display_label(), text, Vec::new());
    ctx.jobs.enqueue(req).await.is_ok()
}

/// Dispatch a Bot API 10.4 widget query string (`sk:*`, `mcp:*`, `mdl:*`, `mem:*`,
/// `counter:*`, `kv:*`, `vote:*`, `poll:*`, `ask:*`, `agy:*`, `ping`, `sys`, `refresh`)
/// and return `(payload, new_chat_data, new_public_data)`.
#[allow(clippy::too_many_arguments)]
pub async fn execute_widget_data_action(
    ctx: &Arc<BotCtx>,
    uid: i64,
    chat_id: i64,
    from_user: &User,
    raw_data: &str,
    handler_name: &str,
    cur_chat_data: Option<&str>,
    cur_public_data: Option<&str>,
    vote_key: &str,
    _wallet_card: Option<&TonWalletCard>,
    q_wid: Option<&str>,
    q_mid: Option<i64>,
) -> (Value, Option<Value>, Option<Value>) {
    let h_low = handler_name.trim().to_ascii_lowercase();
    let st = parse_cur_state(cur_chat_data, cur_public_data);

    if raw_data == "ping" {
        return (
            json!({
                "ok": true,
                "pong": true,
                "wid": q_wid,
                "ts": now_unix_secs(),
            }),
            None,
            None,
        );
    }

    if raw_data == "sys" || raw_data == "sys:refresh" || raw_data == "status" {
        let sys_val = build_sys_state(ctx, uid);
        let cd = compact_widget_cd(&sys_val, COMPACT_CHAT_DATA_MAX_BYTES);
        return (sys_val, Some(cd), None);
    }

    if raw_data == "poll" {
        let resolved = ctx
            .widgets
            .resolve_widget_id(vote_key)
            .unwrap_or_else(|| vote_key.to_string());
        if let Some(vote) = ctx.widgets.snapshot().votes.get(&resolved).cloned() {
            return (json!({ "ok": true, "poll": vote }), None, None);
        }
        return (
            json!({ "ok": true, "poll": Value::Object(parse_cur_state(cur_public_data, cur_chat_data)) }),
            None,
            None,
        );
    }

    if raw_data.starts_with("vote:") || raw_data.starts_with("poll:vote:") {
        match apply_widget_data_action(
            ctx,
            vote_key,
            uid,
            cur_chat_data,
            cur_public_data,
            &Value::String(raw_data.to_string()),
        ) {
            Ok(out) => return (out.result, out.chat_data, out.public_data),
            Err(err) => return (json!({ "ok": false, "error": err.to_string() }), None, None),
        }
    }

    if raw_data == "refresh" && PANEL_RICH_KINDS.contains(&h_low.as_str()) {
        match build_rich_state(ctx, Some(&h_low), uid).await {
            Ok(val) => {
                let cd = compact_widget_cd(&val, COMPACT_CHAT_DATA_MAX_BYTES);
                return (val, Some(cd), None);
            }
            Err(err) => return (json!({ "ok": false, "error": err.to_string() }), None, None),
        }
    }

    let is_special_prefix = |p: &str| {
        raw_data.starts_with(p)
    };
    let has_other_prefix = is_special_prefix("sk:")
        || is_special_prefix("mcp:")
        || is_special_prefix("mdl:")
        || is_special_prefix("mem:")
        || is_special_prefix("tel:")
        || is_special_prefix("counter:")
        || is_special_prefix("kv:")
        || is_special_prefix("ask:")
        || is_special_prefix("agy:");

    if raw_data.starts_with("sk:") || (h_low == "skills" && !has_other_prefix) {
        let mut cur_tab = st
            .get("tab")
            .and_then(Value::as_str)
            .unwrap_or("inst")
            .to_string();
        let cur_q = st
            .get("q")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let mut cur_page = safe_i64(st.get("page"), 0);
        let items = st.get("items").and_then(Value::as_array);

        if let Some(t) = raw_data.strip_prefix("sk:t:") {
            cur_tab = if t.is_empty() {
                "inst".to_string()
            } else {
                t.to_string()
            };
            cur_page = 0;
        } else if raw_data == "sk:p:prev" {
            cur_page = (cur_page - 1).max(0);
        } else if raw_data == "sk:p:next" {
            cur_page += 1;
        } else if let Some(tail) = raw_data.strip_prefix("sk:del:") {
            if !ctx.has_perm(uid, "skills_manage") {
                return (
                    json!({ "ok": false, "error": "Permission denied: skills_manage" }),
                    None,
                    None,
                );
            }
            let name = if let Ok(idx) = tail.parse::<usize>() {
                items
                    .and_then(|arr| arr.get(idx))
                    .and_then(|it| {
                        it.get("name")
                            .or_else(|| it.get("slug"))
                            .or_else(|| it.get("id"))
                            .and_then(Value::as_str)
                    })
                    .unwrap_or(tail)
                    .to_string()
            } else {
                tail.to_string()
            };
            if let Err(err) = delete_installed_skill(&name, &ctx.skills_dir()) {
                return (json!({ "ok": false, "error": err.to_string() }), None, None);
            }
        } else if let Some(tail) = raw_data.strip_prefix("sk:in:") {
            if !ctx.has_perm(uid, "skills_manage") {
                return (
                    json!({ "ok": false, "error": "Permission denied: skills_manage" }),
                    None,
                    None,
                );
            }
            let Ok(idx) = tail.parse::<usize>() else {
                return (json!({ "ok": false, "error": "Skill not found" }), None, None);
            };
            let Some(it) = items.and_then(|arr| arr.get(idx)).filter(|v| v.is_object()) else {
                return (json!({ "ok": false, "error": "Skill not found" }), None, None);
            };
            let src = it
                .get("source")
                .and_then(Value::as_str)
                .unwrap_or(if cur_tab == "sp" { "skillport" } else { "catalog" })
                .to_ascii_lowercase();
            let res = if src == "skillport" {
                let id = it
                    .get("id")
                    .or_else(|| it.get("name"))
                    .and_then(Value::as_str)
                    .unwrap_or("");
                install_skillport_skill(id, &ctx.cfg.skillport_skills_dir, &ctx.skills_dir())
            } else {
                let id = it.get("id").and_then(Value::as_str).unwrap_or("");
                let slug = it.get("slug").and_then(Value::as_str);
                let cat_bin = ctx.cfg.skills_catalog_mcp_bin.to_string_lossy().into_owned();
                install_catalog_skill(id, slug, &ctx.skills_dir(), &cat_bin, 30.0).await
            };
            if let Err(err) = res {
                return (json!({ "ok": false, "error": err.to_string() }), None, None);
            }
        }

        let (compact_cd, mut rich) =
            build_skills_states(ctx, uid, Some(&cur_tab), &cur_q, cur_page.max(0));
        if let Some(m) = rich.as_object_mut() {
            m.insert("ok".to_string(), json!(true));
        }
        return (rich, Some(compact_cd), None);
    }

    if raw_data.starts_with("mcp:") || (h_low == "mcp" && !has_other_prefix) {
        if let Some(tail) = raw_data.strip_prefix("mcp:t:") {
            if !ctx.has_perm(uid, "mcp_manage") {
                return (
                    json!({ "ok": false, "error": "Permission denied: mcp_manage" }),
                    None,
                    None,
                );
            }
            let mut srvs_cur = list_mcp_servers(&ctx.cfg.mcp_config_path).unwrap_or_default();
            srvs_cur.sort_by(|a, b| a.name.cmp(&b.name));
            let srv_name = if let Ok(idx) = tail.parse::<usize>() {
                if let Some(s) = srvs_cur.get(idx) {
                    s.name.clone()
                } else if let Some(s) = st
                    .get("servers")
                    .and_then(Value::as_array)
                    .and_then(|arr| arr.get(idx))
                    .and_then(|v| v.get("name"))
                    .and_then(Value::as_str)
                {
                    s.to_string()
                } else {
                    return (
                        json!({ "ok": false, "error": "MCP server not found" }),
                        None,
                        None,
                    );
                }
            } else {
                tail.to_string()
            };
            if let Err(err) = toggle_mcp_server(&ctx.cfg.mcp_config_path, &srv_name, None) {
                return (json!({ "ok": false, "error": err.to_string() }), None, None);
            }
        }

        let (compact_cd, mut rich) = build_mcp_states(ctx, uid);
        if let Some(m) = rich.as_object_mut() {
            m.insert("ok".to_string(), json!(true));
        }
        return (rich, Some(compact_cd), None);
    }

    if raw_data.starts_with("mdl:") || (h_low == "models" && !has_other_prefix) {
        let is_setting_action = raw_data.starts_with("mdl:eff:")
            || raw_data.starts_with("mdl:e:")
            || raw_data.starts_with("mdl:m:")
            || raw_data.starts_with("mdl:st:");
        let is_model_action = raw_data == "mdl:def"
            || raw_data.starts_with("mdl:sid:")
            || raw_data.starts_with("mdl:s:")
            || raw_data == "mdl:ref";
        if is_setting_action && !ctx.has_perm(uid, "settings_access") {
            return (
                json!({ "ok": false, "error": "Permission denied: settings_access" }),
                None,
                None,
            );
        }
        if is_model_action && !ctx.has_perm(uid, "models_switch") {
            return (
                json!({ "ok": false, "error": "Permission denied: models_switch" }),
                None,
                None,
            );
        }
        let ms = ctx.models_for_user(uid).1;
        if raw_data == "mdl:def" {
            let _ = ctx.store.update_user(uid, |u| {
                u.model = None;
            });
        } else if let Some(id) = raw_data.strip_prefix("mdl:sid:") {
            if ms.iter().any(|m| m.id == id) {
                let mid = id.to_string();
                let _ = ctx.store.update_user(uid, |u| {
                    u.model = Some(mid);
                });
            }
        } else if let Some(tail) = raw_data.strip_prefix("mdl:s:") {
            if let Ok(idx) = tail.parse::<usize>() {
                if let Some(m) = ms.get(idx) {
                    let mid = m.id.clone();
                    let _ = ctx.store.update_user(uid, |u| {
                        u.model = Some(mid);
                    });
                }
            }
        } else if let Some(val) = raw_data
            .strip_prefix("mdl:eff:")
            .or_else(|| raw_data.strip_prefix("mdl:e:"))
        {
            if EFFORTS.contains(&val) {
                let eff_opt = if val == "default" {
                    None
                } else {
                    Some(val.to_string())
                };
                let _ = ctx.store.update_user(uid, |u| {
                    u.effort = eff_opt;
                });
            }
        } else if let Some(val) = raw_data.strip_prefix("mdl:m:") {
            if MODES.contains(&val) {
                let mode_opt = if val == "auto" {
                    None
                } else {
                    Some(val.to_string())
                };
                let _ = ctx.store.update_user(uid, |u| {
                    u.mode = mode_opt;
                });
            }
        } else if let Some(val) = raw_data.strip_prefix("mdl:st:") {
            if STREAM_MODES.contains(&val) {
                let sm = val.to_string();
                let _ = ctx.store.update_user(uid, |u| {
                    u.stream_mode = sm;
                    u.stream = val != "off";
                });
            }
        } else if raw_data == "mdl:ref" {
            let _ = ctx.refresh_models_for_user(uid).await;
        }

        let (compact_cd, mut rich) = build_models_states(ctx, uid);
        if let Some(m) = rich.as_object_mut() {
            m.insert("ok".to_string(), json!(true));
        }
        return (rich, Some(compact_cd), None);
    }

    if raw_data.starts_with("mem:") || (h_low == "memory" && !has_other_prefix) {
        let mut cur_type = st
            .get("type")
            .or_else(|| st.get("filter"))
            .and_then(Value::as_str)
            .unwrap_or("all")
            .to_string();
        let cur_q = st
            .get("q")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();

        if let Some(f) = raw_data.strip_prefix("mem:f:") {
            cur_type = if f.is_empty() {
                "all".to_string()
            } else {
                f.to_string()
            };
        } else if let Some(tail) = raw_data.strip_prefix("mem:d:") {
            if !ctx.is_owner(uid) {
                return (
                    json!({ "ok": false, "error": "Owner permission required" }),
                    None,
                    None,
                );
            }
            let items = st.get("items").and_then(Value::as_array);
            let mem_id = if let Ok(idx) = tail.parse::<usize>() {
                match items.and_then(|arr| arr.get(idx)) {
                    Some(it) => it
                        .get("id")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                    None => {
                        return (
                            json!({ "ok": false, "error": "Memory item not found" }),
                            None,
                            None,
                        );
                    }
                }
            } else {
                tail.to_string()
            };
            let bin = ctx.cfg.ai_memory_mcp_bin.to_string_lossy().into_owned();
            if let Err(err) = memory_remove(&bin, &mem_id).await {
                return (json!({ "ok": false, "error": err.to_string() }), None, None);
            }
        }

        let (compact_cd, mut rich) = build_memory_states(ctx, &cur_q, &cur_type).await;
        if let Some(m) = rich.as_object_mut() {
            m.insert("ok".to_string(), json!(true));
        }
        return (rich, Some(compact_cd), None);
    }

    if raw_data.starts_with("tel:") || (h_low == "telemetry" && !has_other_prefix) {
        if !ctx.is_owner(uid) {
            return (
                json!({ "ok": false, "error": "Owner permission required" }),
                None,
                None,
            );
        }
        let mut force = raw_data == "tel:ref";
        if let Some(eng) = raw_data.strip_prefix("tel:sw:") {
            let eng = eng.trim();
            if matches!(eng, "agy" | "grok" | "gemini_web" | "uncensored") {
                let _ = ctx.store.update_user(uid, |u| {
                    if eng == "agy" {
                        u.extra.remove("engine");
                        if u.model.as_deref().is_some_and(|m| {
                            agy_ext::grok_oauth::is_grok_model(m)
                                || agy_ext::uncensored::is_uncensored_model(m)
                        }) {
                            u.model = None;
                        }
                    } else {
                        u.extra.insert("engine".to_string(), json!(eng));
                    }
                });
                force = false;
            }
        }
        let (compact_cd, mut rich) =
            Box::pin(crate::handlers_telemetry::build_telemetry_widget_states(ctx, uid, force)).await;
        if let Some(m) = rich.as_object_mut() {
            m.insert("ok".to_string(), json!(true));
        }
        return (rich, Some(compact_cd), None);
    }

    if raw_data.starts_with("counter:")
        || raw_data.starts_with("kv:")
        || matches!(h_low.as_str(), "kv" | "counter")
    {
        let cur = cur_chat_data.or(cur_public_data);
        match WidgetStore::apply_kv_mutation(cur.map(WidgetData::Str), raw_data) {
            Ok((_encoded, obj)) => return (obj.clone(), Some(obj), None),
            Err(err) => return (json!({ "ok": false, "error": err.to_string() }), None, None),
        }
    }

    if raw_data.starts_with("ask:") || raw_data.starts_with("agy:") || h_low == "agy" {
        let prompt = raw_data
            .strip_prefix("ask:")
            .or_else(|| raw_data.strip_prefix("agy:"))
            .unwrap_or(raw_data)
            .trim();
        let mut queued = false;
        if !prompt.is_empty() {
            let wid_lbl = q_wid.filter(|s| !s.is_empty()).unwrap_or("-");
            let mid_lbl = q_mid
                .map(|m| m.to_string())
                .unwrap_or_else(|| "-".to_string());
            let body = format!("[widget_query widget_id={wid_lbl} msg_id={mid_lbl}] {prompt}");
            queued = enqueue_widget_prompt(ctx, uid, chat_id, from_user, body).await;
        }
        return (
            json!({ "ok": true, "queued": queued, "ts": now_unix_secs() }),
            None,
            None,
        );
    }

    (
        json!({
            "ok": true,
            "echo": truncate_chars(raw_data, 200, ""),
            "ts": now_unix_secs(),
        }),
        None,
        None,
    )
}

fn acl_user_label(ctx: &BotCtx, uid: i64) -> String {
    let Some(u) = ctx.acl.get_user(uid) else {
        return uid.to_string();
    };
    let full = match (&u.first_name, &u.last_name) {
        (Some(f), Some(l)) => format!("{f} {l}").trim().to_string(),
        (Some(f), None) => f.trim().to_string(),
        (None, Some(l)) => l.trim().to_string(),
        (None, None) => String::new(),
    };
    match &u.username {
        Some(un) if !un.is_empty() && !full.is_empty() => format!("{full} (@{un})"),
        Some(un) if !un.is_empty() => format!("@{un}"),
        _ if !full.is_empty() => full,
        _ => uid.to_string(),
    }
}

async fn submit_mcp_ai_request(
    ctx: &Arc<BotCtx>,
    uid: i64,
    chat_id: i64,
    spec_text: &str,
) -> Result<agy_core::acl::McpRequest> {
    let label = acl_user_label(ctx, uid);
    let req = ctx
        .acl
        .create_mcp_request(uid, &label, chat_id, spec_text.trim())?;
    let spec_safe = truncate_chars(&req.spec_text, 1500, "").replace('`', "'");
    let md = [
        format!("### {} درخواست نصب MCP با AI", ctx.premium.md("rocket")),
        String::new(),
        "| فیلد | مقدار |".to_string(),
        "|---|---|".to_string(),
        format!("| شناسه | `{}` |", md_cell(&req.req_id)),
        format!(
            "| درخواست‌کننده | {} (`{}`) |",
            md_cell(&label),
            uid
        ),
        String::new(),
        "<details><summary>مشخصات درخواستی</summary>".to_string(),
        spec_safe,
        "</details>".to_string(),
    ]
    .join("\n");

    let markup = BotCtx::kb(vec![vec![
        ctx.btn(
            "ok",
            "تایید و نصب",
            Some(&format!("mcp:rok:{}", req.req_id)),
            Some("success"),
            None,
        ),
        ctx.btn(
            "err",
            "رد",
            Some(&format!("mcp:rno:{}", req.req_id)),
            Some("danger"),
            None,
        ),
    ]]);

    ctx.broadcast_owners_rich(&md, Some(markup)).await;
    Ok(req)
}

fn json_str(p: &Value, keys: &[&str]) -> Option<String> {
    for k in keys {
        if let Some(s) = p.get(*k).and_then(Value::as_str) {
            let trimmed = s.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

fn json_str_or_empty(p: &Value, key: &str) -> String {
    p.get(key)
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string()
}

fn value_to_arg_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        other => other.to_string(),
    }
}

fn normalize_mcp_update_patch(
    ctx: &Arc<BotCtx>,
    name: &str,
    p: &Value,
) -> Result<McpServerUpdate> {
    let cmd_val = p
        .get("command")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    let url_val = p
        .get("url")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    let mut args_val: Option<Vec<String>> = None;
    if let Some(raw_args) = p.get("args") {
        if let Some(arr) = raw_args.as_array() {
            let cleaned: Vec<String> = arr
                .iter()
                .map(value_to_arg_string)
                .filter(|s| !s.is_empty())
                .collect();
            if cmd_val.is_some() {
                args_val = Some(cleaned);
            } else if !cleaned.is_empty() {
                if let Ok(Some(cur)) = get_mcp_server(&ctx.cfg.mcp_config_path, name) {
                    if !cur.command.is_empty() {
                        args_val = Some(cleaned);
                    }
                }
            }
        } else if let Some(s) = raw_args.as_str() {
            let trimmed = s.trim();
            if !trimmed.is_empty() && cmd_val.is_some() {
                args_val = Some(
                    shell_words::split(trimmed)
                        .map_err(|err| BridgeError::Validation(err.to_string()))?,
                );
            }
        }
    }

    let env_set = p.get("env_set").and_then(Value::as_object).map(|obj| {
        obj.iter()
            .map(|(k, v)| {
                let raw = value_to_arg_string(v);
                let normalized = if raw == "•••" {
                    MASKED_SECRET.to_string()
                } else {
                    raw
                };
                (k.clone(), normalized)
            })
            .collect::<BTreeMap<String, String>>()
    });

    let env_unset = p.get("env_unset").and_then(Value::as_array).map(|arr| {
        arr.iter()
            .map(value_to_arg_string)
            .filter(|s| !s.is_empty())
            .collect::<Vec<String>>()
    });

    let enabled = p.get("enabled").and_then(Value::as_bool);

    Ok(McpServerUpdate {
        command: cmd_val,
        args: args_val,
        url: url_val,
        env_set,
        env_unset,
        enabled,
    })
}

fn cycle_next<'a>(choices: &[&'a str], current: &str) -> &'a str {
    let idx = choices
        .iter()
        .position(|&c| c.eq_ignore_ascii_case(current))
        .unwrap_or(0);
    choices[(idx + 1) % choices.len()]
}

async fn handle_settings_toggle(ctx: &Arc<BotCtx>, uid: i64, p: &Value) -> BridgeActionResponse {
    if !ctx.has_perm(uid, "settings_access") {
        return BridgeActionResponse::rejected(403, "Permission denied: settings_access");
    }

    let Some(key) = json_str(p, &["key", "setting", "field"]) else {
        return BridgeActionResponse::rejected(400, "Missing setting key");
    };
    let k_low = key.to_ascii_lowercase();

    if matches!(k_low.as_str(), "skip_permissions" | "skip_perms" | "yolo")
        && !ctx.has_perm(uid, "root_access")
    {
        return BridgeActionResponse::rejected(403, "Permission denied: root_access");
    }

    let explicit_bool = p.get("value").and_then(Value::as_bool);
    let explicit_str = p
        .get("value")
        .and_then(Value::as_str)
        .map(str::trim)
        .map(str::to_ascii_lowercase);

    let update_res = ctx.store.try_update_user(uid, |u| match k_low.as_str() {
        "skip_permissions" | "skip_perms" | "yolo" => {
            u.skip_permissions = explicit_bool.unwrap_or(!u.skip_permissions);
            Ok(json!(u.skip_permissions))
        }
        "trace" => {
            u.trace = explicit_bool.unwrap_or(!u.trace);
            Ok(json!(u.trace))
        }
        "stream" => {
            u.stream = explicit_bool.unwrap_or(!u.stream);
            if u.stream && u.stream_mode == "off" {
                u.stream_mode = "semi".to_string();
            } else if !u.stream {
                u.stream_mode = "off".to_string();
            }
            Ok(json!(u.stream))
        }
        "render" => {
            let target = match explicit_str.as_deref() {
                Some(v) if RENDERS.contains(&v) => v,
                Some(bad) => {
                    return Err(BridgeError::Validation(format!(
                        "Invalid render mode: {bad}"
                    )));
                }
                None => cycle_next(RENDERS, &u.render),
            };
            u.render = target.to_string();
            Ok(json!(u.render))
        }
        "mode" => {
            let cur = u.mode.as_deref().unwrap_or("auto");
            let target = match explicit_str.as_deref() {
                Some(v) if MODES.contains(&v) => v,
                Some(bad) => {
                    return Err(BridgeError::Validation(format!("Invalid mode: {bad}")));
                }
                None => cycle_next(MODES, cur),
            };
            u.mode = if target == "auto" {
                None
            } else {
                Some(target.to_string())
            };
            Ok(json!(target))
        }
        "effort" => {
            let cur = u.effort.as_deref().unwrap_or("default");
            let target = match explicit_str.as_deref() {
                Some(v) if EFFORTS.contains(&v) => v,
                Some(bad) => {
                    return Err(BridgeError::Validation(format!("Invalid effort: {bad}")));
                }
                None => cycle_next(EFFORTS, cur),
            };
            u.effort = if target == "default" {
                None
            } else {
                Some(target.to_string())
            };
            Ok(json!(target))
        }
        other => Err(BridgeError::Validation(format!(
            "Unsupported setting key: {other}"
        ))),
    });

    match update_res {
        Ok(val) => {
            let u = ctx.store.get_user(uid);
            let settings_val = build_settings_state(ctx, uid, &u);
            let mut resp = BridgeActionResponse::ok(json!({
                "ok": true,
                "key": k_low,
                "value": val,
                "settings": settings_val,
            }));
            resp.rich_state = Some(settings_val);
            resp
        }
        Err(err) => BridgeActionResponse::rejected(400, err.to_string()),
    }
}

async fn handle_action_impl(
    ctx: &Arc<BotCtx>,
    wid: &str,
    _kind: &str,
    action: &str,
    payload: &Value,
    uid: i64,
    chat_id: Option<i64>,
) -> Result<BridgeActionResponse> {
    let Some(rec) = ctx.widgets.get_webapp_widget(wid) else {
        return Ok(BridgeActionResponse::rejected(404, "Widget not found"));
    };

    let act = action.trim();
    let p = if payload.is_object() {
        payload.clone()
    } else {
        json!({})
    };
    let st = parse_cur_state(rec.chat_data.as_deref(), rec.public_data.as_deref());

    match act {
        "sk_search" | "sk_tab" => {
            let tab = p
                .get("tab")
                .and_then(Value::as_str)
                .map(str::to_string)
                .or_else(|| rec.tab.clone())
                .or_else(|| st.get("tab").and_then(Value::as_str).map(str::to_string))
                .unwrap_or_else(|| "inst".to_string());
            let q = if act == "sk_tab" {
                p.get("q")
                    .and_then(Value::as_str)
                    .or_else(|| st.get("q").and_then(Value::as_str))
                    .unwrap_or("")
                    .to_string()
            } else {
                p.get("q").and_then(Value::as_str).unwrap_or("").to_string()
            };
            let page = if act == "sk_tab" {
                0
            } else {
                safe_i64(p.get("page"), 0)
            };
            let (compact_cd, rich) = build_skills_states(ctx, uid, Some(&tab), &q, page);
            let final_tab = rich.get("tab").and_then(Value::as_str).unwrap_or("inst");
            let _ = ctx.widgets.update_webapp_widget_state(
                wid,
                DataPatch::Unchanged,
                DataPatch::Unchanged,
                Some(final_tab),
            );
            let mut resp = BridgeActionResponse::ok(json!({ "ok": true, "tab": final_tab }));
            resp.chat_data = Some(compact_cd);
            resp.rich_state = Some(rich);
            Ok(resp)
        }

        "sk_install" => {
            if !ctx.has_perm(uid, "skills_manage") {
                return Ok(BridgeActionResponse::rejected(
                    403,
                    "Permission denied: skills_manage",
                ));
            }
            let src = p
                .get("source")
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase();
            let Some(item_id) = json_str(&p, &["id", "slug", "name"]) else {
                return Ok(BridgeActionResponse::rejected(400, "Missing skill id"));
            };
            let slug = json_str(&p, &["slug", "name"]);

            let looks_like_sp = src == "skillport"
                || (src.is_empty()
                    && item_id.split('/').count() == 2
                    && !item_id.starts_with("http"));

            let msg_txt = if looks_like_sp {
                install_skillport_skill(
                    &item_id,
                    &ctx.cfg.skillport_skills_dir,
                    &ctx.skills_dir(),
                )
            } else {
                let cat_bin = ctx.cfg.skills_catalog_mcp_bin.to_string_lossy().into_owned();
                install_catalog_skill(
                    &item_id,
                    slug.as_deref(),
                    &ctx.skills_dir(),
                    &cat_bin,
                    30.0,
                )
                .await
            };

            let msg = match msg_txt {
                Ok(m) => m,
                Err(err) => return Ok(BridgeActionResponse::rejected(400, err.to_string())),
            };

            let default_tab = if src == "skillport" { "sp" } else { "cat" };
            let cur_tab = p
                .get("tab")
                .and_then(Value::as_str)
                .or(rec.tab.as_deref())
                .or_else(|| st.get("tab").and_then(Value::as_str))
                .unwrap_or(default_tab);
            let cur_q = p
                .get("q")
                .and_then(Value::as_str)
                .or_else(|| st.get("q").and_then(Value::as_str))
                .unwrap_or("");
            let (compact_cd, rich) = build_skills_states(ctx, uid, Some(cur_tab), cur_q, 0);
            let mut resp = BridgeActionResponse::ok(json!({ "ok": true, "message": msg }));
            resp.chat_data = Some(compact_cd);
            resp.rich_state = Some(rich);
            Ok(resp)
        }

        "sk_delete" => {
            if !ctx.has_perm(uid, "skills_manage") {
                return Ok(BridgeActionResponse::rejected(
                    403,
                    "Permission denied: skills_manage",
                ));
            }
            let Some(name) = json_str(&p, &["name", "slug", "id"]) else {
                return Ok(BridgeActionResponse::rejected(400, "Missing skill name"));
            };
            let msg = match delete_installed_skill(&name, &ctx.skills_dir()) {
                Ok(m) => m,
                Err(err) => return Ok(BridgeActionResponse::rejected(400, err.to_string())),
            };
            let cur_tab = p
                .get("tab")
                .and_then(Value::as_str)
                .or(rec.tab.as_deref())
                .or_else(|| st.get("tab").and_then(Value::as_str))
                .unwrap_or("inst");
            let cur_q = p
                .get("q")
                .and_then(Value::as_str)
                .or_else(|| st.get("q").and_then(Value::as_str))
                .unwrap_or("");
            let (compact_cd, rich) = build_skills_states(ctx, uid, Some(cur_tab), cur_q, 0);
            let mut resp = BridgeActionResponse::ok(json!({ "ok": true, "message": msg }));
            resp.chat_data = Some(compact_cd);
            resp.rich_state = Some(rich);
            Ok(resp)
        }

        "mcp_toggle" => {
            if !ctx.has_perm(uid, "mcp_manage") {
                return Ok(BridgeActionResponse::rejected(
                    403,
                    "Permission denied: mcp_manage",
                ));
            }
            let name = json_str_or_empty(&p, "name");
            if name.is_empty() {
                return Ok(BridgeActionResponse::rejected(400, "Missing server name"));
            }
            let enabled = p.get("enabled").and_then(Value::as_bool);
            let srv = match toggle_mcp_server(&ctx.cfg.mcp_config_path, &name, enabled) {
                Ok(v) => v,
                Err(err) => return Ok(BridgeActionResponse::rejected(400, err.to_string())),
            };
            let (compact_cd, rich) = build_mcp_states(ctx, uid);
            let mut resp = BridgeActionResponse::ok(json!({ "ok": true, "server": srv }));
            resp.chat_data = Some(compact_cd);
            resp.rich_state = Some(rich);
            Ok(resp)
        }

        "mcp_update" => {
            if !ctx.has_perm(uid, "mcp_manage") {
                return Ok(BridgeActionResponse::rejected(
                    403,
                    "Permission denied: mcp_manage",
                ));
            }
            let name = json_str_or_empty(&p, "name");
            if name.is_empty() {
                return Ok(BridgeActionResponse::rejected(400, "Missing server name"));
            }
            let patch = match normalize_mcp_update_patch(ctx, &name, &p) {
                Ok(patch) => patch,
                Err(err) => return Ok(BridgeActionResponse::rejected(400, err.to_string())),
            };
            let msg = match update_mcp_server(&ctx.cfg.mcp_config_path, &name, patch) {
                Ok(m) => m,
                Err(err) => return Ok(BridgeActionResponse::rejected(400, err.to_string())),
            };
            let (compact_cd, rich) = build_mcp_states(ctx, uid);
            let mut resp = BridgeActionResponse::ok(json!({ "ok": true, "message": msg }));
            resp.chat_data = Some(compact_cd);
            resp.rich_state = Some(rich);
            Ok(resp)
        }

        "mcp_remove" => {
            if !ctx.has_perm(uid, "mcp_manage") {
                return Ok(BridgeActionResponse::rejected(
                    403,
                    "Permission denied: mcp_manage",
                ));
            }
            let name = json_str_or_empty(&p, "name");
            if name.is_empty() {
                return Ok(BridgeActionResponse::rejected(400, "Missing server name"));
            }
            let msg = match remove_mcp_server(&ctx.cfg.mcp_config_path, &name) {
                Ok(m) => m,
                Err(err) => return Ok(BridgeActionResponse::rejected(400, err.to_string())),
            };
            let (compact_cd, rich) = build_mcp_states(ctx, uid);
            let mut resp = BridgeActionResponse::ok(json!({ "ok": true, "message": msg }));
            resp.chat_data = Some(compact_cd);
            resp.rich_state = Some(rich);
            Ok(resp)
        }

        "mcp_ai_install" => {
            if !ctx.has_perm(uid, "mcp_manage") {
                return Ok(BridgeActionResponse::rejected(
                    403,
                    "Permission denied: mcp_manage",
                ));
            }
            let spec = json_str_or_empty(&p, "spec");
            if spec.is_empty() {
                return Ok(BridgeActionResponse::rejected(400, "Enter MCP spec"));
            }
            let target_chat = rec.chat_id.or(chat_id).unwrap_or(uid);
            let req = submit_mcp_ai_request(ctx, uid, target_chat, &spec).await?;
            let (compact_cd, rich) = build_mcp_states(ctx, uid);
            let mut resp = BridgeActionResponse::ok(json!({
                "ok": true,
                "req_id": req.req_id,
                "status": req.status,
            }));
            resp.chat_data = Some(compact_cd);
            resp.rich_state = Some(rich);
            Ok(resp)
        }

        "mcp_refresh" => {
            if !ctx.has_perm(uid, "mcp_manage") {
                return Ok(BridgeActionResponse::rejected(403, "Permission denied: mcp_manage"));
            }
            let (compact_cd, rich) = build_mcp_states(ctx, uid);
            let mut resp = BridgeActionResponse::ok(json!({ "ok": true }));
            resp.chat_data = Some(compact_cd);
            resp.rich_state = Some(rich);
            Ok(resp)
        }

        "mdl_set" | "model_set" => {
            if !ctx.has_perm(uid, "models_switch") {
                return Ok(BridgeActionResponse::rejected(403, "Permission denied: models_switch"));
            }
            let can_settings = ctx.has_perm(uid, "settings_access");
            ctx.store.update_user(uid, |u| {
                if p.get("id").is_some() || p.get("model").is_some() {
                    let mid = p
                        .get("id")
                        .or_else(|| p.get("model"))
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .trim();
                    u.model = if mid.is_empty() || mid == "default" {
                        None
                    } else {
                        Some(mid.to_string())
                    };
                }
                if can_settings {
                    if let Some(eff_raw) = p.get("effort").and_then(Value::as_str) {
                        let eff = eff_raw.trim().to_ascii_lowercase();
                        if EFFORTS.contains(&eff.as_str()) {
                            u.effort = if eff == "default" { None } else { Some(eff) };
                        }
                    }
                    if let Some(mode_raw) = p.get("mode").and_then(Value::as_str) {
                        let mval = mode_raw.trim().to_ascii_lowercase();
                        if MODES.contains(&mval.as_str()) {
                            u.mode = if mval == "auto" { None } else { Some(mval) };
                        }
                    }
                    if p.get("stream_mode").is_some() || p.get("stream").is_some() {
                        let sm = p
                            .get("stream_mode")
                            .or_else(|| p.get("stream"))
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .trim()
                            .to_ascii_lowercase();
                        if STREAM_MODES.contains(&sm.as_str()) {
                            u.stream_mode = sm.clone();
                            u.stream = sm != "off";
                        }
                    }
                }
            })?;
            let (compact_cd, rich) = build_models_states(ctx, uid);
            let mut resp = BridgeActionResponse::ok(json!({ "ok": true }));
            resp.chat_data = Some(compact_cd);
            resp.rich_state = Some(rich);
            Ok(resp)
        }

        "mdl_refresh" | "model_refresh" => {
            if !ctx.has_perm(uid, "models_switch") {
                return Ok(BridgeActionResponse::rejected(403, "Permission denied: models_switch"));
            }
            let _ = ctx.refresh_models_for_user(uid).await;
            let (compact_cd, rich) = build_models_states(ctx, uid);
            let mut resp = BridgeActionResponse::ok(json!({ "ok": true }));
            resp.chat_data = Some(compact_cd);
            resp.rich_state = Some(rich);
            Ok(resp)
        }

        "set_toggle" => Ok(handle_settings_toggle(ctx, uid, &p).await),

        "tel_refresh" => {
            if !ctx.is_owner(uid) {
                return Ok(BridgeActionResponse::rejected(403, "Owner permission required"));
            }
            let force = p.get("force").and_then(Value::as_bool).unwrap_or(true);
            let (compact_cd, rich) =
                Box::pin(crate::handlers_telemetry::build_telemetry_widget_states(ctx, uid, force)).await;
            let mut resp = BridgeActionResponse::ok(json!({ "ok": true }));
            resp.chat_data = Some(compact_cd);
            resp.rich_state = Some(rich);
            Ok(resp)
        }

        "tel_switch" => {
            if !ctx.is_owner(uid) {
                return Ok(BridgeActionResponse::rejected(403, "Owner permission required"));
            }
            let eng = p.get("engine").and_then(Value::as_str).unwrap_or("agy").trim();
            if !matches!(eng, "agy" | "grok" | "gemini_web" | "uncensored") {
                return Ok(BridgeActionResponse::rejected(400, "Unsupported engine"));
            }
            let _ = ctx.store.update_user(uid, |u| {
                if eng == "agy" {
                    u.extra.remove("engine");
                    if u.model.as_deref().is_some_and(|m| {
                        agy_ext::grok_oauth::is_grok_model(m)
                            || agy_ext::uncensored::is_uncensored_model(m)
                    }) {
                        u.model = None;
                    }
                } else {
                    u.extra.insert("engine".to_string(), json!(eng));
                }
            });
            let (compact_cd, rich) =
                Box::pin(crate::handlers_telemetry::build_telemetry_widget_states(ctx, uid, false)).await;
            let mut resp = BridgeActionResponse::ok(json!({ "ok": true, "engine": eng }));
            resp.chat_data = Some(compact_cd);
            resp.rich_state = Some(rich);
            Ok(resp)
        }

        "mem_search" => {
            let q = p.get("q").and_then(Value::as_str).unwrap_or("");
            let mt = p
                .get("type")
                .and_then(Value::as_str)
                .or_else(|| st.get("type").and_then(Value::as_str))
                .unwrap_or("all");
            let (compact_cd, rich) = build_memory_states(ctx, q, mt).await;
            let mut resp = BridgeActionResponse::ok(json!({ "ok": true }));
            resp.chat_data = Some(compact_cd);
            resp.rich_state = Some(rich);
            Ok(resp)
        }

        "mem_add" => {
            if !ctx.is_owner(uid) {
                return Ok(BridgeActionResponse::rejected(403, "Owner permission required"));
            }
            let title = json_str_or_empty(&p, "title");
            let summary = json_str_or_empty(&p, "summary");
            let mtype = p
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or("fact")
                .trim()
                .to_ascii_lowercase();
            let tags: Vec<String> = match p.get("tags").and_then(Value::as_array) {
                Some(arr) => arr.iter().map(value_to_arg_string).collect(),
                None => vec!["telegram".to_string()],
            };
            let bin = ctx.cfg.ai_memory_mcp_bin.to_string_lossy().into_owned();
            let mem_val = match memory_add(&bin, &title, &summary, &mtype, &tags).await {
                Ok(v) => v,
                Err(err) => return Ok(BridgeActionResponse::rejected(400, err.to_string())),
            };
            let cur_type = p
                .get("filter")
                .and_then(Value::as_str)
                .or_else(|| st.get("type").and_then(Value::as_str))
                .unwrap_or("all");
            let cur_q = p
                .get("q")
                .and_then(Value::as_str)
                .or_else(|| st.get("q").and_then(Value::as_str))
                .unwrap_or("");
            let (compact_cd, rich) = build_memory_states(ctx, cur_q, cur_type).await;
            let mut resp = BridgeActionResponse::ok(json!({ "ok": true, "memory": mem_val }));
            resp.chat_data = Some(compact_cd);
            resp.rich_state = Some(rich);
            Ok(resp)
        }

        "mem_delete" => {
            if !ctx.is_owner(uid) {
                return Ok(BridgeActionResponse::rejected(403, "Owner permission required"));
            }
            let mem_id = json_str_or_empty(&p, "id");
            let bin = ctx.cfg.ai_memory_mcp_bin.to_string_lossy().into_owned();
            let msg = match memory_remove(&bin, &mem_id).await {
                Ok(m) => m,
                Err(err) => return Ok(BridgeActionResponse::rejected(400, err.to_string())),
            };
            let cur_type = p
                .get("type")
                .and_then(Value::as_str)
                .or_else(|| st.get("type").and_then(Value::as_str))
                .unwrap_or("all");
            let cur_q = p
                .get("q")
                .and_then(Value::as_str)
                .or_else(|| st.get("q").and_then(Value::as_str))
                .unwrap_or("");
            let (compact_cd, rich) = build_memory_states(ctx, cur_q, cur_type).await;
            let mut resp = BridgeActionResponse::ok(json!({ "ok": true, "message": msg }));
            resp.chat_data = Some(compact_cd);
            resp.rich_state = Some(rich);
            Ok(resp)
        }

        "sys_refresh" => {
            if !ctx.has_perm(uid, "status_net") {
                return Ok(BridgeActionResponse::rejected(403, "Permission denied: status_net"));
            }
            let sys_val = build_sys_state(ctx, uid);
            let mut resp = BridgeActionResponse::ok(json!({ "ok": true, "sys": sys_val }));
            if matches!(
                rec.handler.as_deref().map(str::to_ascii_lowercase).as_deref(),
                Some("sys" | "status" | "panel" | "dash")
            ) {
                resp.chat_data = Some(compact_widget_cd(&sys_val, COMPACT_CHAT_DATA_MAX_BYTES));
            }
            resp.rich_state = Some(sys_val);
            Ok(resp)
        }

        "sys_poll" => {
            if !ctx.has_perm(uid, "status_net") {
                return Ok(BridgeActionResponse::rejected(403, "Permission denied: status_net"));
            }
            let h_snap = ctx.health.snapshot();
            let sys_val = build_sys_state(ctx, uid);
            let mut resp = BridgeActionResponse::ok(json!({
                "ok": true,
                "polling": sys_val.get("polling").cloned().unwrap_or(Value::Null),
                "health": h_snap,
            }));
            resp.rich_state = Some(sys_val);
            Ok(resp)
        }

        "sys_net_test" => {
            if !ctx.has_perm(uid, "status_net") {
                return Ok(BridgeActionResponse::rejected(403, "Permission denied: status_net"));
            }
            let started = std::time::Instant::now();
            let get_me_ok = tokio::time::timeout(
                std::time::Duration::from_secs(3),
                ctx.client.get_me(),
            )
            .await
            .is_ok_and(|res| res.is_ok());
            let latency_ms = started.elapsed().as_millis() as u64;
            let net_val = build_net_state(ctx);
            let mut resp = BridgeActionResponse::ok(json!({
                "ok": true,
                "telegram_ok": get_me_ok,
                "latency_ms": latency_ms,
                "net": net_val,
            }));
            resp.rich_state = Some(net_val);
            Ok(resp)
        }

        "new_chat" => {
            ctx.jobs.clear_awaiting(uid);
            ctx.store.update_user(uid, |u| {
                u.conversation_id = None;
            })?;
            let u = ctx.store.get_user(uid);
            let ses = build_sessions_state(ctx, uid, &u);
            let mut resp = BridgeActionResponse::ok(json!({
                "ok": true,
                "conversation_id": Value::Null,
            }));
            resp.rich_state = Some(ses);
            Ok(resp)
        }

        "stop_job" => {
            let stopped = ctx.jobs.stop_user(uid).await;
            let u = ctx.store.get_user(uid);
            let ses = build_sessions_state(ctx, uid, &u);
            let mut resp = BridgeActionResponse::ok(json!({
                "ok": true,
                "stopped": stopped,
            }));
            resp.rich_state = Some(ses);
            Ok(resp)
        }

        "ses_resume" => {
            if !ctx.has_perm(uid, "dashboard_access") {
                return Ok(BridgeActionResponse::rejected(403, "Permission denied: dashboard_access"));
            }
            let req_id = json_str(&p, &["conversation_id", "id"]);
            let idx_opt = p
                .get("idx")
                .or_else(|| p.get("index"))
                .and_then(Value::as_u64)
                .and_then(|u| usize::try_from(u).ok());
            let selected = ctx.store.try_update_user(uid, |u| {
                let target_id = if let Some(cid) = req_id {
                    cid
                } else if let Some(idx) = idx_opt {
                    u.history
                        .get(idx)
                        .map(|h| h.id.clone())
                        .ok_or_else(|| BridgeError::NotFound("Session index not found".to_string()))?
                } else {
                    return Err(BridgeError::Validation(
                        "Missing session conversation_id or idx".to_string(),
                    ));
                };
                u.push_session(target_id.clone(), "resumed", now_unix_secs());
                Ok(target_id)
            });

            match selected {
                Ok(conv_id) => {
                    let u = ctx.store.get_user(uid);
                    let ses = build_sessions_state(ctx, uid, &u);
                    let mut resp = BridgeActionResponse::ok(json!({
                        "ok": true,
                        "conversation_id": conv_id,
                    }));
                    resp.rich_state = Some(ses);
                    Ok(resp)
                }
                Err(BridgeError::NotFound(e)) => Ok(BridgeActionResponse::rejected(404, e)),
                Err(err) => Ok(BridgeActionResponse::rejected(400, err.to_string())),
            }
        }

        "cron_toggle" => {
            if !ctx.is_owner(uid) {
                return Ok(BridgeActionResponse::rejected(403, "Owner permission required"));
            }
            let Some(job_id) = json_str(&p, &["id", "job_id"]) else {
                return Ok(BridgeActionResponse::rejected(400, "Missing cron job id"));
            };
            let target_enabled = match p.get("enabled").and_then(Value::as_bool) {
                Some(b) => b,
                None => match ctx.cron.get_job(&job_id) {
                    Some(job) => !job.enabled,
                    None => {
                        return Ok(BridgeActionResponse::rejected(404, "Cron job not found"));
                    }
                },
            };
            let job = match ctx.cron.set_enabled(&job_id, target_enabled) {
                Ok(j) => j,
                Err(BridgeError::NotFound(e)) => return Ok(BridgeActionResponse::rejected(404, e)),
                Err(err) => return Ok(BridgeActionResponse::rejected(400, err.to_string())),
            };
            let mut resp = BridgeActionResponse::ok(json!({ "ok": true, "job": job }));
            resp.rich_state = Some(build_cron_state(ctx));
            Ok(resp)
        }

        "cron_run" => {
            if !ctx.is_owner(uid) {
                return Ok(BridgeActionResponse::rejected(403, "Owner permission required"));
            }
            let Some(job_id) = json_str(&p, &["id", "job_id"]) else {
                return Ok(BridgeActionResponse::rejected(400, "Missing cron job id"));
            };
            let job = match ctx.cron.run_now(&job_id).await {
                Ok(j) => j,
                Err(BridgeError::NotFound(e)) => return Ok(BridgeActionResponse::rejected(404, e)),
                Err(err) => return Ok(BridgeActionResponse::rejected(400, err.to_string())),
            };
            let mut resp = BridgeActionResponse::ok(json!({ "ok": true, "job": job }));
            resp.rich_state = Some(build_cron_state(ctx));
            Ok(resp)
        }

        "kv_set" | "poll_vote" => {
            let mut action_obj = match p.as_object() {
                Some(m) => m.clone(),
                None => Map::new(),
            };
            action_obj.insert("action".to_string(), Value::String(act.to_string()));
            let res = apply_widget_data_action(
                ctx,
                wid,
                uid,
                rec.chat_data.as_deref(),
                rec.public_data.as_deref(),
                &Value::Object(action_obj),
            );
            match res {
                Ok(out) => {
                    let mut resp = BridgeActionResponse::ok(out.result);
                    resp.chat_data = out.chat_data;
                    resp.public_data = out.public_data;
                    Ok(resp)
                }
                Err(err) => Ok(BridgeActionResponse::rejected(400, err.to_string())),
            }
        }

        other => Ok(BridgeActionResponse::rejected(
            400,
            format!("Unknown action: {other}"),
        )),
    }
}

fn synthetic_user(ctx: &Arc<BotCtx>, uid: i64) -> User {
    let label = acl_user_label(ctx, uid);
    let u_rec = ctx.acl.get_user(uid);
    User {
        id: uid,
        is_bot: false,
        first_name: label,
        last_name: None,
        username: u_rec.and_then(|u| u.username),
        language_code: None,
        is_premium: None,
    }
}

impl WidgetBridge for BotWebAppBridge {
    fn query_widget<'a>(
        &'a self,
        wid: &'a str,
        kind: &'a str,
        data: &'a str,
        uid: i64,
        chat_id: Option<i64>,
    ) -> BoxFuture<'a, Result<BridgeQueryResponse>> {
        Box::pin(async move {
            let rec = self.ctx.widgets.get_webapp_widget(wid);
            let handler_name = rec
                .as_ref()
                .and_then(|r| r.handler.as_deref())
                .unwrap_or(kind);
            let target_chat = rec
                .as_ref()
                .and_then(|r| r.chat_id)
                .or(chat_id)
                .unwrap_or(uid);
            let vote_key = rec
                .as_ref()
                .and_then(|r| r.shared_widget_id.clone())
                .unwrap_or_else(|| wid.to_string());
            let u_obj = synthetic_user(&self.ctx, uid);

            let (result, new_cd, new_pd) = execute_widget_data_action(
                &self.ctx,
                uid,
                target_chat,
                &u_obj,
                data,
                handler_name,
                rec.as_ref().and_then(|r| r.chat_data.as_deref()),
                rec.as_ref().and_then(|r| r.public_data.as_deref()),
                &vote_key,
                None,
                Some(wid),
                rec.as_ref().and_then(|r| r.message_id),
            )
            .await;

            if let (Some(pd_val), Some(ref r)) = (&new_pd, &rec) {
                if r.is_shared {
                    if let Ok(Some(pd_enc)) =
                        encode_widget_data(Some(WidgetData::Value(pd_val)), true)
                    {
                        let _ = self.ctx.widgets.update_shared_state(
                            &vote_key,
                            Some(WidgetData::Str(&pd_enc)),
                            None,
                        );
                        let peers: HashSet<String> = self
                            .ctx
                            .widgets
                            .find_shared_targets(&vote_key)
                            .into_iter()
                            .filter(|other| other != wid)
                            .collect();
                        for other_wid in peers {
                            let _ = self.ctx.widgets.update_webapp_widget_state(
                                &other_wid,
                                DataPatch::Unchanged,
                                DataPatch::Set(WidgetData::Str(&pd_enc)),
                                None,
                            );
                            let _ =
                                crate::handlers_widgets::refresh_in_bubble_card(&self.ctx, &other_wid)
                                    .await;
                        }
                    }
                }
            }

            Ok(BridgeQueryResponse {
                result,
                chat_data: new_cd,
                public_data: new_pd,
            })
        })
    }

    fn call_action<'a>(
        &'a self,
        wid: &'a str,
        kind: &'a str,
        action: &'a str,
        payload: &'a Value,
        uid: i64,
        chat_id: Option<i64>,
    ) -> BoxFuture<'a, Result<BridgeActionResponse>> {
        Box::pin(async move {
            handle_action_impl(&self.ctx, wid, kind, action, payload, uid, chat_id).await
        })
    }

    fn get_rich_state<'a>(
        &'a self,
        wid: &'a str,
        kind: &'a str,
        uid: i64,
        _chat_id: Option<i64>,
    ) -> BoxFuture<'a, Result<Option<Value>>> {
        Box::pin(async move {
            let rec = self.ctx.widgets.get_webapp_widget(wid);
            let handler = rec
                .as_ref()
                .and_then(|r| r.handler.as_deref())
                .unwrap_or(kind)
                .trim()
                .to_ascii_lowercase();

            if BUILTIN_WIDGET_KINDS.contains(&handler.as_str()) {
                let st = rec
                    .as_ref()
                    .map(|r| parse_cur_state(r.chat_data.as_deref(), r.public_data.as_deref()))
                    .unwrap_or_default();
                let tab = rec
                    .as_ref()
                    .and_then(|r| r.tab.clone())
                    .or_else(|| st.get("tab").and_then(Value::as_str).map(str::to_string));
                let q = st.get("q").and_then(Value::as_str).unwrap_or("");
                let page = safe_i64(st.get("page"), 0);
                let mem_type = st
                    .get("type")
                    .or_else(|| st.get("filter"))
                    .and_then(Value::as_str)
                    .unwrap_or("all");
                let (_, rich) =
                    build_widget_states(&self.ctx, &handler, uid, tab.as_deref(), q, page, mem_type)
                        .await?;
                return Ok(Some(rich));
            }

            if PANEL_RICH_KINDS.contains(&handler.as_str()) {
                let rich = build_rich_state(&self.ctx, Some(&handler), uid).await?;
                return Ok(Some(rich));
            }

            Ok(None)
        })
    }

    fn on_state_changed<'a>(&'a self, wid: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            match crate::handlers_widgets::refresh_in_bubble_card(&self.ctx, wid).await {
                Ok(_) => info!(wid, "refreshed in-bubble card after webapp state change"),
                Err(err) => warn!(wid, error = %err, "failed refreshing in-bubble card"),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::Arc;
    use std::time::Duration;

    use agy_core::acl::{AclStore, RolePreset};
    use agy_core::config::Config;
    use agy_core::health::HealthTracker;
    use agy_core::outbox::OutQueue;
    use agy_core::store::StateStore;
    use agy_ext::engines::ModelInfo;
    use agy_net::proxy::NetConfig;
    use agy_net::{BotApiClient, ProxyPool};
    use agy_render::premium::PremiumState;
    use agy_widgets::spec::WidgetSpec;
    use tempfile::TempDir;

    use crate::auth::AuthGate;
    use crate::cron::CronScheduler;
    use crate::jobs::JobManager;
    use crate::render_bridge::RenderBridge;

    const OWNER: i64 = 1001;
    const STANDARD_UID: i64 = 2002;
    const DEV_UID: i64 = 3003;

    struct TestFixture {
        _tmp: TempDir,
        ctx: Arc<BotCtx>,
        bridge: Arc<BotWebAppBridge>,
    }

    fn setup_fixture() -> TestFixture {
        let tmp = TempDir::new().unwrap();
        let state_dir = tmp.path().join("state");
        let ws_dir = tmp.path().join("workspace");
        let skills_dir = tmp.path().join("skills");
        let sp_dir = tmp.path().join("skillport");
        let catalog_json = tmp.path().join("catalog.json");
        let mcp_cfg = tmp.path().join("mcp_config.json");
        fs::create_dir_all(&state_dir).unwrap();
        fs::create_dir_all(&ws_dir).unwrap();
        fs::create_dir_all(&skills_dir).unwrap();
        fs::create_dir_all(sp_dir.join("coding/demo-sp")).unwrap();
        fs::create_dir_all(skills_dir.join("installed-one")).unwrap();

        fs::write(
            skills_dir.join("installed-one/SKILL.md"),
            "---\nname: installed-one\ndescription: Already installed test skill\ncategory: test\n---\nBody\n",
        )
        .unwrap();
        fs::write(
            sp_dir.join("coding/demo-sp/SKILL.md"),
            "---\nname: demo-sp\ndescription: SkillPort demo skill\n---\nDemo body\n",
        )
        .unwrap();
        fs::write(
            &catalog_json,
            json!({
                "domains": [{ "id": "coding", "label": "Coding" }],
                "skills": [
                    {
                        "id": "repo/cat-skill",
                        "slug": "cat-skill",
                        "name": "cat-skill",
                        "description": "Catalog skill",
                        "primary_tag": "coding",
                        "repo": "demo/repo"
                    },
                    {
                        "id": "repo/cat-two",
                        "slug": "cat-two",
                        "name": "cat-two",
                        "description": "Second catalog skill",
                        "primary_tag": "coding",
                        "repo": "demo/repo"
                    }
                ]
            })
            .to_string(),
        )
        .unwrap();
        fs::write(
            &mcp_cfg,
            json!({
                "mcpServers": {
                    "secret-srv": {
                        "command": "npx",
                        "args": ["-y", "demo-mcp"],
                        "env": {
                            "API_TOKEN": "super_secret_token_999",
                            "PUBLIC_FLAG": "yes"
                        }
                    },
                    "remote-srv": {
                        "url": "https://mcp.example.com/sse",
                        "headers": {
                            "Authorization": "Bearer top-secret-bearer"
                        }
                    }
                }
            })
            .to_string(),
        )
        .unwrap();

        let cfg = Arc::new(Config {
            bot_token: "12345:TEST_TOKEN".to_string(),
            state_dir: state_dir.clone(),
            agy_workspace: ws_dir,
            agy_bin: tmp.path().join("missing-agy"),
            owner_id: OWNER,
            allowed_user_ids: vec![OWNER, STANDARD_UID, DEV_UID],
            allow_inline_widgets: false,
            webapp_base_url: "https://example.test".to_string(),
            widget_port: 8799,
            agy_skills_dir: skills_dir,
            skillport_skills_dir: sp_dir,
            skills_catalog_json: catalog_json,
            mcp_config_path: mcp_cfg,
            ai_memory_mcp_bin: tmp.path().join("missing-mem"),
            skills_catalog_mcp_bin: tmp.path().join("missing-cat"),
            premium_ui: false,
            ..Default::default()
        });

        let store = Arc::new(StateStore::open(state_dir.join("state.json")).unwrap());
        let acl = Arc::new(
            AclStore::open(
                state_dir.join("acl.json"),
                OWNER,
                &[STANDARD_UID, DEV_UID],
                300,
            )
            .unwrap(),
        );
        acl.apply_preset(STANDARD_UID, RolePreset::Std).unwrap();
        acl.apply_preset(DEV_UID, RolePreset::Dev).unwrap();

        let outbox = Arc::new(OutQueue::open(state_dir.join("outbox.json")).unwrap());
        let health = Arc::new(HealthTracker::new(state_dir.join("health.json")));
        let premium = Arc::new(PremiumState::new(false));
        let net_cfg = NetConfig::default().with_api_base("http://127.0.0.1:9/bot");
        let pool = Arc::new(ProxyPool::new(net_cfg.clone()).unwrap());
        let client = Arc::new(
            BotApiClient::with_pool(&cfg.bot_token, &net_cfg.api_base, pool.clone(), Duration::from_secs(2))
                .unwrap(),
        );
        let widgets = Arc::new(WidgetStore::from_state_dir(&state_dir).unwrap());
        let render = Arc::new(
            RenderBridge::new(client.clone(), premium.clone(), outbox.clone())
                .with_state_store(store.clone())
                .with_retry_config(0, 0.01),
        );
        let cron = Arc::new(CronScheduler::new(cfg.clone(), health.clone()).unwrap());
        let jobs = Arc::new(
            JobManager::new(cfg.clone(), acl.clone(), store.clone(), render.clone(), client.clone())
                .unwrap(),
        );
        let auth = Arc::new(AuthGate::new(acl.clone(), false));

        let ctx = BotCtx::new(
            cfg, store, acl, outbox, health, premium, pool, client, widgets, render, cron, jobs,
            auth,
        );
        ctx.set_models_cache(vec![
            ModelInfo {
                id: "claude-opus-4-6".to_string(),
                name: "Claude Opus 4.6".to_string(),
            },
            ModelInfo {
                id: "gemini-3-pro".to_string(),
                name: "Gemini 3 Pro".to_string(),
            },
        ]);
        let bridge = BotWebAppBridge::new(ctx.clone());
        TestFixture {
            _tmp: tmp,
            ctx,
            bridge,
        }
    }

    fn register_kind(ctx: &Arc<BotCtx>, kind: &str, wid: &str) {
        let sp = WidgetSpec {
            html: Some("<div>ok</div>".to_string()),
            handler: Some(kind.to_string()),
            caption: Some(kind.to_string()),
            ..Default::default()
        };
        ctx.widgets
            .register_webapp_widget(&sp, Some(OWNER), Some(10), Some(wid))
            .unwrap();
    }

    #[tokio::test]
    async fn rich_state_masks_mcp_secrets_and_counts_skills() {
        let f = setup_fixture();

        let mcp_val = build_rich_state(&f.ctx, Some("mcp"), OWNER).await.unwrap();
        let mcp_txt = mcp_val.to_string();
        assert!(!mcp_txt.contains("super_secret_token_999"));
        assert!(!mcp_txt.contains("top-secret-bearer"));
        assert!(mcp_txt.contains(MASKED_SECRET));
        assert_eq!(mcp_val["configs"]["secret-srv"]["env"]["PUBLIC_FLAG"], "yes");
        assert_eq!(mcp_val["configs"]["secret-srv"]["env"]["API_TOKEN"], MASKED_SECRET);
        assert_eq!(mcp_val["configs"]["remote-srv"]["headers"]["Authorization"], MASKED_SECRET);

        let skills_val = build_rich_state(&f.ctx, Some("skills"), OWNER).await.unwrap();
        assert_eq!(skills_val["counts"]["installed"], 1);
        assert_eq!(skills_val["counts"]["skillport"], 1);
        assert_eq!(skills_val["counts"]["catalog"], 2);

        for kind in ["sys", "status", "models", "settings", "sessions", "net", "cron", "panel"] {
            let v = build_rich_state(&f.ctx, Some(kind), OWNER).await.unwrap();
            assert!(v.is_object(), "kind={kind} should return JSON object");
        }
        assert!(build_rich_state(&f.ctx, Some("custom_unlisted"), OWNER).await.unwrap().is_null());
    }

    #[tokio::test]
    async fn acl_enforced_strictly_before_disk_or_state_mutation() {
        let f = setup_fixture();
        register_kind(&f.ctx, "skills", "w_sk");
        register_kind(&f.ctx, "mcp", "w_mcp");
        register_kind(&f.ctx, "settings", "w_set");

        let r1 = f
            .bridge
            .call_action(
                "w_sk",
                "skills",
                "sk_install",
                &json!({ "id": "coding/demo-sp", "source": "skillport" }),
                STANDARD_UID,
                None,
            )
            .await
            .unwrap();
        assert!(!r1.ok);
        assert_eq!(r1.status, 403);
        assert!(!f.ctx.skills_dir().join("demo-sp").exists());

        let r2 = f
            .bridge
            .call_action(
                "w_sk",
                "skills",
                "sk_delete",
                &json!({ "name": "installed-one" }),
                STANDARD_UID,
                None,
            )
            .await
            .unwrap();
        assert!(!r2.ok);
        assert_eq!(r2.status, 403);
        assert!(f.ctx.skills_dir().join("installed-one/SKILL.md").is_file());

        let before_mcp = fs::read_to_string(&f.ctx.cfg.mcp_config_path).unwrap();
        for (act, payload) in [
            ("mcp_toggle", json!({ "name": "secret-srv" })),
            ("mcp_update", json!({ "name": "secret-srv", "command": "uvx" })),
            ("mcp_remove", json!({ "name": "secret-srv" })),
        ] {
            let resp = f
                .bridge
                .call_action("w_mcp", "mcp", act, &payload, STANDARD_UID, None)
                .await
                .unwrap();
            assert!(!resp.ok, "{act} must be rejected");
            assert_eq!(resp.status, 403, "{act} must return 403");
        }
        let after_mcp = fs::read_to_string(&f.ctx.cfg.mcp_config_path).unwrap();
        assert_eq!(before_mcp, after_mcp, "MCP config must stay untouched on 403");

        // `dev` role has skills_manage & mcp_manage, NOT root_access!
        let r_set = f
            .bridge
            .call_action(
                "w_set",
                "settings",
                "set_toggle",
                &json!({ "key": "skip_permissions" }),
                DEV_UID,
                None,
            )
            .await
            .unwrap();
        assert!(!r_set.ok);
        assert_eq!(r_set.status, 403);
        assert!(!f.ctx.store.get_user(DEV_UID).skip_permissions);
    }

    #[tokio::test]
    async fn mcp_update_normalizes_empty_command_and_url_and_preserves_secret() {
        let f = setup_fixture();
        register_kind(&f.ctx, "mcp", "w_mcp");

        // Simulates UI saving remote-srv with `command: ""` and `args: []`
        let res_url = f
            .bridge
            .call_action(
                "w_mcp",
                "mcp",
                "mcp_update",
                &json!({
                    "name": "remote-srv",
                    "command": "",
                    "args": [],
                    "url": "https://mcp.example.com/v2",
                    "enabled": false
                }),
                DEV_UID,
                None,
            )
            .await
            .unwrap();
        assert!(res_url.ok, "unexpected error: {:?}", res_url.error);
        let updated_url = get_mcp_server(&f.ctx.cfg.mcp_config_path, "remote-srv").unwrap().unwrap();
        assert_eq!(updated_url.url, "https://mcp.example.com/v2");
        assert!(!updated_url.enabled);

        // Simulates UI saving secret-srv with `url: ""` and masked secret placeholder
        let res_cmd = f
            .bridge
            .call_action(
                "w_mcp",
                "mcp",
                "mcp_update",
                &json!({
                    "name": "secret-srv",
                    "command": "uvx",
                    "args": ["my-mcp"],
                    "url": "",
                    "env_set": {
                        "API_TOKEN": MASKED_SECRET,
                        "PUBLIC_FLAG": "no"
                    }
                }),
                DEV_UID,
                None,
            )
            .await
            .unwrap();
        assert!(res_cmd.ok, "unexpected error: {:?}", res_cmd.error);
        let raw_json: Value = serde_json::from_str(&fs::read_to_string(&f.ctx.cfg.mcp_config_path).unwrap()).unwrap();
        assert_eq!(raw_json["mcpServers"]["secret-srv"]["command"], "uvx");
        assert_eq!(
            raw_json["mcpServers"]["secret-srv"]["env"]["API_TOKEN"],
            "super_secret_token_999"
        );
        assert_eq!(raw_json["mcpServers"]["secret-srv"]["env"]["PUBLIC_FLAG"], "no");
    }

    #[tokio::test]
    async fn skills_models_sessions_cron_sys_kv_and_poll_actions() {
        let f = setup_fixture();
        register_kind(&f.ctx, "skills", "w_sk");
        register_kind(&f.ctx, "models", "w_mdl");
        register_kind(&f.ctx, "settings", "w_set");
        register_kind(&f.ctx, "sessions", "w_ses");
        register_kind(&f.ctx, "cron", "w_cron");
        register_kind(&f.ctx, "sys", "w_sys");
        register_kind(&f.ctx, "kv", "w_kv");
        register_kind(&f.ctx, "poll", "w_poll");

        // Skills tab switch & skillport install/delete
        let tab_r = f
            .bridge
            .call_action("w_sk", "skills", "sk_tab", &json!({ "tab": "sp" }), DEV_UID, None)
            .await
            .unwrap();
        assert!(tab_r.ok);
        assert_eq!(tab_r.rich_state.as_ref().unwrap()["tab"], "sp");

        let inst_r = f
            .bridge
            .call_action(
                "w_sk",
                "skills",
                "sk_install",
                &json!({ "id": "coding/demo-sp", "source": "skillport", "tab": "sp" }),
                DEV_UID,
                None,
            )
            .await
            .unwrap();
        assert!(inst_r.ok, "sk_install failed: {:?}", inst_r.error);
        assert!(f.ctx.skills_dir().join("demo-sp/SKILL.md").is_file());

        let del_r = f
            .bridge
            .call_action(
                "w_sk",
                "skills",
                "sk_delete",
                &json!({ "name": "demo-sp" }),
                DEV_UID,
                None,
            )
            .await
            .unwrap();
        assert!(del_r.ok);
        assert!(!f.ctx.skills_dir().join("demo-sp").exists());

        // Locked STANDARD_UID (no dashboard/models/settings) is denied WebApp model_set, set_toggle, ses_resume, sys_refresh
        let std_mdl = f
            .bridge
            .call_action("w_mdl", "models", "model_set", &json!({ "model": "claude-opus-4-6" }), STANDARD_UID, None)
            .await
            .unwrap();
        assert!(!std_mdl.ok);
        assert_eq!(std_mdl.status, 403);
        let std_set = f
            .bridge
            .call_action("w_set", "settings", "set_toggle", &json!({ "key": "trace" }), STANDARD_UID, None)
            .await
            .unwrap();
        assert!(!std_set.ok);
        assert_eq!(std_set.status, 403);
        let std_ses = f
            .bridge
            .call_action("w_ses", "sessions", "ses_resume", &json!({ "conversation_id": "conv-abc-123" }), STANDARD_UID, None)
            .await
            .unwrap();
        assert!(!std_ses.ok);
        assert_eq!(std_ses.status, 403);

        // DEV_UID (has dashboard_access, models_switch, settings_access) can set model, toggle trace, and resume sessions
        let mdl_r = f
            .bridge
            .call_action(
                "w_mdl",
                "models",
                "model_set",
                &json!({ "model": "claude-opus-4-6", "effort": "high", "mode": "plan" }),
                DEV_UID,
                None,
            )
            .await
            .unwrap();
        assert!(mdl_r.ok);
        let u = f.ctx.store.get_user(DEV_UID);
        assert_eq!(u.model.as_deref(), Some("claude-opus-4-6"));
        assert_eq!(u.effort.as_deref(), Some("high"));
        assert_eq!(u.mode.as_deref(), Some("plan"));

        let trace_r = f
            .bridge
            .call_action(
                "w_set",
                "settings",
                "set_toggle",
                &json!({ "key": "trace" }),
                DEV_UID,
                None,
            )
            .await
            .unwrap();
        assert!(trace_r.ok);
        assert!(f.ctx.store.get_user(DEV_UID).trace);

        let owner_skip = f
            .bridge
            .call_action(
                "w_set",
                "settings",
                "set_toggle",
                &json!({ "key": "skip_permissions" }),
                OWNER,
                None,
            )
            .await
            .unwrap();
        assert!(owner_skip.ok);
        assert!(f.ctx.store.get_user(OWNER).skip_permissions);

        // Sessions resume + new_chat + stop_job (DEV_UID has dashboard_access)
        let ses_r = f
            .bridge
            .call_action(
                "w_ses",
                "sessions",
                "ses_resume",
                &json!({ "conversation_id": "conv-abc-123" }),
                DEV_UID,
                None,
            )
            .await
            .unwrap();
        assert!(ses_r.ok);
        assert_eq!(
            f.ctx.store.get_user(DEV_UID).conversation_id.as_deref(),
            Some("conv-abc-123")
        );
        let nc_r = f
            .bridge
            .call_action("w_ses", "sessions", "new_chat", &json!({}), STANDARD_UID, None)
            .await
            .unwrap();
        assert!(nc_r.ok);
        assert_eq!(f.ctx.store.get_user(STANDARD_UID).conversation_id, None);
        let stop_r = f
            .bridge
            .call_action("w_ses", "sessions", "stop_job", &json!({}), STANDARD_UID, None)
            .await
            .unwrap();
        assert!(stop_r.ok);

        // Cron toggle
        let jobs = f.ctx.cron.list_jobs();
        if let Some(first_job) = jobs.first() {
            let ct = f
                .bridge
                .call_action(
                    "w_cron",
                    "cron",
                    "cron_toggle",
                    &json!({ "id": first_job.id, "enabled": !first_job.enabled }),
                    OWNER,
                    None,
                )
                .await
                .unwrap();
            assert!(ct.ok);
        }

        // Sys actions & ping query
        for act in ["sys_refresh", "sys_poll", "sys_net_test"] {
            let sr = f
                .bridge
                .call_action("w_sys", "sys", act, &json!({}), OWNER, None)
                .await
                .unwrap();
            assert!(sr.ok, "{act} failed");
        }
        let ping_q = f
            .bridge
            .query_widget("w_sys", "sys", "ping", OWNER, None)
            .await
            .unwrap();
        assert_eq!(ping_q.result["pong"], true);

        // KV & poll vote
        let kv_out = apply_widget_data_action(
            &f.ctx,
            "w_kv",
            OWNER,
            None,
            None,
            &json!({ "action": "kv_set", "key": "theme", "value": "dark" }),
        )
        .unwrap();
        assert_eq!(kv_out.chat_data.as_ref().unwrap()["kv"]["theme"], "dark");
        assert_eq!(kv_out.chat_data.as_ref().unwrap()["r"], 1);

        let vote_out = apply_widget_data_action(
            &f.ctx,
            "w_poll",
            OWNER,
            None,
            None,
            &json!({ "action": "poll_vote", "idx": 1, "num_options": 3 }),
        )
        .unwrap();
        assert_eq!(vote_out.public_data.as_ref().unwrap()["r"], 1);
        assert_eq!(vote_out.public_data.as_ref().unwrap()["v"], json!([0, 1, 0]));
    }
}
