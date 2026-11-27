//! Owner-only `/quota` cockpit & live state builder for the built-in `telemetry` widget.
//!
//! Combines `AccountStore` (authoritative 5h/7d token windows + weekly reserve), read-only
//! SQLite activity counts (`agy_ext::quota_probe`), opportunistic loopback LS status, and
//! overflow pool readiness (Grok OAuth, Grok Bot, Gemini Web, Venice) into a zero-token
//! deterministic routing verdict and burn-rate advisor.
//!
//! Security invariant: NEVER exposes raw emails, OAuth tokens, API keys, or proxy credentials.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use agy_core::accounts::format_tokens_compact;
use agy_core::proxies::ResolvedProxy;
use agy_core::security::scan_secret_leaks;
use agy_core::telemetry::{
    assemble_snapshot, build_agy_pool_cards, AdviceSeverity, PoolCard, PoolStatus,
    TelemetrySnapshot,
};
use agy_core::tg::{CallbackQuery, Message};
use agy_ext::gemini_web::GeminiAccountPool;
use agy_ext::grok_bot::load_grok_bot_creds;
use agy_ext::grok_oauth::load_grok_creds;
use agy_ext::quota_probe::{collect_pool_local_probes, invalidate_probe_cache};
use agy_render::md_cell;
use serde_json::{json, Value};

use crate::ctx::BotCtx;
use crate::i18n::{owner_only_html, Lang};

/// Collect a sanitized, cached (60s TTL unless `force_refresh`) [`TelemetrySnapshot`].
pub async fn collect_live_telemetry_snapshot(
    ctx: &Arc<BotCtx>,
    force_refresh: bool,
) -> TelemetrySnapshot {
    if force_refresh {
        invalidate_probe_cache();
    }
    let now = agy_core::text::now_unix();
    let mut cards: Vec<PoolCard> = Vec::new();
    let mut ls_rpc_live = false;
    let mut sqlite_steps_24h: Option<u64> = None;

    if let Some(pool) = ctx.jobs.accounts() {
        let accounts = pool.list();
        let pol = pool.policy();
        let in_flight = pool.active_in_flight_snapshot();
        let mut proxy_ok_map: HashMap<String, bool> = HashMap::with_capacity(accounts.len());
        let mut homes: Vec<(String, PathBuf)> = Vec::new();
        for a in &accounts {
            let ok = !matches!(
                ctx.proxies.resolve(a.proxy_id.as_deref()),
                ResolvedProxy::Blocked { .. }
            );
            proxy_ok_map.insert(a.id.clone(), ok);
            if a.enabled {
                homes.push((a.id.clone(), a.home.clone()));
            }
        }
        let (steps_map, ls_live, total_steps) =
            collect_pool_local_probes(&homes, force_refresh).await;
        ls_rpc_live = ls_live;
        sqlite_steps_24h = total_steps;
        cards.extend(build_agy_pool_cards(
            &accounts,
            &pol,
            &in_flight,
            &proxy_ok_map,
            now,
            Some(&steps_map),
        ));
    }

    // Overflow pool 1: Grok OAuth
    let grok_px_ok = !matches!(ctx.proxies.resolve_grok(), ResolvedProxy::Blocked { .. });
    match load_grok_creds(&ctx.cfg.state_dir) {
        Some(c) => {
            let status = if c.quarantined_reason.is_some() {
                PoolStatus::Disabled
            } else if !grok_px_ok {
                PoolStatus::Cooldown
            } else {
                PoolStatus::Ready
            };
            cards.push(PoolCard {
                pool_id: "grok".to_string(),
                engine: "grok".to_string(),
                label: "Grok OAuth".to_string(),
                masked_identity: c.masked_email().unwrap_or_else(|| "x.ai OAuth".to_string()),
                status,
                window_5h: None,
                window_7d: None,
                in_flight: 0,
                sticky_proxy_ok: grok_px_ok,
                cooldown_secs: 0,
                steps_24h: None,
                source: "grok_oauth".to_string(),
            });
        }
        None => {
            cards.push(PoolCard {
                pool_id: "grok".to_string(),
                engine: "grok".to_string(),
                label: "Grok OAuth".to_string(),
                masked_identity: "—".to_string(),
                status: PoolStatus::Unconfigured,
                window_5h: None,
                window_7d: None,
                in_flight: 0,
                sticky_proxy_ok: grok_px_ok,
                cooldown_secs: 0,
                steps_24h: None,
                source: "grok_oauth".to_string(),
            });
        }
    }

    // Overflow pool 2: Grok Bot
    if let Some(c) = load_grok_bot_creds(&ctx.cfg.state_dir) {
        let status = if c.quarantined_reason.is_some() {
            PoolStatus::Disabled
        } else if !grok_px_ok {
            PoolStatus::Cooldown
        } else {
            PoolStatus::Ready
        };
        cards.push(PoolCard {
            pool_id: "grok_bot".to_string(),
            engine: "grok_bot".to_string(),
            label: "Grok Bot".to_string(),
            masked_identity: c.masked_email().unwrap_or_else(|| "PKCE".to_string()),
            status,
            window_5h: None,
            window_7d: None,
            in_flight: 0,
            sticky_proxy_ok: grok_px_ok,
            cooldown_secs: 0,
            steps_24h: None,
            source: "grok_bot".to_string(),
        });
    }

    // Overflow pool 3: Gemini Manager
    let gpool = GeminiAccountPool::load_locked(&ctx.cfg.state_dir);
    if !gpool.accounts.is_empty() {
        let now_u = now.max(0) as u64;
        let mut ready_cnt = 0usize;
        let mut any_proxy_blocked = false;
        for a in &gpool.accounts {
            let blocked = ctx
                .proxies
                .resolve_at(a.proxy_id.as_deref(), now)
                .is_blocked();
            if blocked {
                any_proxy_blocked = true;
            }
            if a.enabled && !a.is_cooled_down(now_u) && !blocked {
                ready_cnt += 1;
            }
        }
        cards.push(PoolCard {
            pool_id: "gemini_web".to_string(),
            engine: "gemini_web".to_string(),
            label: format!("Gemini Web ({ready_cnt}/{})", gpool.accounts.len()),
            masked_identity: format!("{ready_cnt} ready"),
            status: if ready_cnt > 0 {
                PoolStatus::Ready
            } else if any_proxy_blocked {
                PoolStatus::Disabled
            } else {
                PoolStatus::Cooldown
            },
            window_5h: None,
            window_7d: None,
            in_flight: 0,
            sticky_proxy_ok: !any_proxy_blocked,
            cooldown_secs: 0,
            steps_24h: None,
            source: "gemini_web".to_string(),
        });
    }

    // Overflow pool 4: Venice Uncensored
    if !ctx.cfg.venice_api_key.trim().is_empty() {
        cards.push(PoolCard {
            pool_id: "uncensored".to_string(),
            engine: "uncensored".to_string(),
            label: "Venice".to_string(),
            masked_identity: "configured".to_string(),
            status: PoolStatus::Ready,
            window_5h: None,
            window_7d: None,
            in_flight: 0,
            sticky_proxy_ok: true,
            cooldown_secs: 0,
            steps_24h: None,
            source: "venice".to_string(),
        });
    }

    assemble_snapshot(
        now,
        cards,
        ctx.jobs.active_global_jobs(),
        ctx.jobs.max_global_jobs(),
        ls_rpc_live,
        sqlite_steps_24h,
    )
}

/// Build `(compact_chat_data, rich_state)` for the built-in `"telemetry"` widget.
/// Strictly owner-gated so non-owners cannot enumerate internal pools.
pub async fn build_telemetry_widget_states(
    ctx: &Arc<BotCtx>,
    uid: i64,
    force_refresh: bool,
) -> (Value, Value) {
    if !ctx.is_owner(uid) {
        let denied = json!({
            "ok": false,
            "denied": true,
            "mode": "restricted",
            "reason": "Owner only",
            "pools": [],
            "advice": []
        });
        return (denied.clone(), denied);
    }

    let snap = collect_live_telemetry_snapshot(ctx, force_refresh).await;
    let u = ctx.store.get_user(uid);
    let cur_eng = u
        .extra
        .get("engine")
        .and_then(Value::as_str)
        .unwrap_or("agy")
        .to_string();

    let compact_pools: Vec<Value> = snap
        .pools
        .iter()
        .take(10)
        .map(|p| {
            let w5 = p
                .window_5h
                .as_ref()
                .map(|w| format_tokens_compact(w.used_tokens))
                .unwrap_or_else(|| "—".to_string());
            let w7 = p
                .window_7d
                .as_ref()
                .map(|w| match w.used_pct {
                    Some(pct) => format!("{pct:.0}%"),
                    None => format_tokens_compact(w.used_tokens),
                })
                .unwrap_or_else(|| "—".to_string());
            json!({
                "id": p.pool_id,
                "eng": p.engine,
                "lbl": p.label,
                "st": p.status.as_str(),
                "w5": w5,
                "w7": w7,
                "inf": p.in_flight,
                "px": p.sticky_proxy_ok,
            })
        })
        .collect();

    let compact_advice: Vec<Value> = snap
        .advice
        .iter()
        .take(4)
        .map(|a| {
            json!({
                "sev": a.severity,
                "t": a.title_en,
                "d": a.detail_en,
            })
        })
        .collect();

    let compact = json!({
        "ok": true,
        "mode": snap.verdict.mode.as_str(),
        "mlbl": snap.verdict.mode.label_en(),
        "rec": snap.verdict.recommended_engine,
        "why": snap.verdict.reason_en,
        "eng": cur_eng,
        "act": snap.active_jobs,
        "max": snap.max_jobs,
        "st24": snap.sqlite_steps_24h,
        "ls": snap.ls_rpc_live,
        "pools": compact_pools,
        "adv": compact_advice,
    });

    let rich = json!({
        "ok": true,
        "engine": cur_eng,
        "snapshot": snap,
        "mode": snap.verdict.mode.as_str(),
        "mlbl": snap.verdict.mode.label_en(),
        "rec": snap.verdict.recommended_engine,
        "why": snap.verdict.reason_en,
        "eng": cur_eng,
        "act": snap.active_jobs,
        "max": snap.max_jobs,
        "st24": snap.sqlite_steps_24h,
        "ls": snap.ls_rpc_live,
        "pools": compact_pools,
        "adv": compact_advice,
    });

    (compact, rich)
}

/// Format a sanitized, mobile-friendly GFM Rich Markdown cockpit for `/quota`.
pub fn format_quota_cockpit_md(snap: &TelemetrySnapshot, lang: Lang) -> String {
    let is_fa = matches!(lang, Lang::Fa);
    let mut lines = Vec::new();
    let mode_lbl = if is_fa {
        snap.verdict.mode.label_fa()
    } else {
        snap.verdict.mode.label_en()
    };
    let reason = if is_fa {
        &snap.verdict.reason_fa
    } else {
        &snap.verdict.reason_en
    };

    if is_fa {
        lines.push("## 📊 کاکپیت سهمیه و مسیریابی (Quota Cockpit)".to_string());
        lines.push(format!(
            "> **وضعیت:** `{mode_lbl}` · **پیشنهاد:** `{}` · **اسلات فعال:** `{}/{}`",
            snap.verdict.recommended_engine, snap.active_jobs, snap.max_jobs
        ));
    } else {
        lines.push("## 📊 Quota & Burn-Rate Cockpit".to_string());
        lines.push(format!(
            "> **Mode:** `{mode_lbl}` · **Recommended:** `{}` · **Active Slots:** `{}/{}`",
            snap.verdict.recommended_engine, snap.active_jobs, snap.max_jobs
        ));
    }
    lines.push(format!("> {reason}"));

    if let Some(steps) = snap.sqlite_steps_24h {
        let ls_tag = if snap.ls_rpc_live { "LS-RPC live" } else { "local DB" };
        lines.push(format!(
            "> Activity 24h: `{steps}` steps · Telemetry: `{ls_tag}`"
        ));
    }

    lines.push(String::new());
    lines.push("| Pool | Status | 5h / 7d | Proxy |".to_string());
    lines.push("|---|---|---|---|".to_string());

    for p in &snap.pools {
        let st_icon = match p.status {
            PoolStatus::Ready => "✅ ready",
            PoolStatus::Cooldown => "⏳ wait",
            PoolStatus::Reserved => "🛡 1% res",
            PoolStatus::Disabled => "⛔ off",
            PoolStatus::Unconfigured => "⚪ none",
        };
        let usage = match (&p.window_5h, &p.window_7d) {
            (Some(w5), Some(w7)) => {
                let s5 = format_tokens_compact(w5.used_tokens);
                let s7 = match w7.used_pct {
                    Some(pct) => format!("{pct:.0}%"),
                    None => format_tokens_compact(w7.used_tokens),
                };
                format!("{s5} / {s7}")
            }
            _ => p.masked_identity.clone(),
        };
        let px = if !p.sticky_proxy_ok {
            "⛔ blk"
        } else if p.in_flight > 0 {
            "⚡ busy"
        } else {
            "✓ ok"
        };
        lines.push(format!(
            "| `{}` | {} | `{}` | {} |",
            md_cell(&p.label),
            st_icon,
            md_cell(&usage),
            px
        ));
    }

    if !snap.advice.is_empty() {
        lines.push(String::new());
        lines.push(if is_fa {
            "### 💡 پیشنهادهای بهینه‌سازی مصرف".to_string()
        } else {
            "### 💡 Burn & Routing Advice".to_string()
        });
        for a in &snap.advice {
            let icon = match a.severity {
                AdviceSeverity::Warn => "⚠️",
                AdviceSeverity::Tip => "⚡",
                AdviceSeverity::Info => "ℹ️",
            };
            let title = if is_fa { &a.title_fa } else { &a.title_en };
            let detail = if is_fa { &a.detail_fa } else { &a.detail_en };
            lines.push(format!("- {icon} **{title}** — {detail}"));
        }
    }

    lines.join("\n")
}

/// Render or edit the owner-only `/quota` cockpit.
pub async fn show_quota_cockpit(
    ctx: &Arc<BotCtx>,
    cq: Option<&CallbackQuery>,
    chat_id: i64,
    uid: i64,
    force_refresh: bool,
) {
    if !ctx.is_owner(uid) {
        let html = owner_only_html(ctx, uid);
        let _ = ctx.render.send_html_simple(chat_id, &html, None).await;
        return;
    }
    let snap = collect_live_telemetry_snapshot(ctx, force_refresh).await;
    let lang = ctx.lang(uid);
    let md_raw = format_quota_cockpit_md(&snap, lang);
    // Runtime belt-and-suspenders redaction (active in both debug and release builds).
    let md = agy_ext::mcp_client::redact_secrets_in_text(&ctx.proxies.redact_all(&md_raw));
    debug_assert!(
        scan_secret_leaks(&md, &[]).is_empty(),
        "telemetry cockpit must never leak secrets"
    );

    let rows = vec![
        vec![
            ctx.btn("refresh", "🔄 Refresh", Some("quota:ref"), Some("primary"), None),
            ctx.btn("status", "📊 Telemetry Widget", Some("wmenu:send:telemetry"), None, None),
        ],
        vec![
            ctx.btn("grok", "⚡ Use Grok", Some("qsw:grok"), None, None),
            ctx.btn("gemini", "💎 Use Gemini Web", Some("qsw:gemini_web"), None, None),
        ],
        vec![
            ctx.btn("bolt", "🤖 Use Antigravity", Some("qsw:agy"), None, None),
            ctx.btn("admin", "🛡 Accounts", Some("acct:list"), None, None),
        ],
        vec![ctx.btn("back", "« Admin Menu", Some("home:2"), None, None)],
    ];

    let msg_id = cq.and_then(|c| c.message.as_ref()).map(|m| m.message_id);
    let _ = ctx
        .render
        .edit_or_send_rich(chat_id, msg_id, &md, Some(BotCtx::kb(rows)))
        .await;
}

pub async fn cmd_quota(ctx: &Arc<BotCtx>, msg: &Message, arg: &str) {
    let uid = msg.from_user.as_ref().map(|u| u.id).unwrap_or(0);
    let force = arg.trim().eq_ignore_ascii_case("refresh") || arg.trim() == "-r";
    Box::pin(show_quota_cockpit(ctx, None, msg.chat.id, uid, force)).await;
}

pub async fn handle_quota_cb(
    ctx: &Arc<BotCtx>,
    cq: &CallbackQuery,
    uid: i64,
    chat_id: i64,
    data: &str,
) -> bool {
    if data != "quota" && !data.starts_with("quota:") {
        return false;
    }
    if !ctx.is_owner(uid) {
        ctx.ack(&cq.id, Some("Owner only"), true).await;
        return true;
    }
    let force = data == "quota:ref";
    ctx.ack(
        &cq.id,
        Some(if force { "Refreshing telemetry…" } else { "Quota Cockpit" }),
        false,
    )
    .await;
    Box::pin(show_quota_cockpit(ctx, Some(cq), chat_id, uid, force)).await;
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use agy_core::telemetry::{PoolWindow, RoutingMode};

    #[test]
    fn cockpit_markdown_passes_secret_scanner_in_fa_and_en() {
        let snap = assemble_snapshot(
            1_700_000_000,
            vec![
                PoolCard {
                    pool_id: "acc3".into(),
                    engine: "agy".into(),
                    label: "acc3 · us…er@example.com".into(),
                    masked_identity: "us…er@example.com".into(),
                    status: PoolStatus::Ready,
                    window_5h: Some(PoolWindow {
                        used_tokens: 120_000,
                        budget_tokens: None,
                        used_pct: None,
                        remaining_pct: None,
                        reset_in_secs: 7200,
                        is_reserved: false,
                    }),
                    window_7d: Some(PoolWindow {
                        used_tokens: 4_000_000,
                        budget_tokens: Some(10_000_000),
                        used_pct: Some(40.0),
                        remaining_pct: Some(60.0),
                        reset_in_secs: 300_000,
                        is_reserved: false,
                    }),
                    in_flight: 1,
                    sticky_proxy_ok: true,
                    cooldown_secs: 0,
                    steps_24h: Some(42),
                    source: "accounts.json+sqlite".into(),
                },
                PoolCard {
                    pool_id: "grok".into(),
                    engine: "grok".into(),
                    label: "Grok OAuth".into(),
                    masked_identity: "x.ai OAuth".into(),
                    status: PoolStatus::Ready,
                    window_5h: None,
                    window_7d: None,
                    in_flight: 0,
                    sticky_proxy_ok: true,
                    cooldown_secs: 0,
                    steps_24h: None,
                    source: "grok_oauth".into(),
                },
            ],
            1,
            4,
            false,
            Some(42),
        );
        assert_eq!(snap.verdict.mode, RoutingMode::Balanced);
        let fa = format_quota_cockpit_md(&snap, Lang::Fa);
        let en = format_quota_cockpit_md(&snap, Lang::En);
        assert!(scan_secret_leaks(&fa, &[]).is_empty());
        assert!(scan_secret_leaks(&en, &[]).is_empty());
        assert!(fa.contains("کاکپیت سهمیه"));
        assert!(en.contains("Quota & Burn-Rate Cockpit"));
    }
}
