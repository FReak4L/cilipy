//! `/proxies` management panel (`px:*` callbacks):
//! - Shows Bot Telegram Transport routes (`ctx.pool`) and AI Account Sticky Egress Proxies (`ctx.proxies`).
//! - Owner can add/probe/pause/enable/rename/remove proxies, bind Grok OAuth proxy, and toggle
//!   `FailClosed` (default — prevents leaking server IP) vs `FallbackDirect`.
//! - Users with `status_net` permission can view read-only proxy health summary.
//! - Messages where the owner pastes proxy URLs (potentially containing `user:pass@`) are deleted
//!   from chat immediately and never logged unredacted.

use std::sync::Arc;

use agy_core::proxies::{ProxyEntry, ProxyFallbackPolicy, ProxyHealthStatus};
use agy_core::tg::{CallbackQuery, InlineKeyboardButton, Message};
use agy_net::probe_proxy_route;
use agy_render::{esc, md_cell};
use serde_json::json;
use tracing::{info, warn};

use crate::ctx::BotCtx;
use crate::i18n::{missing_perm_html, owner_only_html, t, Tx};
use crate::jobs::{human_secs, AwaitingInput};

fn now_unix() -> i64 {
    chrono::Utc::now().timestamp()
}

fn health_icon(e: &ProxyEntry) -> &'static str {
    if !e.enabled {
        return "⏸";
    }
    match e.health.status {
        ProxyHealthStatus::Healthy => "🟢",
        ProxyHealthStatus::Degraded => "🟡",
        ProxyHealthStatus::Unhealthy => "🔴",
        ProxyHealthStatus::Unknown => "⚪",
    }
}

fn status_text(e: &ProxyEntry) -> String {
    if !e.enabled {
        return "paused".to_string();
    }
    match e.health.status {
        ProxyHealthStatus::Healthy => "healthy".to_string(),
        ProxyHealthStatus::Degraded => "degraded".to_string(),
        ProxyHealthStatus::Unhealthy => "unhealthy".to_string(),
        ProxyHealthStatus::Unknown => "untested".to_string(),
    }
}

fn ago(ts: Option<i64>) -> String {
    match ts {
        Some(t) if t > 0 => format!("{} ago", human_secs((now_unix() - t).max(0) as u64)),
        _ => "—".to_string(),
    }
}

fn clip(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        s.to_string()
    } else {
        let head: String = s.chars().take(max_chars).collect();
        format!("{head}…")
    }
}

async fn card(
    ctx: &BotCtx,
    cq: Option<&CallbackQuery>,
    chat_id: i64,
    md: &str,
    rows: Vec<Vec<InlineKeyboardButton>>,
) {
    let msg_id = cq.and_then(|c| c.message.as_ref()).map(|m| m.message_id);
    let mk = (!rows.is_empty()).then(|| BotCtx::kb(rows));
    let _ = ctx.render.edit_or_send_rich(chat_id, msg_id, md, mk).await;
}

/// Probe a single registered AI egress proxy and persist its health/latency/score.
pub async fn probe_one_proxy(ctx: &BotCtx, id: &str) -> Option<ProxyEntry> {
    let entry = ctx.proxies.get(id)?;
    let res = probe_proxy_route(
        Some(&entry.url),
        None,
        ctx.cfg.force_ipv4,
        std::time::Duration::from_secs(10),
    )
    .await;
    if res.ok {
        ctx.proxies.record_probe_ok(id, res.latency_ms);
    } else {
        let err_msg = res
            .error
            .unwrap_or_else(|| format!("HTTP {:?}", res.status_code));
        ctx.proxies.record_probe_fail(id, &err_msg);
    }
    ctx.proxies.get(id)
}

/// Probe all enabled AI egress proxies sequentially with a gentle 1.5s gap.
pub async fn probe_all_proxies(ctx: &BotCtx) -> (usize, usize) {
    let entries = ctx.proxies.list();
    let mut probed = 0usize;
    let mut ok_count = 0usize;
    for e in entries {
        if !e.enabled {
            continue;
        }
        probed += 1;
        if let Some(updated) = probe_one_proxy(ctx, &e.id).await {
            if matches!(
                updated.health.status,
                ProxyHealthStatus::Healthy | ProxyHealthStatus::Degraded
            ) {
                ok_count += 1;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
    }
    (ok_count, probed)
}

/// `/proxies` command (Owner or `status_net`).
pub async fn cmd_proxies(ctx: &Arc<BotCtx>, msg: &Message, _arg: &str) {
    let Some(uid) = msg.from_user.as_ref().map(|u| u.id) else {
        return;
    };
    if !ctx.is_owner(uid) && !ctx.has_perm(uid, "status_net") {
        let _ = ctx
            .render
            .send_html_simple(msg.chat.id, &missing_perm_html(ctx, uid, "status_net"), None)
            .await;
        return;
    }
    show_proxies_list(ctx, None, msg.chat.id, uid).await;
}

/// Render or edit the unified `/proxies` overview card.
pub async fn show_proxies_list(
    ctx: &Arc<BotCtx>,
    cq: Option<&CallbackQuery>,
    chat_id: i64,
    uid: i64,
) {
    let is_owner = ctx.is_owner(uid);
    let lang = ctx.lang(uid);
    let entries = ctx.proxies.list();
    let fb = ctx.proxies.fallback_policy();
    let grok_px_id = ctx.proxies.grok_proxy_id();
    let bot_snap = ctx.pool.snapshot();
    let bot_ok = bot_snap.active_healthy;
    let bot_tot = bot_snap.routes.len();
    let acct_list = ctx.jobs.accounts().map(|p| p.list()).unwrap_or_default();

    let mut md = vec![
        format!("### {} {}", ctx.premium.md("web"), t(lang, Tx::PanelProxiesTitle)),
        format!(
            "> **Bot Transport:** {bot_ok}/{bot_tot} route(s) healthy · **AI Egress:** {} proxy(ies)\n> **Fallback Policy:** `{}` ({})",
            entries.len(),
            fb.label(),
            if fb == ProxyFallbackPolicy::FailClosed {
                "blocks account instead of leaking server IP"
            } else {
                "falls back to direct server IP if proxy down"
            }
        ),
        String::new(),
    ];

    let mut rows: Vec<Vec<InlineKeyboardButton>> = Vec::new();

    if entries.is_empty() {
        md.push("_No sticky AI egress proxies configured yet. All accounts currently connect directly._".to_string());
        if is_owner {
            md.push(String::new());
            md.push("> Tip: Add dedicated **1:1 residential/ISP SOCKS5 or HTTP(S)** proxies here, then bind one per account in `/accounts`.".to_string());
        }
    } else {
        md.push("| Proxy | Status | Score | Bound |".to_string());
        md.push("|---|---|---|---|".to_string());
        let mut entry_btns: Vec<InlineKeyboardButton> = Vec::new();
        for e in &entries {
            let mut bound: Vec<String> = acct_list
                .iter()
                .filter(|a| a.proxy_id.as_deref() == Some(e.id.as_str()))
                .map(|a| a.id.clone())
                .collect();
            if grok_px_id.as_deref() == Some(e.id.as_str()) {
                bound.push("⚡grok".to_string());
            }
            let bound_str = if bound.is_empty() {
                "—".to_string()
            } else {
                bound.join(", ")
            };
            let score_str = match e.health.latency_ms {
                Some(ms) => format!("{} ({}ms)", e.health.quality_score, ms),
                None => format!("{}", e.health.quality_score),
            };
            md.push(format!(
                "| {} {} | {} | {} | {} |",
                health_icon(e),
                md_cell(&clip(&e.display_name(), 22)),
                md_cell(&status_text(e)),
                md_cell(&score_str),
                md_cell(&clip(&bound_str, 18)),
            ));
            if is_owner {
                entry_btns.push(ctx.btn(
                    "",
                    &format!("{} {} ({})", health_icon(e), clip(&e.display_name(), 16), e.health.quality_score),
                    Some(&format!("px:v:{}", e.id)),
                    None,
                    None,
                ));
            }
        }
        if is_owner {
            for chunk in entry_btns.chunks(2) {
                rows.push(chunk.to_vec());
            }
        }
    }

    if is_owner {
        rows.push(vec![
            ctx.btn("add", "Add Proxy", Some("px:add"), Some("success"), None),
            ctx.btn("status", "Probe All", Some("px:probe_all"), None, None),
        ]);
        let fb_lbl = match fb {
            ProxyFallbackPolicy::FailClosed => "🔒 Fail-Closed",
            ProxyFallbackPolicy::FallbackDirect => "⚠️ Fallback-Direct",
        };
        rows.push(vec![
            ctx.btn("", fb_lbl, Some("px:fb"), None, None),
            ctx.btn("account", t(lang, Tx::BtnAccounts), Some("acct:list"), None, None),
        ]);
    }

    let back_cb = if is_owner { "home:2" } else { "home:1" };
    rows.push(vec![
        ctx.btn("refresh", t(lang, Tx::BtnRefresh), Some("px:list"), None, None),
        ctx.btn("back", t(lang, Tx::BtnMenu), Some(back_cb), None, None),
    ]);

    card(ctx, cq, chat_id, &md.join("\n"), rows).await;
}

/// Render detailed view for a single proxy (owner only).
pub async fn show_proxy_detail(
    ctx: &Arc<BotCtx>,
    cq: Option<&CallbackQuery>,
    chat_id: i64,
    uid: i64,
    id: &str,
) {
    let Some(e) = ctx.proxies.get(id) else {
        show_proxies_list(ctx, cq, chat_id, uid).await;
        return;
    };
    let grok_bound = ctx.proxies.grok_proxy_id().as_deref() == Some(e.id.as_str());
    let bound_accts: Vec<String> = ctx
        .jobs
        .accounts()
        .map(|p| {
            p.list()
                .into_iter()
                .filter(|a| a.proxy_id.as_deref() == Some(e.id.as_str()))
                .map(|a| format!("{} ({})", a.display_name(), a.id))
                .collect()
        })
        .unwrap_or_default();
    let lat_str = e
        .health
        .latency_ms
        .map(|ms| format!("{ms} ms"))
        .unwrap_or_else(|| "—".to_string());
    let bound_str = if bound_accts.is_empty() {
        "none (bind in /accounts)".to_string()
    } else {
        bound_accts.join(", ")
    };

    let mut md = vec![
        format!("### {} {}", health_icon(&e), md_cell(&e.display_name())),
        String::new(),
        "| Field | Value |".to_string(),
        "|---|---|".to_string(),
        format!("| ID | `{}` |", e.id),
        format!("| Endpoint | `{}` |", md_cell(&e.safe_label())),
        format!("| Status | {} ({}) |", md_cell(&status_text(&e)), if e.enabled { "enabled" } else { "paused" }),
        format!("| Quality Score | **{} / 100** |", e.health.quality_score),
        format!("| Latency | {} |", lat_str),
        format!("| Checks (OK / Fail) | {} / {} (streak: {}) |", e.health.total_ok, e.health.total_fail, e.health.consecutive_failures),
        format!("| Last Checked | {} |", ago(e.health.last_checked_ts)),
        format!("| AGY Accounts | {} |", md_cell(&clip(&bound_str, 80))),
        format!("| Grok OAuth | {} |", if grok_bound { "✅ bound" } else { "no" }),
    ];

    if let Some(ref err) = e.health.last_error {
        md.push(String::new());
        md.push(format!("> ⚠️ **Last error:** {}", md_cell(&clip(err, 220))));
    }

    let tog = if e.enabled {
        ctx.btn("stop", "⏸ Pause", Some(&format!("px:en:{}:0", e.id)), None, None)
    } else {
        ctx.btn("ok", "▶ Enable", Some(&format!("px:en:{}:1", e.id)), Some("success"), None)
    };
    let grok_btn = if grok_bound {
        ctx.btn("", "⚡ Unbind Grok", Some("px:grok_off"), None, None)
    } else {
        ctx.btn("", "⚡ Bind to Grok", Some(&format!("px:grok:{}", e.id)), None, None)
    };

    let rows = vec![
        vec![
            ctx.btn("status", "🩺 Probe Now", Some(&format!("px:probe:{}", e.id)), Some("primary"), None),
            tog,
        ],
        vec![
            grok_btn,
            ctx.btn("", "✏️ Rename", Some(&format!("px:ren:{}", e.id)), None, None),
        ],
        vec![
            ctx.btn("remove", "Remove", Some(&format!("px:rm:{}", e.id)), Some("danger"), None),
            ctx.btn("back", "Proxies", Some("px:list"), None, None),
            ctx.btn("menu", t(ctx.lang(uid), Tx::BtnMenu), Some("home:2"), None, None),
        ],
    ];
    card(ctx, cq, chat_id, &md.join("\n"), rows).await;
}

/// Handle `px:*` callbacks. Returns `true` if handled.
pub async fn handle_px_cb(
    ctx: &Arc<BotCtx>,
    cq: &CallbackQuery,
    uid: i64,
    chat_id: i64,
    data: &str,
) -> bool {
    let Some(rest) = data.strip_prefix("px:") else {
        return false;
    };
    if !ctx.is_owner(uid) && !ctx.has_perm(uid, "status_net") {
        ctx.ack(&cq.id, Some("Permission denied"), true).await;
        return true;
    }

    let mut parts = rest.splitn(3, ':');
    let action = parts.next().unwrap_or("");
    let id = parts.next().unwrap_or("").to_string();
    let arg = parts.next().unwrap_or("");

    if action == "list" {
        ctx.ack(&cq.id, None, false).await;
        show_proxies_list(ctx, Some(cq), chat_id, uid).await;
        return true;
    }

    if !ctx.is_owner(uid) {
        ctx.ack(&cq.id, Some(t(ctx.lang(uid), Tx::OwnerOnly)), true).await;
        return true;
    }

    match action {
        "v" => {
            ctx.ack(&cq.id, None, false).await;
            show_proxy_detail(ctx, Some(cq), chat_id, uid, &id).await;
        }
        "add" => {
            ctx.ack(&cq.id, None, false).await;
            ctx.jobs
                .set_awaiting(uid, AwaitingInput::new("px_add", json!({})));
            let html = "➕ <b>Add Sticky Egress Proxy</b>\n\
                <blockquote>Send the proxy URL as a normal message:\n\
                <code>socks5h://user:pass@host:port</code>\n\
                or with an optional label:\n\
                <code>http://user:pass@1.2.3.4:8080 DE-ISP-1</code></blockquote>\n\
                <i>Supported: <code>http</code>, <code>https</code>, <code>socks5</code>, <code>socks5h</code>.\n\
                Your message is deleted immediately so credentials never stay in chat.</i>";
            let mk = BotCtx::kb(vec![vec![ctx.btn(
                "stop",
                "Cancel",
                Some("inp:cancel"),
                Some("danger"),
                None,
            )]]);
            let _ = ctx.render.send_html_simple(chat_id, html, Some(mk)).await;
        }
        "probe" => {
            ctx.ack(&cq.id, Some("Probing proxy (TLS/HTTP 204)…"), false).await;
            let _ = probe_one_proxy(ctx, &id).await;
            show_proxy_detail(ctx, Some(cq), chat_id, uid, &id).await;
        }
        "probe_all" => {
            ctx.ack(&cq.id, Some("Probing all enabled proxies…"), false).await;
            let (ok_n, tot) = probe_all_proxies(ctx).await;
            info!(ok = ok_n, total = tot, "manual proxy probe_all finished");
            show_proxies_list(ctx, Some(cq), chat_id, uid).await;
        }
        "en" => {
            let on = arg == "1";
            let _ = ctx.proxies.set_enabled(&id, on);
            ctx.ack(&cq.id, Some(if on { "Proxy enabled" } else { "Proxy paused" }), false)
                .await;
            show_proxy_detail(ctx, Some(cq), chat_id, uid, &id).await;
        }
        "fb" => {
            let next = match ctx.proxies.fallback_policy() {
                ProxyFallbackPolicy::FailClosed => ProxyFallbackPolicy::FallbackDirect,
                ProxyFallbackPolicy::FallbackDirect => ProxyFallbackPolicy::FailClosed,
            };
            let _ = ctx.proxies.set_fallback_policy(next);
            ctx.ack(&cq.id, Some(next.label()), false).await;
            show_proxies_list(ctx, Some(cq), chat_id, uid).await;
        }
        "grok" => {
            match ctx.proxies.set_grok_proxy(Some(&id)) {
                Ok(()) => ctx.ack(&cq.id, Some("Bound to Grok OAuth"), false).await,
                Err(e) => ctx.ack(&cq.id, Some(&clip(&e.to_string(), 140)), true).await,
            }
            show_proxy_detail(ctx, Some(cq), chat_id, uid, &id).await;
        }
        "grok_off" => {
            let _ = ctx.proxies.set_grok_proxy(None);
            ctx.ack(&cq.id, Some("Grok set to direct"), false).await;
            show_proxies_list(ctx, Some(cq), chat_id, uid).await;
        }
        "ren" => {
            ctx.ack(&cq.id, None, false).await;
            ctx.jobs
                .set_awaiting(uid, AwaitingInput::new("px_label", json!({ "id": id })));
            let mk = BotCtx::kb(vec![vec![ctx.btn(
                "stop",
                "Cancel",
                Some("inp:cancel"),
                Some("danger"),
                None,
            )]]);
            let _ = ctx
                .render
                .send_html_simple(
                    chat_id,
                    &format!(
                        "✏️ Send a new label for proxy <code>{}</code> (max 32 chars).",
                        esc(&id)
                    ),
                    Some(mk),
                )
                .await;
        }
        "rm" => {
            ctx.ack(&cq.id, None, false).await;
            let md = format!(
                "### 🗑 Remove proxy `{id}`?\n\n> Any Antigravity account or Grok binding pointing to `{id}` will be unbound back to `direct`."
            );
            let rows = vec![vec![
                ctx.btn("", "Yes, remove", Some(&format!("px:rmy:{id}")), Some("danger"), None),
                ctx.btn("", "Cancel", Some(&format!("px:v:{id}")), None, None),
            ]];
            card(ctx, Some(cq), chat_id, &md, rows).await;
        }
        "rmy" => {
            if let Some(pool) = ctx.jobs.accounts() {
                if let Ok(cleared) = pool.clear_proxy_bindings(&id) {
                    if cleared > 0 {
                        info!(proxy = %id, accounts = cleared, "unbound accounts from removed proxy");
                    }
                }
            }
            match ctx.proxies.remove(&id) {
                Ok(()) => ctx.ack(&cq.id, Some("Proxy removed"), false).await,
                Err(e) => ctx.ack(&cq.id, Some(&clip(&e.to_string(), 140)), true).await,
            }
            show_proxies_list(ctx, Some(cq), chat_id, uid).await;
        }
        _ => ctx.ack(&cq.id, None, false).await,
    }
    true
}

/// Handle `px_add` and `px_label` awaiting text inputs. Returns `true` if consumed.
pub async fn handle_proxies_awaiting_text(
    ctx: &Arc<BotCtx>,
    msg: &Message,
    uid: i64,
    chat_id: i64,
    inp: &AwaitingInput,
    text: &str,
) -> bool {
    match inp.kind.as_str() {
        "px_add" => {
            // Always delete user's message immediately so credentials never remain in chat!
            let _ = ctx.client.delete_message(chat_id, msg.message_id).await;
            if !ctx.is_owner(uid) {
                let _ = ctx
                    .render
                    .send_html_simple(chat_id, &owner_only_html(ctx, uid), None)
                    .await;
                return true;
            }
            let trimmed = text.trim();
            let (raw_url, raw_label) = if let Some((u, l)) = trimmed.split_once('|') {
                (u.trim(), Some(l.trim()))
            } else if let Some((u, l)) = trimmed.split_once(char::is_whitespace) {
                (u.trim(), Some(l.trim()))
            } else {
                (trimmed, None)
            };
            match ctx.proxies.add(raw_url, raw_label.unwrap_or("")) {
                Ok(entry) => {
                    let wait = ctx
                        .render
                        .send_html_simple(
                            chat_id,
                            &format!(
                                "🩺 <i>Added <code>{}</code> — probing connectivity…</i>",
                                esc(&entry.safe_label())
                            ),
                            None,
                        )
                        .await
                        .ok()
                        .flatten();
                    let _ = probe_one_proxy(ctx, &entry.id).await;
                    if let Some(m) = wait {
                        let _ = ctx.client.delete_message(chat_id, m.message_id).await;
                    }
                    show_proxy_detail(ctx, None, chat_id, uid, &entry.id).await;
                }
                Err(err) => {
                    warn!(error = %err, "invalid proxy URL submitted");
                    ctx.jobs
                        .set_awaiting(uid, AwaitingInput::new("px_add", json!({})));
                    let _ = ctx
                        .render
                        .send_html_simple(
                            chat_id,
                            &format!(
                                "{} <b>Invalid proxy:</b> <code>{}</code>\n<i>Try again or send /cancel.</i>",
                                ctx.e("err"),
                                esc(&err.to_string())
                            ),
                            None,
                        )
                        .await;
                }
            }
            true
        }
        "px_label" => {
            if !ctx.is_owner(uid) {
                return true;
            }
            let id = inp.data.get("id").and_then(|v| v.as_str()).unwrap_or("");
            let _ = ctx.proxies.rename(id, text);
            show_proxy_detail(ctx, None, chat_id, uid, id).await;
            true
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agy_core::acl::{AclStore, RolePreset, UserStatus};
    use agy_core::config::Config;
    use agy_core::health::HealthTracker;
    use agy_core::outbox::OutQueue;
    use agy_core::store::StateStore;
    use agy_core::tg::{Chat, User};
    use agy_net::{BotApiClient, NetConfig, ProxyPool};
    use agy_render::PremiumState;
    use agy_widgets::WidgetStore;
    use axum::extract::{Path as AxumPath, State};
    use axum::routing::post;
    use axum::{Json, Router};
    use serde_json::Value;
    use tempfile::TempDir;
    use tokio::net::TcpListener;
    use tokio::sync::Mutex;

    const OWNER: i64 = 1_000_000_001;
    const VIEWER: i64 = 7_700_000_001;

    #[derive(Clone, Default)]
    struct MockTg {
        calls: Arc<Mutex<Vec<(String, Value)>>>,
    }

    async fn mock_tg(
        State(st): State<MockTg>,
        AxumPath((_tok, method)): AxumPath<(String, String)>,
        Json(payload): Json<Value>,
    ) -> Json<Value> {
        st.calls.lock().await.push((method.clone(), payload));
        let res = match method.as_str() {
            "answerCallbackQuery" | "deleteMessage" => json!(true),
            _ => json!({"message_id": 55, "chat": {"id": OWNER, "type": "private"}, "text": "ok"}),
        };
        Json(json!({"ok": true, "result": res}))
    }

    async fn make_ctx(dir: &TempDir) -> (Arc<BotCtx>, MockTg) {
        let st = MockTg::default();
        let app = Router::new()
            .route("/bot{token}/{method}", post(mock_tg))
            .with_state(st.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let state_dir = dir.path().join("state");
        std::fs::create_dir_all(&state_dir).unwrap();
        let cfg = Arc::new(Config {
            bot_token: "1:T".into(),
            state_dir: state_dir.clone(),
            agy_workspace: dir.path().to_path_buf(),
            owner_id: OWNER,
            ..Default::default()
        });
        let store = Arc::new(StateStore::open(cfg.state_path()).unwrap());
        let acl = Arc::new(AclStore::open(cfg.acl_path(), OWNER, &[VIEWER], 300).unwrap());
        acl.set_status(VIEWER, UserStatus::Approved, Some(OWNER), Some(RolePreset::Std))
            .unwrap();
        acl.set_perm(VIEWER, "status_net", Some(true)).unwrap();
        let outbox = Arc::new(OutQueue::open(cfg.outbox_path()).unwrap());
        let health = Arc::new(HealthTracker::new(cfg.health_path()));
        let premium = Arc::new(PremiumState::new(false));
        let net_cfg = NetConfig::default().with_api_base(format!("http://{addr}"));
        let pool = Arc::new(ProxyPool::new(net_cfg.clone()).unwrap());
        let client = Arc::new(BotApiClient::new("1:T", net_cfg).unwrap());
        let widgets = Arc::new(WidgetStore::from_state_dir(&state_dir).unwrap());
        let render = Arc::new(crate::render_bridge::RenderBridge::new(
            Arc::clone(&client),
            Arc::clone(&premium),
            Arc::clone(&outbox),
        ));
        let cron = Arc::new(crate::cron::CronScheduler::new(Arc::clone(&cfg), Arc::clone(&health)).unwrap());
        let jobs = Arc::new(
            crate::jobs::JobManager::new(
                Arc::clone(&cfg),
                Arc::clone(&acl),
                Arc::clone(&store),
                Arc::clone(&render),
                Arc::clone(&client),
            )
            .unwrap(),
        );
        let auth = Arc::new(crate::auth::AuthGate::from_config(Arc::clone(&acl), &cfg));
        let ctx = BotCtx::new(
            cfg, store, acl, outbox, health, premium, pool, client, widgets, render, cron, jobs,
            auth,
        );
        (ctx, st)
    }

    fn mk_cq(uid: i64, data: &str) -> CallbackQuery {
        CallbackQuery {
            id: "cq-px".into(),
            from_user: User {
                id: uid,
                is_bot: false,
                first_name: "U".into(),
                last_name: None,
                username: None,
                language_code: None,
                is_premium: Some(false),
            },
            message: Some(Message {
                message_id: 10,
                from_user: None,
                chat: Chat {
                    id: uid,
                    kind: "private".into(),
                    username: None,
                    first_name: None,
                },
                message_thread_id: None,
                text: None,
                caption: None,
                entities: None,
                effect_id: None,
                reply_to_message: None,
                photo: None,
                document: None,
                video: None,
                audio: None,
                voice: None,
                animation: None,
                video_note: None,
                sticker: None,
                widget: None,
                business_connection_id: None,
                sender_business_bot: None,
            }),
            inline_message_id: None,
            data: Some(data.into()),
        }
    }

    #[tokio::test]
    async fn proxies_panel_enforces_rbac_redacts_secrets_and_toggles_policy() {
        let dir = TempDir::new().unwrap();
        let (ctx, st) = make_ctx(&dir).await;

        let added = ctx
            .proxies
            .add("socks5h://alice:supersecret99@198.51.100.10:1080", "DE-ISP-1")
            .unwrap();
        assert_eq!(added.id, "px1");

        // Viewer with status_net can view px:list (redacted, no owner mutate buttons), denied px:fb
        assert!(handle_px_cb(&ctx, &mk_cq(VIEWER, "px:list"), VIEWER, VIEWER, "px:list").await);
        assert!(handle_px_cb(&ctx, &mk_cq(VIEWER, "px:fb"), VIEWER, VIEWER, "px:fb").await);
        assert_eq!(ctx.proxies.fallback_policy(), ProxyFallbackPolicy::FailClosed);

        // Owner toggles fallback policy, binds Grok, renders detail (secret never leaked!)
        assert!(handle_px_cb(&ctx, &mk_cq(OWNER, "px:fb"), OWNER, OWNER, "px:fb").await);
        assert_eq!(ctx.proxies.fallback_policy(), ProxyFallbackPolicy::FallbackDirect);
        assert!(handle_px_cb(&ctx, &mk_cq(OWNER, "px:grok:px1"), OWNER, OWNER, "px:grok:px1").await);
        assert_eq!(ctx.proxies.grok_proxy_id().as_deref(), Some("px1"));

        let calls = st.calls.lock().await;
        for (_, payload) in calls.iter() {
            let dump = payload.to_string();
            assert!(!dump.contains("supersecret99"), "proxy secret leaked into Telegram payload: {dump}");
        }
        drop(calls);

        // Owner removes proxy -> Grok binding cleared
        assert!(handle_px_cb(&ctx, &mk_cq(OWNER, "px:rmy:px1"), OWNER, OWNER, "px:rmy:px1").await);
        assert!(ctx.proxies.is_empty());
        assert_eq!(ctx.proxies.grok_proxy_id(), None);
    }
}
