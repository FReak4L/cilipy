//! Handlers for xAI Grok Subscription OAuth 2.0 (RFC 8628 Device Authorization Grant —
//! NO API key required), autonomous Grok Agent/Chat mode toggle, endpoint selector, and model picker.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use agy_core::proxies::ResolvedProxy;
use agy_core::store::UserState;
use agy_core::tg::{CallbackQuery, CopyTextButton, InlineKeyboardButton, InlineKeyboardMarkup, Message};
use agy_ext::agent_runtime::{agent_tool_count, clear_session_history, session_message_count};
use agy_ext::grok_oauth::{
    delete_grok_creds, ensure_valid_grok_creds_via, is_grok_model, load_cached_grok_models,
    load_grok_creds, poll_device_token_once_via, refresh_grok_models_via, save_grok_creds,
    set_grok_endpoint_mode, start_device_auth_via, DevicePollOutcome, GrokAuthSession,
    GrokEndpointMode, GrokModel,
};
use agy_render::esc;
use serde_json::json;
use tracing::{info, warn};

use crate::ctx::BotCtx;
use crate::i18n::{missing_perm_html, owner_only_html, perm_label, t, Tx};
use crate::jobs::model_pick::MODEL_INVALID_KEY;
use crate::jobs::{JobOverride, JobRequest};

const MODELS_PER_PAGE: usize = 6;
pub const GROK_AGENT_MODE_KEY: &str = "grok_agent_mode";

struct ActiveGrokAuth {
    session: Arc<GrokAuthSession>,
    cancel_rx: tokio::sync::watch::Receiver<bool>,
    verification_uri: String,
    expires_at: Instant,
    polls: Arc<AtomicU32>,
    last_status: Arc<Mutex<Option<String>>>,
}

#[derive(Clone)]
struct GrokAuthSnapshot {
    verification_uri: String,
    user_code: String,
    open_url: String,
    remaining_secs: u64,
    polls: u32,
    last_status: Option<String>,
}

fn active_grok_auth() -> &'static Mutex<Option<ActiveGrokAuth>> {
    static ACTIVE: OnceLock<Mutex<Option<ActiveGrokAuth>>> = OnceLock::new();
    ACTIVE.get_or_init(|| Mutex::new(None))
}

fn active_grok_auth_snapshot() -> Option<GrokAuthSnapshot> {
    let mut slot = active_grok_auth().lock().unwrap_or_else(|e| e.into_inner());
    let cur = slot.as_ref()?;
    let now = Instant::now();
    if *cur.cancel_rx.borrow() || now >= cur.expires_at {
        *slot = None;
        return None;
    }
    let remaining_secs = cur.expires_at.saturating_duration_since(now).as_secs();
    let polls = cur.polls.load(Ordering::Relaxed);
    let last_status = cur
        .last_status
        .lock()
        .ok()
        .and_then(|g| g.clone());
    Some(GrokAuthSnapshot {
        verification_uri: cur.verification_uri.clone(),
        user_code: cur.session.user_code.clone(),
        open_url: cur.session.verification_url.clone(),
        remaining_secs,
        polls,
        last_status,
    })
}

fn fmt_mm_ss(secs: u64) -> String {
    format!("{:02}:{:02}", secs / 60, secs % 60)
}

fn render_device_auth_card(
    ctx: &BotCtx,
    verification_uri: &str,
    user_code: &str,
    open_url: &str,
    rem_secs: u64,
    polls: u32,
    status_note: Option<&str>,
) -> (String, InlineKeyboardMarkup) {
    let status_line = match status_note.filter(|s| !s.trim().is_empty()) {
        Some(note) => format!(
            "⏱ <b>Remaining:</b> <code>{}</code> · checked {}x · <i>{}</i>",
            fmt_mm_ss(rem_secs),
            polls,
            esc(note)
        ),
        None => format!(
            "⏱ <b>Remaining:</b> <code>{}</code> · checked {}x · <i>waiting for x.ai approval…</i>",
            fmt_mm_ss(rem_secs),
            polls
        ),
    };
    let txt = format!(
        "🔐 <b>Sign in to Grok Subscription (x.ai OAuth)</b>\n\
        <blockquote>1. Tap <b>Open x.ai Sign-In</b> below (or visit <code>{}</code>).\n\
        2. Enter code: <code>{}</code>\n\
        3. Approve access with your SuperGrok / X Premium+ account.\n\
        {status_line}</blockquote>",
        esc(verification_uri),
        esc(user_code),
    );
    let copy_btn = InlineKeyboardButton {
        text: format!("📋 Copy Code: {user_code}"),
        copy_text: Some(CopyTextButton {
            text: user_code.to_string(),
        }),
        ..Default::default()
    };
    let mk = BotCtx::kb(vec![
        vec![ctx.btn("", "🌐 Open x.ai Sign-In", None, Some("primary"), Some(open_url))],
        vec![copy_btn],
        vec![
            ctx.btn("", "🔄 New Code", Some("grok:auth"), None, None),
            ctx.btn("", "✖ Cancel Login", Some("grok:auth_cancel"), Some("danger"), None),
        ],
        vec![
            ctx.btn("", "« Grok Panel", Some("grok:open"), None, None),
            ctx.btn("menu", "Menu", Some("home"), None, None),
        ],
    ]);
    (txt, mk)
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn truncate_chars(s: &str, max_chars: usize) -> String {
    let count = s.chars().count();
    if count <= max_chars {
        s.to_string()
    } else {
        s.chars().take(max_chars).collect()
    }
}

fn fmt_token_status(expires_at: i64) -> String {
    if expires_at <= 0 {
        return "active".to_string();
    }
    let rem = expires_at - now_unix();
    if rem <= 0 {
        "auto-refresh on next turn".to_string()
    } else if rem < 60 {
        format!("{rem}s left")
    } else if rem < 3600 {
        format!("{}m left", rem / 60)
    } else {
        format!("{}h {}m left", rem / 3600, (rem % 3600) / 60)
    }
}

/// Whether Grok OAuth runs as a full autonomous Agent (default `true`) or direct Chat (`false`).
pub fn grok_agent_mode(u: &UserState) -> bool {
    u.extra
        .get(GROK_AGENT_MODE_KEY)
        .and_then(|v| v.as_bool())
        .unwrap_or(true)
}

/// Whether the user's sticky engine is currently set to Grok OAuth.
pub fn is_grok_active(u: &UserState) -> bool {
    u.extra.get("engine").and_then(|v| v.as_str()) == Some("grok")
        || u.model.as_deref().is_some_and(is_grok_model)
}

/// Session history key for Grok OAuth per user.
pub fn grok_session_key(uid: i64) -> String {
    format!("grok_{uid}")
}

/// Render or edit the Grok Subscription OAuth dashboard & model picker (`grok:p:{page}`).
pub async fn show_grok_panel(
    ctx: &Arc<BotCtx>,
    cq: Option<&CallbackQuery>,
    chat_id: i64,
    uid: i64,
    page: usize,
) {
    let u = ctx.store.get_user(uid);
    let creds = load_grok_creds(&ctx.cfg.state_dir);
    let ms = load_cached_grok_models(&ctx.cfg.state_dir);

    let pages = ms.len().div_ceil(MODELS_PER_PAGE).max(1);
    let page = page.min(pages - 1);

    let active_grok = is_grok_active(&u);
    let agent_on = grok_agent_mode(&u);
    let sess_msgs = session_message_count(&ctx.cfg.state_dir, &grok_session_key(uid));
    let auth_snap = active_grok_auth_snapshot();
    let tool_cnt = agent_tool_count(
        ctx.has_perm(uid, "root_access"),
        ctx.has_perm(uid, "sandbox_exec"),
    );

    let mut rows: Vec<Vec<InlineKeyboardButton>> = Vec::new();

    // Owner OAuth account controls
    if ctx.is_owner(uid) {
        if let Some(ref snap) = auth_snap {
            let copy_btn = InlineKeyboardButton {
                text: format!("📋 Copy: {}", snap.user_code),
                copy_text: Some(CopyTextButton {
                    text: snap.user_code.clone(),
                }),
                ..Default::default()
            };
            rows.push(vec![
                ctx.btn("", "🌐 Open x.ai Sign-In", None, Some("primary"), Some(&snap.open_url)),
                copy_btn,
            ]);
            rows.push(vec![
                ctx.btn("", "🔄 New Code", Some("grok:auth"), None, None),
                ctx.btn("", "✖ Cancel Login", Some("grok:auth_cancel"), Some("danger"), None),
            ]);
        } else if let Some(ref c) = creds {
            if c.quarantined_reason.is_some() {
                rows.push(vec![ctx.btn(
                    "",
                    "🔐 Reconnect Grok (OAuth)",
                    Some("grok:auth"),
                    Some("primary"),
                    None,
                )]);
            }
            let ep_short = match c.endpoint_mode {
                GrokEndpointMode::CliProxy => "🌐 CLI Proxy",
                GrokEndpointMode::OfficialApi => "🌐 api.x.ai",
            };
            rows.push(vec![
                ctx.btn("", "🔄 Refresh Token", Some("grok:refresh_tok"), None, None),
                ctx.btn("", ep_short, Some("grok:ep"), None, None),
            ]);
            rows.push(vec![
                ctx.btn("", "🔐 New Code", Some("grok:auth"), None, None),
                ctx.btn("", "🌐 Sticky Proxy", Some("px:list"), None, None),
            ]);
            rows.push(vec![
                ctx.btn("", "🔌 Disconnect", Some("grok:logout"), Some("danger"), None),
            ]);
        } else {
            rows.push(vec![
                ctx.btn(
                    "",
                    "🔐 Connect Grok (OAuth)",
                    Some("grok:auth"),
                    Some("primary"),
                    None,
                ),
                ctx.btn("", "🌐 Proxy", Some("px:list"), None, None),
            ]);
        }
    }

    // Mode & session memory row
    let mode_lbl = if agent_on {
        format!("🤖 Agent Mode: ON ({tool_cnt} tools)")
    } else {
        "💬 Mode: Chat Only".to_string()
    };
    let mode_style = if agent_on { Some("primary") } else { None };
    let clear_lbl = if sess_msgs > 0 {
        format!("🧹 Clear Session ({sess_msgs})")
    } else {
        "🧹 Clear Session".to_string()
    };
    rows.push(vec![
        ctx.btn("", &mode_lbl, Some("grok:agent_tog"), mode_style, None),
        ctx.btn("", &clear_lbl, Some("grok:clear"), None, None),
    ]);

    // Switch back to AGY Default
    let agy_lbl = format!(
        "{}Switch to AGY Default",
        if !active_grok { "✅ " } else { "" }
    );
    rows.push(vec![ctx.btn("", &agy_lbl, Some("grok:agy"), None, None)]);
    rows.push(vec![ctx.btn(
        "",
        &format!(
            "🤖 Grok Bot (Cloud & OAuth) {}",
            crate::handlers_grok_bot::grok_bot_status_badge(&ctx.cfg.state_dir)
        ),
        Some("gbot:open"),
        None,
        None,
    )]);

    // Paginated Grok models
    let start = page * MODELS_PER_PAGE;
    let end = (start + MODELS_PER_PAGE).min(ms.len());
    let chunk: Vec<(usize, &GrokModel)> = ms
        .iter()
        .enumerate()
        .skip(start)
        .take(end.saturating_sub(start))
        .collect();

    for pair in chunk.chunks(2) {
        let row = pair
            .iter()
            .map(|&(idx, m)| {
                let mark = if active_grok && u.model.as_deref() == Some(m.id.as_str()) {
                    "✅ "
                } else {
                    ""
                };
                let label = format!("{mark}{}", truncate_chars(&m.name, 28));
                let by_id = format!("grok:m:={}", m.id);
                let cb = if by_id.len() <= 64 {
                    by_id
                } else {
                    format!("grok:m:{idx}")
                };
                ctx.btn("", &label, Some(&cb), None, None)
            })
            .collect();
        rows.push(row);
    }

    let mut nav = Vec::new();
    if page > 0 {
        nav.push(ctx.btn(
            "",
            "‹ Prev",
            Some(&format!("grok:p:{}", page - 1)),
            None,
            None,
        ));
    }
    if page + 1 < pages {
        nav.push(ctx.btn(
            "",
            "Next ›",
            Some(&format!("grok:p:{}", page + 1)),
            None,
            None,
        ));
    }
    if !nav.is_empty() {
        rows.push(nav);
    }

    let lang = ctx.lang(uid);
    rows.push(vec![
        ctx.btn("refresh", t(lang, Tx::BtnRefresh), Some("grok:refresh_models"), None, None),
        ctx.btn("menu", t(lang, Tx::BtnMenu), Some("home"), None, None),
    ]);

    let oauth_line = match &creds {
        Some(c) if c.quarantined_reason.is_some() => {
            let reason = c.quarantined_reason.as_deref().unwrap_or("refresh rejected");
            format!(
                "🔴 <b>OAuth:</b> Quarantined (<code>{}</code>) — reconnect required",
                esc(&truncate_chars(reason, 90))
            )
        }
        Some(c) => {
            let who = c
                .masked_email()
                .unwrap_or_else(|| "x.ai subscription".to_string());
            format!(
                "🟢 <b>OAuth:</b> Connected · <code>{}</code> (<i>{}</i>)\n🌐 <b>Endpoint:</b> <code>{}</code>",
                esc(&who),
                esc(&fmt_token_status(c.expires_at)),
                esc(c.endpoint_mode.label())
            )
        }
        None => "⚪ <b>OAuth:</b> Not connected (no API key needed — sign in with your SuperGrok / X Premium+ account)".to_string(),
    };

    let cur_model = u.model.as_deref().unwrap_or("(AGY default)");
    let engine_line = if active_grok {
        format!(
            "⚡ <b>Active Engine:</b> Grok Subscription OAuth (<code>{}</code>)",
            esc(cur_model)
        )
    } else {
        format!(
            "🤖 <b>Active Engine:</b> {} (<code>{}</code>)",
            if u.extra.get("engine").and_then(|v| v.as_str()) == Some("uncensored") {
                "Venice Uncensored"
            } else {
                "Antigravity CLI"
            },
            esc(cur_model)
        )
    };
    let mode_desc = if agent_on {
        "🤖 <b>Autonomous Agent</b> · Bash, Files, <code>search-v3</code>, AI-Memory, SkillPort &amp; MCPs"
    } else {
        "💬 <b>Direct Chat</b> · No server tools executed"
    };

    let proxy_line = if ctx.is_owner(uid) {
        match ctx.proxies.resolve_grok() {
            ResolvedProxy::Direct => "\n🛡 <b>Proxy:</b> <code>direct</code>".to_string(),
            ResolvedProxy::DirectFallback { safe_label, .. } => {
                format!("\n⚠️ <b>Proxy:</b> <code>{}</code> (fallback→direct)", esc(&safe_label))
            }
            ResolvedProxy::Use { id, safe_label, .. } => {
                let lbl = ctx
                    .proxies
                    .get(&id)
                    .map(|e| format!("{} (score {})", e.display_name(), e.health.quality_score))
                    .unwrap_or(safe_label);
                format!("\n🛡 <b>Proxy:</b> <code>{}</code>", esc(&lbl))
            }
            ResolvedProxy::Blocked { safe_label, .. } => {
                format!("\n🔴 <b>Proxy:</b> <code>{}</code> (fail-closed blocked)", esc(&safe_label))
            }
        }
    } else {
        String::new()
    };

    let auth_line = if let Some(ref snap) = auth_snap {
        let extra = snap
            .last_status
            .as_deref()
            .filter(|s| !s.is_empty())
            .map(|s| format!(" · <i>{}</i>", esc(s)))
            .unwrap_or_default();
        format!(
            "\n⏳ <b>Login in progress:</b> code <code>{}</code> (<i>{} left · checked {}x</i>{extra})\n<i>Visit <code>{}</code> or tap Open x.ai Sign-In above.</i>",
            esc(&snap.user_code),
            fmt_mm_ss(snap.remaining_secs),
            snap.polls,
            esc(&snap.verification_uri),
        )
    } else {
        String::new()
    };

    let text = format!(
        "⚡ <b>{}</b>\n\
        <blockquote>Connects directly to x.ai via RFC 8628 OAuth 2.0 Device Code flow with automatic rotating refresh tokens.\n\
        Use <code>/gagent &lt;task&gt;</code> anytime to run a one-shot autonomous Grok Agent task.</blockquote>\n\
        {oauth_line}{auth_line}{proxy_line}\n\
        {engine_line}\n\
        {mode_desc}\n\
        🧠 <b>Session memory:</b> {sess_msgs} message(s)\n\
        <i>Page {} of {} · {} models available</i>",
        t(lang, Tx::PanelGrokTitle),
        page + 1,
        pages,
        ms.len()
    );

    let mk = BotCtx::kb(rows);
    ctx.edit_or_send(cq, chat_id, &text, Some(mk)).await;
}

/// Start RFC 8628 xAI OAuth Device Authorization Flow (owner-only).
pub async fn start_grok_device_auth(
    ctx: &Arc<BotCtx>,
    cq: Option<&CallbackQuery>,
    uid: i64,
    chat_id: i64,
) {
    if !ctx.is_owner(uid) {
        if let Some(cq) = cq {
            ctx.ack(&cq.id, Some("Owner only"), true).await;
        } else {
            let _ = ctx
                .render
                .send_html_simple(chat_id, "🔒 Only the bot owner can connect or manage Grok OAuth.", None)
                .await;
        }
        return;
    }

    // Cancel any previous in-flight auth session first.
    {
        let mut slot = active_grok_auth().lock().unwrap_or_else(|e| e.into_inner());
        if let Some(prev) = slot.take() {
            prev.session.cancel();
        }
    }

    if let Some(cq) = cq {
        ctx.ack(&cq.id, Some("Requesting x.ai OAuth device code…"), false)
            .await;
    }

    let grok_proxy_url = match ctx.proxies.resolve_grok() {
        ResolvedProxy::Use { url, .. } => Some(url),
        ResolvedProxy::Direct | ResolvedProxy::DirectFallback { .. } => None,
        ResolvedProxy::Blocked { reason, .. } => {
            let txt = format!(
                "{} <b>Grok OAuth blocked (fail-closed proxy)</b>\n<blockquote>{}</blockquote>\n<i>Check /proxies first.</i>",
                ctx.e("err"),
                esc(&reason)
            );
            let mk = BotCtx::kb(vec![vec![
                ctx.btn("", "🌐 Open Proxies", Some("px:list"), Some("primary"), None),
                ctx.btn("", "« Grok", Some("grok:open"), None, None),
            ]]);
            ctx.edit_or_send(cq, chat_id, &txt, Some(mk)).await;
            return;
        }
    };

    let dev = match start_device_auth_via(grok_proxy_url.as_deref()).await {
        Ok(d) => d,
        Err(err) => {
            warn!(error = %err, "xAI Grok OAuth device auth failed to start");
            let txt = format!(
                "{} <b>Failed to start x.ai OAuth Device Login</b>\n\
                <blockquote expandable>{}</blockquote>\n\
                <i>Check server outbound HTTPS access to <code>auth.x.ai</code> and retry.</i>",
                ctx.e("err"),
                esc(&err.to_string())
            );
            let mk = BotCtx::kb(vec![vec![
                ctx.btn("", "🔄 Retry OAuth", Some("grok:auth"), Some("primary"), None),
                ctx.btn("", "« Grok", Some("grok:open"), None, None),
            ]]);
            ctx.edit_or_send(cq, chat_id, &txt, Some(mk)).await;
            return;
        }
    };

    let open_url = dev
        .verification_uri_complete
        .clone()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| dev.verification_uri.clone());

    let expires_secs = dev.expires_in.clamp(60, 1200);
    let deadline = Instant::now() + Duration::from_secs(expires_secs);
    let polls_ctr = Arc::new(AtomicU32::new(0));
    let last_status_box: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));

    let (sess, mut cancel_rx) =
        GrokAuthSession::new(dev.user_code.clone(), open_url.clone());
    {
        let mut slot = active_grok_auth().lock().unwrap_or_else(|e| e.into_inner());
        *slot = Some(ActiveGrokAuth {
            session: Arc::clone(&sess),
            cancel_rx: cancel_rx.clone(),
            verification_uri: dev.verification_uri.clone(),
            expires_at: deadline,
            polls: Arc::clone(&polls_ctr),
            last_status: Arc::clone(&last_status_box),
        });
    }

    let (txt, mk) = render_device_auth_card(
        ctx,
        &dev.verification_uri,
        &dev.user_code,
        &open_url,
        expires_secs,
        0,
        None,
    );

    let cq_msg_id = cq.and_then(|c| c.message.as_ref()).map(|m| m.message_id);
    let prompt_msg_id = if let Some(mid) = cq_msg_id {
        match ctx.render.edit_or_send_html(chat_id, Some(mid), &txt, Some(mk)).await {
            Ok(Some(m)) => Some(m.message_id),
            _ => Some(mid),
        }
    } else {
        match ctx.render.send_html_simple(chat_id, &txt, Some(mk)).await {
            Ok(Some(m)) => Some(m.message_id),
            _ => None,
        }
    };

    let ctx_bg = Arc::clone(ctx);
    let sess_bg = Arc::clone(&sess);
    let polls_bg = Arc::clone(&polls_ctr);
    let status_bg = Arc::clone(&last_status_box);
    let verification_uri_bg = dev.verification_uri.clone();
    let user_code_bg = dev.user_code.clone();
    let open_url_bg = open_url.clone();
    let device_code = dev.device_code.clone();
    let mut interval = dev.interval.clamp(3, 30);

    tokio::spawn(async move {
        let mut transient_errors = 0u32;
        let mut last_ui_edit = Instant::now();
        let final_html: Option<String> = loop {
            if Instant::now() >= deadline {
                break Some(
                    "⏱ <b>Grok OAuth login expired</b>. Tap <b>New Code</b> below or run <code>/grok</code>."
                        .to_string(),
                );
            }
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(interval)) => {}
                res = cancel_rx.changed() => {
                    if res.is_err() || *cancel_rx.borrow() {
                        break Some("✖ <i>Grok OAuth login cancelled.</i>".to_string());
                    }
                }
            }
            if *cancel_rx.borrow() {
                break Some("✖ <i>Grok OAuth login cancelled.</i>".to_string());
            }

            let poll_px = match ctx_bg.proxies.resolve_grok() {
                ResolvedProxy::Use { url, .. } => Some(url),
                ResolvedProxy::Direct | ResolvedProxy::DirectFallback { .. } => None,
                ResolvedProxy::Blocked { reason, .. } => {
                    break Some(format!(
                        "{} <b>Grok OAuth polling stopped (fail-closed proxy):</b> <code>{}</code>",
                        ctx_bg.e("err"),
                        esc(&reason)
                    ));
                }
            };
            let poll_count = polls_bg.fetch_add(1, Ordering::Relaxed) + 1;
            let mut status_changed = false;
            match poll_device_token_once_via(&device_code, interval, poll_px.as_deref()).await {
                Ok(DevicePollOutcome::Pending) => {
                    transient_errors = 0;
                    if let Ok(mut g) = status_bg.lock() {
                        if g.is_some() {
                            *g = None;
                            status_changed = true;
                        }
                    }
                }
                Ok(DevicePollOutcome::SlowDown(next_iv)) => {
                    transient_errors = 0;
                    interval = next_iv.clamp(5, 60);
                    if let Ok(mut g) = status_bg.lock() {
                        *g = Some(format!("slowing poll to {interval}s"));
                        status_changed = true;
                    }
                }
                Ok(DevicePollOutcome::Authorized(creds)) => {
                    if let Err(err) = save_grok_creds(&ctx_bg.cfg.state_dir, &creds) {
                        warn!(error = %err, "failed saving Grok OAuth creds");
                        break Some(format!(
                            "{} <b>Grok OAuth authorized, but failed saving credentials:</b> <code>{}</code>",
                            ctx_bg.e("err"),
                            esc(&err.to_string())
                        ));
                    }
                    let models =
                        refresh_grok_models_via(&ctx_bg.cfg.state_dir, poll_px.as_deref()).await;
                    let who = creds
                        .masked_email()
                        .unwrap_or_else(|| "x.ai account".to_string());
                    info!(email = %who, models = models.len(), "Grok Subscription OAuth connected");
                    break Some(format!(
                        "{} <b>Grok Subscription OAuth connected!</b>\n\
                        <blockquote><b>Account</b>  <code>{}</code>\n\
                        <b>Endpoint</b>  <code>{}</code>\n\
                        <b>Models</b>  {} ready</blockquote>\n\
                        <i>Tap a model in /grok or run <code>/gagent &lt;task&gt;</code>.</i>",
                        ctx_bg.e("ok"),
                        esc(&who),
                        esc(creds.endpoint_mode.label()),
                        models.len()
                    ));
                }
                Ok(DevicePollOutcome::Expired) => {
                    break Some(
                        "⏱ <b>Grok OAuth device code expired</b>. Tap <b>New Code</b> below or run <code>/grok</code>."
                            .to_string(),
                    );
                }
                Ok(DevicePollOutcome::Denied(why)) => {
                    break Some(format!(
                        "🚫 <b>Grok OAuth denied:</b> <code>{}</code>",
                        esc(&why)
                    ));
                }
                Err(err) => {
                    transient_errors += 1;
                    warn!(attempt = transient_errors, error = %err, "Grok OAuth poll error");
                    if transient_errors >= 4 {
                        break Some(format!(
                            "{} <b>Grok OAuth polling failed:</b> <code>{}</code>",
                            ctx_bg.e("err"),
                            esc(&err.to_string())
                        ));
                    }
                    if let Ok(mut g) = status_bg.lock() {
                        *g = Some(format!("retry #{transient_errors}/4"));
                        status_changed = true;
                    }
                }
            }

            if let Some(mid) = prompt_msg_id {
                if status_changed || last_ui_edit.elapsed() >= Duration::from_secs(15) {
                    let rem = deadline.saturating_duration_since(Instant::now()).as_secs();
                    let note = status_bg.lock().ok().and_then(|g| g.clone());
                    let (live_txt, live_mk) = render_device_auth_card(
                        &ctx_bg,
                        &verification_uri_bg,
                        &user_code_bg,
                        &open_url_bg,
                        rem,
                        poll_count,
                        note.as_deref(),
                    );
                    let _ = ctx_bg
                        .render
                        .edit_html(chat_id, mid, &live_txt, Some(live_mk))
                        .await;
                    last_ui_edit = Instant::now();
                }
            }
        };

        // Clear active session slot if it still holds our session.
        {
            let mut slot = active_grok_auth().lock().unwrap_or_else(|e| e.into_inner());
            if slot.as_ref().is_some_and(|cur| Arc::ptr_eq(&cur.session, &sess_bg)) {
                *slot = None;
            }
        }

        if let Some(html) = final_html {
            let mk = BotCtx::kb(vec![
                vec![
                    ctx_bg.btn("grok", "Open Grok Panel", Some("grok:open"), Some("primary"), None),
                    ctx_bg.btn("", "🔄 New Code", Some("grok:auth"), None, None),
                ],
                vec![ctx_bg.btn("menu", "Menu", Some("home"), None, None)],
            ]);
            let _ = ctx_bg
                .render
                .edit_or_send_html(chat_id, prompt_msg_id, &html, Some(mk))
                .await;
        }
    });
}

/// Apply user's Grok model choice.
pub async fn apply_grok_model_selection(
    ctx: &Arc<BotCtx>,
    cq: Option<&CallbackQuery>,
    uid: i64,
    chat_id: i64,
    choice: &str,
) {
    let ms = load_cached_grok_models(&ctx.cfg.state_dir);

    let target = if let Some(id) = choice.strip_prefix('=') {
        ms.iter().find(|m| m.id == id).cloned()
    } else if let Ok(idx) = choice.parse::<usize>() {
        ms.get(idx).cloned()
    } else {
        ms.iter()
            .find(|m| m.id.eq_ignore_ascii_case(choice) || m.name.eq_ignore_ascii_case(choice))
            .cloned()
    };

    let Some(m) = target else {
        if let Some(cq) = cq {
            ctx.ack(&cq.id, Some("Grok model not found"), false).await;
        }
        show_grok_panel(ctx, cq, chat_id, uid, 0).await;
        return;
    };

    let model_id = m.id.clone();
    let model_name = m.name.clone();

    let _ = ctx.store.update_user(uid, |st| {
        st.model = Some(model_id);
        st.extra.insert("engine".to_string(), json!("grok"));
        st.extra.remove(MODEL_INVALID_KEY);
    });

    info!(uid, model = %model_name, "user selected Grok OAuth model");

    if let Some(cq) = cq {
        ctx.ack(
            &cq.id,
            Some(&format!("Grok: {}", truncate_chars(&model_name, 34))),
            false,
        )
        .await;
    }

    show_grok_panel(ctx, cq, chat_id, uid, 0).await;
}

/// Handle callback data starting with `grok:`.
pub async fn handle_grok_cb(
    ctx: &Arc<BotCtx>,
    cq: &CallbackQuery,
    uid: i64,
    chat_id: i64,
    data: &str,
) -> bool {
    let Some(rest) = data.strip_prefix("grok:") else {
        return false;
    };
    if !ctx.has_perm(uid, "grok") {
        let lang = ctx.lang(uid);
        let msg = format!("{} {}", t(lang, Tx::ModuleRequiredHdr), perm_label(lang, "grok"));
        ctx.ack(&cq.id, Some(&msg), true).await;
        return true;
    }

    match rest {
        "open" => {
            ctx.ack(&cq.id, None, false).await;
            show_grok_panel(ctx, Some(cq), chat_id, uid, 0).await;
            true
        }
        "auth" => {
            start_grok_device_auth(ctx, Some(cq), uid, chat_id).await;
            true
        }
        "auth_cancel" => {
            if !ctx.is_owner(uid) {
                ctx.ack(&cq.id, Some("Owner only"), true).await;
                return true;
            }
            let cancelled = {
                let mut slot = active_grok_auth().lock().unwrap_or_else(|e| e.into_inner());
                slot.take().map(|s| {
                    s.session.cancel();
                })
                .is_some()
            };
            ctx.ack(
                &cq.id,
                Some(if cancelled {
                    "Grok login cancelled"
                } else {
                    "No active login"
                }),
                false,
            )
            .await;
            show_grok_panel(ctx, Some(cq), chat_id, uid, 0).await;
            true
        }
        "refresh_tok" => {
            if !ctx.is_owner(uid) {
                ctx.ack(&cq.id, Some("Owner only"), true).await;
                return true;
            }
            ctx.ack(&cq.id, Some("Refreshing x.ai OAuth token…"), false)
                .await;
            let px_res = match ctx.proxies.resolve_grok() {
                ResolvedProxy::Use { url, .. } => Ok(Some(url)),
                ResolvedProxy::Direct | ResolvedProxy::DirectFallback { .. } => Ok(None),
                ResolvedProxy::Blocked { reason, .. } => Err(reason),
            };
            match px_res {
                Err(reason) => {
                    let _ = ctx
                        .render
                        .send_html_simple(
                            chat_id,
                            &format!(
                                "{} <b>Token refresh blocked (fail-closed proxy):</b> <code>{}</code>",
                                ctx.e("err"),
                                esc(&reason)
                            ),
                            None,
                        )
                        .await;
                }
                Ok(px) => match ensure_valid_grok_creds_via(&ctx.cfg.state_dir, true, px.as_deref()).await {
                    Ok(_) => {}
                    Err(err) => {
                        let _ = ctx
                            .render
                            .send_html_simple(
                                chat_id,
                                &format!(
                                    "{} <b>Token refresh failed:</b> <code>{}</code>",
                                    ctx.e("err"),
                                    esc(&err.to_string())
                                ),
                                None,
                            )
                            .await;
                    }
                },
            }
            show_grok_panel(ctx, Some(cq), chat_id, uid, 0).await;
            true
        }
        "ep" => {
            if !ctx.is_owner(uid) {
                ctx.ack(&cq.id, Some("Owner only"), true).await;
                return true;
            }
            let next_mode = match load_grok_creds(&ctx.cfg.state_dir).map(|c| c.endpoint_mode) {
                Some(GrokEndpointMode::CliProxy) => GrokEndpointMode::OfficialApi,
                _ => GrokEndpointMode::CliProxy,
            };
            match set_grok_endpoint_mode(&ctx.cfg.state_dir, next_mode) {
                Ok(_) => {
                    ctx.ack(&cq.id, Some(next_mode.label()), false).await;
                }
                Err(err) => {
                    ctx.ack(&cq.id, Some(&truncate_chars(&err.to_string(), 160)), true)
                        .await;
                }
            }
            show_grok_panel(ctx, Some(cq), chat_id, uid, 0).await;
            true
        }
        "logout" => {
            if !ctx.is_owner(uid) {
                ctx.ack(&cq.id, Some("Owner only"), true).await;
                return true;
            }
            delete_grok_creds(&ctx.cfg.state_dir);
            ctx.ack(&cq.id, Some("Grok OAuth disconnected"), false)
                .await;
            show_grok_panel(ctx, Some(cq), chat_id, uid, 0).await;
            true
        }
        "agent_tog" => {
            let now_on = !grok_agent_mode(&ctx.store.get_user(uid));
            let _ = ctx.store.update_user(uid, |st| {
                st.extra.insert(GROK_AGENT_MODE_KEY.to_string(), json!(now_on));
            });
            ctx.ack(
                &cq.id,
                Some(if now_on {
                    "Grok Autonomous Agent Mode: ON"
                } else {
                    "Grok Chat-Only Mode: ON"
                }),
                false,
            )
            .await;
            show_grok_panel(ctx, Some(cq), chat_id, uid, 0).await;
            true
        }
        "clear" => {
            clear_session_history(&ctx.cfg.state_dir, &grok_session_key(uid));
            ctx.ack(&cq.id, Some("Grok session memory cleared"), false)
                .await;
            show_grok_panel(ctx, Some(cq), chat_id, uid, 0).await;
            true
        }
        "agy" => {
            let _ = ctx.store.update_user(uid, |st| {
                st.extra.remove("engine");
                st.extra.remove(MODEL_INVALID_KEY);
                st.model = None;
            });
            ctx.jobs.clear_model_choices(uid);
            ctx.ack(&cq.id, Some("Switched to AGY default model"), false)
                .await;
            show_grok_panel(ctx, Some(cq), chat_id, uid, 0).await;
            true
        }
        "refresh_models" => {
            match ctx.proxies.resolve_grok() {
                ResolvedProxy::Blocked { reason, .. } => {
                    ctx.ack(
                        &cq.id,
                        Some(&truncate_chars(&format!("Proxy blocked: {reason}"), 160)),
                        true,
                    )
                    .await;
                }
                ResolvedProxy::Use { url, .. } => {
                    let ms = refresh_grok_models_via(&ctx.cfg.state_dir, Some(&url)).await;
                    ctx.ack(&cq.id, Some(&format!("{} Grok model(s) loaded", ms.len())), false)
                        .await;
                }
                ResolvedProxy::Direct | ResolvedProxy::DirectFallback { .. } => {
                    let ms = refresh_grok_models_via(&ctx.cfg.state_dir, None).await;
                    ctx.ack(&cq.id, Some(&format!("{} Grok model(s) loaded", ms.len())), false)
                        .await;
                }
            }
            show_grok_panel(ctx, Some(cq), chat_id, uid, 0).await;
            true
        }
        other => {
            if let Some(p_str) = other.strip_prefix("p:") {
                let page = p_str.parse::<usize>().unwrap_or(0);
                ctx.ack(&cq.id, None, false).await;
                show_grok_panel(ctx, Some(cq), chat_id, uid, page).await;
                return true;
            }
            if let Some(m_str) = other.strip_prefix("m:") {
                apply_grok_model_selection(ctx, Some(cq), uid, chat_id, m_str).await;
                return true;
            }
            false
        }
    }
}

/// Slash command `/grok [login|logout|agent|chat|clear|cli|api|<model>]`.
pub async fn cmd_grok(ctx: &Arc<BotCtx>, msg: &Message, arg: &str) {
    let Some(uid) = msg.from_user.as_ref().map(|u| u.id) else {
        return;
    };
    let chat_id = msg.chat.id;
    if !ctx.has_perm(uid, "grok") {
        let _ = ctx
            .render
            .send_html_simple(chat_id, &missing_perm_html(ctx, uid, "grok"), None)
            .await;
        return;
    }
    let a = arg.trim();

    if a.is_empty() {
        show_grok_panel(ctx, None, chat_id, uid, 0).await;
    } else if a.eq_ignore_ascii_case("bot") {
        crate::handlers_grok_bot::cmd_gbot(ctx, msg, "").await;
    } else if let Some(rest) = a
        .strip_prefix("bot ")
        .or_else(|| a.strip_prefix("BOT "))
        .or_else(|| a.strip_prefix("Bot "))
    {
        crate::handlers_grok_bot::cmd_gbot(ctx, msg, rest).await;
    } else if matches!(a.to_ascii_lowercase().as_str(), "login" | "auth" | "connect") {
        start_grok_device_auth(ctx, None, uid, chat_id).await;
    } else if matches!(a.to_ascii_lowercase().as_str(), "logout" | "disconnect") {
        if !ctx.is_owner(uid) {
            let _ = ctx
                .render
                .send_html_simple(chat_id, &owner_only_html(ctx, uid), None)
                .await;
            return;
        }
        let deleted = delete_grok_creds(&ctx.cfg.state_dir);
        let txt = if deleted {
            "🔌 Grok OAuth disconnected."
        } else {
            "ℹ️ Grok OAuth was not connected."
        };
        let _ = ctx.render.send_html_simple(chat_id, txt, None).await;
    } else if a.eq_ignore_ascii_case("agent") {
        let _ = ctx.store.update_user(uid, |st| {
            st.extra.insert(GROK_AGENT_MODE_KEY.to_string(), json!(true));
        });
        let tool_cnt = agent_tool_count(
            ctx.has_perm(uid, "root_access"),
            ctx.has_perm(uid, "sandbox_exec"),
        );
        let _ = ctx
            .render
            .send_html_simple(
                chat_id,
                &format!(
                    "⚡ Grok OAuth → <b>Autonomous Agent Mode ON</b> ({tool_cnt} server/MCP tools enabled)."
                ),
                None,
            )
            .await;
    } else if a.eq_ignore_ascii_case("chat") {
        let _ = ctx.store.update_user(uid, |st| {
            st.extra.insert(GROK_AGENT_MODE_KEY.to_string(), json!(false));
        });
        let _ = ctx
            .render
            .send_html_simple(
                chat_id,
                "⚡ Grok OAuth → <b>Direct Chat Mode</b> (server tools disabled).",
                None,
            )
            .await;
    } else if a.eq_ignore_ascii_case("clear") || a.eq_ignore_ascii_case("reset") {
        clear_session_history(&ctx.cfg.state_dir, &grok_session_key(uid));
        let _ = ctx
            .render
            .send_html_simple(chat_id, "🧹 Grok session memory cleared.", None)
            .await;
    } else if a.eq_ignore_ascii_case("cli") || a.eq_ignore_ascii_case("api") {
        if !ctx.is_owner(uid) {
            let _ = ctx
                .render
                .send_html_simple(chat_id, &owner_only_html(ctx, uid), None)
                .await;
            return;
        }
        let mode = if a.eq_ignore_ascii_case("api") {
            GrokEndpointMode::OfficialApi
        } else {
            GrokEndpointMode::CliProxy
        };
        match set_grok_endpoint_mode(&ctx.cfg.state_dir, mode) {
            Ok(_) => {
                let _ = ctx
                    .render
                    .send_html_simple(
                        chat_id,
                        &format!("🌐 Grok OAuth endpoint → <code>{}</code>", esc(mode.label())),
                        None,
                    )
                    .await;
            }
            Err(err) => {
                let _ = ctx
                    .render
                    .send_html_simple(chat_id, &format!("⚠️ {}", esc(&err.to_string())), None)
                    .await;
            }
        }
    } else {
        apply_grok_model_selection(ctx, None, uid, chat_id, a).await;
    }
}

/// Slash command `/gagent <task>` — execute an immediate autonomous Grok OAuth Agent task
/// without changing the user's sticky default engine.
pub async fn cmd_gagent(ctx: &Arc<BotCtx>, msg: &Message, arg: &str) {
    let Some(ref user) = msg.from_user else {
        return;
    };
    let uid = user.id;
    let chat_id = msg.chat.id;
    if !ctx.has_perm(uid, "grok") {
        let _ = ctx
            .render
            .send_html_simple(chat_id, &missing_perm_html(ctx, uid, "grok"), None)
            .await;
        return;
    }
    let task = arg.trim();
    if task.is_empty() {
        let txt = "⚡ <b>Grok Subscription Autonomous Agent</b>\n\
            Usage: <code>/gagent &lt;your task&gt;</code>\n\
            <i>Runs an isolated multi-step autonomous Grok agent (Bash, Files, search-v3, AI-Memory, SkillPort &amp; MCPs) via your OAuth subscription.</i>";
        let mk = BotCtx::kb(vec![vec![ctx.btn(
            "grok",
            "Grok OAuth Panel",
            Some("grok:open"),
            Some("primary"),
            None,
        )]]);
        let _ = ctx.render.send_html_simple(chat_id, txt, Some(mk)).await;
        return;
    }

    let mut req = JobRequest::new(uid, chat_id, user.display_label(), task, Vec::new());
    req.overrides = JobOverride {
        isolated: true,
        force_engine: Some("grok".to_string()),
        force_agent_mode: Some(true),
        ..Default::default()
    };
    if let Err(err) = ctx.jobs.enqueue(req).await {
        let _ = ctx
            .render
            .send_html_simple(
                chat_id,
                &format!(
                    "{} <b>Failed to start Grok Agent:</b> <code>{}</code>",
                    ctx.e("err"),
                    esc(&err.to_string())
                ),
                None,
            )
            .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grok_mode_defaults_to_agent_and_engine_detection_works() {
        let mut u = UserState::default();
        assert!(grok_agent_mode(&u));
        assert!(!is_grok_active(&u));

        u.extra.insert(GROK_AGENT_MODE_KEY.to_string(), json!(false));
        assert!(!grok_agent_mode(&u));

        u.extra.insert("engine".to_string(), json!("grok"));
        assert!(is_grok_active(&u));

        u.extra.remove("engine");
        u.model = Some("grok-4.7".to_string());
        assert!(is_grok_active(&u));
    }
}
