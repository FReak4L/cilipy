//! Handlers for Grok Bot (`x.ai/bot` / Cursor Sand) PKCE OAuth 2.0 login,
//! token refresh & regeneration, cloud bot sync/picker, status/usage, and chat execution.

use std::path::Path;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use agy_core::proxies::ResolvedProxy;
use agy_core::store::UserState;
use agy_core::tg::{
    CallbackQuery, CopyTextButton, InlineKeyboardButton, InlineKeyboardMarkup, Message,
};
use agy_ext::grok_bot::{
    delete_grok_bot_creds, ensure_valid_grok_bot_creds_via, fetch_grok_bot_usage_via,
    interrupt_grok_bot_run_via, list_grok_bot_agents_via, list_grok_bot_statuses_via,
    list_transcript_entries_via, load_cached_grok_bot_agents, load_grok_bot_creds,
    poll_pkce_login_once_via, resolve_main_session_via, save_grok_bot_creds, start_pkce_login,
    GrokBotAgent, GrokBotAuthSession, GrokBotEntryView, GrokBotPollOutcome,
};
use agy_render::esc;
use serde_json::json;
use tracing::{info, warn};

use crate::ctx::BotCtx;
use crate::i18n::{missing_perm_html, owner_only_html, perm_label, t, Tx};
use crate::jobs::model_pick::MODEL_INVALID_KEY;
use crate::jobs::{JobOverride, JobRequest};

const BOTS_PER_PAGE: usize = 6;
pub const GROK_BOT_AGENT_ID_KEY: &str = "grok_bot_agent_id";
pub const GROK_BOT_AGENT_NAME_KEY: &str = "grok_bot_agent_name";

struct ActiveGrokBotAuth {
    session: Arc<GrokBotAuthSession>,
    cancel_rx: tokio::sync::watch::Receiver<bool>,
    expires_at: Instant,
    polls: Arc<AtomicU32>,
    last_status: Arc<Mutex<Option<String>>>,
}

#[derive(Clone)]
struct GrokBotAuthSnapshot {
    short_code: String,
    login_url: String,
    remaining_secs: u64,
    polls: u32,
    last_status: Option<String>,
}

fn active_grok_bot_auth() -> &'static Mutex<Option<ActiveGrokBotAuth>> {
    static ACTIVE: OnceLock<Mutex<Option<ActiveGrokBotAuth>>> = OnceLock::new();
    ACTIVE.get_or_init(|| Mutex::new(None))
}

fn active_grok_bot_auth_snapshot() -> Option<GrokBotAuthSnapshot> {
    let mut slot = active_grok_bot_auth()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let cur = slot.as_ref()?;
    let now = Instant::now();
    if *cur.cancel_rx.borrow() || now >= cur.expires_at {
        *slot = None;
        return None;
    }
    let remaining_secs = cur.expires_at.saturating_duration_since(now).as_secs();
    let polls = cur.polls.load(Ordering::Relaxed);
    let last_status = cur.last_status.lock().ok().and_then(|g| g.clone());
    Some(GrokBotAuthSnapshot {
        short_code: cur.session.short_code.clone(),
        login_url: cur.session.login_url.clone(),
        remaining_secs,
        polls,
        last_status,
    })
}

fn fmt_mm_ss(secs: u64) -> String {
    format!("{:02}:{:02}", secs / 60, secs % 60)
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn truncate_chars(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
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
    } else if rem < 3600 {
        format!("{}m left", (rem / 60).max(1))
    } else if rem < 86400 {
        format!("{}h {}m left", rem / 3600, (rem % 3600) / 60)
    } else {
        format!("{}d left", rem / 86400)
    }
}

/// Whether user's sticky engine is currently Grok Bot.
pub fn is_grok_bot_active(u: &UserState) -> bool {
    u.extra.get("engine").and_then(|v| v.as_str()) == Some("grok_bot")
}

/// Selected Grok Bot `(agent_id, agent_name)` stored in user state.
pub fn selected_grok_bot(u: &UserState) -> Option<(String, String)> {
    let id = u
        .extra
        .get(GROK_BOT_AGENT_ID_KEY)
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())?;
    let name = u
        .extra
        .get(GROK_BOT_AGENT_NAME_KEY)
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(id);
    Some((id.to_string(), name.to_string()))
}

/// Short connection badge shown on the Grok Bot entry button in `/grok`.
pub fn grok_bot_status_badge(state_dir: &Path) -> &'static str {
    match load_grok_bot_creds(state_dir) {
        Some(c) if c.quarantined_reason.is_some() => "🔴",
        Some(_) => "🟢",
        None => "⚪",
    }
}

fn resolve_grok_proxy_opt(ctx: &BotCtx) -> std::result::Result<Option<String>, String> {
    match ctx.proxies.resolve_grok() {
        ResolvedProxy::Use { url, .. } => Ok(Some(url)),
        ResolvedProxy::Direct | ResolvedProxy::DirectFallback { .. } => Ok(None),
        ResolvedProxy::Blocked { reason, .. } => Err(reason),
    }
}

fn render_pkce_auth_card(
    ctx: &BotCtx,
    short_code: &str,
    login_url: &str,
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
            "⏱ <b>Remaining:</b> <code>{}</code> · checked {}x · <i>waiting for browser sign-in…</i>",
            fmt_mm_ss(rem_secs),
            polls
        ),
    };
    let txt = format!(
        "🔐 <b>Sign in to Grok Bot (PKCE OAuth)</b>\n\
        <blockquote>1. Tap <b>Open Grok Bot Sign-In</b> below (or copy the link).\n\
        2. Complete sign-in with your Grok Bot / SuperGrok / X account.\n\
        3. Return here — login completes automatically.\n\
        🆔 <b>Session:</b> <code>{}</code>\n\
        {status_line}</blockquote>\n\
        <i>If this link expires, tap <b>New Login Link</b> to generate a fresh one anytime.</i>",
        esc(short_code),
    );
    let copy_btn = InlineKeyboardButton {
        text: "📋 Copy Login Link".to_string(),
        copy_text: Some(CopyTextButton {
            text: login_url.to_string(),
        }),
        ..Default::default()
    };
    let mk = BotCtx::kb(vec![
        vec![ctx.btn(
            "",
            "🌐 Open Grok Bot Sign-In",
            None,
            Some("primary"),
            Some(login_url),
        )],
        vec![copy_btn],
        vec![
            ctx.btn("", "🔄 New Login Link", Some("gbot:auth"), None, None),
            ctx.btn("", "✖ Cancel", Some("gbot:auth_cancel"), Some("danger"), None),
        ],
        vec![
            ctx.btn("", "« Grok Bot", Some("gbot:open"), None, None),
            ctx.btn("", "« Grok Panel", Some("grok:open"), None, None),
        ],
    ]);
    (txt, mk)
}

/// Render the Grok Bot OAuth & Cloud Bots dashboard (`gbot:open` / `gbot:p:{page}`).
pub async fn show_grok_bot_panel(
    ctx: &Arc<BotCtx>,
    cq: Option<&CallbackQuery>,
    chat_id: i64,
    uid: i64,
    page: usize,
) {
    let u = ctx.store.get_user(uid);
    let creds = load_grok_bot_creds(&ctx.cfg.state_dir);
    let agents = load_cached_grok_bot_agents(&ctx.cfg.state_dir);

    let pages = agents.len().div_ceil(BOTS_PER_PAGE).max(1);
    let page = page.min(pages - 1);

    let active_gbot = is_grok_bot_active(&u);
    let selected = selected_grok_bot(&u);
    let auth_snap = active_grok_bot_auth_snapshot();

    let mut rows: Vec<Vec<InlineKeyboardButton>> = Vec::new();

    if ctx.is_owner(uid) {
        if let Some(ref snap) = auth_snap {
            let copy_btn = InlineKeyboardButton {
                text: "📋 Copy Link".to_string(),
                copy_text: Some(CopyTextButton {
                    text: snap.login_url.clone(),
                }),
                ..Default::default()
            };
            rows.push(vec![
                ctx.btn(
                    "",
                    "🌐 Open Grok Bot Sign-In",
                    None,
                    Some("primary"),
                    Some(&snap.login_url),
                ),
                copy_btn,
            ]);
            rows.push(vec![
                ctx.btn("", "🔄 New Login Link", Some("gbot:auth"), None, None),
                ctx.btn("", "✖ Cancel", Some("gbot:auth_cancel"), Some("danger"), None),
            ]);
        } else if let Some(ref c) = creds {
            if c.quarantined_reason.is_some() {
                rows.push(vec![ctx.btn(
                    "",
                    "🔐 Generate New Login Link",
                    Some("gbot:auth"),
                    Some("primary"),
                    None,
                )]);
            }
            rows.push(vec![
                ctx.btn("", "🔄 Refresh Token", Some("gbot:refresh_tok"), None, None),
                ctx.btn("", "📊 Usage & Status", Some("gbot:status"), None, None),
            ]);
            rows.push(vec![
                ctx.btn("", "🔐 New Login Link", Some("gbot:auth"), None, None),
                ctx.btn("", "🔌 Disconnect", Some("gbot:logout"), Some("danger"), None),
            ]);
        } else {
            rows.push(vec![
                ctx.btn(
                    "",
                    "🔐 Connect Grok Bot (OAuth)",
                    Some("gbot:auth"),
                    Some("primary"),
                    None,
                ),
                ctx.btn("", "🌐 Proxy", Some("px:list"), None, None),
            ]);
        }
    }

    if creds.is_some() && selected.is_some() {
        rows.push(vec![
            ctx.btn("", "📜 Recent Log", Some("gbot:log"), None, None),
            ctx.btn("", "⏹ Stop Bot Run", Some("gbot:stop"), Some("danger"), None),
        ]);
    }

    let agy_lbl = format!(
        "{}Switch to AGY Default",
        if !active_gbot { "✅ " } else { "" }
    );
    rows.push(vec![ctx.btn("", &agy_lbl, Some("gbot:agy"), None, None)]);

    let start = page * BOTS_PER_PAGE;
    let end = (start + BOTS_PER_PAGE).min(agents.len());
    let chunk: Vec<(usize, &GrokBotAgent)> = agents
        .iter()
        .enumerate()
        .skip(start)
        .take(end.saturating_sub(start))
        .collect();

    for pair in chunk.chunks(2) {
        let row = pair
            .iter()
            .map(|&(idx, bot)| {
                let is_sel = active_gbot
                    && selected
                        .as_ref()
                        .is_some_and(|(id, _)| id == &bot.agent_id);
                let mark = if is_sel { "✅ " } else { "" };
                let label = format!("{mark}{}", truncate_chars(&bot.name, 26));
                ctx.btn("", &label, Some(&format!("gbot:b:{idx}")), None, None)
            })
            .collect();
        rows.push(row);
    }

    let mut nav = Vec::new();
    if page > 0 {
        nav.push(ctx.btn(
            "",
            "‹ Prev",
            Some(&format!("gbot:p:{}", page - 1)),
            None,
            None,
        ));
    }
    if page + 1 < pages {
        nav.push(ctx.btn(
            "",
            "Next ›",
            Some(&format!("gbot:p:{}", page + 1)),
            None,
            None,
        ));
    }
    if !nav.is_empty() {
        rows.push(nav);
    }

    let lang = ctx.lang(uid);
    rows.push(vec![
        ctx.btn("", "🔄 Sync Bots", Some("gbot:sync"), None, None),
        ctx.btn("", "« Grok Panel", Some("grok:open"), None, None),
    ]);
    rows.push(vec![ctx.btn("menu", t(lang, Tx::BtnMenu), Some("home"), None, None)]);

    let oauth_line = match &creds {
        Some(c) if c.quarantined_reason.is_some() => {
            let reason = c.quarantined_reason.as_deref().unwrap_or("re-login required");
            format!(
                "🔴 <b>Grok Bot OAuth:</b> Expired/Rejected (<code>{}</code>) — generate a new login link",
                esc(&truncate_chars(reason, 90))
            )
        }
        Some(c) => {
            let who = c
                .masked_email()
                .or_else(|| c.first_name.clone())
                .unwrap_or_else(|| "connected".to_string());
            format!(
                "🟢 <b>Grok Bot OAuth:</b> Connected · <code>{}</code> (<i>{}</i>)",
                esc(&who),
                esc(&fmt_token_status(c.expires_at)),
            )
        }
        None => "⚪ <b>Grok Bot OAuth:</b> Not connected (PKCE browser sign-in, no password needed)"
            .to_string(),
    };

    let active_line = if active_gbot {
        match &selected {
            Some((_, name)) => format!("🤖 <b>Active Engine:</b> Grok Bot (<code>{}</code>)", esc(name)),
            None => "🤖 <b>Active Engine:</b> Grok Bot (<i>tap a synced bot below</i>)".to_string(),
        }
    } else {
        match &selected {
            Some((_, name)) => format!("💤 <b>Last Selected Bot:</b> <code>{}</code> (currently inactive)", esc(name)),
            None => "💤 <b>Selected Bot:</b> none (tap Sync Bots after connecting)".to_string(),
        }
    };

    let auth_line = if let Some(ref snap) = auth_snap {
        let extra = snap
            .last_status
            .as_deref()
            .filter(|s| !s.is_empty())
            .map(|s| format!(" · <i>{}</i>", esc(s)))
            .unwrap_or_default();
        format!(
            "\n⏳ <b>Login pending:</b> session <code>{}</code> (<i>{} left · checked {}x</i>{extra})",
            esc(&snap.short_code),
            fmt_mm_ss(snap.remaining_secs),
            snap.polls,
        )
    } else {
        String::new()
    };

    let text = format!(
        "🤖 <b>Grok Bot (Cloud Agents &amp; PKCE OAuth)</b>\n\
        <blockquote>Dedicated Grok Bot flow (<code>cursor.com/loginDeepControl</code> + <code>api2.cursor.sh</code>), independent from Grok CLI OAuth.\n\
        Use <code>/gbot ask &lt;message&gt;</code> for one-shot messages or select a bot below for sticky chat.</blockquote>\n\
        {oauth_line}{auth_line}\n\
        {active_line}\n\
        <i>Page {} of {} · {} bot(s) cached</i>",
        page + 1,
        pages,
        agents.len(),
    );

    ctx.edit_or_send(cq, chat_id, &text, Some(BotCtx::kb(rows)))
        .await;
}

/// Start (or regenerate) a fresh PKCE Deep-Control OAuth login flow for Grok Bot (owner-only).
pub async fn start_grok_bot_oauth(
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
                .send_html_simple(chat_id, &owner_only_html(ctx, uid), None)
                .await;
        }
        return;
    }

    {
        let mut slot = active_grok_bot_auth()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(prev) = slot.take() {
            prev.session.cancel();
        }
    }

    if let Some(cq) = cq {
        ctx.ack(&cq.id, Some("Generating fresh Grok Bot login link…"), false)
            .await;
    }

    let proxy_url = match resolve_grok_proxy_opt(ctx) {
        Ok(px) => px,
        Err(reason) => {
            let txt = format!(
                "{} <b>Grok Bot OAuth blocked (fail-closed proxy)</b>\n<blockquote>{}</blockquote>\n<i>Check /proxies first.</i>",
                ctx.e("err"),
                esc(&reason)
            );
            let mk = BotCtx::kb(vec![vec![
                ctx.btn("", "🌐 Open Proxies", Some("px:list"), Some("primary"), None),
                ctx.btn("", "« Grok Bot", Some("gbot:open"), None, None),
            ]]);
            ctx.edit_or_send(cq, chat_id, &txt, Some(mk)).await;
            return;
        }
    };
    let _ = proxy_url;

    let pkce = match start_pkce_login() {
        Ok(p) => p,
        Err(err) => {
            let txt = format!(
                "{} <b>Failed to generate PKCE login link:</b> <code>{}</code>",
                ctx.e("err"),
                esc(&err.to_string())
            );
            let mk = BotCtx::kb(vec![vec![
                ctx.btn("", "🔄 Retry", Some("gbot:auth"), Some("primary"), None),
                ctx.btn("", "« Grok Bot", Some("gbot:open"), None, None),
            ]]);
            ctx.edit_or_send(cq, chat_id, &txt, Some(mk)).await;
            return;
        }
    };

    let expires_secs = pkce.expires_in.clamp(60, 900);
    let deadline = Instant::now() + Duration::from_secs(expires_secs);
    let polls_ctr = Arc::new(AtomicU32::new(0));
    let last_status_box: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));

    let (sess, mut cancel_rx) =
        GrokBotAuthSession::new(pkce.short_code.clone(), pkce.login_url.clone());
    {
        let mut slot = active_grok_bot_auth()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        *slot = Some(ActiveGrokBotAuth {
            session: Arc::clone(&sess),
            cancel_rx: cancel_rx.clone(),
            expires_at: deadline,
            polls: Arc::clone(&polls_ctr),
            last_status: Arc::clone(&last_status_box),
        });
    }

    let (txt, mk) = render_pkce_auth_card(
        ctx,
        &pkce.short_code,
        &pkce.login_url,
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
    let short_code_bg = pkce.short_code.clone();
    let login_url_bg = pkce.login_url.clone();
    let uuid_bg = pkce.uuid;
    let verifier_bg = pkce.verifier;

    tokio::spawn(async move {
        let mut transient_errors = 0u32;
        let mut last_ui_edit = Instant::now();
        let mut sleep_secs = 2u64;

        let final_html: Option<String> = loop {
            if Instant::now() >= deadline {
                break Some(
                    "⏱ <b>Grok Bot OAuth login link expired.</b>\n\
                    <i>Tap <b>New Login Link</b> below to generate a fresh code anytime.</i>"
                        .to_string(),
                );
            }

            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(sleep_secs)) => {}
                res = cancel_rx.changed() => {
                    if res.is_err() || *cancel_rx.borrow() {
                        break Some("✖ <i>Grok Bot OAuth login cancelled.</i>".to_string());
                    }
                }
            }
            if *cancel_rx.borrow() {
                break Some("✖ <i>Grok Bot OAuth login cancelled.</i>".to_string());
            }

            let poll_px = match resolve_grok_proxy_opt(&ctx_bg) {
                Ok(px) => px,
                Err(reason) => {
                    break Some(format!(
                        "{} <b>Grok Bot OAuth polling stopped (fail-closed proxy):</b> <code>{}</code>",
                        ctx_bg.e("err"),
                        esc(&reason)
                    ));
                }
            };

            let poll_count = polls_bg.fetch_add(1, Ordering::Relaxed) + 1;
            let mut status_changed = false;

            match poll_pkce_login_once_via(&uuid_bg, &verifier_bg, poll_px.as_deref()).await {
                Ok(GrokBotPollOutcome::Pending) => {
                    transient_errors = 0;
                    sleep_secs = 2;
                    if let Ok(mut g) = status_bg.lock() {
                        if g.is_some() {
                            *g = None;
                            status_changed = true;
                        }
                    }
                }
                Ok(GrokBotPollOutcome::Authorized(creds)) => {
                    if let Err(err) = save_grok_bot_creds(&ctx_bg.cfg.state_dir, &creds) {
                        warn!(error = %err, "failed saving Grok Bot OAuth creds");
                        break Some(format!(
                            "{} <b>Grok Bot authorized, but failed saving credentials:</b> <code>{}</code>",
                            ctx_bg.e("err"),
                            esc(&err.to_string())
                        ));
                    }
                    let agents = list_grok_bot_agents_via(&ctx_bg.cfg.state_dir, poll_px.as_deref())
                        .await
                        .unwrap_or_default();
                    let usage_line = fetch_grok_bot_usage_via(&ctx_bg.cfg.state_dir, poll_px.as_deref())
                        .await
                        .ok()
                        .and_then(|u| {
                            u.usage_percent
                                .map(|p| format!("\n<b>Weekly usage</b>  <code>{p:.1}%</code>"))
                        })
                        .unwrap_or_default();
                    let who = creds
                        .masked_email()
                        .or_else(|| creds.first_name.clone())
                        .unwrap_or_else(|| "Grok Bot account".to_string());
                    info!(email = %who, bots = agents.len(), "Grok Bot OAuth connected");
                    break Some(format!(
                        "{} <b>Grok Bot OAuth connected!</b>\n\
                        <blockquote><b>Account</b>  <code>{}</code>\n\
                        <b>Synced bots</b>  {}{usage_line}</blockquote>\n\
                        <i>Open the Grok Bot panel to pick a cloud bot or run <code>/gbot ask &lt;task&gt;</code>.</i>",
                        ctx_bg.e("ok"),
                        esc(&who),
                        agents.len(),
                    ));
                }
                Ok(GrokBotPollOutcome::Expired(why)) => {
                    break Some(format!(
                        "⏱ <b>Grok Bot OAuth link expired</b> (<code>{}</code>).\n\
                        <i>Tap <b>New Login Link</b> below to generate a new code.</i>",
                        esc(&why)
                    ));
                }
                Ok(GrokBotPollOutcome::Denied(why)) => {
                    break Some(format!(
                        "🚫 <b>Grok Bot OAuth denied:</b> <code>{}</code>",
                        esc(&why)
                    ));
                }
                Err(err) => {
                    transient_errors += 1;
                    sleep_secs = (2 * u64::from(transient_errors)).min(10);
                    warn!(attempt = transient_errors, error = %err, "Grok Bot OAuth poll error");
                    if transient_errors >= 6 {
                        break Some(format!(
                            "{} <b>Grok Bot OAuth polling failed:</b> <code>{}</code>\n\
                            <i>Tap <b>New Login Link</b> to generate a fresh login attempt.</i>",
                            ctx_bg.e("err"),
                            esc(&err.to_string())
                        ));
                    }
                    if let Ok(mut g) = status_bg.lock() {
                        *g = Some(format!("retry #{transient_errors}/6"));
                        status_changed = true;
                    }
                }
            }

            if let Some(mid) = prompt_msg_id {
                if status_changed || last_ui_edit.elapsed() >= Duration::from_secs(15) {
                    let rem = deadline.saturating_duration_since(Instant::now()).as_secs();
                    let note = status_bg.lock().ok().and_then(|g| g.clone());
                    let (live_txt, live_mk) = render_pkce_auth_card(
                        &ctx_bg,
                        &short_code_bg,
                        &login_url_bg,
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

        {
            let mut slot = active_grok_bot_auth()
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if slot.as_ref().is_some_and(|cur| Arc::ptr_eq(&cur.session, &sess_bg)) {
                *slot = None;
            }
        }

        if let Some(html) = final_html {
            let mk = BotCtx::kb(vec![
                vec![
                    ctx_bg.btn("", "🤖 Open Grok Bot Panel", Some("gbot:open"), Some("primary"), None),
                    ctx_bg.btn("", "🔄 New Login Link", Some("gbot:auth"), None, None),
                ],
                vec![
                    ctx_bg.btn("", "« Grok Panel", Some("grok:open"), None, None),
                    ctx_bg.btn("menu", "Menu", Some("home"), None, None),
                ],
            ]);
            let _ = ctx_bg
                .render
                .edit_or_send_html(chat_id, prompt_msg_id, &html, Some(mk))
                .await;
        }
    });
}

async fn sync_bots_cmd_or_cb(ctx: &Arc<BotCtx>, cq: Option<&CallbackQuery>, chat_id: i64, uid: i64) {
    let px = match resolve_grok_proxy_opt(ctx) {
        Ok(p) => p,
        Err(reason) => {
            if let Some(cq) = cq {
                ctx.ack(&cq.id, Some(&truncate_chars(&format!("Proxy blocked: {reason}"), 160)), true).await;
            } else {
                let _ = ctx
                    .render
                    .send_html_simple(chat_id, &format!("{} Proxy blocked: <code>{}</code>", ctx.e("err"), esc(&reason)), None)
                    .await;
            }
            return;
        }
    };
    match list_grok_bot_agents_via(&ctx.cfg.state_dir, px.as_deref()).await {
        Ok(bots) => {
            if let Some(cq) = cq {
                ctx.ack(&cq.id, Some(&format!("Synced {} Grok Bot(s)", bots.len())), false).await;
                show_grok_bot_panel(ctx, Some(cq), chat_id, uid, 0).await;
            } else {
                let list = if bots.is_empty() {
                    "<i>No Grok Bots found on this account yet.</i>".to_string()
                } else {
                    bots.iter()
                        .take(20)
                        .map(|b| format!("• <b>{}</b> (<code>{}</code>)", esc(&b.name), esc(&b.agent_id)))
                        .collect::<Vec<_>>()
                        .join("\n")
                };
                let _ = ctx
                    .render
                    .send_html_simple(
                        chat_id,
                        &format!("🤖 <b>Synced {} Grok Bot(s)</b>\n{list}", bots.len()),
                        None,
                    )
                    .await;
            }
        }
        Err(err) => {
            if let Some(cq) = cq {
                ctx.ack(&cq.id, Some(&truncate_chars(&err.to_string(), 160)), true).await;
            } else {
                let _ = ctx
                    .render
                    .send_html_simple(
                        chat_id,
                        &format!("{} <b>Sync failed:</b> <code>{}</code>", ctx.e("err"), esc(&err.to_string())),
                        None,
                    )
                    .await;
            }
        }
    }
}

async fn show_usage_and_status(ctx: &Arc<BotCtx>, chat_id: i64, uid: i64) {
    let px = match resolve_grok_proxy_opt(ctx) {
        Ok(p) => p,
        Err(reason) => {
            let _ = ctx
                .render
                .send_html_simple(chat_id, &format!("{} Proxy blocked: <code>{}</code>", ctx.e("err"), esc(&reason)), None)
                .await;
            return;
        }
    };
    let usage_res = fetch_grok_bot_usage_via(&ctx.cfg.state_dir, px.as_deref()).await;
    let bots_res = list_grok_bot_agents_via(&ctx.cfg.state_dir, px.as_deref()).await;
    let mut lines = Vec::new();
    match usage_res {
        Ok(u) => {
            let pct = u
                .usage_percent
                .map(|p| format!("{p:.1}%"))
                .unwrap_or_else(|| "N/A".to_string());
            let plan = u.grok_plan_label.unwrap_or_else(|| "Grok Bot".to_string());
            let avail = u
                .has_available_usage
                .map(|b| if b { "Yes" } else { "No" })
                .unwrap_or("Unknown");
            lines.push(format!(
                "📊 <b>Plan:</b> <code>{}</code> · <b>Weekly:</b> <code>{pct}</code> · <b>Available:</b> <code>{avail}</code>",
                esc(&plan)
            ));
            if let Some(rst) = u.next_reset_timestamp_utc {
                lines.push(format!("🔄 <b>Resets:</b> <code>{}</code>", esc(&rst)));
            }
        }
        Err(err) => {
            lines.push(format!("⚠️ <b>Usage error:</b> <code>{}</code>", esc(&err.to_string())));
        }
    }

    if let Ok(bots) = bots_res {
        let ids: Vec<String> = bots.iter().map(|b| b.agent_id.clone()).collect();
        let statuses = list_grok_bot_statuses_via(&ctx.cfg.state_dir, &ids, px.as_deref())
            .await
            .unwrap_or_default();
        for b in bots.iter().take(15) {
            let st = statuses.iter().find(|s| s.agent_id == b.agent_id);
            let state = match st.and_then(|s| s.live.as_ref()) {
                Some(live) if live.awaiting.is_some() => {
                    format!("awaiting ({})", live.awaiting.as_ref().map(|a| a.reason.as_str()).unwrap_or("input"))
                }
                Some(live) if live.is_running => {
                    live.activity
                        .as_ref()
                        .map(|a| format!("running: {} {}", a.tool, a.detail).trim().to_string())
                        .filter(|s| !s.is_empty())
                        .unwrap_or_else(|| "running".to_string())
                }
                Some(live) if live.has_running_subagents || !live.working_task_ids.is_empty() => {
                    "background work".to_string()
                }
                _ if st.is_some_and(|s| s.is_running) => "running".to_string(),
                _ => "idle".to_string(),
            };
            lines.push(format!("• <b>{}</b> — <code>{}</code>", esc(&b.name), esc(&state)));
        }
    }

    let mk = BotCtx::kb(vec![vec![
        ctx.btn("", "« Grok Bot", Some("gbot:open"), None, None),
        ctx.btn("menu", t(ctx.lang(uid), Tx::BtnMenu), Some("home"), None, None),
    ]]);
    let _ = ctx
        .render
        .send_html_simple(chat_id, &lines.join("\n"), Some(mk))
        .await;
}

async fn show_recent_log(ctx: &Arc<BotCtx>, chat_id: i64, uid: i64) {
    let u = ctx.store.get_user(uid);
    let Some((agent_id, agent_name)) = selected_grok_bot(&u) else {
        let _ = ctx
            .render
            .send_html_simple(chat_id, "ℹ️ Select a Grok Bot in <code>/gbot</code> first.", None)
            .await;
        return;
    };
    let px = match resolve_grok_proxy_opt(ctx) {
        Ok(p) => p,
        Err(reason) => {
            let _ = ctx
                .render
                .send_html_simple(chat_id, &format!("{} Proxy blocked: <code>{}</code>", ctx.e("err"), esc(&reason)), None)
                .await;
            return;
        }
    };
    let session = resolve_main_session_via(&ctx.cfg.state_dir, &agent_id, px.as_deref())
        .await
        .unwrap_or_default();
    match list_transcript_entries_via(&ctx.cfg.state_dir, &agent_id, &session, 15, None, px.as_deref()).await {
        Ok(mut entries) => {
            entries.reverse();
            let mut lines = Vec::new();
            for e in entries {
                match e.view() {
                    GrokBotEntryView::User { text, .. } if !text.trim().is_empty() => {
                        lines.push(format!("👤 {}", esc(&truncate_chars(text.trim(), 220))));
                    }
                    GrokBotEntryView::Reply { text } if !text.trim().is_empty() => {
                        lines.push(format!("🤖 {}", esc(&truncate_chars(text.trim(), 320))));
                    }
                    GrokBotEntryView::NeedsInput { what, answered } if !answered => {
                        lines.push(format!("⚠️ Needs input: {}", esc(&what)));
                    }
                    _ => {}
                }
            }
            let body = if lines.is_empty() {
                "<i>No recent messages in transcript.</i>".to_string()
            } else {
                lines.join("\n\n")
            };
            let _ = ctx
                .render
                .send_html_simple(
                    chat_id,
                    &format!("📜 <b>Recent Log — {}</b>\n<blockquote>{body}</blockquote>", esc(&agent_name)),
                    None,
                )
                .await;
        }
        Err(err) => {
            let _ = ctx
                .render
                .send_html_simple(
                    chat_id,
                    &format!("{} <b>Failed loading log:</b> <code>{}</code>", ctx.e("err"), esc(&err.to_string())),
                    None,
                )
                .await;
        }
    }
}

async fn stop_active_bot_run(ctx: &Arc<BotCtx>, cq: Option<&CallbackQuery>, chat_id: i64, uid: i64) {
    let u = ctx.store.get_user(uid);
    let Some((agent_id, agent_name)) = selected_grok_bot(&u) else {
        if let Some(cq) = cq {
            ctx.ack(&cq.id, Some("Select a bot first"), true).await;
        }
        return;
    };
    let px = match resolve_grok_proxy_opt(ctx) {
        Ok(p) => p,
        Err(reason) => {
            if let Some(cq) = cq {
                ctx.ack(&cq.id, Some(&truncate_chars(&reason, 160)), true).await;
            }
            return;
        }
    };
    let session = resolve_main_session_via(&ctx.cfg.state_dir, &agent_id, px.as_deref())
        .await
        .unwrap_or_default();
    match interrupt_grok_bot_run_via(&ctx.cfg.state_dir, &agent_id, &session, px.as_deref()).await {
        Ok(had) => {
            let msg = if had {
                format!("⏹ Stopped active run on {agent_name}")
            } else {
                format!("ℹ️ {agent_name} had no active run")
            };
            if let Some(cq) = cq {
                ctx.ack(&cq.id, Some(&truncate_chars(&msg, 180)), false).await;
            } else {
                let _ = ctx.render.send_html_simple(chat_id, &esc(&msg), None).await;
            }
        }
        Err(err) => {
            if let Some(cq) = cq {
                ctx.ack(&cq.id, Some(&truncate_chars(&err.to_string(), 180)), true).await;
            } else {
                let _ = ctx
                    .render
                    .send_html_simple(chat_id, &format!("{} {}", ctx.e("err"), esc(&err.to_string())), None)
                    .await;
            }
        }
    }
}

fn select_bot_by_query(ctx: &BotCtx, uid: i64, query: &str) -> Option<GrokBotAgent> {
    let agents = load_cached_grok_bot_agents(&ctx.cfg.state_dir);
    let found = if let Ok(idx) = query.parse::<usize>() {
        agents.get(idx).cloned()
    } else {
        let q_low = query.trim().to_ascii_lowercase();
        agents
            .iter()
            .find(|a| a.agent_id == query || a.name.eq_ignore_ascii_case(query))
            .cloned()
            .or_else(|| {
                let matches: Vec<&GrokBotAgent> = agents
                    .iter()
                    .filter(|a| a.name.to_ascii_lowercase().starts_with(&q_low))
                    .collect();
                if matches.len() == 1 {
                    Some(matches[0].clone())
                } else {
                    None
                }
            })
    }?;
    let _ = ctx.store.update_user(uid, |st| {
        st.extra.insert("engine".to_string(), json!("grok_bot"));
        st.extra
            .insert(GROK_BOT_AGENT_ID_KEY.to_string(), json!(found.agent_id));
        st.extra
            .insert(GROK_BOT_AGENT_NAME_KEY.to_string(), json!(found.name));
        st.extra.remove(MODEL_INVALID_KEY);
    });
    Some(found)
}

/// Handle callback data starting with `gbot:`.
pub async fn handle_grok_bot_cb(
    ctx: &Arc<BotCtx>,
    cq: &CallbackQuery,
    uid: i64,
    chat_id: i64,
    data: &str,
) -> bool {
    let Some(rest) = data.strip_prefix("gbot:") else {
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
            show_grok_bot_panel(ctx, Some(cq), chat_id, uid, 0).await;
            true
        }
        "auth" => {
            start_grok_bot_oauth(ctx, Some(cq), uid, chat_id).await;
            true
        }
        "auth_cancel" => {
            if !ctx.is_owner(uid) {
                ctx.ack(&cq.id, Some("Owner only"), true).await;
                return true;
            }
            let cancelled = {
                let mut slot = active_grok_bot_auth()
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                slot.take().map(|s| s.session.cancel()).is_some()
            };
            ctx.ack(
                &cq.id,
                Some(if cancelled {
                    "Grok Bot login cancelled"
                } else {
                    "No active login"
                }),
                false,
            )
            .await;
            show_grok_bot_panel(ctx, Some(cq), chat_id, uid, 0).await;
            true
        }
        "refresh_tok" => {
            if !ctx.is_owner(uid) {
                ctx.ack(&cq.id, Some("Owner only"), true).await;
                return true;
            }
            ctx.ack(&cq.id, Some("Refreshing Grok Bot OAuth token…"), false).await;
            match resolve_grok_proxy_opt(ctx) {
                Err(reason) => {
                    let _ = ctx
                        .render
                        .send_html_simple(
                            chat_id,
                            &format!("{} <b>Refresh blocked (proxy):</b> <code>{}</code>", ctx.e("err"), esc(&reason)),
                            None,
                        )
                        .await;
                }
                Ok(px) => {
                    if let Err(err) =
                        ensure_valid_grok_bot_creds_via(&ctx.cfg.state_dir, true, px.as_deref()).await
                    {
                        let mk = BotCtx::kb(vec![vec![ctx.btn(
                            "",
                            "🔐 Generate New Login Link",
                            Some("gbot:auth"),
                            Some("primary"),
                            None,
                        )]]);
                        let _ = ctx
                            .render
                            .send_html_simple(
                                chat_id,
                                &format!(
                                    "{} <b>Token refresh failed:</b> <code>{}</code>",
                                    ctx.e("err"),
                                    esc(&err.to_string())
                                ),
                                Some(mk),
                            )
                            .await;
                    }
                }
            }
            show_grok_bot_panel(ctx, Some(cq), chat_id, uid, 0).await;
            true
        }
        "logout" => {
            if !ctx.is_owner(uid) {
                ctx.ack(&cq.id, Some("Owner only"), true).await;
                return true;
            }
            delete_grok_bot_creds(&ctx.cfg.state_dir);
            ctx.ack(&cq.id, Some("Grok Bot OAuth disconnected"), false).await;
            show_grok_bot_panel(ctx, Some(cq), chat_id, uid, 0).await;
            true
        }
        "sync" => {
            sync_bots_cmd_or_cb(ctx, Some(cq), chat_id, uid).await;
            true
        }
        "status" => {
            ctx.ack(&cq.id, Some("Fetching Grok Bot status & usage…"), false).await;
            show_usage_and_status(ctx, chat_id, uid).await;
            true
        }
        "log" => {
            ctx.ack(&cq.id, Some("Loading recent log…"), false).await;
            show_recent_log(ctx, chat_id, uid).await;
            true
        }
        "stop" => {
            stop_active_bot_run(ctx, Some(cq), chat_id, uid).await;
            true
        }
        "agy" => {
            let _ = ctx.store.update_user(uid, |st| {
                st.extra.remove("engine");
                st.extra.remove(MODEL_INVALID_KEY);
                st.model = None;
            });
            ctx.jobs.clear_model_choices(uid);
            ctx.ack(&cq.id, Some("Switched to AGY default model"), false).await;
            show_grok_bot_panel(ctx, Some(cq), chat_id, uid, 0).await;
            true
        }
        other => {
            if let Some(p_str) = other.strip_prefix("p:") {
                let page = p_str.parse::<usize>().unwrap_or(0);
                ctx.ack(&cq.id, None, false).await;
                show_grok_bot_panel(ctx, Some(cq), chat_id, uid, page).await;
                return true;
            }
            if let Some(b_str) = other.strip_prefix("b:") {
                if let Some(bot) = select_bot_by_query(ctx, uid, b_str) {
                    ctx.ack(
                        &cq.id,
                        Some(&format!("Grok Bot: {}", truncate_chars(&bot.name, 34))),
                        false,
                    )
                    .await;
                } else {
                    ctx.ack(&cq.id, Some("Bot not found — tap Sync Bots"), true).await;
                }
                show_grok_bot_panel(ctx, Some(cq), chat_id, uid, 0).await;
                return true;
            }
            false
        }
    }
}

/// Slash command `/gbot [login|logout|sync|status|log|stop|ask <task>|<bot>]` (and `/grokbot`).
pub async fn cmd_gbot(ctx: &Arc<BotCtx>, msg: &Message, arg: &str) {
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

    let a = arg.trim();
    let low = a.to_ascii_lowercase();
    if a.is_empty() {
        show_grok_bot_panel(ctx, None, chat_id, uid, 0).await;
    } else if matches!(low.as_str(), "login" | "auth" | "connect" | "new") {
        start_grok_bot_oauth(ctx, None, uid, chat_id).await;
    } else if matches!(low.as_str(), "logout" | "disconnect") {
        if !ctx.is_owner(uid) {
            let _ = ctx
                .render
                .send_html_simple(chat_id, &owner_only_html(ctx, uid), None)
                .await;
            return;
        }
        let deleted = delete_grok_bot_creds(&ctx.cfg.state_dir);
        let txt = if deleted {
            "🔌 Grok Bot OAuth disconnected."
        } else {
            "ℹ️ Grok Bot OAuth was not connected."
        };
        let _ = ctx.render.send_html_simple(chat_id, txt, None).await;
    } else if matches!(low.as_str(), "sync" | "list" | "bots") {
        sync_bots_cmd_or_cb(ctx, None, chat_id, uid).await;
    } else if low == "status" || low == "usage" {
        show_usage_and_status(ctx, chat_id, uid).await;
    } else if low == "log" || low == "logs" {
        show_recent_log(ctx, chat_id, uid).await;
    } else if low == "stop" {
        stop_active_bot_run(ctx, None, chat_id, uid).await;
    } else if let Some(task) = a
        .strip_prefix("ask ")
        .or_else(|| a.strip_prefix("ASK "))
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        let mut req = JobRequest::new(uid, chat_id, user.display_label(), task, Vec::new());
        req.overrides = JobOverride {
            isolated: true,
            force_engine: Some("grok_bot".to_string()),
            ..Default::default()
        };
        if let Err(err) = ctx.jobs.enqueue(req).await {
            let _ = ctx
                .render
                .send_html_simple(
                    chat_id,
                    &format!("{} <b>Failed to message Grok Bot:</b> <code>{}</code>", ctx.e("err"), esc(&err.to_string())),
                    None,
                )
                .await;
        }
    } else if let Some(bot) = select_bot_by_query(ctx, uid, a) {
        let _ = ctx
            .render
            .send_html_simple(
                chat_id,
                &format!("🤖 Active Grok Bot → <b>{}</b> (<code>{}</code>)", esc(&bot.name), esc(&bot.agent_id)),
                None,
            )
            .await;
    } else {
        show_grok_bot_panel(ctx, None, chat_id, uid, 0).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grok_bot_state_detection_and_selection() {
        let mut u = UserState::default();
        assert!(!is_grok_bot_active(&u));
        assert!(selected_grok_bot(&u).is_none());

        u.extra.insert("engine".to_string(), json!("grok_bot"));
        u.extra
            .insert(GROK_BOT_AGENT_ID_KEY.to_string(), json!("uuid-123"));
        u.extra
            .insert(GROK_BOT_AGENT_NAME_KEY.to_string(), json!("Research Bot"));
        assert!(is_grok_bot_active(&u));
        assert_eq!(
            selected_grok_bot(&u),
            Some(("uuid-123".to_string(), "Research Bot".to_string()))
        );

        u.extra.remove("engine");
        assert!(!is_grok_bot_active(&u));
    }
}
