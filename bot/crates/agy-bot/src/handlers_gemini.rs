//! Handlers for the unified `🌐 Web Model` hub (`🔥 Venice` + `💎 Gemini Manager`),
//! including Antigravity-style Gemini Account Pool, Gems Studio (with local source files),
//! Canvas mode, Image Create mode, and OpenHands 35-tool Agent mode.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use agy_core::proxies::ResolvedProxy;
use agy_core::store::UserState;
use agy_core::tg::{CallbackQuery, Message};
use agy_ext::agent_runtime::{clear_session_history, ThreeStageMode};
use agy_ext::gemini_web::{
    discover_local_gemini_backends, gemini_gem_sources_dir, parse_account_input_lines,
    probe_and_record_account, probe_gemini_account, sanitize_slug, GeminiAccountPool,
    GeminiBackendKind, GeminiChatMode, GeminiGem, GeminiGemStore, DEFAULT_GEMINI_CANVAS_MODEL,
    DEFAULT_GEMINI_IMAGE_MODEL, DEFAULT_GEMINI_MODEL, DEFAULT_GEMINI_WEB_MODEL,
};
use agy_render::esc;

use crate::ctx::BotCtx;
use crate::i18n::{t, Tx};
use crate::jobs::AwaitingInput;

pub const GEMINI_MODE_KEY: &str = "gemini_mode";
pub const GEMINI_GEM_KEY: &str = "gemini_gem_id";
pub const GEMINI_MODEL_KEY: &str = "gemini_model";
pub const GEMINI_THREE_STAGE_KEY: &str = "gemini_three_stage";
pub const GEMINI_PINNED_ACCT_KEY: &str = "gemini_pinned_account";

pub fn gemini_pinned_account(u: &UserState) -> Option<String> {
    u.extra
        .get(GEMINI_PINNED_ACCT_KEY)
        .and_then(|v| v.as_str())
        .filter(|s| !s.trim().is_empty())
        .map(str::to_string)
}

pub fn gemini_chat_mode(u: &UserState) -> GeminiChatMode {
    u.extra
        .get(GEMINI_MODE_KEY)
        .and_then(|v| v.as_str())
        .map(GeminiChatMode::parse)
        .unwrap_or(GeminiChatMode::Agent)
}

pub fn gemini_active_gem_id(u: &UserState) -> Option<String> {
    u.extra
        .get(GEMINI_GEM_KEY)
        .and_then(|v| v.as_str())
        .filter(|s| !s.trim().is_empty())
        .map(str::to_string)
}

pub fn gemini_selected_model(u: &UserState) -> Option<String> {
    u.extra
        .get(GEMINI_MODEL_KEY)
        .and_then(|v| v.as_str())
        .filter(|s| !s.trim().is_empty())
        .map(str::to_string)
}

pub fn gemini_three_stage_mode(u: &UserState) -> ThreeStageMode {
    match u
        .extra
        .get(GEMINI_THREE_STAGE_KEY)
        .and_then(|v| v.as_str())
        .unwrap_or("auto")
    {
        "always" => ThreeStageMode::Always,
        "off" => ThreeStageMode::Off,
        _ => ThreeStageMode::Auto,
    }
}

pub fn gemini_session_key(uid: i64) -> String {
    format!("gemini_web_{uid}")
}

/// Render the unified `🌐 Web Model` hub (`🔥 Venice` + `✨ Gemini Manager`).
pub async fn show_web_model_hub(
    ctx: &Arc<BotCtx>,
    uid: i64,
    chat_id: i64,
    cq: Option<&CallbackQuery>,
) {
    let lang = ctx.lang(uid);
    let u = ctx.store.get_user(uid);
    let eng = u.extra.get("engine").and_then(|v| v.as_str()).unwrap_or("agy");
    let pool = GeminiAccountPool::load(&ctx.cfg.state_dir);
    let gems = GeminiGemStore::load(&ctx.cfg.state_dir);
    let g_mode = gemini_chat_mode(&u);
    let active_tag = match eng {
        "uncensored" => format!("{} Venice Uncensored", ctx.e("fire")),
        "gemini_web" => format!("{} Gemini Manager", ctx.e("gemini")),
        _ => "Antigravity (default)".to_string(),
    };

    let html = format!(
        "{ic_web} <b>Web Model Hub</b>\n\n\
         <b>Active engine:</b> {active_tag}\n\
         • {ic_fire} <b>Venice</b>: Uncensored OpenHands Agent / Chat\n\
         • {ic_gem} <b>Gemini Manager</b>: <code>{}</code> accs · <code>{}</code> Gems · Mode: <code>{}</code>\n\n\
         <i>Choose a provider below:</i>",
        pool.accounts.len(),
        gems.gems.len(),
        esc(g_mode.label()),
        ic_web = ctx.e("browser"),
        ic_fire = ctx.e("fire"),
        ic_gem = ctx.e("gemini"),
    );
    let markup = BotCtx::kb(vec![
        vec![
            ctx.btn(
                "fire",
                "Venice Uncensored",
                Some("umodels:0"),
                if eng == "uncensored" { Some("primary") } else { None },
                None,
            ),
            ctx.btn(
                "gemini",
                "Gemini Manager",
                Some("gem:home"),
                if eng == "gemini_web" { Some("primary") } else { None },
                None,
            ),
        ],
        vec![ctx.btn("menu", t(lang, Tx::BtnMenu), Some("home"), None, None)],
    ]);
    ctx.edit_or_send(cq, chat_id, &html, Some(markup)).await;
}

/// Render the `✨ Gemini Manager` main dashboard.
pub async fn show_gemini_home(
    ctx: &Arc<BotCtx>,
    uid: i64,
    chat_id: i64,
    cq: Option<&CallbackQuery>,
) {
    let lang = ctx.lang(uid);
    let u = ctx.store.get_user(uid);
    let is_active = u.extra.get("engine").and_then(|v| v.as_str()) == Some("gemini_web");
    let mode = gemini_chat_mode(&u);
    let model = gemini_selected_model(&u).unwrap_or_else(|| "auto".to_string());
    let gem_id = gemini_active_gem_id(&u);
    let pool = GeminiAccountPool::load(&ctx.cfg.state_dir);
    let gems = GeminiGemStore::load(&ctx.cfg.state_dir);
    let ts = gemini_three_stage_mode(&u);

    let active_gem_line = match gem_id.as_deref().and_then(|id| gems.get(id)) {
        Some(g) => format!(
            "<code>{}</code> (<code>{}</code> sources)",
            esc(&g.name),
            g.source_files.len()
        ),
        None => "<code>None (default)</code>".to_string(),
    };

    let agy_emails: Vec<String> = ctx
        .jobs
        .accounts()
        .map(|s| s.list().into_iter().filter_map(|a| a.email).collect())
        .unwrap_or_default();
    let collisions = pool.antigravity_email_collisions(&agy_emails);
    let warn_block = if collisions.is_empty() {
        String::new()
    } else {
        format!(
            "\n{} <b>Anti-Ban Notice:</b> Web sidecar email(s) overlap Antigravity: <code>{}</code>. Keep concurrency=1 &amp; sticky proxy.",
            ctx.e("warn"),
            esc(&collisions.join(", "))
        )
    };

    let status_badge = if is_active {
        format!("{} ACTIVE", ctx.e("ok"))
    } else {
        "inactive".to_string()
    };
    let ts_label = match ts {
        ThreeStageMode::Auto => "Auto",
        ThreeStageMode::Always => "Always",
        ThreeStageMode::Off => "Off",
    };

    let html = format!(
        "{ic_gem} <b>Gemini Manager</b> ({status_badge})\n\n\
         <b>Mode:</b> <code>{}</code>\n\
         <b>Model:</b> <code>{}</code>\n\
         <b>Active Gem:</b> {active_gem_line}\n\
         <b>Accounts Pool:</b> <code>{}</code> configured (CONCURRENCY=1, Sticky Proxy)\n\
         <b>3-Stage Coding:</b> <code>{ts_label}</code>{warn_block}",
        esc(mode.label()),
        esc(&model),
        pool.accounts.len(),
        ic_gem = ctx.e("gemini"),
    );

    let m_style = |m: GeminiChatMode| -> Option<&'static str> {
        if mode == m { Some("primary") } else { None }
    };
    let rows = vec![
        vec![
            ctx.btn("codeintel", "Agent", Some("gem:mode:agent"), m_style(GeminiChatMode::Agent), None),
            ctx.btn("doc", "Canvas", Some("gem:mode:canvas"), m_style(GeminiChatMode::Canvas), None),
        ],
        vec![
            ctx.btn("image", "Image Create", Some("gem:mode:image"), m_style(GeminiChatMode::Image), None),
            ctx.btn("support", "Chat", Some("gem:mode:chat"), m_style(GeminiChatMode::Chat), None),
        ],
        vec![
            ctx.btn(
                if is_active { "ok" } else { "bolt" },
                if is_active { "Active (Gemini)" } else { "Activate Gemini" },
                Some("gem:use"),
                if is_active { Some("success") } else { Some("primary") },
                None,
            ),
            ctx.btn("memory", &format!("3-Stage: {ts_label}"), Some("gem:3stage"), None, None),
        ],
        vec![
            ctx.btn("accounts", &format!("Accounts ({})", pool.accounts.len()), Some("gem:accts"), None, None),
            ctx.btn("skills", &format!("Gems Studio ({})", gems.gems.len()), Some("gem:gems"), None, None),
        ],
        vec![
            ctx.btn("model", "Models", Some("gem:models"), None, None),
            ctx.btn("remove", "Clear Chat", Some("gem:clear"), Some("danger"), None),
        ],
        vec![
            ctx.btn("back", "Web Model", Some("webmodel:home"), None, None),
            ctx.btn("menu", t(lang, Tx::BtnMenu), Some("home"), None, None),
        ],
    ];
    ctx.edit_or_send(cq, chat_id, &html, Some(BotCtx::kb(rows))).await;
}

async fn show_gemini_accounts(
    ctx: &Arc<BotCtx>,
    uid: i64,
    chat_id: i64,
    cq: Option<&CallbackQuery>,
) {
    let pool = GeminiAccountPool::load_locked(&ctx.cfg.state_dir);
    let is_owner = ctx.is_owner(uid);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let mut lines = vec![
        format!("{} <b>Gemini Accounts Pool</b>", ctx.e("accounts")),
        "<i>Anti-ban: CONCURRENCY=1 · Sticky Proxy · EWMA Decay · Auto-Delete Secrets</i>\n"
            .to_string(),
    ];
    let mut rows = Vec::new();
    if pool.accounts.is_empty() {
        lines.push("No accounts configured yet. Tap <b>Smart Add</b> (paste AIza key, URL, or batch lines) or <b>Auto-Discover</b> to detect local sidecars.".to_string());
    } else {
        for a in &pool.accounts {
            let st = if !a.enabled {
                ctx.e("err")
            } else if a.is_cooled_down(now) {
                ctx.e("work")
            } else {
                ctx.e("ok")
            };
            let is_pinned = pool.active_account_id.as_deref() == Some(a.id.as_str());
            let pin = if is_pinned { " [PIN]" } else { "" };
            let proxy_s = match (a.proxy_id.as_deref(), a.proxy_url.as_deref()) {
                (Some(pid), _) => format!("{} {pid}", ctx.e("shield")),
                (None, Some(_)) => format!("{} custom", ctx.e("shield")),
                _ => "direct".to_string(),
            };
            let cd = if a.is_cooled_down(now) {
                format!(" cd={}s", a.cooldown_remaining_secs(now))
            } else {
                String::new()
            };
            let h_pct = a.health_pct(now);
            let lat_s = if a.ewma_latency_ms > 0.0 {
                format!(" · {:.1}s", a.ewma_latency_ms / 1000.0)
            } else {
                String::new()
            };
            let probe_s = match a.last_probe_ok {
                Some(true) => format!(" · {}m", a.discovered_models.len()),
                Some(false) => " · probe_err".to_string(),
                None => String::new(),
            };
            lines.push(format!(
                "{st} <b>{}</b>{pin} · <code>{}</code> · <code>{}</code> · {proxy_s} · {h_pct}%{lat_s}{probe_s}{cd}",
                esc(&a.label),
                esc(a.kind.label()),
                esc(&a.masked_key()),
            ));
            if is_owner {
                rows.push(vec![ctx.btn(
                    if is_pinned { "check" } else if !a.enabled { "stop" } else { "account" },
                    &format!("{} ({h_pct}%)", a.label),
                    Some(&format!("gem:v:{}", a.id)),
                    if is_pinned { Some("primary") } else { None },
                    None,
                )]);
            }
        }
    }

    if is_owner {
        if pool.active_account_id.is_some() {
            rows.push(vec![ctx.btn(
                "optimizer",
                "Auto Smart Balance",
                Some("gem:pin:auto"),
                Some("primary"),
                None,
            )]);
        }
        rows.push(vec![
            ctx.btn("add", "Smart Add (Key/URL)", Some("gem:add:auto"), Some("success"), None),
            ctx.btn("search", "Auto-Discover", Some("gem:scan"), Some("primary"), None),
        ]);
        rows.push(vec![
            ctx.btn("status", "Probe All", Some("gem:probe_all"), None, None),
            ctx.btn("mcp", "Sync Proxies (AGY)", Some("gem:sync_agy"), None, None),
        ]);
    }
    rows.push(vec![ctx.btn("back", "Gemini Manager", Some("gem:home"), None, None)]);

    ctx.edit_or_send(cq, chat_id, &lines.join("\n"), Some(BotCtx::kb(rows))).await;
}

async fn show_gemini_account_detail(
    ctx: &Arc<BotCtx>,
    uid: i64,
    chat_id: i64,
    cq: Option<&CallbackQuery>,
    id: &str,
) {
    let pool = GeminiAccountPool::load_locked(&ctx.cfg.state_dir);
    let Some(a) = pool.get(id) else {
        show_gemini_accounts(ctx, uid, chat_id, cq).await;
        return;
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let is_pinned = pool.active_account_id.as_deref() == Some(a.id.as_str());
    let status = if !a.enabled {
        format!("{} Paused", ctx.e("err"))
    } else if a.is_cooled_down(now) {
        format!("{} Cooldown ({}s)", ctx.e("work"), a.cooldown_remaining_secs(now))
    } else {
        format!("{} Ready", ctx.e("ok"))
    };
    let proxy_line = match (a.proxy_id.as_deref(), a.proxy_url.as_deref()) {
        (Some(pid), _) => format!("<code>{}</code> (managed)", esc(pid)),
        (None, Some(_)) => "<code>custom sticky proxy</code>".to_string(),
        _ => "<code>direct</code>".to_string(),
    };
    let probe_line = match a.last_probe_ok {
        Some(true) => format!(
            "{} OK · <code>{}</code> models · <code>{:.0}ms</code>",
            ctx.e("ok"),
            a.discovered_models.len(),
            a.ewma_latency_ms
        ),
        Some(false) => format!("{} Failed", ctx.e("err")),
        None => "<i>Not probed yet</i>".to_string(),
    };
    let err_line = a
        .last_error
        .as_deref()
        .map(|e| format!("\n<b>Last error:</b> <code>{}</code>", esc(e)))
        .unwrap_or_default();

    let html = format!(
        "{ic} <b>Gemini Account: {}</b> (<code>{}</code>)\n\n\
         <b>Status:</b> {status} · Health: <code>{}%</code>\n\
         <b>Backend:</b> <code>{}</code>\n\
         <b>Endpoint:</b> <code>{}</code>\n\
         <b>Key:</b> <code>{}</code>\n\
         <b>Email:</b> <code>{}</code>\n\
         <b>Sticky Proxy:</b> {proxy_line}\n\
         <b>Live Probe:</b> {probe_line}\n\
         <b>Stats:</b> <code>{}</code> ok / <code>{}</code> fail{err_line}",
        esc(&a.label),
        esc(&a.id),
        a.health_pct(now),
        esc(a.kind.label()),
        esc(&a.base_url),
        esc(&a.masked_key()),
        esc(a.email.as_deref().unwrap_or("—")),
        a.success_count,
        a.failure_count,
        ic = ctx.e("account"),
    );

    let pin_cb = if is_pinned {
        "gem:pin:auto".to_string()
    } else {
        format!("gem:pin:{}", a.id)
    };
    let rows = vec![
        vec![
            ctx.btn("status", "Probe Now", Some(&format!("gem:probe:{}", a.id)), Some("primary"), None),
            ctx.btn("shield", "Bind Proxy", Some(&format!("gem:px:{}", a.id)), None, None),
        ],
        vec![
            ctx.btn("key", "Rotate Key", Some(&format!("gem:key:{}", a.id)), None, None),
            ctx.btn("edit", "Set Email", Some(&format!("gem:em:{}", a.id)), None, None),
        ],
        vec![
            ctx.btn(
                if is_pinned { "optimizer" } else { "check" },
                if is_pinned { "Unpin (Auto)" } else { "Pin Account" },
                Some(&pin_cb),
                if is_pinned { Some("primary") } else { None },
                None,
            ),
            ctx.btn("refresh", "Reset Health", Some(&format!("gem:rst:{}", a.id)), None, None),
        ],
        vec![
            ctx.btn(
                if a.enabled { "stop" } else { "ok" },
                if a.enabled { "Pause" } else { "Enable" },
                Some(&format!("gem:tog:{}", a.id)),
                if a.enabled { None } else { Some("success") },
                None,
            ),
            ctx.btn("remove", "Delete", Some(&format!("gem:delc:{}", a.id)), Some("danger"), None),
        ],
        vec![ctx.btn("back", "Accounts Pool", Some("gem:accts"), None, None)],
    ];
    ctx.edit_or_send(cq, chat_id, &html, Some(BotCtx::kb(rows))).await;
}

async fn show_gemini_proxy_picker(
    ctx: &Arc<BotCtx>,
    chat_id: i64,
    cq: Option<&CallbackQuery>,
    acc_id: &str,
) {
    let pool = GeminiAccountPool::load_locked(&ctx.cfg.state_dir);
    let cur_pid = pool.get(acc_id).and_then(|a| a.proxy_id.clone());
    let proxies = ctx.proxies.list();
    let mut rows = vec![vec![ctx.btn(
        if cur_pid.is_none() { "check" } else { "cancel" },
        "Direct (No Proxy)",
        Some(&format!("gem:pxs:{acc_id}:direct")),
        if cur_pid.is_none() { Some("primary") } else { None },
        None,
    )]];
    for p in proxies.into_iter().filter(|p| p.enabled) {
        let active = cur_pid.as_deref() == Some(p.id.as_str());
        rows.push(vec![ctx.btn(
            if active { "check" } else { "shield" },
            &format!("{} ({})", p.display_name(), p.health.quality_score),
            Some(&format!("gem:pxs:{acc_id}:{}", p.id)),
            if active { Some("primary") } else { None },
            None,
        )]);
    }
    rows.push(vec![ctx.btn("back", "Account Detail", Some(&format!("gem:v:{acc_id}")), None, None)]);
    let html = format!(
        "{} <b>Bind Sticky Proxy for <code>{}</code></b>\n<i>Pick a managed proxy from your Proxy Registry:</i>",
        ctx.e("shield"),
        esc(acc_id)
    );
    ctx.edit_or_send(cq, chat_id, &html, Some(BotCtx::kb(rows))).await;
}

async fn show_gemini_gems(
    ctx: &Arc<BotCtx>,
    uid: i64,
    chat_id: i64,
    cq: Option<&CallbackQuery>,
) {
    let u = ctx.store.get_user(uid);
    let active = gemini_active_gem_id(&u);
    let store = GeminiGemStore::load(&ctx.cfg.state_dir);

    let mut lines = vec![
        format!("{} <b>Gems Studio (System Prompts + Knowledge Sources)</b>", ctx.e("gemini")),
        "<i>Portable across all accounts &amp; failovers. Attach local source files or bind a Web2API `gem-&lt;id&gt;`.</i>\n".to_string(),
    ];
    let mut rows = vec![vec![ctx.btn(
        if active.is_none() { "check" } else { "cancel" },
        "No Gem (Default)",
        Some("gem:guse:none"),
        if active.is_none() { Some("primary") } else { None },
        None,
    )]];

    for g in &store.gems {
        let is_act = active.as_deref() == Some(g.id.as_str());
        let mark = if is_act { format!("{} ", ctx.e("ok")) } else { String::new() };
        let remote = g
            .remote_gem_id
            .as_deref()
            .map(|r| format!(" · <code>{r}</code>"))
            .unwrap_or_default();
        lines.push(format!(
            "{mark}<b>{}</b> (<code>{}</code>) · {} {} files{remote}",
            esc(&g.name),
            esc(&g.id),
            ctx.e("file"),
            g.source_files.len(),
        ));
        rows.push(vec![
            ctx.btn(
                "skills",
                &g.name,
                Some(&format!("gem:gview:{}", g.id)),
                if is_act { Some("primary") } else { None },
                None,
            ),
            ctx.btn(
                if is_act { "check" } else { "bolt" },
                if is_act { "Active" } else { "Use" },
                Some(&format!("gem:guse:{}", g.id)),
                if is_act { Some("success") } else { None },
                None,
            ),
        ]);
    }

    rows.push(vec![ctx.btn("add", "Create New Gem", Some("gem:gnew"), Some("success"), None)]);
    rows.push(vec![ctx.btn("back", "Gemini Manager", Some("gem:home"), None, None)]);

    ctx.edit_or_send(cq, chat_id, &lines.join("\n"), Some(BotCtx::kb(rows))).await;
}

async fn show_gem_detail(
    ctx: &Arc<BotCtx>,
    uid: i64,
    chat_id: i64,
    cq: Option<&CallbackQuery>,
    gem_id: &str,
) {
    let store = GeminiGemStore::load(&ctx.cfg.state_dir);
    let Some(g) = store.get(gem_id) else {
        show_gemini_gems(ctx, uid, chat_id, cq).await;
        return;
    };
    let preview: String = g.system_prompt.chars().take(320).collect();
    let src_list = if g.source_files.is_empty() {
        "<i>None</i>".to_string()
    } else {
        g.source_files
            .iter()
            .map(|p| {
                let n = Path::new(p)
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or(p);
                format!("• <code>{}</code>", esc(n))
            })
            .collect::<Vec<_>>()
            .join("\n")
    };
    let html = format!(
        "{ic_gem} <b>Gem: {}</b> (<code>{}</code>)\n\n\
         <b>Instructions:</b>\n<pre>{}</pre>\n\
         <b>Knowledge Sources ({}):</b>\n{src_list}",
        esc(&g.name),
        esc(&g.id),
        esc(&preview),
        g.source_files.len(),
        ic_gem = ctx.e("gemini"),
    );
    let rows = vec![
        vec![
            ctx.btn("check", "Activate Gem", Some(&format!("gem:guse:{}", g.id)), Some("success"), None),
            ctx.btn("file", "Add Source", Some(&format!("gem:gsrc:{}", g.id)), Some("primary"), None),
        ],
        vec![
            ctx.btn("refresh", "Clear Sources", Some(&format!("gem:gclr:{}", g.id)), None, None),
            ctx.btn("remove", "Delete Gem", Some(&format!("gem:gdel:{}", g.id)), Some("danger"), None),
        ],
        vec![ctx.btn("back", "Gems Studio", Some("gem:gems"), None, None)],
    ];
    ctx.edit_or_send(cq, chat_id, &html, Some(BotCtx::kb(rows))).await;
}

async fn show_gemini_models(
    ctx: &Arc<BotCtx>,
    uid: i64,
    chat_id: i64,
    cq: Option<&CallbackQuery>,
) {
    let cur = gemini_selected_model(&ctx.store.get_user(uid)).unwrap_or_else(|| "auto".to_string());
    let pool = GeminiAccountPool::load_locked(&ctx.cfg.state_dir);
    let presets = [
        ("auto", "bolt", "Auto (Account Default)"),
        (DEFAULT_GEMINI_MODEL, "bolt", "gemini-2.5-flash (Free API)"),
        ("gemini-2.5-pro", "memory", "gemini-2.5-pro"),
        (DEFAULT_GEMINI_WEB_MODEL, "gemini", "gemini-4-hydrogen (Web)"),
        ("gemini-4-neon", "skills", "gemini-4-neon (Web Pro)"),
        ("gemini-4-carbon", "fire", "gemini-4-carbon (Web Pro)"),
        (DEFAULT_GEMINI_CANVAS_MODEL, "doc", "gemini-canvas (Web)"),
        (DEFAULT_GEMINI_IMAGE_MODEL, "image", "gemini-3.1-flash-image"),
    ];
    let mut seen = std::collections::HashSet::new();
    let mut rows = Vec::new();
    for (id, icon, label) in presets {
        seen.insert(id.to_string());
        let active = cur == id;
        rows.push(vec![ctx.btn(
            if active { "check" } else { icon },
            label,
            Some(&format!("gem:mset:{id}")),
            if active { Some("primary") } else { None },
            None,
        )]);
    }
    // Append live discovered models from probed accounts (capped cleanly for mobile keyboards).
    for m in pool.all_discovered_models().into_iter().filter(|m| m.len() <= 52).take(6) {
        if seen.insert(m.clone()) {
            let active = cur == m;
            rows.push(vec![ctx.btn(
                if active { "check" } else { "gemini" },
                &m,
                Some(&format!("gem:mset:{m}")),
                if active { Some("primary") } else { None },
                None,
            )]);
        }
    }
    rows.push(vec![ctx.btn("back", "Gemini Manager", Some("gem:home"), None, None)]);
    ctx.edit_or_send(
        cq,
        chat_id,
        &format!("{} <b>Gemini Models</b>\nCurrent: <code>{}</code>", ctx.e("model"), esc(&cur)),
        Some(BotCtx::kb(rows)),
    )
    .await;
}

/// Slash command `/webmodel` or `/gemini` or `/gems`.
pub async fn cmd_web_model(ctx: &Arc<BotCtx>, msg: &Message, sub: &str) {
    let Some(uid) = msg.from_user.as_ref().map(|u| u.id) else {
        return;
    };
    if !ctx.has_perm(uid, "uncensored") {
        let _ = ctx
            .render
            .send_html_simple(msg.chat.id, "⛔ Web Model permission required.", None)
            .await;
        return;
    }
    match sub.trim().to_ascii_lowercase().as_str() {
        "gemini" => show_gemini_home(ctx, uid, msg.chat.id, None).await,
        "gems" => show_gemini_gems(ctx, uid, msg.chat.id, None).await,
        "accounts" | "accts" => show_gemini_accounts(ctx, uid, msg.chat.id, None).await,
        _ => show_web_model_hub(ctx, uid, msg.chat.id, None).await,
    }
}

/// Handle `webmodel:*` and `gem:*` callbacks. Returns `true` if handled.
pub async fn handle_gemini_cb(
    ctx: &Arc<BotCtx>,
    cq: &CallbackQuery,
    uid: i64,
    chat_id: i64,
    data: &str,
) -> bool {
    if !data.starts_with("webmodel:") && !data.starts_with("gem:") {
        return false;
    }
    if !ctx.has_perm(uid, "uncensored") {
        ctx.ack(&cq.id, Some("Permission denied"), true).await;
        return true;
    }

    if data == "webmodel:home" {
        ctx.ack(&cq.id, None, false).await;
        show_web_model_hub(ctx, uid, chat_id, Some(cq)).await;
        return true;
    }
    if data == "gem:home" {
        ctx.ack(&cq.id, None, false).await;
        show_gemini_home(ctx, uid, chat_id, Some(cq)).await;
        return true;
    }
    if data == "gem:use" {
        let _ = ctx.store.update_user(uid, |u| {
            u.extra.insert(
                "engine".to_string(),
                serde_json::Value::String("gemini_web".to_string()),
            );
        });
        ctx.ack(&cq.id, Some("💎 Gemini Manager activated"), false)
            .await;
        show_gemini_home(ctx, uid, chat_id, Some(cq)).await;
        return true;
    }
    if let Some(m) = data.strip_prefix("gem:mode:") {
        let parsed = GeminiChatMode::parse(m);
        let _ = ctx.store.update_user(uid, |u| {
            u.extra.insert(
                "engine".to_string(),
                serde_json::Value::String("gemini_web".to_string()),
            );
            u.extra.insert(
                GEMINI_MODE_KEY.to_string(),
                serde_json::Value::String(parsed.as_str().to_string()),
            );
        });
        ctx.ack(&cq.id, Some(parsed.label()), false).await;
        show_gemini_home(ctx, uid, chat_id, Some(cq)).await;
        return true;
    }
    if data == "gem:3stage" {
        let cur = gemini_three_stage_mode(&ctx.store.get_user(uid));
        let next = match cur {
            ThreeStageMode::Auto => "always",
            ThreeStageMode::Always => "off",
            ThreeStageMode::Off => "auto",
        };
        let _ = ctx.store.update_user(uid, |u| {
            u.extra.insert(
                GEMINI_THREE_STAGE_KEY.to_string(),
                serde_json::Value::String(next.to_string()),
            );
        });
        ctx.ack(&cq.id, Some(&format!("3-Stage: {next}")), false)
            .await;
        show_gemini_home(ctx, uid, chat_id, Some(cq)).await;
        return true;
    }
    if data == "gem:clear" {
        let _ = clear_session_history(&ctx.cfg.state_dir, &gemini_session_key(uid));
        ctx.ack(&cq.id, Some("🗑 Gemini session cleared"), false)
            .await;
        show_gemini_home(ctx, uid, chat_id, Some(cq)).await;
        return true;
    }
    if data == "gem:models" {
        ctx.ack(&cq.id, None, false).await;
        show_gemini_models(ctx, uid, chat_id, Some(cq)).await;
        return true;
    }
    if let Some(m) = data.strip_prefix("gem:mset:") {
        let _ = ctx.store.update_user(uid, |u| {
            u.extra.insert(
                "engine".to_string(),
                serde_json::Value::String("gemini_web".to_string()),
            );
            if m == "auto" {
                u.extra.remove(GEMINI_MODEL_KEY);
            } else {
                u.extra.insert(
                    GEMINI_MODEL_KEY.to_string(),
                    serde_json::Value::String(m.to_string()),
                );
            }
        });
        ctx.ack(&cq.id, Some(&format!("Model: {m}")), false).await;
        show_gemini_home(ctx, uid, chat_id, Some(cq)).await;
        return true;
    }
    if data == "gem:accts" {
        ctx.ack(&cq.id, None, false).await;
        show_gemini_accounts(ctx, uid, chat_id, Some(cq)).await;
        return true;
    }
    if data == "gem:gems" {
        ctx.ack(&cq.id, None, false).await;
        show_gemini_gems(ctx, uid, chat_id, Some(cq)).await;
        return true;
    }
    if let Some(gid) = data.strip_prefix("gem:gview:") {
        ctx.ack(&cq.id, None, false).await;
        show_gem_detail(ctx, uid, chat_id, Some(cq), gid).await;
        return true;
    }
    if let Some(gid) = data.strip_prefix("gem:guse:") {
        let _ = ctx.store.update_user(uid, |u| {
            u.extra.insert(
                "engine".to_string(),
                serde_json::Value::String("gemini_web".to_string()),
            );
            if gid == "none" {
                u.extra.remove(GEMINI_GEM_KEY);
            } else {
                u.extra.insert(
                    GEMINI_GEM_KEY.to_string(),
                    serde_json::Value::String(gid.to_string()),
                );
            }
        });
        ctx.ack(&cq.id, Some("💎 Active Gem updated"), false).await;
        show_gemini_gems(ctx, uid, chat_id, Some(cq)).await;
        return true;
    }
    if data == "gem:gnew" {
        ctx.jobs
            .set_awaiting(uid, AwaitingInput::new("gem:gnew", serde_json::Value::Null));
        ctx.ack(&cq.id, None, false).await;
        let _ = ctx
            .render
            .send_html_simple(
                chat_id,
                "💎 Send new Gem as:\n<code>Name | System Prompt [| optional remote gem-id]</code>\n\n(Send /cancel to abort.)",
                None,
            )
            .await;
        return true;
    }
    if let Some(gid) = data.strip_prefix("gem:gsrc:") {
        ctx.jobs.set_awaiting(
            uid,
            AwaitingInput::new("gem:gsrc", serde_json::Value::String(gid.to_string())),
        );
        ctx.ack(&cq.id, None, false).await;
        let _ = ctx
            .render
            .send_html_simple(
                chat_id,
                &format!(
                    "📎 Attach knowledge source to Gem <code>{}</code>:\nSend an existing workspace file path (e.g. <code>/root/agy-workspace/spec.md</code>) OR paste raw knowledge text directly.\n\n(Send /cancel to abort.)",
                    esc(gid)
                ),
                None,
            )
            .await;
        return true;
    }
    if let Some(gid) = data.strip_prefix("gem:gclr:") {
        let _ = GeminiGemStore::mutate_locked(&ctx.cfg.state_dir, |store| {
            store.clear_sources(gid);
        });
        ctx.ack(&cq.id, Some("🧹 Sources cleared"), false).await;
        show_gem_detail(ctx, uid, chat_id, Some(cq), gid).await;
        return true;
    }
    if let Some(gid) = data.strip_prefix("gem:gdel:") {
        let _ = GeminiGemStore::mutate_locked(&ctx.cfg.state_dir, |store| {
            store.delete(gid);
        });
        let _ = ctx.store.update_user(uid, |u| {
            if u.extra.get(GEMINI_GEM_KEY).and_then(|v| v.as_str()) == Some(gid) {
                u.extra.remove(GEMINI_GEM_KEY);
            }
        });
        ctx.ack(&cq.id, Some("🗑 Gem deleted"), false).await;
        show_gemini_gems(ctx, uid, chat_id, Some(cq)).await;
        return true;
    }

    // Owner-only Account Pool mutations
    if !ctx.is_owner(uid) {
        ctx.ack(&cq.id, Some("Owner only"), true).await;
        return true;
    }
    if let Some(id) = data.strip_prefix("gem:v:") {
        ctx.ack(&cq.id, None, false).await;
        show_gemini_account_detail(ctx, uid, chat_id, Some(cq), id).await;
        return true;
    }
    if data == "gem:scan" {
        ctx.ack(&cq.id, Some("Scanning local sidecars & env..."), false).await;
        let found = discover_local_gemini_backends(&ctx.cfg.state_dir).await;
        let note = if found.is_empty() {
            format!(
                "{} <i>No local Gemini sidecars (<code>:8083</code> / <code>:8084</code>) or <code>GEMINI_API_KEY</code> detected.</i>",
                ctx.e("info")
            )
        } else {
            let items: Vec<String> = found
                .iter()
                .map(|(lbl, rep)| format!("• <b>{}</b> — {}", esc(lbl), esc(&rep.detail)))
                .collect();
            format!(
                "{} <b>Auto-Discovered {} backend(s):</b>\n{}",
                ctx.e("ok"),
                found.len(),
                items.join("\n")
            )
        };
        let _ = ctx.render.send_html_simple(chat_id, &note, None).await;
        show_gemini_accounts(ctx, uid, chat_id, Some(cq)).await;
        return true;
    }
    if data == "gem:probe_all" {
        ctx.ack(&cq.id, Some("Probing all accounts..."), false).await;
        let ids: Vec<String> = GeminiAccountPool::load_locked(&ctx.cfg.state_dir)
            .accounts
            .into_iter()
            .filter(|a| a.enabled)
            .map(|a| a.id)
            .collect();
        for id in ids {
            let _ = probe_and_record_account(&ctx.cfg.state_dir, &id).await;
        }
        show_gemini_accounts(ctx, uid, chat_id, Some(cq)).await;
        return true;
    }
    if let Some(id) = data.strip_prefix("gem:probe:") {
        ctx.ack(&cq.id, Some("Probing account..."), false).await;
        let _ = probe_and_record_account(&ctx.cfg.state_dir, id).await;
        show_gemini_account_detail(ctx, uid, chat_id, Some(cq), id).await;
        return true;
    }
    if let Some(id) = data.strip_prefix("gem:px:") {
        ctx.ack(&cq.id, None, false).await;
        show_gemini_proxy_picker(ctx, chat_id, Some(cq), id).await;
        return true;
    }
    if let Some(rest) = data.strip_prefix("gem:pxs:") {
        if let Some((acc_id, pid)) = rest.split_once(':') {
            let (proxy_id, proxy_url) = if pid == "direct" {
                (None, None)
            } else {
                let url = match ctx.proxies.resolve(Some(pid)) {
                    ResolvedProxy::Use { url, .. } => Some(url),
                    _ => ctx.proxies.get(pid).map(|e| e.url),
                };
                (Some(pid.to_string()), url)
            };
            let _ = GeminiAccountPool::mutate_locked(&ctx.cfg.state_dir, |pool| {
                pool.set_proxy_binding(acc_id, proxy_id, proxy_url);
            });
            ctx.ack(&cq.id, Some("Sticky proxy updated"), false).await;
            show_gemini_account_detail(ctx, uid, chat_id, Some(cq), acc_id).await;
            return true;
        }
    }
    if let Some(id) = data.strip_prefix("gem:key:") {
        ctx.jobs.set_awaiting(
            uid,
            AwaitingInput::new("gem:key", serde_json::Value::String(id.to_string())),
        );
        ctx.ack(&cq.id, None, false).await;
        let mk = BotCtx::kb(vec![vec![ctx.btn("cancel", "Cancel", Some("inp:cancel"), None, None)]]);
        let _ = ctx
            .render
            .send_html_simple(
                chat_id,
                &format!(
                    "{} <b>Rotate API Key for <code>{}</code></b>\nSend the new API key now — your message will be deleted immediately and live-probed.",
                    ctx.e("key"),
                    esc(id)
                ),
                Some(mk),
            )
            .await;
        return true;
    }
    if let Some(id) = data.strip_prefix("gem:em:") {
        ctx.jobs.set_awaiting(
            uid,
            AwaitingInput::new("gem:em", serde_json::Value::String(id.to_string())),
        );
        ctx.ack(&cq.id, None, false).await;
        let mk = BotCtx::kb(vec![vec![ctx.btn("cancel", "Cancel", Some("inp:cancel"), None, None)]]);
        let _ = ctx
            .render
            .send_html_simple(
                chat_id,
                &format!(
                    "{} <b>Set Email for <code>{}</code></b>\nSend email address (for Antigravity proxy sync &amp; collision checks), or send <code>clear</code> to remove.",
                    ctx.e("edit"),
                    esc(id)
                ),
                Some(mk),
            )
            .await;
        return true;
    }
    if let Some(id) = data.strip_prefix("gem:rst:") {
        let _ = GeminiAccountPool::mutate_locked(&ctx.cfg.state_dir, |pool| {
            pool.reset_cooldown(id);
        });
        ctx.ack(&cq.id, Some("Cooldown & health reset"), false).await;
        show_gemini_account_detail(ctx, uid, chat_id, Some(cq), id).await;
        return true;
    }
    if let Some(kind_s) = data.strip_prefix("gem:add:") {
        ctx.jobs.set_awaiting(
            uid,
            AwaitingInput::new("gem:add", serde_json::Value::String(kind_s.to_string())),
        );
        ctx.ack(&cq.id, None, false).await;
        let mk = BotCtx::kb(vec![vec![ctx.btn("cancel", "Cancel", Some("inp:cancel"), None, None)]]);
        let _ = ctx
            .render
            .send_html_simple(
                chat_id,
                &format!(
                    "{} <b>Smart Add Gemini Account</b>\n\
                     Paste any of the following (multi-line batch supported):\n\
                     • Raw Free Key: <code>AIza...</code>\n\
                     • Sidecar URL: <code>http://127.0.0.1:8083</code>\n\
                     • Full format: <code>Label | Key [| email | proxy]</code>\n\
                     • Custom URL: <code>Label | http://host:port/v1 | Key [| email]</code>\n\n\
                     <i>{} Your message is auto-deleted immediately and live-probed.</i>",
                    ctx.e("add"),
                    ctx.e("shield")
                ),
                Some(mk),
            )
            .await;
        return true;
    }
    if let Some(id) = data.strip_prefix("gem:pin:") {
        let msg = if id == "auto" {
            let _ = ctx.store.update_user(uid, |u| {
                u.extra.remove(GEMINI_PINNED_ACCT_KEY);
            });
            "Switched to Smart Balance (your session)".to_string()
        } else {
            let id_owned = id.to_string();
            let _ = ctx.store.update_user(uid, move |u| {
                u.extra.insert(
                    GEMINI_PINNED_ACCT_KEY.to_string(),
                    serde_json::Value::String(id_owned),
                );
            });
            format!("Pinned {id} for your session")
        };
        ctx.ack(&cq.id, Some(&msg), false).await;
        show_gemini_accounts(ctx, uid, chat_id, Some(cq)).await;
        return true;
    }
    if let Some(id) = data.strip_prefix("gem:tog:") {
        let en = GeminiAccountPool::mutate_locked(&ctx.cfg.state_dir, |pool| {
            pool.toggle(id).unwrap_or(false)
        })
        .unwrap_or(false);
        ctx.ack(&cq.id, Some(if en { "Enabled" } else { "Paused" }), false)
            .await;
        show_gemini_account_detail(ctx, uid, chat_id, Some(cq), id).await;
        return true;
    }
    if let Some(id) = data.strip_prefix("gem:delc:") {
        ctx.ack(&cq.id, None, false).await;
        let mk = BotCtx::kb(vec![vec![
            ctx.btn("remove", "Yes, delete", Some(&format!("gem:del:{id}")), Some("danger"), None),
            ctx.btn("cancel", "Cancel", Some(&format!("gem:v:{id}")), None, None),
        ]]);
        ctx.edit_or_send(
            Some(cq),
            chat_id,
            &format!("{} Delete Gemini account <code>{}</code>?", ctx.e("warn"), esc(id)),
            Some(mk),
        )
        .await;
        return true;
    }
    if let Some(id) = data.strip_prefix("gem:del:") {
        let _ = GeminiAccountPool::mutate_locked(&ctx.cfg.state_dir, |pool| {
            pool.remove(id);
        });
        ctx.ack(&cq.id, Some("Account removed"), false).await;
        show_gemini_accounts(ctx, uid, chat_id, Some(cq)).await;
        return true;
    }
    if data == "gem:sync_agy" {
        let entries: Vec<(String, Option<String>, Option<String>)> = ctx
            .jobs
            .accounts()
            .map(|s| {
                s.list()
                    .into_iter()
                    .map(|a| {
                        let sticky = match ctx.proxies.resolve(a.proxy_id.as_deref()) {
                            ResolvedProxy::Use { url, .. } => Some(url),
                            _ => None,
                        };
                        (a.label, a.email, sticky)
                    })
                    .collect()
            })
            .unwrap_or_default();
        let (synced, collisions) = GeminiAccountPool::mutate_locked(&ctx.cfg.state_dir, |pool| {
            pool.sync_proxies_from_antigravity(&entries)
        })
        .unwrap_or((0, Vec::new()));
        let note = if collisions.is_empty() {
            format!("Synced {synced} sticky proxies (0 email overlaps)")
        } else {
            format!(
                "Synced {synced} proxies · {} shared email(s) with AGY",
                collisions.len()
            )
        };
        ctx.ack(&cq.id, Some(&note), true).await;
        show_gemini_accounts(ctx, uid, chat_id, Some(cq)).await;
        return true;
    }

    true
}

/// Handle `awaiting_text` inputs for `gem:add`, `gem:key`, `gem:em`, `gem:gnew`, `gem:gsrc`. Returns `true` if handled.
pub async fn handle_gemini_awaiting_text(
    ctx: &Arc<BotCtx>,
    msg: &Message,
    uid: i64,
    chat_id: i64,
    inp: &AwaitingInput,
    raw_text: &str,
) -> bool {
    let text = raw_text.trim();
    match inp.kind.as_str() {
        "gem:add" => {
            // Immediately delete secret-bearing Telegram message so credentials never persist in chat history!
            let _ = ctx.client.delete_message(chat_id, msg.message_id).await;
            if !ctx.is_owner(uid) {
                return true;
            }
            let hint_kind = inp
                .data
                .as_str()
                .filter(|s| *s != "auto")
                .and_then(GeminiBackendKind::parse);
            let existing_count = GeminiAccountPool::load_locked(&ctx.cfg.state_dir)
                .accounts
                .len();
            let parsed = match parse_account_input_lines(text, hint_kind, existing_count) {
                Ok(v) => v,
                Err(err_msg) => {
                    // Re-arm awaiting input so a retry never leaks into AI chat!
                    ctx.jobs.set_awaiting(uid, inp.clone());
                    let mk = BotCtx::kb(vec![vec![ctx.btn("cancel", "Cancel", Some("inp:cancel"), None, None)]]);
                    let _ = ctx
                        .render
                        .send_html_simple(
                            chat_id,
                            &format!("{} {} (message deleted — try again or Cancel)", ctx.e("warn"), esc(&err_msg)),
                            Some(mk),
                        )
                        .await;
                    return true;
                }
            };

            let wait = ctx
                .render
                .send_html_simple(
                    chat_id,
                    &format!("{} Verifying {} account(s) via live /models probe...", ctx.e("work"), parsed.len()),
                    None,
                )
                .await
                .ok();

            let mut summary = Vec::new();
            let mut last_added_id: Option<String> = None;
            for mut acc in parsed {
                let is_dup = GeminiAccountPool::load_locked(&ctx.cfg.state_dir)
                    .find_duplicate(&acc.base_url, &acc.api_key)
                    .is_some();
                if is_dup {
                    summary.push(format!("• {} <b>{}</b> — skipped (duplicate)", ctx.e("info"), esc(&acc.label)));
                    continue;
                }
                let rep = probe_gemini_account(&acc).await;
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                acc.last_probe_epoch = now;
                acc.last_probe_ok = Some(rep.ok);
                if rep.ok {
                    acc.discovered_models = rep.models.clone();
                    acc.ewma_latency_ms = rep.latency_ms.max(1) as f64;
                    summary.push(format!(
                        "• {} <b>{}</b> (<code>{}</code>) — {}",
                        ctx.e("ok"),
                        esc(&acc.label),
                        esc(acc.kind.label()),
                        esc(&rep.detail)
                    ));
                } else {
                    acc.last_error = Some(rep.detail.clone());
                    summary.push(format!(
                        "• {} <b>{}</b> saved (probe warning: <code>{}</code>)",
                        ctx.e("warn"),
                        esc(&acc.label),
                        esc(&rep.detail)
                    ));
                }
                let aid = acc.id.clone();
                let _ = GeminiAccountPool::mutate_locked(&ctx.cfg.state_dir, |pool| {
                    pool.upsert(acc);
                });
                last_added_id = Some(aid);
            }

            if let Some(Some(m)) = wait {
                let _ = ctx.client.delete_message(chat_id, m.message_id).await;
            }
            let _ = ctx
                .render
                .send_html_simple(
                    chat_id,
                    &format!("{} <b>Onboarding Result</b> <i>(secret message deleted)</i>\n{}", ctx.e("shield"), summary.join("\n")),
                    None,
                )
                .await;
            if let Some(id) = last_added_id.filter(|_| summary.len() == 1) {
                show_gemini_account_detail(ctx, uid, chat_id, None, &id).await;
            } else {
                show_gemini_accounts(ctx, uid, chat_id, None).await;
            }
            true
        }
        "gem:key" => {
            let _ = ctx.client.delete_message(chat_id, msg.message_id).await;
            if !ctx.is_owner(uid) {
                return true;
            }
            let Some(acc_id) = inp.data.as_str() else {
                return true;
            };
            if text.len() < 6 {
                ctx.jobs.set_awaiting(uid, inp.clone());
                let mk = BotCtx::kb(vec![vec![ctx.btn("cancel", "Cancel", Some("inp:cancel"), None, None)]]);
                let _ = ctx
                    .render
                    .send_html_simple(chat_id, &format!("{} Key too short (try again or Cancel).", ctx.e("warn")), Some(mk))
                    .await;
                return true;
            }
            let _ = GeminiAccountPool::mutate_locked(&ctx.cfg.state_dir, |pool| {
                pool.rotate_key(acc_id, text.to_string());
            });
            let rep = probe_and_record_account(&ctx.cfg.state_dir, acc_id).await;
            let status = match rep {
                Some(r) if r.ok => format!("{} Key rotated & verified: {}", ctx.e("ok"), esc(&r.detail)),
                Some(r) => format!("{} Key rotated (probe failed: <code>{}</code>)", ctx.e("warn"), esc(&r.detail)),
                None => format!("{} Key rotated.", ctx.e("ok")),
            };
            let _ = ctx.render.send_html_simple(chat_id, &status, None).await;
            show_gemini_account_detail(ctx, uid, chat_id, None, acc_id).await;
            true
        }
        "gem:em" => {
            if !ctx.is_owner(uid) {
                return true;
            }
            let Some(acc_id) = inp.data.as_str() else {
                return true;
            };
            let new_em = if text.eq_ignore_ascii_case("clear") || text == "-" {
                None
            } else {
                Some(text.to_string())
            };
            let _ = GeminiAccountPool::mutate_locked(&ctx.cfg.state_dir, |pool| {
                pool.set_email(acc_id, new_em);
            });
            show_gemini_account_detail(ctx, uid, chat_id, None, acc_id).await;
            true
        }
        "gem:gnew" => {
            if !ctx.has_perm(uid, "uncensored") {
                let _ = ctx
                    .render
                    .send_html_simple(chat_id, "⛔ Permission denied.", None)
                    .await;
                return true;
            }
            let parts: Vec<&str> = text.split('|').map(str::trim).collect();
            if parts.len() < 2 || parts[0].is_empty() || parts[1].is_empty() {
                let _ = ctx
                    .render
                    .send_html_simple(
                        chat_id,
                        "⚠️ Expected: <code>Name | System Prompt [| optional remote gem-id]</code>",
                        None,
                    )
                    .await;
                return true;
            }
            let id = sanitize_slug(parts[0]);
            let id_for_gem = id.clone();
            let name_s = parts[0].to_string();
            let prompt_s = parts[1].to_string();
            let remote_s = parts.get(2).filter(|s| !s.is_empty()).map(|s| s.to_string());
            let _ = GeminiGemStore::mutate_locked(&ctx.cfg.state_dir, |store| {
                store.upsert(GeminiGem {
                    id: id_for_gem,
                    name: name_s,
                    system_prompt: prompt_s,
                    remote_gem_id: remote_s,
                    source_files: Vec::new(),
                    canvas_default: false,
                    updated_at: 0,
                });
            });
            let _ = ctx.store.update_user(uid, |u| {
                u.extra.insert(
                    GEMINI_GEM_KEY.to_string(),
                    serde_json::Value::String(id.clone()),
                );
            });
            show_gem_detail(ctx, uid, chat_id, None, &id).await;
            true
        }
        "gem:gsrc" => {
            if !ctx.has_perm(uid, "uncensored") {
                let _ = ctx
                    .render
                    .send_html_simple(chat_id, "⛔ Permission denied.", None)
                    .await;
                return true;
            }
            let Some(gid) = inp.data.as_str() else {
                return true;
            };
            let candidate = Path::new(text);
            let final_path = if candidate.is_file() {
                match validate_gem_source_path(
                    candidate,
                    &ctx.cfg.agy_workspace,
                    &ctx.cfg.state_dir,
                    ctx.has_perm(uid, "root_access"),
                ) {
                    Some(canon) => canon.to_string_lossy().to_string(),
                    None => {
                        let _ = ctx
                            .render
                            .send_html_simple(chat_id, "⛔ Path must be inside workspace.", None)
                            .await;
                        return true;
                    }
                }
            } else {
                let sdir = gemini_gem_sources_dir(&ctx.cfg.state_dir, gid);
                let _ = fs::create_dir_all(&sdir);
                let ts = agy_core::text::now_unix().max(0) as u64;
                let dst = sdir.join(format!("note_{ts}.md"));
                let _ = fs::write(&dst, text);
                dst.to_string_lossy().to_string()
            };
            let _ = GeminiGemStore::mutate_locked(&ctx.cfg.state_dir, |store| {
                store.attach_source(gid, &final_path);
            });
            show_gem_detail(ctx, uid, chat_id, None, gid).await;
            true
        }
        _ => false,
    }
}

/// Validate a file path attached as a Gem source. Non-root users are strictly
/// confined to canonical paths inside `workspace` or `<state_dir>/gemini_web/gem_sources`
/// (blocking `../../`, symlink escapes, and sensitive state files like `proxies.json`).
fn validate_gem_source_path(
    candidate: &Path,
    workspace: &Path,
    state_dir: &Path,
    allow_root: bool,
) -> Option<PathBuf> {
    let canon = fs::canonicalize(candidate).ok()?;
    if !canon.is_file() {
        return None;
    }
    if allow_root {
        return Some(canon);
    }
    let in_ws = fs::canonicalize(workspace)
        .ok()
        .is_some_and(|w| canon.starts_with(&w));
    let gem_sources_root = agy_ext::gemini_web::gemini_state_dir(state_dir).join("gem_sources");
    let in_gem_sources = fs::canonicalize(&gem_sources_root)
        .ok()
        .is_some_and(|s| canon.starts_with(&s));
    (in_ws || in_gem_sources).then_some(canon)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_state_helpers_parse_gemini_defaults_and_overrides() {
        let mut u = UserState::default();
        assert_eq!(gemini_chat_mode(&u), GeminiChatMode::Agent);
        assert_eq!(gemini_active_gem_id(&u), None);
        assert_eq!(gemini_selected_model(&u), None);
        assert_eq!(gemini_three_stage_mode(&u), ThreeStageMode::Auto);
        assert_eq!(gemini_session_key(42), "gemini_web_42");

        u.extra
            .insert(GEMINI_MODE_KEY.into(), serde_json::json!("canvas"));
        u.extra
            .insert(GEMINI_GEM_KEY.into(), serde_json::json!("rust-architect"));
        u.extra
            .insert(GEMINI_MODEL_KEY.into(), serde_json::json!("gemini-2.5-pro"));
        u.extra
            .insert(GEMINI_THREE_STAGE_KEY.into(), serde_json::json!("always"));

        assert_eq!(gemini_chat_mode(&u), GeminiChatMode::Canvas);
        assert_eq!(gemini_active_gem_id(&u).as_deref(), Some("rust-architect"));
        assert_eq!(gemini_selected_model(&u).as_deref(), Some("gemini-2.5-pro"));
        assert_eq!(gemini_three_stage_mode(&u), ThreeStageMode::Always);
    }

    #[test]
    fn validate_gem_source_path_blocks_traversal_for_non_root() {
        let td = tempfile::TempDir::new().unwrap();
        let ws = td.path().join("workspace");
        let st = td.path().join("state");
        let outside = td.path().join("secret.txt");
        let inside = ws.join("notes.md");
        let proxies_json = st.join("proxies.json");
        let gem_accounts = agy_ext::gemini_web::gemini_accounts_path(&st);
        let gem_note = gemini_gem_sources_dir(&st, "g1").join("note.md");
        fs::create_dir_all(&ws).unwrap();
        fs::create_dir_all(gem_note.parent().unwrap()).unwrap();
        fs::write(&outside, "secret").unwrap();
        fs::write(&inside, "hello").unwrap();
        fs::write(&proxies_json, "{\"proxies\":[]}").unwrap();
        fs::write(&gem_accounts, "{\"accounts\":[]}").unwrap();
        fs::write(&gem_note, "gem note").unwrap();

        let traversal = ws.join("..").join("secret.txt");
        // Non-root: traversal outside workspace MUST be rejected
        assert!(validate_gem_source_path(&traversal, &ws, &st, false).is_none());
        // Non-root: sensitive files in state_dir (proxies.json, gemini accounts.json) MUST be rejected
        assert!(validate_gem_source_path(&proxies_json, &ws, &st, false).is_none());
        assert!(validate_gem_source_path(&gem_accounts, &ws, &st, false).is_none());
        // Non-root: legitimate workspace file and gem_sources note succeed
        assert!(validate_gem_source_path(&inside, &ws, &st, false).is_some());
        assert!(validate_gem_source_path(&gem_note, &ws, &st, false).is_some());
        // Root user: allowed
        assert!(validate_gem_source_path(&traversal, &ws, &st, true).is_some());
    }
}
