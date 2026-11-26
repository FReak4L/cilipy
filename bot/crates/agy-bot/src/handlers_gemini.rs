//! Handlers for the unified `🌐 Web Model` hub (`🔥 Venice` + `💎 Gemini Manager`),
//! including Antigravity-style Gemini Account Pool, Gems Studio (with local source files),
//! Canvas mode, Image Create mode, and OpenHands 35-tool Agent mode.

use std::fs;
use std::path::Path;
use std::sync::Arc;

use agy_core::proxies::ResolvedProxy;
use agy_core::store::UserState;
use agy_core::tg::{CallbackQuery, InlineKeyboardButton, InlineKeyboardMarkup, Message};
use agy_ext::agent_runtime::{clear_session_history, ThreeStageMode};
use agy_ext::gemini_web::{
    gemini_gem_sources_dir, sanitize_slug, GeminiAccount, GeminiAccountPool, GeminiBackendKind,
    GeminiChatMode, GeminiGem, GeminiGemStore, DEFAULT_AISTUDIO_SIDECAR_BASE,
    DEFAULT_GEMINI_CANVAS_MODEL, DEFAULT_GEMINI_IMAGE_MODEL, DEFAULT_GEMINI_MODEL,
    DEFAULT_GEMINI_WEB_MODEL, DEFAULT_WEB2API_BASE, OFFICIAL_GEMINI_OPENAI_BASE,
};
use agy_render::esc;

use crate::ctx::BotCtx;
use crate::jobs::AwaitingInput;

pub const GEMINI_MODE_KEY: &str = "gemini_mode";
pub const GEMINI_GEM_KEY: &str = "gemini_gem_id";
pub const GEMINI_MODEL_KEY: &str = "gemini_model";
pub const GEMINI_THREE_STAGE_KEY: &str = "gemini_three_stage";

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

fn btn(text: impl Into<String>, data: impl Into<String>) -> InlineKeyboardButton {
    InlineKeyboardButton::callback(text, data)
}

/// Render the unified `🌐 Web Model` hub (`🔥 Venice` + `💎 Gemini Manager`).
pub async fn show_web_model_hub(
    ctx: &Arc<BotCtx>,
    uid: i64,
    chat_id: i64,
    cq: Option<&CallbackQuery>,
) {
    let u = ctx.store.get_user(uid);
    let eng = u.extra.get("engine").and_then(|v| v.as_str()).unwrap_or("agy");
    let pool = GeminiAccountPool::load(&ctx.cfg.state_dir);
    let gems = GeminiGemStore::load(&ctx.cfg.state_dir);
    let g_mode = gemini_chat_mode(&u);
    let active_tag = match eng {
        "uncensored" => "🔥 Venice Uncensored",
        "gemini_web" => "💎 Gemini Manager",
        _ => "Antigravity (default)",
    };

    let html = format!(
        "<b>🌐 Web Model Hub</b>\n\n\
         Active engine: <code>{active_tag}</code>\n\
         • <b>🔥 Venice</b>: Uncensored OpenHands Agent / Chat\n\
         • <b>💎 Gemini Manager</b>: <code>{}</code> accs · <code>{}</code> Gems · Mode: <code>{}</code>\n\n\
         <i>Choose a provider below:</i>",
        pool.accounts.len(),
        gems.gems.len(),
        esc(g_mode.label())
    );
    let markup = InlineKeyboardMarkup {
        inline_keyboard: vec![
            vec![
                btn("🔥 Venice", "umodels:0"),
                btn("💎 Gemini Manager", "gem:home"),
            ],
            vec![btn("⬅️ Home", "home:0")],
        ],
    };
    ctx.edit_or_send(cq, chat_id, &html, Some(markup)).await;
}

/// Render the `💎 Gemini Manager` main dashboard.
pub async fn show_gemini_home(
    ctx: &Arc<BotCtx>,
    uid: i64,
    chat_id: i64,
    cq: Option<&CallbackQuery>,
) {
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
            "\n⚠️ <b>Anti-Ban Notice:</b> Web sidecar email(s) overlap Antigravity: <code>{}</code>. Keep concurrency=1 &amp; sticky proxy.",
            esc(&collisions.join(", "))
        )
    };

    let status_badge = if is_active { "✅ ACTIVE" } else { "⚪ inactive" };
    let ts_label = match ts {
        ThreeStageMode::Auto => "Auto",
        ThreeStageMode::Always => "Always",
        ThreeStageMode::Off => "Off",
    };

    let html = format!(
        "<b>💎 Gemini Manager</b> ({status_badge})\n\n\
         <b>Mode:</b> <code>{}</code>\n\
         <b>Model:</b> <code>{}</code>\n\
         <b>Active Gem:</b> {active_gem_line}\n\
         <b>Accounts Pool:</b> <code>{}</code> configured (CONCURRENCY=1, Sticky Proxy)\n\
         <b>3-Stage Coding:</b> <code>{ts_label}</code>{warn_block}",
        esc(mode.label()),
        esc(&model),
        pool.accounts.len(),
    );

    let rows = vec![
        vec![
            btn(
                if mode == GeminiChatMode::Agent { "✅ 🤖 Agent" } else { "🤖 Agent" },
                "gem:mode:agent",
            ),
            btn(
                if mode == GeminiChatMode::Canvas { "✅ 📝 Canvas" } else { "📝 Canvas" },
                "gem:mode:canvas",
            ),
        ],
        vec![
            btn(
                if mode == GeminiChatMode::Image { "✅ 🖼 Image" } else { "🖼 Image" },
                "gem:mode:image",
            ),
            btn(
                if mode == GeminiChatMode::Chat { "✅ 💬 Chat" } else { "💬 Chat" },
                "gem:mode:chat",
            ),
        ],
        vec![
            btn(
                if is_active { "💎 Active (Gemini)" } else { "✅ Activate Gemini" },
                "gem:use",
            ),
            btn(format!("🧠 3-Stage: {ts_label}"), "gem:3stage"),
        ],
        vec![
            btn(format!("👤 Accounts ({})", pool.accounts.len()), "gem:accts"),
            btn(format!("💎 Gems Studio ({})", gems.gems.len()), "gem:gems"),
        ],
        vec![
            btn("🤖 Models", "gem:models"),
            btn("🗑 Clear Chat", "gem:clear"),
        ],
        vec![
            btn("⬅️ Web Model", "webmodel:home"),
            btn("🏠 Home", "home:0"),
        ],
    ];
    ctx.edit_or_send(
        cq,
        chat_id,
        &html,
        Some(InlineKeyboardMarkup {
            inline_keyboard: rows,
        }),
    )
    .await;
}

async fn show_gemini_accounts(
    ctx: &Arc<BotCtx>,
    uid: i64,
    chat_id: i64,
    cq: Option<&CallbackQuery>,
) {
    let pool = GeminiAccountPool::load(&ctx.cfg.state_dir);
    let is_owner = ctx.is_owner(uid);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let mut lines = vec![
        "<b>👤 Gemini Accounts Pool</b>".to_string(),
        "<i>Anti-ban: CONCURRENCY=1 · Sticky Proxy · Exponential Cooldown (2m→10m)</i>\n"
            .to_string(),
    ];
    let mut rows = Vec::new();
    if pool.accounts.is_empty() {
        lines.push("No accounts configured yet. Add a Free AI Studio Key (0% ban risk) or a local Web2API / AIStudio2API sidecar.".to_string());
    } else {
        for a in &pool.accounts {
            let st = if !a.enabled {
                "⛔"
            } else if a.is_cooled_down(now) {
                "⏳"
            } else {
                "✅"
            };
            let pin = if pool.active_account_id.as_deref() == Some(a.id.as_str()) {
                " 📌"
            } else {
                ""
            };
            let proxy_s = if a.proxy_url.is_some() { "🛡proxy" } else { "direct" };
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
            lines.push(format!(
                "{st} <b>{}</b>{pin} · <code>{}</code> · <code>{}</code> · {proxy_s} · {h_pct}%{lat_s}{cd}",
                esc(&a.label),
                esc(a.kind.label()),
                esc(&a.masked_key()),
            ));
            if is_owner {
                rows.push(vec![
                    btn(format!("📌 {}", a.id), format!("gem:pin:{}", a.id)),
                    btn("⏯", format!("gem:tog:{}", a.id)),
                    btn("🗑", format!("gem:del:{}", a.id)),
                ]);
            }
        }
    }

    if is_owner {
        if pool.active_account_id.is_some() {
            rows.push(vec![btn("⚖️ Auto Smart Balance (Unpin)", "gem:pin:auto")]);
        }
        rows.push(vec![
            btn("➕ Free AI Studio Key", "gem:add:official"),
            btn("➕ Web2API Sidecar", "gem:add:web"),
        ]);
        rows.push(vec![
            btn("➕ AIStudio2API", "gem:add:aistudio"),
            btn("🔗 Sync Proxies (AGY)", "gem:sync_agy"),
        ]);
    }
    rows.push(vec![btn("⬅️ Gemini Manager", "gem:home")]);

    ctx.edit_or_send(
        cq,
        chat_id,
        &lines.join("\n"),
        Some(InlineKeyboardMarkup {
            inline_keyboard: rows,
        }),
    )
    .await;
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
        "<b>💎 Gems Studio (System Prompts + Knowledge Sources)</b>".to_string(),
        "<i>Portable across all accounts &amp; failovers. Attach local source files or bind a Web2API `gem-&lt;id&gt;`.</i>\n".to_string(),
    ];
    let mut rows = vec![vec![btn(
        if active.is_none() {
            "✅ 🚫 No Gem (Default)"
        } else {
            "🚫 No Gem (Default)"
        },
        "gem:guse:none",
    )]];

    for g in &store.gems {
        let mark = if active.as_deref() == Some(g.id.as_str()) {
            "✅ "
        } else {
            ""
        };
        let remote = g
            .remote_gem_id
            .as_deref()
            .map(|r| format!(" · <code>{r}</code>"))
            .unwrap_or_default();
        lines.push(format!(
            "{mark}<b>{}</b> (<code>{}</code>) · 📎 {} files{remote}",
            esc(&g.name),
            esc(&g.id),
            g.source_files.len(),
        ));
        rows.push(vec![
            btn(format!("{mark}💎 {}", g.name), format!("gem:gview:{}", g.id)),
            btn("Use", format!("gem:guse:{}", g.id)),
        ]);
    }

    rows.push(vec![btn("➕ Create New Gem", "gem:gnew")]);
    rows.push(vec![btn("⬅️ Gemini Manager", "gem:home")]);

    ctx.edit_or_send(
        cq,
        chat_id,
        &lines.join("\n"),
        Some(InlineKeyboardMarkup {
            inline_keyboard: rows,
        }),
    )
    .await;
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
        "<b>💎 Gem: {}</b> (<code>{}</code>)\n\n\
         <b>Instructions:</b>\n<pre>{}</pre>\n\
         <b>Knowledge Sources ({}):</b>\n{src_list}",
        esc(&g.name),
        esc(&g.id),
        esc(&preview),
        g.source_files.len(),
    );
    let rows = vec![
        vec![
            btn("✅ Activate Gem", format!("gem:guse:{}", g.id)),
            btn("📎 Add Source", format!("gem:gsrc:{}", g.id)),
        ],
        vec![
            btn("🧹 Clear Sources", format!("gem:gclr:{}", g.id)),
            btn("🗑 Delete Gem", format!("gem:gdel:{}", g.id)),
        ],
        vec![btn("⬅️ Gems Studio", "gem:gems")],
    ];
    ctx.edit_or_send(
        cq,
        chat_id,
        &html,
        Some(InlineKeyboardMarkup {
            inline_keyboard: rows,
        }),
    )
    .await;
}

async fn show_gemini_models(
    ctx: &Arc<BotCtx>,
    uid: i64,
    chat_id: i64,
    cq: Option<&CallbackQuery>,
) {
    let cur = gemini_selected_model(&ctx.store.get_user(uid)).unwrap_or_else(|| "auto".to_string());
    let presets = [
        ("auto", "⚡ Auto (Account Default)"),
        (DEFAULT_GEMINI_MODEL, "⚡ gemini-2.5-flash (Free API)"),
        ("gemini-2.5-pro", "🧠 gemini-2.5-pro"),
        (DEFAULT_GEMINI_WEB_MODEL, "💧 gemini-4-hydrogen (Web)"),
        ("gemini-4-neon", "🔮 gemini-4-neon (Web Pro)"),
        ("gemini-4-carbon", "🔥 gemini-4-carbon (Web Pro)"),
        (DEFAULT_GEMINI_CANVAS_MODEL, "📝 gemini-canvas (Web)"),
        (DEFAULT_GEMINI_IMAGE_MODEL, "🖼 gemini-3.1-flash-image"),
    ];
    let mut rows = Vec::new();
    for (id, label) in presets {
        let mark = if cur == id { "✅ " } else { "" };
        rows.push(vec![btn(format!("{mark}{label}"), format!("gem:mset:{id}"))]);
    }
    rows.push(vec![btn("⬅️ Gemini Manager", "gem:home")]);
    ctx.edit_or_send(
        cq,
        chat_id,
        &format!("<b>🤖 Gemini Models</b>\nCurrent: <code>{}</code>", esc(&cur)),
        Some(InlineKeyboardMarkup {
            inline_keyboard: rows,
        }),
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
        let mut store = GeminiGemStore::load(&ctx.cfg.state_dir);
        store.clear_sources(gid);
        let _ = store.save(&ctx.cfg.state_dir);
        ctx.ack(&cq.id, Some("🧹 Sources cleared"), false).await;
        show_gem_detail(ctx, uid, chat_id, Some(cq), gid).await;
        return true;
    }
    if let Some(gid) = data.strip_prefix("gem:gdel:") {
        let mut store = GeminiGemStore::load(&ctx.cfg.state_dir);
        store.delete(gid);
        let _ = store.save(&ctx.cfg.state_dir);
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
    if let Some(kind_s) = data.strip_prefix("gem:add:") {
        ctx.jobs.set_awaiting(
            uid,
            AwaitingInput::new("gem:add", serde_json::Value::String(kind_s.to_string())),
        );
        ctx.ack(&cq.id, None, false).await;
        let hint = match kind_s {
            "official" => "<code>Label | AIza...API_KEY [| email]</code>",
            "web" => "<code>Label | http://127.0.0.1:8083/v1 | PROXY_API_KEY [| email | socks5://...]</code>",
            _ => "<code>Label | http://127.0.0.1:8084/v1 | PROXY_API_KEY [| email | socks5://...]</code>",
        };
        let _ = ctx
            .render
            .send_html_simple(
                chat_id,
                &format!("➕ Add Gemini Account ({kind_s}):\n{hint}\n\n(Send /cancel to abort.)"),
                None,
            )
            .await;
        return true;
    }
    if let Some(id) = data.strip_prefix("gem:pin:") {
        let mut pool = GeminiAccountPool::load(&ctx.cfg.state_dir);
        let msg = if id == "auto" {
            pool.active_account_id = None;
            "⚖️ Switched to Smart Balance".to_string()
        } else {
            pool.active_account_id = Some(id.to_string());
            format!("📌 Pinned {id}")
        };
        let _ = pool.save(&ctx.cfg.state_dir);
        ctx.ack(&cq.id, Some(&msg), false).await;
        show_gemini_accounts(ctx, uid, chat_id, Some(cq)).await;
        return true;
    }
    if let Some(id) = data.strip_prefix("gem:tog:") {
        let mut pool = GeminiAccountPool::load(&ctx.cfg.state_dir);
        let en = pool.toggle(id).unwrap_or(false);
        let _ = pool.save(&ctx.cfg.state_dir);
        ctx.ack(&cq.id, Some(if en { "Enabled" } else { "Disabled" }), false)
            .await;
        show_gemini_accounts(ctx, uid, chat_id, Some(cq)).await;
        return true;
    }
    if let Some(id) = data.strip_prefix("gem:del:") {
        let mut pool = GeminiAccountPool::load(&ctx.cfg.state_dir);
        pool.remove(id);
        let _ = pool.save(&ctx.cfg.state_dir);
        ctx.ack(&cq.id, Some("🗑 Account removed"), false).await;
        show_gemini_accounts(ctx, uid, chat_id, Some(cq)).await;
        return true;
    }
    if data == "gem:sync_agy" {
        let mut pool = GeminiAccountPool::load(&ctx.cfg.state_dir);
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
        let (synced, collisions) = pool.sync_proxies_from_antigravity(&entries);
        let _ = pool.save(&ctx.cfg.state_dir);
        let note = if collisions.is_empty() {
            format!("🔗 Synced {synced} sticky proxies (0 email overlaps)")
        } else {
            format!(
                "🔗 Synced {synced} proxies · ⚠️ {} shared email(s) with AGY",
                collisions.len()
            )
        };
        ctx.ack(&cq.id, Some(&note), true).await;
        show_gemini_accounts(ctx, uid, chat_id, Some(cq)).await;
        return true;
    }

    true
}

/// Handle `awaiting_text` inputs for `gem:add`, `gem:gnew`, `gem:gsrc`. Returns `true` if handled.
pub async fn handle_gemini_awaiting_text(
    ctx: &Arc<BotCtx>,
    uid: i64,
    chat_id: i64,
    inp: &AwaitingInput,
    raw_text: &str,
) -> bool {
    let text = raw_text.trim();
    match inp.kind.as_str() {
        "gem:add" => {
            if !ctx.is_owner(uid) {
                return true;
            }
            let kind = inp
                .data
                .as_str()
                .and_then(GeminiBackendKind::parse)
                .unwrap_or(GeminiBackendKind::OfficialFreeKey);
            let parts: Vec<&str> = text.split('|').map(str::trim).collect();
            let (label, base_url, api_key, email, proxy_url) = match kind {
                GeminiBackendKind::OfficialFreeKey => {
                    if parts.len() < 2 {
                        let _ = ctx
                            .render
                            .send_html_simple(
                                chat_id,
                                "⚠️ Expected: <code>Label | API_KEY [| email]</code>",
                                None,
                            )
                            .await;
                        return true;
                    }
                    (
                        parts[0].to_string(),
                        OFFICIAL_GEMINI_OPENAI_BASE.to_string(),
                        parts[1].to_string(),
                        parts.get(2).filter(|s| !s.is_empty()).map(|s| s.to_string()),
                        parts.get(3).filter(|s| !s.is_empty()).map(|s| s.to_string()),
                    )
                }
                GeminiBackendKind::Web2ApiSidecar | GeminiBackendKind::AiStudioSidecar => {
                    let def_base = if kind == GeminiBackendKind::Web2ApiSidecar {
                        DEFAULT_WEB2API_BASE
                    } else {
                        DEFAULT_AISTUDIO_SIDECAR_BASE
                    };
                    if parts.len() < 2 {
                        let _ = ctx
                            .render
                            .send_html_simple(
                                chat_id,
                                "⚠️ Expected: <code>Label | base_url | API_KEY [| email | proxy_url]</code>",
                                None,
                            )
                            .await;
                        return true;
                    }
                    let (b, k, em, px) = if parts.len() == 2 {
                        (def_base.to_string(), parts[1].to_string(), None, None)
                    } else {
                        (
                            parts[1].to_string(),
                            parts[2].to_string(),
                            parts.get(3).filter(|s| !s.is_empty()).map(|s| s.to_string()),
                            parts.get(4).filter(|s| !s.is_empty()).map(|s| s.to_string()),
                        )
                    };
                    (parts[0].to_string(), b, k, em, px)
                }
            };
            if let Err(err_msg) = GeminiAccountPool::validate_account_urls(&base_url, proxy_url.as_deref()) {
                let _ = ctx
                    .render
                    .send_html_simple(chat_id, &format!("⚠️ {}", esc(&err_msg)), None)
                    .await;
                return true;
            }
            let mut pool = GeminiAccountPool::load(&ctx.cfg.state_dir);
            let id = sanitize_slug(&label);
            pool.upsert(GeminiAccount {
                id: id.clone(),
                label: label.clone(),
                email,
                kind,
                base_url,
                api_key,
                proxy_url,
                enabled: true,
                cooldown_until_epoch: 0,
                consecutive_failures: 0,
                last_used_epoch: 0,
                last_error: None,
                ewma_latency_ms: 0.0,
                ewma_error_rate: 0.0,
                success_count: 0,
                failure_count: 0,
            });
            let _ = pool.save(&ctx.cfg.state_dir);
            let _ = ctx
                .render
                .send_html_simple(
                    chat_id,
                    &format!("✅ Added Gemini account <b>{}</b> (<code>{}</code>).", esc(&label), esc(&id)),
                    None,
                )
                .await;
            show_gemini_accounts(ctx, uid, chat_id, None).await;
            true
        }
        "gem:gnew" => {
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
            let mut store = GeminiGemStore::load(&ctx.cfg.state_dir);
            store.upsert(GeminiGem {
                id: id.clone(),
                name: parts[0].to_string(),
                system_prompt: parts[1].to_string(),
                remote_gem_id: parts.get(2).filter(|s| !s.is_empty()).map(|s| s.to_string()),
                source_files: Vec::new(),
                canvas_default: false,
                updated_at: 0,
            });
            let _ = store.save(&ctx.cfg.state_dir);
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
            let Some(gid) = inp.data.as_str() else {
                return true;
            };
            let mut store = GeminiGemStore::load(&ctx.cfg.state_dir);
            let candidate = Path::new(text);
            let final_path = if candidate.is_file() {
                let ws_ok = candidate.starts_with(&ctx.cfg.agy_workspace)
                    || candidate.starts_with(&ctx.cfg.state_dir)
                    || ctx.has_perm(uid, "root_access");
                if !ws_ok {
                    let _ = ctx
                        .render
                        .send_html_simple(chat_id, "⛔ Path must be inside workspace.", None)
                        .await;
                    return true;
                }
                text.to_string()
            } else {
                let sdir = gemini_gem_sources_dir(&ctx.cfg.state_dir, gid);
                let _ = fs::create_dir_all(&sdir);
                let ts = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let dst = sdir.join(format!("note_{ts}.md"));
                let _ = fs::write(&dst, text);
                dst.to_string_lossy().to_string()
            };
            store.attach_source(gid, &final_path);
            let _ = store.save(&ctx.cfg.state_dir);
            show_gem_detail(ctx, uid, chat_id, None, gid).await;
            true
        }
        _ => false,
    }
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
}
