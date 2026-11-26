//! Handlers for Venice Uncensored autonomous agent, chat mode, and model picker.

use std::sync::Arc;

use agy_core::store::UserState;
use agy_core::tg::{CallbackQuery, InlineKeyboardButton, Message};
use agy_ext::agent_runtime::{agent_tool_count, clear_session_history, session_message_count};
use agy_ext::uncensored::{
    clear_custom_sysprompt, ensure_uncensored_models, is_uncensored_model, load_custom_sysprompt,
    refresh_uncensored_models, save_custom_sysprompt, ThreeStageMode, UncensoredModel,
    MAX_CUSTOM_SYSPROMPT_BYTES,
};
use agy_render::esc;
use serde_json::json;
use tracing::info;

use crate::ctx::BotCtx;
use crate::i18n::{missing_perm_html, perm_label, t, Tx};
use crate::jobs::model_pick::MODEL_INVALID_KEY;
use crate::jobs::{AwaitingInput, JobOverride, JobRequest};

const MODELS_PER_PAGE: usize = 6;
pub const UNCENSORED_AGENT_MODE_KEY: &str = "uncensored_agent_mode";
pub const UNCENSORED_THREE_STAGE_KEY: &str = "uncensored_three_stage";

fn truncate_chars(s: &str, max_chars: usize) -> String {
    let count = s.chars().count();
    if count <= max_chars {
        s.to_string()
    } else {
        s.chars().take(max_chars).collect()
    }
}

/// Whether Venice Uncensored runs as a full autonomous Agent (default `true`) or direct Chat (`false`).
pub fn uncensored_agent_mode(u: &UserState) -> bool {
    u.extra
        .get(UNCENSORED_AGENT_MODE_KEY)
        .and_then(|v| v.as_bool())
        .unwrap_or(true)
}

/// Persistent per-user 3-Stage background memory + SkillHub + chunked codegen mode (`Auto` default).
pub fn uncensored_three_stage_mode(u: &UserState) -> ThreeStageMode {
    match u
        .extra
        .get(UNCENSORED_THREE_STAGE_KEY)
        .and_then(|v| v.as_str())
        .unwrap_or("auto")
        .to_ascii_lowercase()
        .as_str()
    {
        "always" | "on" | "true" => ThreeStageMode::Always,
        "off" | "false" | "0" => ThreeStageMode::Off,
        _ => ThreeStageMode::Auto,
    }
}

fn three_stage_btn_label(mode: ThreeStageMode) -> &'static str {
    match mode {
        ThreeStageMode::Auto => "🧠 3-Stage: AUTO",
        ThreeStageMode::Always => "🧠 3-Stage: ON",
        ThreeStageMode::Off => "🧠 3-Stage: OFF",
    }
}

fn three_stage_badge(mode: ThreeStageMode) -> &'static str {
    match mode {
        ThreeStageMode::Auto => "AUTO",
        ThreeStageMode::Always => "ON",
        ThreeStageMode::Off => "OFF",
    }
}

fn next_three_stage_choice(mode: ThreeStageMode) -> (&'static str, &'static str) {
    match mode {
        ThreeStageMode::Auto => ("always", "3-Stage Memory & Chunk Mode: ALWAYS ON"),
        ThreeStageMode::Always => ("off", "3-Stage Memory & Chunk Mode: OFF"),
        ThreeStageMode::Off => ("auto", "3-Stage Memory & Chunk Mode: AUTO (large repos/zips)"),
    }
}

/// Session history key for Venice Uncensored per user.
pub fn uncensored_session_key(uid: i64) -> String {
    format!("uncensored_{uid}")
}

fn format_ctx_badge(ctx_len: Option<u64>) -> String {
    match ctx_len {
        Some(n) if n >= 1_000_000 => format!(" · {}M", n / 1_000_000),
        Some(n) if n >= 1_000 => format!(" · {}K", n / 1_000),
        _ => String::new(),
    }
}

fn clean_btn_model_name(m: &UncensoredModel) -> String {
    let raw = m
        .name
        .trim_start_matches("veniceai/")
        .trim_start_matches("venice-web/")
        .trim_start_matches("ven/")
        .replace(" Uncensored", "");
    format!("{}{}", truncate_chars(&raw, 20), format_ctx_badge(m.context_length))
}

/// Render or edit the paginated Uncensored Agent & model picker (`umodels:{page}`).
pub async fn show_uncensored_models(
    ctx: &Arc<BotCtx>,
    cq: Option<&CallbackQuery>,
    chat_id: i64,
    uid: i64,
    page: usize,
) {
    let u = ctx.store.get_user(uid);
    let ms = ensure_uncensored_models(
        &ctx.cfg.state_dir,
        &ctx.cfg.venice_api_base,
        &ctx.cfg.venice_api_key,
    )
    .await;

    let pages = ms.len().div_ceil(MODELS_PER_PAGE).max(1);
    let page = page.min(pages - 1);

    let is_uncensored_active = u.extra.get("engine").and_then(|v| v.as_str()) == Some("uncensored")
        || u.model.as_deref().is_some_and(is_uncensored_model);
    let agent_on = uncensored_agent_mode(&u);
    let stage3_mode = uncensored_three_stage_mode(&u);
    let sess_key = uncensored_session_key(uid);
    let sess_msgs = session_message_count(&ctx.cfg.state_dir, &sess_key);

    let tool_cnt = agent_tool_count(
        ctx.has_perm(uid, "root_access"),
        ctx.has_perm(uid, "sandbox_exec"),
    );
    let mode_lbl = if agent_on {
        format!("🤖 Agent ({tool_cnt})")
    } else {
        "💬 Chat".to_string()
    };
    let mode_style = if agent_on { Some("primary") } else { None };
    let clear_lbl = if sess_msgs > 0 {
        format!("🧹 Clear ({sess_msgs})")
    } else {
        "🧹 Clear".to_string()
    };

    let agy_lbl = if is_uncensored_active {
        "↩️ AGY Default"
    } else {
        "✅ AGY Default"
    };
    let custom_sys = load_custom_sysprompt(&ctx.cfg.state_dir, uid);
    let sys_lbl = match custom_sys.as_ref() {
        Some(s) => format!("📝 Sys ({:.1}K)", (s.len() as f64) / 1024.0),
        None => "📝 System".to_string(),
    };
    let stage3_btn = ctx.btn(
        "",
        three_stage_btn_label(stage3_mode),
        Some("umodel:stage3_tog"),
        if stage3_mode == ThreeStageMode::Always {
            Some("primary")
        } else {
            None
        },
        None,
    );
    let sys_row = if custom_sys.is_some() {
        vec![
            stage3_btn,
            ctx.btn("", &sys_lbl, Some("umodel:sys"), Some("primary"), None),
            ctx.btn("", "🗑 Clear Sys", Some("umodel:sys_clear"), None, None),
        ]
    } else {
        vec![stage3_btn, ctx.btn("", &sys_lbl, Some("umodel:sys"), None, None)]
    };
    let mut rows: Vec<Vec<InlineKeyboardButton>> = vec![
        vec![
            ctx.btn("", &mode_lbl, Some("umodel:agent_tog"), mode_style, None),
            ctx.btn("", &clear_lbl, Some("umodel:clear"), None, None),
            ctx.btn("", agy_lbl, Some("umodel:agy_default"), None, None),
        ],
        sys_row,
    ];

    let start = page * MODELS_PER_PAGE;
    let end = (start + MODELS_PER_PAGE).min(ms.len());
    let chunk: Vec<(usize, &UncensoredModel)> = ms
        .iter()
        .enumerate()
        .skip(start)
        .take(end.saturating_sub(start))
        .collect();

    for pair in chunk.chunks(2) {
        let row = pair
            .iter()
            .map(|&(idx, m)| {
                let active = is_uncensored_active && u.model.as_deref() == Some(m.id.as_str());
                let mark = if active { "✅ " } else { "" };
                let label = format!("{mark}{}", clean_btn_model_name(m));
                let by_id = format!("umodel:={}", m.id);
                let cb = if by_id.len() <= 64 {
                    by_id
                } else {
                    format!("umodel:{idx}")
                };
                ctx.btn("", &label, Some(&cb), if active { Some("primary") } else { None }, None)
            })
            .collect();
        rows.push(row);
    }

    let lang = ctx.lang(uid);
    let mut footer = Vec::new();
    if page > 0 {
        footer.push(ctx.btn("", "‹", Some(&format!("umodels:{}", page - 1)), None, None));
    }
    footer.push(ctx.btn("refresh", t(lang, Tx::BtnRefresh), Some("umodels:refresh"), None, None));
    footer.push(ctx.btn("menu", t(lang, Tx::BtnMenu), Some("home"), None, None));
    if page + 1 < pages {
        footer.push(ctx.btn("", "›", Some(&format!("umodels:{}", page + 1)), None, None));
    }
    rows.push(footer);

    let cur_model = u.model.as_deref().unwrap_or("AGY default");
    let engine_lbl = if is_uncensored_active {
        format!("🔥 <b>{}</b> · <code>{}</code>", t(lang, Tx::PanelUncensoredTitle), esc(cur_model))
    } else {
        format!("🤖 <b>{}</b> · <code>{}</code>", t(lang, Tx::PanelUncensoredTitle), esc(cur_model))
    };
    let s3_lbl = three_stage_badge(stage3_mode);
    let mode_line = if agent_on {
        format!("⚙️ <b>Mode:</b> Agent ({tool_cnt} tools) · <b>3-Stage:</b> {s3_lbl} · <b>Memory:</b> {sess_msgs}")
    } else {
        format!("💬 <b>Mode:</b> Chat Only · <b>3-Stage:</b> {s3_lbl} · <b>Memory:</b> {sess_msgs}")
    };
    let key_warn = if ctx.cfg.venice_api_key.trim().is_empty() {
        "\n⚠️ <i>VENICE_API_KEY not set</i>"
    } else {
        ""
    };

    let text = format!(
        "{engine_lbl}\n{mode_line}{key_warn}\n<i>Page {}/{} · {} models · </i><code>/uagent &lt;task&gt;</code>",
        page + 1,
        pages,
        ms.len()
    );

    let mk = BotCtx::kb(rows);
    ctx.edit_or_send(cq, chat_id, &text, Some(mk)).await;
}

/// Apply user's uncensored model or mode choice.
pub async fn apply_uncensored_model_selection(
    ctx: &Arc<BotCtx>,
    cq: Option<&CallbackQuery>,
    uid: i64,
    chat_id: i64,
    choice: &str,
) {
    if choice == "stage3_tog" {
        let cur = uncensored_three_stage_mode(&ctx.store.get_user(uid));
        let (next_val, ack_msg) = next_three_stage_choice(cur);
        let _ = ctx.store.update_user(uid, |st| {
            st.extra
                .insert(UNCENSORED_THREE_STAGE_KEY.to_string(), json!(next_val));
        });
        if let Some(cq) = cq {
            ctx.ack(&cq.id, Some(ack_msg), false).await;
        }
        show_uncensored_models(ctx, cq, chat_id, uid, 0).await;
        return;
    }

    if choice == "agent_tog" {
        let now_on = !uncensored_agent_mode(&ctx.store.get_user(uid));
        let _ = ctx.store.update_user(uid, |st| {
            st.extra
                .insert(UNCENSORED_AGENT_MODE_KEY.to_string(), json!(now_on));
        });
        if let Some(cq) = cq {
            ctx.ack(
                &cq.id,
                Some(if now_on {
                    "Autonomous Agent Mode: ON"
                } else {
                    "Chat-Only Mode: ON"
                }),
                false,
            )
            .await;
        }
        show_uncensored_models(ctx, cq, chat_id, uid, 0).await;
        return;
    }

    if choice == "clear" {
        clear_session_history(&ctx.cfg.state_dir, &uncensored_session_key(uid));
        if let Some(cq) = cq {
            ctx.ack(&cq.id, Some("Uncensored session memory cleared"), false)
                .await;
        }
        show_uncensored_models(ctx, cq, chat_id, uid, 0).await;
        return;
    }

    if choice == "sys" {
        ctx.jobs
            .set_awaiting(uid, AwaitingInput::new("uncensored_sysprompt", json!({})));
        if let Some(cq) = cq {
            ctx.ack(&cq.id, Some("Send system prompt text or .txt/.md file"), false)
                .await;
        }
        let cur_info = match load_custom_sysprompt(&ctx.cfg.state_dir, uid) {
            Some(s) => format!(
                "\n<b>Current:</b> {} bytes (preview: <code>{}</code>)",
                s.len(),
                esc(&truncate_chars(&s, 140))
            ),
            None => "\n<i>No custom system prompt set (using default).</i>".to_string(),
        };
        let prompt_msg = format!(
            "📝 <b>Uncensored Custom System Prompt</b> (up to {} KiB){cur_info}\n\
            Send your full system prompt as a <b>text message</b> or upload a <b>.txt / .md file</b> now.\n\
            <i>Send <code>/cancel</code> to abort, or <code>/uncensored sys clear</code> to reset.</i>",
            MAX_CUSTOM_SYSPROMPT_BYTES / 1024
        );
        let mk = BotCtx::kb(vec![vec![
            ctx.btn("", "✖️ Cancel", Some("inp:cancel"), None, None),
            ctx.btn("", "↩️ Back", Some("umodels:0"), None, None),
        ]]);
        let _ = ctx.render.send_html_simple(chat_id, &prompt_msg, Some(mk)).await;
        return;
    }

    if choice == "sys_clear" {
        let removed = clear_custom_sysprompt(&ctx.cfg.state_dir, uid);
        if let Some(cq) = cq {
            ctx.ack(
                &cq.id,
                Some(if removed {
                    "Custom system prompt cleared"
                } else {
                    "No custom system prompt set"
                }),
                false,
            )
            .await;
        }
        show_uncensored_models(ctx, cq, chat_id, uid, 0).await;
        return;
    }

    if choice == "agy_default" || choice == "agy" {
        let _ = ctx.store.update_user(uid, |st| {
            st.extra.remove("engine");
            st.extra.remove(MODEL_INVALID_KEY);
            st.model = None;
        });
        ctx.jobs.clear_model_choices(uid);
        if let Some(cq) = cq {
            ctx.ack(&cq.id, Some("Switched to AGY default model"), false)
                .await;
        }
        show_uncensored_models(ctx, cq, chat_id, uid, 0).await;
        return;
    }

    let ms = ensure_uncensored_models(
        &ctx.cfg.state_dir,
        &ctx.cfg.venice_api_base,
        &ctx.cfg.venice_api_key,
    )
    .await;

    let target = if let Some(id) = choice.strip_prefix('=') {
        ms.iter().find(|m| m.id == id).cloned()
    } else if let Ok(idx) = choice.parse::<usize>() {
        ms.get(idx).cloned()
    } else {
        ms.iter().find(|m| m.id == choice).cloned()
    };

    let Some(m) = target else {
        if let Some(cq) = cq {
            ctx.ack(&cq.id, Some("Model not found in list"), false)
                .await;
        }
        show_uncensored_models(ctx, cq, chat_id, uid, 0).await;
        return;
    };

    let model_id = m.id.clone();
    let model_name = m.name.clone();

    let _ = ctx.store.update_user(uid, |st| {
        st.model = Some(model_id);
        st.extra.insert("engine".to_string(), json!("uncensored"));
        st.extra.remove(MODEL_INVALID_KEY);
    });

    info!(uid, model = %model_name, "user selected uncensored model");

    if let Some(cq) = cq {
        ctx.ack(
            &cq.id,
            Some(&format!("Model: {}", truncate_chars(&model_name, 35))),
            false,
        )
        .await;
    }

    show_uncensored_models(ctx, cq, chat_id, uid, 0).await;
}

/// Handle callback data starting with `umodels:` or `umodel:`.
pub async fn handle_uncensored_cb(
    ctx: &Arc<BotCtx>,
    cq: &CallbackQuery,
    uid: i64,
    chat_id: i64,
    data: &str,
) -> bool {
    if !data.starts_with("umodels:") && !data.starts_with("umodel:") {
        return false;
    }
    if !ctx.has_perm(uid, "uncensored") {
        let lang = ctx.lang(uid);
        let msg = format!("{} {}", t(lang, Tx::ModuleRequiredHdr), perm_label(lang, "uncensored"));
        ctx.ack(&cq.id, Some(&msg), true).await;
        return true;
    }

    if data == "umodels:refresh" {
        ctx.ack(
            &cq.id,
            Some("Refreshing uncensored models from Venice..."),
            false,
        )
        .await;
        let _ = refresh_uncensored_models(
            &ctx.cfg.state_dir,
            &ctx.cfg.venice_api_base,
            &ctx.cfg.venice_api_key,
        )
        .await;
        show_uncensored_models(ctx, Some(cq), chat_id, uid, 0).await;
        return true;
    }

    if let Some(rest) = data.strip_prefix("umodels:") {
        let page = rest.parse::<usize>().unwrap_or(0);
        ctx.ack(&cq.id, None, false).await;
        show_uncensored_models(ctx, Some(cq), chat_id, uid, page).await;
        return true;
    }

    if let Some(rest) = data.strip_prefix("umodel:") {
        apply_uncensored_model_selection(ctx, Some(cq), uid, chat_id, rest).await;
        return true;
    }

    false
}

/// Slash command `/uncensored` or `/umodel`.
pub async fn cmd_uncensored(ctx: &Arc<BotCtx>, msg: &Message, arg: &str) {
    let Some(uid) = msg.from_user.as_ref().map(|u| u.id) else {
        return;
    };
    let chat_id = msg.chat.id;
    if !ctx.has_perm(uid, "uncensored") {
        let _ = ctx
            .render
            .send_html_simple(chat_id, &missing_perm_html(ctx, uid, "uncensored"), None)
            .await;
        return;
    }
    let a = arg.trim();

    if a.is_empty() {
        show_uncensored_models(ctx, None, chat_id, uid, 0).await;
    } else if a.eq_ignore_ascii_case("agent") {
        let _ = ctx.store.update_user(uid, |st| {
            st.extra
                .insert(UNCENSORED_AGENT_MODE_KEY.to_string(), json!(true));
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
                    "🔥 Venice Uncensored → <b>Autonomous Agent Mode ON</b> ({tool_cnt} server/MCP tools enabled)."
                ),
                None,
            )
            .await;
    } else if a.eq_ignore_ascii_case("chat") {
        let _ = ctx.store.update_user(uid, |st| {
            st.extra
                .insert(UNCENSORED_AGENT_MODE_KEY.to_string(), json!(false));
        });
        let _ = ctx
            .render
            .send_html_simple(
                chat_id,
                "🔥 Venice Uncensored → <b>Direct Chat Mode</b> (server tools disabled).",
                None,
            )
            .await;
    } else if a.eq_ignore_ascii_case("3stage")
        || a.eq_ignore_ascii_case("stage3")
        || a.to_ascii_lowercase().starts_with("3stage ")
        || a.to_ascii_lowercase().starts_with("stage3 ")
    {
        let sub = a.split_whitespace().nth(1).unwrap_or("").to_ascii_lowercase();
        let val = match sub.as_str() {
            "on" | "always" | "1" | "true" => Some("always"),
            "off" | "0" | "false" => Some("off"),
            "auto" => Some("auto"),
            "" => {
                let (next_val, _) = next_three_stage_choice(uncensored_three_stage_mode(&ctx.store.get_user(uid)));
                Some(next_val)
            }
            _ => None,
        };
        match val {
            Some(mode_str) => {
                let _ = ctx.store.update_user(uid, |st| {
                    st.extra
                        .insert(UNCENSORED_THREE_STAGE_KEY.to_string(), json!(mode_str));
                });
                let _ = ctx
                    .render
                    .send_html_simple(
                        chat_id,
                        &format!(
                            "🧠 Venice Uncensored <b>3-Stage Memory &amp; Chunk Mode</b> → <code>{}</code>.",
                            esc(&mode_str.to_ascii_uppercase())
                        ),
                        None,
                    )
                    .await;
            }
            None => {
                let _ = ctx
                    .render
                    .send_html_simple(
                        chat_id,
                        "Usage: <code>/uncensored 3stage auto|on|off</code>",
                        None,
                    )
                    .await;
            }
        }
    } else if a.eq_ignore_ascii_case("clear") || a.eq_ignore_ascii_case("reset") {
        clear_session_history(&ctx.cfg.state_dir, &uncensored_session_key(uid));
        let _ = ctx
            .render
            .send_html_simple(chat_id, "🧹 Uncensored session memory cleared.", None)
            .await;
    } else if a.eq_ignore_ascii_case("sys") || a.to_ascii_lowercase().starts_with("sys ") {
        let rest = a.get(3..).map(str::trim).unwrap_or("");
        if rest.is_empty() {
            apply_uncensored_model_selection(ctx, None, uid, chat_id, "sys").await;
        } else if rest.eq_ignore_ascii_case("clear") || rest.eq_ignore_ascii_case("reset") {
            let removed = clear_custom_sysprompt(&ctx.cfg.state_dir, uid);
            let msg_txt = if removed {
                "🧹 Custom Uncensored system prompt cleared (restored default)."
            } else {
                "ℹ️ No custom Uncensored system prompt was set."
            };
            let _ = ctx.render.send_html_simple(chat_id, msg_txt, None).await;
        } else {
            match save_custom_sysprompt(&ctx.cfg.state_dir, uid, rest) {
                Ok(bytes) => {
                    let _ = ctx
                        .render
                        .send_html_simple(
                            chat_id,
                            &format!(
                                "✅ Saved full Uncensored system prompt (<b>{bytes}</b> bytes, 0 truncation)."
                            ),
                            None,
                        )
                        .await;
                }
                Err(e) => {
                    let _ = ctx
                        .render
                        .send_html_simple(
                            chat_id,
                            &format!("{} <code>{}</code>", ctx.e("err"), esc(&e.to_string())),
                            None,
                        )
                        .await;
                }
            }
        }
    } else {
        apply_uncensored_model_selection(ctx, None, uid, chat_id, a).await;
    }
}

/// Handle interactive text input when awaiting an Uncensored custom system prompt.
pub async fn handle_uncensored_awaiting_text(
    ctx: &Arc<BotCtx>,
    uid: i64,
    chat_id: i64,
    inp: &AwaitingInput,
    raw_text: &str,
) -> bool {
    if inp.kind != "uncensored_sysprompt" {
        return false;
    }
    match save_custom_sysprompt(&ctx.cfg.state_dir, uid, raw_text) {
        Ok(bytes) => {
            let _ = ctx
                .render
                .send_html_simple(
                    chat_id,
                    &format!(
                        "✅ Saved full Uncensored system prompt (<b>{bytes}</b> bytes). Active immediately in both Agent &amp; Chat modes."
                    ),
                    Some(BotCtx::kb(vec![vec![ctx.btn(
                        "fire",
                        "Uncensored Panel",
                        Some("umodels:0"),
                        Some("primary"),
                        None,
                    )]])),
                )
                .await;
        }
        Err(e) => {
            let _ = ctx
                .render
                .send_html_simple(
                    chat_id,
                    &format!("{} <code>{}</code>", ctx.e("err"), esc(&e.to_string())),
                    None,
                )
                .await;
        }
    }
    true
}

/// Handle an uploaded `.txt`/`.md` file when awaiting an Uncensored custom system prompt
/// (reads full UTF-8 content up to 64 KiB with zero truncation).
pub async fn handle_uncensored_awaiting_file(
    ctx: &Arc<BotCtx>,
    uid: i64,
    chat_id: i64,
    path: &std::path::Path,
) -> bool {
    let is_waiting = ctx
        .jobs
        .peek_awaiting(uid)
        .is_some_and(|i| i.kind == "uncensored_sysprompt");
    if !is_waiting {
        return false;
    }
    let _ = ctx.jobs.take_awaiting(uid);
    match tokio::fs::read(path).await {
        Ok(bytes) => {
            let text = String::from_utf8_lossy(&bytes);
            match save_custom_sysprompt(&ctx.cfg.state_dir, uid, &text) {
                Ok(saved_len) => {
                    let fname = path
                        .file_name()
                        .and_then(|s| s.to_str())
                        .unwrap_or("prompt.txt");
                    let _ = ctx
                        .render
                        .send_html_simple(
                            chat_id,
                            &format!(
                                "✅ Loaded full Uncensored system prompt from <code>{}</code> (<b>{saved_len}</b> bytes, 0 truncation).",
                                esc(fname)
                            ),
                            Some(BotCtx::kb(vec![vec![ctx.btn(
                                "fire",
                                "Uncensored Panel",
                                Some("umodels:0"),
                                Some("primary"),
                                None,
                            )]])),
                        )
                        .await;
                }
                Err(e) => {
                    let _ = ctx
                        .render
                        .send_html_simple(
                            chat_id,
                            &format!("{} <code>{}</code>", ctx.e("err"), esc(&e.to_string())),
                            None,
                        )
                        .await;
                }
            }
        }
        Err(e) => {
            let _ = ctx
                .render
                .send_html_simple(
                    chat_id,
                    &format!(
                        "{} Failed reading uploaded system prompt: <code>{}</code>",
                        ctx.e("err"),
                        esc(&e.to_string())
                    ),
                    None,
                )
                .await;
        }
    }
    true
}

/// Slash command `/uagent <task>` — execute an immediate autonomous Uncensored Agent task
/// without changing the user's sticky default engine.
pub async fn cmd_uagent(ctx: &Arc<BotCtx>, msg: &Message, arg: &str) {
    let Some(ref user) = msg.from_user else {
        return;
    };
    let uid = user.id;
    let chat_id = msg.chat.id;
    if !ctx.has_perm(uid, "uncensored") {
        let _ = ctx
            .render
            .send_html_simple(chat_id, &missing_perm_html(ctx, uid, "uncensored"), None)
            .await;
        return;
    }
    let task = arg.trim();
    if task.is_empty() {
        let txt = "🔥 <b>Venice Uncensored Autonomous Agent</b>\n\
            Usage: <code>/uagent &lt;your task&gt;</code>\n\
            <i>Runs an isolated multi-step autonomous agent (Bash, Files, search-v3, AI-Memory, SkillPort &amp; MCPs) without changing your default chat engine.</i>";
        let mk = BotCtx::kb(vec![vec![ctx.btn(
            "fire",
            "Uncensored Panel",
            Some("umodels:0"),
            Some("primary"),
            None,
        )]]);
        let _ = ctx.render.send_html_simple(chat_id, txt, Some(mk)).await;
        return;
    }

    let mut req = JobRequest::new(uid, chat_id, user.display_label(), task, Vec::new());
    req.overrides = JobOverride {
        isolated: true,
        force_engine: Some("uncensored".to_string()),
        force_agent_mode: Some(true),
        ..Default::default()
    };
    if let Err(err) = ctx.jobs.enqueue(req).await {
        let _ = ctx
            .render
            .send_html_simple(
                chat_id,
                &format!(
                    "{} <b>Failed to start Uncensored Agent:</b> <code>{}</code>",
                    ctx.e("err"),
                    esc(&err.to_string())
                ),
                None,
            )
            .await;
    }
}
