//! Core system, dashboard, model/settings, workspace, session, network, and cron handlers.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use agy_core::tg::{CallbackQuery, InlineKeyboardButton, Message};
use agy_ext::mcp_client::redact_secrets_in_text;
use agy_render::esc;
use chrono::{Local, TimeZone};
use serde_json::Value;
use tracing::warn;

use crate::cron::CronJobStatus;
use crate::ctx::BotCtx;
use crate::i18n::{missing_perm_html, owner_only_html, perm_label, set_user_lang, t, Lang, Tx};
use crate::jobs::{effective_stream_mode, JobOverride, JobRequest};

/// Supported reasoning effort presets.
pub const EFFORTS: &[&str] = &["default", "low", "medium", "high", "xhigh", "max"];

/// Supported agent execution modes.
pub const MODES: &[&str] = &["auto", "accept-edits", "plan"];

/// Supported draft streaming modes.
pub const STREAM_MODES: &[&str] = &["semi", "live", "off"];

const MODELS_PER_PAGE: usize = 10;
const SESSIONS_PER_VIEW: usize = 8;
const CWD_SKIP_DIRS: &[&str] = &["inbox", "outbox", "graphify-out", "telegram-docs"];

fn now_unix_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

fn msg_uid(msg: &Message) -> Option<i64> {
    msg.from_user.as_ref().map(|u| u.id)
}

fn truncate_chars(s: &str, max_chars: usize) -> String {
    let count = s.chars().count();
    if count <= max_chars {
        s.to_string()
    } else {
        s.chars().take(max_chars).collect()
    }
}

fn truncate_utf8_bytes(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

fn expand_tilde(raw: &str) -> PathBuf {
    if raw == "~" {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home);
        }
    } else if let Some(rest) = raw.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home).join(rest);
        }
    }
    PathBuf::from(raw)
}

fn effective_cwd(ctx: &BotCtx, uid: i64) -> String {
    ctx.store
        .get_user(uid)
        .cwd
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| ctx.cfg.agy_workspace.to_string_lossy().into_owned())
}

fn align_kv_table(rows: &[(&str, String)]) -> String {
    let width = rows.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
    rows.iter()
        .map(|(k, v)| format!("{:<width$}  {}", k, v, width = width))
        .collect::<Vec<_>>()
        .join("\n")
}

async fn deny_cmd_perm(ctx: &BotCtx, chat_id: i64, uid: i64, perm: &str) -> bool {
    if ctx.has_perm(uid, perm) {
        return false;
    }
    let txt = missing_perm_html(ctx, uid, perm);
    let _ = ctx.render.send_html_simple(chat_id, &txt, None).await;
    true
}

async fn deny_cb_perm(ctx: &BotCtx, cq: &CallbackQuery, uid: i64, perm: &str) -> bool {
    if ctx.has_perm(uid, perm) {
        return false;
    }
    let lang = ctx.lang(uid);
    let msg = format!(
        "{} {}",
        t(lang, Tx::ModuleRequiredHdr),
        perm_label(lang, perm)
    );
    ctx.ack(&cq.id, Some(&msg), true).await;
    true
}

/// Build the localized, permission-filtered `/help` HTML text for `uid`.
pub fn help_text_for(ctx: &BotCtx, uid: i64) -> String {
    let lang = ctx.lang(uid);
    let is_owner = ctx.is_owner(uid);
    let has_dash = is_owner || ctx.has_perm(uid, "dashboard_access");
    let ws = ctx.cfg.agy_workspace.to_string_lossy();

    let body = if !has_dash {
        format!(
            "<blockquote>• {}</blockquote>",
            t(lang, Tx::MinimalChatHint)
        )
    } else {
        let tip = match lang {
            Lang::Fa => format!("پیام، تصویر یا فایل (≤ ۲۰ MB) بفرستید تا در <code>{}</code> پردازش شود.", esc(&ws)),
            Lang::La => format!("Mitte textum aut fasciculum (≤ 20 MB) in <code>{}</code>.", esc(&ws)),
            Lang::Zh => format!("直接发送文本、图片或文件 (≤ 20 MB)，将在 <code>{}</code> 中处理。", esc(&ws)),
            Lang::Ru => format!("Отправьте текст, фото или файл (≤ 20 МБ) для работы в <code>{}</code>.", esc(&ws)),
            Lang::En => format!("Send any message, photo or file (≤ 20 MB) to run in <code>{}</code>.", esc(&ws)),
        };
        format!("<blockquote>• {tip}</blockquote>")
    };

    let mut sections = vec![format!(
        "{} <b>{}</b>\n{}\n<b>{}</b>\n/new · /lang · /stop · /cancel · /help{}",
        ctx.e("help"),
        t(lang, Tx::HelpHeader),
        body,
        t(lang, Tx::HelpSecChat),
        if has_dash { " · /menu · /resume" } else { "" },
    )];

    let mut mod_cmds: Vec<&str> = Vec::new();
    if ctx.has_perm(uid, "models_switch") {
        mod_cmds.push("/model");
    }
    if ctx.has_perm(uid, "uncensored") {
        mod_cmds.push("/uncensored · /uagent");
    }
    if ctx.has_perm(uid, "grok") {
        mod_cmds.push("/grok · /gagent");
    }
    if ctx.has_perm(uid, "status_net") {
        mod_cmds.push("/status · /net · /proxies · /cron");
    }
    if ctx.has_perm(uid, "mcp_manage") {
        mod_cmds.push("/mcp");
    }
    if ctx.has_perm(uid, "skills_manage") {
        mod_cmds.push("/skills");
    }
    if ctx.has_perm(uid, "settings_access") {
        mod_cmds.push("/settings · /mode · /effort · /cwd · /agent · /trace · /changelog");
    }
    if ctx.has_perm(uid, "widgets") {
        mod_cmds.push("/widget");
    }
    if ctx.has_perm(uid, "parallel") {
        mod_cmds.push("/parallel");
    }
    if ctx.has_perm(uid, "automations") {
        mod_cmds.push("/auto");
    }

    if !mod_cmds.is_empty() {
        sections.push(format!(
            "\n<b>{}</b>\n{}",
            t(lang, Tx::HelpSecModules),
            mod_cmds.join(" · ")
        ));
    }

    if is_owner || ctx.has_perm(uid, "root_access") {
        sections.push(format!(
            "\n<b>{}</b>\n✓ {}",
            t(lang, Tx::HelpSecAdmin),
            perm_label(lang, "root_access")
        ));
    } else if ctx.has_perm(uid, "sandbox_exec") {
        sections.push(format!(
            "\n<b>{}</b>\n✓ {}",
            t(lang, Tx::HelpSecAdmin),
            perm_label(lang, "sandbox_exec")
        ));
    }

    if is_owner {
        sections.push(format!(
            "\n<b>{}</b>\n/users · /accounts · /proxies · /secretary",
            t(lang, Tx::HelpSecOwner)
        ));
    }

    sections.push(format!("\n<i>{}</i>", t(lang, Tx::HelpFooterTip)));
    sections.join("")
}

/// Render or edit the 5-language picker (`lang:menu`, `/lang`).
pub async fn show_language(ctx: &Arc<BotCtx>, cq: Option<&CallbackQuery>, chat_id: i64, uid: i64) {
    let lang = ctx.lang(uid);
    let html = format!(
        "🌐 <b>{}</b>\n<blockquote><b>{}</b>  <code>{}</code></blockquote>\n<i>{}</i>",
        t(lang, Tx::LangTitle),
        t(lang, Tx::LangCurrentLabel),
        esc(lang.native_label()),
        t(lang, Tx::LangSelectHint),
    );
    let mk = ctx.lang_kb(uid);
    ctx.edit_or_send(cq, chat_id, &html, Some(mk)).await;
}

/// Render or edit the main Antigravity dashboard card (Page 0).
pub async fn show_home(ctx: &Arc<BotCtx>, cq: Option<&CallbackQuery>, chat_id: i64, uid: i64) {
    show_home_page(ctx, cq, chat_id, uid, 0).await;
}

/// Render or edit a specific page (`0`, `1`, `2`) of the tabbed `/menu` dashboard.
pub async fn show_home_page(
    ctx: &Arc<BotCtx>,
    cq: Option<&CallbackQuery>,
    chat_id: i64,
    uid: i64,
    page: usize,
) {
    let clamped = ctx.clamp_menu_page(uid, page);
    let text = ctx.dashboard_text_page(uid, clamped);
    let mk = ctx.main_kb_page(uid, ctx.jobs.is_user_busy(uid), clamped);
    ctx.edit_or_send(cq, chat_id, &text, Some(mk)).await;
}

/// Render or edit the paginated model picker (`models:{page}`, `model:{idx|default}`).
pub async fn show_models(
    ctx: &Arc<BotCtx>,
    cq: Option<&CallbackQuery>,
    chat_id: i64,
    uid: i64,
    page: usize,
) {
    let u = ctx.store.get_user(uid);
    let (acct, mut ms) = ctx.models_for_user(uid);
    if ms.is_empty() && acct.is_some() {
        ms = ctx.refresh_models_for_user(uid).await;
    }
    let pages = ms.len().div_ceil(MODELS_PER_PAGE).max(1);
    let page = page.min(pages - 1);

    let default_lbl = format!(
        "{}Default",
        if u.model.as_deref().is_none_or(str::is_empty) {
            "✅ "
        } else {
            ""
        }
    );
    let mut rows: Vec<Vec<InlineKeyboardButton>> = vec![vec![ctx.btn(
        "",
        &default_lbl,
        Some("model:default"),
        None,
        None,
    )]];

    let start = page * MODELS_PER_PAGE;
    let end = (start + MODELS_PER_PAGE).min(ms.len());
    let chunk: Vec<(usize, &_)> = ms
        .iter()
        .enumerate()
        .skip(start)
        .take(end.saturating_sub(start))
        .collect();

    for pair in chunk.chunks(2) {
        let row = pair
            .iter()
            .map(|&(idx, m)| {
                let mark = if u.model.as_deref() == Some(m.id.as_str()) {
                    "✅ "
                } else {
                    ""
                };
                let label = format!("{mark}{}", truncate_chars(&m.name, 30));
                // id-based so a keyboard stays correct after the list changes
                let by_id = format!("model:={}", m.id);
                let cb = if by_id.len() <= 64 { by_id } else { format!("model:{idx}") };
                ctx.btn("", &label, Some(&cb), None, None)
            })
            .collect();
        rows.push(row);
    }

    let mut nav = Vec::new();
    if page > 0 {
        nav.push(ctx.btn("", "‹ Prev", Some(&format!("models:{}", page - 1)), None, None));
    }
    if page + 1 < pages {
        nav.push(ctx.btn("", "Next ›", Some(&format!("models:{}", page + 1)), None, None));
    }
    if !nav.is_empty() {
        rows.push(nav);
    }

    rows.push(vec![
        ctx.btn("refresh", t(ctx.lang(uid), Tx::BtnRefresh), Some("models:refresh"), None, None),
        ctx.btn("menu", t(ctx.lang(uid), Tx::BtnMenu), Some("home"), None, None),
    ]);

    let lang = ctx.lang(uid);
    let cur_label = ctx.model_label(u.model.as_deref());
    let acct_line = match &acct {
        Some(a) => {
            let name = if ctx.is_owner(uid) { format!("{} ({})", a.display_name(), a.id) } else { a.id.clone() };
            let missing = u
                .model
                .as_deref()
                .filter(|m| !m.is_empty() && !ms.is_empty() && !ms.iter().any(|x| x.id == *m))
                .map(|_| "\n⚠️ Your model is not offered by this account.")
                .unwrap_or("");
            format!("\nAccount: <code>{}</code>{}", esc(&name), missing)
        }
        None => String::new(),
    };
    let text = format!(
        "{} <b>{}</b>\n<blockquote>{}: <code>{}</code>{}\n{} models · {} {}/{}</blockquote>",
        ctx.e("model"),
        t(lang, Tx::PanelModelsTitle),
        t(lang, Tx::DashFieldModel),
        esc(&cur_label),
        acct_line,
        ms.len(),
        "page",
        page + 1,
        pages
    );
    ctx.edit_or_send(cq, chat_id, &text, Some(BotCtx::kb(rows)))
        .await;
}

/// Render or edit host/process/task runtime status.
pub async fn show_status(ctx: &Arc<BotCtx>, cq: Option<&CallbackQuery>, chat_id: i64, uid: i64) {
    let lang = ctx.lang(uid);
    let snap = ctx.sys_snapshot(uid);
    let host = snap["host"].as_str().unwrap_or(&ctx.host);
    let uptime = snap["uptime"].as_str().unwrap_or("0h 0m");
    let load = snap["load"].as_str().unwrap_or("0.00 0.00 0.00");
    let cpu_pct = snap["cpu_pct"].as_u64().unwrap_or(0);
    let ram_str = snap["ram_pct"]
        .as_u64()
        .map(|p| format!("{p}%"))
        .unwrap_or_else(|| "—".to_string());
    let disk_pct = snap["disk_pct"].as_u64().unwrap_or(0);
    let task_str = match ctx.jobs.active_job_info(uid) {
        Some(info) => format!("{} {}s", t(lang, Tx::StatusRunning), info.started.elapsed().as_secs()),
        None => t(lang, Tx::StatusIdle).to_string(),
    };

    let rows: Vec<(&str, String)> = vec![
        ("Host", host.to_string()),
        ("Runtime", format!("agy-telegram-rs {}", env!("CARGO_PKG_VERSION"))),
        ("Uptime", uptime.to_string()),
        ("Load", format!("{load} ({cpu_pct}%)")),
        ("RAM / Disk", format!("{ram_str} / {disk_pct}% used")),
        ("Workspace", ctx.cfg.agy_workspace.to_string_lossy().into_owned()),
        ("Task", task_str),
        (
            "Active jobs",
            format!(
                "{} (global {}/{})",
                ctx.jobs.active_count(),
                ctx.jobs.active_global_jobs(),
                ctx.jobs.max_global_jobs()
            ),
        ),
        (
            "Guards",
            {
                let lim = ctx.jobs.runtime_limits();
                format!(
                    "tools<={} rep<={} burst<={}/m · tmo {}m · rl {}/{} · scan {}",
                    lim.max_tool_steps,
                    lim.tool_repeat_limit,
                    lim.max_tools_per_min,
                    lim.job_timeout_secs / 60,
                    ctx.cfg.http_rl_per_min,
                    lim.tg_user_rl_per_min,
                    if lim.outbox_secret_scan { "on" } else { "off" }
                )
            },
        ),
        (
            "Efficiency",
            format!(
                "compact:{} profile:{} fast:{} mcp_ttl:{}s",
                if ctx.cfg.prompt_compact_resume { "on" } else { "off" },
                if ctx.cfg.agy_dynamic_profile { "on" } else { "off" },
                if ctx.cfg.local_fast_path { "on" } else { "off" },
                ctx.cfg.mcp_ro_cache_ttl_secs,
            ),
        ),
        ("Premium UI", if ctx.premium.active() { "on" } else { "off" }.to_string()),
    ];
    let table = align_kv_table(&rows);
    let html = format!("{} <b>{}</b>\n<pre>{}</pre>", ctx.e("status"), t(lang, Tx::PanelStatusTitle), esc(&table));
    let mut kb_rows = vec![vec![
        ctx.btn("refresh", t(lang, Tx::BtnRefresh), Some("status"), None, None),
        ctx.btn("back", t(lang, Tx::BtnMenu), Some("home"), None, None),
    ]];
    if ctx.is_owner(uid) {
        kb_rows.insert(
            0,
            vec![
                ctx.btn("admin", "Limits & Guards", Some("limits"), Some("primary"), None),
                ctx.btn("bolt", "Safety Policy", Some("acct:pol"), None, None),
            ],
        );
    }
    let mk = BotCtx::kb(kb_rows);
    ctx.edit_or_send(cq, chat_id, &html, Some(mk)).await;
}

/// Interactive owner-only `/limits` panel for AI Safety Guards, anti-flood, timeouts, and secret scanning.
pub async fn show_limits(ctx: &Arc<BotCtx>, cq: Option<&CallbackQuery>, chat_id: i64, uid: i64) {
    if !ctx.is_owner(uid) {
        let html = owner_only_html(ctx, uid);
        let _ = ctx.render.send_html_simple(chat_id, &html, None).await;
        return;
    }
    let lim = ctx.jobs.runtime_limits();
    let fmt_opt = |v: usize, unit: &str| -> String {
        if v == 0 {
            "off".to_string()
        } else {
            format!("{v}{unit}")
        }
    };
    let rl_str = if lim.tg_user_rl_per_min == 0 {
        "off".to_string()
    } else {
        format!("{}/min (owner 3x · nav 3x)", lim.tg_user_rl_per_min)
    };
    let md = format!(
        "### {} Runtime Limits & AI Safety Guards\n\
        > Live AI safety, queue & flood controls synced across `JobManager`, `Parallel`, `Secretary` & Telegram (persisted in `state.json`). Guard knobs stay active within safe bounds.\n\n\
        | Guard / Limit | Value |\n\
        |---|---|\n\
        | Max Tool Steps / Turn | `{}` |\n\
        | Tool Loop Repeat Limit | `{}` |\n\
        | Tool Burst / 60s | `{}` |\n\
        | Job Timeout | `{} min` |\n\
        | Global Concurrent Jobs | `{}` (live max) |\n\
        | User Pending Queue Cap | `{}` per user |\n\
        | Telegram User Anti-Flood | `{rl_str}` |\n\
        | HTTP Rate / Concurrency | `{}/min` · `{}` slots |\n\
        | Outbox Secret Scanner | `{}` |",
        ctx.premium.md("admin"),
        fmt_opt(lim.max_tool_steps, " steps"),
        fmt_opt(lim.tool_repeat_limit, "x"),
        fmt_opt(lim.max_tools_per_min, "/m"),
        lim.job_timeout_secs / 60,
        lim.max_global_ai_jobs,
        lim.max_queue_per_user,
        ctx.cfg.http_rl_per_min,
        ctx.cfg.http_max_concurrency,
        if lim.outbox_secret_scan { "ON" } else { "OFF (⚠)" },
    );

    let rows = vec![
        vec![
            ctx.btn("admin", "🛡 Strict", Some("lim:prof:strict"), None, None),
            ctx.btn("", "⚖️ Standard", Some("lim:prof:std"), None, None),
            ctx.btn("", "🚀 Extended", Some("lim:prof:high"), None, None),
        ],
        vec![
            ctx.btn("", &format!("Steps: {}", fmt_opt(lim.max_tool_steps, "")), Some("lim:steps"), None, None),
            ctx.btn("", &format!("Repeat: {}", fmt_opt(lim.tool_repeat_limit, "x")), Some("lim:rep"), None, None),
        ],
        vec![
            ctx.btn("", &format!("Burst: {}", fmt_opt(lim.max_tools_per_min, "/m")), Some("lim:burst"), None, None),
            ctx.btn("", &format!("Timeout: {}m", lim.job_timeout_secs / 60), Some("lim:tmo"), None, None),
        ],
        vec![
            ctx.btn("", &format!("Global Jobs: {}", lim.max_global_ai_jobs), Some("lim:global"), None, None),
            ctx.btn("", &format!("User Queue: {}", lim.max_queue_per_user), Some("lim:queue"), None, None),
        ],
        vec![
            ctx.btn("", &format!("TG Flood: {}", if lim.tg_user_rl_per_min == 0 { "off".to_string() } else { format!("{}/m", lim.tg_user_rl_per_min) }), Some("lim:rl"), None, None),
            ctx.btn("", &format!("Secret Scan: {}", if lim.outbox_secret_scan { "ON" } else { "OFF" }), Some("lim:scan"), None, None),
        ],
        vec![
            ctx.btn("bolt", "Safety Policy ›", Some("acct:pol"), Some("primary"), None),
            ctx.btn("refresh", "Reset Defaults", Some("lim:reset"), None, None),
        ],
        vec![
            ctx.btn("status", "Status", Some("status"), None, None),
            ctx.btn("back", "Menu", Some("home:2"), None, None),
        ],
    ];
    let msg_id = cq.and_then(|c| c.message.as_ref()).map(|m| m.message_id);
    let _ = ctx
        .render
        .edit_or_send_rich(chat_id, msg_id, &md, Some(BotCtx::kb(rows)))
        .await;
}

/// Render or edit per-user Settings (mode, effort, streaming, rendering, root skip_permissions).
pub async fn show_settings(ctx: &Arc<BotCtx>, cq: Option<&CallbackQuery>, chat_id: i64, uid: i64) {
    let u = ctx.store.get_user(uid);
    let mode = u.mode.as_deref().filter(|s| !s.is_empty()).unwrap_or("auto");
    let effort = u
        .effort
        .as_deref()
        .filter(|s| !s.is_empty())
        .unwrap_or("default");
    let smode = effective_stream_mode(&u);

    let pick = |key: &str, val: &str, cur: &str, label: Option<&str>| -> InlineKeyboardButton {
        let text = format!("{}{}", if cur == val { "● " } else { "" }, label.unwrap_or(val));
        ctx.btn("", &text, Some(&format!("set:{key}:{val}")), None, None)
    };

    let semi_lbl = format!("semi {}s", ctx.cfg.stream_interval.round() as u64);
    let mut rows: Vec<Vec<InlineKeyboardButton>> = vec![
        vec![
            pick("mode", "auto", mode, None),
            pick("mode", "accept-edits", mode, Some("edits")),
            pick("mode", "plan", mode, None),
        ],
        vec![
            pick("effort", "default", effort, Some("def")),
            pick("effort", "low", effort, None),
            pick("effort", "medium", effort, None),
        ],
        vec![
            pick("effort", "high", effort, None),
            pick("effort", "xhigh", effort, None),
            pick("effort", "max", effort, None),
        ],
        vec![
            pick("stream_mode", "semi", smode, Some(&semi_lbl)),
            pick("stream_mode", "live", smode, None),
            pick("stream_mode", "off", smode, None),
        ],
        vec![ctx.btn(
            "",
            &format!("Render: {}", u.render),
            Some("set:render:x"),
            None,
            None,
        )],
    ];

    if ctx.has_perm(uid, crate::jobs::parallel::PARALLEL_PERM) {
        let cur = crate::jobs::parallel::user_parallel_setting(&u);
        let pp = |v: usize, lbl: &str| {
            ctx.btn(
                "",
                &format!("{}{}", if cur == v { "● " } else { "" }, lbl),
                Some(&format!("set:parallel:{v}")),
                None,
                None,
            )
        };
        rows.push(vec![pp(0, "⚡ Parallel: Off"), pp(2, "2 agents"), pp(3, "3 agents")]);
    }

    if ctx.has_perm(uid, "root_access") {
        let perm_lbl = format!(
            "⚠️ Permissions: {}",
            if u.skip_permissions { "SKIP" } else { "default" }
        );
        let style = if u.skip_permissions {
            Some("danger")
        } else {
            None
        };
        let mut sec_row = vec![ctx.btn(
            "",
            &perm_lbl,
            Some("set:skip_permissions:x"),
            style,
            None,
        )];
        if ctx.is_owner(uid) {
            let scan_on = ctx.jobs.runtime_limits().outbox_secret_scan;
            let scan_lbl = format!("🛡 Secret Scan: {}", if scan_on { "ON" } else { "OFF" });
            let scan_style = if scan_on { None } else { Some("danger") };
            sec_row.push(ctx.btn("", &scan_lbl, Some("set:secret_scan:x"), scan_style, None));
        }
        rows.push(sec_row);
    } else if ctx.is_owner(uid) {
        let scan_on = ctx.jobs.runtime_limits().outbox_secret_scan;
        let scan_lbl = format!("🛡 Secret Scan: {}", if scan_on { "ON" } else { "OFF" });
        let scan_style = if scan_on { None } else { Some("danger") };
        rows.push(vec![ctx.btn("", &scan_lbl, Some("set:secret_scan:x"), scan_style, None)]);
    }

    let lang = ctx.lang(uid);
    rows.push(vec![ctx.btn("bolt", "Advanced ›", Some("adv"), None, None)]);
    rows.push(ctx.back_row_for(uid));

    let perm_desc = if u.skip_permissions && ctx.has_perm(uid, "root_access") {
        "⚠️ skip all prompts"
    } else {
        "agy default (safe)"
    };
    let scan_line = if ctx.is_owner(uid) {
        let scan_on = ctx.jobs.runtime_limits().outbox_secret_scan;
        format!(
            "\n<b>Secret Scan</b> {}",
            if scan_on { "🛡 ON" } else { "⚠️ OFF" }
        )
    } else {
        String::new()
    };
    let text = format!(
        "⚙️ <b>{}</b>\n<blockquote>\
        <b>{}</b> {} · <b>{}</b> {}\n\
        <b>Streaming</b> {} · <b>Render</b> {}\n\
        <b>Permissions</b> {}{}</blockquote>",
        t(lang, Tx::PanelSettingsTitle),
        t(lang, Tx::DashFieldMode),
        esc(mode),
        t(lang, Tx::DashFieldEffort),
        esc(effort),
        esc(smode),
        esc(&u.render),
        perm_desc,
        scan_line
    );
    ctx.edit_or_send(cq, chat_id, &text, Some(BotCtx::kb(rows)))
        .await;
}

/// Render or edit the Advanced submenu (Agent, Workspace, Trace, Changelog, Network, Cron).
pub async fn show_advanced(ctx: &Arc<BotCtx>, cq: Option<&CallbackQuery>, chat_id: i64, uid: i64) {
    let lang = ctx.lang(uid);
    let u = ctx.store.get_user(uid);
    let agent = u.agent.as_deref().filter(|s| !s.is_empty()).unwrap_or("default");
    let cwd = effective_cwd(ctx, uid);
    let trace_lbl = if u.trace { "on" } else { "off" };

    let text = format!(
        "⚡ <b>{}</b>\n<blockquote>\
        <b>{}</b> {}\n\
        <b>{}</b> <code>{}</code>\n\
        <b>Tool trace</b> {}</blockquote>",
        t(lang, Tx::PanelAdvancedTitle),
        t(lang, Tx::PanelAgentTitle),
        esc(agent),
        t(lang, Tx::DashFieldWorkspace),
        esc(&cwd),
        trace_lbl
    );

    let mut rows = vec![
        vec![
            ctx.btn("", &format!("🤖 {}", t(lang, Tx::PanelAgentTitle)), Some("agent:list"), None, None),
            ctx.btn("folder", t(lang, Tx::BtnCwd), Some("cwd:list"), None, None),
        ],
        vec![
            ctx.btn(
                "",
                &format!("🧭 Trace: {trace_lbl}"),
                Some("set:trace:x"),
                None,
                None,
            ),
            ctx.btn("doc", t(lang, Tx::PanelChangelogTitle), Some("changelog"), None, None),
        ],
    ];
    if ctx.has_perm(uid, "status_net") {
        rows.push(vec![
            ctx.btn("", &format!("📡 {}", t(lang, Tx::BtnNetwork)), Some("net:show"), None, None),
            ctx.btn("", &format!("🕒 {}", t(lang, Tx::BtnCron)), Some("cron:list"), None, None),
        ]);
    }
    rows.push(vec![
        ctx.btn("", &format!("« {}", t(lang, Tx::BtnSettings)), Some("settings"), None, None),
        ctx.btn("menu", t(lang, Tx::BtnMenu), Some("home"), None, None),
    ]);
    ctx.edit_or_send(cq, chat_id, &text, Some(BotCtx::kb(rows)))
        .await;
}

/// Render or edit the recent session history picker (`res:{idx}`).
pub async fn show_sessions(ctx: &Arc<BotCtx>, cq: Option<&CallbackQuery>, chat_id: i64, uid: i64) {
    let u = ctx.store.get_user(uid);
    let mut rows: Vec<Vec<InlineKeyboardButton>> = Vec::new();
    for (i, h) in u.history.iter().take(SESSIONS_PER_VIEW).enumerate() {
        let cur = if u.conversation_id.as_deref() == Some(h.id.as_str()) {
            "✅ "
        } else {
            ""
        };
        let when = Local
            .timestamp_opt(h.ts, 0)
            .single()
            .map(|dt| dt.format("%m-%d %H:%M").to_string())
            .unwrap_or_else(|| "—".to_string());
        let title = truncate_chars(&h.title, 28);
        let label = format!("{cur}{when} · {title}");
        rows.push(vec![ctx.btn(
            "",
            &label,
            Some(&format!("res:{i}")),
            None,
            None,
        )]);
    }
    let lang = ctx.lang(uid);
    rows.push(vec![
        ctx.btn("new", t(lang, Tx::BtnNewChat), Some("new"), Some("success"), None),
        ctx.btn("menu", t(lang, Tx::BtnMenu), Some("home"), None, None),
    ]);

    let sub = if u.history.is_empty() {
        format!("<i>{}</i>", t(lang, Tx::NoneWord))
    } else {
        "<i>Tap to resume</i>".to_string()
    };
    let text = format!("{} <b>{}</b>\n{sub}", ctx.e("sessions"), t(lang, Tx::PanelSessionsTitle));
    ctx.edit_or_send(cq, chat_id, &text, Some(BotCtx::kb(rows)))
        .await;
}

fn cwd_choices(workspace: &Path) -> Vec<String> {
    let ws_str = workspace.to_string_lossy().into_owned();
    let mut dirs = vec![ws_str];
    let canon_ws = std::fs::canonicalize(workspace).unwrap_or_else(|_| workspace.to_path_buf());
    let Ok(entries) = std::fs::read_dir(workspace) else {
        return dirs;
    };
    let mut subdirs: Vec<String> = entries
        .flatten()
        .filter_map(|e| {
            let p = e.path();
            if !p.is_dir() {
                return None;
            }
            let name = p.file_name()?.to_str()?;
            if name.starts_with('.') || CWD_SKIP_DIRS.contains(&name) {
                return None;
            }
            let canon_p = std::fs::canonicalize(&p).ok()?;
            if !canon_p.starts_with(&canon_ws) {
                return None;
            }
            Some(p.to_string_lossy().into_owned())
        })
        .collect();
    subdirs.sort();
    subdirs.truncate(14);
    dirs.extend(subdirs);
    dirs
}

/// Render or edit workspace directory selector (`cwd:list`, `cwd:{idx}`).
pub async fn show_cwd(
    ctx: &Arc<BotCtx>,
    cq: Option<&CallbackQuery>,
    chat_id: i64,
    uid: i64,
    arg: &str,
) {
    let choices = cwd_choices(&ctx.cfg.agy_workspace);
    if let Ok(idx) = arg.trim().parse::<usize>() {
        if let Some(chosen) = choices.get(idx) {
            let next_cwd = if idx == 0 { None } else { Some(chosen.clone()) };
            if let Err(err) = ctx.store.update_user(uid, |u| {
                u.cwd = next_cwd;
                u.conversation_id = None;
            }) {
                warn!(uid, error = %err, "failed updating cwd");
            }
        }
    }

    let cur = effective_cwd(ctx, uid);
    let mut rows: Vec<Vec<InlineKeyboardButton>> = Vec::new();
    for (chunk_idx, pair) in choices.chunks(2).enumerate() {
        let base = chunk_idx * 2;
        let row = pair
            .iter()
            .enumerate()
            .map(|(j, c)| {
                let global_idx = base + j;
                let mark = if c == &cur { "✅ " } else { "" };
                let name = if global_idx == 0 {
                    "agy-workspace".to_string()
                } else {
                    Path::new(c)
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or(c.as_str())
                        .to_string()
                };
                ctx.btn(
                    "",
                    &format!("{mark}{name}"),
                    Some(&format!("cwd:{global_idx}")),
                    None,
                    None,
                )
            })
            .collect();
        rows.push(row);
    }
    let lang = ctx.lang(uid);
    rows.push(vec![
        ctx.btn("", "« Advanced", Some("adv"), None, None),
        ctx.btn("menu", t(lang, Tx::BtnMenu), Some("home"), None, None),
    ]);

    let text = format!(
        "{} <b>{}</b>\n<blockquote><code>{}</code></blockquote>\n\
        <i>/cwd /path</i>",
        ctx.e("folder"),
        t(lang, Tx::PanelCwdTitle),
        esc(&cur)
    );
    ctx.edit_or_send(cq, chat_id, &text, Some(BotCtx::kb(rows)))
        .await;
}

async fn fetch_agent_names(ctx: &BotCtx, uid: i64) -> Vec<String> {
    let Ok((rc, out, _)) = ctx.agy_cmd_for(Some(uid), &["agents"], 30.0).await else {
        return Vec::new();
    };
    if rc != 0 {
        return Vec::new();
    }
    let mut names = Vec::new();
    for line in out.lines() {
        let trimmed = line.trim();
        let low = trimmed.to_ascii_lowercase();
        if trimmed.is_empty()
            || low.starts_with("name")
            || low.starts_with("available")
            || low.starts_with("no ")
        {
            continue;
        }
        if let Some(first) = trimmed.split_whitespace().next() {
            if let Some(tok) = first.split('\t').next() {
                if !tok.is_empty() {
                    names.push(tok.to_string());
                    if names.len() >= 20 {
                        break;
                    }
                }
            }
        }
    }
    names
}

/// Render or edit custom agent selector (`agent:list`, `agent:-`, `agent:set:{name}`).
pub async fn show_agents(ctx: &Arc<BotCtx>, cq: Option<&CallbackQuery>, chat_id: i64, uid: i64) {
    let u = ctx.store.get_user(uid);
    let names = fetch_agent_names(ctx, uid).await;

    let def_mark = if u.agent.as_deref().is_none_or(str::is_empty) {
        "✅ "
    } else {
        ""
    };
    let mut rows: Vec<Vec<InlineKeyboardButton>> = vec![vec![ctx.btn(
        "",
        &format!("{def_mark}Default"),
        Some("agent:-"),
        None,
        None,
    )]];

    for pair in names.chunks(2) {
        let row = pair
            .iter()
            .map(|n| {
                let mark = if u.agent.as_deref() == Some(n.as_str()) {
                    "✅ "
                } else {
                    ""
                };
                let label = format!("{mark}{}", truncate_chars(n, 28));
                let cb_name = truncate_utf8_bytes(n, 50);
                ctx.btn("", &label, Some(&format!("agent:set:{cb_name}")), None, None)
            })
            .collect();
        rows.push(row);
    }
    let lang = ctx.lang(uid);
    rows.push(vec![
        ctx.btn("", "« Advanced", Some("adv"), None, None),
        ctx.btn("menu", t(lang, Tx::BtnMenu), Some("home"), None, None),
    ]);

    let body = if names.is_empty() {
        "No custom agents defined (<code>agy agents</code>).".to_string()
    } else {
        format!("{} custom agent(s)", names.len())
    };
    let html = format!("🤖 <b>Agent</b>\n<blockquote>{body}</blockquote>");
    ctx.edit_or_send(cq, chat_id, &html, Some(BotCtx::kb(rows)))
        .await;
}

/// Render or edit `agy changelog` release notes.
pub async fn show_changelog(ctx: &Arc<BotCtx>, cq: Option<&CallbackQuery>, chat_id: i64, uid: i64) {
    let first = match ctx.agy_cmd_for(Some(uid), &["changelog"], 30.0).await {
        Ok((_, out, _)) => {
            let trimmed = out.trim();
            if trimmed.is_empty() {
                "(empty)".to_string()
            } else {
                let head = trimmed.split("\n\n").next().unwrap_or(trimmed);
                truncate_chars(head, 3000)
            }
        }
        Err(err) => truncate_chars(&redact_secrets_in_text(&err.to_string()), 500),
    };

    let html = format!(
        "{} <b>agy changelog</b>\n<blockquote expandable>{}</blockquote>",
        ctx.e("doc"),
        esc(&first)
    );
    let mk = BotCtx::kb(vec![vec![ctx.btn("", "« Advanced", Some("adv"), None, None)]]);
    ctx.edit_or_send(cq, chat_id, &html, Some(mk)).await;
}

/// Render or edit network, proxy pool, and polling health diagnostics (`net`, `net:refresh`, `net:rebuild`).
pub async fn show_net(ctx: &Arc<BotCtx>, cq: Option<&CallbackQuery>, chat_id: i64, uid: i64) {
    let lang = ctx.lang(uid);
    let snap = ctx.health.snapshot();
    let pool_snap = ctx.pool.snapshot();
    let now = now_unix_secs();

    let getme_str = if snap.last_getme_ok > 0.0 {
        format!("{:.0}s ago", (now - snap.last_getme_ok).max(0.0))
    } else {
        "—".to_string()
    };

    let mut rows: Vec<(&str, String)> = vec![
        ("Transport", snap.mode),
        ("Last poll ok", format!("{:.0}s ago", ctx.health.stall_secs())),
        (
            "Poll failures",
            format!("{} now / {} total", snap.poll_failures, snap.total_poll_failures),
        ),
        ("Updates", snap.updates.to_string()),
        (
            "Proxy pool",
            format!(
                "{} · {}/{} healthy",
                pool_snap.mode,
                pool_snap.active_healthy,
                pool_snap.routes.len()
            ),
        ),
        ("Session rebuilds", pool_snap.total_rebuilds.to_string()),
        ("Queued sends", ctx.outbox.len().to_string()),
        ("getMe ok", getme_str),
        (
            "IPv4 only",
            if ctx.cfg.force_ipv4 { "yes" } else { "no" }.to_string(),
        ),
    ];

    for r in pool_snap.routes.iter().take(6) {
        let lat = r
            .ewma_latency_ms
            .map(|ms| format!(" {ms:.0}ms"))
            .unwrap_or_default();
        rows.push((
            "Route",
            format!("{} [{}]{}", r.label, r.state, lat),
        ));
    }

    let table = align_kv_table(&rows);
    let html = format!("📡 <b>{}</b>\n<pre>{}</pre>", t(lang, Tx::PanelNetTitle), esc(&table));
    let mut act_row = vec![
        ctx.btn("refresh", t(lang, Tx::BtnRefresh), Some("net:refresh"), None, None),
        ctx.btn("", &format!("🌐 {}", t(lang, Tx::BtnProxies)), Some("px:list"), None, None),
    ];
    if ctx.is_owner(uid) {
        act_row.push(ctx.btn("bolt", "Rebuild", Some("net:rebuild"), None, None));
    }
    let back_row = if ctx.has_perm(uid, "settings_access") {
        vec![ctx.btn("", &format!("« {}", t(lang, Tx::PanelAdvancedTitle)), Some("adv"), None, None)]
    } else {
        ctx.back_row_for(uid)
    };
    let mk = BotCtx::kb(vec![act_row, back_row]);
    ctx.edit_or_send(cq, chat_id, &html, Some(mk)).await;
}

/// Render or edit the persistent Cron & Sync scheduler view (`cron`, `cron:run:*`, `cron:tog:*`).
pub async fn show_cron(ctx: &Arc<BotCtx>, cq: Option<&CallbackQuery>, chat_id: i64, uid: i64) {
    let lang = ctx.lang(uid);
    let is_owner = ctx.is_owner(uid);
    let jobs = ctx.cron.list_jobs();
    let mut lines: Vec<String> = vec![format!(
        "🕒 <b>{}</b> (<i>{}</i>)",
        t(lang, Tx::PanelCronTitle),
        if ctx.cfg.cron_enabled {
            t(lang, Tx::EnabledWord)
        } else {
            t(lang, Tx::DisabledWord)
        }
    )];
    let mut rows: Vec<Vec<InlineKeyboardButton>> = Vec::new();

    for j in &jobs {
        let st_icon = match j.status {
            CronJobStatus::Ok => "✅",
            CronJobStatus::Running => "⏳",
            CronJobStatus::Error => "❌",
            CronJobStatus::Disabled => "⏸",
            CronJobStatus::Idle => "○",
        };
        let detail = if let Some(ref err) = j.last_error {
            format!("err: {}", truncate_chars(&redact_secrets_in_text(err), 70))
        } else if let Some(ref sum) = j.last_summary {
            truncate_chars(&redact_secrets_in_text(sum), 70)
        } else {
            format!("runs: {}", j.run_count)
        };
        lines.push(format!(
            "<blockquote>{st_icon} <code>{}</code> · <code>{}</code>\n{}</blockquote>",
            esc(&j.id),
            esc(&j.schedule),
            esc(&detail)
        ));

        if is_owner {
            let tog_lbl = if j.enabled { "✓ ON" } else { "○ OFF" };
            let run_cb = format!("cron:run:{}", truncate_utf8_bytes(&j.id, 55));
            let tog_cb = format!("cron:tog:{}", truncate_utf8_bytes(&j.id, 55));
            rows.push(vec![
                ctx.btn("", &format!("▶ {}", j.id), Some(&run_cb), None, None),
                ctx.btn("", tog_lbl, Some(&tog_cb), None, None),
            ]);
        }
    }

    if let Some(mcp_sum) = ctx.cron.cached_mcp_health() {
        lines.push(format!(
            "<i>MCP cache: {}/{} enabled</i>",
            mcp_sum.enabled_configured, mcp_sum.total_configured
        ));
    }
    if let Some(mem_sum) = ctx.cron.cached_memory_summary() {
        lines.push(format!(
            "<i>Memory cache: {} total ({} recent 24h)</i>",
            mem_sum.total, mem_sum.recent_24h
        ));
    }

    rows.push(vec![
        ctx.btn("refresh", t(lang, Tx::BtnRefresh), Some("cron:refresh"), None, None),
        ctx.btn("menu", t(lang, Tx::BtnMenu), Some("home"), None, None),
    ]);

    ctx.edit_or_send(cq, chat_id, &lines.join("\n"), Some(BotCtx::kb(rows)))
        .await;
}

// ---------------------------------------------------------------------------
// Slash Command Handlers
// ---------------------------------------------------------------------------

/// Handle `/start`.
pub async fn cmd_start(ctx: &Arc<BotCtx>, msg: &Message, _arg: &str) {
    let Some(uid) = msg_uid(msg) else {
        return;
    };
    ctx.jobs.clear_awaiting(uid);
    if !ctx.commands_set.contains_key(&uid) {
        ctx.sync_user_commands(uid).await;
    }
    show_home(ctx, None, msg.chat.id, uid).await;
}

/// Handle `/menu`.
pub async fn cmd_menu(ctx: &Arc<BotCtx>, msg: &Message, arg: &str) {
    cmd_start(ctx, msg, arg).await;
}

/// Handle `/help`.
pub async fn cmd_help(ctx: &Arc<BotCtx>, msg: &Message, _arg: &str) {
    let Some(uid) = msg_uid(msg) else {
        return;
    };
    let mk = BotCtx::kb(vec![ctx.back_row_for(uid)]);
    let _ = ctx
        .render
        .send_html_simple(msg.chat.id, &help_text_for(ctx, uid), Some(mk))
        .await;
}

/// Handle `/lang [fa|en|la|zh|ru]`.
pub async fn cmd_lang(ctx: &Arc<BotCtx>, msg: &Message, arg: &str) {
    let Some(uid) = msg_uid(msg) else {
        return;
    };
    let a = arg.trim();
    if !a.is_empty() {
        let Some(chosen) = Lang::from_code(a) else {
            let lang = ctx.lang(uid);
            let txt = format!("{} {}", ctx.e("warn"), t(lang, Tx::LangInvalidArg));
            let _ = ctx.render.send_html_simple(msg.chat.id, &txt, None).await;
            return;
        };
        if let Err(err) = set_user_lang(ctx, uid, chosen) {
            warn!(uid, error = %err, "failed saving language");
        }
        ctx.sync_user_commands(uid).await;
    }
    show_language(ctx, None, msg.chat.id, uid).await;
}

/// Handle `/new`.
pub async fn cmd_new(ctx: &Arc<BotCtx>, msg: &Message, _arg: &str) {
    let Some(uid) = msg_uid(msg) else {
        return;
    };
    let lang = ctx.lang(uid);
    if ctx.jobs.is_user_busy(uid) {
        let txt = format!("⏳ {}", t(lang, Tx::WorkingNotice));
        let _ = ctx
            .render
            .send_html_simple(msg.chat.id, &txt, None)
            .await;
        return;
    }
    ctx.jobs.clear_awaiting(uid);
    if let Err(err) = ctx.store.update_user(uid, |u| {
        u.conversation_id = None;
    }) {
        warn!(uid, error = %err, "failed clearing conversation_id on /new");
    }
    agy_ext::agent_runtime::clear_session_history(&ctx.cfg.state_dir, &format!("uncensored_{uid}"));
    agy_ext::agent_runtime::clear_session_history(&ctx.cfg.state_dir, &format!("grok_{uid}"));
    let txt = format!(
        "{} <b>{}</b>",
        ctx.e("new"),
        t(lang, Tx::NewChatStarted)
    );
    let _ = ctx.render.send_html_simple(msg.chat.id, &txt, None).await;
}

/// Handle `/stop`.
pub async fn cmd_stop(ctx: &Arc<BotCtx>, msg: &Message, _arg: &str) {
    let Some(uid) = msg_uid(msg) else {
        return;
    };
    let lang = ctx.lang(uid);
    let stopped = ctx.jobs.stop_user(uid).await;
    let txt = if stopped {
        format!("⏹ <i>{}</i>", t(lang, Tx::StoppingTask))
    } else {
        format!("<i>{}</i>", t(lang, Tx::NoRunningTask))
    };
    let _ = ctx.render.send_html_simple(msg.chat.id, &txt, None).await;
}

/// Handle `/cancel`.
pub async fn cmd_cancel(ctx: &Arc<BotCtx>, msg: &Message, _arg: &str) {
    let Some(uid) = msg_uid(msg) else {
        return;
    };
    let lang = ctx.lang(uid);
    let had = ctx.jobs.clear_awaiting(uid);
    let txt = if had {
        format!("✖ <i>{}</i>", t(lang, Tx::CancellingInput))
    } else {
        format!("<i>{}</i>", t(lang, Tx::NothingToCancel))
    };
    let _ = ctx.render.send_html_simple(msg.chat.id, &txt, None).await;
}

/// Handle `/model`.
pub async fn cmd_model(ctx: &Arc<BotCtx>, msg: &Message, arg: &str) {
    let Some(uid) = msg_uid(msg) else {
        return;
    };
    if deny_cmd_perm(ctx, msg.chat.id, uid, "models_switch").await {
        return;
    }
    let a = arg.trim();
    if !a.is_empty() {
        if a.eq_ignore_ascii_case("default") || a == "-" {
            let _ = ctx.store.update_user(uid, |u| {
                u.model = None;
                u.extra.remove("engine");
                u.extra.remove(crate::jobs::model_pick::MODEL_INVALID_KEY);
            });
            ctx.jobs.clear_model_choices(uid);
            let _ = ctx
                .render
                .send_html_simple(msg.chat.id, "Model → <b>default</b> (Antigravity)", None)
                .await;
            return;
        }
        let models = ctx.models_for_user(uid).1;
        if let Some(found) = models
            .iter()
            .find(|m| m.id == a || m.name.eq_ignore_ascii_case(a))
        {
            let mid = found.id.clone();
            let mname = found.name.clone();
            let _ = ctx.store.update_user(uid, |u| {
                u.model = Some(mid);
                u.extra.remove("engine");
                u.extra.remove(crate::jobs::model_pick::MODEL_INVALID_KEY);
            });
            ctx.jobs.clear_model_choices(uid);
            let _ = ctx
                .render
                .send_html_simple(
                    msg.chat.id,
                    &format!("Model → <b>{}</b>", esc(&mname)),
                    None,
                )
                .await;
            return;
        }
        let _ = ctx
            .render
            .send_html_simple(
                msg.chat.id,
                &format!("⚠️ <code>{}</code> is not available on your current account. Pick one below.", esc(a)),
                None,
            )
            .await;
    }
    show_models(ctx, None, msg.chat.id, uid, 0).await;
}

/// Handle `/status`.
pub async fn cmd_status(ctx: &Arc<BotCtx>, msg: &Message, _arg: &str) {
    let Some(uid) = msg_uid(msg) else {
        return;
    };
    if deny_cmd_perm(ctx, msg.chat.id, uid, "status_net").await {
        return;
    }
    show_status(ctx, None, msg.chat.id, uid).await;
}

/// Handle `/limits` (owner only).
pub async fn cmd_limits(ctx: &Arc<BotCtx>, msg: &Message, _arg: &str) {
    let Some(uid) = msg_uid(msg) else {
        return;
    };
    show_limits(ctx, None, msg.chat.id, uid).await;
}

/// Handle `/settings`.
pub async fn cmd_settings(ctx: &Arc<BotCtx>, msg: &Message, _arg: &str) {
    let Some(uid) = msg_uid(msg) else {
        return;
    };
    if deny_cmd_perm(ctx, msg.chat.id, uid, "settings_access").await {
        return;
    }
    show_settings(ctx, None, msg.chat.id, uid).await;
}

/// Handle `/effort [level]`.
pub async fn cmd_effort(ctx: &Arc<BotCtx>, msg: &Message, arg: &str) {
    let Some(uid) = msg_uid(msg) else {
        return;
    };
    if deny_cmd_perm(ctx, msg.chat.id, uid, "settings_access").await {
        return;
    }
    let a = arg.trim().to_ascii_lowercase();
    if EFFORTS.contains(&a.as_str()) {
        let val = if a == "default" { None } else { Some(a.clone()) };
        if let Err(err) = ctx.store.update_user(uid, |u| {
            u.effort = val;
        }) {
            warn!(uid, error = %err, "failed updating effort");
        }
        let _ = ctx
            .render
            .send_html_simple(msg.chat.id, &format!("Effort → <b>{}</b>", esc(&a)), None)
            .await;
    } else {
        show_settings(ctx, None, msg.chat.id, uid).await;
    }
}

/// Handle `/mode [auto|accept-edits|plan]`.
pub async fn cmd_mode(ctx: &Arc<BotCtx>, msg: &Message, arg: &str) {
    let Some(uid) = msg_uid(msg) else {
        return;
    };
    if deny_cmd_perm(ctx, msg.chat.id, uid, "settings_access").await {
        return;
    }
    let a = arg.trim().to_ascii_lowercase();
    if MODES.contains(&a.as_str()) {
        let val = if a == "auto" { None } else { Some(a.clone()) };
        if let Err(err) = ctx.store.update_user(uid, |u| {
            u.mode = val;
        }) {
            warn!(uid, error = %err, "failed updating mode");
        }
        let _ = ctx
            .render
            .send_html_simple(msg.chat.id, &format!("Mode → <b>{}</b>", esc(&a)), None)
            .await;
    } else {
        show_settings(ctx, None, msg.chat.id, uid).await;
    }
}

/// Handle `/resume [conversation_id]`.
pub async fn cmd_resume(ctx: &Arc<BotCtx>, msg: &Message, arg: &str) {
    let Some(uid) = msg_uid(msg) else {
        return;
    };
    if deny_cmd_perm(ctx, msg.chat.id, uid, "dashboard_access").await {
        return;
    }
    let a = arg.trim();
    if !a.is_empty() {
        let conv = truncate_chars(a, 120);
        if let Err(err) = ctx.store.update_user(uid, |u| {
            u.conversation_id = Some(conv.clone());
        }) {
            warn!(uid, error = %err, "failed updating conversation_id");
        }
        let short = BotCtx::short(Some(&conv), 24);
        let _ = ctx
            .render
            .send_html_simple(
                msg.chat.id,
                &format!("Resuming <code>{}</code>", esc(&short)),
                None,
            )
            .await;
    } else {
        show_sessions(ctx, None, msg.chat.id, uid).await;
    }
}

/// Handle `/cwd [path]`, enforcing `settings_access` and `root_access` for directories outside `agy_workspace`.
pub async fn cmd_cwd(ctx: &Arc<BotCtx>, msg: &Message, arg: &str) {
    let Some(uid) = msg_uid(msg) else {
        return;
    };
    if deny_cmd_perm(ctx, msg.chat.id, uid, "settings_access").await {
        return;
    }
    let a = arg.trim();
    if a.is_empty() {
        show_cwd(ctx, None, msg.chat.id, uid, "list").await;
        return;
    }

    let expanded = expand_tilde(a);
    if !expanded.is_dir() {
        let txt = format!("{} Not a directory: <code>{}</code>", ctx.e("warn"), esc(a));
        let _ = ctx.render.send_html_simple(msg.chat.id, &txt, None).await;
        return;
    }

    let Ok(canon_target) = std::fs::canonicalize(&expanded) else {
        let txt = format!("{} Not a directory: <code>{}</code>", ctx.e("warn"), esc(a));
        let _ = ctx.render.send_html_simple(msg.chat.id, &txt, None).await;
        return;
    };

    let canon_ws = std::fs::canonicalize(&ctx.cfg.agy_workspace)
        .unwrap_or_else(|_| ctx.cfg.agy_workspace.clone());
    let inside = canon_target.starts_with(&canon_ws);

    if !inside && !ctx.has_perm(uid, "root_access") {
        let txt = format!(
            "{} Root access permission required for folders outside workspace.",
            ctx.e("warn")
        );
        let _ = ctx.render.send_html_simple(msg.chat.id, &txt, None).await;
        return;
    }

    let resolved_str = canon_target.to_string_lossy().into_owned();
    if let Err(err) = ctx.store.update_user(uid, |u| {
        u.cwd = Some(resolved_str.clone());
        u.conversation_id = None;
    }) {
        warn!(uid, error = %err, "failed updating cwd");
    }
    let txt = format!(
        "{} Workspace → <code>{}</code> · new chat",
        ctx.e("folder"),
        esc(&resolved_str)
    );
    let _ = ctx.render.send_html_simple(msg.chat.id, &txt, None).await;
}

/// Handle `/agent [name|-|default]`.
pub async fn cmd_agent(ctx: &Arc<BotCtx>, msg: &Message, arg: &str) {
    let Some(uid) = msg_uid(msg) else {
        return;
    };
    if deny_cmd_perm(ctx, msg.chat.id, uid, "settings_access").await {
        return;
    }
    let a = arg.trim();
    if a.is_empty() {
        show_agents(ctx, None, msg.chat.id, uid).await;
        return;
    }
    let next_agent = if a == "-" || a.eq_ignore_ascii_case("default") {
        None
    } else {
        Some(truncate_chars(a, 50))
    };
    if let Err(err) = ctx.store.update_user(uid, |u| {
        u.agent = next_agent.clone();
    }) {
        warn!(uid, error = %err, "failed updating agent");
    }
    let lbl = next_agent.as_deref().unwrap_or("default");
    let _ = ctx
        .render
        .send_html_simple(
            msg.chat.id,
            &format!("🤖 Agent → <b>{}</b>", esc(lbl)),
            None,
        )
        .await;
}

/// Handle `/trace`.
pub async fn cmd_trace(ctx: &Arc<BotCtx>, msg: &Message, _arg: &str) {
    let Some(uid) = msg_uid(msg) else {
        return;
    };
    if deny_cmd_perm(ctx, msg.chat.id, uid, "settings_access").await {
        return;
    }
    let next = ctx
        .store
        .update_user(uid, |u| {
            u.trace = !u.trace;
            u.trace
        })
        .unwrap_or(false);
    let txt = format!("🧭 Tool trace <b>{}</b>", if next { "on" } else { "off" });
    let _ = ctx.render.send_html_simple(msg.chat.id, &txt, None).await;
}

/// Handle `/changelog`.
pub async fn cmd_changelog(ctx: &Arc<BotCtx>, msg: &Message, _arg: &str) {
    let Some(uid) = msg_uid(msg) else {
        return;
    };
    if deny_cmd_perm(ctx, msg.chat.id, uid, "settings_access").await {
        return;
    }
    show_changelog(ctx, None, msg.chat.id, uid).await;
}

/// Handle `/net`.
pub async fn cmd_net(ctx: &Arc<BotCtx>, msg: &Message, _arg: &str) {
    let Some(uid) = msg_uid(msg) else {
        return;
    };
    if deny_cmd_perm(ctx, msg.chat.id, uid, "status_net").await {
        return;
    }
    show_net(ctx, None, msg.chat.id, uid).await;
}

/// Handle `/cron [run <id>|enable <id>|disable <id>]`.
pub async fn cmd_cron(ctx: &Arc<BotCtx>, msg: &Message, arg: &str) {
    let Some(uid) = msg_uid(msg) else {
        return;
    };
    if deny_cmd_perm(ctx, msg.chat.id, uid, "status_net").await {
        return;
    }
    let parts: Vec<&str> = arg.split_whitespace().collect();
    if parts.len() >= 2 {
        if !ctx.is_owner(uid) {
            let _ = ctx
                .render
                .send_html_simple(msg.chat.id, &owner_only_html(ctx, uid), None)
                .await;
            return;
        }
        let sub = parts[0];
        let id = parts[1];
        match sub {
            "run" => {
                let _ = ctx.cron.run_now(id).await;
            }
            "enable" => {
                let _ = ctx.cron.set_enabled(id, true);
            }
            "disable" => {
                let _ = ctx.cron.set_enabled(id, false);
            }
            _ => {}
        }
    }
    show_cron(ctx, None, msg.chat.id, uid).await;
}

// ---------------------------------------------------------------------------
// Callback Router
// ---------------------------------------------------------------------------

async fn apply_model_selection(ctx: &Arc<BotCtx>, cq: &CallbackQuery, uid: i64, chat_id: i64, raw: &str) {
    let mut page = 0usize;
    let ms = ctx.models_for_user(uid).1;
    let mut unknown = false;
    let new_model = if raw == "default" {
        Some(None)
    } else if let Some(id) = raw.strip_prefix('=') {
        match ms.iter().position(|m| m.id == id) {
            Some(i) => {
                page = i / MODELS_PER_PAGE;
                Some(Some(id.to_string()))
            }
            None => {
                unknown = true;
                None
            }
        }
    } else if let Ok(idx) = raw.parse::<usize>() {
        page = idx / MODELS_PER_PAGE;
        ms.get(idx).map(|m| Some(m.id.clone()))
    } else if !raw.is_empty() && ms.iter().any(|m| m.id == raw) {
        Some(Some(raw.to_string()))
    } else {
        None
    };

    if let Some(m_opt) = new_model {
        let _ = ctx.store.update_user(uid, |u| {
            u.model = m_opt;
            u.extra.remove("engine");
            u.extra.remove(crate::jobs::model_pick::MODEL_INVALID_KEY);
        });
        ctx.jobs.clear_model_choices(uid);
    }
    if unknown {
        ctx.ack(&cq.id, Some("That model is no longer in this account's list"), true).await;
        show_models(ctx, Some(cq), chat_id, uid, 0).await;
        return;
    }
    let cur = ctx.store.get_user(uid).model;
    let lbl = ctx.model_label(cur.as_deref());
    ctx.ack(&cq.id, Some(&format!("Model: {lbl}")), false).await;
    show_models(ctx, Some(cq), chat_id, uid, page).await;
}

async fn handle_set_cb(
    ctx: &Arc<BotCtx>,
    cq: &CallbackQuery,
    uid: i64,
    chat_id: i64,
    rest: &str,
) {
    let Some((key, val)) = rest.split_once(':') else {
        ctx.ack(&cq.id, None, false).await;
        return;
    };

    if key == "secret_scan" {
        if !ctx.is_owner(uid) {
            ctx.ack(&cq.id, Some(t(ctx.lang(uid), Tx::OwnerOnly)), true).await;
            return;
        }
        let mut lim = ctx.jobs.runtime_limits();
        lim.outbox_secret_scan = !lim.outbox_secret_scan;
        let on = lim.outbox_secret_scan;
        ctx.jobs.set_runtime_limits(lim);
        let toast = format!("🛡 Outbox Secret Scan: {}", if on { "ON" } else { "OFF" });
        ctx.ack(&cq.id, Some(&toast), false).await;
        show_settings(ctx, Some(cq), chat_id, uid).await;
        return;
    }

    if key == "skip_permissions" && !ctx.has_perm(uid, "root_access") {
        ctx.ack(&cq.id, Some("Root access required"), true).await;
        return;
    }

    let parallel_ok = ctx.has_perm(uid, crate::jobs::parallel::PARALLEL_PERM);
    if key == "parallel" && !parallel_ok {
        ctx.ack(&cq.id, Some("Parallel mode is not enabled for you"), true).await;
        return;
    }
    let _ = ctx.store.update_user(uid, |u| match key {
        "mode" if MODES.contains(&val) => {
            u.mode = if val == "auto" {
                None
            } else {
                Some(val.to_string())
            };
        }
        "effort" if EFFORTS.contains(&val) => {
            u.effort = if val == "default" {
                None
            } else {
                Some(val.to_string())
            };
        }
        "skip_permissions" => {
            u.skip_permissions = !u.skip_permissions;
        }
        "stream_mode" if STREAM_MODES.contains(&val) => {
            u.stream_mode = val.to_string();
            u.stream = true;
        }
        "stream" => {
            u.stream = !u.stream;
        }
        "trace" => {
            u.trace = !u.trace;
        }
        "parallel" if parallel_ok => {
            let n: u64 = val.parse().unwrap_or(0);
            let n = if n >= 2 { n.min(crate::jobs::parallel::PARALLEL_MAX as u64) } else { 0 };
            u.extra.insert(
                crate::jobs::parallel::PARALLEL_SETTING_KEY.to_string(),
                serde_json::json!(n),
            );
        }
        "render" => {
            u.render = if u.render == "rich" {
                "html".to_string()
            } else {
                "rich".to_string()
            };
        }
        _ => {}
    });

    ctx.ack(&cq.id, None, false).await;
    if key == "trace" {
        show_advanced(ctx, Some(cq), chat_id, uid).await;
    } else {
        show_settings(ctx, Some(cq), chat_id, uid).await;
    }
}

async fn clear_cq_markup(ctx: &BotCtx, cq: &CallbackQuery, chat_id: i64) {
    if let Some(ref m) = cq.message {
        let payload = serde_json::json!({
            "chat_id": chat_id,
            "message_id": m.message_id
        });
        let _ = ctx
            .client
            .call_json::<Value>("editMessageReplyMarkup", &payload, None)
            .await;
    }
}

/// Dispatch system/menu/settings/network/cron/retry callback queries.
/// Returns `true` if `data` was handled by this module.
pub async fn handle_system_cb(
    ctx: &Arc<BotCtx>,
    cq: &CallbackQuery,
    uid: i64,
    chat_id: i64,
    data: &str,
) -> bool {
    if data == "home" {
        ctx.jobs.clear_awaiting(uid);
        ctx.ack(&cq.id, None, false).await;
        show_home_page(ctx, Some(cq), chat_id, uid, 0).await;
        return true;
    }
    if let Some(p_str) = data.strip_prefix("home:") {
        let page = p_str.parse::<usize>().unwrap_or(0);
        ctx.jobs.clear_awaiting(uid);
        ctx.ack(&cq.id, None, false).await;
        show_home_page(ctx, Some(cq), chat_id, uid, page).await;
        return true;
    }
    if data == "lang:menu" {
        ctx.ack(&cq.id, None, false).await;
        show_language(ctx, Some(cq), chat_id, uid).await;
        return true;
    }
    if let Some(code) = data.strip_prefix("lang:") {
        let Some(chosen) = Lang::from_code(code) else {
            ctx.ack(&cq.id, Some(t(ctx.lang(uid), Tx::LangInvalidArg)), true).await;
            return true;
        };
        let _ = set_user_lang(ctx, uid, chosen);
        ctx.sync_user_commands(uid).await;
        ctx.ack(&cq.id, Some(t(chosen, Tx::LangUpdatedToast)), false).await;
        show_language(ctx, Some(cq), chat_id, uid).await;
        return true;
    }
    if data == "inp:cancel" {
        ctx.jobs.clear_awaiting(uid);
        let lang = ctx.lang(uid);
        ctx.ack(&cq.id, Some(t(lang, Tx::CancellingInput)), false).await;
        let md = format!("### {} {}", ctx.premium.md("ok"), t(lang, Tx::CancellingInput));
        let msg_id = cq.message.as_ref().map(|m| m.message_id);
        let _ = ctx
            .render
            .edit_or_send_rich(chat_id, msg_id, &md, Some(BotCtx::kb(vec![ctx.back_row_for(uid)])))
            .await;
        return true;
    }
    if data == "new" {
        let lang = ctx.lang(uid);
        if ctx.jobs.is_user_busy(uid) {
            ctx.ack(&cq.id, Some(t(lang, Tx::WorkingNotice)), true).await;
            return true;
        }
        ctx.jobs.clear_awaiting(uid);
        let _ = ctx.store.update_user(uid, |u| {
            u.conversation_id = None;
        });
        agy_ext::agent_runtime::clear_session_history(&ctx.cfg.state_dir, &format!("uncensored_{uid}"));
        agy_ext::agent_runtime::clear_session_history(&ctx.cfg.state_dir, &format!("grok_{uid}"));
        ctx.ack(&cq.id, Some(t(lang, Tx::NewChatStarted)), false).await;
        show_home(ctx, Some(cq), chat_id, uid).await;
        return true;
    }
    if data == "stop" {
        let lang = ctx.lang(uid);
        let stopped = ctx.jobs.stop_user(uid).await;
        let msg = if stopped {
            t(lang, Tx::StoppingTask)
        } else {
            t(lang, Tx::NoRunningTask)
        };
        ctx.ack(&cq.id, Some(msg), false).await;
        return true;
    }
    if data == "models_refresh" || data == "models:refresh" {
        if deny_cb_perm(ctx, cq, uid, "models_switch").await {
            return true;
        }
        ctx.ack(&cq.id, Some("Refreshing this account's models…"), false).await;
        let _ = ctx.refresh_models_for_user(uid).await;
        show_models(ctx, Some(cq), chat_id, uid, 0).await;
        return true;
    }
    if let Some(rest) = data.strip_prefix("models:") {
        if deny_cb_perm(ctx, cq, uid, "models_switch").await {
            return true;
        }
        let page = rest.parse::<usize>().unwrap_or(0);
        ctx.ack(&cq.id, None, false).await;
        show_models(ctx, Some(cq), chat_id, uid, page).await;
        return true;
    }
    if let Some(rest) = data
        .strip_prefix("model:")
        .or_else(|| data.strip_prefix("setmodel:"))
    {
        if deny_cb_perm(ctx, cq, uid, "models_switch").await {
            return true;
        }
        apply_model_selection(ctx, cq, uid, chat_id, rest).await;
        return true;
    }
    if data == "status" {
        if deny_cb_perm(ctx, cq, uid, "status_net").await {
            return true;
        }
        ctx.ack(&cq.id, None, false).await;
        show_status(ctx, Some(cq), chat_id, uid).await;
        return true;
    }
    if data == "limits" || data.starts_with("lim:") {
        if !ctx.is_owner(uid) {
            ctx.ack(&cq.id, Some(t(ctx.lang(uid), Tx::OwnerOnly)), true).await;
            return true;
        }
        if let Some(action) = data.strip_prefix("lim:") {
            let mut lim = ctx.jobs.runtime_limits();
            let toast: String = match action {
                "prof:strict" => {
                    lim.max_tool_steps = 60;
                    lim.tool_repeat_limit = 3;
                    lim.max_tools_per_min = 30;
                    lim.job_timeout_secs = 20 * 60;
                    lim.max_global_ai_jobs = 2;
                    lim.max_queue_per_user = 2;
                    lim.tg_user_rl_per_min = 20;
                    lim.outbox_secret_scan = true;
                    ctx.tg_rl.set_rate(20, 20);
                    "Strict AI Safety profile active".to_string()
                }
                "prof:std" => {
                    lim.max_tool_steps = 80;
                    lim.tool_repeat_limit = 4;
                    lim.max_tools_per_min = 45;
                    lim.job_timeout_secs = 30 * 60;
                    lim.max_global_ai_jobs = 4;
                    lim.max_queue_per_user = 3;
                    lim.tg_user_rl_per_min = 30;
                    lim.outbox_secret_scan = true;
                    ctx.tg_rl.set_rate(30, 30);
                    "Standard Safe limits applied".to_string()
                }
                "prof:high" => {
                    lim.max_tool_steps = 140;
                    lim.tool_repeat_limit = 6;
                    lim.max_tools_per_min = 75;
                    lim.job_timeout_secs = 45 * 60;
                    lim.max_global_ai_jobs = 6;
                    lim.max_queue_per_user = 5;
                    lim.tg_user_rl_per_min = 60;
                    lim.outbox_secret_scan = true;
                    ctx.tg_rl.set_rate(60, 60);
                    "Extended guarded limits applied".to_string()
                }
                "steps" => {
                    lim.max_tool_steps = match lim.max_tool_steps {
                        0..=45 => 60,
                        46..=65 => 80,
                        66..=95 => 120,
                        96..=135 => 160,
                        _ => 40,
                    };
                    format!("Max steps: {}", lim.max_tool_steps)
                }
                "rep" => {
                    lim.tool_repeat_limit = match lim.tool_repeat_limit {
                        0..=3 => 4,
                        4 => 6,
                        5..=7 => 8,
                        _ => 3,
                    };
                    format!("Repeat limit: {}x", lim.tool_repeat_limit)
                }
                "burst" => {
                    lim.max_tools_per_min = match lim.max_tools_per_min {
                        0..=30 => 45,
                        31..=50 => 60,
                        51..=75 => 90,
                        _ => 25,
                    };
                    format!("Burst limit: {}/m", lim.max_tools_per_min)
                }
                "tmo" => {
                    let mins = lim.job_timeout_secs / 60;
                    let next_m = match mins {
                        0..=12 => 20,
                        13..=25 => 30,
                        26..=38 => 45,
                        39..=52 => 60,
                        _ => 10,
                    };
                    lim.job_timeout_secs = next_m * 60;
                    format!("Job timeout: {next_m}m")
                }
                "global" => {
                    lim.max_global_ai_jobs = match lim.max_global_ai_jobs {
                        0..=2 => 4,
                        3..=4 => 6,
                        5..=6 => 8,
                        _ => 2,
                    };
                    format!("Global concurrent AI jobs: {}", lim.max_global_ai_jobs)
                }
                "queue" => {
                    lim.max_queue_per_user = match lim.max_queue_per_user {
                        0..=2 => 3,
                        3 => 5,
                        _ => 2,
                    };
                    format!("Max user queue: {}", lim.max_queue_per_user)
                }
                "rl" => {
                    lim.tg_user_rl_per_min = match lim.tg_user_rl_per_min {
                        0..=20 => 30,
                        21..=40 => 60,
                        41..=80 => 120,
                        _ => 15,
                    };
                    let burst = lim.tg_user_rl_per_min.clamp(20, 60);
                    ctx.tg_rl.set_rate(lim.tg_user_rl_per_min, burst);
                    format!("TG anti-flood: {}/m", lim.tg_user_rl_per_min)
                }
                "scan" => {
                    lim.outbox_secret_scan = !lim.outbox_secret_scan;
                    format!("Secret scanner: {}", if lim.outbox_secret_scan { "ON" } else { "OFF" })
                }
                "reset" => {
                    lim = ctx.jobs.reset_runtime_limits();
                    let burst = if lim.tg_user_rl_per_min == 0 {
                        0
                    } else {
                        lim.tg_user_rl_per_min.clamp(20, 60)
                    };
                    ctx.tg_rl.set_rate(lim.tg_user_rl_per_min, burst);
                    "Limits reset to defaults".to_string()
                }
                _ => "Updated".to_string(),
            };
            if action != "reset" {
                ctx.jobs.set_runtime_limits(lim);
            }
            ctx.ack(&cq.id, Some(&toast), false).await;
        } else {
            ctx.ack(&cq.id, None, false).await;
        }
        show_limits(ctx, Some(cq), chat_id, uid).await;
        return true;
    }
    if data == "settings" {
        if deny_cb_perm(ctx, cq, uid, "settings_access").await {
            return true;
        }
        ctx.ack(&cq.id, None, false).await;
        show_settings(ctx, Some(cq), chat_id, uid).await;
        return true;
    }
    if data == "adv" {
        if deny_cb_perm(ctx, cq, uid, "settings_access").await {
            return true;
        }
        ctx.ack(&cq.id, None, false).await;
        show_advanced(ctx, Some(cq), chat_id, uid).await;
        return true;
    }
    if let Some(rest) = data.strip_prefix("set:") {
        if deny_cb_perm(ctx, cq, uid, "settings_access").await {
            return true;
        }
        handle_set_cb(ctx, cq, uid, chat_id, rest).await;
        return true;
    }
    if data == "sessions" {
        if deny_cb_perm(ctx, cq, uid, "dashboard_access").await {
            return true;
        }
        ctx.ack(&cq.id, None, false).await;
        show_sessions(ctx, Some(cq), chat_id, uid).await;
        return true;
    }
    if let Some(rest) = data
        .strip_prefix("res:")
        .or_else(|| data.strip_prefix("resume:"))
    {
        if deny_cb_perm(ctx, cq, uid, "dashboard_access").await {
            return true;
        }
        let u = ctx.store.get_user(uid);
        if let Ok(idx) = rest.parse::<usize>() {
            if let Some(entry) = u.history.get(idx) {
                let cid = entry.id.clone();
                let _ = ctx.store.update_user(uid, |st| {
                    st.conversation_id = Some(cid);
                });
                ctx.ack(&cq.id, Some("Session resumed"), false).await;
            } else {
                ctx.ack(&cq.id, None, false).await;
            }
        } else {
            ctx.ack(&cq.id, None, false).await;
        }
        show_home(ctx, Some(cq), chat_id, uid).await;
        return true;
    }
    if let Some(rest) = data.strip_prefix("cwd:") {
        if deny_cb_perm(ctx, cq, uid, "settings_access").await {
            return true;
        }
        ctx.ack(&cq.id, None, false).await;
        show_cwd(ctx, Some(cq), chat_id, uid, rest).await;
        return true;
    }
    if data == "agents" || data == "agent:list" {
        if deny_cb_perm(ctx, cq, uid, "settings_access").await {
            return true;
        }
        ctx.ack(&cq.id, None, false).await;
        show_agents(ctx, Some(cq), chat_id, uid).await;
        return true;
    }
    if let Some(rest) = data
        .strip_prefix("agent:")
        .or_else(|| data.strip_prefix("setagent:"))
    {
        if deny_cb_perm(ctx, cq, uid, "settings_access").await {
            return true;
        }
        let raw = rest.strip_prefix("set:").unwrap_or(rest).trim();
        let next = if raw.is_empty() || raw == "-" || raw.eq_ignore_ascii_case("default") {
            None
        } else {
            Some(truncate_chars(raw, 50))
        };
        let _ = ctx.store.update_user(uid, |u| {
            u.agent = next.clone();
        });
        let lbl = next.as_deref().unwrap_or("default");
        ctx.ack(&cq.id, Some(&format!("Agent: {lbl}")), false).await;
        show_advanced(ctx, Some(cq), chat_id, uid).await;
        return true;
    }
    if data == "changelog" {
        if deny_cb_perm(ctx, cq, uid, "settings_access").await {
            return true;
        }
        ctx.ack(&cq.id, None, false).await;
        show_changelog(ctx, Some(cq), chat_id, uid).await;
        return true;
    }
    if data == "net" || data.starts_with("net:") {
        if deny_cb_perm(ctx, cq, uid, "status_net").await {
            return true;
        }
        if data == "net:rebuild" {
            if !ctx.is_owner(uid) {
                ctx.ack(&cq.id, Some(t(ctx.lang(uid), Tx::OwnerOnly)), true).await;
                return true;
            }
            let n = ctx.pool.rebuild_all("manual_net_rebuild");
            ctx.health.set_rebuilds(Some(ctx.pool.total_rebuilds()));
            ctx.ack(&cq.id, Some(&format!("Rebuilt {n} route(s)")), false)
                .await;
        } else {
            ctx.ack(&cq.id, None, false).await;
        }
        show_net(ctx, Some(cq), chat_id, uid).await;
        return true;
    }
    if data == "cron" || data.starts_with("cron:") {
        if deny_cb_perm(ctx, cq, uid, "status_net").await {
            return true;
        }
        if let Some(id) = data.strip_prefix("cron:run:") {
            if !ctx.is_owner(uid) {
                ctx.ack(&cq.id, Some(t(ctx.lang(uid), Tx::OwnerOnly)), true).await;
                return true;
            }
            ctx.ack(&cq.id, Some("Running job…"), false).await;
            if let Err(err) = ctx.cron.run_now(id).await {
                warn!(job = id, error = %err, "cron run_now failed");
            }
            show_cron(ctx, Some(cq), chat_id, uid).await;
            return true;
        }
        if let Some(id) = data.strip_prefix("cron:tog:") {
            if !ctx.is_owner(uid) {
                ctx.ack(&cq.id, Some(t(ctx.lang(uid), Tx::OwnerOnly)), true).await;
                return true;
            }
            let msg = match ctx.cron.get_job(id) {
                Some(rec) => match ctx.cron.set_enabled(id, !rec.enabled) {
                    Ok(upd) => {
                        if upd.enabled {
                            "Enabled"
                        } else {
                            "Disabled"
                        }
                    }
                    Err(_) => "Failed",
                },
                None => "Unknown job",
            };
            ctx.ack(&cq.id, Some(msg), false).await;
            show_cron(ctx, Some(cq), chat_id, uid).await;
            return true;
        }
        ctx.ack(&cq.id, None, false).await;
        show_cron(ctx, Some(cq), chat_id, uid).await;
        return true;
    }
    if let Some(mode_tag) = data.strip_prefix("retry:") {
        if mode_tag == "all" && !ctx.has_perm(uid, "root_access") {
            ctx.ack(&cq.id, Some(t(ctx.lang(uid), Tx::RootRequiredHint)), true).await;
            return true;
        }
        if mode_tag != "edits" && mode_tag != "all" {
            ctx.ack(&cq.id, Some("Invalid retry action"), false).await;
            return true;
        }
        clear_cq_markup(ctx, cq, chat_id).await;
        ctx.ack(&cq.id, None, false).await;
        if let Some((last_text, last_files)) = ctx.jobs.last_prompt(uid) {
            let mut req = JobRequest::new(
                uid,
                chat_id,
                cq.from_user.display_label(),
                last_text,
                last_files,
            );
            req.overrides = if mode_tag == "all" {
                JobOverride {
                    skip_permissions: Some(true),
                    ..Default::default()
                }
            } else {
                JobOverride {
                    mode: Some("accept-edits".to_string()),
                    ..Default::default()
                }
            };
            let _ = ctx.jobs.enqueue(req).await;
        }
        return true;
    }
    if data == "help" {
        ctx.ack(&cq.id, None, false).await;
        let mk = BotCtx::kb(vec![ctx.back_row_for(uid)]);
        ctx.edit_or_send(Some(cq), chat_id, &help_text_for(ctx, uid), Some(mk))
            .await;
        return true;
    }

    false
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
    use agy_ext::engines::ModelInfo;
    use agy_net::{BotApiClient, NetConfig, ProxyPool};
    use agy_render::PremiumState;
    use agy_widgets::WidgetStore;
    use axum::extract::{Path as AxumPath, State};
    use axum::routing::post;
    use axum::{Json, Router};
    use serde_json::json;
    use tempfile::TempDir;
    use tokio::net::TcpListener;
    use tokio::sync::Mutex;

    const OWNER: i64 = 1_000_000_001;
    const LOCKED_USER: i64 = 7_291_430_295;
    const STD_USER: i64 = 1_000_000_002;
    const ADMIN_USER: i64 = 7_291_430_297;

    #[derive(Clone, Default)]
    struct MockTg {
        calls: Arc<Mutex<Vec<(String, Value)>>>,
    }

    async fn mock_tg_handler(
        State(st): State<MockTg>,
        AxumPath((_token, method)): AxumPath<(String, String)>,
        Json(payload): Json<Value>,
    ) -> Json<Value> {
        st.calls.lock().await.push((method.clone(), payload));
        let res = match method.as_str() {
            "answerCallbackQuery" | "setMyCommands" | "setChatMenuButton" => json!(true),
            _ => json!({
                "message_id": 100,
                "chat": {"id": 1, "type": "private"},
                "text": "ok"
            }),
        };
        Json(json!({"ok": true, "result": res}))
    }

    async fn make_test_ctx(dir: &TempDir) -> (Arc<BotCtx>, MockTg) {
        let st = MockTg::default();
        let app = Router::new()
            .route("/bot{token}/{method}", post(mock_tg_handler))
            .with_state(st.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let state_dir = dir.path().join("state");
        let ws = dir.path().join("workspace");
        std::fs::create_dir_all(&state_dir).unwrap();
        std::fs::create_dir_all(ws.join("proj-a")).unwrap();
        std::fs::create_dir_all(dir.path().join("outside")).unwrap();

        let cfg = Arc::new(Config {
            bot_token: "123:ABC".into(),
            state_dir: state_dir.clone(),
            agy_workspace: ws,
            owner_id: OWNER,
            agy_bin: PathBuf::from("/bin/true"),
            ..Default::default()
        });
        let store = Arc::new(StateStore::open(cfg.state_path()).unwrap());
        let acl = Arc::new(
            AclStore::open(cfg.acl_path(), OWNER, &[LOCKED_USER, STD_USER, ADMIN_USER], 300)
                .unwrap(),
        );
        acl.set_status(LOCKED_USER, UserStatus::Approved, Some(OWNER), Some(RolePreset::Std))
            .unwrap();
        acl.set_status(STD_USER, UserStatus::Approved, Some(OWNER), Some(RolePreset::Dev))
            .unwrap();
        acl.set_status(ADMIN_USER, UserStatus::Approved, Some(OWNER), None)
            .unwrap();
        acl.set_tier(ADMIN_USER, agy_core::acl::RoleTier::Admin, true)
            .unwrap();
        let outbox = Arc::new(OutQueue::open(cfg.outbox_path()).unwrap());
        let health = Arc::new(HealthTracker::new(cfg.health_path()));
        let premium = Arc::new(PremiumState::new(false));
        let net_cfg = NetConfig::default().with_api_base(format!("http://{addr}"));
        let pool = Arc::new(ProxyPool::new(net_cfg.clone()).unwrap());
        let client = Arc::new(BotApiClient::new("123:ABC", net_cfg).unwrap());
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
        ctx.set_models_cache(vec![
            ModelInfo {
                id: "m1".into(),
                name: "Model One".into(),
            },
            ModelInfo {
                id: "m2".into(),
                name: "Model Two".into(),
            },
        ]);
        (ctx, st)
    }

    fn mk_msg(uid: i64, text: &str) -> Message {
        Message {
            message_id: 1,
            from_user: Some(User {
                id: uid,
                is_bot: false,
                first_name: "Test".into(),
                last_name: None,
                username: Some("tester".into()),
                language_code: None,
                is_premium: Some(false),
            }),
            chat: Chat {
                id: uid,
                kind: "private".into(),
                username: None,
                first_name: None,
            },
            message_thread_id: None,
            text: Some(text.into()),
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
        }
    }

    fn mk_cq(uid: i64, data: &str) -> CallbackQuery {
        CallbackQuery {
            id: "cq-1".into(),
            from_user: User {
                id: uid,
                is_bot: false,
                first_name: "Test".into(),
                last_name: None,
                username: None,
                language_code: None,
                is_premium: Some(false),
            },
            message: Some(mk_msg(uid, "menu")),
            inline_message_id: None,
            data: Some(data.into()),
        }
    }

    #[tokio::test]
    async fn root_access_enforced_on_cwd_skip_permissions_and_retry_all() {
        let dir = TempDir::new().unwrap();
        let (ctx, st) = make_test_ctx(&dir).await;

        let outside = dir.path().join("outside");
        let inside = ctx.cfg.agy_workspace.join("proj-a");

        // 1. Non-root user denied /cwd outside workspace without mutating state
        cmd_cwd(&ctx, &mk_msg(STD_USER, "/cwd"), &outside.to_string_lossy()).await;
        assert_eq!(ctx.store.get_user(STD_USER).cwd, None);

        // 2. Non-root user allowed /cwd inside workspace
        cmd_cwd(&ctx, &mk_msg(STD_USER, "/cwd"), &inside.to_string_lossy()).await;
        assert_eq!(
            ctx.store.get_user(STD_USER).cwd,
            Some(std::fs::canonicalize(&inside).unwrap().to_string_lossy().into_owned())
        );

        // 3. Owner (root_access) allowed /cwd outside workspace
        cmd_cwd(&ctx, &mk_msg(OWNER, "/cwd"), &outside.to_string_lossy()).await;
        assert_eq!(
            ctx.store.get_user(OWNER).cwd,
            Some(std::fs::canonicalize(&outside).unwrap().to_string_lossy().into_owned())
        );

        // 4. set:skip_permissions denied for STD_USER without mutation
        let handled = handle_system_cb(
            &ctx,
            &mk_cq(STD_USER, "set:skip_permissions:x"),
            STD_USER,
            STD_USER,
            "set:skip_permissions:x",
        )
        .await;
        assert!(handled);
        assert!(!ctx.store.get_user(STD_USER).skip_permissions);

        // 5. set:skip_permissions allowed for OWNER
        assert!(handle_system_cb(
            &ctx,
            &mk_cq(OWNER, "set:skip_permissions:x"),
            OWNER,
            OWNER,
            "set:skip_permissions:x",
        )
        .await);
        assert!(ctx.store.get_user(OWNER).skip_permissions);

        // 6. retry:all denied for STD_USER without clearing markup or enqueueing
        let calls_before = st.calls.lock().await.len();
        assert!(handle_system_cb(
            &ctx,
            &mk_cq(STD_USER, "retry:all"),
            STD_USER,
            STD_USER,
            "retry:all",
        )
        .await);
        let calls = st.calls.lock().await;
        let last_ack = calls[calls_before..].iter().find(|(m, _)| m == "answerCallbackQuery");
        assert!(last_ack.is_some());
        assert_eq!(last_ack.unwrap().1["text"], "Requires root access permission.");
        assert!(!calls[calls_before..].iter().any(|(m, _)| m == "editMessageReplyMarkup"));
        drop(calls);

        // 7. Admin tier HAS root_access (can set skip_permissions & /cwd outside)
        cmd_cwd(&ctx, &mk_msg(ADMIN_USER, "/cwd"), &outside.to_string_lossy()).await;
        assert_eq!(
            ctx.store.get_user(ADMIN_USER).cwd,
            Some(std::fs::canonicalize(&outside).unwrap().to_string_lossy().into_owned())
        );
        assert!(handle_system_cb(&ctx, &mk_cq(ADMIN_USER, "set:skip_permissions:x"), ADMIN_USER, ADMIN_USER, "set:skip_permissions:x").await);
        assert!(ctx.store.get_user(ADMIN_USER).skip_permissions);

        // 8. Admin tier STILL DENIED on Owner-only net:rebuild and cron:run
        assert!(handle_system_cb(&ctx, &mk_cq(ADMIN_USER, "cron:tog:inbox_gc"), ADMIN_USER, ADMIN_USER, "cron:tog:inbox_gc").await);
        let cron_after = ctx.cron.get_job("inbox_gc").unwrap().enabled;
        assert!(handle_system_cb(&ctx, &mk_cq(ADMIN_USER, "net:rebuild"), ADMIN_USER, ADMIN_USER, "net:rebuild").await);
        assert_eq!(ctx.pool.snapshot().total_rebuilds, 0);
        let _ = cron_after;

        // 9. Locked User (no dashboard/settings/models/status) is blocked from modules, but allowed /lang
        cmd_effort(&ctx, &mk_msg(LOCKED_USER, "/effort high"), "high").await;
        assert_eq!(ctx.store.get_user(LOCKED_USER).effort, None);
        assert!(handle_system_cb(&ctx, &mk_cq(LOCKED_USER, "model:1"), LOCKED_USER, LOCKED_USER, "model:1").await);
        assert_eq!(ctx.store.get_user(LOCKED_USER).model, None);
        for &code in &["fa", "en", "la", "zh", "ru"] {
            let cb = format!("lang:{code}");
            assert!(handle_system_cb(&ctx, &mk_cq(LOCKED_USER, &cb), LOCKED_USER, LOCKED_USER, &cb).await);
        }
        assert_eq!(ctx.lang(LOCKED_USER), Lang::Ru);
    }

    #[tokio::test]
    async fn system_commands_and_callbacks_update_state_and_cron() {
        let dir = TempDir::new().unwrap();
        let (ctx, st) = make_test_ctx(&dir).await;

        cmd_start(&ctx, &mk_msg(OWNER, "/start"), "").await;
        assert!(ctx.commands_set.contains_key(&OWNER));

        cmd_effort(&ctx, &mk_msg(STD_USER, "/effort high"), "high").await;
        assert_eq!(ctx.store.get_user(STD_USER).effort.as_deref(), Some("high"));

        cmd_mode(&ctx, &mk_msg(STD_USER, "/mode plan"), "plan").await;
        assert_eq!(ctx.store.get_user(STD_USER).mode.as_deref(), Some("plan"));

        cmd_trace(&ctx, &mk_msg(STD_USER, "/trace"), "").await;
        assert!(ctx.store.get_user(STD_USER).trace);

        cmd_agent(&ctx, &mk_msg(STD_USER, "/agent coder"), "coder").await;
        assert_eq!(ctx.store.get_user(STD_USER).agent.as_deref(), Some("coder"));

        cmd_resume(&ctx, &mk_msg(STD_USER, "/resume conv-123"), "conv-123").await;
        assert_eq!(
            ctx.store.get_user(STD_USER).conversation_id.as_deref(),
            Some("conv-123")
        );

        // model:* and models:* callbacks
        assert!(handle_system_cb(&ctx, &mk_cq(STD_USER, "model:1"), STD_USER, STD_USER, "model:1").await);
        assert_eq!(ctx.store.get_user(STD_USER).model.as_deref(), Some("m2"));

        // sessions & res:*
        ctx.store
            .update_user(STD_USER, |u| {
                u.push_session("conv-xyz", "Session XYZ", 1_700_000_000);
                u.conversation_id = None;
            })
            .unwrap();
        assert!(handle_system_cb(&ctx, &mk_cq(STD_USER, "res:0"), STD_USER, STD_USER, "res:0").await);
        assert_eq!(
            ctx.store.get_user(STD_USER).conversation_id.as_deref(),
            Some("conv-xyz")
        );

        // cron:tog:*
        let before_en = ctx.cron.get_job("inbox_gc").unwrap().enabled;
        assert!(handle_system_cb(
            &ctx,
            &mk_cq(OWNER, "cron:tog:inbox_gc"),
            OWNER,
            OWNER,
            "cron:tog:inbox_gc",
        )
        .await);
        assert_eq!(ctx.cron.get_job("inbox_gc").unwrap().enabled, !before_en);

        // Verify all emitted callback_data stay <= 64 bytes
        let calls = st.calls.lock().await;
        for (_, payload) in calls.iter() {
            if let Some(rows) = payload.pointer("/reply_markup/inline_keyboard").and_then(Value::as_array) {
                for row in rows {
                    if let Some(btns) = row.as_array() {
                        for b in btns {
                            if let Some(cb) = b.get("callback_data").and_then(Value::as_str) {
                                assert!(cb.len() <= 64, "callback_data too long: {cb}");
                            }
                        }
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn pagination_settings_cwd_symlink_and_unhandled_cb() {
        let dir = TempDir::new().unwrap();
        let (ctx, st) = make_test_ctx(&dir).await;

        // Symlink inside workspace escaping outside must be rejected on /cwd
        let outside = dir.path().join("outside");
        let escape_link = ctx.cfg.agy_workspace.join("escape-link");
        std::os::unix::fs::symlink(&outside, &escape_link).unwrap();
        cmd_cwd(&ctx, &mk_msg(STD_USER, "/cwd"), &escape_link.to_string_lossy()).await;
        assert_eq!(ctx.store.get_user(STD_USER).cwd, None);

        // Models pagination across 14 models (2 pages)
        let many: Vec<ModelInfo> = (0..14)
            .map(|i| ModelInfo {
                id: format!("model-{i}"),
                name: format!("Model {i}"),
            })
            .collect();
        ctx.set_models_cache(many);
        assert!(handle_system_cb(&ctx, &mk_cq(STD_USER, "models:1"), STD_USER, STD_USER, "models:1").await);
        assert!(handle_system_cb(&ctx, &mk_cq(STD_USER, "model:12"), STD_USER, STD_USER, "model:12").await);
        assert_eq!(ctx.store.get_user(STD_USER).model.as_deref(), Some("model-12"));

        // Settings mutations: stream_mode, render, mode, effort, trace
        assert!(handle_system_cb(&ctx, &mk_cq(STD_USER, "set:stream_mode:live"), STD_USER, STD_USER, "set:stream_mode:live").await);
        assert!(handle_system_cb(&ctx, &mk_cq(STD_USER, "set:render:x"), STD_USER, STD_USER, "set:render:x").await);
        assert!(handle_system_cb(&ctx, &mk_cq(STD_USER, "set:trace:x"), STD_USER, STD_USER, "set:trace:x").await);
        let u = ctx.store.get_user(STD_USER);
        assert_eq!(u.stream_mode, "live");
        assert_eq!(u.render, "html");
        assert!(u.trace);

        // /cancel & inp:cancel clear awaiting input; /new clears conversation_id
        ctx.jobs.set_awaiting(STD_USER, crate::jobs::AwaitingInput::new("test", json!({})));
        cmd_cancel(&ctx, &mk_msg(STD_USER, "/cancel"), "").await;
        assert!(ctx.jobs.take_awaiting(STD_USER).is_none());
        cmd_new(&ctx, &mk_msg(STD_USER, "/new"), "").await;
        assert_eq!(ctx.store.get_user(STD_USER).conversation_id, None);

        // cwd:1 switches to proj-a, cwd:0 resets to workspace default
        assert!(handle_system_cb(&ctx, &mk_cq(STD_USER, "cwd:1"), STD_USER, STD_USER, "cwd:1").await);
        assert!(ctx.store.get_user(STD_USER).cwd.as_deref().unwrap().ends_with("proj-a"));
        assert!(handle_system_cb(&ctx, &mk_cq(STD_USER, "cwd:0"), STD_USER, STD_USER, "cwd:0").await);
        assert_eq!(ctx.store.get_user(STD_USER).cwd, None);

        // net:rebuild & status & limits & help & cron:run
        assert!(handle_system_cb(&ctx, &mk_cq(OWNER, "net:rebuild"), OWNER, OWNER, "net:rebuild").await);
        assert!(handle_system_cb(&ctx, &mk_cq(OWNER, "status"), OWNER, OWNER, "status").await);
        assert!(handle_system_cb(&ctx, &mk_cq(OWNER, "limits"), OWNER, OWNER, "limits").await);
        // Normal guard buttons never silently cycle into 0 (off)
        for _ in 0..8 {
            assert!(handle_system_cb(&ctx, &mk_cq(OWNER, "lim:steps"), OWNER, OWNER, "lim:steps").await);
            assert!(handle_system_cb(&ctx, &mk_cq(OWNER, "lim:rep"), OWNER, OWNER, "lim:rep").await);
            assert!(handle_system_cb(&ctx, &mk_cq(OWNER, "lim:burst"), OWNER, OWNER, "lim:burst").await);
            assert!(handle_system_cb(&ctx, &mk_cq(OWNER, "lim:rl"), OWNER, OWNER, "lim:rl").await);
            let lim = ctx.jobs.runtime_limits();
            assert!(lim.max_tool_steps > 0 && lim.tool_repeat_limit > 0 && lim.max_tools_per_min > 0 && lim.tg_user_rl_per_min > 0);
        }
        assert!(handle_system_cb(&ctx, &mk_cq(OWNER, "lim:global"), OWNER, OWNER, "lim:global").await);
        assert!(handle_system_cb(&ctx, &mk_cq(OWNER, "lim:queue"), OWNER, OWNER, "lim:queue").await);
        assert!(handle_system_cb(&ctx, &mk_cq(OWNER, "lim:prof:strict"), OWNER, OWNER, "lim:prof:strict").await);
        assert_eq!(ctx.jobs.max_global_jobs(), 2);
        assert_eq!(ctx.tg_rl.rate_per_min(), 20);
        assert!(handle_system_cb(&ctx, &mk_cq(OWNER, "lim:prof:high"), OWNER, OWNER, "lim:prof:high").await);
        assert_eq!(ctx.jobs.max_global_jobs(), 6);
        assert!(handle_system_cb(&ctx, &mk_cq(OWNER, "lim:reset"), OWNER, OWNER, "lim:reset").await);
        assert_eq!(ctx.tg_rl.rate_per_min(), ctx.jobs.runtime_limits().tg_user_rl_per_min);
        // Non-owner is denied /limits mutation
        assert!(handle_system_cb(&ctx, &mk_cq(STD_USER, "lim:scan"), STD_USER, STD_USER, "lim:scan").await);
        assert_eq!(ctx.jobs.runtime_limits().outbox_secret_scan, ctx.cfg.outbox_secret_scan);
        assert!(handle_system_cb(&ctx, &mk_cq(OWNER, "help"), OWNER, OWNER, "help").await);
        assert!(handle_system_cb(&ctx, &mk_cq(OWNER, "cron:run:inbox_gc"), OWNER, OWNER, "cron:run:inbox_gc").await);

        // Long agent name truncated safely <= 64 bytes callback
        let long_agent = "a".repeat(80);
        cmd_agent(&ctx, &mk_msg(STD_USER, "/agent"), &long_agent).await;
        assert_eq!(ctx.store.get_user(STD_USER).agent.as_ref().unwrap().len(), 50);

        // Unhandled prefix returns false
        assert!(!handle_system_cb(&ctx, &mk_cq(OWNER, "uadm:list:all:0"), OWNER, OWNER, "uadm:list:all:0").await);

        let calls = st.calls.lock().await;
        assert!(!calls.is_empty());
    }
}
