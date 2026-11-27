//! `/mcp` server configuration CRUD (secret-masked) and AI MCP installation approval flow.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use agy_core::acl::{McpDecision, McpRequestStatus};
use agy_core::tg::{CallbackQuery, InlineKeyboardButton, Message};
use agy_ext::mcp_client::redact_secrets_in_text;
use agy_ext::mcp_config::{
    get_mcp_server, is_sensitive_key, list_mcp_servers, mcp_config_epoch_for, remove_mcp_server,
    replace_mcp_server_json, toggle_mcp_server, update_mcp_server, McpServerUpdate, McpServerView,
    MASKED_SECRET,
};
use agy_render::md_cell;
use dashmap::DashMap;
use serde_json::json;
use tracing::warn;

use crate::ctx::BotCtx;
use crate::i18n::{missing_perm_html, perm_label, t, Tx};
use crate::jobs::{AwaitingInput, JobOverride, JobRequest};

const MCP_PAGE_SIZE: usize = 16;

type McpCacheKey = (PathBuf, i64);

fn mcp_view_cache() -> &'static DashMap<McpCacheKey, (u64, Vec<McpServerView>)> {
    static CACHE: OnceLock<DashMap<McpCacheKey, (u64, Vec<McpServerView>)>> = OnceLock::new();
    CACHE.get_or_init(DashMap::new)
}

fn mcp_rendered_epoch() -> &'static DashMap<McpCacheKey, u64> {
    static RENDERED: OnceLock<DashMap<McpCacheKey, u64>> = OnceLock::new();
    RENDERED.get_or_init(DashMap::new)
}

fn truncate_chars(s: &str, max_chars: usize) -> String {
    agy_core::text::truncate_chars(s, max_chars)
}

fn load_sorted_servers(ctx: &BotCtx) -> Vec<McpServerView> {
    let mut srvs = list_mcp_servers(&ctx.cfg.mcp_config_path).unwrap_or_default();
    srvs.sort_by(|a, b| a.name.cmp(&b.name));
    srvs
}

fn refresh_mcp_cache(ctx: &BotCtx, uid: i64) -> Vec<McpServerView> {
    ctx.invalidate_mcp_rows_cache();
    let epoch = mcp_config_epoch_for(&ctx.cfg.mcp_config_path);
    let srvs = load_sorted_servers(ctx);
    mcp_view_cache().insert((ctx.cfg.mcp_config_path.clone(), uid), (epoch, srvs.clone()));
    srvs
}

fn get_cached_servers(ctx: &BotCtx, uid: i64) -> Vec<McpServerView> {
    let cur_epoch = mcp_config_epoch_for(&ctx.cfg.mcp_config_path);
    let key = (ctx.cfg.mcp_config_path.clone(), uid);
    if let Some(existing) = mcp_view_cache().get(&key) {
        if existing.0 == cur_epoch && !existing.1.is_empty() {
            return existing.1.clone();
        }
    }
    refresh_mcp_cache(ctx, uid)
}

fn rendered_epoch_stale(ctx: &BotCtx, uid: i64) -> bool {
    let cur_epoch = mcp_config_epoch_for(&ctx.cfg.mcp_config_path);
    let key = (ctx.cfg.mcp_config_path.clone(), uid);
    mcp_rendered_epoch()
        .get(&key)
        .is_some_and(|e| *e != cur_epoch)
}

fn redacted_env_lines(srv: &McpServerView) -> Vec<String> {
    let mut lines = Vec::new();
    for (k, v) in &srv.env {
        let shown = if is_sensitive_key(k) {
            MASKED_SECRET.to_string()
        } else {
            redact_secrets_in_text(v)
        };
        lines.push(format!("{k}={shown}"));
    }
    for (k, v) in &srv.headers {
        let shown = if is_sensitive_key(k) {
            MASKED_SECRET.to_string()
        } else {
            redact_secrets_in_text(v)
        };
        lines.push(format!("[header] {k}={shown}"));
    }
    lines
}

fn mcp_detail_text(srv: &McpServerView, ctx: &BotCtx) -> String {
    let cmd_raw = if srv.command.is_empty() {
        "—".to_string()
    } else {
        redact_secrets_in_text(&srv.command)
    };
    let args_raw = if srv.args.is_empty() {
        "—".to_string()
    } else {
        redact_secrets_in_text(&srv.args.join(" "))
    };
    let url_raw = if srv.url.is_empty() {
        "—".to_string()
    } else {
        redact_secrets_in_text(&srv.url)
    };
    let env_lines = redacted_env_lines(srv);
    let state_lbl = if srv.enabled {
        "✓ فعال"
    } else {
        "○ غیرفعال"
    };
    let srv_type = if srv.server_type.is_empty() {
        "stdio"
    } else {
        &srv.server_type
    };

    let mut lines = vec![
        format!("### {} {}", ctx.premium.md("mcp"), md_cell(&srv.name)),
        String::new(),
        "| فیلد | مقدار |".to_string(),
        "|---|---|".to_string(),
        format!("| وضعیت | {state_lbl} |"),
        format!("| نوع | `{}` |", md_cell(srv_type)),
        format!("| Command | `{}` |", md_cell(&truncate_chars(&cmd_raw, 120))),
        format!("| Args | `{}` |", md_cell(&truncate_chars(&args_raw, 140))),
        format!("| URL | `{}` |", md_cell(&truncate_chars(&url_raw, 140))),
    ];
    if env_lines.is_empty() {
        lines.push(String::new());
        lines.push("> بدون متغیر محیطی (env)".to_string());
    } else {
        lines.push(String::new());
        lines.push("<details><summary>متغیرهای محیطی (ماسک‌شده)</summary>".to_string());
        for ln in env_lines.iter().take(20) {
            lines.push(format!("`{}`", ln.replace('`', "'")));
        }
        lines.push("</details>".to_string());
    }
    lines.join("\n")
}

async fn send_rich_card(
    ctx: &BotCtx,
    cq: Option<&CallbackQuery>,
    chat_id: i64,
    md: &str,
    rows: Vec<Vec<InlineKeyboardButton>>,
) {
    let msg_id = cq.and_then(|c| c.message.as_ref()).map(|m| m.message_id);
    let mk = if rows.is_empty() {
        None
    } else {
        Some(BotCtx::kb(rows))
    };
    let _ = ctx
        .render
        .edit_or_send_rich(chat_id, msg_id, md, mk)
        .await;
}

fn build_mcp_install_prompt(rid: &str, spec_text: &str, cfg_path: &str) -> String {
    format!(
        "Install, configure, and verify this MCP server on the host system (Request ID: {rid}).\n\
        Requested MCP spec:\n{spec_text}\n\n\
        Requirements:\n\
        1. Inspect the source/package carefully and install any dependencies cleanly on the server.\n\
        2. Add or update the server entry in `{cfg_path}` atomically without breaking or exposing any existing server configs or secrets.\n\
        3. Verify with `agy mcp list` and run a real stdio/HTTP JSON-RPC `initialize` + `tools/list` check.\n\
        4. Report in Persian what was installed, the exact server name/command, available tools, verification results, and any missing env/API keys."
    )
}

fn strip_json_fence(raw: &str) -> String {
    let trimmed = raw.trim();
    if let Some(after_open) = trimmed.strip_prefix("```") {
        if let Some(nl) = after_open.find('\n') {
            let body = &after_open[nl + 1..];
            if let Some(before_close) = body.trim_end().strip_suffix("```") {
                return before_close.trim().to_string();
            }
        }
    }
    trimmed.to_string()
}

/// Handle `/mcp` slash command.
pub async fn cmd_mcp(ctx: &Arc<BotCtx>, msg: &Message) {
    let Some(uid) = msg.from_user.as_ref().map(|u| u.id) else {
        return;
    };
    if !ctx.has_perm(uid, "mcp_manage") {
        let _ = ctx
            .render
            .send_html_simple(msg.chat.id, &missing_perm_html(ctx, uid, "mcp_manage"), None)
            .await;
        return;
    }
    show_mcp(ctx, None, msg.chat.id, uid).await;
}

/// Render or edit the MCP servers list view (`mcp`).
pub async fn show_mcp(
    ctx: &Arc<BotCtx>,
    cq: Option<&CallbackQuery>,
    chat_id: i64,
    uid: i64,
) {
    show_mcp_page(ctx, cq, chat_id, uid, 0).await;
}

pub async fn show_mcp_page(
    ctx: &Arc<BotCtx>,
    cq: Option<&CallbackQuery>,
    chat_id: i64,
    uid: i64,
    page: usize,
) {
    let can_m = ctx.has_perm(uid, "mcp_manage");
    let srvs = refresh_mcp_cache(ctx, uid);
    mcp_rendered_epoch().insert(
        (ctx.cfg.mcp_config_path.clone(), uid),
        mcp_config_epoch_for(&ctx.cfg.mcp_config_path),
    );

    if srvs.is_empty() {
        let live_rows = ctx.mcp_rows_live(Some(uid)).await;
        let mut md_lines = vec![
            format!("### {} {}", ctx.premium.md("mcp"), t(ctx.lang(uid), Tx::PanelMcpTitle)),
            String::new(),
        ];
        if live_rows.is_empty() {
            md_lines.push("> هیچ سرور MCP در کانفیگ یافت نشد.".to_string());
        } else {
            let total_live = live_rows.len();
            let pages = total_live.div_ceil(MCP_PAGE_SIZE).max(1);
            let p = page.min(pages - 1);
            let start = p * MCP_PAGE_SIZE;
            let end = (start + MCP_PAGE_SIZE).min(total_live);
            if pages > 1 {
                md_lines.push(format!("> صفحه **{}/{pages}** · {total_live} سرور", p + 1));
                md_lines.push(String::new());
            }
            md_lines.push("| سرور | وضعیت |".to_string());
            md_lines.push("|---|---|".to_string());
            for (name, st) in &live_rows[start..end] {
                let st_lbl = if st.eq_ignore_ascii_case("enabled") {
                    "✓ فعال"
                } else {
                    "○ غیرفعال"
                };
                md_lines.push(format!("| {} | {st_lbl} |", md_cell(name)));
            }
        }
        let mut rows: Vec<Vec<InlineKeyboardButton>> = Vec::new();
        if live_rows.len() > MCP_PAGE_SIZE {
            let pages = live_rows.len().div_ceil(MCP_PAGE_SIZE);
            let p = page.min(pages - 1);
            let mut nav = Vec::new();
            if p > 0 {
                nav.push(ctx.btn("", "◀ قبلی", Some(&format!("mcp:p:{}", p - 1)), None, None));
            }
            if p + 1 < pages {
                nav.push(ctx.btn("", "بعدی ▶", Some(&format!("mcp:p:{}", p + 1)), None, None));
            }
            if !nav.is_empty() {
                rows.push(nav);
            }
        }
        if can_m {
            rows.push(vec![ctx.btn(
                "rocket",
                "نصب با AI",
                Some("mcp:ai"),
                Some("primary"),
                None,
            )]);
        }
        rows.push(vec![
            ctx.btn("refresh", "Refresh", Some("mcp"), None, None),
            ctx.btn("menu", "Menu", Some("home"), None, None),
        ]);
        send_rich_card(ctx, cq, chat_id, &md_lines.join("\n"), rows).await;
        return;
    }

    let total = srvs.len();
    let pages = total.div_ceil(MCP_PAGE_SIZE).max(1);
    let p = page.min(pages - 1);
    let start = p * MCP_PAGE_SIZE;
    let end = (start + MCP_PAGE_SIZE).min(total);

    let on_cnt = srvs.iter().filter(|s| s.enabled).count();
    let mut md_lines = vec![
        format!("### {} سرورهای MCP", ctx.premium.md("mcp")),
        if pages > 1 {
            format!("> **{on_cnt}/{total}** فعال · صفحه **{}/{pages}**", p + 1)
        } else {
            format!("> **{on_cnt}/{total}** فعال")
        },
        String::new(),
        "| سرور | نوع | وضعیت |".to_string(),
        "|---|---|---|".to_string(),
    ];

    for s in &srvs[start..end] {
        let st_lbl = if s.enabled {
            "✓ فعال"
        } else {
            "○ غیرفعال"
        };
        let srv_t = if s.server_type.is_empty() {
            "stdio"
        } else {
            &s.server_type
        };
        md_lines.push(format!(
            "| {} | `{}` | {st_lbl} |",
            md_cell(&s.name),
            md_cell(srv_t)
        ));
    }

    let mut rows: Vec<Vec<InlineKeyboardButton>> = Vec::new();
    let srv_btns: Vec<InlineKeyboardButton> = srvs[start..end]
        .iter()
        .enumerate()
        .map(|(offset, s)| {
            let idx = start + offset;
            let mark = if s.enabled { "✓" } else { "○" };
            ctx.btn(
                "",
                &format!("{mark} {}", truncate_chars(&s.name, 18)),
                Some(&format!("mcp:v:{idx}")),
                None,
                None,
            )
        })
        .collect();
    for pair in srv_btns.chunks(2) {
        rows.push(pair.to_vec());
    }
    if pages > 1 {
        let mut nav = Vec::new();
        if p > 0 {
            nav.push(ctx.btn("", "◀ قبلی", Some(&format!("mcp:p:{}", p - 1)), None, None));
        }
        if p + 1 < pages {
            nav.push(ctx.btn("", "بعدی ▶", Some(&format!("mcp:p:{}", p + 1)), None, None));
        }
        if !nav.is_empty() {
            rows.push(nav);
        }
    }
    if can_m {
        let mut action_row = vec![ctx.btn(
            "rocket",
            "نصب با AI",
            Some("mcp:ai"),
            Some("primary"),
            None,
        )];
        if ctx.is_owner(uid) {
            action_row.push(ctx.btn(
                "mcp",
                "🌐 MCP Gateway",
                Some("mcpgw"),
                None,
                None,
            ));
        }
        rows.push(action_row);
    }
    rows.push(vec![
        ctx.btn("refresh", "Refresh", Some("mcp"), None, None),
        ctx.btn("menu", "Menu", Some("home"), None, None),
    ]);

    send_rich_card(ctx, cq, chat_id, &md_lines.join("\n"), rows).await;
}

/// Render or edit detail view for a single MCP server (`mcp:v:{idx}`).
pub async fn show_mcp_detail(
    ctx: &Arc<BotCtx>,
    cq: Option<&CallbackQuery>,
    chat_id: i64,
    uid: i64,
    idx: usize,
) {
    let srvs = get_cached_servers(ctx, uid);
    let Some(entry) = srvs.get(idx) else {
        show_mcp(ctx, cq, chat_id, uid).await;
        return;
    };
    let fresh = match get_mcp_server(&ctx.cfg.mcp_config_path, &entry.name) {
        Ok(Some(v)) => v,
        _ => {
            show_mcp(ctx, cq, chat_id, uid).await;
            return;
        }
    };
    let cache_key = (ctx.cfg.mcp_config_path.clone(), uid);
    let cur_epoch = mcp_config_epoch_for(&ctx.cfg.mcp_config_path);
    if let Some(mut cached) = mcp_view_cache().get_mut(&cache_key) {
        if cached.0 == cur_epoch {
            if let Some(slot) = cached.1.get_mut(idx) {
                *slot = fresh.clone();
            }
        }
    }
    mcp_rendered_epoch().insert(cache_key, cur_epoch);

    let can_m = ctx.has_perm(uid, "mcp_manage");
    let mut rows: Vec<Vec<InlineKeyboardButton>> = Vec::new();
    if can_m {
        let tog_lbl = if fresh.enabled {
            "غیرفعال کن"
        } else {
            "فعال کن"
        };
        if !fresh.url.is_empty() && fresh.command.is_empty() {
            rows.push(vec![
                ctx.btn("", tog_lbl, Some(&format!("mcp:tog:{idx}")), Some("primary"), None),
                ctx.btn("", "URL", Some(&format!("mcp:eurl:{idx}")), None, None),
            ]);
        } else {
            rows.push(vec![
                ctx.btn("", tog_lbl, Some(&format!("mcp:tog:{idx}")), Some("primary"), None),
                ctx.btn("", "Cmd", Some(&format!("mcp:ecmd:{idx}")), None, None),
                ctx.btn("", "Args", Some(&format!("mcp:earg:{idx}")), None, None),
            ]);
        }
        rows.push(vec![
            ctx.btn("", "Env", Some(&format!("mcp:eenv:{idx}")), None, None),
            ctx.btn("", "JSON", Some(&format!("mcp:ejson:{idx}")), None, None),
            ctx.btn("", "حذف", Some(&format!("mcp:rm:{idx}")), Some("danger"), None),
        ]);
    }
    rows.push(vec![
        ctx.btn("", "« MCP", Some("mcp"), None, None),
        ctx.btn("menu", "Menu", Some("home"), None, None),
    ]);

    let note = if can_m {
        ""
    } else {
        "\n\n> فقط مشاهده — دسترسی ویرایش MCP غیرفعال است."
    };
    let md = format!("{}{note}", mcp_detail_text(&fresh, ctx));
    send_rich_card(ctx, cq, chat_id, &md, rows).await;
}

async fn handle_mreq_decision(
    ctx: &Arc<BotCtx>,
    cq: &CallbackQuery,
    uid: i64,
    chat_id: i64,
    rid: &str,
    decision: McpDecision,
) {
    if !ctx.is_owner(uid) {
        ctx.ack(&cq.id, Some("Owner only"), true).await;
        return;
    }
    let Some(existing) = ctx.acl.get_mcp_request(rid) else {
        ctx.ack(&cq.id, Some("درخواست یافت نشد"), false).await;
        return;
    };
    if existing.status != McpRequestStatus::Pending {
        let st_s = match existing.status {
            McpRequestStatus::Approved => "approved",
            McpRequestStatus::Rejected => "rejected",
            McpRequestStatus::Pending => "pending",
        };
        ctx.ack(&cq.id, Some(&format!("قبلاً {st_s} شده است")), false)
            .await;
        return;
    }

    let Ok(Some(rec)) = ctx.acl.resolve_mcp_request(rid, decision, uid) else {
        ctx.ack(&cq.id, Some("درخواست قبلاً پردازش شده است"), false)
            .await;
        return;
    };

    if decision == McpDecision::Rejected {
        ctx.ack(&cq.id, Some("رد شد"), false).await;
        let md = format!(
            "### {} درخواست نصب MCP رد شد\n\n> شناسه: `{}`",
            ctx.premium.md("err"),
            md_cell(rid)
        );
        let rows = vec![vec![ctx.btn("mcp", "سرورهای MCP", Some("mcp"), None, None)]];
        send_rich_card(ctx, Some(cq), chat_id, &md, rows).await;
        if rec.chat_id != 0 && rec.chat_id != chat_id {
            let notice = format!(
                "### {} درخواست نصب MCP رد شد\n\n> شناسه: `{}`",
                ctx.premium.md("err"),
                md_cell(rid)
            );
            let _ = ctx
                .render
                .send_rich_card_message(rec.chat_id, &notice, None)
                .await;
        }
        return;
    }

    ctx.ack(&cq.id, Some("تایید شد و در صف نصب قرار گرفت"), false)
        .await;
    let md = format!(
        "### {} نصب MCP تایید شد\n\n> شناسه: `{}` — در حال نصب روی سرور...",
        ctx.premium.md("ok"),
        md_cell(rid)
    );
    let rows = vec![vec![ctx.btn("mcp", "سرورهای MCP", Some("mcp"), None, None)]];
    send_rich_card(ctx, Some(cq), chat_id, &md, rows).await;

    let req_chat = if rec.chat_id != 0 {
        rec.chat_id
    } else {
        chat_id
    };
    if req_chat != chat_id {
        let notice = format!(
            "### {} درخواست نصب MCP تایید شد\n\n> شناسه: `{}` — در حال نصب است.",
            ctx.premium.md("ok"),
            md_cell(rid)
        );
        let _ = ctx
            .render
            .send_rich_card_message(req_chat, &notice, None)
            .await;
    }

    let cfg_path = ctx.cfg.mcp_config_path.to_string_lossy();
    let install_prompt = build_mcp_install_prompt(rid, &rec.spec_text, &cfg_path);
    let mut job_req = JobRequest::new(
        uid,
        req_chat,
        cq.from_user.display_label(),
        install_prompt,
        Vec::new(),
    );
    job_req.overrides = JobOverride {
        isolated: true,
        owner_approved_mcp: true,
        skip_permissions: Some(true),
        force_engine: Some("agy".to_string()),
        ..Default::default()
    };
    let _ = ctx.jobs.enqueue(job_req).await;
}

/// Dispatch `mcp`, `mcp:*`, and `mreq:*` callback queries.
/// Returns `true` if `data` was handled by this module.
pub async fn handle_mcp_cb(
    ctx: &Arc<BotCtx>,
    cq: &CallbackQuery,
    uid: i64,
    chat_id: i64,
    data: &str,
) -> bool {
    if data == "mcp" {
        if !ctx.has_perm(uid, "mcp_manage") {
            let lang = ctx.lang(uid);
            let msg = format!("{} {}", t(lang, Tx::ModuleRequiredHdr), perm_label(lang, "mcp_manage"));
            ctx.ack(&cq.id, Some(&msg), true).await;
            return true;
        }
        ctx.ack(&cq.id, None, false).await;
        show_mcp(ctx, Some(cq), chat_id, uid).await;
        return true;
    }

    if let Some(rest) = data.strip_prefix("mreq:") {
        let mut it = rest.splitn(2, ':');
        let act = it.next().unwrap_or("");
        let rid = it.next().unwrap_or("");
        match act {
            "app" if !rid.is_empty() => {
                handle_mreq_decision(ctx, cq, uid, chat_id, rid, McpDecision::Approved).await;
            }
            "rej" if !rid.is_empty() => {
                handle_mreq_decision(ctx, cq, uid, chat_id, rid, McpDecision::Rejected).await;
            }
            _ => {
                ctx.ack(&cq.id, Some("Invalid MCP request"), false).await;
            }
        }
        return true;
    }

    if !data.starts_with("mcp:") {
        return false;
    }

    let parts: Vec<&str> = data.split(':').collect();
    let act = parts.get(1).copied().unwrap_or("");

    // Support legacy `mcp:rok:{rid}` / `mcp:rno:{rid}` approval callbacks (owner-only inside handler)
    if matches!(act, "rok" | "rno") && parts.len() >= 3 {
        let dec = if act == "rok" {
            McpDecision::Approved
        } else {
            McpDecision::Rejected
        };
        handle_mreq_decision(ctx, cq, uid, chat_id, parts[2], dec).await;
        return true;
    }

    // All remaining MCP panel & configuration actions require `mcp_manage`
    if !ctx.has_perm(uid, "mcp_manage") {
        let lang = ctx.lang(uid);
        let msg = format!("{} {}", t(lang, Tx::ModuleRequiredHdr), perm_label(lang, "mcp_manage"));
        ctx.ack(&cq.id, Some(&msg), true).await;
        return true;
    }

    // Support direct `mcp:{idx}` shortcut
    if let Ok(direct_idx) = act.parse::<usize>() {
        ctx.ack(&cq.id, None, false).await;
        show_mcp_detail(ctx, Some(cq), chat_id, uid, direct_idx).await;
        return true;
    }

    if act == "p" {
        ctx.ack(&cq.id, None, false).await;
        let page = parts.get(2).and_then(|s| s.parse::<usize>().ok()).unwrap_or(0);
        show_mcp_page(ctx, Some(cq), chat_id, uid, page).await;
        return true;
    }

    if rendered_epoch_stale(ctx, uid) && matches!(act, "v" | "tog" | "rm" | "ecmd" | "earg" | "eurl" | "eenv" | "ejson" | "delok") {
        ctx.ack(&cq.id, Some("لیست قدیمی است — بروزرسانی شد"), false).await;
        show_mcp(ctx, Some(cq), chat_id, uid).await;
        return true;
    }

    if act == "v" {
        ctx.ack(&cq.id, None, false).await;
        let Some(idx) = parts.get(2).and_then(|s| s.parse::<usize>().ok()) else {
            show_mcp(ctx, Some(cq), chat_id, uid).await;
            return true;
        };
        show_mcp_detail(ctx, Some(cq), chat_id, uid, idx).await;
        return true;
    }

    if matches!(act, "ai" | "ai_add") {
        ctx.jobs
            .set_awaiting(uid, AwaitingInput::new("mcp_ai", json!({})));
        ctx.ack(&cq.id, None, false).await;
        let md = format!(
            "### {} نصب خودکار MCP با AI\n\n\
            لینک گیت‌هاب، نام پکیج npm/PyPI یا توضیح سرور MCP موردنظر را ارسال کنید.",
            ctx.premium.md("rocket")
        );
        let mk = BotCtx::kb(vec![vec![ctx.btn(
            "",
            "انصراف",
            Some("inp:cancel"),
            None,
            None,
        )]]);
        let _ = ctx.render.send_rich_card_message(chat_id, &md, Some(mk)).await;
        return true;
    }

    // `mcp:rm:ok:{idx}` confirmation execution
    if act == "rm" && parts.get(2) == Some(&"ok") {
        let Some(idx) = parts.get(3).and_then(|s| s.parse::<usize>().ok()) else {
            ctx.ack(&cq.id, Some("لیست قدیمی است — بروزرسانی شد"), false)
                .await;
            show_mcp(ctx, Some(cq), chat_id, uid).await;
            return true;
        };
        let srvs = get_cached_servers(ctx, uid);
        let Some(target) = srvs.get(idx) else {
            ctx.ack(&cq.id, Some("لیست قدیمی است — بروزرسانی شد"), false)
                .await;
            show_mcp(ctx, Some(cq), chat_id, uid).await;
            return true;
        };
        let ack_txt = match remove_mcp_server(&ctx.cfg.mcp_config_path, &target.name) {
            Ok(m) => m,
            Err(err) => redact_secrets_in_text(&err.to_string()),
        };
        refresh_mcp_cache(ctx, uid);
        ctx.ack(&cq.id, Some(&truncate_chars(&ack_txt, 160)), false)
            .await;
        show_mcp(ctx, Some(cq), chat_id, uid).await;
        return true;
    }

    let Some(idx) = parts.get(2).and_then(|s| s.parse::<usize>().ok()) else {
        ctx.ack(&cq.id, Some("لیست قدیمی است — بروزرسانی شد"), false)
            .await;
        show_mcp(ctx, Some(cq), chat_id, uid).await;
        return true;
    };

    let srvs = get_cached_servers(ctx, uid);
    let Some(cached_srv) = srvs.get(idx).cloned() else {
        ctx.ack(&cq.id, Some("لیست قدیمی است — بروزرسانی شد"), false)
            .await;
        show_mcp(ctx, Some(cq), chat_id, uid).await;
        return true;
    };
    let name = cached_srv.name.clone();

    match act {
        "tog" => {
            match toggle_mcp_server(&ctx.cfg.mcp_config_path, &name, None) {
                Ok(updated) => {
                    refresh_mcp_cache(ctx, uid);
                    let st_lbl = if updated.enabled {
                        "فعال شد"
                    } else {
                        "غیرفعال شد"
                    };
                    ctx.ack(&cq.id, Some(&format!("{name}: {st_lbl}")), false)
                        .await;
                }
                Err(err) => {
                    let clean = redact_secrets_in_text(&err.to_string());
                    ctx.ack(&cq.id, Some(&truncate_chars(&clean, 160)), false)
                        .await;
                }
            }
            show_mcp_detail(ctx, Some(cq), chat_id, uid, idx).await;
        }
        "ecmd" => {
            let cur = get_mcp_server(&ctx.cfg.mcp_config_path, &name)
                .ok()
                .flatten()
                .unwrap_or(cached_srv);
            let cur_val = if !cur.url.trim().is_empty() {
                redact_secrets_in_text(cur.url.trim())
            } else {
                let joined = format!("{} {}", cur.command.trim(), cur.args.join(" "));
                redact_secrets_in_text(joined.trim())
            };
            ctx.jobs.set_awaiting(
                uid,
                AwaitingInput::new("mcp_cmd", json!({"name": name, "idx": idx})),
            );
            ctx.ack(&cq.id, None, false).await;
            let md = format!(
                "### {} ویرایش Command / URL · `{}`\n\n\
                > فعلی: `{}`\n\n\
                آدرس HTTP/HTTPS یا دستور و آرگومان‌ها را ارسال کنید (مثلاً `npx -y @pkg/server`).",
                ctx.premium.md("mcp"),
                md_cell(&name),
                md_cell(if cur_val.is_empty() { "—" } else { &cur_val })
            );
            let mk = BotCtx::kb(vec![vec![ctx.btn(
                "",
                "انصراف",
                Some("inp:cancel"),
                None,
                None,
            )]]);
            let _ = ctx.render.send_rich_card_message(chat_id, &md, Some(mk)).await;
        }
        "earg" => {
            let cur = get_mcp_server(&ctx.cfg.mcp_config_path, &name)
                .ok()
                .flatten()
                .unwrap_or(cached_srv);
            let cur_args = if cur.args.is_empty() {
                "—".to_string()
            } else {
                redact_secrets_in_text(&cur.args.join(" "))
            };
            ctx.jobs.set_awaiting(
                uid,
                AwaitingInput::new("mcp_args", json!({"name": name, "idx": idx})),
            );
            ctx.ack(&cq.id, None, false).await;
            let md = format!(
                "### {} ویرایش Args · `{}`\n\n\
                > فعلی: `{}`\n\n\
                آرگومان‌های جدید را ارسال کنید (یا `-` برای خالی کردن).",
                ctx.premium.md("mcp"),
                md_cell(&name),
                md_cell(&cur_args)
            );
            let mk = BotCtx::kb(vec![vec![ctx.btn(
                "",
                "انصراف",
                Some("inp:cancel"),
                None,
                None,
            )]]);
            let _ = ctx.render.send_rich_card_message(chat_id, &md, Some(mk)).await;
        }
        "eurl" => {
            let cur = get_mcp_server(&ctx.cfg.mcp_config_path, &name)
                .ok()
                .flatten()
                .unwrap_or(cached_srv);
            let cur_url = if cur.url.trim().is_empty() {
                "—".to_string()
            } else {
                redact_secrets_in_text(cur.url.trim())
            };
            ctx.jobs.set_awaiting(
                uid,
                AwaitingInput::new("mcp_url", json!({"name": name, "idx": idx})),
            );
            ctx.ack(&cq.id, None, false).await;
            let md = format!(
                "### {} ویرایش URL · `{}`\n\n\
                > فعلی: `{}`\n\n\
                آدرس HTTP/HTTPS جدید سرور MCP را ارسال کنید.",
                ctx.premium.md("mcp"),
                md_cell(&name),
                md_cell(&cur_url)
            );
            let mk = BotCtx::kb(vec![vec![ctx.btn(
                "",
                "انصراف",
                Some("inp:cancel"),
                None,
                None,
            )]]);
            let _ = ctx.render.send_rich_card_message(chat_id, &md, Some(mk)).await;
        }
        "eenv" => {
            let cur = get_mcp_server(&ctx.cfg.mcp_config_path, &name)
                .ok()
                .flatten()
                .unwrap_or(cached_srv);
            let env_lines: Vec<String> = cur
                .env
                .iter()
                .map(|(k, v)| {
                    let masked = if is_sensitive_key(k) {
                        MASKED_SECRET.to_string()
                    } else {
                        redact_secrets_in_text(v)
                    };
                    format!("{k}={masked}")
                })
                .collect();
            let env_txt = if env_lines.is_empty() {
                "(خالی)".to_string()
            } else {
                env_lines.join("\n")
            };
            ctx.jobs.set_awaiting(
                uid,
                AwaitingInput::new("mcp_env", json!({"name": name, "idx": idx})),
            );
            ctx.ack(&cq.id, None, false).await;
            let md = format!(
                "### {} ویرایش Env · `{}`\n\n\
                ```\n{}\n```\n\n\
                هر خط `KEY=VALUE` برای تنظیم یا `-KEY` برای حذف ارسال کنید.",
                ctx.premium.md("mcp"),
                md_cell(&name),
                env_txt.replace("```", "'''")
            );
            let mk = BotCtx::kb(vec![vec![ctx.btn(
                "",
                "انصراف",
                Some("inp:cancel"),
                None,
                None,
            )]]);
            let _ = ctx.render.send_rich_card_message(chat_id, &md, Some(mk)).await;
        }
        "ejson" => {
            let cur = get_mcp_server(&ctx.cfg.mcp_config_path, &name)
                .ok()
                .flatten()
                .unwrap_or(cached_srv);
            let pretty = serde_json::to_string_pretty(&cur.config_redacted)
                .unwrap_or_else(|_| "{}".to_string());
            let clipped = truncate_chars(&pretty, 2800);
            ctx.jobs.set_awaiting(
                uid,
                AwaitingInput::new("mcp_ejson", json!({"name": name, "idx": idx})),
            );
            ctx.ack(&cq.id, None, false).await;
            let md = format!(
                "### {} ویرایش JSON · `{}`\n\n\
                ```json\n{}\n```\n\n\
                آبجکت JSON جدید را بفرستید (مقادیر `{MASKED_SECRET}` از سکرت قبلی حفظ می‌شوند).",
                ctx.premium.md("mcp"),
                md_cell(&name),
                clipped.replace("```", "'''")
            );
            let mk = BotCtx::kb(vec![vec![ctx.btn(
                "",
                "انصراف",
                Some("inp:cancel"),
                None,
                None,
            )]]);
            let _ = ctx.render.send_rich_card_message(chat_id, &md, Some(mk)).await;
        }
        "rm" | "del" => {
            ctx.ack(&cq.id, None, false).await;
            let md = format!(
                "### {} حذف سرور MCP\n\n> آیا `{}` از کانفیگ حذف شود؟",
                ctx.premium.md("warn"),
                md_cell(&name)
            );
            let rows = vec![vec![
                ctx.btn(
                    "err",
                    "بله، حذف شود",
                    Some(&format!("mcp:rm:ok:{idx}")),
                    Some("danger"),
                    None,
                ),
                ctx.btn("", "انصراف", Some(&format!("mcp:v:{idx}")), None, None),
            ]];
            send_rich_card(ctx, Some(cq), chat_id, &md, rows).await;
        }
        "delok" => {
            let ack_txt = match remove_mcp_server(&ctx.cfg.mcp_config_path, &name) {
                Ok(m) => m,
                Err(err) => redact_secrets_in_text(&err.to_string()),
            };
            refresh_mcp_cache(ctx, uid);
            ctx.ack(&cq.id, Some(&truncate_chars(&ack_txt, 160)), false)
                .await;
            show_mcp(ctx, Some(cq), chat_id, uid).await;
        }
        _ => {
            ctx.ack(&cq.id, None, false).await;
        }
    }

    true
}

async fn rearm_error_card(
    ctx: &BotCtx,
    uid: i64,
    chat_id: i64,
    inp: &AwaitingInput,
    title_md: &str,
) {
    ctx.jobs
        .set_awaiting(uid, AwaitingInput::new(inp.kind.clone(), inp.data.clone()));
    let mk = BotCtx::kb(vec![vec![ctx.btn(
        "",
        "انصراف",
        Some("inp:cancel"),
        None,
        None,
    )]]);
    let _ = ctx
        .render
        .send_rich_card_message(chat_id, title_md, Some(mk))
        .await;
}

fn resolve_new_idx(ctx: &BotCtx, uid: i64, name: &str, fallback_idx: usize) -> usize {
    let srvs = refresh_mcp_cache(ctx, uid);
    srvs.iter()
        .position(|s| s.name == name)
        .unwrap_or(fallback_idx)
}

/// Handle multi-step `AwaitingInput` text for `/mcp`
/// (`mcp_cmd`, `mcp_args`, `mcp_url`, `mcp_env`, `mcp_ejson`, `mcp_ai`).
/// Returns `true` if `inp.kind` was handled by this module.
pub async fn handle_mcp_awaiting_text(
    ctx: &Arc<BotCtx>,
    _msg: &Message,
    uid: i64,
    chat_id: i64,
    user_label: &str,
    inp: &AwaitingInput,
    text: &str,
) -> bool {
    let kind = inp.kind.as_str();
    let is_mcp_kind = matches!(
        kind,
        "mcp_cmd" | "mcp_ecmd" | "mcp_args" | "mcp_url" | "mcp_env" | "mcp_eenv" | "mcp_ejson"
            | "mcp_ai" | "mcp_ai_add"
    );
    if !is_mcp_kind {
        return false;
    }

    if !ctx.has_perm(uid, "mcp_manage") {
        let md = format!(
            "### {} دسترسی غیرمجاز\n\n> `mcp_manage` لازم است.",
            ctx.premium.md("err")
        );
        let _ = ctx.render.send_rich_card_message(chat_id, &md, None).await;
        return true;
    }

    let name = inp
        .data
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let idx = inp
        .data
        .get("idx")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as usize;

    match kind {
        "mcp_cmd" | "mcp_ecmd" => {
            let val = text.trim();
            if val.is_empty() {
                rearm_error_card(
                    ctx,
                    uid,
                    chat_id,
                    inp,
                    &format!(
                        "### {} ورودی خالی است\n\nآدرس HTTP/HTTPS یا دستور را ارسال کنید.",
                        ctx.premium.md("warn")
                    ),
                )
                .await;
                return true;
            }
            let patch = if val.to_ascii_lowercase().starts_with("http://")
                || val.to_ascii_lowercase().starts_with("https://")
            {
                McpServerUpdate {
                    url: Some(val.to_string()),
                    ..Default::default()
                }
            } else {
                let parts = match shell_words::split(val) {
                    Ok(p) if !p.is_empty() => p,
                    Ok(_) => {
                        rearm_error_card(
                            ctx,
                            uid,
                            chat_id,
                            inp,
                            &format!("### {} دستور نامعتبر است", ctx.premium.md("err")),
                        )
                        .await;
                        return true;
                    }
                    Err(err) => {
                        let md = format!(
                            "### {} خطا در ساختار دستور\n\n`{}`",
                            ctx.premium.md("err"),
                            md_cell(&err.to_string())
                        );
                        rearm_error_card(ctx, uid, chat_id, inp, &md).await;
                        return true;
                    }
                };
                McpServerUpdate {
                    command: Some(parts[0].clone()),
                    args: Some(parts[1..].to_vec()),
                    ..Default::default()
                }
            };
            if let Err(err) = update_mcp_server(&ctx.cfg.mcp_config_path, &name, patch) {
                let clean = redact_secrets_in_text(&err.to_string());
                let md = format!(
                    "### {} خطا در ذخیره\n\n`{}`",
                    ctx.premium.md("err"),
                    md_cell(&truncate_chars(&clean, 260))
                );
                rearm_error_card(ctx, uid, chat_id, inp, &md).await;
                return true;
            }
            let new_idx = resolve_new_idx(ctx, uid, &name, idx);
            show_mcp_detail(ctx, None, chat_id, uid, new_idx).await;
            true
        }
        "mcp_args" => {
            let val = text.trim();
            let new_args = if val.is_empty() || val == "-" {
                Vec::new()
            } else {
                match shell_words::split(val) {
                    Ok(p) => p,
                    Err(err) => {
                        let md = format!(
                            "### {} خطا در ساختار Args\n\n`{}`",
                            ctx.premium.md("err"),
                            md_cell(&err.to_string())
                        );
                        rearm_error_card(ctx, uid, chat_id, inp, &md).await;
                        return true;
                    }
                }
            };
            let patch = McpServerUpdate {
                args: Some(new_args),
                ..Default::default()
            };
            if let Err(err) = update_mcp_server(&ctx.cfg.mcp_config_path, &name, patch) {
                let clean = redact_secrets_in_text(&err.to_string());
                let md = format!(
                    "### {} خطا در ذخیره\n\n`{}`",
                    ctx.premium.md("err"),
                    md_cell(&truncate_chars(&clean, 260))
                );
                rearm_error_card(ctx, uid, chat_id, inp, &md).await;
                return true;
            }
            let new_idx = resolve_new_idx(ctx, uid, &name, idx);
            show_mcp_detail(ctx, None, chat_id, uid, new_idx).await;
            true
        }
        "mcp_url" => {
            let val = text.trim();
            if val.is_empty() {
                rearm_error_card(
                    ctx,
                    uid,
                    chat_id,
                    inp,
                    &format!(
                        "### {} ورودی خالی است\n\nآدرس HTTP/HTTPS را ارسال کنید.",
                        ctx.premium.md("warn")
                    ),
                )
                .await;
                return true;
            }
            let patch = McpServerUpdate {
                url: Some(val.to_string()),
                ..Default::default()
            };
            if let Err(err) = update_mcp_server(&ctx.cfg.mcp_config_path, &name, patch) {
                let clean = redact_secrets_in_text(&err.to_string());
                let md = format!(
                    "### {} خطا در ذخیره URL\n\n`{}`",
                    ctx.premium.md("err"),
                    md_cell(&truncate_chars(&clean, 260))
                );
                rearm_error_card(ctx, uid, chat_id, inp, &md).await;
                return true;
            }
            let new_idx = resolve_new_idx(ctx, uid, &name, idx);
            show_mcp_detail(ctx, None, chat_id, uid, new_idx).await;
            true
        }
        "mcp_env" | "mcp_eenv" => {
            let mut env_set: BTreeMap<String, String> = BTreeMap::new();
            let mut env_unset: Vec<String> = Vec::new();
            let mut bad_lines: Vec<String> = Vec::new();

            for raw_ln in text.lines() {
                let ln = raw_ln.trim();
                if ln.is_empty() || ln.starts_with('#') {
                    continue;
                }
                if let Some(rest) = ln.strip_prefix('-') {
                    let k_un = rest.trim();
                    if k_un.is_empty() {
                        bad_lines.push(ln.to_string());
                    } else {
                        env_unset.push(k_un.to_string());
                    }
                } else if let Some((k_raw, v_raw)) = ln.split_once('=') {
                    let k_ev = k_raw.trim();
                    let v_ev = v_raw.trim();
                    if k_ev.is_empty() {
                        bad_lines.push(ln.to_string());
                        continue;
                    }
                    if v_ev == MASKED_SECRET {
                        continue;
                    }
                    env_set.insert(k_ev.to_string(), v_ev.to_string());
                } else {
                    bad_lines.push(ln.to_string());
                }
            }

            if !bad_lines.is_empty() {
                rearm_error_card(
                    ctx,
                    uid,
                    chat_id,
                    inp,
                    &format!(
                        "### {} فرمت نامعتبر\n\nهر خط باید `KEY=VALUE` یا `-KEY` باشد.",
                        ctx.premium.md("err")
                    ),
                )
                .await;
                return true;
            }

            let patch = McpServerUpdate {
                env_set: Some(env_set),
                env_unset: Some(env_unset),
                ..Default::default()
            };
            if let Err(err) = update_mcp_server(&ctx.cfg.mcp_config_path, &name, patch) {
                let clean = redact_secrets_in_text(&err.to_string());
                let md = format!(
                    "### {} خطا در ذخیره Env\n\n`{}`",
                    ctx.premium.md("err"),
                    md_cell(&truncate_chars(&clean, 260))
                );
                rearm_error_card(ctx, uid, chat_id, inp, &md).await;
                return true;
            }
            let new_idx = resolve_new_idx(ctx, uid, &name, idx);
            show_mcp_detail(ctx, None, chat_id, uid, new_idx).await;
            true
        }
        "mcp_ejson" => {
            let raw_json = strip_json_fence(text);
            if let Err(err) = replace_mcp_server_json(&ctx.cfg.mcp_config_path, &name, &raw_json) {
                let clean = redact_secrets_in_text(&err.to_string());
                let md = format!(
                    "### {} JSON نامعتبر\n\n`{}`",
                    ctx.premium.md("err"),
                    md_cell(&truncate_chars(&clean, 260))
                );
                rearm_error_card(ctx, uid, chat_id, inp, &md).await;
                return true;
            }
            let new_idx = resolve_new_idx(ctx, uid, &name, idx);
            show_mcp_detail(ctx, None, chat_id, uid, new_idx).await;
            true
        }
        "mcp_ai" | "mcp_ai_add" => {
            let spec_txt = text.trim();
            if spec_txt.is_empty() {
                rearm_error_card(
                    ctx,
                    uid,
                    chat_id,
                    inp,
                    &format!(
                        "### {} مشخصات خالی است\n\nلینک یا توضیح سرور MCP را ارسال کنید.",
                        ctx.premium.md("warn")
                    ),
                )
                .await;
                return true;
            }

            if ctx.is_owner(uid) {
                let cfg_path = ctx.cfg.mcp_config_path.to_string_lossy();
                let install_prompt = build_mcp_install_prompt("owner-direct", spec_txt, &cfg_path);
                let mut job_req =
                    JobRequest::new(uid, chat_id, user_label, install_prompt, Vec::new());
                job_req.overrides = JobOverride {
                    isolated: true,
                    owner_approved_mcp: true,
                    skip_permissions: Some(true),
                    force_engine: Some("agy".to_string()),
                    ..Default::default()
                };
                let _ = ctx.jobs.enqueue(job_req).await;
                let md = format!(
                    "### {} نصب MCP توسط مالک آغاز شد\n\n> عملیات نصب و تست در صف اجرا قرار گرفت.",
                    ctx.premium.md("rocket")
                );
                let mk = BotCtx::kb(vec![vec![ctx.btn(
                    "mcp",
                    "سرورهای MCP",
                    Some("mcp"),
                    None,
                    None,
                )]]);
                let _ = ctx.render.send_rich_card_message(chat_id, &md, Some(mk)).await;
                return true;
            }

            match ctx
                .acl
                .create_mcp_request(uid, user_label, chat_id, spec_txt)
            {
                Ok(req) => {
                    let rid = req.req_id.clone();
                    let spec_safe = truncate_chars(&redact_secrets_in_text(&req.spec_text), 1500)
                        .replace('`', "'");
                    let owner_md = [
                        format!("### {} درخواست نصب MCP با AI", ctx.premium.md("rocket")),
                        String::new(),
                        "| فیلد | مقدار |".to_string(),
                        "|---|---|".to_string(),
                        format!("| شناسه | `{}` |", md_cell(&rid)),
                        format!("| درخواست‌کننده | {} (`{uid}`) |", md_cell(user_label)),
                        String::new(),
                        "<details><summary>مشخصات درخواستی</summary>".to_string(),
                        spec_safe,
                        "</details>".to_string(),
                    ]
                    .join("\n");
                    let owner_mk = BotCtx::kb(vec![vec![
                        ctx.btn(
                            "ok",
                            "تایید و نصب",
                            Some(&format!("mreq:app:{rid}")),
                            Some("success"),
                            None,
                        ),
                        ctx.btn(
                            "err",
                            "رد",
                            Some(&format!("mreq:rej:{rid}")),
                            Some("danger"),
                            None,
                        ),
                    ]]);
                    ctx.broadcast_owners_rich(&owner_md, Some(owner_mk)).await;

                    let user_md = format!(
                        "### {} درخواست نصب MCP ثبت شد\n\n> شناسه: `{}` — منتظر تایید مالک.",
                        ctx.premium.md("ok"),
                        md_cell(&rid)
                    );
                    let user_mk = BotCtx::kb(vec![vec![ctx.btn(
                        "mcp",
                        "سرورهای MCP",
                        Some("mcp"),
                        None,
                        None,
                    )]]);
                    let _ = ctx
                        .render
                        .send_rich_card_message(chat_id, &user_md, Some(user_mk))
                        .await;
                }
                Err(err) => {
                    warn!(uid, error = %err, "failed creating MCP request");
                    let md = format!(
                        "### {} خطا در ثبت درخواست\n\n`{}`",
                        ctx.premium.md("err"),
                        md_cell(&redact_secrets_in_text(&err.to_string()))
                    );
                    let _ = ctx.render.send_rich_card_message(chat_id, &md, None).await;
                }
            }
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
    use serde_json::{json, Value};
    use std::path::PathBuf;
    use tempfile::TempDir;
    use tokio::net::TcpListener;
    use tokio::sync::Mutex;

    const OWNER: i64 = 1_000_000_001;
    const STD_USER: i64 = 1_000_000_002;
    const DEV_USER: i64 = 7_291_430_297;

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
            "answerCallbackQuery" => json!(true),
            _ => json!({"message_id": 88, "chat": {"id": 1, "type": "private"}, "text": "ok"}),
        };
        Json(json!({"ok": true, "result": res}))
    }

    async fn setup_ctx(dir: &TempDir) -> (Arc<BotCtx>, MockTg) {
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
        std::fs::create_dir_all(&state_dir).unwrap();
        let mcp_path = dir.path().join("mcp_config.json");
        std::fs::write(
            &mcp_path,
            serde_json::to_string_pretty(&json!({
                "mcpServers": {
                    "alpha": {
                        "command": "node",
                        "args": ["srv.js"],
                        "env": {
                            "API_KEY": "super-secret-value-xyz",
                            "LOG_LEVEL": "info"
                        }
                    },
                    "remote": {
                        "url": "https://mcp.example.com/sse",
                        "headers": {
                            "Authorization": "Bearer secret-header-token-999"
                        }
                    }
                }
            }))
            .unwrap(),
        )
        .unwrap();

        let cfg = Arc::new(Config {
            bot_token: "123:ABC".into(),
            state_dir: state_dir.clone(),
            agy_workspace: dir.path().to_path_buf(),
            owner_id: OWNER,
            agy_bin: PathBuf::from("/bin/true"),
            mcp_config_path: mcp_path,
            ..Default::default()
        });
        let store = Arc::new(StateStore::open(cfg.state_path()).unwrap());
        let acl = Arc::new(AclStore::open(cfg.acl_path(), OWNER, &[STD_USER, DEV_USER], 300).unwrap());
        acl.set_status(STD_USER, UserStatus::Approved, Some(OWNER), Some(RolePreset::Std))
            .unwrap();
        acl.set_status(DEV_USER, UserStatus::Approved, Some(OWNER), Some(RolePreset::Dev))
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
        let cron =
            Arc::new(crate::cron::CronScheduler::new(Arc::clone(&cfg), Arc::clone(&health)).unwrap());
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
        (
            BotCtx::new(
                cfg, store, acl, outbox, health, premium, pool, client, widgets, render, cron,
                jobs, auth,
            ),
            st,
        )
    }

    fn mk_msg(uid: i64, text: &str) -> Message {
        Message {
            message_id: 1,
            from_user: Some(User {
                id: uid,
                is_bot: false,
                first_name: "U".into(),
                last_name: None,
                username: Some("u".into()),
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
            id: "cq-mcp".into(),
            from_user: User {
                id: uid,
                is_bot: false,
                first_name: "U".into(),
                last_name: None,
                username: Some("u".into()),
                language_code: None,
                is_premium: Some(false),
            },
            message: Some(mk_msg(uid, "mcp")),
            inline_message_id: None,
            data: Some(data.into()),
        }
    }

    #[tokio::test]
    async fn mcp_secret_redaction_and_acl_enforcement() {
        let dir = TempDir::new().unwrap();
        let (ctx, st) = setup_ctx(&dir).await;

        // Locked STD_USER (without mcp_manage) is denied BOTH view & mutating MCP actions
        cmd_mcp(&ctx, &mk_msg(STD_USER, "/mcp")).await;
        for cb in [
            "mcp",
            "mcp:v:0",
            "mcp:v:1",
            "mcp:tog:0",
            "mcp:rm:0",
            "mcp:ecmd:0",
            "mcp:earg:0",
            "mcp:eurl:1",
            "mcp:eenv:0",
            "mcp:ejson:0",
            "mcp:ai",
        ] {
            assert!(handle_mcp_cb(&ctx, &mk_cq(STD_USER, cb), STD_USER, STD_USER, cb).await);
            assert!(ctx.jobs.take_awaiting(STD_USER).is_none());
        }
        assert!(get_mcp_server(&ctx.cfg.mcp_config_path, "alpha").unwrap().unwrap().enabled);

        // DEV_USER (has mcp_manage) can view details & open edit prompts, and raw secrets MUST still be redacted
        assert!(handle_mcp_cb(&ctx, &mk_cq(DEV_USER, "mcp:v:0"), DEV_USER, DEV_USER, "mcp:v:0").await);
        assert!(handle_mcp_cb(&ctx, &mk_cq(DEV_USER, "mcp:v:1"), DEV_USER, DEV_USER, "mcp:v:1").await);
        assert!(handle_mcp_cb(&ctx, &mk_cq(DEV_USER, "mcp:eenv:0"), DEV_USER, DEV_USER, "mcp:eenv:0").await);
        let _ = ctx.jobs.take_awaiting(DEV_USER).unwrap();
        assert!(handle_mcp_cb(&ctx, &mk_cq(DEV_USER, "mcp:ejson:0"), DEV_USER, DEV_USER, "mcp:ejson:0").await);
        let _ = ctx.jobs.take_awaiting(DEV_USER).unwrap();

        let calls = st.calls.lock().await;
        let dumped = serde_json::to_string(&*calls).unwrap();
        assert!(!dumped.contains("super-secret-value-xyz"));
        assert!(!dumped.contains("secret-header-token-999"));
        assert!(dumped.contains(MASKED_SECRET));
    }

    #[tokio::test]
    async fn mcp_crud_awaiting_text_and_non_owner_mreq_approval_flow() {
        let dir = TempDir::new().unwrap();
        let (ctx, st) = setup_ctx(&dir).await;

        // 1. DEV_USER toggles alpha, edits cmd/args/url/env/json, then deletes remote
        assert!(handle_mcp_cb(&ctx, &mk_cq(DEV_USER, "mcp:tog:0"), DEV_USER, DEV_USER, "mcp:tog:0").await);
        assert!(!get_mcp_server(&ctx.cfg.mcp_config_path, "alpha").unwrap().unwrap().enabled);

        assert!(handle_mcp_cb(&ctx, &mk_cq(DEV_USER, "mcp:ecmd:0"), DEV_USER, DEV_USER, "mcp:ecmd:0").await);
        let inp_cmd = ctx.jobs.take_awaiting(DEV_USER).unwrap();
        assert_eq!(inp_cmd.kind, "mcp_cmd");
        assert!(
            handle_mcp_awaiting_text(
                &ctx,
                &mk_msg(DEV_USER, "npx -y @org/mcp"),
                DEV_USER,
                DEV_USER,
                "Dev",
                &inp_cmd,
                "npx -y @org/mcp",
            )
            .await
        );
        let srv_a = get_mcp_server(&ctx.cfg.mcp_config_path, "alpha").unwrap().unwrap();
        assert_eq!(srv_a.command, "npx");
        assert_eq!(srv_a.args, vec!["-y", "@org/mcp"]);

        assert!(handle_mcp_cb(&ctx, &mk_cq(DEV_USER, "mcp:earg:0"), DEV_USER, DEV_USER, "mcp:earg:0").await);
        let inp_arg = ctx.jobs.take_awaiting(DEV_USER).unwrap();
        assert_eq!(inp_arg.kind, "mcp_args");
        assert!(
            handle_mcp_awaiting_text(
                &ctx,
                &mk_msg(DEV_USER, "--port 9000"),
                DEV_USER,
                DEV_USER,
                "Dev",
                &inp_arg,
                "--port 9000",
            )
            .await
        );
        assert_eq!(
            get_mcp_server(&ctx.cfg.mcp_config_path, "alpha").unwrap().unwrap().args,
            vec!["--port", "9000"]
        );

        assert!(handle_mcp_cb(&ctx, &mk_cq(DEV_USER, "mcp:eurl:1"), DEV_USER, DEV_USER, "mcp:eurl:1").await);
        let inp_url = ctx.jobs.take_awaiting(DEV_USER).unwrap();
        assert_eq!(inp_url.kind, "mcp_url");
        assert!(
            handle_mcp_awaiting_text(
                &ctx,
                &mk_msg(DEV_USER, "https://new.example.com/mcp"),
                DEV_USER,
                DEV_USER,
                "Dev",
                &inp_url,
                "https://new.example.com/mcp",
            )
            .await
        );
        assert_eq!(
            get_mcp_server(&ctx.cfg.mcp_config_path, "remote").unwrap().unwrap().url,
            "https://new.example.com/mcp"
        );

        assert!(handle_mcp_cb(&ctx, &mk_cq(DEV_USER, "mcp:eenv:0"), DEV_USER, DEV_USER, "mcp:eenv:0").await);
        let inp_env = ctx.jobs.take_awaiting(DEV_USER).unwrap();
        assert_eq!(inp_env.kind, "mcp_env");
        assert!(
            handle_mcp_awaiting_text(
                &ctx,
                &mk_msg(DEV_USER, "LOG_LEVEL=debug\nNEW_OPT=1"),
                DEV_USER,
                DEV_USER,
                "Dev",
                &inp_env,
                "LOG_LEVEL=debug\nNEW_OPT=1",
            )
            .await
        );
        let env_after = get_mcp_server(&ctx.cfg.mcp_config_path, "alpha").unwrap().unwrap().env;
        assert_eq!(env_after.get("LOG_LEVEL").map(String::as_str), Some("debug"));
        assert_eq!(env_after.get("NEW_OPT").map(String::as_str), Some("1"));
        assert_eq!(env_after.get("API_KEY").map(String::as_str), Some(MASKED_SECRET));

        assert!(handle_mcp_cb(&ctx, &mk_cq(DEV_USER, "mcp:ejson:0"), DEV_USER, DEV_USER, "mcp:ejson:0").await);
        let inp_json = ctx.jobs.take_awaiting(DEV_USER).unwrap();
        assert_eq!(inp_json.kind, "mcp_ejson");
        let json_payload = format!(
            "```json\n{}\n```",
            json!({
                "command": "uvx",
                "args": ["mcp-server"],
                "env": {"API_KEY": MASKED_SECRET, "LOG_LEVEL": "warn"}
            })
        );
        assert!(
            handle_mcp_awaiting_text(
                &ctx,
                &mk_msg(DEV_USER, &json_payload),
                DEV_USER,
                DEV_USER,
                "Dev",
                &inp_json,
                &json_payload,
            )
            .await
        );
        assert_eq!(
            get_mcp_server(&ctx.cfg.mcp_config_path, "alpha").unwrap().unwrap().command,
            "uvx"
        );
        // Secret was preserved on disk!
        let disk_raw = std::fs::read_to_string(&ctx.cfg.mcp_config_path).unwrap();
        assert!(disk_raw.contains("super-secret-value-xyz"));

        // Confirm and remove `remote` (idx 1)
        assert!(handle_mcp_cb(&ctx, &mk_cq(DEV_USER, "mcp:rm:1"), DEV_USER, DEV_USER, "mcp:rm:1").await);
        assert!(handle_mcp_cb(&ctx, &mk_cq(DEV_USER, "mcp:rm:ok:1"), DEV_USER, DEV_USER, "mcp:rm:ok:1").await);
        assert!(get_mcp_server(&ctx.cfg.mcp_config_path, "remote").unwrap().is_none());

        // 2. Non-owner DEV_USER submits mcp_ai -> creates McpRequest + owner notice with mreq:app / mreq:rej
        assert!(handle_mcp_cb(&ctx, &mk_cq(DEV_USER, "mcp:ai"), DEV_USER, DEV_USER, "mcp:ai").await);
        let inp_ai = ctx.jobs.take_awaiting(DEV_USER).unwrap();
        assert_eq!(inp_ai.kind, "mcp_ai");
        assert!(
            handle_mcp_awaiting_text(
                &ctx,
                &mk_msg(DEV_USER, "install @modelcontextprotocol/server-filesystem"),
                DEV_USER,
                DEV_USER,
                "Dev",
                &inp_ai,
                "install @modelcontextprotocol/server-filesystem",
            )
            .await
        );
        assert_eq!(ctx.acl.mcp_request_count(), 1);

        // Extract req_id from emitted mreq:app:{rid} callback in mock calls
        let rid = {
            let calls = st.calls.lock().await;
            let found = calls.iter().find_map(|(_, p)| {
                let rows = p.pointer("/reply_markup/inline_keyboard")?.as_array()?;
                for row in rows {
                    for b in row.as_array()? {
                        let cb = b.get("callback_data")?.as_str()?;
                        if let Some(id) = cb.strip_prefix("mreq:app:") {
                            return Some(id.to_string());
                        }
                    }
                }
                None
            });
            found.expect("expected mreq:app callback button")
        };

        // Non-owner cannot approve/reject mreq:*
        let app_cb = format!("mreq:app:{rid}");
        assert!(handle_mcp_cb(&ctx, &mk_cq(DEV_USER, &app_cb), DEV_USER, DEV_USER, &app_cb).await);
        assert_eq!(ctx.acl.get_mcp_request(&rid).unwrap().status, McpRequestStatus::Pending);

        // Owner rejects cleanly
        let rej_cb = format!("mreq:rej:{rid}");
        assert!(handle_mcp_cb(&ctx, &mk_cq(OWNER, &rej_cb), OWNER, OWNER, &rej_cb).await);
        assert_eq!(ctx.acl.get_mcp_request(&rid).unwrap().status, McpRequestStatus::Rejected);
    }

    #[tokio::test]
    async fn mcp_owner_immediate_ai_mreq_approve_idempotent_and_validation_rearms() {
        let dir = TempDir::new().unwrap();
        let (ctx, st) = setup_ctx(&dir).await;

        // 1. Invalid JSON & malformed env line re-arm AwaitingInput cleanly
        assert!(handle_mcp_cb(&ctx, &mk_cq(DEV_USER, "mcp:ejson:0"), DEV_USER, DEV_USER, "mcp:ejson:0").await);
        let inp_bad_json = ctx.jobs.take_awaiting(DEV_USER).unwrap();
        assert!(
            handle_mcp_awaiting_text(
                &ctx,
                &mk_msg(DEV_USER, "{not-valid-json"),
                DEV_USER,
                DEV_USER,
                "Dev",
                &inp_bad_json,
                "{not-valid-json",
            )
            .await
        );
        assert_eq!(ctx.jobs.take_awaiting(DEV_USER).unwrap().kind, "mcp_ejson");

        assert!(handle_mcp_cb(&ctx, &mk_cq(DEV_USER, "mcp:eenv:0"), DEV_USER, DEV_USER, "mcp:eenv:0").await);
        let inp_bad_env = ctx.jobs.take_awaiting(DEV_USER).unwrap();
        assert!(
            handle_mcp_awaiting_text(
                &ctx,
                &mk_msg(DEV_USER, "MISSING_EQUALS_SIGN"),
                DEV_USER,
                DEV_USER,
                "Dev",
                &inp_bad_env,
                "MISSING_EQUALS_SIGN",
            )
            .await
        );
        assert_eq!(ctx.jobs.take_awaiting(DEV_USER).unwrap().kind, "mcp_env");

        // Unset LOG_LEVEL via -LOG_LEVEL
        assert!(
            handle_mcp_awaiting_text(
                &ctx,
                &mk_msg(DEV_USER, "-LOG_LEVEL"),
                DEV_USER,
                DEV_USER,
                "Dev",
                &inp_bad_env,
                "-LOG_LEVEL",
            )
            .await
        );
        assert!(!get_mcp_server(&ctx.cfg.mcp_config_path, "alpha").unwrap().unwrap().env.contains_key("LOG_LEVEL"));

        // 2. Owner mcp_ai executes immediately WITHOUT creating an McpRequest
        let before_reqs = ctx.acl.mcp_request_count();
        assert!(handle_mcp_cb(&ctx, &mk_cq(OWNER, "mcp:ai"), OWNER, OWNER, "mcp:ai").await);
        let owner_inp = ctx.jobs.take_awaiting(OWNER).unwrap();
        assert!(
            handle_mcp_awaiting_text(
                &ctx,
                &mk_msg(OWNER, "install @org/owner-mcp"),
                OWNER,
                OWNER,
                "Owner",
                &owner_inp,
                "install @org/owner-mcp",
            )
            .await
        );
        assert_eq!(ctx.acl.mcp_request_count(), before_reqs);

        // 3. Non-owner creates request -> owner approves via mreq:app -> second mreq:app is idempotent
        let req = ctx
            .acl
            .create_mcp_request(DEV_USER, "Dev", DEV_USER, "install @org/dev-mcp")
            .unwrap();
        let app_cb = format!("mreq:app:{}", req.req_id);
        assert!(handle_mcp_cb(&ctx, &mk_cq(OWNER, &app_cb), OWNER, OWNER, &app_cb).await);
        assert_eq!(
            ctx.acl.get_mcp_request(&req.req_id).unwrap().status,
            McpRequestStatus::Approved
        );
        // Second click is idempotent no-op
        assert!(handle_mcp_cb(&ctx, &mk_cq(OWNER, &app_cb), OWNER, OWNER, &app_cb).await);

        let calls = st.calls.lock().await;
        assert!(calls.iter().any(|(m, p)| {
            m == "answerCallbackQuery"
                && p["text"].as_str().is_some_and(|t| t.contains("قبلاً"))
        }));
    }
}
