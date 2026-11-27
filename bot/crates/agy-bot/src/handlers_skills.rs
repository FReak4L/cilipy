//! `/skills` browser, SkillPort & community catalog installer, and AI skill creator.

use std::sync::{Arc, OnceLock};

use agy_core::tg::{CallbackQuery, InlineKeyboardButton, Message};
use agy_ext::mcp_client::redact_secrets_in_text;
use agy_ext::skills::{
    delete_installed_skill, get_installed_skill, install_catalog_skill, install_skillport_skill,
    list_catalog_domains, list_installed_skills, list_skillport_namespaces, list_skillport_skills,
    search_catalog_skills, CatalogDomain, CatalogSkill, InstalledSkill, SkillPortSkill,
};
use agy_render::md_cell;
use dashmap::DashMap;
use serde_json::json;

use crate::ctx::{BotCtx, SkillViewState};
use crate::i18n::{missing_perm_html, perm_label, t, Tx};
use crate::jobs::{AwaitingInput, JobOverride, JobRequest};

const SKILLS_PER_PAGE: usize = 8;
const CATALOG_SEARCH_LIMIT: usize = 40;
const CATALOG_INSTALL_TIMEOUT_SECS: f64 = 30.0;

#[derive(Debug, Default, Clone)]
struct SkillBrowserCache {
    inst: Vec<InstalledSkill>,
    sp: Vec<SkillPortSkill>,
    sp_ns: Vec<String>,
    sp_ns_cur: Option<String>,
    sp_q: String,
    cat: Vec<CatalogSkill>,
    cat_dom: Vec<CatalogDomain>,
    cat_dom_cur: Option<String>,
    cat_q: String,
}

fn skill_cache() -> &'static DashMap<i64, SkillBrowserCache> {
    static CACHE: OnceLock<DashMap<i64, SkillBrowserCache>> = OnceLock::new();
    CACHE.get_or_init(DashMap::new)
}

fn truncate_chars(s: &str, max_chars: usize) -> String {
    agy_core::text::truncate_chars(s, max_chars)
}

fn sync_ctx_view(ctx: &BotCtx, uid: i64, tab: &str, cache: &SkillBrowserCache) {
    let q = match tab {
        "sp" => cache.sp_q.clone(),
        "cat" => cache.cat_q.clone(),
        _ => String::new(),
    };
    ctx.sk_view.insert(
        uid,
        SkillViewState {
            tab: tab.to_string(),
            sp_ns: cache.sp_ns_cur.clone(),
            cat_dom: cache.cat_dom_cur.clone(),
            q,
        },
    );
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

/// Handle `/skills` slash command.
pub async fn cmd_skills(ctx: &Arc<BotCtx>, msg: &Message) {
    let Some(uid) = msg.from_user.as_ref().map(|u| u.id) else {
        return;
    };
    if !ctx.has_perm(uid, "skills_manage") {
        let _ = ctx
            .render
            .send_html_simple(msg.chat.id, &missing_perm_html(ctx, uid, "skills_manage"), None)
            .await;
        return;
    }
    show_skills(ctx, None, msg.chat.id, 0, uid).await;
}

/// Render or edit the installed skills browser (`skills:{page}`).
pub async fn show_skills(
    ctx: &Arc<BotCtx>,
    cq: Option<&CallbackQuery>,
    chat_id: i64,
    page: usize,
    uid: i64,
) {
    let can_m = ctx.has_perm(uid, "skills_manage");
    let inst = list_installed_skills(&ctx.skills_dir()).unwrap_or_default();

    {
        let mut entry = skill_cache().entry(uid).or_default();
        entry.inst = inst.clone();
        sync_ctx_view(ctx, uid, "inst", &entry);
    }

    let pages = inst.len().div_ceil(SKILLS_PER_PAGE).max(1);
    let page = page.min(pages - 1);
    let start = page * SKILLS_PER_PAGE;
    let end = (start + SKILLS_PER_PAGE).min(inst.len());

    let mut md_lines = vec![
        format!("### {} {}", ctx.premium.md("skills"), t(ctx.lang(uid), Tx::PanelSkillsTitle)),
        format!(
            "> **{}** نصب‌شده · صفحه **{}/{pages}**",
            inst.len(),
            page + 1
        ),
        String::new(),
        "| اسکیل | توضیح |".to_string(),
        "|---|---|".to_string(),
    ];

    let chunk: Vec<(usize, &InstalledSkill)> = inst
        .iter()
        .enumerate()
        .skip(start)
        .take(end.saturating_sub(start))
        .collect();

    if chunk.is_empty() {
        md_lines.push("| — | اسکیلی نصب نشده است |".to_string());
    } else {
        for &(_, s) in &chunk {
            let desc = if s.description.trim().is_empty() {
                "—"
            } else {
                &s.description
            };
            md_lines.push(format!(
                "| {} | {} |",
                md_cell(&s.name),
                md_cell(&truncate_chars(desc, 60))
            ));
        }
    }

    let top_row = vec![
        ctx.btn("", "SkillPort (64)", Some("sk:sp:ns"), Some("primary"), None),
        ctx.btn("", "کاتالوگ (9.1k)", Some("sk:cat:dom"), Some("primary"), None),
    ];
    let mut second_row = vec![ctx.btn("", "📚 Skill Hub", Some("hub:open"), None, None)];
    if can_m {
        second_row.push(ctx.btn("", "با AI", Some("sk:ai_new"), None, None));
    }
    let mut rows: Vec<Vec<InlineKeyboardButton>> = vec![top_row, second_row];

    for pair in chunk.chunks(2) {
        let row = pair
            .iter()
            .map(|&(idx, s)| {
                ctx.btn(
                    "",
                    &truncate_chars(&s.name, 22),
                    Some(&format!("sk:inst:{idx}")),
                    None,
                    None,
                )
            })
            .collect();
        rows.push(row);
    }

    if pages > 1 {
        let mut nav = Vec::new();
        if page > 0 {
            nav.push(ctx.btn(
                "",
                "‹ قبلی",
                Some(&format!("skills:{}", page - 1)),
                None,
                None,
            ));
        }
        if page + 1 < pages {
            nav.push(ctx.btn(
                "",
                "بعدی ›",
                Some(&format!("skills:{}", page + 1)),
                None,
                None,
            ));
        }
        rows.push(nav);
    }
    rows.push(ctx.back_row());

    send_rich_card(ctx, cq, chat_id, &md_lines.join("\n"), rows).await;
}

async fn show_skillport_list(
    ctx: &Arc<BotCtx>,
    cq: Option<&CallbackQuery>,
    chat_id: i64,
    uid: i64,
    ns: Option<&str>,
    q: &str,
    page: usize,
) {
    let q_opt = (!q.trim().is_empty()).then_some(q.trim());
    let items = list_skillport_skills(
        ns,
        q_opt,
        &ctx.cfg.skillport_skills_dir,
        &ctx.skills_dir(),
    )
    .unwrap_or_default();

    let ns_list = {
        let mut entry = skill_cache().entry(uid).or_default();
        if entry.sp_ns.is_empty() {
            entry.sp_ns = list_skillport_namespaces(&ctx.cfg.skillport_skills_dir)
                .unwrap_or_default()
                .into_iter()
                .map(|n| n.name)
                .collect();
        }
        entry.sp = items.clone();
        entry.sp_ns_cur = ns.map(ToString::to_string);
        entry.sp_q = q.to_string();
        sync_ctx_view(ctx, uid, "sp", &entry);
        entry.sp_ns.clone()
    };

    let pages = items.len().div_ceil(SKILLS_PER_PAGE).max(1);
    let page = page.min(pages - 1);
    let start = page * SKILLS_PER_PAGE;
    let end = (start + SKILLS_PER_PAGE).min(items.len());
    let chunk: Vec<(usize, &SkillPortSkill)> = items
        .iter()
        .enumerate()
        .skip(start)
        .take(end.saturating_sub(start))
        .collect();

    let hdr = if let Some(n) = ns {
        format!("دسته `{}`", md_cell(n))
    } else if !q.trim().is_empty() {
        format!("جستجو `{}`", md_cell(q.trim()))
    } else {
        "همه".to_string()
    };

    let mut md_lines = vec![
        format!("### {} SkillPort", ctx.premium.md("skills")),
        format!(
            "> {hdr} · **{}** مورد · صفحه **{}/{pages}**",
            items.len(),
            page + 1
        ),
        String::new(),
        "| اسکیل | وضعیت |".to_string(),
        "|---|---|".to_string(),
    ];

    if chunk.is_empty() {
        md_lines.push("| — | موردی یافت نشد |".to_string());
    } else {
        for &(_, s) in &chunk {
            let st_lbl = if s.installed {
                "✓ نصب‌شده"
            } else {
                "آماده نصب"
            };
            md_lines.push(format!(
                "| {} (`{}`) | {st_lbl} |",
                md_cell(&s.name),
                md_cell(&s.namespace)
            ));
        }
    }

    let mut rows: Vec<Vec<InlineKeyboardButton>> = Vec::new();
    for pair in chunk.chunks(2) {
        let row = pair
            .iter()
            .map(|&(idx, s)| {
                let mark = if s.installed { "✓" } else { "○" };
                ctx.btn(
                    "",
                    &format!("{mark} {}", truncate_chars(&s.name, 20)),
                    Some(&format!("sk:spv:{idx}")),
                    None,
                    None,
                )
            })
            .collect();
        rows.push(row);
    }

    let pfx = match ns.and_then(|n| ns_list.iter().position(|x| x == n)) {
        Some(ns_idx) => format!("sk:sp:n:{ns_idx}"),
        None => "sk:sp:all".to_string(),
    };
    if pages > 1 {
        let mut nav = Vec::new();
        if page > 0 {
            nav.push(ctx.btn(
                "",
                "‹ قبلی",
                Some(&format!("{pfx}:{}", page - 1)),
                None,
                None,
            ));
        }
        if page + 1 < pages {
            nav.push(ctx.btn(
                "",
                "بعدی ›",
                Some(&format!("{pfx}:{}", page + 1)),
                None,
                None,
            ));
        }
        rows.push(nav);
    }

    rows.push(vec![
        ctx.btn("", "« دسته‌ها", Some("sk:sp:ns"), None, None),
        ctx.btn("", "« اسکیل‌ها", Some("skills:0"), None, None),
    ]);

    send_rich_card(ctx, cq, chat_id, &md_lines.join("\n"), rows).await;
}

async fn show_catalog_list(
    ctx: &Arc<BotCtx>,
    cq: Option<&CallbackQuery>,
    chat_id: i64,
    uid: i64,
    domain: Option<&str>,
    q: &str,
    page: usize,
) {
    let items = search_catalog_skills(
        q,
        domain,
        CATALOG_SEARCH_LIMIT,
        &ctx.cfg.skills_catalog_json,
        &ctx.skills_dir(),
    )
    .unwrap_or_default();

    let doms = {
        let mut entry = skill_cache().entry(uid).or_default();
        if entry.cat_dom.is_empty() {
            entry.cat_dom = list_catalog_domains(&ctx.cfg.skills_catalog_json).unwrap_or_default();
        }
        entry.cat = items.clone();
        entry.cat_dom_cur = domain.map(ToString::to_string);
        entry.cat_q = q.to_string();
        sync_ctx_view(ctx, uid, "cat", &entry);
        entry.cat_dom.clone()
    };

    let pages = items.len().div_ceil(SKILLS_PER_PAGE).max(1);
    let page = page.min(pages - 1);
    let start = page * SKILLS_PER_PAGE;
    let end = (start + SKILLS_PER_PAGE).min(items.len());
    let chunk: Vec<(usize, &CatalogSkill)> = items
        .iter()
        .enumerate()
        .skip(start)
        .take(end.saturating_sub(start))
        .collect();

    let hdr = if let Some(d) = domain {
        format!("دامنه `{}`", md_cell(d))
    } else {
        let q_lbl = if q.trim().is_empty() { "all" } else { q.trim() };
        format!("جستجو `{}`", md_cell(q_lbl))
    };

    let mut md_lines = vec![
        format!("### {} کاتالوگ جامعه", ctx.premium.md("skills")),
        format!(
            "> {hdr} · **{}** نتیجه · صفحه **{}/{pages}**",
            items.len(),
            page + 1
        ),
        String::new(),
        "| اسکیل | وضعیت |".to_string(),
        "|---|---|".to_string(),
    ];

    if chunk.is_empty() {
        md_lines.push("| — | نتیجه‌ای یافت نشد |".to_string());
    } else {
        for &(_, s) in &chunk {
            let st_lbl = if s.installed {
                "✓ نصب‌شده"
            } else {
                "آماده نصب"
            };
            md_lines.push(format!("| {} | {st_lbl} |", md_cell(&s.name)));
        }
    }

    let mut rows: Vec<Vec<InlineKeyboardButton>> = Vec::new();
    for pair in chunk.chunks(2) {
        let row = pair
            .iter()
            .map(|&(idx, s)| {
                let mark = if s.installed { "✓" } else { "○" };
                ctx.btn(
                    "",
                    &format!("{mark} {}", truncate_chars(&s.name, 20)),
                    Some(&format!("sk:catv:{idx}")),
                    None,
                    None,
                )
            })
            .collect();
        rows.push(row);
    }

    let pfx = match domain.and_then(|d| doms.iter().position(|x| x.id == d)) {
        Some(di) => format!("sk:cat:d:{di}"),
        None => "sk:cat:r".to_string(),
    };
    if pages > 1 {
        let mut nav = Vec::new();
        if page > 0 {
            nav.push(ctx.btn(
                "",
                "‹ قبلی",
                Some(&format!("{pfx}:{}", page - 1)),
                None,
                None,
            ));
        }
        if page + 1 < pages {
            nav.push(ctx.btn(
                "",
                "بعدی ›",
                Some(&format!("{pfx}:{}", page + 1)),
                None,
                None,
            ));
        }
        rows.push(nav);
    }

    rows.push(vec![
        ctx.btn("", "« دامنه‌ها", Some("sk:cat:dom"), None, None),
        ctx.btn("", "« اسکیل‌ها", Some("skills:0"), None, None),
    ]);

    send_rich_card(ctx, cq, chat_id, &md_lines.join("\n"), rows).await;
}

fn ensure_inst_cache(ctx: &BotCtx, uid: i64) -> Vec<InstalledSkill> {
    let cur = skill_cache().get(&uid).map(|r| r.inst.clone()).unwrap_or_default();
    if !cur.is_empty() {
        return cur;
    }
    let fresh = list_installed_skills(&ctx.skills_dir()).unwrap_or_default();
    skill_cache().entry(uid).or_default().inst = fresh.clone();
    fresh
}

/// Dispatch `skills:*` and `sk:*` callbacks. Returns `true` if `data` was handled.
pub async fn handle_sk_cb(
    ctx: &Arc<BotCtx>,
    cq: &CallbackQuery,
    uid: i64,
    chat_id: i64,
    data: &str,
) -> bool {
    let is_skills = data.starts_with("skills:");
    let is_sk = data.starts_with("sk:");
    if !is_skills && !is_sk {
        return false;
    }
    if !ctx.has_perm(uid, "skills_manage") {
        let lang = ctx.lang(uid);
        let msg = format!("{} {}", t(lang, Tx::ModuleRequiredHdr), perm_label(lang, "skills_manage"));
        ctx.ack(&cq.id, Some(&msg), true).await;
        return true;
    }
    if let Some(pg_str) = data.strip_prefix("skills:") {
        let page = pg_str.parse::<usize>().unwrap_or(0);
        ctx.ack(&cq.id, None, false).await;
        show_skills(ctx, Some(cq), chat_id, page, uid).await;
        return true;
    }

    let parts: Vec<&str> = data.split(':').collect();
    let act = parts.get(1).copied().unwrap_or("");
    let can_m = ctx.has_perm(uid, "skills_manage");

    match act {
        "inst" => {
            let Some(idx) = parts.get(2).and_then(|s| s.parse::<usize>().ok()) else {
                ctx.ack(&cq.id, None, false).await;
                show_skills(ctx, Some(cq), chat_id, 0, uid).await;
                return true;
            };
            ctx.ack(&cq.id, None, false).await;
            let inst = ensure_inst_cache(ctx, uid);
            let Some(summary) = inst.get(idx).cloned() else {
                show_skills(ctx, Some(cq), chat_id, 0, uid).await;
                return true;
            };

            let detail_opt = get_installed_skill(&summary.name, &ctx.skills_dir())
                .ok()
                .flatten();
            let (name, category, description, preview) = match detail_opt {
                Some(d) => (d.name, d.category, d.description, d.preview),
                None => (
                    summary.name.clone(),
                    summary.category.clone(),
                    summary.description.clone(),
                    String::new(),
                ),
            };

            let mut rows = Vec::new();
            if can_m {
                rows.push(vec![ctx.btn(
                    "",
                    "حذف اسکیل",
                    Some(&format!("sk:del:{idx}")),
                    Some("danger"),
                    None,
                )]);
            }
            rows.push(vec![ctx.btn("", "« اسکیل‌ها", Some("skills:0"), None, None)]);

            let mut md_lines = vec![
                format!("### {} {}", ctx.premium.md("skills"), md_cell(&name)),
                String::new(),
                "| فیلد | مقدار |".to_string(),
                "|---|---|".to_string(),
                format!(
                    "| دسته | `{}` |",
                    md_cell(if category.is_empty() { "—" } else { &category })
                ),
                format!(
                    "| توضیح | {} |",
                    md_cell(&truncate_chars(
                        if description.is_empty() {
                            "—"
                        } else {
                            &description
                        },
                        180
                    ))
                ),
            ];
            let prev_trimmed = preview.trim();
            if !prev_trimmed.is_empty() {
                md_lines.push(String::new());
                md_lines.push("<details><summary>پیش‌نمایش SKILL.md</summary>".to_string());
                md_lines.push(truncate_chars(prev_trimmed, 1200).replace('`', "'"));
                md_lines.push("</details>".to_string());
            }
            send_rich_card(ctx, Some(cq), chat_id, &md_lines.join("\n"), rows).await;
        }
        "del" => {
            if !can_m {
                ctx.ack(&cq.id, Some("Permission denied: skills_manage"), true)
                    .await;
                return true;
            }
            let Some(idx) = parts.get(2).and_then(|s| s.parse::<usize>().ok()) else {
                ctx.ack(&cq.id, Some("اسکیل یافت نشد"), false).await;
                show_skills(ctx, Some(cq), chat_id, 0, uid).await;
                return true;
            };
            let inst = ensure_inst_cache(ctx, uid);
            let Some(target) = inst.get(idx).cloned() else {
                ctx.ack(&cq.id, Some("اسکیل یافت نشد"), false).await;
                show_skills(ctx, Some(cq), chat_id, 0, uid).await;
                return true;
            };
            let ack_msg = match delete_installed_skill(&target.name, &ctx.skills_dir()) {
                Ok(m) => m,
                Err(err) => redact_secrets_in_text(&err.to_string()),
            };
            ctx.ack(&cq.id, Some(&truncate_chars(&ack_msg, 160)), false)
                .await;
            show_skills(ctx, Some(cq), chat_id, 0, uid).await;
        }
        "sp" => {
            let sub = parts.get(2).copied().unwrap_or("ns");
            match sub {
                "ns" => {
                    ctx.ack(&cq.id, None, false).await;
                    let ns_pairs = list_skillport_namespaces(&ctx.cfg.skillport_skills_dir)
                        .unwrap_or_default();
                    {
                        let mut entry = skill_cache().entry(uid).or_default();
                        entry.sp_ns = ns_pairs.iter().map(|n| n.name.clone()).collect();
                        sync_ctx_view(ctx, uid, "sp", &entry);
                    }
                    let mut rows: Vec<Vec<InlineKeyboardButton>> = Vec::new();
                    let ns_btns: Vec<InlineKeyboardButton> = ns_pairs
                        .iter()
                        .take(24)
                        .enumerate()
                        .map(|(i, n)| {
                            ctx.btn(
                                "",
                                &format!("{} ({})", n.name, n.count),
                                Some(&format!("sk:sp:n:{i}:0")),
                                None,
                                None,
                            )
                        })
                        .collect();
                    for pair in ns_btns.chunks(2) {
                        rows.push(pair.to_vec());
                    }
                    rows.push(vec![
                        ctx.btn("", "جستجو", Some("sk:sp:q"), None, None),
                        ctx.btn("", "همه", Some("sk:sp:all:0"), None, None),
                    ]);
                    rows.push(vec![ctx.btn("", "« اسکیل‌ها", Some("skills:0"), None, None)]);

                    let mut md_lines = vec![
                        format!("### {} دسته‌های SkillPort", ctx.premium.md("skills")),
                        String::new(),
                        "| دسته | تعداد |".to_string(),
                        "|---|---|".to_string(),
                    ];
                    if ns_pairs.is_empty() {
                        md_lines.push("| — | خالی |".to_string());
                    } else {
                        for n in ns_pairs.iter().take(16) {
                            md_lines.push(format!("| {} | `{}` |", md_cell(&n.name), n.count));
                        }
                    }
                    send_rich_card(ctx, Some(cq), chat_id, &md_lines.join("\n"), rows).await;
                }
                "q" => {
                    ctx.jobs
                        .set_awaiting(uid, AwaitingInput::new("skill_sp_q", json!({})));
                    ctx.ack(&cq.id, None, false).await;
                    let md = format!(
                        "### {} جستجو در SkillPort\n\nکلمه کلیدی موردنظر را ارسال کنید.",
                        ctx.premium.md("skills")
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
                "all" => {
                    let page = parts
                        .get(3)
                        .and_then(|s| s.parse::<usize>().ok())
                        .unwrap_or(0);
                    skill_cache().entry(uid).or_default().sp_q.clear();
                    ctx.ack(&cq.id, None, false).await;
                    show_skillport_list(ctx, Some(cq), chat_id, uid, None, "", page).await;
                }
                "n" => {
                    let ns_idx = parts
                        .get(3)
                        .and_then(|s| s.parse::<usize>().ok())
                        .unwrap_or(0);
                    let page = parts
                        .get(4)
                        .and_then(|s| s.parse::<usize>().ok())
                        .unwrap_or(0);
                    let ns_list = {
                        let mut entry = skill_cache().entry(uid).or_default();
                        if entry.sp_ns.is_empty() {
                            entry.sp_ns = list_skillport_namespaces(&ctx.cfg.skillport_skills_dir)
                                .unwrap_or_default()
                                .into_iter()
                                .map(|n| n.name)
                                .collect();
                        }
                        entry.sp_ns.clone()
                    };
                    let ns = ns_list.get(ns_idx).map(String::as_str);
                    ctx.ack(&cq.id, None, false).await;
                    show_skillport_list(ctx, Some(cq), chat_id, uid, ns, "", page).await;
                }
                _ => {
                    ctx.ack(&cq.id, None, false).await;
                }
            }
        }
        "spv" => {
            ctx.ack(&cq.id, None, false).await;
            let Some(idx) = parts.get(2).and_then(|s| s.parse::<usize>().ok()) else {
                show_skills(ctx, Some(cq), chat_id, 0, uid).await;
                return true;
            };
            let item_opt = skill_cache()
                .get(&uid)
                .and_then(|c| c.sp.get(idx).cloned());
            let Some(it) = item_opt else {
                show_skills(ctx, Some(cq), chat_id, 0, uid).await;
                return true;
            };
            let mut rows = Vec::new();
            if can_m {
                let lbl = if it.installed { "بروزرسانی" } else { "نصب" };
                rows.push(vec![ctx.btn(
                    "",
                    lbl,
                    Some(&format!("sk:spi:{idx}")),
                    Some("primary"),
                    None,
                )]);
            }
            rows.push(vec![
                ctx.btn("", "« بازگشت", Some("sk:sp:all:0"), None, None),
                ctx.btn("", "« اسکیل‌ها", Some("skills:0"), None, None),
            ]);
            let md = [
                format!("### {} {}", ctx.premium.md("skills"), md_cell(&it.name)),
                String::new(),
                "| فیلد | مقدار |".to_string(),
                "|---|---|".to_string(),
                format!("| ID | `{}` |", md_cell(&it.id)),
                format!(
                    "| توضیح | {} |",
                    md_cell(&truncate_chars(
                        if it.description.is_empty() {
                            "—"
                        } else {
                            &it.description
                        },
                        300
                    ))
                ),
            ]
            .join("\n");
            send_rich_card(ctx, Some(cq), chat_id, &md, rows).await;
        }
        "spi" => {
            if !can_m {
                ctx.ack(&cq.id, Some("Permission denied: skills_manage"), true)
                    .await;
                return true;
            }
            let Some(idx) = parts.get(2).and_then(|s| s.parse::<usize>().ok()) else {
                ctx.ack(&cq.id, Some("لیست منقضی شده است"), false).await;
                return true;
            };
            let item_opt = skill_cache()
                .get(&uid)
                .and_then(|c| c.sp.get(idx).cloned());
            let Some(it) = item_opt else {
                ctx.ack(&cq.id, Some("لیست منقضی شده است"), false).await;
                return true;
            };
            match install_skillport_skill(&it.id, &ctx.cfg.skillport_skills_dir, &ctx.skills_dir())
            {
                Ok(msg_txt) => {
                    if let Some(mut entry) = skill_cache().get_mut(&uid) {
                        if let Some(slot) = entry.sp.get_mut(idx) {
                            slot.installed = true;
                        }
                    }
                    ctx.ack(&cq.id, Some(&truncate_chars(&msg_txt, 160)), false)
                        .await;
                }
                Err(err) => {
                    let clean = redact_secrets_in_text(&err.to_string());
                    ctx.ack(&cq.id, Some(&truncate_chars(&clean, 160)), false)
                        .await;
                }
            }
            show_skills(ctx, Some(cq), chat_id, 0, uid).await;
        }
        "cat" => {
            let sub = parts.get(2).copied().unwrap_or("dom");
            match sub {
                "dom" => {
                    ctx.ack(&cq.id, None, false).await;
                    let doms =
                        list_catalog_domains(&ctx.cfg.skills_catalog_json).unwrap_or_default();
                    {
                        let mut entry = skill_cache().entry(uid).or_default();
                        entry.cat_dom = doms.clone();
                        sync_ctx_view(ctx, uid, "cat", &entry);
                    }
                    let mut rows: Vec<Vec<InlineKeyboardButton>> = Vec::new();
                    let d_btns: Vec<InlineKeyboardButton> = doms
                        .iter()
                        .take(20)
                        .enumerate()
                        .map(|(i, d)| {
                            let lbl = if d.label.is_empty() { &d.id } else { &d.label };
                            ctx.btn(
                                "",
                                &truncate_chars(lbl, 20),
                                Some(&format!("sk:cat:d:{i}:0")),
                                None,
                                None,
                            )
                        })
                        .collect();
                    for pair in d_btns.chunks(2) {
                        rows.push(pair.to_vec());
                    }
                    rows.push(vec![
                        ctx.btn("", "جستجو", Some("sk:cat:q"), Some("primary"), None),
                        ctx.btn("", "« اسکیل‌ها", Some("skills:0"), None, None),
                    ]);

                    let mut md_lines = vec![
                        format!("### {} کاتالوگ جامعه (9.1k)", ctx.premium.md("skills")),
                        String::new(),
                        "| دامنه | شناسه |".to_string(),
                        "|---|---|".to_string(),
                    ];
                    if doms.is_empty() {
                        md_lines.push("| — | دامنه‌ای یافت نشد |".to_string());
                    } else {
                        for d in doms.iter().take(16) {
                            let lbl = if d.label.is_empty() { &d.id } else { &d.label };
                            md_lines
                                .push(format!("| {} | `{}` |", md_cell(lbl), md_cell(&d.id)));
                        }
                    }
                    send_rich_card(ctx, Some(cq), chat_id, &md_lines.join("\n"), rows).await;
                }
                "q" => {
                    ctx.jobs
                        .set_awaiting(uid, AwaitingInput::new("skill_cat_q", json!({})));
                    ctx.ack(&cq.id, None, false).await;
                    let md = format!(
                        "### {} جستجو در کاتالوگ\n\nکلمه کلیدی جستجو را ارسال کنید.",
                        ctx.premium.md("skills")
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
                "d" => {
                    let di = parts
                        .get(3)
                        .and_then(|s| s.parse::<usize>().ok())
                        .unwrap_or(0);
                    let page = parts
                        .get(4)
                        .and_then(|s| s.parse::<usize>().ok())
                        .unwrap_or(0);
                    let doms = {
                        let mut entry = skill_cache().entry(uid).or_default();
                        if entry.cat_dom.is_empty() {
                            entry.cat_dom = list_catalog_domains(&ctx.cfg.skills_catalog_json)
                                .unwrap_or_default();
                        }
                        entry.cat_dom.clone()
                    };
                    let dom = doms
                        .get(di)
                        .map(|d| d.id.as_str())
                        .filter(|s| !s.is_empty());
                    ctx.ack(&cq.id, None, false).await;
                    show_catalog_list(ctx, Some(cq), chat_id, uid, dom, "", page).await;
                }
                "r" => {
                    let page = parts
                        .get(3)
                        .and_then(|s| s.parse::<usize>().ok())
                        .unwrap_or(0);
                    let q = skill_cache()
                        .get(&uid)
                        .map(|c| c.cat_q.clone())
                        .unwrap_or_default();
                    ctx.ack(&cq.id, None, false).await;
                    show_catalog_list(ctx, Some(cq), chat_id, uid, None, &q, page).await;
                }
                _ => {
                    ctx.ack(&cq.id, None, false).await;
                }
            }
        }
        "catv" => {
            ctx.ack(&cq.id, None, false).await;
            let Some(idx) = parts.get(2).and_then(|s| s.parse::<usize>().ok()) else {
                show_skills(ctx, Some(cq), chat_id, 0, uid).await;
                return true;
            };
            let item_opt = skill_cache()
                .get(&uid)
                .and_then(|c| c.cat.get(idx).cloned());
            let Some(it) = item_opt else {
                show_skills(ctx, Some(cq), chat_id, 0, uid).await;
                return true;
            };
            let mut rows = Vec::new();
            if can_m {
                rows.push(vec![ctx.btn(
                    "",
                    "نصب از کاتالوگ",
                    Some(&format!("sk:cati:{idx}")),
                    Some("primary"),
                    None,
                )]);
            }
            rows.push(vec![
                ctx.btn("", "« بازگشت", Some("sk:cat:dom"), None, None),
                ctx.btn("", "« اسکیل‌ها", Some("skills:0"), None, None),
            ]);
            let src = if !it.repo.is_empty() {
                &it.repo
            } else if !it.domain.is_empty() {
                &it.domain
            } else {
                "—"
            };
            let md = [
                format!("### {} {}", ctx.premium.md("skills"), md_cell(&it.name)),
                String::new(),
                "| فیلد | مقدار |".to_string(),
                "|---|---|".to_string(),
                format!("| ID | `{}` |", md_cell(&it.id)),
                format!("| منبع | {} |", md_cell(src)),
                format!(
                    "| توضیح | {} |",
                    md_cell(&truncate_chars(
                        if it.description.is_empty() {
                            "—"
                        } else {
                            &it.description
                        },
                        300
                    ))
                ),
            ]
            .join("\n");
            send_rich_card(ctx, Some(cq), chat_id, &md, rows).await;
        }
        "cati" => {
            if !can_m {
                ctx.ack(&cq.id, Some("Permission denied: skills_manage"), true)
                    .await;
                return true;
            }
            let Some(idx) = parts.get(2).and_then(|s| s.parse::<usize>().ok()) else {
                ctx.ack(&cq.id, Some("لیست منقضی شده است"), false).await;
                return true;
            };
            let item_opt = skill_cache()
                .get(&uid)
                .and_then(|c| c.cat.get(idx).cloned());
            let Some(it) = item_opt else {
                ctx.ack(&cq.id, Some("لیست منقضی شده است"), false).await;
                return true;
            };
            ctx.ack(&cq.id, Some("در حال دریافت و نصب..."), false).await;
            let slug_opt = (!it.slug.trim().is_empty()).then_some(it.slug.as_str());
            let bin_str = ctx.cfg.skills_catalog_mcp_bin.to_string_lossy();
            match install_catalog_skill(
                &it.id,
                slug_opt,
                &ctx.skills_dir(),
                &bin_str,
                CATALOG_INSTALL_TIMEOUT_SECS,
            )
            .await
            {
                Ok(_) => {
                    if let Some(mut entry) = skill_cache().get_mut(&uid) {
                        if let Some(slot) = entry.cat.get_mut(idx) {
                            slot.installed = true;
                        }
                    }
                    show_skills(ctx, Some(cq), chat_id, 0, uid).await;
                }
                Err(err) => {
                    let clean = redact_secrets_in_text(&err.to_string());
                    let md = format!(
                        "### {} خطا در نصب اسکیل\n\n`{}`",
                        ctx.premium.md("err"),
                        md_cell(&truncate_chars(&clean, 300))
                    );
                    let mk = BotCtx::kb(vec![vec![ctx.btn(
                        "",
                        "« اسکیل‌ها",
                        Some("skills:0"),
                        None,
                        None,
                    )]]);
                    let _ = ctx.render.send_rich_card_message(chat_id, &md, Some(mk)).await;
                }
            }
        }
        "ai_new" => {
            if !can_m {
                ctx.ack(&cq.id, Some("Permission denied: skills_manage"), true)
                    .await;
                return true;
            }
            ctx.jobs
                .set_awaiting(uid, AwaitingInput::new("skill_ai", json!({})));
            ctx.ack(&cq.id, None, false).await;
            let md = format!(
                "### {} ساخت اسکیل با AI\n\n\
                نام یا توضیح اسکیل موردنظر (و کاربرد آن) را ارسال کنید.",
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
        }
        _ => {
            ctx.ack(&cq.id, None, false).await;
        }
    }

    true
}

/// Handle multi-step `AwaitingInput` text for `/skills` (`skill_sp_q`, `skill_cat_q`, `skill_ai`).
/// Returns `true` if `inp.kind` was handled by this module.
pub async fn handle_skills_awaiting_text(
    ctx: &Arc<BotCtx>,
    _msg: &Message,
    uid: i64,
    chat_id: i64,
    user_label: &str,
    inp: &AwaitingInput,
    text: &str,
) -> bool {
    match inp.kind.as_str() {
        "skill_sp_q" | "sk_sp_q" => {
            if !ctx.has_perm(uid, "skills_manage") {
                let _ = ctx
                    .render
                    .send_html_simple(chat_id, &missing_perm_html(ctx, uid, "skills_manage"), None)
                    .await;
                return true;
            }
            let q = text.trim();
            show_skillport_list(ctx, None, chat_id, uid, None, q, 0).await;
            true
        }
        "skill_cat_q" | "sk_cat_q" => {
            if !ctx.has_perm(uid, "skills_manage") {
                let _ = ctx
                    .render
                    .send_html_simple(chat_id, &missing_perm_html(ctx, uid, "skills_manage"), None)
                    .await;
                return true;
            }
            let q = text.trim();
            show_catalog_list(ctx, None, chat_id, uid, None, q, 0).await;
            true
        }
        "skill_ai" => {
            if !ctx.has_perm(uid, "skills_manage") {
                let md = format!(
                    "### {} دسترسی غیرمجاز\n\n> `skills_manage` لازم است.",
                    ctx.premium.md("err")
                );
                let _ = ctx.render.send_rich_card_message(chat_id, &md, None).await;
                return true;
            }
            let spec_txt = text.trim();
            if spec_txt.is_empty() {
                ctx.jobs
                    .set_awaiting(uid, AwaitingInput::new("skill_ai", inp.data.clone()));
                let md = format!(
                    "### {} متن خالی است\n\nنام یا توضیح اسکیل را ارسال کنید.",
                    ctx.premium.md("warn")
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
            let skills_dir_s = ctx.skills_dir().to_string_lossy().into_owned();
            let skill_prompt = format!(
                "Create or install an Antigravity skill in `{skills_dir_s}` based on this request:\n\
                {spec_txt}\n\n\
                Requirements:\n\
                1. Pick a clean lowercase slug `[a-z0-9][a-z0-9._-]*` and create `<slug>/SKILL.md` with valid YAML frontmatter (`name`, `description`).\n\
                2. Verify the directory and `SKILL.md` frontmatter are readable.\n\
                3. Reply concisely in Persian with the skill slug, path, and summary."
            );
            let mut req = JobRequest::new(uid, chat_id, user_label, skill_prompt, Vec::new());
            req.overrides = JobOverride {
                isolated: true,
                ..Default::default()
            };
            let _ = ctx.jobs.enqueue(req).await;
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
            _ => json!({"message_id": 77, "chat": {"id": 1, "type": "private"}, "text": "ok"}),
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
        let skills_dir = dir.path().join("skills");
        let sp_dir = dir.path().join("skillport");
        let cat_json = dir.path().join("catalog.json");

        std::fs::create_dir_all(&state_dir).unwrap();
        std::fs::create_dir_all(skills_dir.join("installed-one")).unwrap();
        std::fs::write(
            skills_dir.join("installed-one").join("SKILL.md"),
            "---\nname: installed-one\ndescription: First skill\n---\n# Installed\n",
        )
        .unwrap();

        std::fs::create_dir_all(sp_dir.join("coding").join("sp-alpha")).unwrap();
        std::fs::write(
            sp_dir.join("coding").join("sp-alpha").join("SKILL.md"),
            "---\nname: sp-alpha\ndescription: SkillPort Alpha\n---\n# SP Alpha\n",
        )
        .unwrap();

        std::fs::write(
            &cat_json,
            serde_json::to_string(&json!({
                "domains": [{"id": "testing", "label": "Testing"}],
                "skills": [{
                    "id": "repo/testing/cat-beta",
                    "slug": "cat-beta",
                    "name": "cat-beta",
                    "description": "Catalog Beta",
                    "domain": "testing",
                    "repo": "example/skills"
                }]
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
            agy_skills_dir: skills_dir,
            skillport_skills_dir: sp_dir,
            skills_catalog_json: cat_json,
            skills_catalog_mcp_bin: PathBuf::from("/nonexistent/catalog-mcp"),
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
                username: None,
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
            id: "cq-sk".into(),
            from_user: User {
                id: uid,
                is_bot: false,
                first_name: "U".into(),
                last_name: None,
                username: None,
                language_code: None,
                is_premium: Some(false),
            },
            message: Some(mk_msg(uid, "skills")),
            inline_message_id: None,
            data: Some(data.into()),
        }
    }

    #[tokio::test]
    async fn skills_manage_acl_enforced_and_skillport_install_delete_works() {
        let dir = TempDir::new().unwrap();
        let (ctx, _st) = setup_ctx(&dir).await;

        // Locked STD_USER (no skills_manage) is denied /skills, browsing, search, & mutating actions
        cmd_skills(&ctx, &mk_msg(STD_USER, "/skills")).await;
        assert!(handle_sk_cb(&ctx, &mk_cq(STD_USER, "skills:0"), STD_USER, STD_USER, "skills:0").await);
        assert!(handle_sk_cb(&ctx, &mk_cq(STD_USER, "sk:sp:ns"), STD_USER, STD_USER, "sk:sp:ns").await);
        assert!(handle_sk_cb(&ctx, &mk_cq(STD_USER, "sk:sp:n:0:0"), STD_USER, STD_USER, "sk:sp:n:0:0").await);
        assert!(handle_sk_cb(&ctx, &mk_cq(STD_USER, "sk:sp:q"), STD_USER, STD_USER, "sk:sp:q").await);
        assert!(ctx.jobs.take_awaiting(STD_USER).is_none());

        // STD_USER denied sk:del, sk:spi, sk:cati, sk:ai_new
        assert!(handle_sk_cb(&ctx, &mk_cq(STD_USER, "sk:del:0"), STD_USER, STD_USER, "sk:del:0").await);
        assert!(ctx.skills_dir().join("installed-one").exists());

        assert!(handle_sk_cb(&ctx, &mk_cq(STD_USER, "sk:spi:0"), STD_USER, STD_USER, "sk:spi:0").await);
        assert!(!ctx.skills_dir().join("sp-alpha").exists());

        assert!(handle_sk_cb(&ctx, &mk_cq(STD_USER, "sk:ai_new"), STD_USER, STD_USER, "sk:ai_new").await);
        assert!(ctx.jobs.take_awaiting(STD_USER).is_none());

        // STD_USER denied awaiting text for skill_ai & skill_sp_q
        assert!(
            handle_skills_awaiting_text(
                &ctx,
                &mk_msg(STD_USER, "create my skill"),
                STD_USER,
                STD_USER,
                "Std",
                &AwaitingInput::new("skill_ai", json!({})),
                "create my skill",
            )
            .await
        );
        assert!(
            handle_skills_awaiting_text(
                &ctx,
                &mk_msg(STD_USER, "alpha"),
                STD_USER,
                STD_USER,
                "Std",
                &AwaitingInput::new("skill_sp_q", json!({})),
                "alpha",
            )
            .await
        );
        assert!(ctx.sk_view.get(&STD_USER).is_none());

        // DEV_USER (has skills_manage) can browse, search SkillPort & Catalog via AwaitingInput, install, and delete
        assert!(handle_sk_cb(&ctx, &mk_cq(DEV_USER, "sk:sp:q"), DEV_USER, DEV_USER, "sk:sp:q").await);
        let inp_sp = ctx.jobs.take_awaiting(DEV_USER).unwrap();
        assert_eq!(inp_sp.kind, "skill_sp_q");
        assert!(
            handle_skills_awaiting_text(&ctx, &mk_msg(DEV_USER, "alpha"), DEV_USER, DEV_USER, "Dev", &inp_sp, "alpha")
                .await
        );
        assert_eq!(
            ctx.sk_view.get(&DEV_USER).map(|v| v.q.clone()),
            Some("alpha".to_string())
        );

        assert!(handle_sk_cb(&ctx, &mk_cq(DEV_USER, "sk:cat:q"), DEV_USER, DEV_USER, "sk:cat:q").await);
        let inp_cat = ctx.jobs.take_awaiting(DEV_USER).unwrap();
        assert_eq!(inp_cat.kind, "skill_cat_q");
        assert!(
            handle_skills_awaiting_text(&ctx, &mk_msg(DEV_USER, "beta"), DEV_USER, DEV_USER, "Dev", &inp_cat, "beta")
                .await
        );

        assert!(handle_sk_cb(&ctx, &mk_cq(DEV_USER, "sk:sp:all:0"), DEV_USER, DEV_USER, "sk:sp:all:0").await);
        assert!(handle_sk_cb(&ctx, &mk_cq(DEV_USER, "sk:spi:0"), DEV_USER, DEV_USER, "sk:spi:0").await);
        assert!(ctx.skills_dir().join("sp-alpha").join("SKILL.md").is_file());

        show_skills(&ctx, None, DEV_USER, 0, DEV_USER).await;
        assert!(handle_sk_cb(&ctx, &mk_cq(DEV_USER, "sk:del:0"), DEV_USER, DEV_USER, "sk:del:0").await);
        assert!(!ctx.skills_dir().join("installed-one").exists());

        // DEV_USER can trigger sk:ai_new awaiting prompt
        assert!(handle_sk_cb(&ctx, &mk_cq(DEV_USER, "sk:ai_new"), DEV_USER, DEV_USER, "sk:ai_new").await);
        let inp_ai = ctx.jobs.take_awaiting(DEV_USER).unwrap();
        assert_eq!(inp_ai.kind, "skill_ai");
    }

    #[tokio::test]
    async fn skills_pagination_and_catalog_mcp_install_work() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let (ctx, st) = setup_ctx(&dir).await;

        // Create 10 installed skills to test pagination (8 per page)
        for i in 0..10 {
            let sdir = ctx.skills_dir().join(format!("skill-{i:02}"));
            std::fs::create_dir_all(&sdir).unwrap();
            std::fs::write(
                sdir.join("SKILL.md"),
                format!("---\nname: skill-{i:02}\ndescription: Skill {i}\n---\nBody {i}\n"),
            )
            .unwrap();
        }
        assert!(handle_sk_cb(&ctx, &mk_cq(DEV_USER, "skills:1"), DEV_USER, DEV_USER, "skills:1").await);
        assert!(handle_sk_cb(&ctx, &mk_cq(DEV_USER, "sk:inst:8"), DEV_USER, DEV_USER, "sk:inst:8").await);

        // Write executable mock catalog MCP script and test sk:cat:dom -> sk:cat:d:0:0 -> sk:catv:0 -> sk:cati:0
        let mock_bin = dir.path().join("mock-catalog-mcp");
        std::fs::write(
            &mock_bin,
            "#!/usr/bin/env python3\nimport json, sys\nfor line in sys.stdin:\n  req = json.loads(line)\n  m = req.get('method')\n  if m == 'initialize':\n    print(json.dumps({'jsonrpc':'2.0','id':req['id'],'result':{'protocolVersion':'2024-11-05','capabilities':{}}}), flush=True)\n  elif m == 'tools/call':\n    print(json.dumps({'jsonrpc':'2.0','id':req['id'],'result':{'content':[{'type':'text','text':'---\\nname: cat-beta\\ndescription: Catalog Beta\\n---\\n# Cat Beta\\n'}]}}), flush=True)\n",
        )
        .unwrap();
        let mut perms = std::fs::metadata(&mock_bin).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&mock_bin, perms).unwrap();

        // Point a new BotCtx at the mock catalog MCP binary
        let mut cfg2 = (*ctx.cfg).clone();
        cfg2.skills_catalog_mcp_bin = mock_bin;
        let cfg2 = Arc::new(cfg2);
        let ctx2 = BotCtx::new(
            cfg2,
            Arc::clone(&ctx.store),
            Arc::clone(&ctx.acl),
            Arc::clone(&ctx.outbox),
            Arc::clone(&ctx.health),
            Arc::clone(&ctx.premium),
            Arc::clone(&ctx.pool),
            Arc::clone(&ctx.client),
            Arc::clone(&ctx.widgets),
            Arc::clone(&ctx.render),
            Arc::clone(&ctx.cron),
            Arc::clone(&ctx.jobs),
            Arc::clone(&ctx.auth),
        );

        assert!(handle_sk_cb(&ctx2, &mk_cq(DEV_USER, "sk:cat:dom"), DEV_USER, DEV_USER, "sk:cat:dom").await);
        assert!(handle_sk_cb(&ctx2, &mk_cq(DEV_USER, "sk:cat:d:0:0"), DEV_USER, DEV_USER, "sk:cat:d:0:0").await);
        assert!(handle_sk_cb(&ctx2, &mk_cq(DEV_USER, "sk:catv:0"), DEV_USER, DEV_USER, "sk:catv:0").await);
        assert!(handle_sk_cb(&ctx2, &mk_cq(DEV_USER, "sk:cati:0"), DEV_USER, DEV_USER, "sk:cati:0").await);
        assert!(ctx2.skills_dir().join("cat-beta").join("SKILL.md").is_file());

        // Verify all emitted callback_data <= 64 bytes
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
}
