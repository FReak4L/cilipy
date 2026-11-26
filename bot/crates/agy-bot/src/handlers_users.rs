//! Owner-only `/users` ACL administration panel (`uadm:*` callbacks).

use std::collections::HashSet;
use std::str::FromStr;
use std::sync::Arc;

use agy_core::acl::{
    AclUser, BulkTarget, Perms, RolePreset, RoleTier, UserFilter, UserStatus, PERM_KEYS,
};
use agy_core::tg::{BotCommandScope, CallbackQuery, InlineKeyboardButton, Message};
use agy_render::md_cell;
use tracing::warn;

use crate::ctx::BotCtx;
use crate::i18n::{owner_lang, owner_only_html, perm_label, t, tier_badge_name, Lang, Tx};

const USERS_PER_PAGE: usize = 8;

fn status_icon(st: UserStatus) -> &'static str {
    match st {
        UserStatus::Approved => "✓",
        UserStatus::Pending => "○",
        UserStatus::Blocked => "×",
    }
}

fn scope_title(lang: Lang, scope: BulkTarget) -> &'static str {
    match (lang, scope) {
        (Lang::Fa, BulkTarget::Selected) => "کاربران انتخاب‌شده",
        (Lang::Fa, BulkTarget::Pending) => "در انتظار تایید",
        (Lang::Fa, BulkTarget::ApprovedNonOwner) => "تاییدشده‌ها (غیراز مالک)",
        (Lang::Fa, BulkTarget::AllNonOwner) => "همه کاربران (غیراز مالک)",
        (Lang::La, BulkTarget::Selected) => "Usores selecti",
        (Lang::La, BulkTarget::Pending) => "Exspectantes",
        (Lang::La, BulkTarget::ApprovedNonOwner) => "Probati (sine Domino)",
        (Lang::La, BulkTarget::AllNonOwner) => "Omnes (sine Domino)",
        (Lang::Zh, BulkTarget::Selected) => "已选用户",
        (Lang::Zh, BulkTarget::Pending) => "待审批用户",
        (Lang::Zh, BulkTarget::ApprovedNonOwner) => "已批准用户（不含所有者）",
        (Lang::Zh, BulkTarget::AllNonOwner) => "全部非所有者用户",
        (Lang::Ru, BulkTarget::Selected) => "Выбранные",
        (Lang::Ru, BulkTarget::Pending) => "Ожидающие",
        (Lang::Ru, BulkTarget::ApprovedNonOwner) => "Одобренные (кроме владельца)",
        (Lang::Ru, BulkTarget::AllNonOwner) => "Все (кроме владельца)",
        (_, BulkTarget::Selected) => "Selected",
        (_, BulkTarget::Pending) => "Pending",
        (_, BulkTarget::ApprovedNonOwner) => "Approved (non-owner)",
        (_, BulkTarget::AllNonOwner) => "All (non-owner)",
    }
}

fn perm_tags(p: &Perms) -> String {
    let mut tags = Vec::with_capacity(6);
    if p.dashboard_access {
        tags.push("D");
    }
    if p.models_switch {
        tags.push("M");
    }
    if p.uncensored {
        tags.push("U");
    }
    if p.grok {
        tags.push("G");
    }
    if p.mcp_manage {
        tags.push("MCP");
    }
    if p.skills_manage {
        tags.push("S");
    }
    if p.root_access {
        tags.push("R");
    } else if p.sandbox_exec {
        tags.push("SB");
    }
    if tags.is_empty() {
        "—".to_string()
    } else {
        tags.join("·")
    }
}

fn acl_user_label(u: &AclUser) -> String {
    let full = match (&u.first_name, &u.last_name) {
        (Some(f), Some(l)) => format!("{f} {l}").trim().to_string(),
        (Some(f), None) => f.trim().to_string(),
        (None, Some(l)) => l.trim().to_string(),
        (None, None) => String::new(),
    };
    match &u.username {
        Some(un) if !un.is_empty() && !full.is_empty() => format!("{full} (@{un})"),
        Some(un) if !un.is_empty() => format!("@{un}"),
        _ if !full.is_empty() => full,
        _ => u.uid.to_string(),
    }
}

fn truncate_chars(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        s.to_string()
    } else {
        s.chars().take(max_chars).collect()
    }
}

async fn sync_user_commands_for(ctx: &BotCtx, tuid: i64) {
    if ctx.is_approved(tuid) {
        ctx.sync_user_commands(tuid).await;
    } else {
        ctx.commands_set.remove(&tuid);
        let _ = ctx
            .client
            .set_my_commands(&[], Some(BotCommandScope::Chat { chat_id: tuid }))
            .await;
    }
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

/// Handle `/users` command (strictly owner-only — denied for Admin and User tiers).
pub async fn cmd_users(ctx: &Arc<BotCtx>, msg: &Message) {
    let Some(uid) = msg.from_user.as_ref().map(|u| u.id) else {
        return;
    };
    if !ctx.is_owner(uid) {
        let txt = owner_only_html(ctx, uid);
        let _ = ctx.render.send_html_simple(msg.chat.id, &txt, None).await;
        return;
    }
    show_users_panel(ctx, None, msg.chat.id, "all", 0).await;
}

fn users_lbl<'a>(lang: Lang, key: &'a str) -> &'a str {
    let arr: [&'a str; 5] = match key {
        "all" => ["همه", "All", "Omnes", "全部", "Все"],
        "pend" => ["انتظار", "Pending", "Exspect.", "待审", "Ожид."],
        "app" => ["تایید", "Approved", "Probati", "已批", "Одобр."],
        "blk" => ["مسدود", "Blocked", "Intercl.", "封禁", "Блок"],
        "sel" => ["منتخب", "Sel", "Sel", "已选", "Выбр"],
        "page" => ["صفحه", "Page", "Pag", "页", "Стр"],
        "col_u" => ["کاربر", "User", "Usor", "用户", "Пользователь"],
        "col_s" => ["سطح/وضعیت", "Tier/St", "Grad/St", "等级/状态", "Уров/Стат"],
        "col_p" => ["ماژول‌ها", "Modules", "Moduli", "模块", "Модули"],
        "empty" => ["کاربری یافت نشد", "No users found", "Nulli usores", "无用户", "Нет пользователей"],
        "prev" => ["‹ قبلی", "‹ Prev", "‹ Prior", "‹ 上页", "‹ Назад"],
        "next" => ["بعدی ›", "Next ›", "Sequens ›", "下页 ›", "Далее ›"],
        "bulk" => ["عملیات جمعی", "Bulk actions", "Acta gregalia", "批量操作", "Массовые"],
        "app_pend" => ["تایید انتظار", "Approve pend.", "Proba exsp.", "批准待审", "Одобрить"],
        "back_u" => ["« کاربران", "« Users", "« Usores", "« 用户列表", "« Пользователи"],
        "not_found" => ["کاربر یافت نشد", "User not found", "Usor non inventus", "未找到用户", "Пользователь не найден"],
        "attr" => ["ویژگی", "Field", "Campus", "字段", "Поле"],
        "val" => ["مقدار", "Value", "Valor", "值", "Значение"],
        "uid" => ["شناسه", "ID", "ID", "ID", "ID"],
        "uname" => ["یوزرنیم", "Username", "Nomen", "用户名", "Юзернейм"],
        "tier" => ["سطح", "Tier", "Gradus", "等级", "Уровень"],
        "status" => ["وضعیت", "Status", "Status", "状态", "Статус"],
        "owner_imm" => [
            "دسترسی‌های مالک همیشه کامل و تغییرناپذیر است.",
            "Owner privileges are always full and immutable.",
            "Potestas Domini semper plena et immutabilis est.",
            "所有者权限始终完整且不可更改。",
            "Права владельца всегда полные и неизменяемые.",
        ],
        "st_app" => ["تایید", "Approve", "Proba", "批准", "Одобрить"],
        "st_pend" => ["انتظار", "Pending", "Exspecta", "待审", "Ожидание"],
        "st_blk" => ["مسدود", "Block", "Interclude", "封禁", "Блок"],
        "remove" => ["حذف", "Remove", "Remove", "删除", "Удалить"],
        "scope" => ["محدوده", "Scope", "Ambitus", "范围", "Область"],
        "count" => ["مشمول", "Matched", "Numerus", "匹配数", "Затронуто"],
        "manage" => ["مدیریت کاربر", "Manage user", "Gere usorem", "管理用户", "Управление"],
        "sel_clr" => ["پاک کردن انتخاب", "Clear sel", "Purgare", "清空选择", "Сбросить"],
        _ => [key, key, key, key, key],
    };
    arr[lang.idx()]
}

/// Render or edit the paginated `/users` ACL list panel (`uadm:list:{flt}:{page}`).
pub async fn show_users_panel(
    ctx: &Arc<BotCtx>,
    cq: Option<&CallbackQuery>,
    chat_id: i64,
    flt: &str,
    page: usize,
) {
    let lang = owner_lang(ctx);
    let flt_norm = match flt {
        "pending" | "approved" | "blocked" => flt,
        _ => "all",
    };
    let filter_enum = UserFilter::from_str(flt_norm).unwrap_or(UserFilter::All);
    let all_u = ctx.acl.list_users(UserFilter::All);
    let filtered = ctx.acl.list_users(filter_enum);
    let sel: HashSet<i64> = ctx.acl.selected_uids().into_iter().collect();

    let cnt_app = all_u
        .iter()
        .filter(|r| r.status == UserStatus::Approved)
        .count();
    let cnt_pend = all_u
        .iter()
        .filter(|r| r.status == UserStatus::Pending)
        .count();
    let cnt_blk = all_u
        .iter()
        .filter(|r| r.status == UserStatus::Blocked)
        .count();

    let pages = filtered.len().div_ceil(USERS_PER_PAGE).max(1);
    let page = page.min(pages - 1);
    let start = page * USERS_PER_PAGE;
    let end = (start + USERS_PER_PAGE).min(filtered.len());
    let chunk = filtered.get(start..end).unwrap_or(&[]);

    let mut rows: Vec<Vec<InlineKeyboardButton>> = vec![vec![
        ctx.btn(
            "",
            &format!(
                "{}{} ({})",
                if flt_norm == "all" { "● " } else { "" },
                users_lbl(lang, "all"),
                all_u.len()
            ),
            Some("uadm:list:all:0"),
            None,
            None,
        ),
        ctx.btn(
            "",
            &format!(
                "{}{} ({cnt_pend})",
                if flt_norm == "pending" { "● " } else { "" },
                users_lbl(lang, "pend"),
            ),
            Some("uadm:list:pending:0"),
            None,
            None,
        ),
        ctx.btn(
            "",
            &format!(
                "{}{} ({cnt_app})",
                if flt_norm == "approved" { "● " } else { "" },
                users_lbl(lang, "app"),
            ),
            Some("uadm:list:approved:0"),
            None,
            None,
        ),
        ctx.btn(
            "",
            &format!(
                "{}{} ({cnt_blk})",
                if flt_norm == "blocked" { "● " } else { "" },
                users_lbl(lang, "blk"),
            ),
            Some("uadm:list:blocked:0"),
            None,
            None,
        ),
    ]];

    let mut md_lines = vec![
        format!("### {} {}", ctx.premium.md("account"), t(lang, Tx::PanelUsersTitle)),
        format!(
            "> {}: **{cnt_app}** · {}: **{cnt_pend}** · {}: **{cnt_blk}** · {}: **{}** · {} **{}/{pages}**",
            users_lbl(lang, "app"),
            users_lbl(lang, "pend"),
            users_lbl(lang, "blk"),
            users_lbl(lang, "sel"),
            sel.len(),
            users_lbl(lang, "page"),
            page + 1
        ),
        String::new(),
        format!(
            "| {} | {} | {} |",
            users_lbl(lang, "col_u"),
            users_lbl(lang, "col_s"),
            users_lbl(lang, "col_p")
        ),
        "|---|---|---|".to_string(),
    ];

    for r in chunk {
        let tuid = r.uid;
        let lbl = acl_user_label(r);
        let pt = perm_tags(&r.perms);
        let is_own = ctx.is_owner(tuid);
        let tier_b = if is_own { RoleTier::Owner.badge() } else { r.tier().badge() };
        let st_i = if is_own { "✓" } else { status_icon(r.status) };
        let sel_dot = if !is_own && sel.contains(&tuid) {
            "● "
        } else {
            ""
        };
        md_lines.push(format!(
            "| {sel_dot}{} `{tuid}` | {tier_b} {st_i} | `{pt}` |",
            md_cell(&truncate_chars(&lbl, 22))
        ));

        if is_own {
            rows.push(vec![ctx.btn(
                "",
                &format!("★ {} · Owner", truncate_chars(&lbl, 22)),
                Some(&format!("uadm:u:{tuid}")),
                None,
                None,
            )]);
        } else {
            rows.push(vec![
                ctx.btn(
                    "",
                    if sel.contains(&tuid) { "●" } else { "○" },
                    Some(&format!("uadm:sel:{tuid}:{flt_norm}:{page}")),
                    None,
                    None,
                ),
                ctx.btn(
                    "",
                    &format!("{tier_b}{st_i} {} · {pt}", truncate_chars(&lbl, 16)),
                    Some(&format!("uadm:u:{tuid}")),
                    None,
                    None,
                ),
            ]);
        }
    }

    if chunk.is_empty() {
        md_lines.push(format!("| — | — | {} |", users_lbl(lang, "empty")));
    }

    if pages > 1 {
        let mut nav = Vec::new();
        if page > 0 {
            nav.push(ctx.btn(
                "",
                users_lbl(lang, "prev"),
                Some(&format!("uadm:list:{flt_norm}:{}", page - 1)),
                None,
                None,
            ));
        }
        if page + 1 < pages {
            nav.push(ctx.btn(
                "",
                users_lbl(lang, "next"),
                Some(&format!("uadm:list:{flt_norm}:{}", page + 1)),
                None,
                None,
            ));
        }
        rows.push(nav);
    }

    let mut footer = vec![ctx.btn(
        "",
        &format!("{} ({})", users_lbl(lang, "bulk"), sel.len()),
        Some("uadm:bulk"),
        Some("primary"),
        None,
    )];
    if cnt_pend > 0 {
        footer.push(ctx.btn(
            "",
            &format!("{} ({cnt_pend})", users_lbl(lang, "app_pend")),
            Some("uadm:b_st:pending:approved"),
            Some("success"),
            None,
        ));
    }
    footer.push(ctx.btn("menu", t(lang, Tx::BtnMenu), Some("home"), None, None));
    rows.push(footer);

    send_rich_card(ctx, cq, chat_id, &md_lines.join("\n"), rows).await;
}

/// Render or edit single-user ACL detail card (`uadm:u:{tuid}`).
pub async fn show_user_detail(
    ctx: &Arc<BotCtx>,
    cq: Option<&CallbackQuery>,
    chat_id: i64,
    tuid: i64,
) {
    let lang = owner_lang(ctx);
    let Some(rec) = ctx.acl.get_user(tuid) else {
        let md = format!(
            "### {} {}\n\n> `{tuid}`",
            ctx.premium.md("warn"),
            users_lbl(lang, "not_found")
        );
        let rows = vec![vec![
            ctx.btn("", users_lbl(lang, "back_u"), Some("uadm:list:all:0"), None, None),
            ctx.btn("menu", t(lang, Tx::BtnMenu), Some("home"), None, None),
        ]];
        send_rich_card(ctx, cq, chat_id, &md, rows).await;
        return;
    };

    let uname = rec
        .username
        .as_deref()
        .filter(|s| !s.is_empty())
        .map(|u| format!("@{u}"))
        .unwrap_or_else(|| "—".to_string());
    let lbl = acl_user_label(&rec);
    let is_own = ctx.is_owner(tuid);
    let st = rec.status;
    let tier = if is_own { RoleTier::Owner } else { rec.tier() };

    let mut md_lines = vec![
        format!("### {} {}", ctx.premium.md("bolt"), md_cell(&lbl)),
        String::new(),
        format!("| {} | {} |", users_lbl(lang, "attr"), users_lbl(lang, "val")),
        "|---|---|".to_string(),
        format!("| {} | `{tuid}` |", users_lbl(lang, "uid")),
        format!("| {} | `{}` |", users_lbl(lang, "uname"), md_cell(&uname)),
        format!(
            "| {} / {} | `{}` · `{}` |",
            users_lbl(lang, "tier"),
            users_lbl(lang, "status"),
            md_cell(&tier_badge_name(lang, tier)),
            md_cell(st.as_str()),
        ),
    ];

    for key in PERM_KEYS {
        let on = rec.perms.get(key).unwrap_or(false);
        md_lines.push(format!(
            "| {} | `{}` |",
            md_cell(perm_label(lang, key)),
            if on { "✅" } else { "○" }
        ));
    }

    let mut rows: Vec<Vec<InlineKeyboardButton>> = Vec::new();
    if is_own {
        md_lines.push(String::new());
        md_lines.push(format!("> {}", users_lbl(lang, "owner_imm")));
        rows.push(vec![
            ctx.btn("", users_lbl(lang, "back_u"), Some("uadm:list:all:0"), None, None),
            ctx.btn("menu", t(lang, Tx::BtnMenu), Some("home"), None, None),
        ]);
    } else {
        // Status row
        rows.push(vec![
            ctx.btn(
                "",
                &format!(
                    "{}{}",
                    if st == UserStatus::Approved { "● " } else { "" },
                    users_lbl(lang, "st_app")
                ),
                Some(&format!("uadm:st:{tuid}:approved")),
                if st != UserStatus::Approved { Some("success") } else { None },
                None,
            ),
            ctx.btn(
                "",
                &format!(
                    "{}{}",
                    if st == UserStatus::Pending { "● " } else { "" },
                    users_lbl(lang, "st_pend")
                ),
                Some(&format!("uadm:st:{tuid}:pending")),
                None,
                None,
            ),
            ctx.btn(
                "",
                &format!(
                    "{}{}",
                    if st == UserStatus::Blocked { "● " } else { "" },
                    users_lbl(lang, "st_blk")
                ),
                Some(&format!("uadm:st:{tuid}:blocked")),
                if st != UserStatus::Blocked { Some("danger") } else { None },
                None,
            ),
        ]);

        // Tier switcher row (User minimal vs Admin full + root; Owner stays immutable)
        rows.push(vec![
            ctx.btn(
                "",
                &format!(
                    "{}{}",
                    if tier == RoleTier::User { "● " } else { "" },
                    tier_badge_name(lang, RoleTier::User)
                ),
                Some(&format!("uadm:tier:{tuid}:user")),
                None,
                None,
            ),
            ctx.btn(
                "",
                &format!(
                    "{}{}",
                    if tier == RoleTier::Admin { "● " } else { "" },
                    tier_badge_name(lang, RoleTier::Admin)
                ),
                Some(&format!("uadm:tier:{tuid}:admin")),
                if tier != RoleTier::Admin { Some("primary") } else { None },
                None,
            ),
        ]);

        // Modular 12-module permission grid (works on BOTH User and Admin!)
        for chunk in PERM_KEYS.chunks(3) {
            let row = chunk
                .iter()
                .map(|&perm_key| {
                    let on = rec.perms.get(perm_key).unwrap_or(false);
                    ctx.btn(
                        "",
                        &format!("{} {}", if on { "✅" } else { "○" }, perm_label(lang, perm_key)),
                        Some(&format!("uadm:perm:{tuid}:{perm_key}")),
                        None,
                        None,
                    )
                })
                .collect();
            rows.push(row);
        }

        rows.push(vec![
            ctx.btn("", users_lbl(lang, "remove"), Some(&format!("uadm:rm:{tuid}")), Some("danger"), None),
            ctx.btn("", users_lbl(lang, "back_u"), Some("uadm:list:all:0"), None, None),
            ctx.btn("menu", t(lang, Tx::BtnMenu), Some("home"), None, None),
        ]);
    }

    send_rich_card(ctx, cq, chat_id, &md_lines.join("\n"), rows).await;
}

/// Render or edit the bulk ACL operations view (`uadm:bulk`, `uadm:bscope:{scope}`).
pub async fn show_users_bulk(
    ctx: &Arc<BotCtx>,
    cq: Option<&CallbackQuery>,
    chat_id: i64,
    scope_raw: &str,
) {
    let lang = owner_lang(ctx);
    let target = BulkTarget::from_str(scope_raw).unwrap_or(BulkTarget::Selected);
    let scope = target.as_str();
    let all_non: Vec<AclUser> = ctx
        .acl
        .list_users(UserFilter::All)
        .into_iter()
        .filter(|r| !ctx.is_owner(r.uid))
        .collect();
    let cnt_sel = ctx.acl.selected_uids().len();
    let cnt_pend = all_non
        .iter()
        .filter(|r| r.status == UserStatus::Pending)
        .count();
    let cnt_app = all_non
        .iter()
        .filter(|r| r.status == UserStatus::Approved)
        .count();
    let cnt_all = all_non.len();

    let target_cnt = match target {
        BulkTarget::Selected => cnt_sel,
        BulkTarget::Pending => cnt_pend,
        BulkTarget::ApprovedNonOwner => cnt_app,
        BulkTarget::AllNonOwner => cnt_all,
    };

    let rows = vec![
        vec![
            ctx.btn(
                "",
                &format!(
                    "{}{} ({cnt_sel})",
                    if target == BulkTarget::Selected { "● " } else { "" },
                    users_lbl(lang, "sel")
                ),
                Some("uadm:bscope:selected"),
                None,
                None,
            ),
            ctx.btn(
                "",
                &format!(
                    "{}{} ({cnt_pend})",
                    if target == BulkTarget::Pending { "● " } else { "" },
                    users_lbl(lang, "pend")
                ),
                Some("uadm:bscope:pending"),
                None,
                None,
            ),
            ctx.btn(
                "",
                &format!(
                    "{}{} ({cnt_app})",
                    if target == BulkTarget::ApprovedNonOwner { "● " } else { "" },
                    users_lbl(lang, "app")
                ),
                Some("uadm:bscope:approved_non_owner"),
                None,
                None,
            ),
            ctx.btn(
                "",
                &format!(
                    "{}{} ({cnt_all})",
                    if target == BulkTarget::AllNonOwner { "● " } else { "" },
                    users_lbl(lang, "all")
                ),
                Some("uadm:bscope:all_non_owner"),
                None,
                None,
            ),
        ],
        vec![
            ctx.btn(
                "",
                users_lbl(lang, "st_app"),
                Some(&format!("uadm:b_st:{scope}:approved")),
                Some("success"),
                None,
            ),
            ctx.btn(
                "",
                users_lbl(lang, "st_pend"),
                Some(&format!("uadm:b_st:{scope}:pending")),
                None,
                None,
            ),
            ctx.btn(
                "",
                users_lbl(lang, "st_blk"),
                Some(&format!("uadm:b_st:{scope}:blocked")),
                Some("danger"),
                None,
            ),
        ],
        vec![
            ctx.btn(
                "",
                &format!("→ {}", tier_badge_name(lang, RoleTier::User)),
                Some(&format!("uadm:b_tier:{scope}:user")),
                None,
                None,
            ),
            ctx.btn(
                "",
                &format!("→ {}", tier_badge_name(lang, RoleTier::Admin)),
                Some(&format!("uadm:b_tier:{scope}:admin")),
                Some("primary"),
                None,
            ),
        ],
        vec![
            ctx.btn("", "Dash +", Some(&format!("uadm:b_p:{scope}:dashboard_access:1")), None, None),
            ctx.btn("", "Uncens +", Some(&format!("uadm:b_p:{scope}:uncensored:1")), None, None),
            ctx.btn("", "Root +", Some(&format!("uadm:b_p:{scope}:root_access:1")), None, None),
        ],
        vec![
            ctx.btn("", "Dash −", Some(&format!("uadm:b_p:{scope}:dashboard_access:0")), None, None),
            ctx.btn("", "Uncens −", Some(&format!("uadm:b_p:{scope}:uncensored:0")), None, None),
            ctx.btn("", "Root −", Some(&format!("uadm:b_p:{scope}:root_access:0")), Some("danger"), None),
        ],
        vec![
            ctx.btn("", "Skills +", Some(&format!("uadm:b_p:{scope}:skills_manage:1")), None, None),
            ctx.btn("", "MCP +", Some(&format!("uadm:b_p:{scope}:mcp_manage:1")), None, None),
            ctx.btn("", "Skills −", Some(&format!("uadm:b_p:{scope}:skills_manage:0")), None, None),
            ctx.btn("", "MCP −", Some(&format!("uadm:b_p:{scope}:mcp_manage:0")), None, None),
        ],
        vec![
            ctx.btn("", "Grok +", Some(&format!("uadm:b_p:{scope}:grok:1")), None, None),
            ctx.btn("", "Grok −", Some(&format!("uadm:b_p:{scope}:grok:0")), None, None),
            ctx.btn("", "Sandbox +", Some(&format!("uadm:b_p:{scope}:sandbox_exec:1")), None, None),
            ctx.btn("", "Sandbox −", Some(&format!("uadm:b_p:{scope}:sandbox_exec:0")), None, None),
        ],
        vec![
            ctx.btn("", users_lbl(lang, "back_u"), Some("uadm:list:all:0"), None, None),
            ctx.btn("menu", t(lang, Tx::BtnMenu), Some("home"), None, None),
        ],
    ];

    let md = [
        format!("### {} {}", ctx.premium.md("bolt"), users_lbl(lang, "bulk")),
        String::new(),
        format!("| {} | {} |", users_lbl(lang, "attr"), users_lbl(lang, "val")),
        "|---|---|".to_string(),
        format!("| {} | {} |", users_lbl(lang, "scope"), md_cell(scope_title(lang, target))),
        format!("| {} | `{target_cnt}` |", users_lbl(lang, "count")),
    ]
    .join("\n");

    send_rich_card(ctx, cq, chat_id, &md, rows).await;
}

/// Dispatch all `uadm:*` callback queries (owner-only). Returns `true` if `data` starts with `uadm:`.
pub async fn handle_uadm_cb(
    ctx: &Arc<BotCtx>,
    cq: &CallbackQuery,
    uid: i64,
    chat_id: i64,
    data: &str,
) -> bool {
    if !data.starts_with("uadm:") {
        return false;
    }
    if !ctx.is_owner(uid) {
        let lang = ctx.lang(uid);
        ctx.ack(&cq.id, Some(t(lang, Tx::OwnerOnly)), true).await;
        return true;
    }

    let parts: Vec<&str> = data.split(':').collect();
    let act = parts.get(1).copied().unwrap_or("");

    match act {
        "list" => {
            let flt = parts.get(2).copied().unwrap_or("all");
            let pg = parts
                .get(3)
                .and_then(|s| s.parse::<isize>().ok())
                .map(|n| n.max(0) as usize)
                .unwrap_or(0);
            ctx.ack(&cq.id, None, false).await;
            show_users_panel(ctx, Some(cq), chat_id, flt, pg).await;
        }
        "sel" if parts.len() >= 5 => {
            if let Ok(tuid) = parts[2].parse::<i64>() {
                let _ = ctx.acl.toggle_select(tuid);
            }
            let pg = parts[4].parse::<usize>().unwrap_or(0);
            ctx.ack(&cq.id, None, false).await;
            show_users_panel(ctx, Some(cq), chat_id, parts[3], pg).await;
        }
        "selpage" if parts.len() >= 4 => {
            let flt = parts[2];
            let pg = parts[3].parse::<usize>().unwrap_or(0);
            let filter_enum = UserFilter::from_str(flt).unwrap_or(UserFilter::All);
            let filtered = ctx.acl.list_users(filter_enum);
            let start = pg * USERS_PER_PAGE;
            let page_uids: Vec<i64> = filtered
                .into_iter()
                .skip(start)
                .take(USERS_PER_PAGE)
                .map(|r| r.uid)
                .filter(|&id| !ctx.is_owner(id))
                .collect();
            let count = page_uids.len();
            if count > 0 {
                let _ = ctx.acl.select_many(&page_uids, true);
            }
            ctx.ack(&cq.id, Some(&format!("Selected {count}")), false)
                .await;
            show_users_panel(ctx, Some(cq), chat_id, flt, pg).await;
        }
        "selclr" if parts.len() >= 4 => {
            let _ = ctx.acl.clear_selection();
            let pg = parts[3].parse::<usize>().unwrap_or(0);
            ctx.ack(&cq.id, Some("Selection cleared"), false).await;
            show_users_panel(ctx, Some(cq), chat_id, parts[2], pg).await;
        }
        "u" if parts.len() >= 3 => {
            if let Ok(tuid) = parts[2].parse::<i64>() {
                ctx.ack(&cq.id, None, false).await;
                show_user_detail(ctx, Some(cq), chat_id, tuid).await;
            } else {
                ctx.ack(&cq.id, Some("Invalid user ID"), false).await;
            }
        }
        "ok" if parts.len() >= 3 => {
            let Ok(tuid) = parts[2].parse::<i64>() else {
                ctx.ack(&cq.id, Some("Invalid user ID"), false).await;
                return true;
            };
            let preset_str = parts.get(3).copied().unwrap_or("std");
            let preset = RolePreset::from_str(preset_str).unwrap_or(RolePreset::Std);
            if ctx.is_owner(tuid) {
                ctx.ack(&cq.id, Some("Owner already approved"), false).await;
                return true;
            }
            let prev = ctx.acl.get_user(tuid).map(|r| r.status);
            match ctx
                .acl
                .set_status(tuid, UserStatus::Approved, Some(uid), Some(preset))
            {
                Ok(rec) => {
                    sync_user_commands_for(ctx, tuid).await;
                    if prev != Some(UserStatus::Approved) {
                        ctx.send_approved_welcome(tuid).await;
                    }
                    ctx.ack(&cq.id, Some("تایید شد"), false).await;
                    let lbl = acl_user_label(&rec);
                    let md = format!(
                        "### {} کاربر تایید شد\n\n> {} (`{tuid}`) · پریست `{}`",
                        ctx.premium.md("ok"),
                        md_cell(&lbl),
                        md_cell(preset.as_str())
                    );
                    let rows = vec![vec![
                        ctx.btn("", "مدیریت کاربر", Some(&format!("uadm:u:{tuid}")), None, None),
                        ctx.btn("", "کاربران", Some("uadm:list:all:0"), None, None),
                    ]];
                    send_rich_card(ctx, Some(cq), chat_id, &md, rows).await;
                }
                Err(err) => {
                    warn!(tuid, error = %err, "uadm:ok failed");
                    ctx.ack(&cq.id, Some("Failed"), false).await;
                }
            }
        }
        "blk" if parts.len() >= 3 => {
            let Ok(tuid) = parts[2].parse::<i64>() else {
                ctx.ack(&cq.id, Some("Invalid user ID"), false).await;
                return true;
            };
            if ctx.is_owner(tuid) {
                ctx.ack(&cq.id, Some("Cannot block owner"), false).await;
                return true;
            }
            match ctx
                .acl
                .set_status(tuid, UserStatus::Blocked, Some(uid), None)
            {
                Ok(rec) => {
                    ctx.jobs.stop_user(tuid).await;
                    ctx.jobs.clear_awaiting(tuid);
                    sync_user_commands_for(ctx, tuid).await;
                    ctx.ack(&cq.id, Some("مسدود شد"), false).await;
                    let lbl = acl_user_label(&rec);
                    let md = format!(
                        "### {} کاربر مسدود شد\n\n> {} (`{tuid}`)",
                        ctx.premium.md("err"),
                        md_cell(&lbl)
                    );
                    let rows = vec![vec![
                        ctx.btn("", "مدیریت کاربر", Some(&format!("uadm:u:{tuid}")), None, None),
                        ctx.btn("", "کاربران", Some("uadm:list:all:0"), None, None),
                    ]];
                    send_rich_card(ctx, Some(cq), chat_id, &md, rows).await;
                }
                Err(err) => {
                    warn!(tuid, error = %err, "uadm:blk failed");
                    ctx.ack(&cq.id, Some("Failed"), false).await;
                }
            }
        }
        "st" if parts.len() >= 4 => {
            let Ok(tuid) = parts[2].parse::<i64>() else {
                ctx.ack(&cq.id, Some("Invalid user ID"), false).await;
                return true;
            };
            let Ok(st_val) = UserStatus::from_str(parts[3]) else {
                ctx.ack(&cq.id, Some("Invalid status"), false).await;
                return true;
            };
            if ctx.is_owner(tuid) && st_val != UserStatus::Approved {
                ctx.ack(&cq.id, Some("Owner cannot be demoted"), false)
                    .await;
                return true;
            }
            if !ctx.is_owner(tuid) {
                let prev = ctx.acl.get_user(tuid).map(|r| r.status);
                if let Err(err) = ctx.acl.set_status(tuid, st_val, Some(uid), None) {
                    warn!(tuid, error = %err, "uadm:st failed");
                    ctx.ack(&cq.id, Some("Failed"), false).await;
                    return true;
                }
                sync_user_commands_for(ctx, tuid).await;
                if st_val == UserStatus::Approved && prev != Some(UserStatus::Approved) {
                    ctx.send_approved_welcome(tuid).await;
                }
            }
            ctx.ack(&cq.id, Some(&format!("Status: {}", st_val.as_str())), false)
                .await;
            show_user_detail(ctx, Some(cq), chat_id, tuid).await;
        }
        "perm" if parts.len() >= 4 => {
            let Ok(tuid) = parts[2].parse::<i64>() else {
                ctx.ack(&cq.id, Some("Invalid user ID"), false).await;
                return true;
            };
            let perm = parts[3];
            if ctx.is_owner(tuid) {
                ctx.ack(&cq.id, Some("Owner permissions immutable"), false)
                    .await;
                return true;
            }
            match ctx.acl.set_perm(tuid, perm, None) {
                Ok(rec) => {
                    sync_user_commands_for(ctx, tuid).await;
                    let on = rec.perms.get(perm).unwrap_or(false);
                    ctx.ack(
                        &cq.id,
                        Some(&format!(
                            "{}: {}",
                            perm_label(owner_lang(ctx), perm),
                            if on { "ON" } else { "OFF" }
                        )),
                        false,
                    )
                    .await;
                    show_user_detail(ctx, Some(cq), chat_id, tuid).await;
                }
                Err(err) => {
                    ctx.ack(&cq.id, Some(&truncate_chars(&err.to_string(), 160)), false)
                        .await;
                }
            }
        }
        "tier" if parts.len() >= 4 => {
            let Ok(tuid) = parts[2].parse::<i64>() else {
                ctx.ack(&cq.id, Some("Invalid user ID"), false).await;
                return true;
            };
            let Ok(tier) = RoleTier::parse_non_owner(parts[3]) else {
                ctx.ack(&cq.id, Some("Invalid tier"), false).await;
                return true;
            };
            match ctx.acl.set_tier(tuid, tier, true) {
                Ok(_) => {
                    sync_user_commands_for(ctx, tuid).await;
                    let lbl = tier_badge_name(owner_lang(ctx), tier);
                    ctx.ack(&cq.id, Some(&lbl), false).await;
                    show_user_detail(ctx, Some(cq), chat_id, tuid).await;
                }
                Err(err) => {
                    ctx.ack(&cq.id, Some(&truncate_chars(&err.to_string(), 160)), false)
                        .await;
                }
            }
        }
        "pre" if parts.len() >= 4 => {
            let Ok(tuid) = parts[2].parse::<i64>() else {
                ctx.ack(&cq.id, Some("Invalid user ID"), false).await;
                return true;
            };
            if ctx.is_owner(tuid) {
                ctx.ack(&cq.id, Some("Owner permissions immutable"), false)
                    .await;
                return true;
            }
            let Ok(preset) = RolePreset::from_str(parts[3]) else {
                ctx.ack(&cq.id, Some("Unknown preset"), false).await;
                return true;
            };
            if ctx.acl.apply_preset(tuid, preset).is_ok() {
                sync_user_commands_for(ctx, tuid).await;
                ctx.ack(&cq.id, Some(&format!("Preset: {}", preset.as_str())), false)
                    .await;
                show_user_detail(ctx, Some(cq), chat_id, tuid).await;
            } else {
                ctx.ack(&cq.id, Some("Failed"), false).await;
            }
        }
        "rm" if parts.len() >= 3 => {
            let Ok(tuid) = parts[2].parse::<i64>() else {
                ctx.ack(&cq.id, Some("Invalid user ID"), false).await;
                return true;
            };
            if ctx.is_owner(tuid) {
                ctx.ack(&cq.id, Some("Cannot remove owner"), false).await;
                return true;
            }
            let ok = ctx.acl.remove_user(tuid).unwrap_or(false);
            if ok {
                ctx.jobs.stop_user(tuid).await;
                ctx.jobs.clear_awaiting(tuid);
                sync_user_commands_for(ctx, tuid).await;
            }
            ctx.ack(&cq.id, Some(if ok { "حذف شد" } else { "یافت نشد" }), false)
                .await;
            show_users_panel(ctx, Some(cq), chat_id, "all", 0).await;
        }
        "bulk" => {
            ctx.ack(&cq.id, None, false).await;
            let scope = if ctx.acl.selected_uids().is_empty() {
                "all_non_owner"
            } else {
                "selected"
            };
            show_users_bulk(ctx, Some(cq), chat_id, scope).await;
        }
        "bscope" if parts.len() >= 3 => {
            ctx.ack(&cq.id, None, false).await;
            show_users_bulk(ctx, Some(cq), chat_id, parts[2]).await;
        }
        "b_st" if parts.len() >= 4 => {
            let Ok(target) = BulkTarget::from_str(parts[2]) else {
                ctx.ack(&cq.id, Some("Invalid bulk scope"), false).await;
                return true;
            };
            let Ok(st_val) = UserStatus::from_str(parts[3]) else {
                ctx.ack(&cq.id, Some("Invalid status"), false).await;
                return true;
            };
            let prev_app: HashSet<i64> = ctx
                .acl
                .list_users(UserFilter::Approved)
                .into_iter()
                .map(|r| r.uid)
                .collect();
            let uids = ctx
                .acl
                .bulk_set_status(target, st_val, None, Some(uid))
                .unwrap_or_default();
            for &tid in &uids {
                sync_user_commands_for(ctx, tid).await;
                if st_val == UserStatus::Approved && !prev_app.contains(&tid) && !ctx.is_owner(tid)
                {
                    ctx.send_approved_welcome(tid).await;
                }
            }
            ctx.ack(&cq.id, Some(&format!("Updated {} user(s)", uids.len())), false)
                .await;
            let msg_txt = cq
                .message
                .as_ref()
                .and_then(|m| m.text.as_deref())
                .unwrap_or("");
            if msg_txt.contains("عملیات جمعی")
                || msg_txt.contains("محدوده")
                || msg_txt.contains("Bulk")
                || msg_txt.contains("gregalia")
                || msg_txt.contains("批量")
                || msg_txt.contains("Массовые")
            {
                show_users_bulk(ctx, Some(cq), chat_id, target.as_str()).await;
            } else {
                show_users_panel(ctx, Some(cq), chat_id, "all", 0).await;
            }
        }
        "b_tier" if parts.len() >= 4 => {
            let Ok(target) = BulkTarget::from_str(parts[2]) else {
                ctx.ack(&cq.id, Some("Invalid bulk scope"), false).await;
                return true;
            };
            let Ok(tier) = RoleTier::parse_non_owner(parts[3]) else {
                ctx.ack(&cq.id, Some("Invalid tier"), false).await;
                return true;
            };
            let uids = ctx
                .acl
                .bulk_set_tier(target, tier, true)
                .unwrap_or_default();
            for &tid in &uids {
                sync_user_commands_for(ctx, tid).await;
            }
            let lbl = tier_badge_name(owner_lang(ctx), tier);
            ctx.ack(&cq.id, Some(&format!("{lbl} ({})", uids.len())), false)
                .await;
            show_users_bulk(ctx, Some(cq), chat_id, target.as_str()).await;
        }
        "b_p" if parts.len() >= 5 => {
            let Ok(target) = BulkTarget::from_str(parts[2]) else {
                ctx.ack(&cq.id, Some("Invalid bulk scope"), false).await;
                return true;
            };
            let perm = parts[3];
            let val = parts[4] == "1";
            match ctx.acl.bulk_set_perm(target, perm, val) {
                Ok(uids) => {
                    for &tid in &uids {
                        sync_user_commands_for(ctx, tid).await;
                    }
                    ctx.ack(
                        &cq.id,
                        Some(&format!(
                            "{perm} -> {} ({})",
                            if val { "ON" } else { "OFF" },
                            uids.len()
                        )),
                        false,
                    )
                    .await;
                    show_users_bulk(ctx, Some(cq), chat_id, target.as_str()).await;
                }
                Err(err) => {
                    ctx.ack(&cq.id, Some(&truncate_chars(&err.to_string(), 160)), false)
                        .await;
                }
            }
        }
        "b_pre" if parts.len() >= 4 => {
            let Ok(target) = BulkTarget::from_str(parts[2]) else {
                ctx.ack(&cq.id, Some("Invalid bulk scope"), false).await;
                return true;
            };
            let Ok(preset) = RolePreset::from_str(parts[3]) else {
                ctx.ack(&cq.id, Some("Unknown preset"), false).await;
                return true;
            };
            let uids = ctx
                .acl
                .bulk_apply_preset(target, preset)
                .unwrap_or_default();
            for &tid in &uids {
                sync_user_commands_for(ctx, tid).await;
            }
            ctx.ack(
                &cq.id,
                Some(&format!("Preset {} -> {} user(s)", preset.as_str(), uids.len())),
                false,
            )
            .await;
            show_users_bulk(ctx, Some(cq), chat_id, target.as_str()).await;
        }
        _ => {
            ctx.ack(&cq.id, None, false).await;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use agy_core::acl::AclStore;
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
    const USER_A: i64 = 1_000_000_002;
    const USER_B: i64 = 8_000_111_222;

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
            _ => json!({"message_id": 55, "chat": {"id": 1, "type": "private"}, "text": "ok"}),
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
        let cfg = Arc::new(Config {
            bot_token: "123:ABC".into(),
            state_dir: state_dir.clone(),
            agy_workspace: dir.path().to_path_buf(),
            owner_id: OWNER,
            agy_bin: PathBuf::from("/bin/true"),
            ..Default::default()
        });
        let store = Arc::new(StateStore::open(cfg.state_path()).unwrap());
        let acl = Arc::new(AclStore::open(cfg.acl_path(), OWNER, &[], 300).unwrap());
        acl.touch_user(&User {
            id: USER_A,
            is_bot: false,
            first_name: "Alice".into(),
            last_name: None,
            username: Some("alice".into()),
            language_code: None,
            is_premium: Some(false),
        })
        .unwrap();
        acl.touch_user(&User {
            id: USER_B,
            is_bot: false,
            first_name: "Bob".into(),
            last_name: None,
            username: None,
            language_code: None,
            is_premium: Some(false),
        })
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
            message_id: 10,
            from_user: Some(User {
                id: uid,
                is_bot: false,
                first_name: "Actor".into(),
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

    fn mk_cq(uid: i64, data: &str, msg_text: &str) -> CallbackQuery {
        CallbackQuery {
            id: "cq-uadm".into(),
            from_user: User {
                id: uid,
                is_bot: false,
                first_name: "Actor".into(),
                last_name: None,
                username: None,
                language_code: None,
                is_premium: Some(false),
            },
            message: Some(mk_msg(uid, msg_text)),
            inline_message_id: None,
            data: Some(data.into()),
        }
    }

    #[tokio::test]
    async fn users_panel_is_strictly_owner_only() {
        let dir = TempDir::new().unwrap();
        let (ctx, st) = setup_ctx(&dir).await;

        // Non-owner (both User and Admin tiers) /users denied
        let _ = ctx.acl.set_status(USER_A, UserStatus::Approved, Some(OWNER), None);
        let _ = ctx.acl.set_tier(USER_A, RoleTier::Admin, true);
        cmd_users(&ctx, &mk_msg(USER_A, "/users")).await;
        let calls = st.calls.lock().await;
        assert!(calls.iter().any(|(m, p)| m == "sendMessage"
            && (p["text"].as_str().unwrap_or("").contains("Owner-only")
                || p["text"].as_str().unwrap_or("").contains("مالک"))));
        drop(calls);

        // Non-owner Admin uadm:* denied without mutating ACL
        assert!(handle_uadm_cb(
            &ctx,
            &mk_cq(USER_A, &format!("uadm:ok:{USER_B}:full"), ""),
            USER_A,
            USER_A,
            &format!("uadm:ok:{USER_B}:full"),
        )
        .await);
        assert_eq!(ctx.acl.get_user(USER_B).unwrap().status, UserStatus::Pending);
        assert!(!ctx.acl.has_perm(USER_B, "root_access"));
    }

    #[tokio::test]
    async fn owner_can_approve_toggle_perms_bulk_update_and_remove_users() {
        let dir = TempDir::new().unwrap();
        let (ctx, st) = setup_ctx(&dir).await;

        cmd_users(&ctx, &mk_msg(OWNER, "/users")).await;

        // Approve USER_A with dev preset -> sends welcome + sets commands
        let ok_cb = format!("uadm:ok:{USER_A}:dev");
        assert!(handle_uadm_cb(&ctx, &mk_cq(OWNER, &ok_cb, ""), OWNER, OWNER, &ok_cb).await);
        assert_eq!(ctx.acl.get_user(USER_A).unwrap().status, UserStatus::Approved);
        assert!(ctx.acl.has_perm(USER_A, "skills_manage"));
        assert!(ctx.acl.has_perm(USER_A, "mcp_manage"));
        assert!(!ctx.acl.has_perm(USER_A, "root_access"));
        assert!(ctx.commands_set.contains_key(&USER_A));

        // Toggle root_access on USER_A
        let perm_cb = format!("uadm:perm:{USER_A}:root_access");
        assert!(handle_uadm_cb(&ctx, &mk_cq(OWNER, &perm_cb, ""), OWNER, OWNER, &perm_cb).await);
        assert!(ctx.acl.has_perm(USER_A, "root_access"));

        // Owner immunity on demote/block/perm
        let blk_owner = format!("uadm:blk:{OWNER}");
        assert!(handle_uadm_cb(&ctx, &mk_cq(OWNER, &blk_owner, ""), OWNER, OWNER, &blk_owner).await);
        assert!(ctx.is_approved(OWNER));

        // Select USER_B and bulk-approve + grant skills_manage
        let sel_cb = format!("uadm:sel:{USER_B}:all:0");
        assert!(handle_uadm_cb(&ctx, &mk_cq(OWNER, &sel_cb, ""), OWNER, OWNER, &sel_cb).await);
        assert_eq!(ctx.acl.selected_uids(), vec![USER_B]);

        assert!(handle_uadm_cb(
            &ctx,
            &mk_cq(OWNER, "uadm:b_st:selected:approved", "عملیات جمعی"),
            OWNER,
            OWNER,
            "uadm:b_st:selected:approved",
        )
        .await);
        assert_eq!(ctx.acl.get_user(USER_B).unwrap().status, UserStatus::Approved);

        assert!(handle_uadm_cb(
            &ctx,
            &mk_cq(OWNER, "uadm:b_p:selected:skills_manage:1", "عملیات جمعی"),
            OWNER,
            OWNER,
            "uadm:b_p:selected:skills_manage:1",
        )
        .await);
        assert!(ctx.acl.has_perm(USER_B, "skills_manage"));

        // Remove USER_B -> clears commands & removes record
        let rm_cb = format!("uadm:rm:{USER_B}");
        assert!(handle_uadm_cb(&ctx, &mk_cq(OWNER, &rm_cb, ""), OWNER, OWNER, &rm_cb).await);
        assert!(ctx.acl.get_user(USER_B).is_none());
        assert!(!ctx.commands_set.contains_key(&USER_B));

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
    async fn users_pagination_selpage_preset_and_non_uadm_ignored() {
        let dir = TempDir::new().unwrap();
        let (ctx, st) = setup_ctx(&dir).await;

        // Add 10 more users -> total 13 users -> 2 pages (8 per page)
        for i in 0..10_i64 {
            ctx.acl
                .touch_user(&User {
                    id: 9_000_000 + i,
                    is_bot: false,
                    first_name: format!("User{i}"),
                    last_name: None,
                    username: None,
                    language_code: None,
                    is_premium: Some(false),
                })
                .unwrap();
        }

        assert!(handle_uadm_cb(&ctx, &mk_cq(OWNER, "uadm:list:all:1", ""), OWNER, OWNER, "uadm:list:all:1").await);
        assert!(handle_uadm_cb(&ctx, &mk_cq(OWNER, "uadm:selpage:all:1", ""), OWNER, OWNER, "uadm:selpage:all:1").await);
        assert!(!ctx.acl.selected_uids().is_empty());

        // Bulk preset apply on selected users
        assert!(handle_uadm_cb(&ctx, &mk_cq(OWNER, "uadm:b_pre:selected:dev", ""), OWNER, OWNER, "uadm:b_pre:selected:dev").await);
        for &sel_id in &ctx.acl.selected_uids() {
            let rec = ctx.acl.get_user(sel_id).unwrap();
            assert!(rec.perms.skills_manage);
            assert!(rec.perms.mcp_manage);
            assert!(!rec.perms.root_access);
        }

        // Clear selection
        assert!(handle_uadm_cb(&ctx, &mk_cq(OWNER, "uadm:selclr:all:0", ""), OWNER, OWNER, "uadm:selclr:all:0").await);
        assert!(ctx.acl.selected_uids().is_empty());

        // Single user preset & status transitions & tier switching
        let pre_cb = format!("uadm:pre:{USER_A}:full");
        assert!(handle_uadm_cb(&ctx, &mk_cq(OWNER, &pre_cb, ""), OWNER, OWNER, &pre_cb).await);
        let st_cb = format!("uadm:st:{USER_A}:approved");
        assert!(handle_uadm_cb(&ctx, &mk_cq(OWNER, &st_cb, ""), OWNER, OWNER, &st_cb).await);
        assert!(ctx.acl.has_perm(USER_A, "root_access"));

        // Promote to Admin -> gets all 12 perms; revoke dashboard_access -> revoked while staying Admin; demote to User -> stripped
        let admin_cb = format!("uadm:tier:{USER_A}:admin");
        assert!(handle_uadm_cb(&ctx, &mk_cq(OWNER, &admin_cb, ""), OWNER, OWNER, &admin_cb).await);
        assert!(ctx.acl.is_admin(USER_A));
        assert!(ctx.acl.has_perm(USER_A, "dashboard_access"));
        let rev_dash = format!("uadm:perm:{USER_A}:dashboard_access");
        assert!(handle_uadm_cb(&ctx, &mk_cq(OWNER, &rev_dash, ""), OWNER, OWNER, &rev_dash).await);
        assert!(ctx.acl.is_admin(USER_A));
        assert!(!ctx.acl.has_perm(USER_A, "dashboard_access"));
        let user_cb = format!("uadm:tier:{USER_A}:user");
        assert!(handle_uadm_cb(&ctx, &mk_cq(OWNER, &user_cb, ""), OWNER, OWNER, &user_cb).await);
        assert!(!ctx.acl.is_admin(USER_A));
        assert!(!ctx.acl.has_perm(USER_A, "root_access"));

        // Non-uadm callback returns false
        assert!(!handle_uadm_cb(&ctx, &mk_cq(OWNER, "mcp", ""), OWNER, OWNER, "mcp").await);
        assert!(!st.calls.lock().await.is_empty());
    }
}
