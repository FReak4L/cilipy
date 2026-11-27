//! Owner-only `/accounts` panel: multi-account Antigravity pool (`acct:*` callbacks),
//! including the Telegram-relayed Google OAuth sign-in for new account slots.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use agy_core::accounts::{
    format_tokens_compact, Account, AccountPolicy, AccountPolicyPreset, AccountStore, HealthStatus,
    TokenState,
};
use agy_core::proxies::ResolvedProxy;
use agy_core::tg::{CallbackQuery, InlineKeyboardButton, Message};
use agy_ext::login::LoginSession;
use agy_render::md_cell;
use dashmap::DashMap;
use serde_json::json;
use tracing::{info, warn};

use crate::ctx::BotCtx;
use crate::jobs::{human_secs, AwaitingInput};

struct ActiveLogin {
    session: Arc<LoginSession>,
    initiator_uid: i64,
}

/// Concurrent per-account in-flight sign-ins keyed by `account_id` (supports multiple owners).
fn login_slots() -> &'static DashMap<String, ActiveLogin> {
    static S: OnceLock<DashMap<String, ActiveLogin>> = OnceLock::new();
    S.get_or_init(DashMap::new)
}

fn take_login_for(account_id: &str) -> Option<ActiveLogin> {
    login_slots().remove(account_id).map(|(_, v)| v)
}

fn take_login_if_same(account_id: &str, sess: &Arc<LoginSession>) -> Option<ActiveLogin> {
    login_slots()
        .remove_if(account_id, |_, v| Arc::ptr_eq(&v.session, sess))
        .map(|(_, v)| v)
}

fn current_login_for(account_id: &str) -> Option<(Arc<LoginSession>, i64)> {
    login_slots()
        .get(account_id)
        .map(|v| (Arc::clone(&v.session), v.initiator_uid))
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

fn status_cell(a: &Account, pol: &AccountPolicy) -> String {
    let n = now();
    if !a.enabled && a.health.status != HealthStatus::Disabled {
        return "⏸ paused".to_string();
    }
    if a.health.status == HealthStatus::Ok && a.usage.is_weekly_reserved(n, pol) {
        return format!("🛡 {:.0}% res", pol.weekly_reserve_pct);
    }
    match a.health.status {
        HealthStatus::Ok => "✅ ready".to_string(),
        HealthStatus::Cooldown => match a.health.until_ts {
            Some(u) if u > n => format!("⏳ {}", human_secs((u - n) as u64)),
            _ => "✅ ready".to_string(),
        },
        HealthStatus::Disabled => "⛔ off".to_string(),
    }
}

fn status_icon(a: &Account, pol: &AccountPolicy) -> &'static str {
    let n = now();
    if !a.enabled && a.health.status != HealthStatus::Disabled {
        return "⏸";
    }
    if a.health.status == HealthStatus::Ok && a.usage.is_weekly_reserved(n, pol) {
        return "🛡";
    }
    match a.health.status {
        HealthStatus::Ok => "✅",
        HealthStatus::Cooldown if a.health.until_ts.is_some_and(|u| u > n) => "⏳",
        HealthStatus::Cooldown => "✅",
        HealthStatus::Disabled => "⛔",
    }
}

fn usage_cell(a: &Account, pol: &AccountPolicy) -> String {
    let n = now();
    let mut u = a.usage.clone();
    u.roll_windows(n);
    if let Some(pct) = u.weekly_used_pct_at(n, pol) {
        format!("{pct:.0}% · 5h {}", format_tokens_compact(u.tokens_5h))
    } else if u.tokens_week > 0 || u.tokens_5h > 0 {
        format!(
            "7d {} · 5h {}",
            format_tokens_compact(u.tokens_week),
            format_tokens_compact(u.tokens_5h)
        )
    } else {
        "—".to_string()
    }
}

fn proxy_cell(ctx: &BotCtx, a: &Account) -> String {
    match ctx.proxies.resolve(a.proxy_id.as_deref()) {
        ResolvedProxy::Direct => "direct".to_string(),
        ResolvedProxy::DirectFallback { safe_label, .. } => format!("⚠ {safe_label}→direct"),
        ResolvedProxy::Use { id, safe_label, .. } => {
            if let Some(e) = ctx.proxies.get(&id) {
                format!("{} ({})", e.display_name(), e.health.quality_score)
            } else {
                safe_label
            }
        }
        ResolvedProxy::Blocked { safe_label, .. } => format!("🔴 {safe_label}"),
    }
}

fn parse_token_budget(raw: &str) -> Option<Option<u64>> {
    let s = raw.trim().to_ascii_lowercase();
    if s.is_empty() {
        return None;
    }
    if matches!(s.as_str(), "0" | "auto" | "off" | "none" | "-") {
        return Some(None);
    }
    let (num_str, mult): (&str, f64) = if let Some(n) = s.strip_suffix('b') {
        (n.trim(), 1_000_000_000.0)
    } else if let Some(n) = s.strip_suffix('m') {
        (n.trim(), 1_000_000.0)
    } else if let Some(n) = s.strip_suffix('k') {
        (n.trim(), 1_000.0)
    } else {
        (s.as_str(), 1.0)
    };
    let val = num_str.replace('_', "").parse::<f64>().ok()?;
    if !val.is_finite() || val <= 0.0 {
        return None;
    }
    let total = (val * mult).round() as u64;
    if total < 10_000 {
        return None;
    }
    Some(Some(total))
}

fn ago(ts: Option<i64>) -> String {
    match ts {
        Some(t) if t > 0 => format!("{} ago", human_secs((now() - t).max(0) as u64)),
        _ => "—".to_string(),
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

fn pool(ctx: &BotCtx) -> Option<Arc<AccountStore>> {
    ctx.jobs.accounts()
}

/// `/accounts` (owner only).
pub async fn cmd_accounts(ctx: &Arc<BotCtx>, msg: &Message) {
    let Some(uid) = msg.from_user.as_ref().map(|u| u.id) else {
        return;
    };
    if !ctx.is_owner(uid) {
        let txt = format!("{} <i>Owner only.</i>", ctx.e("err"));
        let _ = ctx.render.send_html_simple(msg.chat.id, &txt, None).await;
        return;
    }
    show_list(ctx, None, msg.chat.id).await;
}

pub async fn show_list(ctx: &Arc<BotCtx>, cq: Option<&CallbackQuery>, chat_id: i64) {
    let Some(p) = pool(ctx) else {
        card(ctx, cq, chat_id, "### Accounts\n\n> Account pool is not initialised.", vec![]).await;
        return;
    };
    let all = p.list();
    let avail = p.available_count();
    let pol = p.policy();
    let reserved = p.weekly_reserved_count();
    let brk = p.breaker_status();
    let now_i = now();
    let cooldown_n = all
        .iter()
        .filter(|a| a.enabled && a.health.status == HealthStatus::Cooldown && a.health.until_ts.is_none_or(|u| u > now_i))
        .count();
    let disabled_n = all
        .iter()
        .filter(|a| a.health.status == HealthStatus::Disabled)
        .count();
    let paused_n = all
        .iter()
        .filter(|a| !a.enabled && a.health.status != HealthStatus::Disabled)
        .count();
    let mut state_extra = String::new();
    if reserved > 0 {
        state_extra.push_str(&format!(" · 🛡 **{reserved}** reserved"));
    }
    if cooldown_n > 0 {
        state_extra.push_str(&format!(" · ⏳ **{cooldown_n}** cooldown"));
    }
    if disabled_n > 0 {
        state_extra.push_str(&format!(" · ⛔ **{disabled_n}** disabled"));
    }
    if paused_n > 0 {
        state_extra.push_str(&format!(" · ⏸ **{paused_n}** paused"));
    }

    let mut md = vec![
        format!("### {} Antigravity accounts", ctx.premium.md("account")),
        format!(
            "> **{}** accounts · **{avail}** ready{state_extra} · Policy: **{}** (`{:.1}%` weekly res · conc `{}` · gap `{}s`)",
            all.len(),
            pol.preset.label(),
            pol.weekly_reserve_pct,
            pol.max_concurrency_per_account,
            pol.min_gap_secs,
        ),
    ];
    let mut rows: Vec<Vec<InlineKeyboardButton>> = Vec::new();
    if let Some((until_ts, ref reason)) = brk {
        let rem = (until_ts - now()).max(0) as u64;
        md.push(String::new());
        md.push(format!(
            "> 🛑 **Safety Breaker ACTIVE ({}):** {} — automatic rotation paused.",
            human_secs(rem),
            md_cell(reason)
        ));
        rows.push(vec![ctx.btn(
            "ok",
            "▶ Resume Pool (Reset Breaker)",
            Some("acct:brk_rst"),
            Some("success"),
            None,
        )]);
    }
    md.push(String::new());
    md.push("| # | Account | Status | Weekly / 5h | Proxy |".to_string());
    md.push("|---|---|---|---|---|".to_string());

    for (i, a) in all.iter().enumerate() {
        let dn = a.display_name();
        let name = if dn == a.id || dn.starts_with(&format!("{} ·", a.id)) {
            dn
        } else {
            format!("{dn} · {}", a.id)
        };
        md.push(format!(
            "| {} | {} | {} | {} | {} |",
            i + 1,
            md_cell(&name),
            md_cell(&status_cell(a, &pol)),
            md_cell(&usage_cell(a, &pol)),
            md_cell(&proxy_cell(ctx, a)),
        ));
        rows.push(vec![ctx.btn(
            "",
            &format!("{} {}", status_icon(a, &pol), name),
            Some(&format!("acct:v:{}", a.id)),
            None,
            None,
        )]);
    }
    let active_ids: Vec<String> = login_slots().iter().map(|e| e.key().clone()).collect();
    if !active_ids.is_empty() {
        md.push(String::new());
        md.push(format!("> 🔐 Sign-in in progress for `{}`", active_ids.join("`, `")));
    }
    rows.push(vec![
        ctx.btn("add", "Add Account", Some("acct:add"), Some("success"), None),
        ctx.btn("admin", "Safety Policy", Some("acct:pol"), Some("primary"), None),
    ]);
    rows.push(vec![
        ctx.btn("web", "Proxies", Some("px:list"), None, None),
        ctx.btn("status", "Runtime Limits", Some("limits"), None, None),
    ]);
    rows.push(vec![
        ctx.btn("refresh", "Refresh", Some("acct:list"), None, None),
        ctx.btn("back", "Menu", Some("home:2"), None, None),
    ]);
    card(ctx, cq, chat_id, &md.join("\n"), rows).await;
}

async fn show_detail(ctx: &Arc<BotCtx>, cq: Option<&CallbackQuery>, chat_id: i64, id: &str) {
    let Some(p) = pool(ctx) else { return };
    let Some(a) = p.get(id) else {
        show_list(ctx, cq, chat_id).await;
        return;
    };
    let pol = p.policy();
    let token = match agy_core::accounts::inspect_token(&a.token_path()) {
        TokenState::Present { .. } => "present (0600)",
        TokenState::Invalid => "unreadable",
        TokenState::Missing => "missing",
    };
    let until = match (a.health.status, a.health.until_ts) {
        (HealthStatus::Cooldown, Some(u)) if u > now() => human_secs((u - now()) as u64),
        _ => "—".to_string(),
    };
    let n = now();
    let mut u_snap = a.usage.clone();
    u_snap.roll_windows(n);
    let cap_str = match u_snap.effective_weekly_budget(&pol) {
        Some(b) => {
            let src = if u_snap.weekly_budget_override.is_some() {
                "custom"
            } else if u_snap.calibrated_weekly_budget.is_some() {
                "auto-cal"
            } else {
                "default"
            };
            format!("{} ({src})", format_tokens_compact(b))
        }
        None => "auto (set cap or auto-calibrates)".to_string(),
    };
    let weekly_str = match u_snap.weekly_used_pct_at(n, &pol) {
        Some(pct) => format!(
            "{} / {cap_str} (**{pct:.1}%**{})",
            format_tokens_compact(u_snap.tokens_week),
            if a.usage.is_weekly_reserved(n, &pol) {
                " · 🛡 reserved"
            } else {
                ""
            }
        ),
        None => format!("{} ({cap_str})", format_tokens_compact(u_snap.tokens_week)),
    };
    let five_h_str = format!(
        "{} ({} turns · never triggers reserve)",
        format_tokens_compact(u_snap.tokens_5h),
        u_snap.runs_5h
    );

    let mut md = vec![
        format!("### {} {}", ctx.premium.md("bolt"), md_cell(&a.display_name())),
        String::new(),
        "| Field | Value |".to_string(),
        "|---|---|".to_string(),
        format!("| ID | `{}`{} |", a.id, if a.is_primary() { " (server login)" } else { "" }),
        format!("| Status | {} |", md_cell(&status_cell(&a, &pol))),
        format!("| Sticky Proxy | {} |", md_cell(&proxy_cell(ctx, &a))),
        format!("| Weekly (7d) | {} |", weekly_str),
        format!("| Window (5h) | {} |", md_cell(&five_h_str)),
        format!("| Cooldown left | {until} |"),
        format!("| E-mail | {} |", md_cell(&a.masked_email().unwrap_or_else(|| "—".into()))),
        format!("| Token | {token} |"),
        format!("| Runs / failures | {} / {} (busy: {}) |", a.health.runs, a.health.failures, p.in_flight(&a.id)),
        {
            let ms = crate::models_pool::load(&ctx.cfg.state_dir, &a.id);
            let age = crate::models_pool::age_secs(&ctx.cfg.state_dir, &a.id)
                .map(|s| format!(" · updated {} ago", human_secs(s)))
                .unwrap_or_default();
            if ms.is_empty() {
                "| Models | not loaded yet |".to_string()
            } else {
                let names: Vec<String> = ms.iter().take(8).map(|m| m.name.clone()).collect();
                format!("| Models | {}{} — {} |", ms.len(), age, md_cell(&names.join(", ")))
            }
        },
        format!("| Last OK / Fail | {} / {} |", ago(a.health.last_ok_ts), ago(a.health.last_fail_ts)),
    ];
    if let (Some(c), Some(d)) = (a.health.class, a.health.detail.as_deref()) {
        md.push(String::new());
        md.push(format!("> **{}** — {}", c.label(), md_cell(&d.chars().take(240).collect::<String>())));
    }
    let tog = if a.enabled {
        ctx.btn("stop", "Pause", Some(&format!("acct:en:{}:0", a.id)), None, None)
    } else {
        ctx.btn("check", "Enable", Some(&format!("acct:en:{}:1", a.id)), Some("success"), None)
    };
    let mut cap_row = vec![
        ctx.btn("web", "Bind Proxy", Some(&format!("acct:px:{}", a.id)), Some("primary"), None),
        ctx.btn("status", "Weekly Cap", Some(&format!("acct:cap:{}", a.id)), None, None),
    ];
    if a.usage.calibrated_weekly_budget.is_some() {
        cap_row.push(ctx.btn("", "🧹 Clear Cal", Some(&format!("acct:clrcal:{}", a.id)), None, None));
    }
    let mut rows = vec![
        vec![
            tog,
            ctx.btn("refresh", "Reset Health", Some(&format!("acct:rst:{}", a.id)), None, None),
        ],
        cap_row,
    ];
    let mut r3 = vec![
        ctx.btn("refresh", "Models", Some(&format!("acct:mdl:{}", a.id)), None, None),
        ctx.btn("", "⬆ Move up", Some(&format!("acct:up:{}", a.id)), None, None),
    ];
    if !a.is_primary() {
        rows.push(vec![
            ctx.btn("account", "Sign in again", Some(&format!("acct:login:{}", a.id)), None, None),
            ctx.btn("", "✏️ Rename", Some(&format!("acct:ren:{}", a.id)), None, None),
        ]);
        r3.push(ctx.btn("remove", "Remove", Some(&format!("acct:rm:{}", a.id)), Some("danger"), None));
        rows.push(r3);
    } else {
        rows.push(r3);
        rows.push(vec![ctx.btn("", "✏️ Rename", Some(&format!("acct:ren:{}", a.id)), None, None)]);
    }
    rows.push(vec![
        ctx.btn("back", "Accounts", Some("acct:list"), None, None),
        ctx.btn("menu", "Menu", Some("home:2"), None, None),
    ]);
    card(ctx, cq, chat_id, &md.join("\n"), rows).await;
}

/// Show Account Safety Policy & 1% Weekly Reserve tuning screen (`acct:pol`).
pub async fn show_policy(ctx: &Arc<BotCtx>, cq: Option<&CallbackQuery>, chat_id: i64) {
    let Some(p) = pool(ctx) else { return };
    let pol = p.policy();
    let cap_str = if pol.default_weekly_token_budget > 0 {
        format_tokens_compact(pol.default_weekly_token_budget)
    } else {
        "auto".to_string()
    };
    let brk_str = if pol.pool_breaker_threshold == 0 {
        "off".to_string()
    } else {
        format!(
            "{} severe / {}m (pause {}m)",
            pol.pool_breaker_threshold,
            pol.pool_breaker_window_secs / 60,
            pol.pool_breaker_cooldown_secs / 60
        )
    };
    let md = format!(
        "### {} Account Safety Policy\n\
        > Obsessive anti-ban controls. The weekly reserve parks accounts strictly on **7-day weekly usage** — **5-hour usage never triggers it**.\n\n\
        | Setting | Value |\n\
        |---|---|\n\
        | Preset | **{}** |\n\
        | Weekly Reserve | **{:.1}%** (parks at {:.1}% 7d) |\n\
        | Default Weekly Cap | `{cap_str}` |\n\
        | Soft Throttle / Fresher | `{:.0}%` / `{:.0}%` 7d |\n\
        | Concurrency / Account | `{}` |\n\
        | Min Gap + Jitter | `{}s` (scaled at {:.0}%/{:.0}% 7d) |\n\
        | Soft Switch Delay | `{}s` |\n\
        | Max Failover Attempts | `{}` |\n\
        | Safety Breaker | `{brk_str}` |",
        ctx.premium.md("admin"),
        pol.preset.label(),
        pol.weekly_reserve_pct,
        (100.0 - pol.weekly_reserve_pct).max(0.0),
        pol.soft_throttle_start_pct,
        pol.prefer_fresher_pct,
        pol.max_concurrency_per_account,
        pol.min_gap_secs,
        pol.soft_throttle_start_pct,
        pol.prefer_fresher_pct,
        pol.switch_delay_secs,
        pol.max_failover_attempts,
    );
    let brk_btn = if pol.pool_breaker_threshold == 0 {
        "Breaker: off".to_string()
    } else {
        format!("Breaker: {}/{}m", pol.pool_breaker_threshold, pol.pool_breaker_window_secs / 60)
    };
    let rows = vec![
        vec![
            ctx.btn(
                "admin",
                if pol.preset == AccountPolicyPreset::StrictSafe {
                    "● Strict Safe"
                } else {
                    "Strict Safe"
                },
                Some("acct:pol_preset:strict"),
                if pol.preset == AccountPolicyPreset::StrictSafe { Some("primary") } else { None },
                None,
            ),
            ctx.btn(
                "",
                if pol.preset == AccountPolicyPreset::Balanced {
                    "● ⚖️ Balanced"
                } else {
                    "⚖️ Balanced"
                },
                Some("acct:pol_preset:balanced"),
                if pol.preset == AccountPolicyPreset::Balanced { Some("primary") } else { None },
                None,
            ),
        ],
        vec![
            ctx.btn("", &format!("🛡 Reserve: {:.1}%", pol.weekly_reserve_pct), Some("acct:pol_res"), None, None),
            ctx.btn("", &format!("📊 Cap: {cap_str}"), Some("acct:pol_cap"), None, None),
        ],
        vec![
            ctx.btn("", &format!("⚡ Conc: {}/acct", pol.max_concurrency_per_account), Some("acct:pol_conc"), None, None),
            ctx.btn("", &format!("⏱ Gap: {}s", pol.min_gap_secs), Some("acct:pol_gap"), None, None),
        ],
        vec![
            ctx.btn("", &format!("🔁 Switch: {}s", pol.switch_delay_secs), Some("acct:pol_sw"), None, None),
            ctx.btn("", &format!("🔄 Retries: {}", pol.max_failover_attempts), Some("acct:pol_att"), None, None),
        ],
        vec![
            ctx.btn("", &brk_btn, Some("acct:pol_brk"), None, None),
            ctx.btn("", &format!("⏳ Pause: {}m", pol.pool_breaker_cooldown_secs / 60), Some("acct:pol_bkcd"), None, None),
        ],
        vec![
            ctx.btn("", &format!("🎚 Throttle: {:.0}%/{:.0}%", pol.soft_throttle_start_pct, pol.prefer_fresher_pct), Some("acct:pol_thr"), None, None),
            ctx.btn("status", "Runtime Limits ›", Some("limits"), Some("primary"), None),
        ],
        vec![
            ctx.btn("back", "Accounts", Some("acct:list"), None, None),
            ctx.btn("menu", "Menu", Some("home:2"), None, None),
        ],
    ];
    card(ctx, cq, chat_id, &md, rows).await;
}

/// Show 1:1 sticky proxy picker for a specific Antigravity account (`acct:px:<acct_id>`).
async fn show_account_proxy_picker(
    ctx: &Arc<BotCtx>,
    cq: Option<&CallbackQuery>,
    chat_id: i64,
    acct_id: &str,
) {
    let Some(p) = pool(ctx) else { return };
    let Some(a) = p.get(acct_id) else {
        show_list(ctx, cq, chat_id).await;
        return;
    };
    let all_accts = p.list();
    let proxies = ctx.proxies.list();
    let cur = a.proxy_id.as_deref();
    let mut md = vec![
        format!("### 🌐 Sticky Proxy for `{}`", a.id),
        "> Recommended: bind **1 dedicated residential/ISP proxy per account** (1:1 sticky isolation).".to_string(),
        String::new(),
        format!("Current: **{}**", md_cell(&proxy_cell(ctx, &a))),
    ];
    let mut rows: Vec<Vec<InlineKeyboardButton>> = vec![vec![ctx.btn(
        "",
        if cur.is_none() {
            "✅ Direct (no proxy)"
        } else {
            "Direct (no proxy)"
        },
        Some(&format!("acct:pxs:{}:direct", a.id)),
        None,
        None,
    )]];

    for px in &proxies {
        let selected = cur == Some(px.id.as_str());
        let others: Vec<String> = all_accts
            .iter()
            .filter(|o| o.id != a.id && o.proxy_id.as_deref() == Some(px.id.as_str()))
            .map(|o| o.id.clone())
            .collect();
        let shared = if others.is_empty() {
            String::new()
        } else {
            format!(" ⚠ {}", others.join(","))
        };
        let mark = if selected { "✅ " } else { "" };
        rows.push(vec![ctx.btn(
            "",
            &format!("{mark}{} ({}){shared}", px.display_name(), px.health.quality_score),
            Some(&format!("acct:pxs:{}:{}", a.id, px.id)),
            if selected { Some("primary") } else { None },
            None,
        )]);
    }
    if proxies.is_empty() {
        md.push(String::new());
        md.push("_No proxies added yet. Add one in `/proxies` first._".to_string());
    }
    rows.push(vec![
        ctx.btn("new", "➕ Manage Proxies", Some("px:list"), None, None),
        ctx.btn("", &format!("‹ {}", a.id), Some(&format!("acct:v:{}", a.id)), None, None),
    ]);
    card(ctx, cq, chat_id, &md.join("\n"), rows).await;
}

/// Start (or restart) the relayed OAuth sign-in for account `id`.
async fn start_login(ctx: &Arc<BotCtx>, uid: i64, chat_id: i64, id: &str) {
    let Some(p) = pool(ctx) else { return };
    let Some(a) = p.get(id) else { return };
    if a.is_primary() {
        return;
    }
    if p.in_flight(&a.id) > 0 {
        let _ = ctx
            .render
            .send_html_simple(chat_id, &format!("⏳ <code>{}</code> is running a task right now. Sign in again when it is idle (or pause it first).", a.id), None)
            .await;
        return;
    }
    if let Some((_, holder_uid)) = current_login_for(&a.id) {
        if holder_uid != uid {
            let _ = ctx
                .render
                .send_html_simple(
                    chat_id,
                    &format!(
                        "⏳ Another owner is currently signing in to <code>{}</code>. Wait for them to finish (or sign in to a different slot).",
                        a.id
                    ),
                    None,
                )
                .await;
            return;
        }
        if let Some(old) = take_login_for(&a.id) {
            abandon_login(ctx, &old.session).await;
        }
    }
    let proxy_url = match ctx.proxies.resolve(a.proxy_id.as_deref()) {
        ResolvedProxy::Use { url, .. } => Some(url),
        ResolvedProxy::Direct | ResolvedProxy::DirectFallback { .. } => None,
        ResolvedProxy::Blocked { reason, .. } => {
            let _ = ctx
                .render
                .send_html_simple(
                    chat_id,
                    &format!(
                        "{} <b>Sign-in blocked (fail-closed proxy):</b> <code>{}</code>\n<i>Check /proxies or change this account's proxy first.</i>",
                        ctx.e("err"),
                        agy_render::esc(&reason)
                    ),
                    None,
                )
                .await;
            return;
        }
    };
    if let Err(e) = p.prepare_home(&a) {
        let _ = ctx
            .render
            .send_html_simple(chat_id, &format!("{} Could not prepare account home: <code>{}</code>", ctx.e("err"), agy_render::esc(&e.to_string())), None)
            .await;
        return;
    }
    // a fresh sign-in must not reuse a stale/revoked token
    let tok = a.token_path();
    if tok.exists() {
        let bak = tok.with_extension("prev");
        let _ = std::fs::rename(&tok, &bak);
    }
    let wait = ctx
        .render
        .send_html_simple(chat_id, &format!("🔐 <b>Starting sign-in</b> for <code>{}</code>…", a.id), None)
        .await
        .ok()
        .flatten();
    let bin = ctx.cfg.agy_bin.to_string_lossy().into_owned();
    let sess = match LoginSession::spawn_with_proxy(&bin, &a.home, &a.id, proxy_url.as_deref()) {
        Ok(s) => s,
        Err(e) => {
            restore_prev_token(&tok);
            reenable_after_restore(&p, &a.id);
            let _ = ctx
                .render
                .send_html_simple(chat_id, &format!("{} Sign-in could not start: <code>{}</code>", ctx.e("err"), agy_render::esc(&e.to_string())), None)
                .await;
            return;
        }
    };
    login_slots().insert(
        a.id.clone(),
        ActiveLogin {
            session: Arc::clone(&sess),
            initiator_uid: uid,
        },
    );
    let url = match sess.wait_for_url(Duration::from_secs(45)).await {
        Ok(u) => u,
        Err(e) => {
            sess.stop().await;
            let _ = take_login_if_same(&a.id, &sess);
            restore_prev_token(&tok);
            reenable_after_restore(&p, &a.id);
            let _ = ctx
                .render
                .send_html_simple(chat_id, &format!("{} <b>Sign-in failed to start</b>\n<blockquote expandable>{}</blockquote>", ctx.e("err"), agy_render::esc(&e.to_string())), None)
                .await;
            return;
        }
    };
    if let Some(m) = wait {
        let _ = ctx.client.delete_message(chat_id, m.message_id).await;
    }
    ctx.jobs
        .set_awaiting(uid, AwaitingInput::new("acct_code", json!({ "id": a.id })));
    let html = format!(
        "🔐 <b>Sign in account</b> <code>{}</code>\n\n\
         1. Tap <b>Open Google sign-in</b> and choose the Google account to add.\n\
         2. Google shows an <b>authorization code</b> — copy it.\n\
         3. Send the code here as a normal message (it is deleted from the chat right away).\n\n\
         <i>The link is single-use and expires in ~10 minutes.</i>",
        a.id
    );
    let mk = BotCtx::kb(vec![
        vec![ctx.btn("", "🌐 Open Google sign-in", None, None, Some(&url))],
        vec![ctx.btn("stop", "Cancel", Some(&format!("acct:lc:{}", a.id)), Some("danger"), None)],
    ]);
    let _ = ctx.render.send_html(chat_id, &html, Some(mk), None, None, false).await;

    // auto-expire the session after 10 minutes: put the previous token back and stop
    // waiting for a code
    let sess_w = Arc::downgrade(&sess);
    let ctx_w = Arc::clone(ctx);
    let acct_id_w = a.id.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(600)).await;
        if let Some(s) = sess_w.upgrade() {
            if let Some(old) = take_login_if_same(&acct_id_w, &s) {
                abandon_login(&ctx_w, &old.session).await;
                if ctx_w.jobs.peek_awaiting(uid).is_some_and(|i| i.kind == "acct_code") {
                    ctx_w.jobs.clear_awaiting(uid);
                }
                let _ = ctx_w
                    .render
                    .send_html_simple(chat_id, &format!("⌛ <i>Sign-in for <code>{}</code> expired; the previous sign-in (if any) was kept.</i>", s.account_id), None)
                    .await;
            }
        }
    });
}

fn restore_prev_token(tok: &std::path::Path) -> bool {
    let bak = tok.with_extension("prev");
    if !tok.exists() && bak.exists() {
        return std::fs::rename(&bak, tok).is_ok();
    }
    false
}

/// Stop an unfinished sign-in: restore the previous token and, if the account was only
/// disabled because the token was missing during the sign-in, make it usable again.
async fn abandon_login(ctx: &Arc<BotCtx>, s: &Arc<LoginSession>) {
    s.stop().await;
    let Some(p) = pool(ctx) else { return };
    let Some(a) = p.get(&s.account_id) else { return };
    restore_prev_token(&a.token_path());
    reenable_after_restore(&p, &a.id);
}

fn reenable_after_restore(p: &Arc<agy_core::accounts::AccountStore>, id: &str) {
    let Some(a) = p.get(id) else { return };
    let token_ok = matches!(agy_core::accounts::inspect_token(&a.token_path()), TokenState::Present { .. });
    let missing_only = a.health.status == HealthStatus::Disabled
        && a.health.detail.as_deref().is_some_and(|d| d.contains("sign-in token missing"));
    if token_ok && missing_only {
        let _ = p.reset_health(id);
        info!(account = %id, "previous token restored; account usable again");
    }
}

/// Handle the pasted OAuth code (`acct_code` awaiting input). Returns `true` if consumed.
pub async fn handle_accounts_awaiting_text(
    ctx: &Arc<BotCtx>,
    msg: &Message,
    uid: i64,
    chat_id: i64,
    inp: &AwaitingInput,
    text: &str,
) -> bool {
    match inp.kind.as_str() {
        "acct_code" => {}
        "acct_label" => {
            if !ctx.is_owner(uid) {
                return true;
            }
            let id = inp.data.get("id").and_then(|v| v.as_str()).unwrap_or("");
            if let Some(p) = pool(ctx) {
                let _ = p.rename(id, text);
            }
            show_detail(ctx, None, chat_id, id).await;
            return true;
        }
        "acct_wcap" => {
            if !ctx.is_owner(uid) {
                return true;
            }
            let target = inp.data.get("id").and_then(|v| v.as_str()).unwrap_or("");
            let Some(parsed) = parse_token_budget(text) else {
                ctx.jobs.set_awaiting(
                    uid,
                    AwaitingInput::new("acct_wcap", json!({ "id": target })),
                );
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
                        "⚠️ Send a token budget like <code>20M</code>, <code>500k</code>, or <code>auto</code> (or /cancel).",
                        Some(mk),
                    )
                    .await;
                return true;
            };
            if let Some(p) = pool(ctx) {
                if target == "__default__" {
                    let mut pol = p.policy();
                    pol.default_weekly_token_budget = parsed.unwrap_or(0);
                    let _ = p.set_policy(pol);
                    show_policy(ctx, None, chat_id).await;
                } else {
                    let _ = p.set_weekly_budget(target, parsed);
                    show_detail(ctx, None, chat_id, target).await;
                }
            }
            return true;
        }
        _ => return false,
    }
    if !ctx.is_owner(uid) {
        return true;
    }
    let id = inp.data.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let t = text.trim();
    // Something that is clearly a normal message (spaces / short) is not a code: hand it
    // back to the normal flow instead of swallowing it.
    let code_like = !t.is_empty() && !t.contains(char::is_whitespace) && t.len() >= 20;
    let Some((sess, _)) = current_login_for(&id) else {
        if code_like {
            let _ = ctx.client.delete_message(chat_id, msg.message_id).await;
            let _ = ctx
                .render
                .send_html_simple(chat_id, "⌛ <i>That sign-in session has expired. Start it again from /accounts.</i>", None)
                .await;
            return true;
        }
        return false;
    };
    if !agy_ext::login::valid_auth_code(text) {
        ctx.jobs
            .set_awaiting(uid, AwaitingInput::new("acct_code", json!({ "id": id })));
        if !code_like {
            return false;
        }
        // never leave a code-like secret in the chat history
        let _ = ctx.client.delete_message(chat_id, msg.message_id).await;
        let _ = ctx
            .render
            .send_html_simple(chat_id, "⚠️ <i>That does not look like an authorization code. Paste the code exactly as Google shows it.</i>", None)
            .await;
        return true;
    }
    // never leave the code in the chat history
    let _ = ctx.client.delete_message(chat_id, msg.message_id).await;
    let Some(p) = pool(ctx) else { return true };
    let Some(acc) = p.get(&id) else { return true };
    let tok = acc.token_path();
    let progress = ctx
        .render
        .send_html_simple(chat_id, "⏳ <i>Verifying sign-in…</i>", None)
        .await
        .ok()
        .flatten();
    if let Err(e) = sess.submit_code(text).await {
        warn!(error = %e, "submit code failed");
    }
    let mut ok = false;
    for i in 0..90 {
        if matches!(agy_core::accounts::inspect_token(&tok), TokenState::Present { .. }) {
            ok = true;
            break;
        }
        if i >= 2 && sess.is_exited().await {
            if matches!(agy_core::accounts::inspect_token(&tok), TokenState::Present { .. }) {
                ok = true;
            }
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    let tail = sess.tail(500);
    let _ = take_login_if_same(&id, &sess);
    sess.stop().await;
    if let Some(m) = progress {
        let _ = ctx.client.delete_message(chat_id, m.message_id).await;
    }
    if ok {
        let _ = std::fs::remove_file(tok.with_extension("prev"));
        let st = p.finish_login(&id);
        let email = p.get(&id).and_then(|a| a.masked_email()).unwrap_or_else(|| "—".into());
        let html = match st {
            Ok(TokenState::Present { .. }) => format!(
                "{} <b>Account <code>{}</code> signed in</b> · {}\n<i>It is now part of the pool and will be used for failover and load sharing.</i>",
                ctx.e("ok"),
                id,
                agy_render::esc(&email)
            ),
            _ => format!("{} <b>Token saved but could not be verified.</b>", ctx.e("warn")),
        };
        let _ = ctx.render.send_html_simple(chat_id, &html, None).await;
        let dups = p.duplicates_of(&id);
        if !dups.is_empty() {
            let _ = ctx
                .render
                .send_html_simple(
                    chat_id,
                    &format!(
                        "⚠️ <b>Same Google account twice</b>\n<code>{}</code> is signed in with the same e-mail as <code>{}</code>. They share one quota, so failover between them does not help. Nothing was removed — remove one from /accounts if you want.",
                        id,
                        agy_render::esc(&dups.join(", "))
                    ),
                    None,
                )
                .await;
        }
        // load the new account's own model list right away (list-only, no quota)
        if let Some(a) = p.get(&id) {
            let px = match ctx.proxies.resolve(a.proxy_id.as_deref()) {
                ResolvedProxy::Use { url, .. } => Some(url),
                _ => None,
            };
            let n = crate::models_pool::refresh_with_proxy(&ctx.cfg, &a, px.as_deref())
                .await
                .len();
            info!(account = %id, models = n, "models loaded after sign-in");
        }
        show_detail(ctx, None, chat_id, &id).await;
    } else {
        restore_prev_token(&tok);
        reenable_after_restore(&p, &id);
        let html = format!(
            "{} <b>Sign-in did not complete</b> for <code>{}</code>.\n<blockquote expandable>{}</blockquote>\n<i>Start again with “Sign in again”. Codes are single-use.</i>",
            ctx.e("err"),
            id,
            agy_render::esc(&tail)
        );
        let _ = ctx.render.send_html_simple(chat_id, &html, None).await;
    }
    true
}

/// Route `acct:*` callbacks. Returns `true` if handled.
pub async fn handle_acct_cb(
    ctx: &Arc<BotCtx>,
    cq: &CallbackQuery,
    uid: i64,
    chat_id: i64,
    data: &str,
) -> bool {
    let Some(rest) = data.strip_prefix("acct:") else {
        return false;
    };
    if !ctx.is_owner(uid) {
        ctx.ack(&cq.id, Some("Owner only"), true).await;
        return true;
    }
    let Some(p) = pool(ctx) else {
        ctx.ack(&cq.id, Some("Account pool unavailable"), true).await;
        return true;
    };
    let mut parts = rest.splitn(3, ':');
    let action = parts.next().unwrap_or("");
    let id = parts.next().unwrap_or("").to_string();
    let arg = parts.next().unwrap_or("");
    match action {
        "list" => {
            ctx.ack(&cq.id, None, false).await;
            show_list(ctx, Some(cq), chat_id).await;
        }
        "v" => {
            ctx.ack(&cq.id, None, false).await;
            show_detail(ctx, Some(cq), chat_id, &id).await;
        }
        "add" => {
            match p.add_slot("") {
                Ok(a) => {
                    ctx.ack(&cq.id, Some("Slot created — starting sign-in"), false).await;
                    start_login(ctx, uid, chat_id, &a.id).await;
                }
                Err(e) => ctx.ack(&cq.id, Some(&e.to_string()), true).await,
            }
        }
        "login" => {
            ctx.ack(&cq.id, None, false).await;
            start_login(ctx, uid, chat_id, &id).await;
        }
        "lc" => {
            // only cancel the sign-in this button belongs to
            if let Some(old) = take_login_for(&id) {
                abandon_login(ctx, &old.session).await;
                ctx.jobs.clear_awaiting(old.initiator_uid);
                ctx.jobs.clear_awaiting(uid);
            } else {
                ctx.ack(&cq.id, Some("That sign-in is no longer active"), false).await;
                return true;
            }
            ctx.ack(&cq.id, Some("Sign-in cancelled"), false).await;
            if let Some(m) = cq.message.as_ref() {
                let _ = ctx.render.edit_html(chat_id, m.message_id, "✖️ <i>Sign-in cancelled.</i>", None).await;
            }
        }
        "en" => {
            let on = arg == "1";
            if on {
                // enabling also clears a stale disabled state if a token exists
                let _ = p.set_enabled(&id, true);
                if p.get(&id).is_some_and(|a| a.health.status == HealthStatus::Disabled) {
                    let _ = p.reset_health(&id);
                }
            } else {
                let _ = p.set_enabled(&id, false);
            }
            ctx.ack(&cq.id, Some(if on { "Enabled" } else { "Paused" }), false).await;
            show_detail(ctx, Some(cq), chat_id, &id).await;
        }
        "mdl" => {
            ctx.ack(&cq.id, Some("Loading this account's models (list only, no quota)…"), false).await;
            if let Some(a) = p.get(&id) {
                match ctx.proxies.resolve(a.proxy_id.as_deref()) {
                    ResolvedProxy::Blocked { reason, .. } => {
                        let _ = ctx
                            .render
                            .send_html_simple(
                                chat_id,
                                &format!(
                                    "⚠️ <b>Models refresh skipped (fail-closed proxy):</b> <code>{}</code>",
                                    agy_render::esc(&reason)
                                ),
                                None,
                            )
                            .await;
                    }
                    other => {
                        let px = match other {
                            ResolvedProxy::Use { url, .. } => Some(url),
                            _ => None,
                        };
                        let ms = crate::models_pool::refresh_with_proxy(&ctx.cfg, &a, px.as_deref()).await;
                        if a.is_primary() && !ms.is_empty() {
                            ctx.set_models_cache(ms);
                        }
                    }
                }
            }
            show_detail(ctx, Some(cq), chat_id, &id).await;
        }
        "pol" => {
            ctx.ack(&cq.id, None, false).await;
            show_policy(ctx, Some(cq), chat_id).await;
        }
        "pol_preset" => {
            let mut pol = match id.as_str() {
                "balanced" => AccountPolicy::balanced(),
                _ => AccountPolicy::strict_safe(),
            };
            pol.default_weekly_token_budget = p.policy().default_weekly_token_budget;
            let _ = p.set_policy(pol);
            ctx.ack(&cq.id, Some("Policy preset applied"), false).await;
            show_policy(ctx, Some(cq), chat_id).await;
        }
        "pol_res" => {
            let mut pol = p.policy();
            pol.weekly_reserve_pct = if (pol.weekly_reserve_pct - 1.0).abs() < 0.05 {
                2.0
            } else if (pol.weekly_reserve_pct - 2.0).abs() < 0.05 {
                3.0
            } else if (pol.weekly_reserve_pct - 3.0).abs() < 0.05 {
                5.0
            } else if (pol.weekly_reserve_pct - 5.0).abs() < 0.05 {
                10.0
            } else {
                1.0
            };
            let _ = p.set_policy(pol.clone());
            ctx.ack(&cq.id, Some(&format!("Weekly reserve: {:.1}% (active)", pol.weekly_reserve_pct)), false).await;
            show_policy(ctx, Some(cq), chat_id).await;
        }
        "pol_conc" => {
            let mut pol = p.policy();
            pol.max_concurrency_per_account = match pol.max_concurrency_per_account {
                0 | 1 => 2,
                2 => 3,
                _ => 1,
            };
            let _ = p.set_policy(pol.clone());
            ctx.ack(&cq.id, Some(&format!("Max concurrency: {}/acct", pol.max_concurrency_per_account)), false).await;
            show_policy(ctx, Some(cq), chat_id).await;
        }
        "pol_gap" => {
            let mut pol = p.policy();
            pol.min_gap_secs = match pol.min_gap_secs {
                0 => 3,
                1..=4 => 8,
                5..=8 => 15,
                9..=15 => 30,
                _ => 0,
            };
            let _ = p.set_policy(pol.clone());
            ctx.ack(&cq.id, Some(&format!("Min gap: {}s", pol.min_gap_secs)), false).await;
            show_policy(ctx, Some(cq), chat_id).await;
        }
        "pol_sw" => {
            let mut pol = p.policy();
            pol.switch_delay_secs = match pol.switch_delay_secs {
                0 => 1,
                1 => 3,
                2..=3 => 5,
                4..=5 => 10,
                _ => 0,
            };
            let _ = p.set_policy(pol.clone());
            ctx.ack(&cq.id, Some(&format!("Switch delay: {}s", pol.switch_delay_secs)), false).await;
            show_policy(ctx, Some(cq), chat_id).await;
        }
        "pol_att" => {
            let mut pol = p.policy();
            pol.max_failover_attempts = match pol.max_failover_attempts {
                0..=2 => 4,
                3..=4 => 6,
                5..=6 => 8,
                _ => 2,
            };
            let _ = p.set_policy(pol.clone());
            ctx.ack(&cq.id, Some(&format!("Max failovers: {}", pol.max_failover_attempts)), false).await;
            show_policy(ctx, Some(cq), chat_id).await;
        }
        "pol_brk" => {
            let mut pol = p.policy();
            pol.pool_breaker_threshold = match pol.pool_breaker_threshold {
                0..=2 => 3,
                3 => 4,
                _ => 2,
            };
            let _ = p.set_policy(pol.clone());
            ctx.ack(
                &cq.id,
                Some(&format!("Safety Breaker: {} severe / {}m", pol.pool_breaker_threshold, pol.pool_breaker_window_secs / 60)),
                false,
            )
            .await;
            show_policy(ctx, Some(cq), chat_id).await;
        }
        "pol_thr" => {
            let mut pol = p.policy();
            let cur = pol.soft_throttle_start_pct.round() as u32;
            let (s, f) = match cur {
                0..=68 => (75.0, 90.0),
                69..=78 => (80.0, 92.0),
                _ => (65.0, 85.0),
            };
            pol.soft_throttle_start_pct = s;
            pol.prefer_fresher_pct = f;
            let _ = p.set_policy(pol.clone());
            ctx.ack(&cq.id, Some(&format!("Throttle/Fresher: {s:.0}%/{f:.0}%")), false).await;
            show_policy(ctx, Some(cq), chat_id).await;
        }
        "pol_bkcd" => {
            let mut pol = p.policy();
            let mins = pol.pool_breaker_cooldown_secs / 60;
            pol.pool_breaker_cooldown_secs = match mins {
                0..=20 => 30 * 60,
                21..=45 => 60 * 60,
                46..=90 => 120 * 60,
                _ => 15 * 60,
            };
            let _ = p.set_policy(pol.clone());
            ctx.ack(&cq.id, Some(&format!("Breaker pause: {}m", pol.pool_breaker_cooldown_secs / 60)), false).await;
            show_policy(ctx, Some(cq), chat_id).await;
        }
        "pol_cap" => {
            ctx.ack(&cq.id, None, false).await;
            ctx.jobs.set_awaiting(
                uid,
                AwaitingInput::new("acct_wcap", json!({ "id": "__default__" })),
            );
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
                    "📊 Send the <b>default 7-day weekly token cap</b> for all accounts (e.g. <code>20M</code>, <code>5M</code>, or <code>auto</code>).",
                    Some(mk),
                )
                .await;
        }
        "brk_rst" => {
            let _ = p.reset_breaker();
            ctx.ack(&cq.id, Some("Pool Safety Breaker reset — pool resumed"), false).await;
            show_list(ctx, Some(cq), chat_id).await;
        }
        "px" => {
            ctx.ack(&cq.id, None, false).await;
            show_account_proxy_picker(ctx, Some(cq), chat_id, &id).await;
        }
        "pxs" => {
            let px_opt = if arg == "direct" || arg.is_empty() {
                None
            } else {
                Some(arg)
            };
            match p.set_account_proxy(&id, px_opt) {
                Ok(()) => ctx.ack(&cq.id, Some("Sticky proxy updated"), false).await,
                Err(e) => ctx.ack(&cq.id, Some(&e.to_string()), true).await,
            }
            show_detail(ctx, Some(cq), chat_id, &id).await;
        }
        "cap" => {
            ctx.ack(&cq.id, None, false).await;
            ctx.jobs
                .set_awaiting(uid, AwaitingInput::new("acct_wcap", json!({ "id": id })));
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
                        "📊 Send a <b>7-day weekly token cap</b> for <code>{}</code> (e.g. <code>20M</code>, <code>500k</code>, or <code>auto</code>).\n<i>Account parks automatically at {:.1}% to hold {:.1}% weekly reserve.</i>",
                        agy_render::esc(&id),
                        (100.0 - p.policy().weekly_reserve_pct).max(0.0),
                        p.policy().weekly_reserve_pct,
                    ),
                    Some(mk),
                )
                .await;
        }
        "rst" => {
            let _ = p.reset_health(&id);
            ctx.ack(&cq.id, Some("Health reset"), false).await;
            show_detail(ctx, Some(cq), chat_id, &id).await;
        }
        "clrcal" => {
            let _ = p.clear_calibrated_budget(&id);
            ctx.ack(&cq.id, Some("Auto-calibrated weekly cap cleared"), false).await;
            show_detail(ctx, Some(cq), chat_id, &id).await;
        }
        "up" => {
            let _ = p.move_up(&id);
            ctx.ack(&cq.id, Some("Moved up"), false).await;
            show_list(ctx, Some(cq), chat_id).await;
        }
        "ren" => {
            ctx.ack(&cq.id, None, false).await;
            ctx.jobs
                .set_awaiting(uid, AwaitingInput::new("acct_label", json!({ "id": id })));
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
                    &format!("✏️ Send a new label for <code>{}</code> (max 32 chars).", agy_render::esc(&id)),
                    Some(mk),
                )
                .await;
        }
        "rm" => {
            ctx.ack(&cq.id, None, false).await;
            let md = format!(
                "### 🗑 Remove `{id}`?\n\n> Its private sign-in token and caches are deleted. Shared conversations, skills and MCP config are **not** touched."
            );
            let rows = vec![vec![
                ctx.btn("", "Yes, remove", Some(&format!("acct:rmy:{id}")), Some("danger"), None),
                ctx.btn("", "Cancel", Some(&format!("acct:v:{id}")), None, None),
            ]];
            card(ctx, Some(cq), chat_id, &md, rows).await;
        }
        "rmy" => {
            if p.in_flight(&id) > 0 {
                ctx.ack(&cq.id, Some("This account is running a task; try again when it is idle"), true).await;
                return true;
            }
            if let Some(old) = take_login_for(&id) {
                old.session.stop().await;
            }
            match p.remove(&id) {
                Ok(()) => ctx.ack(&cq.id, Some("Removed"), false).await,
                Err(e) => ctx.ack(&cq.id, Some(&e.to_string()), true).await,
            }
            show_list(ctx, Some(cq), chat_id).await;
        }
        _ => ctx.ack(&cq.id, None, false).await,
    }
    true
}
