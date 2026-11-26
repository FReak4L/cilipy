//! `/updates` — Zero-AI modular fleet updater: check, apply, seal, rollback, history.

use std::sync::Arc;

use agy_core::tg::{CallbackQuery, InlineKeyboardMarkup, Message};
use agy_ext::fleet_updater::{self, UpdateScope};
use agy_render::esc;

use crate::ctx::BotCtx;
use crate::i18n::{missing_perm_html, owner_only_html, t, Tx};

const MAX_REPLY_CHARS: usize = 3200;

const USAGE: &str = "/updates status               seal, policy & last run
/updates check [scope]        dry-run math & version check (hub|skills|mcps|all)
/updates apply [scope]        transactional update (hub|skills|mcps|all)
/updates seal [refresh]       verify (or re-capture) SHA-256 protected seal
/updates rollback [tx_id]     restore latest (or named) skill snapshot
/updates history              last 10 update transactions";

fn clip(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max).collect();
        out.push_str("\n… [truncated]");
        out
    }
}

fn updates_kb(ctx: &BotCtx, uid: i64) -> InlineKeyboardMarkup {
    let lang = ctx.lang(uid);
    BotCtx::kb(vec![
        vec![
            ctx.btn("", "🔍 Check All", Some("upd:check"), Some("primary"), None),
            ctx.btn("", "🛡 Verify Seal", Some("upd:seal"), None, None),
        ],
        vec![
            ctx.btn("", "⬆️ Apply Skills", Some("upd:apply_skills"), None, None),
            ctx.btn("", "📜 History", Some("upd:history"), None, None),
        ],
        vec![
            ctx.btn("refresh", t(lang, Tx::BtnRefresh), Some("upd:status"), None, None),
            ctx.btn("back", t(lang, Tx::BtnMenu), Some("home:2"), None, None),
        ],
    ])
}

async fn send(ctx: &Arc<BotCtx>, cq: Option<&CallbackQuery>, chat: i64, uid: i64, title: &str, body: &str) {
    let mk = Some(updates_kb(ctx, uid));
    let html = format!("<b>{}</b>\n<pre>{}</pre>", esc(title), esc(&clip(body, MAX_REPLY_CHARS)));
    if let Some(c) = cq {
        ctx.edit_or_send(Some(c), chat, &html, mk).await;
        return;
    }
    if let Err(e) = ctx.render.send_html_simple(chat, &html, mk.clone()).await {
        tracing::warn!(error = %e, "updates reply failed; retrying shorter");
        let short = format!("<b>{}</b>\n<pre>{}</pre>", esc(title), esc(&clip(body, 1200)));
        let _ = ctx.render.send_html_simple(chat, &short, mk).await;
    }
}

fn status_body(sd: &std::path::Path) -> String {
    let m = fleet_updater::load_manifest(sd);
    let seal = fleet_updater::verify_seal(sd);
    let hist = fleet_updater::load_history(sd, 1);
    let seal_line = match seal {
        Ok(s) => format!(
            "Seal: {} ({} protected files, {} drifted, {} missing)",
            if s.ok { "OK" } else { "DRIFT" },
            s.checked,
            s.drifted.len(),
            s.missing.len()
        ),
        Err(e) => format!("Seal error: {e}"),
    };
    let last_line = hist
        .first()
        .map(|h| {
            format!(
                "Last run: {} [{}] scope={} seal_ok={} skills_upd={} mcps_upd={}",
                h.action,
                h.tx_id.as_deref().unwrap_or("-"),
                h.scope,
                h.seal_ok,
                h.skills_updated,
                h.mcps_updated
            )
        })
        .unwrap_or_else(|| "Last run: none".into());
    format!(
        "{seal_line}\nPolicy: auto_apply_skills={} · auto_apply_mcps={} · min_prov_sim={:.2}\nSkill roots: {} · Managed MCPs: {}\n{last_line}\n\n{USAGE}",
        m.auto_apply_skills,
        m.auto_apply_mcps,
        m.min_provenance_cosine,
        m.skill_roots.len(),
        m.mcps.len(),
    )
}

fn seal_verify_body(sd: &std::path::Path) -> String {
    match fleet_updater::verify_seal(sd) {
        Ok(s) => {
            let mut txt = format!(
                "Seal: {} ({} checked, {} drifted, {} missing)\n",
                if s.ok { "OK" } else { "DRIFT" },
                s.checked,
                s.drifted.len(),
                s.missing.len()
            );
            for d in &s.drifted {
                txt.push_str(&format!("- DRIFT: {}\n", d.path));
            }
            for m in &s.missing {
                txt.push_str(&format!("- MISSING: {m}\n"));
            }
            txt
        }
        Err(e) => format!("seal verify failed: {e}"),
    }
}

fn history_body(sd: &std::path::Path) -> String {
    let hist = fleet_updater::load_history(sd, 10);
    if hist.is_empty() {
        "No update transactions recorded yet.".to_string()
    } else {
        hist.into_iter()
            .map(|h| {
                format!(
                    "- {} {} [{}] scope={} seal_ok={} sk_upd={} sk_blk={} mcp_upd={}",
                    h.timestamp,
                    h.action,
                    h.tx_id.as_deref().unwrap_or("-"),
                    h.scope,
                    h.seal_ok,
                    h.skills_updated,
                    h.skills_blocked,
                    h.mcps_updated
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}

/// Handle `upd:*` interactive callbacks (owner/root_access only).
pub async fn handle_updates_cb(
    ctx: &Arc<BotCtx>,
    cq: &CallbackQuery,
    uid: i64,
    chat_id: i64,
    data: &str,
) -> bool {
    let Some(act) = data.strip_prefix("upd:") else {
        return false;
    };
    let root = ctx.is_owner(uid) || ctx.has_perm(uid, "root_access");
    if !root {
        let msg = owner_only_html(ctx, uid);
        ctx.ack(&cq.id, Some("Root access required"), true).await;
        let _ = ctx.render.send_html_simple(chat_id, &msg, None).await;
        return true;
    }
    let sd = ctx.cfg.state_dir.clone();
    match act {
        "status" => {
            ctx.ack(&cq.id, None, false).await;
            let body = status_body(&sd);
            send(ctx, Some(cq), chat_id, uid, "Fleet Updates · status", &body).await;
        }
        "seal" => {
            let body = seal_verify_body(&sd);
            ctx.ack(&cq.id, Some("Seal checked"), false).await;
            send(ctx, Some(cq), chat_id, uid, "Fleet Updates · seal", &body).await;
        }
        "history" => {
            ctx.ack(&cq.id, None, false).await;
            let body = history_body(&sd);
            send(ctx, Some(cq), chat_id, uid, "Fleet Updates · history", &body).await;
        }
        "check" => {
            ctx.ack(&cq.id, Some("Running dry-run check…"), false).await;
            send(ctx, Some(cq), chat_id, uid, "Fleet Updates · check", "Running deterministic dry-run check…").await;
            let ctx2 = Arc::clone(ctx);
            let msg_id = cq.message.as_ref().map(|m| m.message_id);
            tokio::spawn(async move {
                let out = match fleet_updater::check_all(&sd, UpdateScope::All).await {
                    Ok(rep) => fleet_updater::format_report(&rep),
                    Err(e) => format!("check failed: {e}"),
                };
                let html = format!("<b>Fleet Updates · check</b>\n<pre>{}</pre>", esc(&clip(&out, MAX_REPLY_CHARS)));
                let _ = ctx2
                    .render
                    .edit_or_send_html(chat_id, msg_id, &html, Some(updates_kb(&ctx2, uid)))
                    .await;
            });
        }
        "apply_skills" => {
            ctx.ack(&cq.id, Some("Applying skill updates…"), false).await;
            send(ctx, Some(cq), chat_id, uid, "Fleet Updates · apply", "Running transactional skill update…").await;
            let ctx2 = Arc::clone(ctx);
            let msg_id = cq.message.as_ref().map(|m| m.message_id);
            tokio::spawn(async move {
                let out = match fleet_updater::apply_updates(&sd, UpdateScope::Skills, false).await {
                    Ok(rep) => fleet_updater::format_report(&rep),
                    Err(e) => format!("apply failed: {e}"),
                };
                let html = format!("<b>Fleet Updates · apply</b>\n<pre>{}</pre>", esc(&clip(&out, MAX_REPLY_CHARS)));
                let _ = ctx2
                    .render
                    .edit_or_send_html(chat_id, msg_id, &html, Some(updates_kb(&ctx2, uid)))
                    .await;
            });
        }
        _ => {
            ctx.ack(&cq.id, None, false).await;
        }
    }
    true
}

/// Handle `/updates [sub] [args]`. Strictly owner/root_access only.
pub async fn cmd_updates(ctx: &Arc<BotCtx>, msg: &Message, arg: &str) {
    let Some(uid) = msg.from_user.as_ref().map(|u| u.id) else {
        return;
    };
    let chat = msg.chat.id;
    let root = ctx.is_owner(uid) || ctx.has_perm(uid, "root_access");
    if !root {
        let _ = ctx
            .render
            .send_html_simple(chat, &missing_perm_html(ctx, uid, "root_access"), None)
            .await;
        return;
    }

    let arg = arg.trim();
    let (sub, rest) = match arg.split_once(char::is_whitespace) {
        Some((a, b)) => (a.to_ascii_lowercase(), b.trim()),
        None => (arg.to_ascii_lowercase(), ""),
    };
    let sd = ctx.cfg.state_dir.clone();

    match sub.as_str() {
        "help" => send(ctx, None, chat, uid, "Fleet Updates", USAGE).await,
        "" | "status" => {
            let body = status_body(&sd);
            send(ctx, None, chat, uid, "Fleet Updates · status", &body).await;
        }
        "check" => {
            let scope = match UpdateScope::parse(rest) {
                Ok(s) => s,
                Err(e) => {
                    send(ctx, None, chat, uid, "Fleet Updates · check", &e.to_string()).await;
                    return;
                }
            };
            send(ctx, None, chat, uid, "Fleet Updates · check", "Running deterministic dry-run check…").await;
            let ctx2 = Arc::clone(ctx);
            tokio::spawn(async move {
                let out = match fleet_updater::check_all(&sd, scope).await {
                    Ok(rep) => fleet_updater::format_report(&rep),
                    Err(e) => format!("check failed: {e}"),
                };
                send(&ctx2, None, chat, uid, "Fleet Updates · check", &out).await;
            });
        }
        "apply" => {
            let scope = match UpdateScope::parse(rest) {
                Ok(s) => s,
                Err(e) => {
                    send(ctx, None, chat, uid, "Fleet Updates · apply", &e.to_string()).await;
                    return;
                }
            };
            let force_mcps = matches!(scope, UpdateScope::Mcps);
            send(ctx, None, chat, uid, "Fleet Updates · apply", "Running transactional update…").await;
            let ctx2 = Arc::clone(ctx);
            tokio::spawn(async move {
                let out = match fleet_updater::apply_updates(&sd, scope, force_mcps).await {
                    Ok(rep) => fleet_updater::format_report(&rep),
                    Err(e) => format!("apply failed: {e}"),
                };
                send(&ctx2, None, chat, uid, "Fleet Updates · apply", &out).await;
            });
        }
        "seal" => {
            let out = if rest.eq_ignore_ascii_case("refresh") {
                match fleet_updater::refresh_seal(&sd) {
                    Ok(s) => format!("Seal refreshed: {} protected files hashed.", s.entries.len()),
                    Err(e) => format!("seal refresh failed: {e}"),
                }
            } else {
                seal_verify_body(&sd)
            };
            send(ctx, None, chat, uid, "Fleet Updates · seal", &out).await;
        }
        "rollback" | "rb" => {
            let tx_id = (!rest.is_empty()).then_some(rest.to_string());
            let out = match tokio::task::spawn_blocking(move || {
                fleet_updater::rollback_tx(&sd, tx_id.as_deref())
            })
            .await
            {
                Ok(Ok(rb)) => format!(
                    "Rolled back {} ({} file(s) restored)\nSeal after: {}",
                    rb.tx_id,
                    rb.restored.len(),
                    if rb.seal_after.ok { "OK" } else { "DRIFT" }
                ),
                Ok(Err(e)) => format!("rollback failed: {e}"),
                Err(e) => format!("rollback task failed: {e}"),
            };
            send(ctx, None, chat, uid, "Fleet Updates · rollback", &out).await;
        }
        "history" | "log" => {
            let out = history_body(&sd);
            send(ctx, None, chat, uid, "Fleet Updates · history", &out).await;
        }
        _ => send(ctx, None, chat, uid, "Fleet Updates", USAGE).await,
    }
}
