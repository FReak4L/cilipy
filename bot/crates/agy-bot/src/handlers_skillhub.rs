//! `/skillhub` — Claude Code ecosystem hub: search, show, sync, sources, add, remove, install, stats.

use std::sync::Arc;

use agy_core::tg::{CallbackQuery, InlineKeyboardMarkup, Message};
use agy_ext::skill_hub;
use agy_render::esc;
use serde_json::json;

use crate::ctx::BotCtx;
use crate::i18n::{missing_perm_html, perm_label, t, Tx};

const MAX_REPLY_CHARS: usize = 3000;

const USAGE: &str = "/skillhub <query>            search (default)
/skillhub catalog [src] [kind] browse ecosystem & Superpowers
/skillhub superpowers         list all 15 Superpowers skills
/skillhub show <id|name>      read a document
/skillhub stats | sources     index / source status
/skillhub sync [source]       pull latest from GitHub   (root)
/skillhub add owner/repo [id] track a repo              (root)
/skillhub remove <id>         untrack + delete clone    (root)
/skillhub install <id|name>   skill → SkillPort         (root)

Query: terms +must -not \"phrase\" /regex/i pre* fuzy~ fuzy~2
name: desc: tag: body: source:ecc kind:skill|agent|command|rule|prompt|doc path:
lines:<200 chars:>1000 words: tokens: lines:50..300 sort:-lines dedup:off";

fn clip(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max).collect();
        out.push_str("\n… [truncated]");
        out
    }
}

fn skillhub_kb(ctx: &BotCtx, uid: i64) -> InlineKeyboardMarkup {
    let lang = ctx.lang(uid);
    BotCtx::kb(vec![
        vec![
            ctx.btn("", "⚡ Superpowers", Some("hub:superpowers"), Some("primary"), None),
            ctx.btn("", "📚 Catalog", Some("hub:catalog"), None, None),
        ],
        vec![
            ctx.btn("", "📦 Sources", Some("hub:sources"), None, None),
            ctx.btn("", "📊 Stats", Some("hub:stats"), None, None),
        ],
        vec![
            ctx.btn("skills", "✨ Skills", Some("skills:0"), None, None),
            ctx.btn("back", t(lang, Tx::BtnMenu), Some("home:1"), None, None),
        ],
    ])
}

async fn send(
    ctx: &Arc<BotCtx>,
    cq: Option<&CallbackQuery>,
    chat: i64,
    uid: i64,
    title: &str,
    body: &str,
) {
    let mk = Some(skillhub_kb(ctx, uid));
    let html = format!("<b>{}</b>\n<pre>{}</pre>", esc(title), esc(&clip(body, MAX_REPLY_CHARS)));
    if let Some(c) = cq {
        ctx.edit_or_send(Some(c), chat, &html, mk).await;
        return;
    }
    if let Err(e) = ctx.render.send_html_simple(chat, &html, mk.clone()).await {
        tracing::warn!(error = %e, "skillhub reply failed; retrying shorter");
        let short = format!("<b>{}</b>\n<pre>{}</pre>", esc(title), esc(&clip(body, 1200)));
        let _ = ctx.render.send_html_simple(chat, &short, mk).await;
    }
}

/// Handle `hub:*` callbacks from `/skills` and `/skillhub` cards.
pub async fn handle_skillhub_cb(
    ctx: &Arc<BotCtx>,
    cq: &CallbackQuery,
    uid: i64,
    chat_id: i64,
    data: &str,
) -> bool {
    let Some(act) = data.strip_prefix("hub:") else {
        return false;
    };
    if !ctx.has_perm(uid, "skills_manage") {
        let lang = ctx.lang(uid);
        let msg = format!("{} {}", t(lang, Tx::ModuleRequiredHdr), perm_label(lang, "skills_manage"));
        ctx.ack(&cq.id, Some(&msg), true).await;
        return true;
    }
    let sd = ctx.cfg.state_dir.clone();
    match act {
        "open" => {
            ctx.ack(&cq.id, None, false).await;
            send(ctx, Some(cq), chat_id, uid, "Skill Hub", USAGE).await;
        }
        "superpowers" => {
            ctx.ack(&cq.id, None, false).await;
            let out = skill_hub::call_hub_tool(
                &sd,
                "skillhub_catalog",
                &json!({ "source": "superpowers", "kind": "skill", "limit": 50 }),
            )
            .await
            .unwrap_or_else(|e| e);
            send(ctx, Some(cq), chat_id, uid, "Skill Hub · Superpowers", &out).await;
        }
        "catalog" => {
            ctx.ack(&cq.id, None, false).await;
            let out = skill_hub::call_hub_tool(&sd, "skillhub_catalog", &json!({ "limit": 30 }))
                .await
                .unwrap_or_else(|e| e);
            send(ctx, Some(cq), chat_id, uid, "Skill Hub · catalog", &out).await;
        }
        "sources" => {
            ctx.ack(&cq.id, None, false).await;
            send(ctx, Some(cq), chat_id, uid, "Skill Hub · sources", &skill_hub::sources_summary(&sd)).await;
        }
        "stats" => {
            ctx.ack(&cq.id, None, false).await;
            let out = skill_hub::call_hub_tool(&sd, "skillhub_stats", &json!({}))
                .await
                .unwrap_or_else(|e| e);
            send(ctx, Some(cq), chat_id, uid, "Skill Hub · stats", &out).await;
        }
        _ => {
            ctx.ack(&cq.id, None, false).await;
        }
    }
    true
}

/// Handle `/skillhub [sub] [args]`.
pub async fn cmd_skillhub(ctx: &Arc<BotCtx>, msg: &Message, arg: &str) {
    let Some(uid) = msg.from_user.as_ref().map(|u| u.id) else {
        return;
    };
    let chat = msg.chat.id;
    if !ctx.has_perm(uid, "skills_manage") {
        let _ = ctx
            .render
            .send_html_simple(chat, &missing_perm_html(ctx, uid, "skills_manage"), None)
            .await;
        return;
    }
    let root = ctx.is_owner(uid) || ctx.has_perm(uid, "root_access");
    let arg = arg.trim();
    let (sub, rest) = match arg.split_once(char::is_whitespace) {
        Some((a, b)) => (a, b.trim()),
        None => (arg, ""),
    };
    let sub_low = sub.to_ascii_lowercase();
    let sd = ctx.cfg.state_dir.clone();
    let needs_root = matches!(sub_low.as_str(), "sync" | "update" | "add" | "remove" | "rm" | "install");
    if needs_root && !root {
        send(ctx, None, chat, uid, "Skill Hub", "This action requires root_access.").await;
        return;
    }
    match sub_low.as_str() {
        "" | "help" => send(ctx, None, chat, uid, "Skill Hub", USAGE).await,
        "sync" | "update" => {
            send(ctx, None, chat, uid, "Skill Hub", "Syncing from GitHub… I will report when done.").await;
            let ctx2 = Arc::clone(ctx);
            let only = rest.to_string();
            tokio::spawn(async move {
                let out = skill_hub::call_hub_tool(&sd, "skillhub_sync", &json!({ "source": only }))
                    .await
                    .unwrap_or_else(|e| format!("sync failed: {e}"));
                let st = skill_hub::hub_index_async(&sd).await.stats();
                let summary = format!(
                    "Index: {} docs ({} unique) · {} terms · {} trigrams · build {} ms · {:.1} MB",
                    st.docs,
                    st.dedup_groups,
                    st.terms,
                    st.trigrams,
                    st.build_ms,
                    st.approx_bytes as f64 / (1024.0 * 1024.0)
                );
                send(&ctx2, None, chat, uid, "Skill Hub · sync", &format!("{out}\n\n{summary}")).await;
            });
        }
        "catalog" | "list" | "ls" => {
            let mut it = rest.split_whitespace();
            let first = it.next();
            let second = it.next();
            let (src, knd) = match (first, second) {
                (Some(a), Some(b)) => (Some(a), Some(b)),
                (Some(a), None) if agy_ext::skill_index::DocKind::parse(a).is_some() => (None, Some(a)),
                (Some(a), None) => (Some(a), None),
                (None, None) => (None, None),
                (None, Some(b)) => (None, Some(b)),
            };
            let out = skill_hub::call_hub_tool(
                &sd,
                "skillhub_catalog",
                &json!({ "source": src, "kind": knd, "limit": 30 }),
            )
            .await
            .unwrap_or_else(|e| e);
            send(ctx, None, chat, uid, "Skill Hub · catalog", &out).await;
        }
        "superpowers" | "sp" => {
            let out = skill_hub::call_hub_tool(
                &sd,
                "skillhub_catalog",
                &json!({ "source": "superpowers", "kind": "skill", "limit": 50 }),
            )
            .await
            .unwrap_or_else(|e| e);
            send(ctx, None, chat, uid, "Skill Hub · Superpowers", &out).await;
        }
        "sources" => send(ctx, None, chat, uid, "Skill Hub · sources", &skill_hub::sources_summary(&sd)).await,
        "stats" => {
            let out = skill_hub::call_hub_tool(&sd, "skillhub_stats", &json!({})).await.unwrap_or_else(|e| e);
            send(ctx, None, chat, uid, "Skill Hub · stats", &out).await;
        }
        "add" => {
            let mut it = rest.split_whitespace();
            let out = match it.next() {
                Some(spec) => match skill_hub::add_source(&sd, spec, it.next()) {
                    Ok(s) => format!("added {} ({}) — run /skillhub sync {}", s.id, s.repo, s.id),
                    Err(e) => e.to_string(),
                },
                None => "usage: /skillhub add owner/repo [id]".into(),
            };
            send(ctx, None, chat, uid, "Skill Hub", &out).await;
        }
        "remove" | "rm" => {
            if rest.is_empty() {
                send(ctx, None, chat, uid, "Skill Hub", "usage: /skillhub remove <id>").await;
                return;
            }
            let (sd2, id) = (sd.clone(), rest.to_string());
            let out = match tokio::task::spawn_blocking(move || skill_hub::remove_source(&sd2, &id)).await {
                Ok(Ok(true)) => format!("removed {rest}"),
                Ok(Ok(false)) => format!("unknown source {rest}"),
                Ok(Err(e)) => e.to_string(),
                Err(e) => e.to_string(),
            };
            send(ctx, None, chat, uid, "Skill Hub", &out).await;
        }
        "install" => {
            if rest.is_empty() {
                send(ctx, None, chat, uid, "Skill Hub", "usage: /skillhub install <id|name>").await;
                return;
            }
            let out = skill_hub::install_skill(&sd, rest, None).await.unwrap_or_else(|e| e.to_string());
            send(ctx, None, chat, uid, "Skill Hub", &out).await;
        }
        "show" | "get" => {
            if rest.is_empty() {
                send(ctx, None, chat, uid, "Skill Hub", "usage: /skillhub show <id|name>").await;
                return;
            }
            let out = skill_hub::call_hub_tool(&sd, "skillhub_get", &json!({ "id": rest, "max_chars": 3200 }))
                .await
                .unwrap_or_else(|e| e);
            send(ctx, None, chat, uid, "Skill Hub · document", &out).await;
        }
        "search" | "s" => {
            if rest.is_empty() {
                send(ctx, None, chat, uid, "Skill Hub", "usage: /skillhub search <query>").await;
                return;
            }
            let out = skill_hub::call_hub_tool(&sd, "skillhub_search", &json!({ "query": rest, "limit": 8 }))
                .await
                .unwrap_or_else(|e| e);
            send(ctx, None, chat, uid, "Skill Hub · search", &out).await;
        }
        _ => {
            let out = skill_hub::call_hub_tool(&sd, "skillhub_search", &json!({ "query": arg, "limit": 8 }))
                .await
                .unwrap_or_else(|e| e);
            send(ctx, None, chat, uid, "Skill Hub · search", &out).await;
        }
    }
}
