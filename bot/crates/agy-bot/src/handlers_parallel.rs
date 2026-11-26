//! `/parallel` command and `par:*` callbacks (Parallel mode: bot-orchestrated mother agents).

use std::sync::Arc;

use agy_core::tg::{CallbackQuery, Message};
use agy_render::markdown::esc;
use serde_json::json;

use crate::ctx::BotCtx;
use crate::i18n::missing_perm_html;
use crate::jobs::parallel::{user_parallel_setting, PARALLEL_MAX, PARALLEL_PERM, PARALLEL_SETTING_KEY};
use crate::jobs::JobRequest;

fn usage(cur: usize) -> String {
    format!(
        "⚡ <b>Parallel mode</b>: {}\n\
         <blockquote>When on, a big request is planned by the lead agent, split into up to 2–3 independent parts, \
         run by separate agents at the same time (on different Antigravity accounts when possible), then merged into one answer. \
         Small requests are answered normally.</blockquote>\n\
         <code>/parallel 2</code> · <code>/parallel 3</code> · <code>/parallel off</code> — default for your messages\n\
         <code>/parallel 3 &lt;task&gt;</code> — one-off parallel run\n\
         <code>/parallel stop</code> — stop running agents",
        if cur == 0 { "<b>Off</b>".to_string() } else { format!("<b>{cur} agents</b>") }
    )
}

/// Handle `/parallel [off|2|3|stop|N <task>]`.
pub async fn cmd_parallel(ctx: &Arc<BotCtx>, msg: &Message, arg: &str) {
    let Some(user) = msg.from_user.as_ref() else { return };
    let uid = user.id;
    let chat_id = msg.chat.id;
    if !ctx.has_perm(uid, PARALLEL_PERM) {
        let _ = ctx
            .render
            .send_html_simple(chat_id, &missing_perm_html(ctx, uid, PARALLEL_PERM), None)
            .await;
        return;
    }
    let arg = arg.trim();
    let (first, rest) = match arg.split_once(char::is_whitespace) {
        Some((a, b)) => (a.to_ascii_lowercase(), b.trim().to_string()),
        None => (arg.to_ascii_lowercase(), String::new()),
    };
    let set = |n: usize| {
        let _ = ctx.store.update_user(uid, |u| {
            u.extra.insert(PARALLEL_SETTING_KEY.to_string(), json!(n));
        });
    };
    match first.as_str() {
        "" => {
            let cur = user_parallel_setting(&ctx.store.get_user(uid));
            let _ = ctx.render.send_html_simple(chat_id, &usage(cur), None).await;
        }
        "off" | "0" | "1" if rest.is_empty() => {
            set(0);
            let _ = ctx.render.send_html_simple(chat_id, "⚡ Parallel mode: <b>Off</b>", None).await;
        }
        "stop" => {
            let runs = ctx.jobs.parallel_runs_of(uid);
            let mut n = 0;
            for r in runs {
                if ctx.jobs.stop_parallel(uid, &r.run_id, None).await {
                    n += 1;
                }
            }
            let txt = if n > 0 { "⏹ <i>Stopping parallel agents…</i>" } else { "<i>No parallel run is active.</i>" };
            let _ = ctx.render.send_html_simple(chat_id, txt, None).await;
        }
        num if num.parse::<usize>().is_ok() => {
            let raw_n = num.parse::<usize>().unwrap_or(0);
            if raw_n < 2 {
                let _ = ctx
                    .render
                    .send_html_simple(
                        chat_id,
                        "⚡ Parallel mode requires at least <b>2</b> agents (e.g. <code>/parallel 2 &lt;task&gt;</code> or <code>/parallel off</code>).",
                        None,
                    )
                    .await;
                return;
            }
            let n = raw_n.clamp(2, PARALLEL_MAX);
            if rest.is_empty() {
                set(n);
                let _ = ctx
                    .render
                    .send_html_simple(chat_id, &format!("⚡ Parallel mode: <b>{n} agents</b> for big requests"), None)
                    .await;
            } else {
                let mut req = JobRequest::new(uid, chat_id, user.display_label(), rest, Vec::new());
                req.overrides.parallel = Some(n as u8);
                if let Err(err) = ctx.jobs.enqueue(req).await {
                    let _ = ctx
                        .render
                        .send_html_simple(chat_id, &format!("Failed to queue: <code>{}</code>", esc(&err.to_string())), None)
                        .await;
                }
            }
        }
        _ => {
            // `/parallel <task>` → one-off with the user's width or 2
            let cur = user_parallel_setting(&ctx.store.get_user(uid)).max(2);
            let mut req = JobRequest::new(uid, chat_id, user.display_label(), arg.to_string(), Vec::new());
            req.overrides.parallel = Some(cur as u8);
            if let Err(err) = ctx.jobs.enqueue(req).await {
                let _ = ctx
                    .render
                    .send_html_simple(chat_id, &format!("Failed to queue: <code>{}</code>", esc(&err.to_string())), None)
                    .await;
            }
        }
    }
}

/// `par:stop:<run_id>:all|<k>` callbacks. Returns `true` when handled.
pub async fn handle_par_cb(ctx: &Arc<BotCtx>, cq: &CallbackQuery, uid: i64, data: &str) -> bool {
    let Some(rest) = data.strip_prefix("par:stop:") else {
        return false;
    };
    let Some((run_id, which)) = rest.rsplit_once(':') else {
        ctx.ack(&cq.id, None, false).await;
        return true;
    };
    let which = if which == "all" {
        None
    } else {
        let Ok(k) = which.parse::<usize>() else {
            ctx.ack(&cq.id, Some("Invalid agent target"), false).await;
            return true;
        };
        Some(k)
    };
    let ok = ctx.jobs.stop_parallel(uid, run_id, which).await;
    let note = match (ok, which) {
        (false, _) => "Run not found or not yours",
        (true, None) => "Stopping all agents…",
        (true, Some(_)) => "Stopping that agent…",
    };
    ctx.ack(&cq.id, Some(note), false).await;
    true
}
