//! Telegram Bot API 10.4 widget delivery, Dual In-Telegram WebApp fallback, commands,
//! callbacks, inline/widget queries, startup `widget_once.json`, and outbox delivery.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use chrono::Local;
use dashmap::DashMap;
use serde_json::{json, Value};
use tokio::time::sleep;
use tracing::{error, info, warn};

use agy_core::error::{BridgeError, Result};
use agy_core::tg::{
    CallbackQuery, InlineKeyboardButton, InlineKeyboardMarkup, InlineQuery,
    InlineQueryResultArticle, InputRichMessage, Message, ReplyParameters, SharedWidgetQuery,
    User, WidgetQuery, WidgetQueryType,
};
use agy_net::client::{
    tg_retry, EditMessageTextParams, EditSharedWidgetDataParams, EditWidgetDataParams,
    SendSharedWidgetParams, SendWidgetParams,
};
use agy_render::{
    esc, md_cell, rich_to_html_card, strip_custom_emoji, strip_md_custom_emoji,
};
use agy_widgets::builtins::{build_inline_widget_article, builtin_widget};
use agy_widgets::parser::{
    extract_widgets_from_markdown, parse_widget_html_file, parse_widget_json,
    EditMessageDataAction, EditSharedDataAction, ParsedWidgetAction,
};
use agy_widgets::spec::{
    count_widget_size, encode_widget_data, lint_widget_profile, validate_widget_spec, WidgetData,
    WidgetSpec, BUILTIN_WIDGET_KINDS, WIDGET_ANSWER_DATA_LIMIT, WIDGET_HTML_RAW_LIMIT,
    WIDGET_HTML_ZLIB_LIMIT,
};
use agy_widgets::store::{DataPatch, RecordSentOpts, WebAppWidgetRecord};
use agy_widgets::webapp::render_in_bubble_widget;

use crate::ctx::BotCtx;
use crate::i18n::{missing_perm_html, perm_label, t, Tx};
use crate::jobs::JobRequest;
use crate::webapp_bridge::{
    build_widget_states, execute_widget_data_action, BotWebAppBridge,
};

const WIDGET_API_PROBE_COOLDOWN: Duration = Duration::from_secs(600);
const MAX_CB_DATA_BYTES: usize = 64;

static WIDGET_API_BLOCKED_UNTIL: OnceLock<DashMap<PathBuf, Instant>> = OnceLock::new();
static PENDING_WIDGET_FILES: OnceLock<DashMap<(PathBuf, i64), Vec<PathBuf>>> = OnceLock::new();

fn gate_map() -> &'static DashMap<PathBuf, Instant> {
    WIDGET_API_BLOCKED_UNTIL.get_or_init(DashMap::new)
}

fn pending_files_map() -> &'static DashMap<(PathBuf, i64), Vec<PathBuf>> {
    PENDING_WIDGET_FILES.get_or_init(DashMap::new)
}

fn is_widget_api_blocked(ctx: &BotCtx) -> bool {
    let map = gate_map();
    if let Some(entry) = map.get(&ctx.cfg.state_dir) {
        if Instant::now() < *entry.value() {
            return true;
        }
        drop(entry);
        map.remove(&ctx.cfg.state_dir);
    }
    false
}

fn mark_widget_api_blocked(ctx: &BotCtx) {
    gate_map().insert(
        ctx.cfg.state_dir.clone(),
        Instant::now() + WIDGET_API_PROBE_COOLDOWN,
    );
}

/// Reset any cached native widget cloud-gate cooldown for this context's `state_dir`.
#[cfg(test)]
pub fn clear_widget_api_gate(ctx: &BotCtx) {
    gate_map().remove(&ctx.cfg.state_dir);
}

/// Take any pending saved inbox `.html` / `.json` widget paths for `uid`.
pub fn take_pending_widget_files(ctx: &BotCtx, uid: i64) -> Vec<PathBuf> {
    pending_files_map()
        .remove(&(ctx.cfg.state_dir.clone(), uid))
        .map(|(_, v)| v)
        .unwrap_or_default()
}

/// Peek pending saved inbox `.html` / `.json` widget paths for `uid`.
pub fn pending_widget_files(ctx: &BotCtx, uid: i64) -> Vec<PathBuf> {
    pending_files_map()
        .get(&(ctx.cfg.state_dir.clone(), uid))
        .map(|v| v.clone())
        .unwrap_or_default()
}

/// Append a pending regular/widget uploaded file path for `uid`.
pub fn push_pending_file(ctx: &BotCtx, uid: i64, path: PathBuf) {
    push_pending_widget_files(ctx, uid, vec![path]);
}

fn push_pending_widget_files(ctx: &BotCtx, uid: i64, paths: Vec<PathBuf>) {
    pending_files_map()
        .entry((ctx.cfg.state_dir.clone(), uid))
        .or_default()
        .extend(paths);
}

fn truncate_chars(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        return s.to_string();
    }
    s.chars().take(max_chars).collect()
}

fn truncate_utf8_bytes(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_string();
    }
    let mut end = 0usize;
    for (idx, ch) in s.char_indices() {
        let next = idx + ch.len_utf8();
        if next > max_bytes {
            break;
        }
        end = next;
    }
    s[..end].to_string()
}

/// Return `https://<host>/w/<wid>` when `WEBAPP_BASE_URL` uses HTTPS, else `None`.
pub fn webapp_url_for(ctx: &BotCtx, wid: &str) -> Option<String> {
    let base = ctx.cfg.webapp_base_url.trim().trim_end_matches('/');
    if base.starts_with("https://") {
        Some(format!("{base}/w/{wid}"))
    } else {
        None
    }
}

/// Construct one of the 4 official built-in widgets hydrated with live state for `uid`.
pub async fn build_builtin_widget(ctx: &Arc<BotCtx>, kind: &str, uid: i64) -> Result<WidgetSpec> {
    let k = kind.trim().to_ascii_lowercase();
    let (compact_cd, _) = build_widget_states(ctx, &k, uid, None, "", 0, "all").await?;
    builtin_widget(&k, Some(&compact_cd))
}

fn builtin_widget_kind_for(slug_or_handler: Option<&str>) -> Option<&'static str> {
    let key = slug_or_handler?.trim().to_ascii_lowercase();
    match key.as_str() {
        "skills_hub" | "skills" => Some("skills"),
        "mcp_hub" | "mcp" => Some("mcp"),
        "models_hub" | "models" => Some("models"),
        "memory_hub" | "memory" => Some("memory"),
        _ => None,
    }
}

fn hydrate_shared_for_webapp(ctx: &BotCtx, norm: &WidgetSpec) -> WidgetSpec {
    if norm.html.is_some() {
        return norm.clone();
    }
    let key = norm.widget_id.as_deref().unwrap_or("");
    let wrec = ctx.widgets.get_webapp_widget(key);
    let sh = ctx.widgets.get_shared(key);

    let mut html_src = wrec.as_ref().and_then(|r| r.html.clone());
    let pd_src = norm
        .public_data
        .clone()
        .or_else(|| sh.as_ref().and_then(|s| s.public_data.clone()))
        .or_else(|| wrec.as_ref().and_then(|r| r.public_data.clone()));
    let h_name = norm
        .handler
        .clone()
        .or_else(|| sh.as_ref().and_then(|s| s.handler.clone()))
        .or_else(|| wrec.as_ref().and_then(|r| r.handler.clone()));
    let cap = norm
        .caption
        .clone()
        .or_else(|| sh.as_ref().and_then(|s| s.caption.clone()))
        .or_else(|| wrec.as_ref().and_then(|r| r.caption.clone()));
    let slug = norm
        .slug
        .clone()
        .or_else(|| sh.as_ref().and_then(|s| s.slug.clone()))
        .or_else(|| wrec.as_ref().and_then(|r| r.slug.clone()));

    if html_src.is_none() {
        if let Some(mapped) = builtin_widget_kind_for(slug.as_deref().or(h_name.as_deref())) {
            if let Ok(built) = builtin_widget(mapped, None) {
                html_src = built.html;
            }
        }
    }

    let mut out = norm.clone();
    out.html = html_src;
    out.public_data = pd_src;
    out.handler = h_name;
    out.caption = cap;
    out.slug = slug;
    out
}

fn merge_widget_markups(
    card_mk: InlineKeyboardMarkup,
    extra_mk: Option<InlineKeyboardMarkup>,
) -> InlineKeyboardMarkup {
    let mut rows = card_mk.inline_keyboard;
    if let Some(extra) = extra_mk {
        rows.extend(extra.inline_keyboard);
    }
    InlineKeyboardMarkup::new(rows)
}

fn is_strict_premium_err(err: &BridgeError, has_premium: bool) -> bool {
    if err.looks_like_premium_rejection() {
        return true;
    }
    has_premium && matches!(err, BridgeError::BotApi { code: 400, .. })
}

async fn send_in_telegram_widget(
    ctx: &Arc<BotCtx>,
    chat_id: i64,
    norm: &WidgetSpec,
    reply_markup_override: Option<InlineKeyboardMarkup>,
    reason: &str,
) -> Result<(Option<Message>, String)> {
    let hydrated = hydrate_shared_for_webapp(ctx, norm);
    let wid = ctx
        .widgets
        .register_webapp_widget(&hydrated, Some(chat_id), None, None)?;
    let rec = ctx
        .widgets
        .get_webapp_widget(&wid)
        .unwrap_or_else(|| WebAppWidgetRecord {
            wid: wid.clone(),
            ..Default::default()
        });
    let wurl = webapp_url_for(ctx, &wid);
    let (md, card_mk) = render_in_bubble_widget(&rec, wurl.as_deref(), None, &ctx.premium)?;
    let extra_mk = reply_markup_override.or_else(|| hydrated.reply_markup.clone());
    let final_mk = merge_widget_markups(card_mk, extra_mk);

    let (msg_opt, used_rich) = ctx
        .render
        .send_rich_card_message(chat_id, &md, Some(final_mk))
        .await?;
    let Some(msg) = msg_opt else {
        return Ok((None, format!("unavailable:{}", truncate_chars(reason, 80))));
    };

    ctx.widgets
        .bind_webapp_message(&wid, chat_id, msg.message_id, used_rich, None)?;
    let shared_wid = hydrated
        .widget_id
        .as_deref()
        .or(if hydrated.is_shared == Some(true) {
            Some(wid.as_str())
        } else {
            None
        });
    ctx.widgets.record_sent_with(RecordSentOpts {
        chat_id: Some(chat_id),
        message_id: Some(msg.message_id),
        spec: Some(&hydrated),
        widget_id: shared_wid,
        ..Default::default()
    })?;

    Ok((Some(msg), format!("webapp:{wid}")))
}

fn non_empty_mk(mk: Option<InlineKeyboardMarkup>) -> Option<InlineKeyboardMarkup> {
    mk.filter(|m| !m.inline_keyboard.is_empty())
}

/// Re-render and edit an in-Telegram WebApp widget bubble card in place after state updates.
pub async fn refresh_in_bubble_card(ctx: &Arc<BotCtx>, wid: &str) -> Result<bool> {
    let Some(rec) = ctx.widgets.get_webapp_widget(wid) else {
        return Ok(false);
    };
    let (Some(cid), Some(mid)) = (rec.chat_id, rec.message_id) else {
        return Ok(false);
    };
    let wurl = webapp_url_for(ctx, wid);
    let (md, mk) = render_in_bubble_widget(&rec, wurl.as_deref(), None, &ctx.premium)?;
    let mk_opt = non_empty_mk(Some(mk));
    let plain_md = strip_md_custom_emoji(&md);
    let plain_mk = mk_opt
        .clone()
        .map(|m| ctx.premium.strip_markup_icons(m));

    if rec.rich {
        let mut attempts: Vec<(String, Option<InlineKeyboardMarkup>)> = Vec::new();
        let has_prem_mk = mk_opt.as_ref().is_some_and(InlineKeyboardMarkup::has_custom_icons);
        if ctx.premium.active() && (plain_md != md || has_prem_mk) {
            attempts.push((md.clone(), mk_opt.clone()));
        }
        attempts.push((plain_md.clone(), plain_mk.clone()));

        let total = attempts.len();
        for (idx, (cur_md, cur_mk)) in attempts.into_iter().enumerate() {
            let p = EditMessageTextParams {
                chat_id: Some(cid),
                message_id: Some(mid),
                rich_message: Some(InputRichMessage::markdown(cur_md.clone())),
                reply_markup: cur_mk.clone(),
                ..Default::default()
            };
            match tg_retry(2, 3.0, || ctx.client.edit_message_text(&p)).await {
                Ok(_) => return Ok(true),
                Err(err) if err.is_not_modified() => return Ok(true),
                Err(err) => {
                    let has_prem =
                        cur_md.contains("tg://emoji") || cur_mk.as_ref().is_some_and(InlineKeyboardMarkup::has_custom_icons);
                    if idx + 1 < total && is_strict_premium_err(&err, has_prem) {
                        if err.looks_like_premium_rejection() {
                            ctx.premium.disable(&err.to_string());
                        }
                        continue;
                    }
                    if matches!(err, BridgeError::BotApi { code: 400, .. }) {
                        info!(wid, error = %err, "rich card edit rejected -> HTML fallback");
                        let _ = ctx.widgets.bind_webapp_message(wid, cid, mid, false, None);
                        break;
                    }
                    warn!(wid, error = %err, "rich card edit failed");
                    return Ok(false);
                }
            }
        }
    }

    let card_html = rich_to_html_card(&plain_md);
    match ctx.render.edit_html(cid, mid, &card_html, plain_mk).await {
        Ok(()) => Ok(true),
        Err(err) if err.is_not_modified() => Ok(true),
        Err(err) => {
            info!(wid, error = %err, "HTML card edit rejected");
            Ok(false)
        }
    }
}

fn resolve_effect_id(ctx: &BotCtx, raw: Option<&str>) -> Option<String> {
    let eff = raw?.trim();
    if eff.is_empty() {
        return None;
    }
    if matches!(eff, "fire" | "like" | "heart" | "party") {
        ctx.premium.effect(eff).map(str::to_string)
    } else if ctx.premium.effects_ok() {
        Some(eff.to_string())
    } else {
        None
    }
}

struct NativeSendOpts {
    effect_id: Option<String>,
    reply_markup: Option<InlineKeyboardMarkup>,
    parse_mode: Option<String>,
    caption: Option<String>,
    caption_entities: Option<Vec<agy_core::tg::MessageEntity>>,
}

async fn call_send_native_widget(
    ctx: &BotCtx,
    chat_id: i64,
    norm: &WidgetSpec,
    opts: NativeSendOpts,
) -> Result<Message> {
    let rparams = norm
        .reply_to_message_id
        .map(|mid| ReplyParameters {
            message_id: mid,
            chat_id: None,
        });

    if norm.html.is_none() {
        if let Some(ref wid) = norm.widget_id {
            let params = SendSharedWidgetParams {
                chat_id,
                widget_id: wid.clone(),
                message_thread_id: norm.message_thread_id,
                chat_data: norm.chat_data.clone(),
                caption: opts.caption,
                parse_mode: opts.parse_mode,
                caption_entities: opts.caption_entities,
                show_caption_above_media: norm.show_caption_above_media,
                disable_notification: norm.disable_notification,
                protect_content: norm.protect_content,
                allow_paid_broadcast: norm.allow_paid_broadcast,
                message_effect_id: opts.effect_id,
                reply_parameters: rparams,
                reply_markup: opts.reply_markup,
            };
            return tg_retry(1, 2.0, || ctx.client.send_shared_widget(&params)).await;
        }
    }

    let params = SendWidgetParams {
        chat_id,
        html: norm.html.clone().unwrap_or_default(),
        message_thread_id: norm.message_thread_id,
        width: norm.width,
        height: norm.height,
        public_data: norm.public_data.clone(),
        chat_data: norm.chat_data.clone(),
        caption: opts.caption,
        parse_mode: opts.parse_mode,
        caption_entities: opts.caption_entities,
        show_caption_above_media: norm.show_caption_above_media,
        allow_queries: norm.allow_queries,
        is_shared: norm.is_shared,
        disable_notification: norm.disable_notification,
        protect_content: norm.protect_content,
        allow_paid_broadcast: norm.allow_paid_broadcast,
        message_effect_id: opts.effect_id,
        reply_parameters: rparams,
        reply_markup: opts.reply_markup,
    };
    tg_retry(1, 2.0, || ctx.client.send_widget(&params)).await
}

fn looks_like_widget_gate(err: &BridgeError) -> bool {
    let msg = err.to_string().to_ascii_lowercase();
    [
        "widget_not_allowed",
        "not_allowed",
        "too_large",
        "html_invalid",
        "unsupported",
    ]
    .iter()
    .any(|kw| msg.contains(kw))
}

/// Validate and send a Bot API 10.4 HTML/shared widget, automatically falling back
/// to the Dual In-Telegram Rich Card WebApp engine when Telegram cloud-gates widgets.
pub async fn send_widget_safe(
    ctx: &Arc<BotCtx>,
    chat_id: i64,
    spec: WidgetSpec,
) -> Result<(Option<Message>, String)> {
    send_widget_safe_with_markup(ctx, chat_id, spec, None).await
}

/// Variant of [`send_widget_safe`] allowing an explicit inline keyboard override.
pub async fn send_widget_safe_with_markup(
    ctx: &Arc<BotCtx>,
    chat_id: i64,
    mut spec: WidgetSpec,
    reply_markup_override: Option<InlineKeyboardMarkup>,
) -> Result<(Option<Message>, String)> {
    if spec.html.is_none() {
        let lookup = spec
            .widget_id
            .as_deref()
            .or(spec.slug.as_deref())
            .unwrap_or("");
        if let Some(resolved) = ctx.widgets.resolve_widget_id(lookup) {
            spec.widget_id = Some(resolved);
        }
    }

    let (norm, warns) = validate_widget_spec(&spec)?;
    if !warns.is_empty() {
        let slug = norm.slug.as_deref().unwrap_or("-");
        let preview: String = warns.iter().take(4).cloned().collect::<Vec<_>>().join("; ");
        info!(slug, warnings = %preview, "widget Profile-1 lint warnings");
    }

    if is_widget_api_blocked(ctx) {
        return send_in_telegram_widget(ctx, chat_id, &norm, reply_markup_override, "cached_gate")
            .await;
    }

    let eff = resolve_effect_id(ctx, norm.message_effect_id.as_deref());
    let markup = non_empty_mk(reply_markup_override.clone().or_else(|| norm.reply_markup.clone()));
    let ents = norm.caption_entities.clone().filter(|v| !v.is_empty());
    let use_pm = if ents.is_some() {
        None
    } else {
        norm.parse_mode.clone()
    };

    let mut attempt_res = call_send_native_widget(
        ctx,
        chat_id,
        &norm,
        NativeSendOpts {
            effect_id: eff,
            reply_markup: markup.clone(),
            parse_mode: use_pm,
            caption: norm.caption.clone(),
            caption_entities: ents,
        },
    )
    .await;

    if let Err(ref err) = attempt_res {
        if err.is_chat_unavailable() {
            warn!(chat_id, error = %err, "sendWidget skipped for unavailable chat");
            return Ok((
                None,
                format!("unavailable:{}", truncate_chars(&err.to_string(), 80)),
            ));
        }

        let msg_low = err.to_string().to_ascii_lowercase();
        // Native Bot API 10.4 widgets are private-chat only; never let a group rejection
        // globally block native widgets for private chats!
        if chat_id > 0 && msg_low.contains("widget_not_allowed") {
            mark_widget_api_blocked(ctx);
        }

        if matches!(err, BridgeError::BotApi { code: 400, .. }) && !looks_like_widget_gate(err) {
            let plain_cap = norm.caption.as_deref().map(strip_custom_emoji);
            let plain_mk = markup.map(|m| ctx.premium.strip_markup_icons(m));
            attempt_res = call_send_native_widget(
                ctx,
                chat_id,
                &norm,
                NativeSendOpts {
                    effect_id: None,
                    reply_markup: plain_mk,
                    parse_mode: None,
                    caption: plain_cap,
                    caption_entities: None,
                },
            )
            .await;
        }
    }

    let msg = match attempt_res {
        Ok(m) => m,
        Err(err) if err.is_chat_unavailable() => {
            return Ok((
                None,
                format!("unavailable:{}", truncate_chars(&err.to_string(), 80)),
            ));
        }
        Err(err) if matches!(err, BridgeError::BotApi { code: 400 | 403 | 404, .. }) => {
            info!(
                chat_id,
                error = %err,
                "sendWidget gated/rejected -> In-Telegram Dual Engine"
            );
            return send_in_telegram_widget(
                ctx,
                chat_id,
                &norm,
                reply_markup_override,
                &err.to_string(),
            )
            .await;
        }
        Err(err) => {
            warn!(chat_id, error = %err, "sendWidget failed");
            return Ok((
                None,
                format!("error:{}", truncate_chars(&err.to_string(), 80)),
            ));
        }
    };

    let wid_real = msg
        .widget
        .as_ref()
        .and_then(|w| w.id.clone())
        .or_else(|| norm.widget_id.clone());

    ctx.widgets.record_sent_with(RecordSentOpts {
        chat_id: Some(chat_id),
        message_id: Some(msg.message_id),
        spec: Some(&norm),
        widget_id: wid_real.as_deref(),
        ..Default::default()
    })?;

    if norm.is_shared == Some(true) {
        if let (Some(ct), Some(ref wid)) = (norm.cache_time.filter(|&c| c > 0), &wid_real) {
            let pd = norm.public_data.as_deref().unwrap_or("");
            let _ = edit_shared_widget_safe(ctx, wid, Some(WidgetData::Str(pd)), Some(ct)).await;
        }
    }

    Ok((Some(msg), "sent".to_string()))
}

/// Update `public_data` / `chat_data` on a message widget (native or In-Telegram WebApp fallback).
pub async fn edit_message_widget_safe<'a>(
    ctx: &Arc<BotCtx>,
    chat_id: Option<i64>,
    message_id: Option<i64>,
    inline_message_id: Option<&str>,
    public_data: Option<WidgetData<'a>>,
    chat_data: Option<WidgetData<'a>>,
) -> Result<bool> {
    let pd = match public_data {
        Some(v) => encode_widget_data(Some(v), true)?,
        None => None,
    };
    let cd = match chat_data {
        Some(v) => encode_widget_data(Some(v), true)?,
        None => None,
    };
    if pd.is_none() && cd.is_none() {
        return Ok(false);
    }

    let ww_ids = if inline_message_id.is_none() {
        match (chat_id, message_id) {
            (Some(cid), Some(mid)) => ctx.widgets.find_message_targets(cid, mid),
            _ => Vec::new(),
        }
    } else {
        Vec::new()
    };

    let pd_patch = match pd.as_deref() {
        Some(s) => DataPatch::Set(WidgetData::Str(s)),
        None => DataPatch::Unchanged,
    };
    let cd_patch = match cd.as_deref() {
        Some(s) => DataPatch::Set(WidgetData::Str(s)),
        None => DataPatch::Unchanged,
    };

    if !ww_ids.is_empty() {
        for w_id in ww_ids {
            let _ = ctx
                .widgets
                .update_webapp_widget_state(&w_id, cd_patch, pd_patch, None);
            let _ = refresh_in_bubble_card(ctx, &w_id).await;
        }
        ctx.widgets
            .update_message_state(chat_id, message_id, inline_message_id, cd_patch, pd_patch)?;
        return Ok(true);
    }

    let params = EditWidgetDataParams {
        chat_id,
        message_id,
        inline_message_id: inline_message_id.map(str::to_string),
        public_data: pd.clone(),
        chat_data: cd.clone(),
    };
    match tg_retry(1, 2.0, || ctx.client.edit_message_widget_data(&params)).await {
        Ok(_) => {}
        Err(err) if err.is_not_modified() => {}
        Err(err) => {
            info!(error = %err, "editMessageWidgetData rejected");
            return Ok(false);
        }
    }

    ctx.widgets
        .update_message_state(chat_id, message_id, inline_message_id, cd_patch, pd_patch)?;
    Ok(true)
}

/// Update `public_data` and optional `cache_time` on a shared widget, respecting the
/// shared-edit rate limit or updating bound In-Telegram WebApp cards directly.
pub async fn edit_shared_widget_safe<'a>(
    ctx: &Arc<BotCtx>,
    widget_id_or_slug: &str,
    public_data: Option<WidgetData<'a>>,
    cache_time: Option<u32>,
) -> Result<bool> {
    let wid = ctx
        .widgets
        .resolve_widget_id(widget_id_or_slug)
        .unwrap_or_else(|| widget_id_or_slug.to_string());
    let pd = match public_data {
        Some(v) => encode_widget_data(Some(v), true)?.unwrap_or_default(),
        None => String::new(),
    };

    let mut ww_ids = ctx.widgets.find_shared_targets(&wid);
    if ww_ids.is_empty() && ctx.widgets.get_webapp_widget(&wid).is_some() {
        ww_ids.push(wid.clone());
    }

    if !ww_ids.is_empty() {
        ctx.widgets
            .update_shared_state(&wid, Some(WidgetData::Str(&pd)), cache_time)?;
        for w_id in ww_ids {
            let _ = ctx.widgets.update_webapp_widget_state(
                &w_id,
                DataPatch::Unchanged,
                DataPatch::Set(WidgetData::Str(&pd)),
                None,
            );
            let _ = refresh_in_bubble_card(ctx, &w_id).await;
        }
        return Ok(true);
    }

    let delay_s = ctx.widgets.shared_edit_delay(&wid, None);
    if delay_s > 0.0 {
        sleep(Duration::from_secs_f64(delay_s)).await;
    }

    let params = EditSharedWidgetDataParams {
        widget_id: wid.clone(),
        public_data: pd.clone(),
        cache_time,
    };
    match tg_retry(1, 2.0, || ctx.client.edit_shared_widget_data(&params)).await {
        Ok(_) => {}
        Err(err) if err.is_not_modified() => {}
        Err(err) => {
            info!(wid = %wid, error = %err, "editSharedWidgetData rejected");
            return Ok(false);
        }
    }

    ctx.widgets
        .update_shared_state(&wid, Some(WidgetData::Str(&pd)), cache_time)?;
    Ok(true)
}

/// Dispatch an outbox `edit_message_data` or `edit_shared_data` action.
pub async fn edit_widget_action(
    ctx: &Arc<BotCtx>,
    chat_id: i64,
    action: &ParsedWidgetAction,
) -> Result<bool> {
    match action {
        ParsedWidgetAction::EditMessageData(EditMessageDataAction {
            chat_id: act_cid,
            message_id,
            inline_message_id,
            chat_data,
            public_data,
        }) => {
            let cid = act_cid.or_else(|| if inline_message_id.is_some() { None } else { Some(chat_id) });
            edit_message_widget_safe(
                ctx,
                cid,
                *message_id,
                inline_message_id.as_deref(),
                public_data.as_deref().map(WidgetData::Str),
                chat_data.as_deref().map(WidgetData::Str),
            )
            .await
        }
        ParsedWidgetAction::EditSharedData(EditSharedDataAction {
            widget_id,
            slug,
            public_data,
            cache_time,
        }) => {
            let target = widget_id
                .as_deref()
                .filter(|s| !s.is_empty())
                .or(slug.as_deref())
                .unwrap_or("");
            if target.is_empty() {
                return Ok(false);
            }
            let pd = public_data.as_deref().unwrap_or("");
            edit_shared_widget_safe(ctx, target, Some(WidgetData::Str(pd)), *cache_time).await
        }
        ParsedWidgetAction::Send(_) => Ok(false),
    }
}

fn safe_cb_with_prefix(prefix: &str, payload: &str) -> String {
    let avail = MAX_CB_DATA_BYTES.saturating_sub(prefix.len());
    format!("{prefix}{}", truncate_utf8_bytes(payload, avail))
}

/// Render or edit the `/widget` launcher menu card.
pub async fn show_widget_menu(
    ctx: &Arc<BotCtx>,
    cq: Option<&CallbackQuery>,
    chat_id: i64,
    uid: i64,
) {
    let lang = ctx.lang(uid);
    let rec = ctx.widgets.list_recent(8);
    let md = [
        format!("### {} {}", ctx.premium.md("party"), t(lang, Tx::PanelWidgetsTitle)),
        String::new(),
        "| Category | Count |".to_string(),
        "|---|---|".to_string(),
        format!("| Messages | `{}` |", rec.messages.len()),
        format!("| Shared | `{}` |", rec.shared.len()),
    ]
    .join("\n");

    let mk = BotCtx::kb(vec![
        vec![
            ctx.btn("skills", "Skills", Some("wmenu:send:skills"), Some("primary"), None),
            ctx.btn("mcp", "MCP", Some("wmenu:send:mcp"), Some("primary"), None),
        ],
        vec![
            ctx.btn("model", "Models", Some("wmenu:send:models"), None, None),
            ctx.btn("doc", "Memory", Some("wmenu:send:memory"), None, None),
        ],
        vec![
            ctx.btn("folder", "Tracked", Some("wmenu:list"), None, None),
            ctx.btn("menu", t(lang, Tx::BtnMenu), Some("home"), None, None),
        ],
    ]);

    let mid = cq.and_then(|c| c.message.as_ref()).map(|m| m.message_id);
    if let Err(err) = ctx
        .render
        .edit_or_send_rich(chat_id, mid, &md, Some(mk))
        .await
    {
        warn!(chat_id, error = %err, "show_widget_menu failed");
    }
}

/// Render or edit the `/widget list` tracked widgets card.
pub async fn show_widget_list(ctx: &Arc<BotCtx>, cq: Option<&CallbackQuery>, chat_id: i64) {
    let rec = ctx.widgets.list_recent(8);
    let mut lines = vec![
        format!("### {} ویجت‌های ردیابی‌شده", ctx.premium.md("folder")),
        String::new(),
    ];
    let mut rows: Vec<Vec<InlineKeyboardButton>> = Vec::new();

    if !rec.shared.is_empty() || !rec.messages.is_empty() {
        lines.push("| نوع | شناسه | توضیح |".to_string());
        lines.push("|---|---|---|".to_string());
        for s in rec.shared.iter().take(4) {
            let short_id = truncate_chars(&s.widget_id, 12);
            let slug = s.slug.as_deref().unwrap_or(&short_id);
            let cap = s.caption.as_deref().unwrap_or(slug);
            lines.push(format!(
                "| shared | `{}` | {} |",
                md_cell(&s.widget_id),
                md_cell(&truncate_chars(cap, 30))
            ));
            let resend_target = s
                .slug
                .as_deref()
                .filter(|v| !v.is_empty())
                .unwrap_or(&s.widget_id);
            let cb = safe_cb_with_prefix("wmenu:resend:", resend_target);
            rows.push(vec![ctx.btn(
                "",
                &format!("↻ {}", truncate_chars(slug, 22)),
                Some(&cb),
                None,
                None,
            )]);
        }
        for m in rec.messages.iter().take(4) {
            let mid_lbl = m
                .message_id
                .map(|v| v.to_string())
                .or_else(|| m.inline_message_id.clone())
                .unwrap_or_else(|| "—".to_string());
            let h_lbl = m.handler.as_deref().unwrap_or("static");
            let cap_lbl = truncate_chars(m.caption.as_deref().unwrap_or("—"), 24);
            lines.push(format!(
                "| msg | `{}` | {} · {} |",
                md_cell(&mid_lbl),
                md_cell(h_lbl),
                md_cell(&cap_lbl)
            ));
        }
    } else {
        lines.push("> هنوز ویجتی ارسال نشده است.".to_string());
    }

    rows.push(vec![
        ctx.btn("", "« Widgets", Some("wmenu:open"), None, None),
        ctx.btn("menu", "Menu", Some("home"), None, None),
    ]);

    let mid = cq.and_then(|c| c.message.as_ref()).map(|m| m.message_id);
    if let Err(err) = ctx
        .render
        .edit_or_send_rich(chat_id, mid, &lines.join("\n"), Some(BotCtx::kb(rows)))
        .await
    {
        warn!(chat_id, error = %err, "show_widget_list failed");
    }
}

fn strip_markdown_code_fence(raw: &str) -> &str {
    let trimmed = raw.trim();
    if let Some(after_open) = trimmed.strip_prefix("```") {
        if let Some(nl) = after_open.find('\n') {
            let body = &after_open[nl + 1..];
            if let Some(stripped_close) = body.strip_suffix("```") {
                return stripped_close.trim();
            }
        }
    }
    trimmed
}

fn build_shared_resend_spec(ctx: &BotCtx, target: &str) -> WidgetSpec {
    let wid = ctx
        .widgets
        .resolve_widget_id(target)
        .unwrap_or_else(|| target.to_string());
    let sh = ctx.widgets.get_shared(&wid);
    let wrec = ctx.widgets.get_webapp_widget(&wid);
    WidgetSpec {
        widget_id: Some(wid),
        slug: sh
            .as_ref()
            .and_then(|s| s.slug.clone())
            .or_else(|| wrec.as_ref().and_then(|r| r.slug.clone())),
        handler: sh
            .as_ref()
            .and_then(|s| s.handler.clone())
            .or_else(|| wrec.as_ref().and_then(|r| r.handler.clone())),
        caption: sh
            .as_ref()
            .and_then(|s| s.caption.clone())
            .or_else(|| wrec.as_ref().and_then(|r| r.caption.clone())),
        is_shared: Some(true),
        ..Default::default()
    }
}

/// Handle `/widget [skills|mcp|models|memory|list|resend <id>|edit <mid> <json>|shared <id> <json> [ct]|check]`.
pub async fn cmd_widget(ctx: &Arc<BotCtx>, msg: &Message, arg: &str) {
    let trimmed = arg.trim();
    let uid = msg
        .from_user
        .as_ref()
        .map(|u| u.id)
        .unwrap_or(msg.chat.id);
    if !ctx.has_perm(uid, "widgets") {
        let _ = ctx
            .render
            .send_html_simple(msg.chat.id, &missing_perm_html(ctx, uid, "widgets"), None)
            .await;
        return;
    }

    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("menu") {
        show_widget_menu(ctx, None, msg.chat.id, uid).await;
        return;
    }

    let mut split3 = trimmed.splitn(3, char::is_whitespace);
    let sub_raw = split3.next().unwrap_or("");
    let p1 = split3.next().map(str::trim).unwrap_or("");
    let p2 = split3.next().map(str::trim).unwrap_or("");
    let sub = sub_raw.to_ascii_lowercase();

    if BUILTIN_WIDGET_KINDS.contains(&sub.as_str()) {
        match build_builtin_widget(ctx, &sub, uid).await {
            Ok(sp) => {
                if let Err(err) = send_widget_safe(ctx, msg.chat.id, sp).await {
                    warn!(error = %err, kind = %sub, "failed sending built-in widget");
                }
            }
            Err(err) => {
                let _ = ctx
                    .render
                    .send_html_simple(msg.chat.id, &format!("⚠️ <i>{}</i>", esc(&err.to_string())), None)
                    .await;
            }
        }
        return;
    }

    if sub == "list" {
        show_widget_list(ctx, None, msg.chat.id).await;
        return;
    }

    if sub == "resend" && !p1.is_empty() {
        let sp = build_shared_resend_spec(ctx, p1);
        let _ = send_widget_safe(ctx, msg.chat.id, sp).await;
        return;
    }

    if sub == "edit" && !p1.is_empty() && !p2.is_empty() {
        if let Ok(mid) = p1.parse::<i64>() {
            let payload = if matches!(p2, "\"\"" | "''" | "clear") {
                ""
            } else {
                p2
            };
            let ok = edit_message_widget_safe(
                ctx,
                Some(msg.chat.id),
                Some(mid),
                None,
                None,
                Some(WidgetData::Str(payload)),
            )
            .await
            .unwrap_or(false);
            let txt = if ok {
                "✅ <i>Updated message widget data.</i>"
            } else {
                "⚠️ <i>Failed to update widget data.</i>"
            };
            let _ = ctx.render.send_html_simple(msg.chat.id, txt, None).await;
            return;
        }
    }

    if sub == "shared" && !p1.is_empty() && !p2.is_empty() {
        let mut rest = p2;
        let mut ct: Option<u32> = None;
        if let Some((maybe_payload, maybe_ct)) = rest.rsplit_once(' ') {
            if !maybe_ct.is_empty() && maybe_ct.chars().all(|c| c.is_ascii_digit()) {
                if let Ok(parsed_ct) = maybe_ct.parse::<u32>() {
                    rest = maybe_payload.trim();
                    ct = Some(parsed_ct);
                }
            }
        }
        let payload = if matches!(rest, "\"\"" | "''" | "clear") {
            ""
        } else {
            rest
        };
        let ok = edit_shared_widget_safe(ctx, p1, Some(WidgetData::Str(payload)), ct)
            .await
            .unwrap_or(false);
        let txt = if ok {
            "✅ <i>Updated shared widget data.</i>"
        } else {
            "⚠️ <i>Failed to update shared widget.</i>"
        };
        let _ = ctx.render.send_html_simple(msg.chat.id, txt, None).await;
        return;
    }

    if sub == "check" {
        let mut raw_html = String::new();
        if let Some(ref rep) = msg.reply_to_message {
            if let Some(ref w) = rep.widget {
                if let Some(ref h) = w.html {
                    raw_html = h.clone();
                }
            }
            if raw_html.is_empty() {
                raw_html = rep
                    .text
                    .clone()
                    .or_else(|| rep.caption.clone())
                    .unwrap_or_default();
            }
        } else if trimmed.len() > sub_raw.len() {
            raw_html = trimmed[sub_raw.len()..].trim().to_string();
        }

        let html_src = strip_markdown_code_fence(&raw_html);
        if html_src.is_empty() {
            let _ = ctx
                .render
                .send_html_simple(
                    msg.chat.id,
                    "<i>Reply to a widget or HTML message with </i><code>/widget check</code>.",
                    None,
                )
                .await;
            return;
        }

        let sz = count_widget_size(html_src);
        let warns = lint_widget_profile(html_src);
        let wtxt = if warns.is_empty() {
            "None — Profile-1 clean ✅".to_string()
        } else {
            warns
                .iter()
                .take(8)
                .map(|w| format!("• {}", esc(w)))
                .collect::<Vec<_>>()
                .join("\n")
        };
        let report = format!(
            "🔍 <b>Widget Check</b>\n\
            <blockquote><b>Raw</b>  {} / {WIDGET_HTML_RAW_LIMIT} B\n\
            <b>Zlib-9</b>  {} / {WIDGET_HTML_ZLIB_LIMIT} B\n\
            <b>NUL</b>  {}\n\
            <b>Size OK</b>  {}</blockquote>\n\
            <b>Profile-1 Lint ({})</b>\n{wtxt}",
            sz.raw_bytes,
            sz.zlib_bytes,
            if sz.has_nul { "yes ❌" } else { "no" },
            if sz.ok { "yes ✅" } else { "no ❌" },
            warns.len(),
        );
        let _ = ctx.render.send_html_simple(msg.chat.id, &report, None).await;
        return;
    }

    let _ = ctx
        .render
        .send_html_simple(
            msg.chat.id,
            "<b>Usage:</b> <code>/widget</code> [skills|mcp|models|memory|list|resend &lt;id&gt;|edit &lt;mid&gt; &lt;json&gt;|shared &lt;id&gt; &lt;json&gt;|check]",
            None,
        )
        .await;
}

/// Handle `wmenu:*` and `wact:*` inline keyboard callbacks, returning `true` when consumed.
pub async fn handle_widget_cb(
    ctx: &Arc<BotCtx>,
    cq: &CallbackQuery,
    uid: i64,
    chat_id: i64,
    data: &str,
) -> bool {
    if data.starts_with("wmenu:") && !ctx.has_perm(uid, "widgets") {
        let lang = ctx.lang(uid);
        let msg = format!("{} {}", t(lang, Tx::ModuleRequiredHdr), perm_label(lang, "widgets"));
        ctx.ack(&cq.id, Some(&msg), true).await;
        return true;
    }

    if data == "wmenu:open" {
        ctx.ack(&cq.id, None, false).await;
        show_widget_menu(ctx, Some(cq), chat_id, uid).await;
        return true;
    }

    if data == "wmenu:list" {
        ctx.ack(&cq.id, None, false).await;
        show_widget_list(ctx, Some(cq), chat_id).await;
        return true;
    }

    if let Some(kind) = data.strip_prefix("wmenu:send:") {
        ctx.ack(&cq.id, None, false).await;
        if BUILTIN_WIDGET_KINDS.contains(&kind) {
            if let Ok(sp) = build_builtin_widget(ctx, kind, uid).await {
                let _ = send_widget_safe(ctx, chat_id, sp).await;
            }
        }
        return true;
    }

    if let Some(target) = data.strip_prefix("wmenu:resend:") {
        ctx.ack(&cq.id, None, false).await;
        let sp = build_shared_resend_spec(ctx, target);
        let _ = send_widget_safe(ctx, chat_id, sp).await;
        return true;
    }

    if let Some(rest) = data.strip_prefix("wact:") {
        let Some((wid, act)) = rest.split_once(':') else {
            ctx.ack(&cq.id, None, false).await;
            return true;
        };

        let Some(rec) = ctx.widgets.get_webapp_widget(wid) else {
            ctx.ack(&cq.id, Some("Widget expired"), false).await;
            return true;
        };

        let h_low = rec
            .handler
            .as_deref()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();

        if let Some(tval) = act.strip_prefix("tab:") {
            let _ = ctx.widgets.update_webapp_widget_state(
                wid,
                DataPatch::Unchanged,
                DataPatch::Unchanged,
                Some(tval),
            );
            let _ = refresh_in_bubble_card(ctx, wid).await;
            ctx.ack(&cq.id, Some(&format!("Tab: {tval}")), false).await;
            return true;
        }

        if act == "refresh" && !BUILTIN_WIDGET_KINDS.contains(&h_low.as_str()) {
            let _ = refresh_in_bubble_card(ctx, wid).await;
            ctx.ack(&cq.id, Some("Updated"), false).await;
            return true;
        }

        let eff_act = if act == "refresh" {
            match h_low.as_str() {
                "skills" => "sk:ref",
                "mcp" => "mcp:ref",
                "models" => "mdl:ref",
                "memory" => "mem:ref",
                _ => act,
            }
        } else {
            act
        };

        let bridge = BotWebAppBridge::new(ctx.clone());
        use agy_widgets::webapp::WidgetBridge;
        let out = match bridge
            .query_widget(wid, &h_low, eff_act, uid, Some(chat_id))
            .await
        {
            Ok(res) => res,
            Err(err) => {
                ctx.ack(&cq.id, Some(&truncate_chars(&err.to_string(), 160)), false)
                    .await;
                return true;
            }
        };

        let cd_str = out
            .chat_data
            .as_ref()
            .and_then(|v| encode_widget_data(Some(WidgetData::Value(v)), true).ok())
            .flatten();
        let pd_str = out
            .public_data
            .as_ref()
            .and_then(|v| encode_widget_data(Some(WidgetData::Value(v)), true).ok())
            .flatten();

        let cd_patch = match cd_str.as_deref() {
            Some(s) => DataPatch::Set(WidgetData::Str(s)),
            None => DataPatch::Unchanged,
        };
        let pd_patch = match pd_str.as_deref() {
            Some(s) => DataPatch::Set(WidgetData::Str(s)),
            None => DataPatch::Unchanged,
        };
        let tab_patch = eff_act.strip_prefix("sk:t:");

        if !matches!(cd_patch, DataPatch::Unchanged)
            || !matches!(pd_patch, DataPatch::Unchanged)
            || tab_patch.is_some()
        {
            let _ = ctx
                .widgets
                .update_webapp_widget_state(wid, cd_patch, pd_patch, tab_patch);
        }

        let _ = refresh_in_bubble_card(ctx, wid).await;

        let toast = if out.result.get("ok").and_then(Value::as_bool) == Some(false) {
            out.result
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("Error")
        } else {
            "Updated"
        };
        ctx.ack(&cq.id, Some(&truncate_chars(toast, 160)), false)
            .await;
        return true;
    }

    false
}

/// Handle an incoming Telegram widget message sent by a user, saving `.html` and `.json`
/// to `inbox/<uid>/` and enqueueing immediately when a caption is attached.
pub async fn handle_widget_message(ctx: &Arc<BotCtx>, msg: &Message) -> bool {
    let (Some(w), Some(from_user)) = (&msg.widget, &msg.from_user) else {
        return false;
    };
    let html_src = w.html.as_deref().unwrap_or("");
    let uid = from_user.id;
    let user_inbox = ctx.cfg.inbox_dir().join(uid.to_string());
    if let Err(err) = fs::create_dir_all(&user_inbox) {
        warn!(uid, error = %err, "failed creating widget inbox directory");
        return true;
    }

    let ts = Local::now().format("%Y%m%d-%H%M%S").to_string();
    let html_path = user_inbox.join(format!("{ts}_widget_{}.html", msg.message_id));
    let json_path = user_inbox.join(format!("{ts}_widget_{}.json", msg.message_id));

    if let Err(err) = fs::write(&html_path, html_src) {
        warn!(path = %html_path.display(), error = %err, "failed saving widget html");
    }
    let meta_json = serde_json::to_string_pretty(w).unwrap_or_else(|_| "{}".to_string());
    if let Err(err) = fs::write(&json_path, meta_json) {
        warn!(path = %json_path.display(), error = %err, "failed saving widget json");
    }

    let sz = count_widget_size(html_src);
    let warns = lint_widget_profile(html_src);

    if let Some(caption) = msg.caption.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        let mut attachments = take_pending_widget_files(ctx, uid);
        attachments.push(html_path);
        attachments.push(json_path);
        let req = JobRequest::new(
            uid,
            msg.chat.id,
            from_user.display_label(),
            caption.to_string(),
            attachments,
        );
        if let Err(err) = ctx.jobs.enqueue(req).await {
            warn!(uid, error = %err, "failed enqueueing captioned widget message");
        }
        return true;
    }

    let fname = html_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("widget.html")
        .to_string();
    push_pending_widget_files(ctx, uid, vec![html_path, json_path]);

    let summary = format!(
        "{} Saved widget <code>{}</code> (raw {} B, zlib-9 {} B, lint {})\n<i>Send instructions, or analyze now.</i>",
        ctx.e("new"),
        esc(&fname),
        sz.raw_bytes,
        sz.zlib_bytes,
        warns.len(),
    );
    let mk = BotCtx::kb(vec![vec![
        ctx.btn("rocket", "Analyze", Some("files:run"), Some("primary"), None),
        ctx.btn("", "Discard", Some("files:drop"), None, None),
    ]]);
    let _ = ctx
        .render
        .send_html_simple(msg.chat.id, &summary, Some(mk))
        .await;
    true
}

/// Clamp `answerWidgetQuery` JSON payload to `<= 1024` UTF-8 bytes while guaranteeing valid JSON.
pub fn clamp_ans_json(payload: &Value) -> String {
    let raw = match payload {
        Value::String(s) => s.clone(),
        other => serde_json::to_string(other).unwrap_or_else(|_| "{}".to_string()),
    };
    if raw.len() <= WIDGET_ANSWER_DATA_LIMIT {
        return raw;
    }
    if let Value::Object(map) = payload {
        if let Ok((trimmed, _)) = agy_widgets::WidgetStore::bump_rev(map) {
            if trimmed.len() <= WIDGET_ANSWER_DATA_LIMIT {
                return trimmed;
            }
        }
        // Compact safely so QuickJS JSON.parse() never receives truncated invalid JSON
        let mut minimal = serde_json::Map::new();
        for key in ["ok", "status", "error", "rev", "msg", "toast", "tab", "page"] {
            if let Some(v) = map.get(key) {
                minimal.insert(key.to_string(), v.clone());
            }
        }
        minimal.insert("truncated".to_string(), Value::Bool(true));
        if let Ok(s) = serde_json::to_string(&Value::Object(minimal)) {
            if s.len() <= WIDGET_ANSWER_DATA_LIMIT {
                return s;
            }
        }
    }
    r#"{"ok":true,"truncated":true}"#.to_string()
}

#[allow(clippy::too_many_arguments)]
async fn dispatch_any_widget_query(
    ctx: &Arc<BotCtx>,
    query_id: &str,
    from_user: &User,
    chat_id: Option<i64>,
    message_id: Option<i64>,
    inline_message_id: Option<&str>,
    widget_id: Option<&str>,
    data: Option<&str>,
    kind: &WidgetQueryType,
    is_shared_forward: bool,
) {
    let uid = from_user.id;
    let target_chat = chat_id.unwrap_or(uid);
    let raw_data = data.unwrap_or("");
    let mut ans_sent = false;

    async fn send_reply(ctx: &BotCtx, qid: &str, payload: &Value, ans_sent: &mut bool) {
        if !*ans_sent {
            *ans_sent = true;
            let clamped = clamp_ans_json(payload);
            let _ = ctx
                .client
                .answer_widget_query(qid, Some(&clamped))
                .await;
        }
    }

    match kind {
        WidgetQueryType::SignData { wallet, sign_data } => {
            let _ = ctx.widgets.record_wallet_event(
                uid,
                "sign_data",
                json!({
                    "address": wallet.address,
                    "amount": wallet.amount,
                    "data": raw_data,
                    "sign_data": truncate_chars(sign_data, 256),
                }),
            );
            send_reply(
                ctx,
                query_id,
                &json!({
                    "ok": true,
                    "kind": "sign_data",
                    "address": wallet.address,
                    "amount": wallet.amount,
                }),
                &mut ans_sent,
            )
            .await;
            if let Some(prompt) = raw_data
                .strip_prefix("ask:")
                .or_else(|| raw_data.strip_prefix("agy:"))
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                let req = JobRequest::new(
                    uid,
                    target_chat,
                    from_user.display_label(),
                    format!("[widget sign_data address={}] {prompt}", wallet.address),
                    Vec::new(),
                );
                let _ = ctx.jobs.enqueue(req).await;
            }
            return;
        }
        WidgetQueryType::SentTransaction { wallet, msg_hash } => {
            let _ = ctx.widgets.record_wallet_event(
                uid,
                "sent_transaction",
                json!({
                    "address": wallet.address,
                    "amount": wallet.amount,
                    "msg_hash": msg_hash,
                    "data": raw_data,
                }),
            );
            send_reply(
                ctx,
                query_id,
                &json!({
                    "ok": true,
                    "kind": "sent_transaction",
                    "msg_hash": msg_hash,
                    "address": wallet.address,
                }),
                &mut ans_sent,
            )
            .await;
            if let Some(prompt) = raw_data
                .strip_prefix("ask:")
                .or_else(|| raw_data.strip_prefix("agy:"))
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                let req = JobRequest::new(
                    uid,
                    target_chat,
                    from_user.display_label(),
                    format!("[widget sent_transaction hash={msg_hash}] {prompt}"),
                    Vec::new(),
                );
                let _ = ctx.jobs.enqueue(req).await;
            }
            return;
        }
        WidgetQueryType::Data { .. } | WidgetQueryType::Unknown => {}
    }

    let msg_rec = if inline_message_id.is_some() || (chat_id.is_some() && message_id.is_some()) {
        ctx.widgets.get_message(chat_id, message_id, inline_message_id)
    } else {
        None
    };
    let sh_rec = widget_id.and_then(|wid| ctx.widgets.get_shared(wid));

    let handler_name = msg_rec
        .as_ref()
        .and_then(|r| r.handler.as_deref())
        .or_else(|| sh_rec.as_ref().and_then(|s| s.handler.as_deref()))
        .unwrap_or("")
        .to_ascii_lowercase();

    let cur_cd = msg_rec.as_ref().and_then(|r| r.chat_data.as_deref());
    let cur_pd = sh_rec
        .as_ref()
        .and_then(|s| s.public_data.as_deref())
        .or_else(|| msg_rec.as_ref().and_then(|r| r.public_data.as_deref()));

    let vote_key = widget_id
        .map(str::to_string)
        .or_else(|| inline_message_id.map(|s| format!("inline:{s}")))
        .unwrap_or_else(|| format!("{target_chat}:{}", message_id.unwrap_or(0)));

    let wallet_card = match kind {
        WidgetQueryType::Data { wallet_card } => wallet_card.as_ref(),
        _ => None,
    };

    let (payload, new_cd, new_pd) = execute_widget_data_action(
        ctx,
        uid,
        target_chat,
        from_user,
        raw_data,
        &handler_name,
        cur_cd,
        cur_pd,
        &vote_key,
        wallet_card,
        widget_id,
        message_id,
    )
    .await;

    send_reply(ctx, query_id, &payload, &mut ans_sent).await;

    if let (Some(pd_val), Some(wid)) = (&new_pd, widget_id) {
        let _ = edit_shared_widget_safe(ctx, wid, Some(WidgetData::Value(pd_val)), None).await;
    } else if (new_cd.is_some() || new_pd.is_some())
        && !is_shared_forward
        && (inline_message_id.is_some() || (chat_id.is_some() && message_id.is_some()))
    {
        let _ = edit_message_widget_safe(
            ctx,
            chat_id,
            message_id,
            inline_message_id,
            new_pd.as_ref().map(WidgetData::Value),
            new_cd.as_ref().map(WidgetData::Value),
        )
        .await;
    }

    if !ans_sent {
        send_reply(
            ctx,
            query_id,
            &json!({ "ok": false, "error": "internal" }),
            &mut ans_sent,
        )
        .await;
    }
}

/// Handle a `widget_query` update from Telegram Bot API 10.4.
pub async fn handle_widget_query(ctx: &Arc<BotCtx>, wq: &WidgetQuery) {
    dispatch_any_widget_query(
        ctx,
        &wq.id,
        &wq.from_user,
        wq.chat.as_ref().map(|c| c.id),
        wq.message_id,
        wq.inline_message_id.as_deref(),
        wq.widget_id.as_deref(),
        wq.data.as_deref(),
        &wq.kind,
        false,
    )
    .await;
}

/// Handle a `shared_widget_query` update from Telegram Bot API 10.4.
pub async fn handle_shared_widget_query(ctx: &Arc<BotCtx>, swq: &SharedWidgetQuery) {
    dispatch_any_widget_query(
        ctx,
        &swq.id,
        &swq.from_user,
        None,
        None,
        None,
        Some(&swq.widget_id),
        swq.data.as_deref(),
        &swq.kind,
        true,
    )
    .await;
}

/// Handle Telegram `inline_query` updates by offering built-in interactive widgets.
pub async fn handle_inline_query(ctx: &Arc<BotCtx>, iq: &InlineQuery) {
    let uid = iq.from_user.id;
    let q = iq.query.trim().to_ascii_lowercase();
    let mut articles: Vec<InlineQueryResultArticle> = Vec::new();

    if ctx.cfg.allow_inline_widgets {
        for kind in BUILTIN_WIDGET_KINDS {
            if !q.is_empty() && !kind.contains(&q) && !q.contains(kind) {
                continue;
            }
            if let Ok(sp) = build_builtin_widget(ctx, kind, uid).await {
                let title = sp
                    .caption
                    .clone()
                    .unwrap_or_else(|| format!("Antigravity {kind}"));
                let desc = format!("Interactive {kind} widget");
                if let Ok(article) =
                    build_inline_widget_article(&format!("builtin:{kind}"), &title, &sp, Some(&desc))
                {
                    articles.push(article);
                }
            }
        }
    }

    if let Err(err) = ctx
        .client
        .answer_inline_query(&iq.id, &articles, Some(15), Some(true))
        .await
    {
        warn!(uid, error = %err, "answerInlineQuery failed");
    }
}

/// Process optional `$STATE_DIR/widget_once.json` startup test/bootstrap trigger once.
pub async fn consume_startup_widget_once(
    ctx: &Arc<BotCtx>,
    approved_uids: &[i64],
) -> Result<Option<Value>> {
    let once_file = ctx.cfg.state_dir.join("widget_once.json");
    if !once_file.is_file() {
        return Ok(None);
    }

    let raw_w = fs::read_to_string(&once_file)
        .map_err(|e| BridgeError::io(format!("reading {}", once_file.display()), e))?;
    let _ = fs::remove_file(&once_file);

    let obj_w: Value = serde_json::from_str(&raw_w)
        .map_err(|e| BridgeError::json("parsing widget_once.json", e))?;

    let target_uids: Vec<i64> = match obj_w.get("uid").and_then(Value::as_i64) {
        Some(req_uid) => {
            if ctx.is_approved(req_uid) {
                vec![req_uid]
            } else {
                Vec::new()
            }
        }
        None => {
            let _ = approved_uids;
            vec![ctx.cfg.owner_id]
        }
    };

    let builtins_list: Option<Vec<String>> =
        if let Some(arr) = obj_w.get("builtins").and_then(Value::as_array) {
            Some(
                arr.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect(),
            )
        } else {
            obj_w
                .get("builtin")
                .and_then(Value::as_str)
                .map(|b| vec![b.to_string()])
        };

    let mut w_results = serde_json::Map::new();
    for uid in target_uids {
        let mut specs_for_uid: Vec<WidgetSpec> = Vec::new();
        if let Some(ref kinds) = builtins_list {
            for bkind in kinds {
                if BUILTIN_WIDGET_KINDS.contains(&bkind.as_str()) {
                    if let Ok(sp) = build_builtin_widget(ctx, bkind, uid).await {
                        specs_for_uid.push(sp);
                    }
                }
            }
        } else if let Ok(ParsedWidgetAction::Send(sp)) = parse_widget_json(&obj_w, None) {
            specs_for_uid.push(*sp);
        }

        let mut uid_entries: Vec<Value> = Vec::new();
        for sp in specs_for_uid {
            match send_widget_safe(ctx, uid, sp).await {
                Ok((m_opt, status_w)) => {
                    uid_entries.push(json!({
                        "status": status_w,
                        "message_id": m_opt.map(|m| m.message_id),
                    }));
                }
                Err(err) => {
                    warn!(uid, error = %err, "startup widget_once send failed");
                    uid_entries.push(json!({
                        "status": format!("error:{}", truncate_chars(&err.to_string(), 80)),
                        "message_id": Value::Null,
                    }));
                }
            }
        }

        if uid_entries.len() == 1 {
            w_results.insert(uid.to_string(), uid_entries.remove(0));
        } else if !uid_entries.is_empty() {
            w_results.insert(uid.to_string(), Value::Array(uid_entries));
        }
    }

    let results_val = Value::Object(w_results);
    ctx.store
        .set_meta("last_widget_startup", results_val.clone())?;
    Ok(Some(results_val))
}

fn send_outbox_widget_error(ctx: &Arc<BotCtx>, chat_id: i64, path: &Path, err: &BridgeError) {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("widget");
    let msg = format!(
        "⚠️ <b>Widget file error</b> (<code>{}</code>): <code>{}</code>",
        esc(name),
        esc(&truncate_chars(&err.to_string(), 200))
    );
    let client_ctx = ctx.clone();
    tokio::spawn(async move {
        let _ = client_ctx
            .render
            .send_html_simple(chat_id, &msg, None)
            .await;
    });
}

fn extract_consumed_html_path(obj: &Value, json_path: &Path) -> Option<PathBuf> {
    let raw_hf = obj.get("html_file").and_then(Value::as_str)?;
    let trimmed = raw_hf.trim();
    if trimmed.is_empty() {
        return None;
    }
    let p = PathBuf::from(trimmed);
    let resolved = if p.is_absolute() {
        p
    } else {
        json_path.parent().unwrap_or_else(|| Path::new(".")).join(p)
    };
    Some(resolved.canonicalize().unwrap_or(resolved))
}

fn is_widget_json_sidecar(obj: &serde_json::Map<String, Value>, json_path: &Path) -> bool {
    const ACTION_KEYS: [&str; 6] = ["action", "html", "html_file", "builtin", "widget_id", "slug"];
    let has_action_key = ACTION_KEYS.iter().any(|k| obj.contains_key(*k));
    if has_action_key {
        return false;
    }
    json_path.with_extension("html").is_file()
}

/// Deliver a single `.widget.json` or `.widget.html` outbox file to `chat_id`.
pub async fn deliver_outbox_widget_file(ctx: &Arc<BotCtx>, chat_id: i64, path: &Path) -> bool {
    let fname = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");

    if fname.ends_with(".widget.json") {
        let raw_txt = match fs::read_to_string(path) {
            Ok(t) => t,
            Err(err) => {
                let berr = BridgeError::io(format!("read {}", path.display()), err);
                warn!(file = fname, error = %berr, "outbox widget json failed");
                send_outbox_widget_error(ctx, chat_id, path, &berr);
                return false;
            }
        };

        if let Ok(Value::Object(ref obj)) = serde_json::from_str::<Value>(&raw_txt) {
            if is_widget_json_sidecar(obj, path) {
                return false;
            }
        }

        let parsed = match parse_widget_json(raw_txt.as_str(), path.parent()) {
            Ok(p) => p,
            Err(err) => {
                warn!(file = fname, error = %err, "outbox widget json parse failed");
                let _ = ctx
                    .render
                    .send_html_simple(
                        chat_id,
                        &format!(
                            "⚠️ <b>Widget file error</b> (<code>{}</code>): <code>{}</code>",
                            esc(fname),
                            esc(&truncate_chars(&err.to_string(), 200))
                        ),
                        None,
                    )
                    .await;
                return false;
            }
        };

        return match parsed {
            ParsedWidgetAction::Send(sp) => send_widget_safe(ctx, chat_id, *sp)
                .await
                .is_ok_and(|(m, _)| m.is_some()),
            ref edit_act => edit_widget_action(ctx, chat_id, edit_act)
                .await
                .unwrap_or(false),
        };
    }

    if fname.ends_with(".widget.html") {
        let sp = match parse_widget_html_file(path) {
            Ok(s) => s,
            Err(err) => {
                warn!(file = fname, error = %err, "outbox widget html failed");
                let _ = ctx
                    .render
                    .send_html_simple(
                        chat_id,
                        &format!(
                            "⚠️ <b>Widget file error</b> (<code>{}</code>): <code>{}</code>",
                            esc(fname),
                            esc(&truncate_chars(&err.to_string(), 200))
                        ),
                        None,
                    )
                    .await;
                return false;
            }
        };
        return send_widget_safe(ctx, chat_id, sp)
            .await
            .is_ok_and(|(m, _)| m.is_some());
    }

    false
}

/// Deliver all `.widget.json` and `.widget.html` files in `dir`, deduplicating `html_file` targets
/// referenced by `.widget.json` manifests, and return canonicalized paths of all widget files handled.
pub async fn deliver_outbox_widgets_in_dir(
    ctx: &Arc<BotCtx>,
    chat_id: i64,
    dir: &Path,
) -> HashSet<PathBuf> {
    let mut handled = HashSet::new();
    let Ok(entries) = fs::read_dir(dir) else {
        return handled;
    };

    let mut wjson_files: Vec<PathBuf> = Vec::new();
    let mut whtml_files: Vec<PathBuf> = Vec::new();
    for entry in entries.flatten() {
        let p = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with('.') {
            continue;
        }
        let Ok(meta) = fs::symlink_metadata(&p) else {
            continue;
        };
        if meta.file_type().is_symlink() || !meta.is_file() {
            continue;
        }
        if name.ends_with(".widget.json") {
            wjson_files.push(p);
        } else if name.ends_with(".widget.html") {
            whtml_files.push(p);
        }
    }
    wjson_files.sort();
    whtml_files.sort();

    let mut consumed_html: HashSet<PathBuf> = HashSet::new();
    for p in wjson_files {
        let canon = p.canonicalize().unwrap_or_else(|_| p.clone());
        handled.insert(canon);
        if let Ok(raw_txt) = fs::read_to_string(&p) {
            if let Ok(val) = serde_json::from_str::<Value>(&raw_txt) {
                if let Some(hf) = extract_consumed_html_path(&val, &p) {
                    consumed_html.insert(hf);
                }
            }
        }
        let _ = deliver_outbox_widget_file(ctx, chat_id, &p).await;
    }

    for p in whtml_files {
        let canon = p.canonicalize().unwrap_or_else(|_| p.clone());
        handled.insert(canon.clone());
        if consumed_html.contains(&canon) {
            continue;
        }
        let _ = deliver_outbox_widget_file(ctx, chat_id, &p).await;
    }

    handled
}

/// Extract inline `<tg-widget>` and `<tg-shared-widget>` tags from markdown, send them safely,
/// and return the cleaned markdown text.
pub async fn extract_and_send_markdown_widgets(
    ctx: &Arc<BotCtx>,
    chat_id: i64,
    md: &str,
) -> Result<String> {
    let (cleaned, specs) = match extract_widgets_from_markdown(md) {
        Ok(res) => res,
        Err(err) => {
            error!(chat_id, error = %err, "extract_widgets_from_markdown failed");
            return Ok(md.to_string());
        }
    };
    for sp in specs {
        if let Err(err) = send_widget_safe(ctx, chat_id, sp).await {
            warn!(chat_id, error = %err, "inline markdown widget send failed");
        }
    }
    Ok(cleaned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    use axum::extract::State;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use axum::routing::{get, post};
    use axum::{Json, Router};
    use tokio::net::TcpListener;

    use agy_core::acl::{AclStore, RolePreset};
    use agy_core::config::Config;
    use agy_core::health::HealthTracker;
    use agy_core::outbox::OutQueue;
    use agy_core::store::StateStore;
    use agy_core::tg::{Chat, InlineQuery, Message, SharedWidgetQuery, WidgetQuery, WidgetQueryWallet};
    use agy_net::proxy::NetConfig;
    use agy_net::{BotApiClient, ProxyPool};
    use agy_render::premium::PremiumState;
    use agy_widgets::store::WidgetStore;
    use tempfile::TempDir;

    use crate::auth::AuthGate;
    use crate::cron::CronScheduler;
    use crate::jobs::JobManager;
    use crate::render_bridge::RenderBridge;

    #[derive(Clone, Default)]
    struct MockTgState {
        calls: Arc<Mutex<Vec<(String, Value)>>>,
        next_msg_id: Arc<Mutex<i64>>,
        send_widget_error: Arc<Mutex<Option<(u16, String)>>>,
        edit_widget_error: Arc<Mutex<Option<(u16, String)>>>,
        edit_message_error: Arc<Mutex<Option<(u16, String)>>>,
        rich_rejected: Arc<Mutex<bool>>,
    }

    impl MockTgState {
        fn record(&self, method: &str, body: Value) {
            self.calls
                .lock()
                .unwrap()
                .push((method.to_string(), body));
        }

        fn next_id(&self) -> i64 {
            let mut g = self.next_msg_id.lock().unwrap();
            *g += 1;
            *g
        }

        fn methods(&self) -> Vec<String> {
            self.calls
                .lock()
                .unwrap()
                .iter()
                .map(|(m, _)| m.clone())
                .collect()
        }

        fn last_body(&self, method: &str) -> Option<Value> {
            self.calls
                .lock()
                .unwrap()
                .iter()
                .rev()
                .find(|(m, _)| m == method)
                .map(|(_, b)| b.clone())
        }
    }

    fn err_json(code: u16, desc: &str) -> (StatusCode, Json<Value>) {
        let status = StatusCode::from_u16(code).unwrap_or(StatusCode::BAD_REQUEST);
        (
            status,
            Json(json!({
                "ok": false,
                "error_code": code,
                "description": desc,
            })),
        )
    }

    async fn mock_get_me() -> Json<Value> {
        Json(json!({
            "ok": true,
            "result": { "id": 999, "is_bot": true, "first_name": "AgyBot", "username": "agy_test_bot" }
        }))
    }

    async fn mock_send_widget(
        State(st): State<MockTgState>,
        Json(body): Json<Value>,
    ) -> impl IntoResponse {
        st.record("sendWidget", body.clone());
        if let Some((code, desc)) = st.send_widget_error.lock().unwrap().clone() {
            return err_json(code, &desc).into_response();
        }
        let mid = st.next_id();
        let chat_id = body["chat_id"].as_i64().unwrap_or(1001);
        let shared_id = if body.get("is_shared").and_then(Value::as_bool) == Some(true) {
            Some(format!("sh_{mid}"))
        } else {
            None
        };
        Json(json!({
            "ok": true,
            "result": {
                "message_id": mid,
                "chat": { "id": chat_id, "type": "private" },
                "widget": { "id": shared_id }
            }
        }))
        .into_response()
    }

    async fn mock_send_shared_widget(
        State(st): State<MockTgState>,
        Json(body): Json<Value>,
    ) -> impl IntoResponse {
        st.record("sendSharedWidget", body.clone());
        if let Some((code, desc)) = st.send_widget_error.lock().unwrap().clone() {
            return err_json(code, &desc).into_response();
        }
        let mid = st.next_id();
        let chat_id = body["chat_id"].as_i64().unwrap_or(1001);
        let wid = body["widget_id"].as_str().unwrap_or("sh_0");
        Json(json!({
            "ok": true,
            "result": {
                "message_id": mid,
                "chat": { "id": chat_id, "type": "private" },
                "widget": { "id": wid }
            }
        }))
        .into_response()
    }

    async fn mock_edit_widget_data(
        State(st): State<MockTgState>,
        Json(body): Json<Value>,
    ) -> impl IntoResponse {
        st.record("editMessageWidgetData", body);
        if let Some((code, desc)) = st.edit_widget_error.lock().unwrap().clone() {
            return err_json(code, &desc).into_response();
        }
        Json(json!({ "ok": true, "result": true })).into_response()
    }

    async fn mock_edit_shared_data(
        State(st): State<MockTgState>,
        Json(body): Json<Value>,
    ) -> impl IntoResponse {
        st.record("editSharedWidgetData", body);
        if let Some((code, desc)) = st.edit_widget_error.lock().unwrap().clone() {
            return err_json(code, &desc).into_response();
        }
        Json(json!({ "ok": true, "result": true })).into_response()
    }

    async fn mock_send_rich(
        State(st): State<MockTgState>,
        Json(body): Json<Value>,
    ) -> impl IntoResponse {
        st.record("sendRichMessage", body.clone());
        if *st.rich_rejected.lock().unwrap() {
            return err_json(400, "Bad Request: RICH_MESSAGE_UNSUPPORTED").into_response();
        }
        let mid = st.next_id();
        let chat_id = body["chat_id"].as_i64().unwrap_or(1001);
        Json(json!({
            "ok": true,
            "result": { "message_id": mid, "chat": { "id": chat_id, "type": "private" } }
        }))
        .into_response()
    }

    async fn mock_send_message(
        State(st): State<MockTgState>,
        Json(body): Json<Value>,
    ) -> impl IntoResponse {
        st.record("sendMessage", body.clone());
        let mid = st.next_id();
        let chat_id = body["chat_id"].as_i64().unwrap_or(1001);
        Json(json!({
            "ok": true,
            "result": { "message_id": mid, "chat": { "id": chat_id, "type": "private" } }
        }))
    }

    async fn mock_edit_message_text(
        State(st): State<MockTgState>,
        Json(body): Json<Value>,
    ) -> impl IntoResponse {
        st.record("editMessageText", body.clone());
        if let Some((code, desc)) = st.edit_message_error.lock().unwrap().clone() {
            return err_json(code, &desc).into_response();
        }
        let mid = body.get("message_id").and_then(Value::as_i64).unwrap_or(1);
        let chat_id = body.get("chat_id").and_then(Value::as_i64).unwrap_or(1001);
        Json(json!({
            "ok": true,
            "result": { "message_id": mid, "chat": { "id": chat_id, "type": "private" } }
        }))
        .into_response()
    }

    async fn mock_answer_widget_query(
        State(st): State<MockTgState>,
        Json(body): Json<Value>,
    ) -> impl IntoResponse {
        st.record("answerWidgetQuery", body);
        Json(json!({ "ok": true, "result": true }))
    }

    async fn mock_answer_callback_query(
        State(st): State<MockTgState>,
        Json(body): Json<Value>,
    ) -> impl IntoResponse {
        st.record("answerCallbackQuery", body);
        Json(json!({ "ok": true, "result": true }))
    }

    async fn mock_answer_inline_query(
        State(st): State<MockTgState>,
        Json(body): Json<Value>,
    ) -> impl IntoResponse {
        st.record("answerInlineQuery", body);
        Json(json!({ "ok": true, "result": true }))
    }

    async fn spawn_mock_tg() -> (String, MockTgState, tokio::task::JoinHandle<()>) {
        let st = MockTgState {
            next_msg_id: Arc::new(Mutex::new(100)),
            ..Default::default()
        };
        let router = Router::new()
            .route("/bot{tok}/getMe", get(mock_get_me))
            .route("/bot{tok}/sendWidget", post(mock_send_widget))
            .route("/bot{tok}/sendSharedWidget", post(mock_send_shared_widget))
            .route("/bot{tok}/editMessageWidgetData", post(mock_edit_widget_data))
            .route("/bot{tok}/editSharedWidgetData", post(mock_edit_shared_data))
            .route("/bot{tok}/sendRichMessage", post(mock_send_rich))
            .route("/bot{tok}/sendMessage", post(mock_send_message))
            .route("/bot{tok}/editMessageText", post(mock_edit_message_text))
            .route("/bot{tok}/answerWidgetQuery", post(mock_answer_widget_query))
            .route("/bot{tok}/answerCallbackQuery", post(mock_answer_callback_query))
            .route("/bot{tok}/answerInlineQuery", post(mock_answer_inline_query))
            .with_state(st.clone());

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });
        (format!("http://{addr}"), st, handle)
    }

    const OWNER: i64 = 1001;
    const STD_UID: i64 = 2002;

    struct BotHarness {
        _tmp: TempDir,
        ctx: Arc<BotCtx>,
        mock: MockTgState,
        server_handle: tokio::task::JoinHandle<()>,
    }

    impl Drop for BotHarness {
        fn drop(&mut self) {
            self.server_handle.abort();
        }
    }

    async fn make_harness(allow_inline: bool) -> BotHarness {
        let tmp = TempDir::new().unwrap();
        let state_dir = tmp.path().join("state");
        let ws_dir = tmp.path().join("workspace");
        let skills_dir = tmp.path().join("skills");
        let sp_dir = tmp.path().join("skillport");
        fs::create_dir_all(&state_dir).unwrap();
        fs::create_dir_all(&ws_dir).unwrap();
        fs::create_dir_all(&skills_dir).unwrap();
        fs::create_dir_all(sp_dir.join("coding/demo-sp")).unwrap();
        fs::write(
            sp_dir.join("coding/demo-sp/SKILL.md"),
            "---\nname: demo-sp\ndescription: SkillPort test skill\n---\nBody\n",
        )
        .unwrap();

        let (api_base, mock, server_handle) = spawn_mock_tg().await;
        let cfg = Arc::new(Config {
            bot_token: "12345:MOCK_TOKEN".to_string(),
            state_dir: state_dir.clone(),
            agy_workspace: ws_dir,
            agy_bin: tmp.path().join("missing-agy"),
            owner_id: OWNER,
            allowed_user_ids: vec![OWNER, STD_UID],
            allow_inline_widgets: allow_inline,
            webapp_base_url: "https://app.example.test".to_string(),
            widget_port: 8799,
            agy_skills_dir: skills_dir,
            skillport_skills_dir: sp_dir,
            skills_catalog_json: tmp.path().join("missing-catalog.json"),
            mcp_config_path: tmp.path().join("mcp_config.json"),
            ai_memory_mcp_bin: tmp.path().join("missing-mem"),
            skills_catalog_mcp_bin: tmp.path().join("missing-cat"),
            premium_ui: false,
            ..Default::default()
        });

        let store = Arc::new(StateStore::open(state_dir.join("state.json")).unwrap());
        let acl = Arc::new(AclStore::open(state_dir.join("acl.json"), OWNER, &[STD_UID], 300).unwrap());
        acl.apply_preset(STD_UID, RolePreset::Std).unwrap();
        let outbox = Arc::new(OutQueue::open(state_dir.join("outbox.json")).unwrap());
        let health = Arc::new(HealthTracker::new(state_dir.join("health.json")));
        let premium = Arc::new(PremiumState::new(false));
        let net_cfg = NetConfig::default().with_api_base(api_base);
        let pool = Arc::new(ProxyPool::new(net_cfg.clone()).unwrap());
        let client = Arc::new(
            BotApiClient::with_pool(&cfg.bot_token, &net_cfg.api_base, pool.clone(), Duration::from_secs(2))
                .unwrap(),
        );
        let widgets = Arc::new(WidgetStore::from_state_dir(&state_dir).unwrap());
        let render = Arc::new(
            RenderBridge::new(client.clone(), premium.clone(), outbox.clone())
                .with_state_store(store.clone())
                .with_retry_config(0, 0.01),
        );
        let cron = Arc::new(CronScheduler::new(cfg.clone(), health.clone()).unwrap());
        let jobs = Arc::new(
            JobManager::new(cfg.clone(), acl.clone(), store.clone(), render.clone(), client.clone())
                .unwrap(),
        );
        let auth = Arc::new(AuthGate::new(acl.clone(), allow_inline));

        let ctx = BotCtx::new(
            cfg, store, acl, outbox, health, premium, pool, client, widgets, render, cron, jobs,
            auth,
        );
        clear_widget_api_gate(&ctx);
        BotHarness {
            _tmp: tmp,
            ctx,
            mock,
            server_handle,
        }
    }

    fn make_user(id: i64, name: &str) -> User {
        User {
            id,
            is_bot: false,
            first_name: name.to_string(),
            last_name: None,
            username: Some(name.to_ascii_lowercase()),
            language_code: None,
            is_premium: None,
        }
    }

    fn make_msg(uid: i64, mid: i64, text: Option<&str>) -> Message {
        Message {
            message_id: mid,
            from_user: Some(make_user(uid, "Owner")),
            chat: Chat {
                id: uid,
                kind: "private".to_string(),
                username: None,
                first_name: Some("Owner".to_string()),
            },
            message_thread_id: None,
            text: text.map(str::to_string),
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

    fn make_cq(uid: i64, mid: i64, data: &str) -> CallbackQuery {
        CallbackQuery {
            id: "cq_1".to_string(),
            from_user: make_user(uid, "User"),
            message: Some(make_msg(uid, mid, None)),
            inline_message_id: None,
            data: Some(data.to_string()),
        }
    }

    #[tokio::test]
    async fn send_widget_safe_native_shared_and_cloud_gate_webapp_fallback() {
        let h = make_harness(false).await;

        // 1. Native shared widget send
        let sp_shared = WidgetSpec {
            html: Some("<button>Go</button>".to_string()),
            caption: Some("Shared Hub".to_string()),
            slug: Some("demo_shared".to_string()),
            handler: Some("kv".to_string()),
            is_shared: Some(true),
            cache_time: Some(30),
            public_data: Some("{\"r\":1}".to_string()),
            ..Default::default()
        };
        let (m1, status1) = send_widget_safe(&h.ctx, OWNER, sp_shared).await.unwrap();
        assert_eq!(status1, "sent");
        let m1 = m1.unwrap();
        assert!(h.ctx.widgets.get_shared("demo_shared").is_some());

        // Resend by slug without HTML -> calls sendSharedWidget
        let sp_resend = WidgetSpec {
            slug: Some("demo_shared".to_string()),
            is_shared: Some(true),
            ..Default::default()
        };
        let (_, status2) = send_widget_safe(&h.ctx, OWNER, sp_resend).await.unwrap();
        assert_eq!(status2, "sent");
        assert!(h.mock.methods().contains(&"sendSharedWidget".to_string()));

        // Edit message data with "not modified" returns true gracefully
        *h.mock.edit_widget_error.lock().unwrap() = Some((400, "Bad Request: message is not modified".to_string()));
        assert!(
            edit_message_widget_safe(
                &h.ctx,
                Some(OWNER),
                Some(m1.message_id),
                None,
                None,
                Some(WidgetData::Str("{\"a\":1}")),
            )
            .await
            .unwrap()
        );
        *h.mock.edit_widget_error.lock().unwrap() = None;

        // 2. Telegram cloud-gate rejection (`WIDGET_NOT_ALLOWED`) -> WebApp Rich Card fallback
        *h.mock.send_widget_error.lock().unwrap() =
            Some((400, "Bad Request: WIDGET_NOT_ALLOWED".to_string()));
        let sp_builtin = build_builtin_widget(&h.ctx, "skills", OWNER).await.unwrap();
        let (m_fb, status_fb) = send_widget_safe(&h.ctx, OWNER, sp_builtin).await.unwrap();
        let wid = status_fb.strip_prefix("webapp:").expect("must return webapp:<wid>");
        let m_fb = m_fb.unwrap();

        let rec = h.ctx.widgets.get_webapp_widget(wid).unwrap();
        assert_eq!(rec.chat_id, Some(OWNER));
        assert_eq!(rec.message_id, Some(m_fb.message_id));
        assert_eq!(rec.handler.as_deref(), Some("skills"));
        assert!(h.mock.methods().contains(&"sendRichMessage".to_string()));

        // Verify web_app button uses https://app.example.test/w/<wid>
        let rich_body = h.mock.last_body("sendRichMessage").unwrap();
        assert!(rich_body.to_string().contains(&format!("https://app.example.test/w/{wid}")));

        // 3. Cached cooldown skips second native sendWidget call completely
        let before_send_widget_cnt = h
            .mock
            .methods()
            .into_iter()
            .filter(|m| m == "sendWidget")
            .count();
        let sp2 = build_builtin_widget(&h.ctx, "models", OWNER).await.unwrap();
        let (_, status_cached) = send_widget_safe(&h.ctx, OWNER, sp2).await.unwrap();
        assert!(status_cached.starts_with("webapp:"));
        let after_send_widget_cnt = h
            .mock
            .methods()
            .into_iter()
            .filter(|m| m == "sendWidget")
            .count();
        assert_eq!(before_send_widget_cnt, after_send_widget_cnt);
    }

    #[tokio::test]
    async fn commands_callbacks_and_wact_enforce_acl() {
        let h = make_harness(false).await;
        *h.mock.send_widget_error.lock().unwrap() =
            Some((400, "Bad Request: WIDGET_NOT_ALLOWED".to_string()));

        // `/widget menu`, `/widget skills`, `/widget list`, `/widget check`
        cmd_widget(&h.ctx, &make_msg(OWNER, 1, Some("/widget")), "").await;
        cmd_widget(&h.ctx, &make_msg(OWNER, 2, Some("/widget skills")), "skills").await;
        cmd_widget(&h.ctx, &make_msg(OWNER, 3, Some("/widget list")), "list").await;
        cmd_widget(
            &h.ctx,
            &make_msg(OWNER, 4, None),
            "check <style>b{}</style><div>Hello</div>",
        )
        .await;
        let check_body = h.mock.last_body("sendMessage").unwrap();
        assert!(check_body["text"].as_str().unwrap().contains("Widget Check"));

        // `wmenu:open`, `wmenu:list`, `wmenu:send:models`
        assert!(handle_widget_cb(&h.ctx, &make_cq(OWNER, 5, "wmenu:open"), OWNER, OWNER, "wmenu:open").await);
        assert!(handle_widget_cb(&h.ctx, &make_cq(OWNER, 6, "wmenu:list"), OWNER, OWNER, "wmenu:list").await);
        assert!(
            handle_widget_cb(
                &h.ctx,
                &make_cq(OWNER, 7, "wmenu:send:models"),
                OWNER,
                OWNER,
                "wmenu:send:models"
            )
            .await
        );

        // `wact:` tab switch & ACL denial on unprivileged `sk:in:0`
        let skills_sp = build_builtin_widget(&h.ctx, "skills", STD_UID).await.unwrap();
        let (_, status) = send_widget_safe(&h.ctx, STD_UID, skills_sp).await.unwrap();
        let wid = status.strip_prefix("webapp:").unwrap().to_string();

        assert!(
            handle_widget_cb(
                &h.ctx,
                &make_cq(STD_UID, 20, &format!("wact:{wid}:tab:sp")),
                STD_UID,
                STD_UID,
                &format!("wact:{wid}:tab:sp"),
            )
            .await
        );
        assert_eq!(
            h.ctx.widgets.get_webapp_widget(&wid).unwrap().tab.as_deref(),
            Some("sp")
        );

        // Switch state to SkillPort items, then attempt `sk:in:0` as standard user -> denied
        assert!(
            handle_widget_cb(
                &h.ctx,
                &make_cq(STD_UID, 20, &format!("wact:{wid}:sk:t:sp")),
                STD_UID,
                STD_UID,
                &format!("wact:{wid}:sk:t:sp"),
            )
            .await
        );
        assert!(
            handle_widget_cb(
                &h.ctx,
                &make_cq(STD_UID, 20, &format!("wact:{wid}:sk:in:0")),
                STD_UID,
                STD_UID,
                &format!("wact:{wid}:sk:in:0"),
            )
            .await
        );
        let cq_ack = h.mock.last_body("answerCallbackQuery").unwrap();
        assert!(cq_ack["text"].as_str().unwrap().contains("Permission denied"));
        assert!(!h.ctx.skills_dir().join("demo-sp").exists());

        // `wact:` refresh updates card in-place
        assert!(
            handle_widget_cb(
                &h.ctx,
                &make_cq(OWNER, 20, &format!("wact:{wid}:refresh")),
                OWNER,
                OWNER,
                &format!("wact:{wid}:refresh"),
            )
            .await
        );
        assert!(h.mock.methods().contains(&"editMessageText".to_string()));
    }

    #[tokio::test]
    async fn widget_queries_shared_queries_inline_queries_and_incoming_widget_message() {
        let h = make_harness(true).await;

        let sp = WidgetSpec {
            html: Some("<div>Counter</div>".to_string()),
            handler: Some("kv".to_string()),
            is_shared: Some(true),
            slug: Some("shared_kv".to_string()),
            ..Default::default()
        };
        let (msg_opt, _) = send_widget_safe(&h.ctx, OWNER, sp).await.unwrap();
        let mid = msg_opt.unwrap().message_id;
        let wid = h.ctx.widgets.resolve_widget_id("shared_kv").unwrap();

        // Direct widget_query -> kv:set
        let wq = WidgetQuery {
            id: "wq_1".to_string(),
            from_user: make_user(OWNER, "Owner"),
            chat: Some(Chat {
                id: OWNER,
                kind: "private".to_string(),
                username: None,
                first_name: None,
            }),
            chat_type: Some("private".to_string()),
            message_id: Some(mid),
            inline_message_id: None,
            widget_id: None,
            data: Some("counter:inc".to_string()),
            kind: WidgetQueryType::Data { wallet_card: None },
        };
        handle_widget_query(&h.ctx, &wq).await;
        let ans = h.mock.last_body("answerWidgetQuery").unwrap();
        let parsed_ans: Value = serde_json::from_str(ans["data"].as_str().unwrap()).unwrap();
        assert_eq!(parsed_ans["count"], 1);
        assert!(h.mock.methods().contains(&"editMessageWidgetData".to_string()));

        // Shared widget query -> edits shared widget data ONLY, does NOT call editMessageWidgetData again
        let before_edit_msg_cnt = h
            .mock
            .methods()
            .into_iter()
            .filter(|m| m == "editMessageWidgetData")
            .count();
        let swq = SharedWidgetQuery {
            id: "swq_1".to_string(),
            from_user: make_user(OWNER, "Owner"),
            widget_id: wid.clone(),
            data: Some("kv:set:status=ok".to_string()),
            kind: WidgetQueryType::Data { wallet_card: None },
        };
        handle_shared_widget_query(&h.ctx, &swq).await;
        // Note `kv:` sets `chat_data` not `public_data`, while `vote:` sets `public_data`!
        let swq_vote = SharedWidgetQuery {
            id: "swq_2".to_string(),
            from_user: make_user(OWNER, "Owner"),
            widget_id: wid.clone(),
            data: Some("vote:0".to_string()),
            kind: WidgetQueryType::Data { wallet_card: None },
        };
        handle_shared_widget_query(&h.ctx, &swq_vote).await;
        assert!(h.mock.methods().contains(&"editSharedWidgetData".to_string()));
        let after_edit_msg_cnt = h
            .mock
            .methods()
            .into_iter()
            .filter(|m| m == "editMessageWidgetData")
            .count();
        assert_eq!(before_edit_msg_cnt, after_edit_msg_cnt);

        // Wallet sign_data event
        let wq_wallet = WidgetQuery {
            id: "wq_w1".to_string(),
            from_user: make_user(OWNER, "Owner"),
            chat: None,
            chat_type: None,
            message_id: None,
            inline_message_id: None,
            widget_id: None,
            data: Some("signed".to_string()),
            kind: WidgetQueryType::SignData {
                wallet: WidgetQueryWallet {
                    address: "EQDemoWallet".to_string(),
                    amount: Some("1.5".to_string()),
                },
                sign_data: "hello-ton".to_string(),
            },
        };
        handle_widget_query(&h.ctx, &wq_wallet).await;
        assert_eq!(h.ctx.widgets.snapshot().wallet_events.len(), 1);

        // Inline query
        let iq = InlineQuery {
            id: "iq_1".to_string(),
            from_user: make_user(OWNER, "Owner"),
            query: "skills".to_string(),
            chat_type: Some("private".to_string()),
        };
        handle_inline_query(&h.ctx, &iq).await;
        let iq_body = h.mock.last_body("answerInlineQuery").unwrap();
        assert_eq!(iq_body["results"].as_array().unwrap().len(), 1);

        // Incoming widget message without caption saves files & pushes pending
        let mut wmsg = make_msg(OWNER, 88, None);
        wmsg.widget = Some(agy_core::tg::Widget {
            id: Some("w_in_1".to_string()),
            html: Some("<div>User Widget</div>".to_string()),
            width: Some(300),
            height: Some(200),
            public_data: None,
            chat_data: None,
        });
        assert!(handle_widget_message(&h.ctx, &wmsg).await);
        assert_eq!(pending_widget_files(&h.ctx, OWNER).len(), 2);
        assert_eq!(take_pending_widget_files(&h.ctx, OWNER).len(), 2);
        assert!(take_pending_widget_files(&h.ctx, OWNER).is_empty());
    }

    #[tokio::test]
    async fn startup_widget_once_and_outbox_widget_files() {
        let h = make_harness(false).await;
        *h.mock.send_widget_error.lock().unwrap() =
            Some((400, "Bad Request: WIDGET_NOT_ALLOWED".to_string()));

        // Startup widget_once.json
        let once_path = h.ctx.cfg.state_dir.join("widget_once.json");
        fs::write(
            &once_path,
            json!({
                "uid": OWNER,
                "builtins": ["models"]
            })
            .to_string(),
        )
        .unwrap();

        let startup_res = consume_startup_widget_once(&h.ctx, &[OWNER, STD_UID])
            .await
            .unwrap()
            .unwrap();
        assert!(!once_path.exists());
        assert!(startup_res[OWNER.to_string()]["status"]
            .as_str()
            .unwrap()
            .starts_with("webapp:"));
        assert!(h.ctx.store.meta("last_widget_startup").is_some());

        // Outbox `.widget.html`, `.widget.json` (with `html_file` dedup + sidecar skip), and markdown extraction
        let outbox_dir = h.ctx.cfg.state_dir.join("job_out");
        fs::create_dir_all(&outbox_dir).unwrap();
        fs::write(
            outbox_dir.join("panel.widget.html"),
            "<!-- widget: {\"caption\": \"Panel\", \"slug\": \"panel_slug\"} -->\n<div>Panel</div>",
        )
        .unwrap();
        fs::write(
            outbox_dir.join("manifest.widget.json"),
            json!({ "action": "send", "html_file": "panel.widget.html", "caption": "Manifest" }).to_string(),
        )
        .unwrap();
        // Sidecar without action/html keys should be ignored cleanly when `.widget.html` exists
        fs::write(
            outbox_dir.join("panel.widget.json"),
            json!({ "width": 320 }).to_string(),
        )
        .unwrap();

        let before_cards = h
            .mock
            .methods()
            .into_iter()
            .filter(|m| m == "sendRichMessage")
            .count();
        let handled = deliver_outbox_widgets_in_dir(&h.ctx, OWNER, &outbox_dir).await;
        assert_eq!(handled.len(), 3);
        let after_cards = h
            .mock
            .methods()
            .into_iter()
            .filter(|m| m == "sendRichMessage")
            .count();
        // Only manifest.widget.json sends (panel.widget.html deduplicated, sidecar skipped)
        assert_eq!(after_cards - before_cards, 1);

        let cleaned = extract_and_send_markdown_widgets(
            &h.ctx,
            OWNER,
            "Hello!\n<tg-widget caption=\"Mini\"><div>Hi</div></tg-widget>",
        )
        .await
        .unwrap();
        assert!(!cleaned.contains("<tg-widget"));
    }
}
