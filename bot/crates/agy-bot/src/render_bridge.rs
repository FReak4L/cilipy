//! Rich Markdown / HTML rendering bridge, graceful Premium fallback, outbox retry drain,
//! and multi-type media file delivery.

use std::collections::{BTreeSet, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use agy_core::outbox::OutQueue;
use agy_core::security::{scan_file_for_secrets, DEFAULT_MAX_SECRET_SCAN_BYTES};
use agy_core::store::StateStore;
use agy_core::tg::{InlineKeyboardMarkup, InputRichMessage, LinkPreviewOptions, Message};
use agy_core::{BridgeError, Result};
use agy_ext::mcp_client::redact_secrets_in_text;
use agy_net::{
    tg_retry, BotApiClient, EditMessageTextParams, MediaInput, SendMediaOptions,
    SendMessageParams, SendRichMessageParams, MAX_UPLOAD_BYTES,
};
use agy_render::{
    cut_utf16, esc, extract_tg_button_rows, is_premium_error, is_rtl_dominant, md_to_html,
    normalize_rich_markdown, rich_to_html_card, sanitize_rich_buttons, split_html, split_markdown,
    strip_custom_emoji, strip_md_custom_emoji, truncate_utf8_bytes, utf16_len, PremiumState,
    DEFAULT_HTML_SPLIT_LIMIT, DEFAULT_MD_SPLIT_LIMIT, DEFAULT_MD_SPLIT_LINES, TG_TEXT_LIMIT,
};
use bytes::Bytes;
use regex::Regex;
use tracing::{info, warn};

const PHOTO_MAX_BYTES: u64 = 10 * 1024 * 1024;
const IMG_EXTS: &[&str] = &["png", "jpg", "jpeg", "webp"];
const VID_EXTS: &[&str] = &["mp4", "mov", "webm", "mkv"];
const AUD_EXTS: &[&str] = &["mp3", "m4a", "flac", "wav", "aac"];
const VOICE_EXTS: &[&str] = &["ogg", "oga", "opus"];

fn html_tags_regex() -> Option<&'static Regex> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"<[^>]+>").ok()).as_ref()
}

/// Strip HTML tags and unescape basic entities into plain text.
pub fn strip_html_to_plain(html_text: &str) -> String {
    let without_tags = match html_tags_regex() {
        Some(re) => re.replace_all(html_text, "").into_owned(),
        None => html_text.to_string(),
    };
    without_tags
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#x27;", "'")
        .replace("&#39;", "'")
        .replace("&amp;", "&")
}

fn has_icons(markup: Option<&InlineKeyboardMarkup>) -> bool {
    markup.is_some_and(InlineKeyboardMarkup::has_custom_icons)
}

fn strip_markup_opt(
    markup: Option<InlineKeyboardMarkup>,
    premium: &PremiumState,
) -> Option<InlineKeyboardMarkup> {
    markup.map(|m| premium.strip_markup_icons(m))
}

fn is_strict_premium_rejection(err: &BridgeError, has_premium_markup: bool) -> bool {
    if !is_premium_error(err) {
        return false;
    }
    let low = err.to_string().to_ascii_lowercase();
    // Account/bot-level capability errors always disable global Premium;
    // generic `DOCUMENT_INVALID` only disables global Premium when our own
    // vetted button/markup icons were sent (vs an unverified AI-emitted ID).
    low.contains("premium_account_required")
        || low.contains("button_user_privacy_restricted")
        || has_premium_markup
}

fn disable_preview() -> Option<LinkPreviewOptions> {
    Some(LinkPreviewOptions {
        is_disabled: Some(true),
    })
}

fn short_ask_route_key(raw: &str) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    raw.hash(&mut h);
    format!("askr:{:012x}", h.finish() & 0xffff_ffff_ffff)
}

fn merge_inline_markups(
    extra: Option<InlineKeyboardMarkup>,
    base: Option<InlineKeyboardMarkup>,
) -> Option<InlineKeyboardMarkup> {
    match (extra, base) {
        (Some(mut e), Some(b)) => {
            e.inline_keyboard.extend(b.inline_keyboard);
            Some(e)
        }
        (Some(e), None) => Some(e),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }
}

fn clean_callback_data(raw: &str) -> String {
    let cleaned: String = raw
        .chars()
        .filter_map(|c| {
            if matches!(c, '\n' | '\r' | '\t') {
                Some(' ')
            } else if c.is_control() {
                None
            } else {
                Some(c)
            }
        })
        .collect();
    cleaned.trim().to_string()
}

fn sanitize_markup_callbacks<F>(
    markup: Option<InlineKeyboardMarkup>,
    mut map_cb: F,
) -> Option<InlineKeyboardMarkup>
where
    F: FnMut(&str) -> Option<String>,
{
    let mut mk = markup?;
    for row in &mut mk.inline_keyboard {
        row.retain_mut(|btn| {
            let Some(ref cb) = btn.callback_data else {
                return true;
            };
            let cleaned = clean_callback_data(cb);
            if cleaned.is_empty() {
                btn.callback_data = None;
                return btn.url.is_some() || btn.copy_text.is_some();
            }
            let needs_map = cleaned.len() > 64
                || (cleaned.starts_with("ask:") && cleaned.contains(['"', '&', '<', '>', '\'']));
            if needs_map {
                let rep = map_cb(&cleaned)
                    .filter(|s| !s.is_empty() && s.len() <= 64)
                    .unwrap_or_else(|| truncate_utf8_bytes(&cleaned, 64).trim().to_string());
                if rep.is_empty() {
                    return false;
                }
                btn.callback_data = Some(rep);
            } else if cleaned != *cb {
                btn.callback_data = Some(cleaned);
            }
            true
        });
    }
    mk.inline_keyboard.retain(|row| !row.is_empty());
    (!mk.inline_keyboard.is_empty()).then_some(mk)
}

/// Summary report returned by [`RenderBridge::deliver_outbox_files`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OutboxDeliveryReport {
    pub delivered: Vec<String>,
    pub skipped_oversize: Vec<String>,
    pub skipped_empty: Vec<String>,
    /// Files blocked before upload because suspected secrets were detected (`(filename, kinds)`).
    pub blocked_secrets: Vec<(String, Vec<String>)>,
    pub overflow_count: usize,
    pub errors: Vec<String>,
}

/// Bridge coordinating Markdown/HTML rendering, Premium UI downgrade, persistent retry queue,
/// and outgoing media file delivery.
pub struct RenderBridge {
    client: Arc<BotApiClient>,
    premium: Arc<PremiumState>,
    outbox: Arc<OutQueue>,
    store: Option<Arc<StateStore>>,
    retries: u32,
    retry_cap_secs: f64,
}

impl RenderBridge {
    /// Construct a new [`RenderBridge`] with default retry settings (`retries = 3, cap = 10s`).
    pub fn new(
        client: Arc<BotApiClient>,
        premium: Arc<PremiumState>,
        outbox: Arc<OutQueue>,
    ) -> Self {
        Self {
            client,
            premium,
            outbox,
            store: None,
            retries: 3,
            retry_cap_secs: 10.0,
        }
    }

    /// Attach an optional [`StateStore`] so runtime premium degradation persists in `meta`.
    pub fn with_state_store(mut self, store: Arc<StateStore>) -> Self {
        self.store = Some(store);
        self
    }

    /// Customize Telegram retry count and jitter cap (primarily for deterministic tests).
    pub fn with_retry_config(mut self, retries: u32, retry_cap_secs: f64) -> Self {
        self.retries = retries;
        self.retry_cap_secs = retry_cap_secs;
        self
    }

    pub fn client(&self) -> &Arc<BotApiClient> {
        &self.client
    }

    pub fn premium(&self) -> &Arc<PremiumState> {
        &self.premium
    }

    pub fn outbox(&self) -> &Arc<OutQueue> {
        &self.outbox
    }

    fn disable_premium(&self, reason: &str) {
        if !self.premium.active() {
            return;
        }
        let short_reason: String = reason.chars().take(200).collect();
        self.premium.disable(&short_reason);
        if let Some(ref store) = self.store {
            if let Err(err) = store.set_meta("premium_disabled", serde_json::json!(short_reason)) {
                warn!(error = %err, "failed to persist premium_disabled metadata");
            }
        }
    }

    fn queue_failed_html(
        &self,
        chat_id: i64,
        text: &str,
        markup: &Option<InlineKeyboardMarkup>,
    ) {
        let mk_json = markup
            .as_ref()
            .and_then(|m| serde_json::to_string(m).ok());
        match self.outbox.push(chat_id, text, mk_json, None) {
            Ok(key) => warn!(chat_id, key = %key, "send failed transiently; queued for retry"),
            Err(err) => warn!(chat_id, error = %err, "failed to push message to outbox"),
        }
    }

    async fn send_html_chunk(
        &self,
        chat_id: i64,
        html: &str,
        markup: Option<InlineKeyboardMarkup>,
        effect_id: Option<&str>,
        disable_notification: Option<bool>,
        queue_on_fail: bool,
    ) -> Result<Option<Message>> {
        let mut cur_text = if self.premium.active() {
            html.to_string()
        } else {
            strip_custom_emoji(html)
        };
        let mut cur_mk = if self.premium.active() {
            markup
        } else {
            strip_markup_opt(markup, &self.premium)
        };
        let mut cur_eff = if self.premium.effects_ok() {
            effect_id.map(ToString::to_string)
        } else {
            None
        };

        for _attempt in 0..2 {
            let params = SendMessageParams {
                chat_id,
                text: cur_text.clone(),
                parse_mode: Some("HTML".to_string()),
                link_preview_options: disable_preview(),
                disable_notification,
                message_effect_id: cur_eff.clone(),
                reply_markup: cur_mk.clone(),
                ..Default::default()
            };

            match tg_retry(self.retries, self.retry_cap_secs, || {
                self.client.send_message(&params)
            })
            .await
            {
                Ok(msg) => return Ok(Some(msg)),
                Err(err) => {
                    if err.is_chat_unavailable() {
                        warn!(chat_id, error = %err, "chat unavailable; skipping send");
                        return Ok(None);
                    }
                    let msg_low = err.to_string().to_ascii_lowercase();
                    if cur_eff.is_some() && msg_low.contains("effect") {
                        // Message effects are private-chat only; don't disable them globally on group errors.
                        if chat_id > 0 {
                            self.premium.disable_effects();
                        }
                        cur_eff = None;
                        continue;
                    }

                    let has_prem = cur_text.contains("<tg-emoji") || has_icons(cur_mk.as_ref());
                    if matches!(err, BridgeError::BotApi { code: 400, .. }) {
                        if is_strict_premium_rejection(&err, has_prem) || has_prem {
                            if is_strict_premium_rejection(&err, has_prem) {
                                self.disable_premium(&err.to_string());
                            }
                            cur_text = strip_custom_emoji(&cur_text);
                            cur_mk = strip_markup_opt(cur_mk, &self.premium);

                            let stripped_params = SendMessageParams {
                                chat_id,
                                text: cur_text.clone(),
                                parse_mode: Some("HTML".to_string()),
                                link_preview_options: disable_preview(),
                                disable_notification,
                                message_effect_id: None,
                                reply_markup: cur_mk.clone(),
                                ..Default::default()
                            };
                            match tg_retry(self.retries, self.retry_cap_secs, || {
                                self.client.send_message(&stripped_params)
                            })
                            .await
                            {
                                Ok(msg) => return Ok(Some(msg)),
                                Err(e2) if e2.is_chat_unavailable() => return Ok(None),
                                Err(e2) if e2.is_retryable() => {
                                    if queue_on_fail {
                                        self.queue_failed_html(chat_id, &cur_text, &cur_mk);
                                        return Ok(None);
                                    }
                                    return Err(e2);
                                }
                                Err(_) => {}
                            }
                        }

                        // HTML parse/entity rejection -> fall back cleanly to plain text
                        info!(chat_id, error = %err, "HTML rejected -> falling back to plain text");
                        let plain_raw = strip_html_to_plain(&strip_custom_emoji(&cur_text));
                        let plain_text = if plain_raw.trim().is_empty() {
                            cut_utf16(&cur_text, TG_TEXT_LIMIT).to_string()
                        } else {
                            cut_utf16(&plain_raw, TG_TEXT_LIMIT).to_string()
                        };
                        let plain_mk = strip_markup_opt(cur_mk.clone(), &self.premium);
                        let plain_params = SendMessageParams {
                            chat_id,
                            text: plain_text.clone(),
                            parse_mode: None,
                            link_preview_options: disable_preview(),
                            disable_notification,
                            reply_markup: plain_mk.clone(),
                            ..Default::default()
                        };
                        match tg_retry(self.retries, self.retry_cap_secs, || {
                            self.client.send_message(&plain_params)
                        })
                        .await
                        {
                            Ok(msg) => return Ok(Some(msg)),
                            Err(e2) if e2.is_chat_unavailable() => return Ok(None),
                            Err(e2) if e2.is_retryable() && queue_on_fail => {
                                self.queue_failed_html(chat_id, &plain_text, &plain_mk);
                                return Ok(None);
                            }
                            Err(e2) => return Err(e2),
                        }
                    }

                    if err.is_retryable() && queue_on_fail {
                        self.queue_failed_html(chat_id, &cur_text, &cur_mk);
                        return Ok(None);
                    }
                    return Err(err);
                }
            }
        }
        Ok(None)
    }

    /// Send HTML text, splitting at `<= 4000` UTF-16 units with balanced tags and full
    /// Premium -> stripped HTML -> plain text -> OutQueue fallback cascade.
    pub async fn send_html(
        &self,
        chat_id: i64,
        html: &str,
        markup: Option<InlineKeyboardMarkup>,
        effect_id: Option<&str>,
        disable_notification: Option<bool>,
        queue_on_fail: bool,
    ) -> Result<Option<Message>> {
        if html.is_empty() {
            return Ok(None);
        }
        let chunks = split_html(html, DEFAULT_HTML_SPLIT_LIMIT);
        let total = chunks.len();
        let mut last = None;
        for (idx, chunk) in chunks.into_iter().enumerate() {
            let chunk_mk = if idx + 1 == total {
                markup.clone()
            } else {
                None
            };
            let chunk_eff = if idx == 0 { effect_id } else { None };
            last = self
                .send_html_chunk(
                    chat_id,
                    &chunk,
                    chunk_mk,
                    chunk_eff,
                    disable_notification,
                    queue_on_fail,
                )
                .await?;
        }
        Ok(last)
    }

    /// Ergonomic wrapper for [`Self::send_html`] with `queue_on_fail = true`.
    pub async fn send_html_simple(
        &self,
        chat_id: i64,
        html: &str,
        markup: Option<InlineKeyboardMarkup>,
    ) -> Result<Option<Message>> {
        self.send_html(chat_id, html, markup, None, None, true).await
    }

    /// Edit a message with HTML text (`<= 4000` UTF-16 units), treating `not modified` as `Ok(())`
    /// and falling back from Premium -> stripped HTML -> plain text.
    pub async fn edit_html(
        &self,
        chat_id: i64,
        message_id: i64,
        html: &str,
        markup: Option<InlineKeyboardMarkup>,
    ) -> Result<()> {
        let chunks = split_html(html, DEFAULT_HTML_SPLIT_LIMIT);
        let Some(chunk) = chunks.into_iter().next() else {
            return Ok(());
        };
        let cur_text = if self.premium.active() {
            chunk
        } else {
            strip_custom_emoji(&chunk)
        };
        let cur_mk = if self.premium.active() {
            markup
        } else {
            strip_markup_opt(markup, &self.premium)
        };

        let params = EditMessageTextParams {
            chat_id: Some(chat_id),
            message_id: Some(message_id),
            text: Some(cur_text.clone()),
            parse_mode: Some("HTML".to_string()),
            link_preview_options: disable_preview(),
            reply_markup: cur_mk.clone(),
            ..Default::default()
        };

        match tg_retry(self.retries, self.retry_cap_secs, || {
            self.client.edit_message_text(&params)
        })
        .await
        {
            Ok(_) => Ok(()),
            Err(err) if err.is_not_modified() => Ok(()),
            Err(err) if err.is_chat_unavailable() => Ok(()),
            Err(err) => {
                let has_prem = cur_text.contains("<tg-emoji") || has_icons(cur_mk.as_ref());
                if matches!(err, BridgeError::BotApi { code: 400, .. }) {
                    if is_strict_premium_rejection(&err, has_prem) || has_prem {
                        if is_strict_premium_rejection(&err, has_prem) {
                            self.disable_premium(&err.to_string());
                        }
                        let stripped = strip_custom_emoji(&cur_text);
                        let stripped_mk = strip_markup_opt(cur_mk.clone(), &self.premium);
                        let p2 = EditMessageTextParams {
                            chat_id: Some(chat_id),
                            message_id: Some(message_id),
                            text: Some(stripped),
                            parse_mode: Some("HTML".to_string()),
                            link_preview_options: disable_preview(),
                            reply_markup: stripped_mk,
                            ..Default::default()
                        };
                        match tg_retry(self.retries, self.retry_cap_secs, || {
                            self.client.edit_message_text(&p2)
                        })
                        .await
                        {
                            Ok(_) => return Ok(()),
                            Err(e2) if e2.is_not_modified() => return Ok(()),
                            Err(e2) if e2.is_chat_unavailable() => return Ok(()),
                            Err(_) => {}
                        }
                    }

                    let plain = cut_utf16(
                        &strip_html_to_plain(&strip_custom_emoji(&cur_text)),
                        TG_TEXT_LIMIT,
                    )
                    .to_string();
                    let plain_mk = strip_markup_opt(cur_mk, &self.premium);
                    let p3 = EditMessageTextParams {
                        chat_id: Some(chat_id),
                        message_id: Some(message_id),
                        text: Some(plain),
                        parse_mode: None,
                        link_preview_options: disable_preview(),
                        reply_markup: plain_mk,
                        ..Default::default()
                    };
                    match tg_retry(self.retries, self.retry_cap_secs, || {
                        self.client.edit_message_text(&p3)
                    })
                    .await
                    {
                        Ok(_) => return Ok(()),
                        Err(e3) if e3.is_not_modified() || e3.is_chat_unavailable() => return Ok(()),
                        Err(e3) => return Err(e3),
                    }
                }
                Err(err)
            }
        }
    }

    /// Edit an existing message with HTML, or send a new message if `message_id` is `None` or edit fails.
    pub async fn edit_or_send_html(
        &self,
        chat_id: i64,
        message_id: Option<i64>,
        html: &str,
        markup: Option<InlineKeyboardMarkup>,
    ) -> Result<Option<Message>> {
        if let Some(mid) = message_id {
            if self.edit_html(chat_id, mid, html, markup.clone()).await.is_ok() {
                return Ok(None);
            }
        }
        self.send_html(chat_id, html, markup, None, None, true).await
    }

    /// Register an oversized `ask:<choice>` callback payload under a compact `askr:<hex>` token
    /// in `StateStore` meta so buttons > 64 UTF-8 bytes (e.g. Persian prompts) never trigger `BUTTON_DATA_INVALID`.
    pub fn register_ask_route(&self, raw_data: &str) -> Option<String> {
        let store = self.store.as_ref()?;
        let cleaned = clean_callback_data(raw_data);
        let payload = cleaned.strip_prefix("ask:")?.trim();
        if payload.is_empty() {
            return None;
        }
        let key = short_ask_route_key(&cleaned);
        let mut map = store
            .meta("ask_routes")
            .and_then(|v| v.as_object().cloned())
            .unwrap_or_default();
        if map.len() >= 256 {
            let excess = map.len() - 192;
            let old_keys: Vec<String> = map.keys().take(excess).cloned().collect();
            for k in old_keys {
                map.remove(&k);
            }
        }
        map.insert(key.clone(), serde_json::Value::String(payload.to_string()));
        let _ = store.set_meta("ask_routes", serde_json::Value::Object(map));
        Some(key)
    }

    /// Look up a shortened `askr:<hex>` callback payload stored via [`Self::register_ask_route`].
    pub fn resolve_ask_route(&self, key: &str) -> Option<String> {
        self.store
            .as_ref()?
            .meta("ask_routes")?
            .get(key)?
            .as_str()
            .map(ToString::to_string)
    }

    /// Prepare Rich Markdown (`normalize_rich_markdown` + `sanitize_rich_buttons` with `askr:` mapping).
    pub fn prepare_rich_markdown(&self, md: &str) -> String {
        let norm = normalize_rich_markdown(md);
        sanitize_rich_buttons(&norm, |raw| self.register_ask_route(raw))
    }

    /// Prepare an HTML/Plain fallback body + keyboard by extracting `<tg-button*>` rows safely.
    pub fn prepare_html_fallback(
        &self,
        md: &str,
        base_markup: Option<InlineKeyboardMarkup>,
    ) -> (String, Option<InlineKeyboardMarkup>) {
        let (clean_md, inline_mk) = extract_tg_button_rows(md, |raw| self.register_ask_route(raw));
        let html = md_to_html(&clean_md, 6);
        let merged = merge_inline_markups(inline_mk, sanitize_markup_callbacks(base_markup, |r| self.register_ask_route(r)));
        (html, merged)
    }

    /// Send Rich Markdown via Bot API `sendRichMessage`, splitting with `split_markdown`,
    /// retrying without Premium custom emoji/icons on rejection, and falling back to
    /// `md_to_html` + `split_html` + `send_html` on rejection or transport error.
    pub async fn send_rich_message(
        &self,
        chat_id: i64,
        md: &str,
        markup: Option<InlineKeyboardMarkup>,
        disable_notification: Option<bool>,
        queue_on_fail: bool,
    ) -> Result<Vec<Message>> {
        let prepared_md = self.prepare_rich_markdown(md);
        let safe_markup = sanitize_markup_callbacks(markup, |raw| self.register_ask_route(raw));
        let parts = split_markdown(&prepared_md, DEFAULT_MD_SPLIT_LIMIT, DEFAULT_MD_SPLIT_LINES);
        if parts.is_empty() {
            return Ok(Vec::new());
        }
        let total = parts.len();
        let mut sent = Vec::with_capacity(total);

        for (idx, part) in parts.into_iter().enumerate() {
            let part_mk = if idx + 1 == total {
                safe_markup.clone()
            } else {
                None
            };
            let rtl = is_rtl_dominant(&part);
            let plain_md = strip_md_custom_emoji(&part);
            let plain_mk = strip_markup_opt(part_mk.clone(), &self.premium);

            let (cur_md, cur_mk) = if self.premium.active() {
                (part.clone(), part_mk.clone())
            } else {
                (plain_md.clone(), plain_mk.clone())
            };

            let rich_params = SendRichMessageParams {
                chat_id,
                rich_message: InputRichMessage::markdown_with_rtl(cur_md.clone(), rtl),
                disable_notification,
                reply_markup: cur_mk.clone(),
                ..Default::default()
            };

            match tg_retry(self.retries, self.retry_cap_secs, || {
                self.client.send_rich_message(&rich_params)
            })
            .await
            {
                Ok(m) => {
                    sent.push(m);
                    continue;
                }
                Err(err) => {
                    if err.is_chat_unavailable() {
                        return Ok(sent);
                    }
                    // Never multiply flood waits or duplicate messages on network/5xx timeouts by
                    // falling back from Rich Message to multi-chunk HTML!
                    if matches!(err, BridgeError::RateLimited { .. }) || err.is_retryable() {
                        if queue_on_fail {
                            let (html, merged_mk) = self.prepare_html_fallback(&plain_md, plain_mk);
                            for hchunk in split_html(&html, DEFAULT_HTML_SPLIT_LIMIT) {
                                self.queue_failed_html(chat_id, &hchunk, &merged_mk);
                            }
                            return Ok(sent);
                        }
                        return Err(err);
                    }
                    let has_known_emoji = self.premium.has_known_emoji_in_md(&cur_md);
                    let has_prem = has_icons(cur_mk.as_ref()) || has_known_emoji;
                    if matches!(err, BridgeError::BotApi { .. })
                        && (cur_md != plain_md || has_icons(cur_mk.as_ref()))
                        && is_premium_error(&err)
                    {
                        if is_strict_premium_rejection(&err, has_prem) {
                            self.disable_premium(&err.to_string());
                        }
                        let plain_rich = SendRichMessageParams {
                            chat_id,
                            rich_message: InputRichMessage::markdown_with_rtl(plain_md.clone(), rtl),
                            disable_notification,
                            reply_markup: plain_mk.clone(),
                            ..Default::default()
                        };
                        match tg_retry(self.retries, self.retry_cap_secs, || {
                            self.client.send_rich_message(&plain_rich)
                        })
                        .await
                        {
                            Ok(m) => {
                                sent.push(m);
                                continue;
                            }
                            Err(e2) if e2.is_chat_unavailable() => return Ok(sent),
                            Err(e2) => {
                                info!(chat_id, error = %e2, "plain Rich rejected -> HTML fallback");
                            }
                        }
                    } else {
                        info!(chat_id, error = %err, "sendRichMessage rejected/failed -> HTML fallback");
                    }

                    let (html, merged_mk) = self.prepare_html_fallback(&plain_md, plain_mk);
                    if let Some(m) = self
                        .send_html(
                            chat_id,
                            &html,
                            merged_mk,
                            None,
                            disable_notification,
                            queue_on_fail,
                        )
                        .await?
                    {
                        sent.push(m);
                    }
                }
            }
        }
        Ok(sent)
    }

    /// Send Markdown either as Rich (`use_rich = true`) or HTML (`use_rich = false`),
    /// attaching oversized answers as `answer.md` when exceeding chat-safe limits.
    pub async fn send_markdown(
        &self,
        chat_id: i64,
        md: &str,
        markup: Option<InlineKeyboardMarkup>,
        use_rich: bool,
        queue_on_fail: bool,
    ) -> Result<Vec<Message>> {
        if utf16_len(md) > 3 * 31_000 {
            let cut = cut_utf16(md, 3000);
            let preview = match cut.rfind('\n') {
                Some(pos) if pos > 0 => &cut[..pos],
                _ => cut,
            };
            let preview_md = format!("{preview}\n\n…");
            let mut msgs = self
                .send_rich_message(chat_id, &preview_md, None, None, queue_on_fail)
                .await?;
            let cap = format!("{} <b>Full answer</b> (too long for chat)", self.premium.e("doc"));
            if let Some(doc_msg) = self
                .send_document_bytes(
                    chat_id,
                    md.as_bytes().to_vec(),
                    "answer.md",
                    Some(cap),
                    markup,
                )
                .await?
            {
                msgs.push(doc_msg);
            }
            return Ok(msgs);
        }

        if use_rich {
            return self
                .send_rich_message(chat_id, md, markup, None, queue_on_fail)
                .await;
        }

        let html = md_to_html(md, 6);
        let chunks = split_html(&html, DEFAULT_HTML_SPLIT_LIMIT);
        if chunks.len() > 6 {
            let mut msgs = Vec::new();
            if let Some(first) = chunks.first() {
                if let Some(m) = self
                    .send_html(chat_id, first, None, None, None, queue_on_fail)
                    .await?
                {
                    msgs.push(m);
                }
            }
            let cap = format!("{} <b>Full answer</b>", self.premium.e("doc"));
            if let Some(doc_msg) = self
                .send_document_bytes(
                    chat_id,
                    md.as_bytes().to_vec(),
                    "answer.md",
                    Some(cap),
                    markup,
                )
                .await?
            {
                msgs.push(doc_msg);
            }
            return Ok(msgs);
        }

        let mut msgs = Vec::new();
        if let Some(m) = self
            .send_html(chat_id, &html, markup, None, None, queue_on_fail)
            .await?
        {
            msgs.push(m);
        }
        Ok(msgs)
    }

    async fn send_document_bytes(
        &self,
        chat_id: i64,
        data: Vec<u8>,
        filename: &str,
        caption: Option<String>,
        markup: Option<InlineKeyboardMarkup>,
    ) -> Result<Option<Message>> {
        let bytes = Bytes::from(data);
        let cap_variants = match caption {
            Some(c) => {
                let stripped = strip_custom_emoji(&c);
                if stripped != c {
                    vec![Some(c), Some(stripped), None]
                } else {
                    vec![Some(c), None]
                }
            }
            None => vec![None],
        };
        let mk_plain = strip_markup_opt(markup.clone(), &self.premium);

        for (idx, cap) in cap_variants.into_iter().enumerate() {
            let cur_mk = if idx == 0 && self.premium.active() {
                markup.clone()
            } else {
                mk_plain.clone()
            };
            let opts = SendMediaOptions {
                caption: cap,
                parse_mode: Some("HTML".to_string()),
                reply_markup: cur_mk,
                ..Default::default()
            };
            match tg_retry(self.retries, self.retry_cap_secs, || {
                self.client.send_document(
                    chat_id,
                    MediaInput::from_bytes(bytes.clone(), filename.to_string()),
                    opts.clone(),
                )
            })
            .await
            {
                Ok(m) => return Ok(Some(m)),
                Err(err) if err.is_chat_unavailable() => return Ok(None),
                Err(BridgeError::BotApi { code: 400, .. }) => continue,
                Err(err) => return Err(err),
            }
        }
        Ok(None)
    }

    /// Send an interactive Rich Card message, falling back cleanly to plain Rich or
    /// `rich_to_html_card`-clamped HTML. Returns `(sent_message, used_rich)`.
    pub async fn send_rich_card_message(
        &self,
        chat_id: i64,
        md: &str,
        markup: Option<InlineKeyboardMarkup>,
    ) -> Result<(Option<Message>, bool)> {
        let prepared = self.prepare_rich_markdown(md);
        let rm = sanitize_markup_callbacks(markup, |raw| self.register_ask_route(raw))
            .filter(|m| !m.inline_keyboard.is_empty());
        let rtl = is_rtl_dominant(&prepared);
        let plain_md = strip_md_custom_emoji(&prepared);
        let plain_mk = strip_markup_opt(rm.clone(), &self.premium);

        let mut attempts: Vec<(String, Option<InlineKeyboardMarkup>)> = Vec::new();
        if self.premium.active() && (plain_md != prepared || has_icons(rm.as_ref())) {
            attempts.push((prepared.clone(), rm));
        }
        attempts.push((plain_md.clone(), plain_mk.clone()));

        let total_attempts = attempts.len();
        for (idx, (cur_md, cur_mk)) in attempts.into_iter().enumerate() {
            let params = SendRichMessageParams {
                chat_id,
                rich_message: InputRichMessage::markdown_with_rtl(cur_md.clone(), rtl),
                reply_markup: cur_mk.clone(),
                ..Default::default()
            };
            match tg_retry(self.retries, self.retry_cap_secs, || {
                self.client.send_rich_message(&params)
            })
            .await
            {
                Ok(m) => return Ok((Some(m), true)),
                Err(err) => {
                    if err.is_chat_unavailable() {
                        return Ok((None, false));
                    }
                    let has_prem =
                        has_icons(cur_mk.as_ref()) || self.premium.has_known_emoji_in_md(&cur_md);
                    if is_premium_error(&err) {
                        if is_strict_premium_rejection(&err, has_prem) {
                            self.disable_premium(&err.to_string());
                        }
                        if idx + 1 < total_attempts {
                            continue;
                        }
                    }
                    info!(chat_id, error = %err, "rich card rejected/failed -> HTML fallback");
                    break;
                }
            }
        }

        let card_html = rich_to_html_card(&plain_md);
        let msg = self
            .send_html(chat_id, &card_html, plain_mk, None, None, true)
            .await?;
        Ok((msg, false))
    }

    /// Edit an existing message as Rich Markdown, falling back cleanly to plain Rich or
    /// `rich_to_html_card` HTML, or sending a new card when `message_id` is `None`.
    pub async fn edit_or_send_rich(
        &self,
        chat_id: i64,
        message_id: Option<i64>,
        md: &str,
        markup: Option<InlineKeyboardMarkup>,
    ) -> Result<Option<Message>> {
        let Some(mid) = message_id else {
            let (msg, _) = self.send_rich_card_message(chat_id, md, markup).await?;
            return Ok(msg);
        };

        let prepared = self.prepare_rich_markdown(md);
        let rm = sanitize_markup_callbacks(markup, |raw| self.register_ask_route(raw))
            .filter(|m| !m.inline_keyboard.is_empty());
        let rtl = is_rtl_dominant(&prepared);
        let plain_md = strip_md_custom_emoji(&prepared);
        let plain_mk = strip_markup_opt(rm.clone(), &self.premium);

        let cur_md = if self.premium.active() {
            prepared.clone()
        } else {
            plain_md.clone()
        };
        let cur_mk = if self.premium.active() {
            rm
        } else {
            plain_mk.clone()
        };

        let p1 = EditMessageTextParams {
            chat_id: Some(chat_id),
            message_id: Some(mid),
            rich_message: Some(InputRichMessage::markdown_with_rtl(cur_md.clone(), rtl)),
            reply_markup: cur_mk.clone(),
            ..Default::default()
        };
        match tg_retry(self.retries, self.retry_cap_secs, || {
            self.client.edit_message_text(&p1)
        })
        .await
        {
            Ok(_) => return Ok(None),
            Err(err) if err.is_not_modified() || err.is_chat_unavailable() => return Ok(None),
            Err(err) => {
                let has_prem =
                    has_icons(cur_mk.as_ref()) || self.premium.has_known_emoji_in_md(&cur_md);
                if matches!(err, BridgeError::BotApi { code: 400, .. })
                    && (cur_md != plain_md || has_icons(cur_mk.as_ref()))
                    && is_premium_error(&err)
                {
                    if is_strict_premium_rejection(&err, has_prem) {
                        self.disable_premium(&err.to_string());
                    }
                    let p2 = EditMessageTextParams {
                        chat_id: Some(chat_id),
                        message_id: Some(mid),
                        rich_message: Some(InputRichMessage::markdown_with_rtl(plain_md.clone(), rtl)),
                        reply_markup: plain_mk.clone(),
                        ..Default::default()
                    };
                    match tg_retry(self.retries, self.retry_cap_secs, || {
                        self.client.edit_message_text(&p2)
                    })
                    .await
                    {
                        Ok(_) => return Ok(None),
                        Err(e2) if e2.is_not_modified() || e2.is_chat_unavailable() => {
                            return Ok(None)
                        }
                        Err(_) => {}
                    }
                }
            }
        }

        let html_card = rich_to_html_card(&plain_md);
        self.edit_or_send_html(chat_id, Some(mid), &html_card, plain_mk)
            .await
    }

    /// Drain due items from [`OutQueue`], sending HTML/plain text and updating `done` / `failed`.
    pub async fn flush_outbox(&self) -> Result<(usize, usize)> {
        let client = Arc::clone(&self.client);
        let premium = Arc::clone(&self.premium);

        self.outbox
            .drain(|item| {
                let client = Arc::clone(&client);
                let premium = Arc::clone(&premium);
                async move {
                    let mk: Option<InlineKeyboardMarkup> = item
                        .markup
                        .as_deref()
                        .and_then(|raw| serde_json::from_str(raw).ok());

                    let params = SendMessageParams {
                        chat_id: item.chat,
                        text: item.text.clone(),
                        parse_mode: Some("HTML".to_string()),
                        link_preview_options: disable_preview(),
                        reply_markup: mk.clone(),
                        ..Default::default()
                    };

                    match client.send_message(&params).await {
                        Ok(_) => true,
                        Err(err) if err.is_chat_unavailable() => true, // drop dead chat
                        Err(BridgeError::BotApi { code: 400, .. }) => {
                            let stripped_text = strip_custom_emoji(&item.text);
                            let stripped_mk = strip_markup_opt(mk, &premium);
                            let p2 = SendMessageParams {
                                chat_id: item.chat,
                                text: stripped_text.clone(),
                                parse_mode: Some("HTML".to_string()),
                                link_preview_options: disable_preview(),
                                reply_markup: stripped_mk.clone(),
                                ..Default::default()
                            };
                            match client.send_message(&p2).await {
                                Ok(_) => true,
                                Err(e2) if e2.is_chat_unavailable() => true,
                                Err(BridgeError::BotApi { code: 400, .. }) => {
                                    let plain = cut_utf16(
                                        &strip_html_to_plain(&stripped_text),
                                        TG_TEXT_LIMIT,
                                    )
                                    .to_string();
                                    let p3 = SendMessageParams {
                                        chat_id: item.chat,
                                        text: plain,
                                        parse_mode: None,
                                        link_preview_options: disable_preview(),
                                        reply_markup: stripped_mk,
                                        ..Default::default()
                                    };
                                    match client.send_message(&p3).await {
                                        Ok(_) => true,
                                        Err(e3) if !e3.is_retryable() => true,
                                        Err(_) => false,
                                    }
                                }
                                Err(e2) if !e2.is_retryable() => true,
                                Err(_) => false,
                            }
                        }
                        Err(err) if !err.is_retryable() => true,
                        Err(_) => false,
                    }
                }
            })
            .await
    }

    /// Scan `outbox_dir` for non-hidden files in sorted order (`<= max_files`, `<= max_bytes`),
    /// dispatch via `send_photo` / `send_animation` / `send_video` / `send_audio` / `send_voice`
    /// / `send_document`, and return a secret-safe [`OutboxDeliveryReport`].
    pub async fn deliver_outbox_files(
        &self,
        chat_id: i64,
        outbox_dir: &Path,
        max_files: usize,
        max_bytes: usize,
    ) -> Result<OutboxDeliveryReport> {
        self.deliver_outbox_files_excluding(
            chat_id,
            outbox_dir,
            max_files,
            max_bytes,
            &HashSet::new(),
        )
        .await
    }

    /// Variant of [`Self::deliver_outbox_files`] excluding canonical paths already delivered as widgets.
    pub async fn deliver_outbox_files_excluding(
        &self,
        chat_id: i64,
        outbox_dir: &Path,
        max_files: usize,
        max_bytes: usize,
        skip_paths: &HashSet<PathBuf>,
    ) -> Result<OutboxDeliveryReport> {
        self.deliver_outbox_files_guarded(
            chat_id,
            outbox_dir,
            max_files,
            max_bytes,
            skip_paths,
            true,
            &[],
        )
        .await
    }

    /// Variant of [`Self::deliver_outbox_files_excluding`] with configurable secret-leak scanning
    /// against both standard secret patterns and live `extra_secrets` literals.
    #[allow(clippy::too_many_arguments)]
    pub async fn deliver_outbox_files_guarded(
        &self,
        chat_id: i64,
        outbox_dir: &Path,
        max_files: usize,
        max_bytes: usize,
        skip_paths: &HashSet<PathBuf>,
        scan_secrets: bool,
        extra_secrets: &[String],
    ) -> Result<OutboxDeliveryReport> {
        let mut report = OutboxDeliveryReport::default();
        if !outbox_dir.is_dir() {
            return Ok(report);
        }

        let files: Vec<PathBuf> = collect_non_hidden_files(outbox_dir)?
            .into_iter()
            .filter(|p| {
                let canon = p.canonicalize().unwrap_or_else(|_| p.clone());
                !skip_paths.contains(&canon) && !skip_paths.contains(p)
            })
            .collect();
        let cap = if max_files == 0 { 10 } else { max_files };
        let byte_cap = if max_bytes == 0 {
            MAX_UPLOAD_BYTES
        } else {
            max_bytes
        };

        if files.len() > cap {
            report.overflow_count = files.len() - cap;
        }

        let extra_refs: Vec<&str> = extra_secrets.iter().map(String::as_str).collect();

        for path in files.into_iter().take(cap) {
            let fname = path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("file.bin")
                .to_string();
            let meta = match tokio::fs::metadata(&path).await {
                Ok(m) => m,
                Err(err) => {
                    report.errors.push(redact_secrets_in_text(&format!(
                        "{fname}: {err}"
                    )));
                    continue;
                }
            };
            let size = meta.len();
            if size == 0 {
                report.skipped_empty.push(fname);
                continue;
            }
            if size > byte_cap as u64 {
                report.skipped_oversize.push(fname.clone());
                let size_mb = size / (1024 * 1024);
                let limit_mb = byte_cap / (1024 * 1024);
                let msg = format!(
                    "{} <code>{}</code> is {} MB — over the {} MB bot upload limit.",
                    self.premium.e("warn"),
                    esc(&fname),
                    size_mb,
                    limit_mb
                );
                let _ = self.send_html_simple(chat_id, &msg, None).await;
                continue;
            }

            if scan_secrets {
                let findings =
                    scan_file_for_secrets(&path, DEFAULT_MAX_SECRET_SCAN_BYTES, &extra_refs);
                if !findings.is_empty() {
                    let kinds: Vec<String> =
                        findings.iter().map(|f| f.kind.to_string()).collect();
                    warn!(
                        file = %fname,
                        kinds = %kinds.join(","),
                        "blocked outbox file containing suspected secret"
                    );
                    report.blocked_secrets.push((fname.clone(), kinds.clone()));
                    let msg = format!(
                        "🛡 <b>Blocked outbox file</b> <code>{}</code> — suspected secret detected (<code>{}</code>).\n<i>Inspect or redact locally before sharing.</i>",
                        esc(&fname),
                        esc(&kinds.join(", "))
                    );
                    let _ = self.send_html_simple(chat_id, &msg, None).await;
                    continue;
                }
            }

            let cap_html = format!("<code>{}</code>", esc(&fname));
            let opts = SendMediaOptions {
                caption: Some(cap_html),
                parse_mode: Some("HTML".to_string()),
                ..Default::default()
            };

            let ext = path
                .extension()
                .and_then(|s| s.to_str())
                .map(|s| s.to_ascii_lowercase())
                .unwrap_or_default();

            let res = if IMG_EXTS.contains(&ext.as_str()) && size <= PHOTO_MAX_BYTES {
                tg_retry(self.retries, self.retry_cap_secs, || {
                    self.client
                        .send_photo(chat_id, MediaInput::from_path(&path), opts.clone())
                })
                .await
            } else if ext == "gif" {
                tg_retry(self.retries, self.retry_cap_secs, || {
                    self.client
                        .send_animation(chat_id, MediaInput::from_path(&path), opts.clone())
                })
                .await
            } else if VID_EXTS.contains(&ext.as_str()) {
                let mut vopts = opts.clone();
                vopts.supports_streaming = Some(true);
                tg_retry(self.retries, self.retry_cap_secs, || {
                    self.client
                        .send_video(chat_id, MediaInput::from_path(&path), vopts.clone())
                })
                .await
            } else if AUD_EXTS.contains(&ext.as_str()) {
                tg_retry(self.retries, self.retry_cap_secs, || {
                    self.client
                        .send_audio(chat_id, MediaInput::from_path(&path), opts.clone())
                })
                .await
            } else if VOICE_EXTS.contains(&ext.as_str()) {
                tg_retry(self.retries, self.retry_cap_secs, || {
                    self.client
                        .send_voice(chat_id, MediaInput::from_path(&path), opts.clone())
                })
                .await
            } else {
                tg_retry(self.retries, self.retry_cap_secs, || {
                    self.client
                        .send_document(chat_id, MediaInput::from_path(&path), opts.clone())
                })
                .await
            };

            match res {
                Ok(_) => report.delivered.push(fname),
                Err(BridgeError::BotApi { code: 400, .. }) => {
                    // Fallback to generic sendDocument if media-specific endpoint rejected metadata
                    match tg_retry(self.retries, self.retry_cap_secs, || {
                        self.client
                            .send_document(chat_id, MediaInput::from_path(&path), opts.clone())
                    })
                    .await
                    {
                        Ok(_) => report.delivered.push(fname),
                        Err(e2) => report.errors.push(redact_secrets_in_text(&format!(
                            "{fname}: {e2}"
                        ))),
                    }
                }
                Err(err) => {
                    report.errors.push(redact_secrets_in_text(&format!(
                        "{fname}: {err}"
                    )));
                }
            }
        }

        if report.overflow_count > 0 {
            let notice = format!(
                "{} {} more file(s) in outbox (limit {cap} per turn).",
                self.premium.e("folder"),
                report.overflow_count
            );
            let _ = self.send_html_simple(chat_id, &notice, None).await;
        }

        Ok(report)
    }
}

fn collect_non_hidden_files(root: &Path) -> Result<Vec<PathBuf>> {
    let mut visited = BTreeSet::new();
    let mut stack = vec![root.to_path_buf()];
    let mut out = Vec::new();

    while let Some(dir) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(it) => it,
            Err(e) => return Err(BridgeError::io(format!("read_dir {}", dir.display()), e)),
        };
        for entry_res in entries {
            let entry = match entry_res {
                Ok(e) => e,
                Err(_) => continue,
            };
            let name = entry.file_name();
            if name.to_string_lossy().starts_with('.') {
                continue;
            }
            let path = entry.path();
            let Ok(meta) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            if meta.file_type().is_symlink() {
                continue;
            }
            if meta.is_dir() {
                stack.push(path);
            } else if meta.is_file() && visited.insert(path.clone()) {
                out.push(path);
            }
        }
    }

    out.sort();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use agy_core::tg::{Chat, InlineKeyboardButton, User};
    use agy_net::NetConfig;
    use axum::extract::{Path as AxumPath, Request, State};
    use axum::http::StatusCode;
    use axum::response::{IntoResponse, Response};
    use axum::routing::post;
    use axum::{Json, Router};
    use serde_json::{json, Value};
    use std::collections::VecDeque;
    use tempfile::TempDir;
    use tokio::net::TcpListener;
    use tokio::sync::Mutex;

    #[derive(Clone, Default)]
    struct MockApi {
        calls: Arc<Mutex<Vec<(String, Value)>>>,
        multipart_methods: Arc<Mutex<Vec<String>>>,
        responses: Arc<Mutex<VecDeque<(u16, Value)>>>,
    }

    impl MockApi {
        async fn push_err(&self, code: u16, desc: &str) {
            self.responses.lock().await.push_back((
                code,
                json!({ "ok": false, "error_code": code, "description": desc }),
            ));
        }
        async fn push_ok_msg(&self, id: i64) {
            self.responses.lock().await.push_back((
                200,
                json!({ "ok": true, "result": sample_msg(id) }),
            ));
        }
    }

    fn sample_msg(id: i64) -> Message {
        Message {
            message_id: id,
            from_user: Some(User {
                id: 42,
                is_bot: true,
                first_name: "Bot".into(),
                last_name: None,
                username: Some("bot".into()),
                language_code: None,
                is_premium: Some(true),
            }),
            chat: Chat {
                id: 100,
                kind: "private".into(),
                username: None,
                first_name: None,
            },
            message_thread_id: None,
            text: Some("ok".into()),
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

    async fn mock_handler(
        State(st): State<MockApi>,
        AxumPath((_tok, method)): AxumPath<(String, String)>,
        req: Request,
    ) -> Response {
        let is_mp = req
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|ct| ct.starts_with("multipart/form-data"));

        if is_mp {
            let _ = axum::body::to_bytes(req.into_body(), 64 * 1024 * 1024).await;
            st.multipart_methods.lock().await.push(method.clone());
        } else {
            let bytes = axum::body::to_bytes(req.into_body(), 2 * 1024 * 1024)
                .await
                .unwrap_or_default();
            let val: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
            st.calls.lock().await.push((method.clone(), val));
        }

        if let Some((code, body)) = st.responses.lock().await.pop_front() {
            let status = StatusCode::from_u16(code).unwrap_or(StatusCode::BAD_REQUEST);
            return (status, Json(body)).into_response();
        }
        (
            StatusCode::OK,
            Json(json!({ "ok": true, "result": sample_msg(77) })),
        )
            .into_response()
    }

    async fn spawn_mock() -> (MockApi, String, TempDir) {
        let st = MockApi::default();
        let app = Router::new()
            .route("/bot{token}/{method}", post(mock_handler))
            .with_state(st.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        let dir = TempDir::new().unwrap();
        (st, format!("http://{addr}"), dir)
    }

    fn make_bridge(api_base: &str, dir: &TempDir, premium_on: bool) -> RenderBridge {
        let client = Arc::new(
            BotApiClient::new(
                "123:TEST_SECRET_TOKEN",
                NetConfig::default().with_api_base(api_base),
            )
            .unwrap(),
        );
        let premium = Arc::new(PremiumState::new(premium_on));
        let outbox = Arc::new(OutQueue::open(dir.path().join("outbox.json")).unwrap());
        let store = Arc::new(StateStore::open(dir.path().join("state.json")).unwrap());
        RenderBridge::new(client, premium, outbox)
            .with_state_store(store)
            .with_retry_config(1, 0.01)
    }

    #[tokio::test]
    async fn rich_premium_rejection_disables_premium_and_falls_back_to_html_then_plain() {
        let (st, base, dir) = spawn_mock().await;
        let rb = make_bridge(&base, &dir, true);

        // 1: sendRichMessage with premium emoji -> 400 DOCUMENT_INVALID
        // 2: retried sendRichMessage stripped -> 400 RICH_UNSUPPORTED
        // 3: sendMessage HTML -> 400 can't parse entities
        // 4: sendMessage plain text -> 200 OK
        st.push_err(400, "Bad Request: DOCUMENT_INVALID").await;
        st.push_err(400, "Bad Request: rich message unsupported").await;
        st.push_err(400, "Bad Request: can't parse entities at byte 3").await;
        st.push_ok_msg(99).await;

        let mk = InlineKeyboardMarkup::new(vec![vec![InlineKeyboardButton {
            text: "Ok".into(),
            callback_data: Some("ok".into()),
            icon_custom_emoji_id: Some("5427009714745517609".into()),
            ..Default::default()
        }]]);

        let md = format!("### {} Heading\n\n**bold** <tag>", rb.premium().md("ok"));
        let msgs = rb.send_rich_message(100, &md, Some(mk), None, true).await.unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].message_id, 99);
        assert!(!rb.premium().active());

        let calls = st.calls.lock().await;
        assert_eq!(calls.len(), 4);
        assert_eq!(calls[0].0, "sendRichMessage");
        assert!(calls[0].1["rich_message"]["markdown"]
            .as_str()
            .unwrap()
            .contains("tg://emoji?id="));
        assert_eq!(calls[1].0, "sendRichMessage");
        assert!(!calls[1].1["rich_message"]["markdown"]
            .as_str()
            .unwrap()
            .contains("tg://emoji?id="));
        assert_eq!(calls[2].0, "sendMessage");
        assert_eq!(calls[2].1["parse_mode"], json!("HTML"));
        assert_eq!(calls[3].0, "sendMessage");
        assert!(calls[3].1.get("parse_mode").is_none());
    }

    #[tokio::test]
    async fn edit_html_handles_not_modified_and_outqueue_flush() {
        let (st, base, dir) = spawn_mock().await;
        let rb = make_bridge(&base, &dir, false);

        st.push_err(400, "Bad Request: message is not modified").await;
        rb.edit_html(100, 5, "<b>same</b>", None).await.unwrap();

        // Simulate persistent network outage -> send_html queues into OutQueue
        let dead_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_addr = dead_listener.local_addr().unwrap();
        drop(dead_listener);
        let dead_client = Arc::new(
            BotApiClient::new(
                "123:TEST",
                NetConfig::default().with_api_base(format!("http://{dead_addr}")),
            )
            .unwrap(),
        );
        let dead_rb = RenderBridge::new(
            dead_client,
            Arc::new(PremiumState::new(false)),
            Arc::clone(rb.outbox()),
        )
        .with_retry_config(0, 0.01);

        let res = dead_rb.send_html_simple(100, "<b>queued</b>", None).await.unwrap();
        assert!(res.is_none());
        assert_eq!(rb.outbox().len(), 1);

        // Flush using healthy RenderBridge
        st.push_ok_msg(101).await;
        let (ok, fail) = rb.flush_outbox().await.unwrap();
        assert_eq!((ok, fail), (1, 0));
        assert!(rb.outbox().is_empty());
    }

    #[tokio::test]
    async fn deliver_outbox_files_dispatches_extensions_skips_hidden_and_respects_limits() {
        let (st, base, dir) = spawn_mock().await;
        let rb = make_bridge(&base, &dir, false);

        let outdir = dir.path().join("out");
        std::fs::create_dir_all(&outdir).unwrap();
        std::fs::write(outdir.join(".secret_hidden.txt"), b"ignore").unwrap();
        std::fs::write(outdir.join("01_pic.png"), b"png").unwrap();
        std::fs::write(outdir.join("02_anim.gif"), b"gif").unwrap();
        std::fs::write(outdir.join("03_vid.mp4"), b"mp4").unwrap();
        std::fs::write(outdir.join("04_aud.mp3"), b"mp3").unwrap();
        std::fs::write(outdir.join("05_voice.ogg"), b"ogg").unwrap();
        std::fs::write(outdir.join("06_doc.pdf"), b"pdf").unwrap();
        std::fs::write(outdir.join("07_empty.txt"), b"").unwrap();
        std::fs::write(outdir.join("08_big.bin"), vec![1u8; 200]).unwrap();

        let report = rb
            .deliver_outbox_files(100, &outdir, 10, 100)
            .await
            .unwrap();

        assert_eq!(
            report.delivered,
            vec![
                "01_pic.png",
                "02_anim.gif",
                "03_vid.mp4",
                "04_aud.mp3",
                "05_voice.ogg",
                "06_doc.pdf"
            ]
        );
        assert_eq!(report.skipped_empty, vec!["07_empty.txt"]);
        assert_eq!(report.skipped_oversize, vec!["08_big.bin"]);

        let methods = st.multipart_methods.lock().await.clone();
        assert_eq!(
            methods,
            vec![
                "sendPhoto",
                "sendAnimation",
                "sendVideo",
                "sendAudio",
                "sendVoice",
                "sendDocument"
            ]
        );
    }

    #[tokio::test]
    async fn edit_or_send_rich_card_clamps_html_fallback() {
        let (st, base, dir) = spawn_mock().await;
        let rb = make_bridge(&base, &dir, false);

        st.push_err(400, "Bad Request: rich unsupported").await;
        st.push_ok_msg(50).await;

        let big_md = format!("# Card\n\n{}", "word ".repeat(1500));
        let msg = rb.edit_or_send_rich(100, Some(10), &big_md, None).await.unwrap();
        assert!(msg.is_none()); // edit succeeded via HTML fallback

        let calls = st.calls.lock().await;
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].0, "editMessageText");
        assert!(calls[0].1.get("rich_message").is_some());
        assert_eq!(calls[1].0, "editMessageText");
        let sent_html = calls[1].1["text"].as_str().unwrap();
        assert!(utf16_len(sent_html) <= 4096);
    }

    #[tokio::test]
    async fn rich_ask_over_64b_maps_to_askr_sets_rtl_and_html_fallback_extracts_buttons() {
        let (st, base, dir) = spawn_mock().await;
        let rb = make_bridge(&base, &dir, true);

        // 1. Persian prompt + >64B ask:<persian> button sends valid <=64B askr: token and is_rtl=true
        let long_choice = "بررسی_کامل_سلامت_اکانت_ها_و_پروکسی_های_سیستم_با_جزئیات";
        let md = format!(
            "سلام! \\(\\alpha + \\beta = \\gamma\\)\n\n<tg-button-row>\n<tg-button type=\"callback_data\" style=\"primary\" data=\"ask:{long_choice}\">اجرا</tg-button>\n</tg-button-row>"
        );
        st.push_ok_msg(201).await;
        let msgs = rb.send_rich_message(100, &md, None, None, true).await.unwrap();
        assert_eq!(msgs[0].message_id, 201);

        {
            let calls = st.calls.lock().await;
            let sent_md = calls[0].1["rich_message"]["markdown"].as_str().unwrap();
            assert_eq!(calls[0].1["rich_message"]["is_rtl"], json!(true));
            assert!(sent_md.contains("$\\alpha + \\beta = \\gamma$"));
            assert!(sent_md.contains("data=\"askr:"));
            let key_start = sent_md.find("askr:").unwrap();
            let key_end = key_start + sent_md[key_start..].find('"').unwrap();
            let askr_key = &sent_md[key_start..key_end];
            assert!(askr_key.len() <= 64);
            assert_eq!(rb.resolve_ask_route(askr_key).as_deref(), Some(long_choice));
        }

        // 2. When Rich fails (e.g. non-premium non-retryable error), HTML fallback converts button row into reply_markup & renders LaTeX cleanly
        st.calls.lock().await.clear();
        st.push_err(400, "Bad Request: RICH_UNSUPPORTED").await;
        st.push_ok_msg(202).await;
        rb.send_rich_message(100, &md, None, None, true).await.unwrap();
        {
            let calls2 = st.calls.lock().await;
            assert_eq!(calls2.len(), 2);
            assert_eq!(calls2[1].0, "sendMessage");
            let html_text = calls2[1].1["text"].as_str().unwrap();
            assert!(!html_text.contains("<tg-button"));
            assert!(html_text.contains("<code>α + β = γ</code>"));
            let kb0 = calls2[1].1["reply_markup"]["inline_keyboard"][0][0]["callback_data"]
                .as_str()
                .unwrap();
            assert!(kb0.starts_with("askr:") && kb0.len() <= 64);
        }

        // 3. Unknown AI-emitted emoji rejection does NOT kill global PremiumState
        st.calls.lock().await.clear();
        let bad_ai_md = "نتیجه ![🔥](tg://emoji?id=999999999999)";
        st.push_err(400, "Bad Request: DOCUMENT_INVALID").await;
        st.push_ok_msg(203).await;
        rb.send_rich_message(100, bad_ai_md, None, None, true).await.unwrap();
        assert!(
            rb.premium().active(),
            "unknown AI-emitted custom_emoji rejection must strip/retry that message without disabling global Premium"
        );
    }

    #[test]
    fn sanitize_markup_callbacks_cleans_controls_empty_and_oversize() {
        let mk = InlineKeyboardMarkup::new(vec![
            vec![
                InlineKeyboardButton::callback("Ok", "cmd:\nok\r\t"),
                InlineKeyboardButton::callback("Empty", "   \n  "),
            ],
            vec![InlineKeyboardButton::callback(
                "Long",
                "x:".to_string() + &"ب".repeat(50),
            )],
        ]);
        let clean = sanitize_markup_callbacks(Some(mk), |_| None).unwrap();
        assert_eq!(clean.inline_keyboard.len(), 2);
        assert_eq!(clean.inline_keyboard[0].len(), 1);
        assert_eq!(clean.inline_keyboard[0][0].callback_data.as_deref(), Some("cmd: ok"));
        let cb2 = clean.inline_keyboard[1][0].callback_data.as_deref().unwrap();
        assert!(cb2.len() <= 64);
    }
}
