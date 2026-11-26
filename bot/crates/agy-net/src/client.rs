//! Typed Telegram Bot API 10.4 HTTP client with full-jitter retry, circuit-breaker failover,
//! empty-string JSON preservation, multipart media upload, and streaming bounded downloads.

use std::borrow::Borrow;
use std::fmt;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use agy_core::tg::{
    ApiResponse, BotCommand, BotCommandScope, InlineKeyboardMarkup, InlineQueryResultArticle,
    InputRichMessage, LinkPreviewOptions, MenuButton, Message, MessageEntity, ReplyParameters,
    TelegramFile, Update, User, WebhookInfo,
};
use agy_core::{BridgeError, Result};
use bytes::Bytes;
use futures_util::StreamExt;
use rand::Rng;
use reqwest::multipart::{Form, Part};
use reqwest::StatusCode;
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::{json, Value};
use tokio::io::AsyncWriteExt;
use tracing::warn;
use url::Url;

use crate::proxy::{NetConfig, ProxyMode, ProxyPool};

/// Cloud Bot API maximum file download size (20 MB).
pub const MAX_DOWNLOAD_BYTES: usize = 20 * 1024 * 1024;

/// Cloud Bot API maximum bot file upload size (50 MB).
pub const MAX_UPLOAD_BYTES: usize = 50 * 1024 * 1024;

/// AWS 'full jitter': `uniform(0, min(cap_secs, base_secs * 2^attempt))`.
pub fn full_jitter(attempt: u32, base_secs: f64, cap_secs: f64) -> f64 {
    let mut rng = rand::thread_rng();
    full_jitter_with(attempt, base_secs, cap_secs, || rng.gen::<f64>())
}

/// Deterministic full-jitter calculation using a caller-supplied unit random sample in `[0, 1)`.
pub fn full_jitter_with<R: FnMut() -> f64>(
    attempt: u32,
    base_secs: f64,
    cap_secs: f64,
    mut rnd: R,
) -> f64 {
    let exp = 2_f64.powi(attempt.min(30) as i32);
    let upper = (base_secs.max(0.0) * exp).min(cap_secs.max(0.0));
    let sample = rnd().clamp(0.0, 1.0);
    sample * upper
}

/// Longest single flood-control wait `tg_retry` will sleep (seconds). A longer `retry_after`
/// is returned to the caller at once: sends with `queue_on_fail` go to the durable outbox,
/// progress edits are dropped (the next tick redraws).
pub static MAX_RETRY_AFTER_SECS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(30);
/// Total flood-control sleep allowed for one call across all its retries (seconds).
pub static MAX_RETRY_AFTER_TOTAL_SECS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(60);

/// Execute an async Telegram Bot API call with retries:
/// - `429 RateLimited`: honors `retry_after_secs` up to [`MAX_RETRY_AFTER_SECS`] per wait and
///   [`MAX_RETRY_AFTER_TOTAL_SECS`] per call; beyond that the error is returned (queue/drop)
/// - retryable `Network` / `5xx BotApi`: sleeps `0.3 + full_jitter(attempt, 0.8, cap_secs)`
/// - non-retryable `4xx` / validation errors: returns immediately.
pub async fn tg_retry<T, F, Fut>(retries: u32, cap_secs: f64, mut op: F) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T>>,
{
    let max_one = MAX_RETRY_AFTER_SECS.load(std::sync::atomic::Ordering::Relaxed);
    let max_total = MAX_RETRY_AFTER_TOTAL_SECS.load(std::sync::atomic::Ordering::Relaxed);
    let mut flood_waited: u64 = 0;
    for attempt in 0..=retries {
        match op().await {
            Ok(v) => return Ok(v),
            Err(err) => {
                if attempt == retries {
                    return Err(err);
                }
                match &err {
                    BridgeError::RateLimited {
                        retry_after_secs, ..
                    } => {
                        let wait_secs = (*retry_after_secs).max(1);
                        if wait_secs > max_one || flood_waited + wait_secs > max_total {
                            warn!(retry_after_secs = wait_secs, waited = flood_waited, "Telegram flood control too long; giving up this call (queue/drop)");
                            return Err(err);
                        }
                        flood_waited += wait_secs;
                        warn!(retry_after_secs = wait_secs, "Telegram flood control; sleeping");
                        tokio::time::sleep(Duration::from_secs(wait_secs)).await;
                    }
                    _ if err.is_retryable() => {
                        let delay = 0.3 + full_jitter(attempt, 0.8, cap_secs);
                        warn!(
                            attempt = attempt + 1,
                            delay_s = format_args!("{delay:.2}"),
                            err = %err,
                            "Telegram call failed; retrying"
                        );
                        tokio::time::sleep(Duration::from_secs_f64(delay)).await;
                    }
                    _ => return Err(err),
                }
            }
        }
    }
    Err(BridgeError::Internal("tg_retry loop exhausted".into()))
}

/// Media payload source for upload methods (`sendDocument`, `sendPhoto`, etc.).
#[derive(Debug, Clone)]
pub enum MediaInput {
    Bytes { data: Bytes, filename: String },
    Path(PathBuf),
    FileIdOrUrl(String),
}

impl MediaInput {
    pub fn from_bytes(data: impl Into<Bytes>, filename: impl Into<String>) -> Self {
        Self::Bytes {
            data: data.into(),
            filename: filename.into(),
        }
    }

    pub fn from_path(path: impl Into<PathBuf>) -> Self {
        Self::Path(path.into())
    }

    pub fn from_id_or_url(id_or_url: impl Into<String>) -> Self {
        Self::FileIdOrUrl(id_or_url.into())
    }
}

/// Optional metadata fields shared across Bot API media upload methods.
#[derive(Debug, Clone, Default)]
pub struct SendMediaOptions {
    pub message_thread_id: Option<i64>,
    pub caption: Option<String>,
    pub parse_mode: Option<String>,
    pub caption_entities: Option<Vec<MessageEntity>>,
    pub show_caption_above_media: Option<bool>,
    pub has_spoiler: Option<bool>,
    pub supports_streaming: Option<bool>,
    pub duration: Option<u32>,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub performer: Option<String>,
    pub title: Option<String>,
    pub disable_notification: Option<bool>,
    pub protect_content: Option<bool>,
    pub allow_paid_broadcast: Option<bool>,
    pub message_effect_id: Option<String>,
    pub reply_parameters: Option<ReplyParameters>,
    pub reply_markup: Option<InlineKeyboardMarkup>,
}

/// Parameters for `sendMessage`.
#[derive(Debug, Clone, Default, Serialize)]
pub struct SendMessageParams {
    pub chat_id: i64,
    pub text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_thread_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parse_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entities: Option<Vec<MessageEntity>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub link_preview_options: Option<LinkPreviewOptions>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disable_notification: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protect_content: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_paid_broadcast: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_effect_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply_parameters: Option<ReplyParameters>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply_markup: Option<InlineKeyboardMarkup>,
}

impl SendMessageParams {
    pub fn new(chat_id: i64, text: impl Into<String>) -> Self {
        Self {
            chat_id,
            text: text.into(),
            ..Default::default()
        }
    }

    pub fn html(chat_id: i64, html_text: impl Into<String>) -> Self {
        Self {
            chat_id,
            text: html_text.into(),
            parse_mode: Some("HTML".to_string()),
            ..Default::default()
        }
    }
}

/// Parameters for `sendRichMessage` (Bot API 10.4).
#[derive(Debug, Clone, Default, Serialize)]
pub struct SendRichMessageParams {
    pub chat_id: i64,
    pub rich_message: InputRichMessage,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_thread_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disable_notification: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protect_content: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_paid_broadcast: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_effect_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply_parameters: Option<ReplyParameters>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply_markup: Option<InlineKeyboardMarkup>,
}

/// Parameters for `sendRichMessageDraft` (Bot API 10.4 streaming markdown draft).
#[derive(Debug, Clone, Default, Serialize)]
pub struct SendRichMessageDraftParams {
    pub chat_id: i64,
    pub draft_id: i64,
    pub rich_message: InputRichMessage,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_thread_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub can_stop: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keep_on_stop: Option<bool>,
}

/// Parameters for `sendMessageDraft` (streaming text/HTML draft).
#[derive(Debug, Clone, Default, Serialize)]
pub struct SendMessageDraftParams {
    pub chat_id: i64,
    pub draft_id: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_thread_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parse_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entities: Option<Vec<MessageEntity>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub can_stop: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keep_on_stop: Option<bool>,
}

/// Parameters for `editMessageText` (supports HTML text or `rich_message`).
#[derive(Debug, Clone, Default, Serialize)]
pub struct EditMessageTextParams {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chat_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inline_message_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parse_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entities: Option<Vec<MessageEntity>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub link_preview_options: Option<LinkPreviewOptions>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rich_message: Option<InputRichMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply_markup: Option<InlineKeyboardMarkup>,
}

/// Parameters for `sendWidget` (Bot API 10.4).
#[derive(Debug, Clone, Default, Serialize)]
pub struct SendWidgetParams {
    pub chat_id: i64,
    pub html: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_thread_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub width: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub height: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_data: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chat_data: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caption: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parse_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caption_entities: Option<Vec<MessageEntity>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub show_caption_above_media: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_queries: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_shared: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disable_notification: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protect_content: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_paid_broadcast: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_effect_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply_parameters: Option<ReplyParameters>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply_markup: Option<InlineKeyboardMarkup>,
}

/// Parameters for `sendSharedWidget` (Bot API 10.4).
#[derive(Debug, Clone, Default, Serialize)]
pub struct SendSharedWidgetParams {
    pub chat_id: i64,
    pub widget_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_thread_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chat_data: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caption: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parse_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caption_entities: Option<Vec<MessageEntity>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub show_caption_above_media: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disable_notification: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protect_content: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_paid_broadcast: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_effect_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply_parameters: Option<ReplyParameters>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply_markup: Option<InlineKeyboardMarkup>,
}

/// Parameters for `editMessageWidgetData` (preserves `Some("")` to clear state).
#[derive(Debug, Clone, Default, Serialize)]
pub struct EditWidgetDataParams {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chat_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inline_message_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_data: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chat_data: Option<String>,
}

/// Parameters for `editSharedWidgetData` (preserves `""` to clear shared state).
#[derive(Debug, Clone, Default, Serialize)]
pub struct EditSharedWidgetDataParams {
    pub widget_id: String,
    pub public_data: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_time: Option<u32>,
}

/// Full options for `answerCallbackQuery`.
#[derive(Debug, Clone, Default, Serialize)]
pub struct AnswerCallbackQueryParams {
    pub callback_query_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub show_alert: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_time: Option<u32>,
}

#[derive(Debug)]
enum ApiCallFailure {
    /// Transport, timeout, or proxy/gateway failure — fail over to another route.
    RouteError(String),
    /// Telegram responded with an API-level error — route itself is healthy.
    TelegramError(BridgeError),
}

/// Industrial-strength Telegram Bot API 10.4 HTTP client backed by `ProxyPool`.
pub struct BotApiClient {
    api_base: String,
    bot_token: String,
    pool: Arc<ProxyPool>,
    default_timeout: Duration,
}

impl fmt::Debug for BotApiClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BotApiClient")
            .field("api_base", &self.api_base)
            .field("bot_token", &"[REDACTED]")
            .field("pool", &self.pool)
            .field("default_timeout", &self.default_timeout)
            .finish()
    }
}

impl BotApiClient {
    /// Create a new `BotApiClient` from `bot_token` and `NetConfig`.
    pub fn new(bot_token: impl Into<String>, config: NetConfig) -> Result<Self> {
        let default_timeout = config.default_request_timeout;
        let api_base = normalize_api_base(&config.api_base)?;
        let pool = Arc::new(ProxyPool::new(config)?);
        Self::build(bot_token.into(), api_base, pool, default_timeout)
    }

    /// Create a `BotApiClient` sharing an existing `ProxyPool`.
    pub fn with_pool(
        bot_token: impl Into<String>,
        api_base: impl AsRef<str>,
        pool: Arc<ProxyPool>,
        default_timeout: Duration,
    ) -> Result<Self> {
        let base = normalize_api_base(api_base.as_ref())?;
        Self::build(bot_token.into(), base, pool, default_timeout)
    }

    fn build(
        bot_token: String,
        api_base: String,
        pool: Arc<ProxyPool>,
        default_timeout: Duration,
    ) -> Result<Self> {
        let trimmed = bot_token.trim().to_string();
        if trimmed.is_empty() {
            return Err(BridgeError::Config("bot_token cannot be empty".into()));
        }
        Ok(Self {
            api_base,
            bot_token: trimmed,
            pool,
            default_timeout,
        })
    }

    pub fn api_base(&self) -> &str {
        &self.api_base
    }

    pub fn pool(&self) -> &Arc<ProxyPool> {
        &self.pool
    }

    fn method_url(&self, method: &str) -> String {
        format!("{}/bot{}/{}", self.api_base, self.bot_token, method)
    }

    fn file_url(&self, file_path: &str) -> String {
        format!(
            "{}/file/bot{}/{}",
            self.api_base,
            self.bot_token,
            file_path.trim_start_matches('/')
        )
    }

    fn sanitize_error(&self, msg: &str) -> String {
        let no_token = msg.replace(&self.bot_token, "[REDACTED]");
        self.pool.redact_secrets(&no_token)
    }

    fn format_reqwest_error(&self, err: reqwest::Error) -> String {
        let clean = err.without_url();
        self.sanitize_error(&clean.to_string())
    }

    /// Invoke a Bot API JSON method across the `ProxyPool` with automatic failover and hedged racing
    /// for idempotent methods.
    pub async fn call_json<T: DeserializeOwned>(
        &self,
        method: &str,
        payload: &Value,
        request_timeout: Option<Duration>,
    ) -> Result<T> {
        let timeout = request_timeout.unwrap_or(self.default_timeout);
        let url = self.method_url(method);
        let candidates = self.pool.select_candidates();
        let idempotent = is_idempotent_method(method);

        if self.pool.mode() == ProxyMode::Race && idempotent && candidates.len() >= 2 {
            return self
                .execute_json_hedged::<T>(&url, payload, timeout, &candidates)
                .await;
        }

        let mut last_route_err: Option<String> = None;
        for (idx, client, _label) in candidates {
            match self
                .send_json_once::<T>(idx, &client, &url, payload, timeout)
                .await
            {
                Ok(val) => return Ok(val),
                Err(ApiCallFailure::TelegramError(err)) => return Err(err),
                Err(ApiCallFailure::RouteError(msg)) => {
                    last_route_err = Some(msg);
                }
            }
        }

        Err(BridgeError::Network(
            last_route_err.unwrap_or_else(|| "no proxy routes available".into()),
        ))
    }

    async fn execute_json_hedged<T: DeserializeOwned>(
        &self,
        url: &str,
        payload: &Value,
        timeout: Duration,
        candidates: &[(usize, reqwest::Client, String)],
    ) -> Result<T> {
        let hedge_delay = self.pool.race_hedge_delay();
        let (idx0, ref client0, _) = candidates[0];
        let (idx1, ref client1, _) = candidates[1];

        let fut0 = self.send_json_once::<T>(idx0, client0, url, payload, timeout);
        tokio::pin!(fut0);

        match tokio::time::timeout(hedge_delay, &mut fut0).await {
            Ok(Ok(val)) => return Ok(val),
            Ok(Err(ApiCallFailure::TelegramError(err))) => return Err(err),
            Ok(Err(ApiCallFailure::RouteError(first_err))) => {
                let mut last_err = first_err;
                for (idx, client, _) in &candidates[1..] {
                    match self
                        .send_json_once::<T>(*idx, client, url, payload, timeout)
                        .await
                    {
                        Ok(val) => return Ok(val),
                        Err(ApiCallFailure::TelegramError(err)) => return Err(err),
                        Err(ApiCallFailure::RouteError(msg)) => last_err = msg,
                    }
                }
                return Err(BridgeError::Network(last_err));
            }
            Err(_hedge_elapsed) => {}
        }

        // Hedged race: primary is still in flight; start secondary concurrently.
        let fut1 = self.send_json_once::<T>(idx1, client1, url, payload, timeout);
        tokio::pin!(fut1);

        let (winner_done_first, other_is_fut0) = tokio::select! {
            res0 = &mut fut0 => (res0, false),
            res1 = &mut fut1 => (res1, true),
        };

        let mut last_route_err = match winner_done_first {
            Ok(val) => return Ok(val),
            Err(ApiCallFailure::TelegramError(err)) => return Err(err),
            Err(ApiCallFailure::RouteError(err0)) => {
                let second_res = if other_is_fut0 {
                    fut0.await
                } else {
                    fut1.await
                };
                match second_res {
                    Ok(val) => return Ok(val),
                    Err(ApiCallFailure::TelegramError(err)) => return Err(err),
                    Err(ApiCallFailure::RouteError(err1)) => {
                        format!("{err0}; {err1}")
                    }
                }
            }
        };

        for (idx, client, _) in &candidates[2..] {
            match self
                .send_json_once::<T>(*idx, client, url, payload, timeout)
                .await
            {
                Ok(val) => return Ok(val),
                Err(ApiCallFailure::TelegramError(err)) => return Err(err),
                Err(ApiCallFailure::RouteError(msg)) => last_route_err = msg,
            }
        }

        Err(BridgeError::Network(last_route_err))
    }

    async fn send_json_once<T: DeserializeOwned>(
        &self,
        route_idx: usize,
        client: &reqwest::Client,
        url: &str,
        payload: &Value,
        timeout: Duration,
    ) -> std::result::Result<T, ApiCallFailure> {
        let start = Instant::now();
        let resp = match client.post(url).json(payload).timeout(timeout).send().await {
            Ok(r) => r,
            Err(e) => {
                let msg = self.format_reqwest_error(e);
                self.pool.record_failure(route_idx, &msg);
                return Err(ApiCallFailure::RouteError(msg));
            }
        };

        self.handle_api_http_response(route_idx, resp, start).await
    }

    /// Execute a single multipart Bot API call on the best healthy route.
    /// For multi-route failover on media uploads, prefer `call_multipart_with`.
    pub async fn call_multipart<T: DeserializeOwned>(
        &self,
        method: &str,
        form: Form,
        request_timeout: Option<Duration>,
    ) -> Result<T> {
        let timeout = request_timeout.unwrap_or_else(|| self.default_timeout.max(Duration::from_secs(180)));
        let url = self.method_url(method);
        let candidates = self.pool.select_candidates();
        let Some((idx, client, _)) = candidates.into_iter().next() else {
            return Err(BridgeError::Network("no proxy routes available".into()));
        };
        let start = Instant::now();
        let resp = match client.post(&url).multipart(form).timeout(timeout).send().await {
            Ok(r) => r,
            Err(e) => {
                let msg = self.format_reqwest_error(e);
                self.pool.record_failure(idx, &msg);
                return Err(BridgeError::Network(msg));
            }
        };

        match self.handle_api_http_response(idx, resp, start).await {
            Ok(v) => Ok(v),
            Err(ApiCallFailure::TelegramError(e)) => Err(e),
            Err(ApiCallFailure::RouteError(msg)) => Err(BridgeError::Network(msg)),
        }
    }

    /// Invoke a multipart Bot API method with full multi-route proxy failover by rebuilding
    /// the `Form` from zero-copy `Bytes` / text parts per route attempt.
    pub async fn call_multipart_with<T, F>(
        &self,
        method: &str,
        mut make_form: F,
        request_timeout: Option<Duration>,
    ) -> Result<T>
    where
        T: DeserializeOwned,
        F: FnMut() -> Result<Form>,
    {
        let timeout = request_timeout.unwrap_or_else(|| self.default_timeout.max(Duration::from_secs(180)));
        let url = self.method_url(method);
        let candidates = self.pool.select_candidates();
        let mut last_route_err: Option<String> = None;

        for (idx, client, _) in candidates {
            let form = make_form()?;
            let start = Instant::now();
            let resp = match client.post(&url).multipart(form).timeout(timeout).send().await {
                Ok(r) => r,
                Err(e) => {
                    let msg = self.format_reqwest_error(e);
                    self.pool.record_failure(idx, &msg);
                    last_route_err = Some(msg);
                    continue;
                }
            };
            match self.handle_api_http_response(idx, resp, start).await {
                Ok(v) => return Ok(v),
                Err(ApiCallFailure::TelegramError(e)) => return Err(e),
                Err(ApiCallFailure::RouteError(msg)) => {
                    last_route_err = Some(msg);
                }
            }
        }

        Err(BridgeError::Network(
            last_route_err.unwrap_or_else(|| "no proxy routes available".into()),
        ))
    }

    async fn handle_api_http_response<T: DeserializeOwned>(
        &self,
        route_idx: usize,
        resp: reqwest::Response,
        start: Instant,
    ) -> std::result::Result<T, ApiCallFailure> {
        let status = resp.status();
        let retry_after_hdr = resp
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .map(ToOwned::to_owned);

        let body = match resp.bytes().await {
            Ok(b) => b,
            Err(e) => {
                let msg = self.format_reqwest_error(e);
                self.pool.record_failure(route_idx, &msg);
                return Err(ApiCallFailure::RouteError(msg));
            }
        };

        let elapsed = start.elapsed();

        if status == StatusCode::PROXY_AUTHENTICATION_REQUIRED {
            let msg = "proxy returned HTTP 407 Proxy Authentication Required".to_string();
            self.pool.record_failure(route_idx, &msg);
            return Err(ApiCallFailure::RouteError(msg));
        }

        let parsed: serde_json::Result<ApiResponse<T>> = serde_json::from_slice(&body);
        match parsed {
            Ok(env) if env.ok => {
                self.pool.record_success(route_idx, elapsed);
                match env.result {
                    Some(res) => Ok(res),
                    None => Err(ApiCallFailure::TelegramError(BridgeError::BotApi {
                        code: status.as_u16(),
                        message: "Bot API returned ok=true with missing result".into(),
                        retryable: false,
                    })),
                }
            }
            Ok(env) => {
                self.pool.record_success(route_idx, elapsed);
                let code = env.error_code.unwrap_or_else(|| status.as_u16());
                let desc = env
                    .description
                    .unwrap_or_else(|| format!("HTTP {}", status.as_u16()));
                let desc = self.sanitize_error(&desc);

                if code == 429 || status == StatusCode::TOO_MANY_REQUESTS {
                    let retry_after_secs = env
                        .parameters
                        .and_then(|p| p.retry_after)
                        .or_else(|| {
                            retry_after_hdr
                                .as_deref()
                                .and_then(|h| h.trim().parse::<u64>().ok())
                        })
                        .unwrap_or(1);
                    return Err(ApiCallFailure::TelegramError(BridgeError::RateLimited {
                        retry_after_secs,
                        message: desc,
                    }));
                }

                Err(ApiCallFailure::TelegramError(BridgeError::BotApi {
                    code,
                    message: desc,
                    retryable: code >= 500,
                }))
            }
            Err(json_err) => {
                // Non-JSON response on 5xx / 4xx typically indicates a broken proxy or captive gateway.
                if status.is_server_error() || status == StatusCode::BAD_GATEWAY {
                    let msg = format!("upstream/proxy HTTP {} non-JSON body", status.as_u16());
                    self.pool.record_failure(route_idx, &msg);
                    return Err(ApiCallFailure::RouteError(msg));
                }
                if status == StatusCode::TOO_MANY_REQUESTS {
                    self.pool.record_success(route_idx, elapsed);
                    let retry_after_secs = retry_after_hdr
                        .as_deref()
                        .and_then(|h| h.trim().parse::<u64>().ok())
                        .unwrap_or(1);
                    return Err(ApiCallFailure::TelegramError(BridgeError::RateLimited {
                        retry_after_secs,
                        message: "HTTP 429 Too Many Requests".into(),
                    }));
                }
                // On HTTP 200 with valid JSON envelope (`ok == true`), a schema mismatch in T
                // is NOT a proxy transport failure; do not trip proxy circuits or duplicate POSTs.
                if status.is_success() {
                    if let Ok(env) = serde_json::from_slice::<ApiResponse<Value>>(&body) {
                        if env.ok {
                            self.pool.record_success(route_idx, elapsed);
                            return Err(ApiCallFailure::TelegramError(BridgeError::json(
                                "decoding Bot API result payload",
                                json_err,
                            )));
                        }
                    }
                }
                let msg = format!(
                    "invalid Bot API JSON (HTTP {}): {}",
                    status.as_u16(),
                    self.sanitize_error(&json_err.to_string())
                );
                self.pool.record_failure(route_idx, &msg);
                Err(ApiCallFailure::RouteError(msg))
            }
        }
    }

    // ───────────────────────────── High-level Bot API 10.4 methods

    pub async fn get_me(&self) -> Result<User> {
        self.call_json("getMe", &json!({}), None).await
    }

    pub async fn get_me_with_timeout(&self, timeout: Duration) -> Result<User> {
        self.call_json("getMe", &json!({}), Some(timeout)).await
    }

    pub async fn get_updates(
        &self,
        offset: Option<i64>,
        timeout: u64,
        allowed_updates: &[String],
    ) -> Result<Vec<Update>> {
        let mut body = serde_json::Map::new();
        if let Some(off) = offset {
            body.insert("offset".into(), json!(off));
        }
        body.insert("timeout".into(), json!(timeout));
        if !allowed_updates.is_empty() {
            body.insert("allowed_updates".into(), json!(allowed_updates));
        }
        let req_timeout = Duration::from_secs(timeout.saturating_add(10));
        let raw_updates: Vec<Value> = self
            .call_json("getUpdates", &Value::Object(body), Some(req_timeout))
            .await?;
        let mut out = Vec::with_capacity(raw_updates.len());
        for raw in raw_updates {
            match serde_json::from_value::<Update>(raw.clone()) {
                Ok(u) => out.push(u),
                Err(err) => {
                    let uid = raw.get("update_id").and_then(Value::as_i64);
                    warn!(update_id = ?uid, error = %err, "skipping malformed Telegram update payload");
                    // Keep update_id so the poller advances past the poison pill instead of wedging forever.
                    if let Some(id) = uid {
                        out.push(Update {
                            update_id: id,
                            message: None,
                            callback_query: None,
                            inline_query: None,
                            widget_query: None,
                            shared_widget_query: None,
                            business: Default::default(),
                            stopped_message_generation: None,
                        });
                    }
                }
            }
        }
        Ok(out)
    }

    pub async fn set_webhook(
        &self,
        url: &str,
        secret_token: Option<&str>,
        allowed_updates: &[String],
        drop_pending_updates: bool,
    ) -> Result<bool> {
        let mut body = serde_json::Map::new();
        body.insert("url".into(), json!(url));
        if let Some(secret) = secret_token {
            body.insert("secret_token".into(), json!(secret));
        }
        if !allowed_updates.is_empty() {
            body.insert("allowed_updates".into(), json!(allowed_updates));
        }
        if drop_pending_updates {
            body.insert("drop_pending_updates".into(), json!(true));
        }
        self.call_json("setWebhook", &Value::Object(body), None)
            .await
    }

    pub async fn delete_webhook(&self, drop_pending_updates: bool) -> Result<bool> {
        let mut body = serde_json::Map::new();
        if drop_pending_updates {
            body.insert("drop_pending_updates".into(), json!(true));
        }
        self.call_json("deleteWebhook", &Value::Object(body), None)
            .await
    }

    pub async fn get_webhook_info(&self) -> Result<WebhookInfo> {
        self.call_json("getWebhookInfo", &json!({}), None).await
    }

    pub async fn send_message(&self, params: impl Borrow<SendMessageParams>) -> Result<Message> {
        let payload = to_json_value("sendMessage", params.borrow())?;
        self.call_json("sendMessage", &payload, None).await
    }

    pub async fn send_rich_message(
        &self,
        params: impl Borrow<SendRichMessageParams>,
    ) -> Result<Message> {
        let payload = to_json_value("sendRichMessage", params.borrow())?;
        self.call_json("sendRichMessage", &payload, None).await
    }

    pub async fn send_rich_message_draft(
        &self,
        params: impl Borrow<SendRichMessageDraftParams>,
    ) -> Result<bool> {
        let payload = to_json_value("sendRichMessageDraft", params.borrow())?;
        self.call_json("sendRichMessageDraft", &payload, None).await
    }

    pub async fn send_message_draft(
        &self,
        params: impl Borrow<SendMessageDraftParams>,
    ) -> Result<bool> {
        let payload = to_json_value("sendMessageDraft", params.borrow())?;
        self.call_json("sendMessageDraft", &payload, None).await
    }

    pub async fn edit_message_text(
        &self,
        params: impl Borrow<EditMessageTextParams>,
    ) -> Result<Value> {
        let payload = to_json_value("editMessageText", params.borrow())?;
        self.call_json("editMessageText", &payload, None).await
    }

    pub async fn send_widget(&self, params: impl Borrow<SendWidgetParams>) -> Result<Message> {
        let payload = to_json_value("sendWidget", params.borrow())?;
        self.call_json("sendWidget", &payload, None).await
    }

    pub async fn send_shared_widget(
        &self,
        params: impl Borrow<SendSharedWidgetParams>,
    ) -> Result<Message> {
        let payload = to_json_value("sendSharedWidget", params.borrow())?;
        self.call_json("sendSharedWidget", &payload, None).await
    }

    pub async fn edit_message_widget_data(
        &self,
        params: impl Borrow<EditWidgetDataParams>,
    ) -> Result<bool> {
        let payload = to_json_value("editMessageWidgetData", params.borrow())?;
        self.call_json("editMessageWidgetData", &payload, None)
            .await
    }

    pub async fn edit_shared_widget_data(
        &self,
        params: impl Borrow<EditSharedWidgetDataParams>,
    ) -> Result<bool> {
        let payload = to_json_value("editSharedWidgetData", params.borrow())?;
        self.call_json("editSharedWidgetData", &payload, None).await
    }

    pub async fn answer_widget_query(
        &self,
        widget_query_id: &str,
        data: Option<&str>,
    ) -> Result<bool> {
        let mut body = serde_json::Map::new();
        body.insert("widget_query_id".into(), json!(widget_query_id));
        if let Some(d) = data {
            // Preserves explicit Some("") cleanly.
            body.insert("data".into(), json!(d));
        }
        self.call_json("answerWidgetQuery", &Value::Object(body), None)
            .await
    }

    pub async fn answer_callback_query(
        &self,
        callback_query_id: &str,
        text: Option<&str>,
    ) -> Result<bool> {
        self.answer_callback_query_with(AnswerCallbackQueryParams {
            callback_query_id: callback_query_id.to_string(),
            text: text.map(ToOwned::to_owned),
            ..Default::default()
        })
        .await
    }

    pub async fn answer_callback_query_with(
        &self,
        params: impl Borrow<AnswerCallbackQueryParams>,
    ) -> Result<bool> {
        let payload = to_json_value("answerCallbackQuery", params.borrow())?;
        self.call_json("answerCallbackQuery", &payload, None).await
    }

    pub async fn answer_inline_query(
        &self,
        inline_query_id: &str,
        results: &[InlineQueryResultArticle],
        cache_time: Option<u32>,
        is_personal: Option<bool>,
    ) -> Result<bool> {
        let mut body = serde_json::Map::new();
        body.insert("inline_query_id".into(), json!(inline_query_id));
        body.insert("results".into(), to_json_value("answerInlineQuery.results", &results)?);
        if let Some(ct) = cache_time {
            body.insert("cache_time".into(), json!(ct));
        }
        if let Some(ip) = is_personal {
            body.insert("is_personal".into(), json!(ip));
        }
        self.call_json("answerInlineQuery", &Value::Object(body), None)
            .await
    }

    pub async fn delete_message(&self, chat_id: i64, message_id: i64) -> Result<bool> {
        self.call_json(
            "deleteMessage",
            &json!({ "chat_id": chat_id, "message_id": message_id }),
            None,
        )
        .await
    }

    pub async fn send_chat_action(&self, chat_id: i64, action: &str) -> Result<bool> {
        self.call_json(
            "sendChatAction",
            &json!({ "chat_id": chat_id, "action": action }),
            None,
        )
        .await
    }

    pub async fn set_my_commands(
        &self,
        commands: &[BotCommand],
        scope: impl Into<Option<BotCommandScope>>,
    ) -> Result<bool> {
        let mut body = serde_json::Map::new();
        body.insert(
            "commands".into(),
            to_json_value("setMyCommands.commands", &commands)?,
        );
        if let Some(sc) = scope.into() {
            body.insert("scope".into(), to_json_value("setMyCommands.scope", &sc)?);
        }
        self.call_json("setMyCommands", &Value::Object(body), None)
            .await
    }

    pub async fn set_chat_menu_button(
        &self,
        chat_id: Option<i64>,
        menu_button: impl Into<Option<MenuButton>>,
    ) -> Result<bool> {
        let mut body = serde_json::Map::new();
        if let Some(cid) = chat_id {
            body.insert("chat_id".into(), json!(cid));
        }
        if let Some(mb) = menu_button.into() {
            body.insert(
                "menu_button".into(),
                to_json_value("setChatMenuButton.menu_button", &mb)?,
            );
        }
        self.call_json("setChatMenuButton", &Value::Object(body), None)
            .await
    }

    // ───────────────────────────── Media uploads

    pub async fn send_document(
        &self,
        chat_id: i64,
        media: MediaInput,
        opts: impl Into<Option<SendMediaOptions>>,
    ) -> Result<Message> {
        self.send_media("sendDocument", "document", chat_id, media, opts.into().unwrap_or_default())
            .await
    }

    pub async fn send_photo(
        &self,
        chat_id: i64,
        media: MediaInput,
        opts: impl Into<Option<SendMediaOptions>>,
    ) -> Result<Message> {
        self.send_media("sendPhoto", "photo", chat_id, media, opts.into().unwrap_or_default())
            .await
    }

    pub async fn send_video(
        &self,
        chat_id: i64,
        media: MediaInput,
        opts: impl Into<Option<SendMediaOptions>>,
    ) -> Result<Message> {
        self.send_media("sendVideo", "video", chat_id, media, opts.into().unwrap_or_default())
            .await
    }

    pub async fn send_audio(
        &self,
        chat_id: i64,
        media: MediaInput,
        opts: impl Into<Option<SendMediaOptions>>,
    ) -> Result<Message> {
        self.send_media("sendAudio", "audio", chat_id, media, opts.into().unwrap_or_default())
            .await
    }

    pub async fn send_voice(
        &self,
        chat_id: i64,
        media: MediaInput,
        opts: impl Into<Option<SendMediaOptions>>,
    ) -> Result<Message> {
        self.send_media("sendVoice", "voice", chat_id, media, opts.into().unwrap_or_default())
            .await
    }

    pub async fn send_animation(
        &self,
        chat_id: i64,
        media: MediaInput,
        opts: impl Into<Option<SendMediaOptions>>,
    ) -> Result<Message> {
        self.send_media(
            "sendAnimation",
            "animation",
            chat_id,
            media,
            opts.into().unwrap_or_default(),
        )
        .await
    }

    async fn send_media(
        &self,
        method: &str,
        field_name: &str,
        chat_id: i64,
        media: MediaInput,
        opts: SendMediaOptions,
    ) -> Result<Message> {
        match media {
            MediaInput::FileIdOrUrl(val) => {
                let mut body = serde_json::Map::new();
                body.insert("chat_id".into(), json!(chat_id));
                body.insert(field_name.into(), json!(val));
                insert_media_json_opts(&mut body, &opts)?;
                self.call_json(method, &Value::Object(body), Some(Duration::from_secs(180)))
                    .await
            }
            MediaInput::Bytes { data, filename } => {
                if data.len() > MAX_UPLOAD_BYTES {
                    return Err(BridgeError::PayloadTooLarge {
                        actual: data.len(),
                        limit: MAX_UPLOAD_BYTES,
                    });
                }
                let safe_name = sanitize_upload_filename(&filename);
                self.send_media_bytes(method, field_name, chat_id, data, &safe_name, &opts)
                    .await
            }
            MediaInput::Path(path) => {
                let meta = tokio::fs::metadata(&path)
                    .await
                    .map_err(|e| BridgeError::io(format!("stat {}", path.display()), e))?;
                if meta.len() > MAX_UPLOAD_BYTES as u64 {
                    return Err(BridgeError::PayloadTooLarge {
                        actual: meta.len().min(usize::MAX as u64) as usize,
                        limit: MAX_UPLOAD_BYTES,
                    });
                }
                let raw = tokio::fs::read(&path)
                    .await
                    .map_err(|e| BridgeError::io(format!("read {}", path.display()), e))?;
                if raw.len() > MAX_UPLOAD_BYTES {
                    return Err(BridgeError::PayloadTooLarge {
                        actual: raw.len(),
                        limit: MAX_UPLOAD_BYTES,
                    });
                }
                let filename = path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .map(sanitize_upload_filename)
                    .unwrap_or_else(|| "file.bin".to_string());
                self.send_media_bytes(
                    method,
                    field_name,
                    chat_id,
                    Bytes::from(raw),
                    &filename,
                    &opts,
                )
                .await
            }
        }
    }

    async fn send_media_bytes(
        &self,
        method: &str,
        field_name: &str,
        chat_id: i64,
        data: Bytes,
        filename: &str,
        opts: &SendMediaOptions,
    ) -> Result<Message> {
        let len = data.len() as u64;
        self.call_multipart_with(
            method,
            || {
                let mut form = Form::new().text("chat_id", chat_id.to_string());
                form = apply_media_form_opts(form, opts)?;
                let part = Part::stream_with_length(reqwest::Body::from(data.clone()), len)
                    .file_name(filename.to_string());
                Ok(form.part(field_name.to_string(), part))
            },
            Some(Duration::from_secs(180)),
        )
        .await
    }

    // ───────────────────────────── File metadata & streaming download

    pub async fn get_file(&self, file_id: &str) -> Result<TelegramFile> {
        self.call_json("getFile", &json!({ "file_id": file_id }), None)
            .await
    }

    /// Stream-download a file from Telegram's `/file/bot<token>/<file_path>` endpoint
    /// directly to `dest_path` via a sibling temp file, aborting cleanly if size exceeds `max_bytes`.
    pub async fn download_file(
        &self,
        file_path: &str,
        dest_path: &Path,
        max_bytes: usize,
    ) -> Result<u64> {
        if file_path.is_empty() || file_path.contains("..") || file_path.contains('\\') {
            return Err(BridgeError::Validation(format!(
                "invalid Telegram file_path '{file_path}'"
            )));
        }

        let parent = dest_path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|e| BridgeError::io(format!("mkdir {}", parent.display()), e))?;

        let url = self.file_url(file_path);
        let candidates = self.pool.select_candidates();
        let timeout = Duration::from_secs(180);
        let mut last_route_err: Option<String> = None;

        for (idx, client, _) in candidates {
            let start = Instant::now();
            let resp = match client.get(&url).timeout(timeout).send().await {
                Ok(r) => r,
                Err(e) => {
                    let msg = self.format_reqwest_error(e);
                    self.pool.record_failure(idx, &msg);
                    last_route_err = Some(msg);
                    continue;
                }
            };

            let status = resp.status();
            if status == StatusCode::PROXY_AUTHENTICATION_REQUIRED {
                let msg = "proxy returned HTTP 407 Proxy Authentication Required".to_string();
                self.pool.record_failure(idx, &msg);
                last_route_err = Some(msg);
                continue;
            }
            if status.is_server_error() {
                let msg = format!("file download HTTP {}", status.as_u16());
                self.pool.record_failure(idx, &msg);
                last_route_err = Some(msg);
                continue;
            }
            if status == StatusCode::TOO_MANY_REQUESTS {
                self.pool.record_success(idx, start.elapsed());
                let retry_after_secs = resp
                    .headers()
                    .get(reqwest::header::RETRY_AFTER)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|h| h.trim().parse::<u64>().ok())
                    .unwrap_or(5);
                return Err(BridgeError::RateLimited {
                    retry_after_secs,
                    message: "file download HTTP 429 Too Many Requests".into(),
                });
            }
            if !status.is_success() {
                self.pool.record_success(idx, start.elapsed());
                return Err(BridgeError::BotApi {
                    code: status.as_u16(),
                    message: format!("file download failed with HTTP {}", status.as_u16()),
                    retryable: false,
                });
            }

            if let Some(cl) = resp.content_length() {
                if cl > max_bytes as u64 {
                    self.pool.record_success(idx, start.elapsed());
                    return Err(BridgeError::PayloadTooLarge {
                        actual: cl.min(usize::MAX as u64) as usize,
                        limit: max_bytes,
                    });
                }
            }

            let tmp = tempfile::Builder::new()
                .prefix(".dl-")
                .suffix(".tmp")
                .tempfile_in(parent)
                .map_err(|e| BridgeError::io("create temp download file", e))?;
            let (std_file, tmp_path) = tmp.into_parts();
            let mut async_file = tokio::fs::File::from_std(std_file);

            let mut total: u64 = 0;
            let mut stream = resp.bytes_stream();
            let mut stream_err: Option<String> = None;

            while let Some(chunk_res) = stream.next().await {
                let chunk = match chunk_res {
                    Ok(c) => c,
                    Err(e) => {
                        stream_err = Some(self.format_reqwest_error(e));
                        break;
                    }
                };
                let next_total = total.saturating_add(chunk.len() as u64);
                if next_total > max_bytes as u64 {
                    drop(async_file);
                    drop(tmp_path);
                    self.pool.record_success(idx, start.elapsed());
                    return Err(BridgeError::PayloadTooLarge {
                        actual: next_total.min(usize::MAX as u64) as usize,
                        limit: max_bytes,
                    });
                }
                async_file
                    .write_all(&chunk)
                    .await
                    .map_err(|e| BridgeError::io("write download chunk", e))?;
                total = next_total;
            }

            if let Some(msg) = stream_err {
                drop(async_file);
                drop(tmp_path);
                self.pool.record_failure(idx, &msg);
                last_route_err = Some(msg);
                continue;
            }

            async_file
                .flush()
                .await
                .map_err(|e| BridgeError::io("flush downloaded file", e))?;
            drop(async_file);

            tmp_path
                .persist(dest_path)
                .map_err(|e| BridgeError::io(format!("persist {}", dest_path.display()), e.error))?;

            self.pool.record_success(idx, start.elapsed());
            return Ok(total);
        }

        Err(BridgeError::Network(
            last_route_err.unwrap_or_else(|| "no proxy routes available".into()),
        ))
    }
}

fn normalize_api_base(raw: &str) -> Result<String> {
    let trimmed = raw.trim().trim_end_matches('/');
    let parsed = Url::parse(trimmed)
        .map_err(|e| BridgeError::Config(format!("invalid api_base '{trimmed}': {e}")))?;
    match parsed.scheme() {
        "http" | "https" => Ok(trimmed.to_string()),
        other => Err(BridgeError::Config(format!(
            "unsupported api_base scheme '{other}' (expected http or https)"
        ))),
    }
}

/// Methods safe to concurrently hedge in `ProxyMode::Race`.
/// NEVER include long-polling (`getUpdates`, causes instant 409 Conflict loops) or
/// state-changing/one-shot methods (`deleteMessage`, `answerCallbackQuery`, `editMessageText`).
fn is_idempotent_method(method: &str) -> bool {
    matches!(method, "getMe" | "getWebhookInfo" | "getFile")
}

fn to_json_value<T: Serialize>(ctx: &str, val: &T) -> Result<Value> {
    serde_json::to_value(val).map_err(|e| BridgeError::json(ctx, e))
}

fn sanitize_upload_filename(name: &str) -> String {
    let base = Path::new(name)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("file.bin");
    if base.is_empty() {
        "file.bin".to_string()
    } else {
        base.to_string()
    }
}

fn insert_media_json_opts(
    body: &mut serde_json::Map<String, Value>,
    opts: &SendMediaOptions,
) -> Result<()> {
    if let Some(tid) = opts.message_thread_id {
        body.insert("message_thread_id".into(), json!(tid));
    }
    if let Some(ref c) = opts.caption {
        body.insert("caption".into(), json!(c));
    }
    if let Some(ref pm) = opts.parse_mode {
        body.insert("parse_mode".into(), json!(pm));
    }
    if let Some(ref ents) = opts.caption_entities {
        body.insert("caption_entities".into(), to_json_value("caption_entities", ents)?);
    }
    if let Some(b) = opts.show_caption_above_media {
        body.insert("show_caption_above_media".into(), json!(b));
    }
    if let Some(b) = opts.has_spoiler {
        body.insert("has_spoiler".into(), json!(b));
    }
    if let Some(b) = opts.supports_streaming {
        body.insert("supports_streaming".into(), json!(b));
    }
    if let Some(d) = opts.duration {
        body.insert("duration".into(), json!(d));
    }
    if let Some(w) = opts.width {
        body.insert("width".into(), json!(w));
    }
    if let Some(h) = opts.height {
        body.insert("height".into(), json!(h));
    }
    if let Some(ref p) = opts.performer {
        body.insert("performer".into(), json!(p));
    }
    if let Some(ref t) = opts.title {
        body.insert("title".into(), json!(t));
    }
    if let Some(b) = opts.disable_notification {
        body.insert("disable_notification".into(), json!(b));
    }
    if let Some(b) = opts.protect_content {
        body.insert("protect_content".into(), json!(b));
    }
    if let Some(b) = opts.allow_paid_broadcast {
        body.insert("allow_paid_broadcast".into(), json!(b));
    }
    if let Some(ref eid) = opts.message_effect_id {
        body.insert("message_effect_id".into(), json!(eid));
    }
    if let Some(ref rp) = opts.reply_parameters {
        body.insert("reply_parameters".into(), to_json_value("reply_parameters", rp)?);
    }
    if let Some(ref rm) = opts.reply_markup {
        body.insert("reply_markup".into(), to_json_value("reply_markup", rm)?);
    }
    Ok(())
}

fn apply_media_form_opts(mut form: Form, opts: &SendMediaOptions) -> Result<Form> {
    if let Some(tid) = opts.message_thread_id {
        form = form.text("message_thread_id", tid.to_string());
    }
    if let Some(ref c) = opts.caption {
        form = form.text("caption", c.clone());
    }
    if let Some(ref pm) = opts.parse_mode {
        form = form.text("parse_mode", pm.clone());
    }
    if let Some(ref ents) = opts.caption_entities {
        let s = serde_json::to_string(ents).map_err(|e| BridgeError::json("caption_entities", e))?;
        form = form.text("caption_entities", s);
    }
    if let Some(b) = opts.show_caption_above_media {
        form = form.text("show_caption_above_media", b.to_string());
    }
    if let Some(b) = opts.has_spoiler {
        form = form.text("has_spoiler", b.to_string());
    }
    if let Some(b) = opts.supports_streaming {
        form = form.text("supports_streaming", b.to_string());
    }
    if let Some(d) = opts.duration {
        form = form.text("duration", d.to_string());
    }
    if let Some(w) = opts.width {
        form = form.text("width", w.to_string());
    }
    if let Some(h) = opts.height {
        form = form.text("height", h.to_string());
    }
    if let Some(ref p) = opts.performer {
        form = form.text("performer", p.clone());
    }
    if let Some(ref t) = opts.title {
        form = form.text("title", t.clone());
    }
    if let Some(b) = opts.disable_notification {
        form = form.text("disable_notification", b.to_string());
    }
    if let Some(b) = opts.protect_content {
        form = form.text("protect_content", b.to_string());
    }
    if let Some(b) = opts.allow_paid_broadcast {
        form = form.text("allow_paid_broadcast", b.to_string());
    }
    if let Some(ref eid) = opts.message_effect_id {
        form = form.text("message_effect_id", eid.clone());
    }
    if let Some(ref rp) = opts.reply_parameters {
        let s = serde_json::to_string(rp).map_err(|e| BridgeError::json("reply_parameters", e))?;
        form = form.text("reply_parameters", s);
    }
    if let Some(ref rm) = opts.reply_markup {
        let s = serde_json::to_string(rm).map_err(|e| BridgeError::json("reply_markup", e))?;
        form = form.text("reply_markup", s);
    }
    Ok(form)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn flood_wait_is_bounded_then_returned_for_queue_or_drop() {
        use std::sync::atomic::{AtomicU32, Ordering as O};
        // a huge retry_after is not slept: returned at once (caller queues / drops)
        let calls = AtomicU32::new(0);
        let t0 = std::time::Instant::now();
        let r: Result<()> = tg_retry(5, 1.0, || {
            calls.fetch_add(1, O::SeqCst);
            async { Err(BridgeError::RateLimited { retry_after_secs: 3600, message: "flood".into() }) }
        })
        .await;
        assert!(matches!(r, Err(BridgeError::RateLimited { .. })));
        assert_eq!(calls.load(O::SeqCst), 1);
        assert!(t0.elapsed() < Duration::from_secs(1));
        // a short one is honoured and the call retried
        let calls = AtomicU32::new(0);
        let r: Result<u8> = tg_retry(3, 1.0, || {
            let n = calls.fetch_add(1, O::SeqCst);
            async move {
                if n == 0 {
                    Err(BridgeError::RateLimited { retry_after_secs: 1, message: "flood".into() })
                } else {
                    Ok(7)
                }
            }
        })
        .await;
        assert_eq!(r.unwrap(), 7);
        assert_eq!(calls.load(O::SeqCst), 2);
    }

    #[test]
    fn full_jitter_bounds() {
        for a in 0..12 {
            for _ in 0..200 {
                let d = full_jitter(a, 1.0, 30.0);
                let upper = (2_f64.powi(a as i32)).min(30.0);
                assert!((0.0..=upper).contains(&d));
            }
        }
        assert_eq!(full_jitter_with(50, 1.0, 30.0, || 1.0), 30.0);
        assert!(full_jitter_with(0, 1.0, 30.0, || 0.999) < 1.0);
    }

    #[test]
    fn debug_redacts_bot_token() {
        let client = BotApiClient::new("123456:SUPER_SECRET_TOKEN", NetConfig::default()).unwrap();
        let dbg = format!("{client:?}");
        assert!(!dbg.contains("SUPER_SECRET_TOKEN"));
        assert!(dbg.contains("[REDACTED]"));
    }

    #[test]
    fn empty_string_widget_fields_preserved_in_json() {
        let edit_msg = EditWidgetDataParams {
            chat_id: Some(1),
            message_id: Some(2),
            inline_message_id: None,
            public_data: Some(String::new()),
            chat_data: Some(String::new()),
        };
        let v = serde_json::to_value(&edit_msg).unwrap();
        assert_eq!(v["public_data"], json!(""));
        assert_eq!(v["chat_data"], json!(""));
        assert!(v.get("inline_message_id").is_none());

        let edit_partial = EditWidgetDataParams {
            inline_message_id: Some("im1".into()),
            public_data: Some(String::new()),
            ..Default::default()
        };
        let vp = serde_json::to_value(&edit_partial).unwrap();
        assert_eq!(vp["inline_message_id"], json!("im1"));
        assert_eq!(vp["public_data"], json!(""));
        assert!(vp.get("chat_data").is_none());

        let edit_shared = EditSharedWidgetDataParams {
            widget_id: "w1".into(),
            public_data: String::new(),
            cache_time: None,
        };
        let vs = serde_json::to_value(&edit_shared).unwrap();
        assert_eq!(vs["widget_id"], json!("w1"));
        assert_eq!(vs["public_data"], json!(""));
    }
}
