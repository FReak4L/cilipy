//! Telegram Webhook Axum router, `HealthMetricsAdapter`, and multi-mode `TransportSupervisor`
//! supporting `Polling`, `Webhook`, and `Auto` (with transparent fallback to long-polling).

use std::collections::{HashSet, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use agy_core::config::{Config, TransportMode};
use agy_core::health::HealthTracker;
use agy_core::tg::Update;
use agy_core::{BridgeError, Result};
use agy_net::{
    sd_notify_stopping, tg_retry, verify_webhook_secret, BotApiClient, NetMetricsSink, Poller,
    PollerConfig, Watchdog, WatchdogConfig, WatchdogSnapshot,
};
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use axum::Router;
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::sync::{watch, Mutex, Semaphore};
use tracing::{error, info, warn};

/// Maximum incoming Telegram webhook request body size (2 MiB).
pub const WEBHOOK_BODY_LIMIT_BYTES: usize = 2 * 1024 * 1024;

/// Default maximum concurrent update handlers spawned from webhook requests.
pub const DEFAULT_WEBHOOK_CONCURRENCY: usize = 64;

/// Bounded FIFO deduplication window for webhook `update_id`s.
pub const MAX_WEBHOOK_DEDUP_IDS: usize = 2000;

/// Default allowed Telegram update types matching Python `ALLOWED_UPDATES`.
pub const DEFAULT_ALLOWED_UPDATES: &[&str] = &[
    "message",
    "callback_query",
    "stopped_message_generation",
    "widget_query",
    "shared_widget_query",
    // Secretary Mode (Telegram Business). Must be listed explicitly: allowed_updates is explicit.
    "business_connection",
    "business_message",
    "edited_business_message",
    "deleted_business_messages",
];

/// Extended `getWebhookInfo` response including `last_error_date` & `pending_update_count`
/// so stale transient errors (Telegram retains them for 24h) do not trigger false fallbacks or watchdog kills.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct FullWebhookInfo {
    #[serde(default)]
    pub last_error_message: Option<String>,
    #[serde(default)]
    pub last_error_date: Option<i64>,
    #[serde(default)]
    pub pending_update_count: Option<u64>,
}

impl FullWebhookInfo {
    /// Returns `true` only if `last_error_message` is non-empty AND appears recent/active
    /// (error occurred after `since_unix - 60`, or no timestamp is present while pending updates > 0).
    fn has_active_error(&self, since_unix: i64) -> Option<&str> {
        let msg = self
            .last_error_message
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())?;
        let now = chrono::Utc::now().timestamp();
        match self.last_error_date {
            Some(ts) => {
                // Ignore stale errors older than 10 minutes or strictly before our threshold
                let recent = ts >= since_unix.saturating_sub(60) && now.saturating_sub(ts) <= 600;
                if recent || self.pending_update_count.unwrap_or(0) > 0 && now.saturating_sub(ts) <= 3600 {
                    Some(msg)
                } else {
                    None
                }
            }
            None => Some(msg),
        }
    }
}

/// Bridges `agy_core::health::HealthTracker` to `agy_net::NetMetricsSink`.
pub struct HealthMetricsAdapter {
    health: Arc<HealthTracker>,
}

impl HealthMetricsAdapter {
    pub fn new(health: Arc<HealthTracker>) -> Self {
        Self { health }
    }
}

impl NetMetricsSink for HealthMetricsAdapter {
    fn on_poll_ok(&self, update_count: usize) {
        self.health.poll_ok(update_count as u64);
    }

    fn on_poll_fail(&self) {
        self.health.poll_fail();
    }

    fn stall_secs(&self) -> f64 {
        self.health.stall_secs()
    }

    fn on_getme_ok(&self) {
        self.health.mark_getme_ok();
    }

    fn on_watchdog_snapshot(&self, snapshot: &WatchdogSnapshot) {
        self.health.set_rebuilds(Some(snapshot.rebuilds));
        if let Some(ref note) = snapshot.note {
            self.health.set_note(note.clone());
        }
        let active_label = snapshot
            .proxy_pool
            .routes
            .iter()
            .find(|r| r.state == "closed" || r.state == "half_open")
            .or_else(|| snapshot.proxy_pool.routes.first())
            .map(|r| r.label.as_str());
        let pool_val: Option<Value> = serde_json::to_value(&snapshot.proxy_pool).ok();
        self.health.set_proxy_state(active_label, pool_val);
        if let Err(err) = self.health.write() {
            warn!(error = %err, "failed to persist health.json snapshot");
        }
    }
}

/// Shared asynchronous Telegram update dispatcher trait for both polling and webhook transports.
pub trait UpdateDispatcher: Send + Sync {
    fn dispatch<'a>(&'a self, update: Update) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>>;
}

impl<T: UpdateDispatcher + ?Sized> UpdateDispatcher for Arc<T> {
    fn dispatch<'a>(&'a self, update: Update) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        (**self).dispatch(update)
    }
}

/// Convenience [`UpdateDispatcher`] wrapper around an async closure.
pub struct FnDispatcher<F>(pub F);

impl<F, Fut> UpdateDispatcher for FnDispatcher<F>
where
    F: Fn(Update) -> Fut + Send + Sync,
    Fut: Future<Output = ()> + Send + 'static,
{
    fn dispatch<'a>(&'a self, update: Update) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        let fut = (self.0)(update);
        Box::pin(fut)
    }
}

#[derive(Default)]
struct UpdateDedup {
    seen: HashSet<i64>,
    order: VecDeque<i64>,
}

impl UpdateDedup {
    /// Returns `true` if `update_id` is new (and records it), `false` if duplicate.
    fn insert_if_new(&mut self, update_id: i64) -> bool {
        if !self.seen.insert(update_id) {
            return false;
        }
        self.order.push_back(update_id);
        while self.order.len() > MAX_WEBHOOK_DEDUP_IDS {
            if let Some(evicted) = self.order.pop_front() {
                self.seen.remove(&evicted);
            }
        }
        true
    }
}

#[derive(Clone)]
struct WebhookState {
    secret: String,
    dispatcher: Arc<dyn UpdateDispatcher>,
    health: Arc<HealthTracker>,
    semaphore: Arc<Semaphore>,
    dedup: Arc<Mutex<UpdateDedup>>,
}

/// Build an Axum [`Router`] handling `POST /tg/webhook` with constant-time secret verification,
/// a 2 MiB body limit, bounded non-blocking dispatch, FIFO `update_id` dedup, and health telemetry updates.
pub fn webhook_router(
    secret: String,
    dispatcher: Arc<dyn UpdateDispatcher>,
    health: Arc<HealthTracker>,
) -> Router {
    webhook_router_with_concurrency(secret, dispatcher, health, DEFAULT_WEBHOOK_CONCURRENCY)
}

/// Variant of [`webhook_router`] with configurable max concurrent update handlers.
pub fn webhook_router_with_concurrency(
    secret: String,
    dispatcher: Arc<dyn UpdateDispatcher>,
    health: Arc<HealthTracker>,
    max_in_flight: usize,
) -> Router {
    let state = WebhookState {
        secret,
        dispatcher,
        health,
        semaphore: Arc::new(Semaphore::new(max_in_flight.max(1))),
        dedup: Arc::new(Mutex::new(UpdateDedup::default())),
    };

    Router::new()
        .route("/tg/webhook", post(handle_webhook))
        .layer(DefaultBodyLimit::max(WEBHOOK_BODY_LIMIT_BYTES))
        .with_state(state)
}

async fn handle_webhook(
    State(state): State<WebhookState>,
    headers: HeaderMap,
    body: Bytes,
) -> StatusCode {
    let hdr_val = headers
        .get("X-Telegram-Bot-Api-Secret-Token")
        .and_then(|v| v.to_str().ok());
    if !verify_webhook_secret(hdr_val, &state.secret) {
        return StatusCode::UNAUTHORIZED;
    }

    let update: Update = match serde_json::from_slice(&body) {
        Ok(u) => u,
        Err(err) => {
            warn!(error = %err, "webhook: malformed JSON update payload");
            return StatusCode::BAD_REQUEST;
        }
    };

    let permit = match state.semaphore.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            warn!("webhook concurrency saturated; returning 503 for Telegram backoff");
            return StatusCode::SERVICE_UNAVAILABLE;
        }
    };

    {
        let mut dedup = state.dedup.lock().await;
        if !dedup.insert_if_new(update.update_id) {
            return StatusCode::OK;
        }
    }

    state.health.poll_ok(1);

    let dispatcher = Arc::clone(&state.dispatcher);
    tokio::spawn(async move {
        let _permit = permit;
        dispatcher.dispatch(update).await;
    });

    StatusCode::OK
}

/// Multi-mode Telegram transport supervisor (`Polling`, `Webhook`, `Auto`).
pub struct TransportSupervisor {
    cfg: Arc<Config>,
    client: Arc<BotApiClient>,
    health: Arc<HealthTracker>,
    dispatcher: Arc<dyn UpdateDispatcher>,
    allowed_updates: Vec<String>,
    busy_fn: Arc<dyn Fn() -> bool + Send + Sync>,
    watchdog_cfg: WatchdogConfig,
    webhook_info_interval: Duration,
}

impl TransportSupervisor {
    pub fn new(
        cfg: Arc<Config>,
        client: Arc<BotApiClient>,
        health: Arc<HealthTracker>,
        dispatcher: Arc<dyn UpdateDispatcher>,
        busy_fn: Arc<dyn Fn() -> bool + Send + Sync>,
    ) -> Self {
        let watchdog_cfg = WatchdogConfig {
            soft_stall: Duration::from_secs_f64(cfg.wd_soft.max(1.0)),
            hard_stall: Duration::from_secs_f64(cfg.wd_hard.max(1.0)),
            ..Default::default()
        };
        Self {
            cfg,
            client,
            health,
            dispatcher,
            allowed_updates: DEFAULT_ALLOWED_UPDATES
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
            busy_fn,
            watchdog_cfg,
            webhook_info_interval: Duration::from_secs(60),
        }
    }

    pub fn with_allowed_updates(mut self, allowed: Vec<String>) -> Self {
        self.allowed_updates = allowed;
        self
    }

    #[cfg(test)]
    pub fn with_watchdog_config(mut self, wd_cfg: WatchdogConfig) -> Self {
        self.watchdog_cfg = wd_cfg;
        self
    }

    #[cfg(test)]
    pub fn with_webhook_info_interval(mut self, interval: Duration) -> Self {
        self.webhook_info_interval = interval;
        self
    }

    /// Start and supervise the configured transport until `shutdown` flips to `true`.
    /// Returns the active [`TransportMode`] that ran (`Polling` or `Webhook`).
    pub async fn run(&self, shutdown: watch::Receiver<bool>) -> Result<TransportMode> {
        match self.cfg.tg_transport {
            TransportMode::Polling => {
                self.run_polling(shutdown).await?;
                Ok(TransportMode::Polling)
            }
            TransportMode::Webhook => {
                self.run_webhook(shutdown, false).await?;
                Ok(TransportMode::Webhook)
            }
            TransportMode::Auto => self.run_auto(shutdown).await,
        }
    }

    async fn run_auto(&self, shutdown: watch::Receiver<bool>) -> Result<TransportMode> {
        let url_opt = self
            .cfg
            .webhook_url
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let sec_opt = self
            .cfg
            .webhook_secret
            .as_deref()
            .filter(|s| !s.is_empty());

        let (Some(url), Some(secret)) = (url_opt, sec_opt) else {
            info!("auto transport: webhook_url or webhook_secret absent -> falling back to polling");
            self.run_polling(shutdown).await?;
            return Ok(TransportMode::Polling);
        };

        let info_res = self
            .client
            .call_json::<FullWebhookInfo>("getWebhookInfo", &json!({}), None)
            .await;

        let probe_since = chrono::Utc::now().timestamp().saturating_sub(600);
        match info_res {
            Ok(info) => {
                if let Some(err_msg) = info.has_active_error(probe_since) {
                    warn!(
                        last_error = %err_msg,
                        "auto transport: getWebhookInfo reports active error -> falling back to polling"
                    );
                    self.run_polling(shutdown).await?;
                    return Ok(TransportMode::Polling);
                }
            }
            Err(err) => {
                warn!(error = %err, "auto transport: getWebhookInfo probe failed -> falling back to polling");
                self.run_polling(shutdown).await?;
                return Ok(TransportMode::Polling);
            }
        }

        if let Err(err) = tg_retry(2, 2.0, || {
            self.client
                .set_webhook(url, Some(secret), &self.allowed_updates, false)
        })
        .await
        {
            warn!(error = %err, "auto transport: setWebhook failed -> falling back to polling");
            self.run_polling(shutdown).await?;
            return Ok(TransportMode::Polling);
        }

        info!("auto transport: webhook verified and registered -> running webhook mode");
        let fell_back = self.run_webhook_loop(shutdown.clone(), true).await?;
        if fell_back {
            warn!("auto transport: runtime webhook error detected -> falling back to polling");
            self.run_polling(shutdown).await?;
            return Ok(TransportMode::Polling);
        }
        Ok(TransportMode::Webhook)
    }

    async fn run_polling(&self, mut shutdown: watch::Receiver<bool>) -> Result<()> {
        if let Err(err) = tg_retry(2, 2.0, || self.client.delete_webhook(false)).await {
            warn!(error = %err, "deleteWebhook failed during polling startup (continuing)");
        }
        self.health.set_mode("polling");
        let _ = self.health.write();

        let metrics = Arc::new(HealthMetricsAdapter::new(Arc::clone(&self.health)));
        let poller = Arc::new(Poller::new(
            PollerConfig {
                allowed_updates: self.allowed_updates.clone(),
                poll_timeout_secs: self.cfg.poll_timeout,
                offset_file: self.cfg.offset_path(),
                ..Default::default()
            },
            metrics.clone(),
        ));

        let kick_poller = Arc::clone(&poller);
        let wd = Watchdog::new(
            self.watchdog_cfg.clone(),
            metrics,
            Arc::clone(self.client.pool()),
            self.client.clone() as Arc<dyn agy_net::ProbeTarget>,
            Arc::clone(&self.busy_fn),
        )
        .with_on_recover(Arc::new(move || {
            kick_poller.kick();
        }));
        let wd = Arc::new(wd);

        let (wd_tx, wd_rx) = watch::channel(*shutdown.borrow());
        let wd_task = tokio::spawn({
            let wd = Arc::clone(&wd);
            async move {
                wd.run(wd_rx).await;
            }
        });

        let stop_poller = Arc::clone(&poller);
        let shutdown_task = tokio::spawn(async move {
            loop {
                if *shutdown.borrow() {
                    let _ = wd_tx.send(true);
                    stop_poller.stop();
                    break;
                }
                if shutdown.changed().await.is_err() {
                    let _ = wd_tx.send(true);
                    stop_poller.stop();
                    break;
                }
            }
        });

        let disp = Arc::clone(&self.dispatcher);
        poller
            .run(&*self.client, move |update| {
                let d = Arc::clone(&disp);
                async move {
                    d.dispatch(update).await;
                }
            })
            .await;

        sd_notify_stopping();
        let _ = wd_task.await;
        shutdown_task.abort();
        Ok(())
    }

    async fn run_webhook(&self, shutdown: watch::Receiver<bool>, allow_fallback: bool) -> Result<()> {
        let url = self
            .cfg
            .webhook_url
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                BridgeError::Config("WEBHOOK_URL must be set for webhook transport".into())
            })?;
        let secret = self
            .cfg
            .webhook_secret
            .as_deref()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                BridgeError::Config("WEBHOOK_SECRET must be set for webhook transport".into())
            })?;

        tg_retry(3, 5.0, || {
            self.client
                .set_webhook(url, Some(secret), &self.allowed_updates, false)
        })
        .await?;

        let _ = self.run_webhook_loop(shutdown, allow_fallback).await?;
        Ok(())
    }

    async fn run_webhook_loop(
        &self,
        mut shutdown: watch::Receiver<bool>,
        allow_fallback: bool,
    ) -> Result<bool> {
        self.health.set_mode("webhook");
        self.health.poll_ok(0);
        let _ = self.health.write();

        let metrics = Arc::new(HealthMetricsAdapter::new(Arc::clone(&self.health)));
        let wd = Arc::new(Watchdog::new(
            self.watchdog_cfg.clone(),
            metrics,
            Arc::clone(self.client.pool()),
            self.client.clone() as Arc<dyn agy_net::ProbeTarget>,
            Arc::clone(&self.busy_fn),
        ));

        let (wd_tx, wd_rx) = watch::channel(*shutdown.borrow());
        let wd_task = tokio::spawn({
            let wd = Arc::clone(&wd);
            async move {
                wd.run(wd_rx).await;
            }
        });

        let mut fell_back = false;
        let check_interval = self.webhook_info_interval.max(Duration::from_millis(50));
        let loop_started_unix = chrono::Utc::now().timestamp();

        loop {
            if *shutdown.borrow() {
                break;
            }
            tokio::select! {
                _ = tokio::time::sleep(check_interval) => {
                    match self.client.call_json::<FullWebhookInfo>("getWebhookInfo", &json!({}), None).await {
                        Ok(info) => {
                            if let Some(err_msg) = info.has_active_error(loop_started_unix) {
                                error!(last_error = %err_msg, "webhook delivery error reported by Telegram");
                                if allow_fallback {
                                    fell_back = true;
                                    break;
                                }
                                // In dedicated Webhook mode, keep health heartbeat alive if getWebhookInfo succeeded
                                // and no backlog is piling up, avoiding spurious watchdog exit(75) loops.
                                if info.pending_update_count.unwrap_or(0) == 0 {
                                    self.health.poll_ok(0);
                                }
                            } else {
                                self.health.poll_ok(0);
                            }
                        }
                        Err(err) => {
                            warn!(error = %err, "getWebhookInfo monitor tick failed");
                        }
                    }
                }
                res = shutdown.changed() => {
                    if res.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
            }
        }

        let _ = wd_tx.send(true);
        let _ = wd_task.await;
        if !fell_back {
            sd_notify_stopping();
        }
        Ok(fell_back)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agy_core::tg::{Chat, Message, User};
    use agy_net::NetConfig;
    use axum::body::Body;
    use axum::extract::{Path as AxumPath, Request, State};
    use axum::http::Request as HttpRequest;
    use axum::response::{IntoResponse, Response};
    use axum::routing::post;
    use axum::{Json, Router};
    use serde_json::json;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use tempfile::TempDir;
    use tokio::net::TcpListener;
    use tokio::sync::Mutex;
    use tower::ServiceExt;

    fn sample_update(id: i64) -> Update {
        Update {
            update_id: id,
            message: Some(Message {
                message_id: id,
                from_user: Some(User {
                    id: 1000000001,
                    is_bot: false,
                    first_name: "Owner".into(),
                    last_name: None,
                    username: Some("owner".into()),
                    language_code: None,
                    is_premium: Some(false),
                }),
                chat: Chat {
                    id: 1000000001,
                    kind: "private".into(),
                    username: None,
                    first_name: None,
                },
                message_thread_id: None,
                text: Some("hi".into()),
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
            }),
            callback_query: None,
            widget_query: None,
            shared_widget_query: None,
            inline_query: None,
            business: Default::default(),
            stopped_message_generation: None,
        }
    }

    #[tokio::test]
    async fn webhook_router_enforces_secret_body_limit_and_dispatches() {
        let dir = TempDir::new().unwrap();
        let health = Arc::new(HealthTracker::new(dir.path().join("health.json")));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen_cb = Arc::clone(&seen);
        let disp: Arc<dyn UpdateDispatcher> = Arc::new(FnDispatcher(move |u: Update| {
            let s = Arc::clone(&seen_cb);
            async move {
                s.lock().await.push(u.update_id);
            }
        }));

        let app = webhook_router("top-secret-123".into(), disp.clone(), Arc::clone(&health));

        let payload = serde_json::to_vec(&sample_update(42)).unwrap();

        // 1. Missing secret -> 401
        let resp_missing = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/tg/webhook")
                    .header("content-type", "application/json")
                    .body(Body::from(payload.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp_missing.status(), StatusCode::UNAUTHORIZED);

        // 2. Wrong secret -> 401
        let resp_wrong = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/tg/webhook")
                    .header("content-type", "application/json")
                    .header("X-Telegram-Bot-Api-Secret-Token", "wrong-secret")
                    .body(Body::from(payload.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp_wrong.status(), StatusCode::UNAUTHORIZED);

        // 3. Valid secret -> 200 OK & dispatches asynchronously & updates health
        let resp_ok = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/tg/webhook")
                    .header("content-type", "application/json")
                    .header("X-Telegram-Bot-Api-Secret-Token", "top-secret-123")
                    .body(Body::from(payload.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp_ok.status(), StatusCode::OK);
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(*seen.lock().await, vec![42]);
        assert_eq!(health.snapshot().updates, 1);

        // 4. Empty expected secret fails closed -> 401
        let app_empty_secret = webhook_router(String::new(), disp, Arc::clone(&health));
        let resp_empty = app_empty_secret
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/tg/webhook")
                    .header("content-type", "application/json")
                    .header("X-Telegram-Bot-Api-Secret-Token", "")
                    .body(Body::from(payload))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp_empty.status(), StatusCode::UNAUTHORIZED);

        // 5. Payload > 2 MiB rejected (413 Payload Too Large)
        let huge = vec![b'a'; WEBHOOK_BODY_LIMIT_BYTES + 1024];
        let resp_huge = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/tg/webhook")
                    .header("content-type", "application/json")
                    .header("X-Telegram-Bot-Api-Secret-Token", "top-secret-123")
                    .body(Body::from(huge))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp_huge.status(), StatusCode::PAYLOAD_TOO_LARGE);

        // 6. Malformed JSON with invalid secret returns 401 BEFORE deserializing
        let resp_bad_auth_bad_json = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/tg/webhook")
                    .header("content-type", "application/json")
                    .header("X-Telegram-Bot-Api-Secret-Token", "bad")
                    .body(Body::from("{not-valid-json"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp_bad_auth_bad_json.status(), StatusCode::UNAUTHORIZED);

        // 7. Malformed JSON with valid secret returns 400 Bad Request
        let resp_bad_json = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/tg/webhook")
                    .header("content-type", "application/json")
                    .header("X-Telegram-Bot-Api-Secret-Token", "top-secret-123")
                    .body(Body::from("{not-valid-json"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp_bad_json.status(), StatusCode::BAD_REQUEST);

        // 8. Duplicate update_id is ACKed 200 OK but not re-dispatched
        let dup_payload = serde_json::to_vec(&sample_update(42)).unwrap();
        let resp_dup = app
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/tg/webhook")
                    .header("content-type", "application/json")
                    .header("X-Telegram-Bot-Api-Secret-Token", "top-secret-123")
                    .body(Body::from(dup_payload))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp_dup.status(), StatusCode::OK);
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(*seen.lock().await, vec![42]);
        assert_eq!(health.snapshot().updates, 1);
    }

    #[derive(Clone, Default)]
    struct MockTgTransport {
        methods: Arc<Mutex<Vec<String>>>,
        webhook_error: Arc<Mutex<Option<String>>>,
        delivered_poll: Arc<AtomicBool>,
        shutdown_tx: Arc<Mutex<Option<watch::Sender<bool>>>>,
    }

    async fn tg_mock_handler(
        State(st): State<MockTgTransport>,
        AxumPath((_tok, method)): AxumPath<(String, String)>,
        req: Request,
    ) -> Response {
        let _ = axum::body::to_bytes(req.into_body(), 1024 * 1024).await;
        st.methods.lock().await.push(method.clone());
        match method.as_str() {
            "getMe" => (
                StatusCode::OK,
                Json(json!({
                    "ok": true,
                    "result": { "id": 1, "is_bot": true, "first_name": "Bot" }
                })),
            )
                .into_response(),
            "getWebhookInfo" => {
                let err = st.webhook_error.lock().await.clone();
                (
                    StatusCode::OK,
                    Json(json!({
                        "ok": true,
                        "result": {
                            "url": "https://example.org/tg/webhook",
                            "pending_update_count": 0,
                            "last_error_message": err
                        }
                    })),
                )
                    .into_response()
            }
            "getUpdates" => {
                if !st.delivered_poll.swap(true, Ordering::SeqCst) {
                    if let Some(ref tx) = *st.shutdown_tx.lock().await {
                        let _ = tx.send(true);
                    }
                    (
                        StatusCode::OK,
                        Json(json!({ "ok": true, "result": [sample_update(700)] })),
                    )
                        .into_response()
                } else {
                    (StatusCode::OK, Json(json!({ "ok": true, "result": [] }))).into_response()
                }
            }
            _ => (StatusCode::OK, Json(json!({ "ok": true, "result": true }))).into_response(),
        }
    }

    #[tokio::test]
    async fn transport_supervisor_auto_falls_back_when_webhook_errors_and_uses_webhook_when_clean() {
        let st = MockTgTransport::default();
        let app = Router::new()
            .route("/bot{token}/{method}", post(tg_mock_handler))
            .with_state(st.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let dir = TempDir::new().unwrap();
        let cfg = Arc::new(Config {
            bot_token: "123:TOK".into(),
            state_dir: dir.path().join("state"),
            tg_transport: TransportMode::Auto,
            webhook_url: Some("https://example.org/tg/webhook".into()),
            webhook_secret: Some("sec-123".into()),
            poll_timeout: 1,
            ..Default::default()
        });
        std::fs::create_dir_all(&cfg.state_dir).unwrap();

        let client = Arc::new(
            BotApiClient::new(
                "123:TOK",
                NetConfig::default().with_api_base(format!("http://{addr}")),
            )
            .unwrap(),
        );
        let health = Arc::new(HealthTracker::new(cfg.health_path()));

        // Case 1: getWebhookInfo has last_error_message -> Auto falls back to deleteWebhook + Poller
        *st.webhook_error.lock().await = Some("Connection refused".into());
        let count = Arc::new(AtomicUsize::new(0));
        let count_cb = Arc::clone(&count);
        let (tx1, rx1) = watch::channel(false);
        let tx1_cb = tx1.clone();
        let disp1: Arc<dyn UpdateDispatcher> = Arc::new(FnDispatcher(move |_u: Update| {
            let c = Arc::clone(&count_cb);
            let tx = tx1_cb.clone();
            async move {
                c.fetch_add(1, Ordering::SeqCst);
                let _ = tx.send(true);
            }
        }));
        *st.shutdown_tx.lock().await = None;

        let sup = TransportSupervisor::new(
            Arc::clone(&cfg),
            Arc::clone(&client),
            Arc::clone(&health),
            disp1.clone(),
            Arc::new(|| false),
        )
        .with_watchdog_config(WatchdogConfig {
            interval: Duration::from_millis(50),
            ..Default::default()
        });

        let mode1 = tokio::time::timeout(Duration::from_secs(5), sup.run(rx1))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(mode1, TransportMode::Polling);
        let methods1 = st.methods.lock().await.clone();
        assert!(methods1.contains(&"deleteWebhook".to_string()));
        assert!(methods1.contains(&"getUpdates".to_string()));
        assert_eq!(count.load(Ordering::SeqCst), 1);

        // Case 2: getWebhookInfo has empty last_error_message -> Auto registers setWebhook and runs Webhook
        st.methods.lock().await.clear();
        *st.webhook_error.lock().await = Some(String::new());
        let (tx2, rx2) = watch::channel(false);
        let sup2 = TransportSupervisor::new(
            Arc::clone(&cfg),
            Arc::clone(&client),
            Arc::clone(&health),
            disp1,
            Arc::new(|| false),
        )
        .with_webhook_info_interval(Duration::from_millis(40))
        .with_watchdog_config(WatchdogConfig {
            interval: Duration::from_millis(40),
            ..Default::default()
        });

        let task2 = tokio::spawn(async move { sup2.run(rx2).await });
        tokio::time::sleep(Duration::from_millis(120)).await;
        let _ = tx2.send(true);
        let mode2 = tokio::time::timeout(Duration::from_secs(5), task2)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(mode2, TransportMode::Webhook);
        assert_eq!(health.snapshot().mode, "webhook");
        let methods2 = st.methods.lock().await.clone();
        assert!(methods2.contains(&"setWebhook".to_string()));
        assert!(!methods2.contains(&"deleteWebhook".to_string()));
    }
}
