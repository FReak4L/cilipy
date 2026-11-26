//! Resilient Telegram long-polling loop, atomic offset persistence, bounded deduplication,
//! watchdog kick cancellation, and constant-time webhook secret verification.

use std::collections::{HashSet, VecDeque};
use std::future::Future;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use agy_core::tg::Update;
use agy_core::{BridgeError, Result};
use futures_util::future::join_all;
use subtle::ConstantTimeEq;
use tokio::sync::{Mutex, Notify};
use tracing::{error, info, warn};

use crate::client::{full_jitter, BotApiClient};
use crate::watchdog::NetMetricsSink;

/// Constant-time verification for Telegram's `X-Telegram-Bot-Api-Secret-Token` webhook header.
/// Fails closed (`false`) if `expected_secret` is empty or the header is missing.
pub fn verify_webhook_secret(header_val: Option<&str>, expected_secret: &str) -> bool {
    if expected_secret.is_empty() {
        return false;
    }
    let Some(actual) = header_val else {
        return false;
    };
    bool::from(actual.as_bytes().ct_eq(expected_secret.as_bytes()))
}

/// Abstract update source for `Poller`, implemented by `BotApiClient` and mock test fetchers.
pub trait UpdateFetcher: Send + Sync {
    fn fetch_updates<'a>(
        &'a self,
        offset: Option<i64>,
        timeout_secs: u64,
        allowed_updates: &'a [String],
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Update>>> + Send + 'a>>;
}

impl UpdateFetcher for BotApiClient {
    fn fetch_updates<'a>(
        &'a self,
        offset: Option<i64>,
        timeout_secs: u64,
        allowed_updates: &'a [String],
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Update>>> + Send + 'a>> {
        Box::pin(async move { self.get_updates(offset, timeout_secs, allowed_updates).await })
    }
}

/// Configuration for `Poller`.
#[derive(Debug, Clone)]
pub struct PollerConfig {
    pub allowed_updates: Vec<String>,
    pub poll_timeout_secs: u64,
    pub handle_timeout: Duration,
    pub offset_file: PathBuf,
    pub dedup_capacity: usize,
    pub dedup_evict_batch: usize,
    pub backoff_scale: f64,
}

impl Default for PollerConfig {
    fn default() -> Self {
        Self {
            allowed_updates: Vec::new(),
            poll_timeout_secs: 30,
            handle_timeout: Duration::from_secs(25),
            offset_file: PathBuf::from("/var/lib/agy-telegram/offset"),
            dedup_capacity: 2000,
            dedup_evict_batch: 1000,
            backoff_scale: 1.0,
        }
    }
}

struct PollerState {
    offset: Option<i64>,
    seen_set: HashSet<i64>,
    seen_order: VecDeque<i64>,
}

struct InFlightGuard<'a>(&'a AtomicBool);

impl Drop for InFlightGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

/// Safe long-polling loop:
/// - reads/writes numeric `offset` atomically to `offset_file`
/// - maintains a bounded 2000-entry seen `update_id` deduplication cache
/// - spawns concurrent update handlers bounded by `handle_timeout` (`25s`) before confirming offset
/// - supports immediate cancellation of stalled long-polls via `kick()` (`Notify` + `select!`).
pub struct Poller {
    cfg: PollerConfig,
    metrics: Arc<dyn NetMetricsSink>,
    state: Mutex<PollerState>,
    cached_offset: AtomicI64,
    kick_notify: Arc<Notify>,
    stop_notify: Arc<Notify>,
    in_flight: AtomicBool,
    stopped: AtomicBool,
}

impl Poller {
    pub fn new(cfg: PollerConfig, metrics: Arc<dyn NetMetricsSink>) -> Self {
        let initial_offset = load_offset(&cfg.offset_file);
        let cached = initial_offset.unwrap_or(0);
        Self {
            cfg,
            metrics,
            state: Mutex::new(PollerState {
                offset: initial_offset,
                seen_set: HashSet::new(),
                seen_order: VecDeque::new(),
            }),
            cached_offset: AtomicI64::new(cached),
            kick_notify: Arc::new(Notify::new()),
            stop_notify: Arc::new(Notify::new()),
            in_flight: AtomicBool::new(false),
            stopped: AtomicBool::new(false),
        }
    }

    /// Current confirmed next-update offset (`None` if unset / 0).
    pub fn offset(&self) -> Option<i64> {
        let v = self.cached_offset.load(Ordering::Relaxed);
        (v > 0).then_some(v)
    }

    /// Abort an in-flight long-poll (e.g., called by `Watchdog` on probe recovery) so `run()`
    /// immediately retries `getUpdates` over a fresh socket.
    pub fn kick(&self) {
        if self.in_flight.load(Ordering::SeqCst) {
            self.kick_notify.notify_one();
        }
    }

    /// Request graceful stop of the polling loop.
    pub fn stop(&self) {
        self.stopped.store(true, Ordering::SeqCst);
        self.stop_notify.notify_waiters();
    }

    pub fn is_stopped(&self) -> bool {
        self.stopped.load(Ordering::SeqCst)
    }

    /// Process a batch of updates: deduplicate, dispatch concurrent handlers up to
    /// `handle_timeout`, advance `offset`, evict old dedup entries, and atomically persist offset.
    /// Returns the number of non-duplicate updates dispatched.
    pub async fn process_updates<H, Fut>(&self, updates: Vec<Update>, handler: H) -> usize
    where
        H: Fn(Update) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        if updates.is_empty() {
            return 0;
        }

        let update_ids: Vec<i64> = updates.iter().map(|u| u.update_id).collect();
        let fresh: Vec<Update> = {
            let mut st = self.state.lock().await;
            let mut out = Vec::new();
            for u in updates {
                if st.seen_set.insert(u.update_id) {
                    st.seen_order.push_back(u.update_id);
                    out.push(u);
                }
            }
            out
        };

        let fresh_count = fresh.len();
        if !fresh.is_empty() {
            let handles: Vec<_> = fresh
                .into_iter()
                .map(|u| {
                    let fut = handler(u);
                    tokio::spawn(fut)
                })
                .collect();

            let total_tasks = handles.len();
            if tokio::time::timeout(self.cfg.handle_timeout, join_all(handles))
                .await
                .is_err()
            {
                info!(
                    handlers = total_tasks,
                    timeout_s = self.cfg.handle_timeout.as_secs(),
                    "handler(s) still running; confirming offset anyway"
                );
            }
        }

        let next_offset = {
            let mut st = self.state.lock().await;
            for uid in update_ids {
                if st.seen_set.insert(uid) {
                    st.seen_order.push_back(uid);
                }
                let candidate = uid.saturating_add(1);
                let next = st.offset.unwrap_or(0).max(candidate);
                st.offset = Some(next);
            }
            if st.seen_order.len() > self.cfg.dedup_capacity {
                let to_evict = self
                    .cfg
                    .dedup_evict_batch
                    .min(st.seen_order.len());
                for _ in 0..to_evict {
                    if let Some(old_id) = st.seen_order.pop_front() {
                        st.seen_set.remove(&old_id);
                    }
                }
            }
            st.offset
        };

        if let Some(off) = next_offset {
            self.cached_offset.store(off, Ordering::Relaxed);
        }
        save_offset(&self.cfg.offset_file, next_offset);

        fresh_count
    }

    /// Run the resilient long-polling loop until `stop()` is called.
    pub async fn run<F, H, Fut>(&self, fetcher: &F, handler: H)
    where
        F: UpdateFetcher,
        H: Fn(Update) -> Fut + Send + Sync + Clone + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let mut attempt: u32 = 0;

        while !self.is_stopped() {
            // Drain any stale kick notifications from prior iterations before arming in_flight.
            tokio::select! {
                biased;
                _ = self.kick_notify.notified() => {}
                _ = std::future::ready(()) => {}
            }

            let cur_offset = self.offset();
            self.in_flight.store(true, Ordering::SeqCst);
            let fetch_result = {
                let _guard = InFlightGuard(&self.in_flight);
                let stop_fut = self.stop_notify.notified();
                tokio::pin!(stop_fut);
                stop_fut.as_mut().enable();
                if self.is_stopped() {
                    break;
                }
                tokio::select! {
                    biased;
                    _ = stop_fut => {
                        break;
                    }
                    _ = self.kick_notify.notified() => {
                        info!("long-poll restarted by watchdog");
                        continue;
                    }
                    res = fetcher.fetch_updates(cur_offset, self.cfg.poll_timeout_secs, &self.cfg.allowed_updates) => res
                }
            };

            if self.is_stopped() {
                if let Ok(updates) = fetch_result {
                    self.metrics.on_poll_ok(updates.len());
                    self.process_updates(updates, handler).await;
                }
                break;
            }

            match fetch_result {
                Ok(updates) => {
                    if attempt > 0 {
                        info!(failed_attempts = attempt, "polling recovered");
                    }
                    attempt = 0;
                    self.metrics.on_poll_ok(updates.len());
                    self.process_updates(updates, handler.clone()).await;
                }
                Err(BridgeError::RateLimited {
                    retry_after_secs, ..
                }) => {
                    let wait = Duration::from_secs_f64(
                        (retry_after_secs.saturating_add(1)) as f64 * self.cfg.backoff_scale,
                    );
                    warn!(retry_after_secs, "getUpdates rate limited; backing off");
                    if self.sleep_interruptible(wait).await {
                        break;
                    }
                }
                Err(BridgeError::BotApi {
                    code: 409, message, ..
                }) => {
                    self.metrics.on_poll_fail();
                    let d = (full_jitter(attempt, 2.0, 30.0) + 5.0) * self.cfg.backoff_scale;
                    error!(
                        err = %truncate_err(&message, 120),
                        retry_s = format_args!("{d:.1}"),
                        "getUpdates conflict (webhook set or another instance)"
                    );
                    attempt = attempt.saturating_add(1);
                    if self.sleep_interruptible(Duration::from_secs_f64(d)).await {
                        break;
                    }
                }
                Err(e) if e.is_retryable() => {
                    self.metrics.on_poll_fail();
                    attempt = attempt.saturating_add(1);
                    let d = full_jitter(attempt, 1.0, 30.0) * self.cfg.backoff_scale;
                    warn!(
                        err = %truncate_err(&e.to_string(), 80),
                        retry_s = format_args!("{d:.1}"),
                        "getUpdates failed; retrying"
                    );
                    if self.sleep_interruptible(Duration::from_secs_f64(d)).await {
                        break;
                    }
                }
                Err(e) => {
                    self.metrics.on_poll_fail();
                    attempt = attempt.saturating_add(1);
                    let d = (full_jitter(attempt, 2.0, 30.0) + 2.0) * self.cfg.backoff_scale;
                    error!(
                        err = %truncate_err(&e.to_string(), 120),
                        retry_s = format_args!("{d:.1}"),
                        "getUpdates unexpected API error"
                    );
                    if self.sleep_interruptible(Duration::from_secs_f64(d)).await {
                        break;
                    }
                }
            }
        }
    }

    async fn sleep_interruptible(&self, duration: Duration) -> bool {
        if self.is_stopped() {
            return true;
        }
        if duration.is_zero() {
            return false;
        }
        tokio::select! {
            biased;
            _ = self.stop_notify.notified() => true,
            _ = tokio::time::sleep(duration) => self.is_stopped(),
        }
    }
}

fn load_offset(path: &Path) -> Option<i64> {
    let raw = std::fs::read_to_string(path).ok()?;
    let val = raw.trim().parse::<i64>().ok()?;
    (val > 0).then_some(val)
}

fn save_offset(path: &Path, offset: Option<i64>) {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if let Err(e) = std::fs::create_dir_all(parent) {
        warn!(path = %path.display(), err = %e, "failed to create offset parent dir");
        return;
    }
    let mut tmp = match tempfile::Builder::new()
        .prefix(".offset-")
        .suffix(".tmp")
        .tempfile_in(parent)
    {
        Ok(f) => f,
        Err(e) => {
            warn!(path = %path.display(), err = %e, "failed to create temp offset file");
            return;
        }
    };
    let text = offset.unwrap_or(0).to_string();
    if let Err(e) = tmp.write_all(text.as_bytes()).and_then(|_| tmp.flush()) {
        warn!(path = %path.display(), err = %e, "failed to write temp offset file");
        return;
    }
    if let Err(e) = tmp.persist(path) {
        warn!(path = %path.display(), err = %e.error, "failed to persist offset file");
    }
}

fn truncate_err(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        return s.to_string();
    }
    s.chars().take(max_chars).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::watchdog::AtomicNetMetrics;
    use agy_core::tg::{Chat, Message};
    use std::sync::atomic::AtomicUsize;

    fn dummy_update(id: i64) -> Update {
        Update {
            update_id: id,
            message: Some(Message {
                message_id: id,
                from_user: None,
                chat: Chat {
                    id: 1,
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

    #[test]
    fn webhook_secret_constant_time_and_fail_closed() {
        assert!(verify_webhook_secret(Some("top-secret-token"), "top-secret-token"));
        assert!(!verify_webhook_secret(Some("top-secret-tokeN"), "top-secret-token"));
        assert!(!verify_webhook_secret(Some("short"), "top-secret-token"));
        assert!(!verify_webhook_secret(None, "top-secret-token"));
        // Fail closed if expected secret is empty
        assert!(!verify_webhook_secret(Some(""), ""));
        assert!(!verify_webhook_secret(None, ""));
    }

    #[tokio::test]
    async fn poller_offset_persistence_and_dedup() {
        let dir = tempfile::tempdir().unwrap();
        let off_path = dir.path().join("off");
        let metrics = Arc::new(AtomicNetMetrics::new());
        let seen = Arc::new(Mutex::new(Vec::new()));

        let poller = Poller::new(
            PollerConfig {
                offset_file: off_path.clone(),
                dedup_capacity: 5,
                dedup_evict_batch: 2,
                ..Default::default()
            },
            metrics,
        );

        let s1 = seen.clone();
        poller
            .process_updates(vec![dummy_update(10), dummy_update(11)], move |u| {
                let s = s1.clone();
                async move {
                    s.lock().await.push(u.update_id);
                }
            })
            .await;

        let s2 = seen.clone();
        poller
            .process_updates(vec![dummy_update(11), dummy_update(12)], move |u| {
                let s = s2.clone();
                async move {
                    s.lock().await.push(u.update_id);
                }
            })
            .await;

        let mut got = seen.lock().await.clone();
        got.sort();
        assert_eq!(got, vec![10, 11, 12]);
        assert_eq!(poller.offset(), Some(13));
        assert_eq!(std::fs::read_to_string(&off_path).unwrap(), "13");

        let poller2 = Poller::new(
            PollerConfig {
                offset_file: off_path,
                ..Default::default()
            },
            Arc::new(AtomicNetMetrics::new()),
        );
        assert_eq!(poller2.offset(), Some(13));
    }

    #[tokio::test]
    async fn poller_retries_network_and_429_and_conflict() {
        struct MockFetcher {
            calls: AtomicUsize,
            stop_poller: Mutex<Option<Arc<Poller>>>,
        }

        impl UpdateFetcher for MockFetcher {
            fn fetch_updates<'a>(
                &'a self,
                _offset: Option<i64>,
                _timeout_secs: u64,
                _allowed_updates: &'a [String],
            ) -> Pin<Box<dyn Future<Output = Result<Vec<Update>>> + Send + 'a>> {
                Box::pin(async move {
                    let n = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
                    match n {
                        1 => Err(BridgeError::Network("timeout".into())),
                        2 => Err(BridgeError::RateLimited {
                            retry_after_secs: 0,
                            message: "slow down".into(),
                        }),
                        3 => Err(BridgeError::BotApi {
                            code: 409,
                            message: "Conflict: other instance".into(),
                            retryable: false,
                        }),
                        _ => {
                            if let Some(p) = self.stop_poller.lock().await.as_ref() {
                                p.stop();
                            }
                            Ok(vec![dummy_update(5)])
                        }
                    }
                })
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let metrics = Arc::new(AtomicNetMetrics::new());
        let poller = Arc::new(Poller::new(
            PollerConfig {
                offset_file: dir.path().join("off"),
                backoff_scale: 0.001,
                ..Default::default()
            },
            metrics.clone(),
        ));
        let fetcher = MockFetcher {
            calls: AtomicUsize::new(0),
            stop_poller: Mutex::new(Some(poller.clone())),
        };
        let got = Arc::new(Mutex::new(Vec::new()));
        let got_cb = got.clone();
        poller
            .run(&fetcher, move |u| {
                let g = got_cb.clone();
                async move {
                    g.lock().await.push(u.update_id);
                }
            })
            .await;

        assert_eq!(fetcher.calls.load(Ordering::SeqCst), 4);
        assert_eq!(*got.lock().await, vec![5]);
        assert_eq!(metrics.total_poll_failures(), 2); // Network + 409; 429 doesn't increment poll_fail
        assert_eq!(metrics.poll_failures(), 0);
    }

    #[tokio::test]
    async fn poller_kick_restarts_stalled_fetch() {
        struct StallingFetcher {
            calls: AtomicUsize,
            poller: Mutex<Option<Arc<Poller>>>,
        }

        impl UpdateFetcher for StallingFetcher {
            fn fetch_updates<'a>(
                &'a self,
                _offset: Option<i64>,
                _timeout_secs: u64,
                _allowed_updates: &'a [String],
            ) -> Pin<Box<dyn Future<Output = Result<Vec<Update>>> + Send + 'a>> {
                Box::pin(async move {
                    let n = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
                    if n == 1 {
                        tokio::time::sleep(Duration::from_secs(60)).await;
                        unreachable!("should be kicked before 60s");
                    }
                    if let Some(p) = self.poller.lock().await.as_ref() {
                        p.stop();
                    }
                    Ok(vec![dummy_update(1)])
                })
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let metrics = Arc::new(AtomicNetMetrics::new());
        let poller = Arc::new(Poller::new(
            PollerConfig {
                offset_file: dir.path().join("off"),
                ..Default::default()
            },
            metrics,
        ));
        let fetcher = Arc::new(StallingFetcher {
            calls: AtomicUsize::new(0),
            poller: Mutex::new(Some(poller.clone())),
        });

        let got = Arc::new(Mutex::new(Vec::new()));
        let got_cb = got.clone();
        let poller_task = {
            let p = poller.clone();
            let f = fetcher.clone();
            tokio::spawn(async move {
                p.run(&*f, move |u| {
                    let g = got_cb.clone();
                    async move {
                        g.lock().await.push(u.update_id);
                    }
                })
                .await;
            })
        };

        tokio::time::sleep(Duration::from_millis(50)).await;
        poller.kick();
        tokio::time::timeout(Duration::from_secs(5), poller_task)
            .await
            .expect("poller should finish promptly after kick")
            .unwrap();

        assert_eq!(fetcher.calls.load(Ordering::SeqCst), 2);
        assert_eq!(*got.lock().await, vec![1]);
    }

    #[tokio::test]
    async fn poller_dedup_eviction_and_handle_timeout() {
        let dir = tempfile::tempdir().unwrap();
        let metrics = Arc::new(AtomicNetMetrics::new());
        let poller = Poller::new(
            PollerConfig {
                offset_file: dir.path().join("off"),
                dedup_capacity: 4,
                dedup_evict_batch: 2,
                handle_timeout: Duration::from_millis(40),
                ..Default::default()
            },
            metrics,
        );

        let completed = Arc::new(AtomicUsize::new(0));
        let c1 = completed.clone();
        let t0 = std::time::Instant::now();
        // Slow handler (150ms) exceeds handle_timeout (40ms): offset still confirms promptly
        let n = poller
            .process_updates(
                (1..=5).map(dummy_update).collect(),
                move |_u| {
                    let c = c1.clone();
                    async move {
                        tokio::time::sleep(Duration::from_millis(120)).await;
                        c.fetch_add(1, Ordering::SeqCst);
                    }
                },
            )
            .await;
        assert_eq!(n, 5);
        assert!(t0.elapsed() < Duration::from_millis(110));
        assert_eq!(poller.offset(), Some(6));

        // Ids 1 and 2 were evicted (capacity 4, evicted 2), while 3,4,5 remain seen
        let n2 = poller
            .process_updates(vec![dummy_update(1), dummy_update(4)], |_| async {})
            .await;
        assert_eq!(n2, 1);

        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(completed.load(Ordering::SeqCst), 5);
    }
}
