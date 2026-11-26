//! Linux `sd_notify`, transport telemetry counters, and active connection Watchdog.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use agy_core::Result;
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};

use crate::client::BotApiClient;
use crate::proxy::{ProxyPool, ProxyPoolSnapshot};

/// Send a notification message to systemd over `$NOTIFY_SOCKET` (supports filesystem and
/// Linux `@abstract` Unix datagram sockets). Returns `false` if `$NOTIFY_SOCKET` is unset
/// or delivery fails.
pub fn sd_notify(state: &str) -> bool {
    let Some(addr) = std::env::var_os("NOTIFY_SOCKET") else {
        return false;
    };
    let Some(addr_str) = addr.to_str() else {
        return false;
    };
    sd_notify_to(addr_str, state)
}

/// Send an `sd_notify` datagram explicitly to `addr` (filesystem socket path or `@abstract` name).
pub fn sd_notify_to(addr: &str, state: &str) -> bool {
    if addr.is_empty() {
        return false;
    }
    let Ok(sock) = std::os::unix::net::UnixDatagram::unbound() else {
        return false;
    };
    if let Some(abstract_name) = addr.strip_prefix('@') {
        #[cfg(target_os = "linux")]
        {
            use std::os::linux::net::SocketAddrExt;
            use std::os::unix::net::SocketAddr;
            let Ok(sa) = SocketAddr::from_abstract_name(abstract_name.as_bytes()) else {
                return false;
            };
            return sock.send_to_addr(state.as_bytes(), &sa).is_ok();
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = abstract_name;
            return false;
        }
    }
    sock.send_to(state.as_bytes(), addr).is_ok()
}

pub fn sd_notify_ready() -> bool {
    sd_notify("READY=1")
}

pub fn sd_notify_watchdog() -> bool {
    sd_notify("WATCHDOG=1")
}

pub fn sd_notify_stopping() -> bool {
    sd_notify("STOPPING=1")
}

pub fn sd_notify_status(status: &str) -> bool {
    sd_notify(&format!("STATUS={status}"))
}

/// Snapshot emitted by `Watchdog` on every tick so `agy-bot` can persist `health.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchdogSnapshot {
    pub ts_epoch_secs: f64,
    pub stall_s: f64,
    pub rebuilds: u64,
    pub probe_failed: bool,
    pub note: Option<String>,
    pub proxy_pool: ProxyPoolSnapshot,
}

/// Decoupled telemetry interface connecting `Poller` + `Watchdog` to `agy-core::health::Health`
/// without creating a compile-time dependency on `agy-core::health`.
pub trait NetMetricsSink: Send + Sync {
    fn on_poll_ok(&self, update_count: usize);
    fn on_poll_fail(&self);
    fn stall_secs(&self) -> f64;
    fn on_getme_ok(&self);
    fn on_getme_fail(&self, _err: &str) {}
    fn on_watchdog_snapshot(&self, _snapshot: &WatchdogSnapshot) {}
}

/// Lock-free atomic metrics implementation for standalone use and tests.
pub struct AtomicNetMetrics {
    started_ms: u64,
    last_poll_ok_ms: AtomicU64,
    last_getme_ok_ms: AtomicU64,
    poll_failures: AtomicU64,
    total_poll_failures: AtomicU64,
    updates: AtomicU64,
    last_snapshot: Mutex<Option<WatchdogSnapshot>>,
}

impl Default for AtomicNetMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl AtomicNetMetrics {
    pub fn new() -> Self {
        let now = now_epoch_ms();
        Self {
            started_ms: now,
            last_poll_ok_ms: AtomicU64::new(now),
            last_getme_ok_ms: AtomicU64::new(0),
            poll_failures: AtomicU64::new(0),
            total_poll_failures: AtomicU64::new(0),
            updates: AtomicU64::new(0),
            last_snapshot: Mutex::new(None),
        }
    }

    pub fn started_epoch_secs(&self) -> f64 {
        self.started_ms as f64 / 1000.0
    }

    pub fn last_getme_ok_secs(&self) -> f64 {
        self.last_getme_ok_ms.load(Ordering::Relaxed) as f64 / 1000.0
    }

    pub fn poll_failures(&self) -> u64 {
        self.poll_failures.load(Ordering::Relaxed)
    }

    pub fn total_poll_failures(&self) -> u64 {
        self.total_poll_failures.load(Ordering::Relaxed)
    }

    pub fn updates(&self) -> u64 {
        self.updates.load(Ordering::Relaxed)
    }

    pub fn last_snapshot(&self) -> Option<WatchdogSnapshot> {
        self.last_snapshot
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Adjust `last_poll_ok` backward by `ago` (useful for deterministic stall tests).
    pub fn set_last_poll_ok_ago(&self, ago: Duration) {
        let ms = ago.as_millis().min(u64::MAX as u128) as u64;
        let target = now_epoch_ms().saturating_sub(ms);
        self.last_poll_ok_ms.store(target, Ordering::Relaxed);
    }
}

impl NetMetricsSink for AtomicNetMetrics {
    fn on_poll_ok(&self, update_count: usize) {
        self.last_poll_ok_ms.store(now_epoch_ms(), Ordering::Relaxed);
        self.poll_failures.store(0, Ordering::Relaxed);
        self.updates
            .fetch_add(update_count as u64, Ordering::Relaxed);
    }

    fn on_poll_fail(&self) {
        self.poll_failures.fetch_add(1, Ordering::Relaxed);
        self.total_poll_failures.fetch_add(1, Ordering::Relaxed);
    }

    fn stall_secs(&self) -> f64 {
        let last = self.last_poll_ok_ms.load(Ordering::Relaxed);
        let now = now_epoch_ms();
        now.saturating_sub(last) as f64 / 1000.0
    }

    fn on_getme_ok(&self) {
        self.last_getme_ok_ms
            .store(now_epoch_ms(), Ordering::Relaxed);
    }

    fn on_watchdog_snapshot(&self, snapshot: &WatchdogSnapshot) {
        let mut guard = self.last_snapshot.lock().unwrap_or_else(|e| e.into_inner());
        *guard = Some(snapshot.clone());
    }
}

/// Async health-probe target invoked by `Watchdog` (`getMe` by default).
pub trait ProbeTarget: Send + Sync {
    fn probe_get_me<'a>(&'a self) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>>;
}

impl ProbeTarget for BotApiClient {
    fn probe_get_me<'a>(&'a self) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            // Use a 10s request timeout inside BotApiClient so slow/blackholed proxies trip
            // the circuit breaker before the outer 12s watchdog probe timeout cancels the future.
            self.get_me_with_timeout(Duration::from_secs(10)).await?;
            Ok(())
        })
    }
}

/// Configuration parameters for `Watchdog`.
#[derive(Debug, Clone)]
pub struct WatchdogConfig {
    pub interval: Duration,
    pub getme_every: Duration,
    pub probe_timeout: Duration,
    pub soft_stall: Duration,
    pub hard_stall: Duration,
    pub rebuild_cooldown: Duration,
}

impl Default for WatchdogConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(10),
            getme_every: Duration::from_secs(30),
            probe_timeout: Duration::from_secs(12),
            soft_stall: Duration::from_secs(75),
            hard_stall: Duration::from_secs(300),
            rebuild_cooldown: Duration::from_secs(30),
        }
    }
}

struct WatchdogInner {
    last_probe: Option<Instant>,
    last_rebuild: Option<Instant>,
    actions: Vec<String>,
}

/// Active connection watchdog:
/// - pings systemd `WATCHDOG=1`
/// - probes `getMe` (`30s` healthy / `10s` while failing) and triggers `on_recover` (poller kick)
/// - rebuilds proxy clients when polling stalls beyond `soft_stall` (`75s`)
/// - performs controlled exit (`75`) beyond `hard_stall` (`300s`) only when `!is_busy()`.
pub struct Watchdog {
    cfg: WatchdogConfig,
    metrics: Arc<dyn NetMetricsSink>,
    pool: Arc<ProxyPool>,
    probe: Arc<dyn ProbeTarget>,
    is_busy: Arc<dyn Fn() -> bool + Send + Sync>,
    on_recover: Option<Arc<dyn Fn() + Send + Sync>>,
    exit_fn: Arc<dyn Fn(i32) + Send + Sync>,
    probe_failed: AtomicBool,
    inner: Mutex<WatchdogInner>,
}

impl Watchdog {
    pub fn new(
        cfg: WatchdogConfig,
        metrics: Arc<dyn NetMetricsSink>,
        pool: Arc<ProxyPool>,
        probe: Arc<dyn ProbeTarget>,
        is_busy: Arc<dyn Fn() -> bool + Send + Sync>,
    ) -> Self {
        Self {
            cfg,
            metrics,
            pool,
            probe,
            is_busy,
            on_recover: None,
            exit_fn: Arc::new(|code| std::process::exit(code)),
            probe_failed: AtomicBool::new(false),
            inner: Mutex::new(WatchdogInner {
                last_probe: None,
                last_rebuild: None,
                actions: Vec::new(),
            }),
        }
    }

    pub fn with_on_recover(mut self, cb: Arc<dyn Fn() + Send + Sync>) -> Self {
        self.on_recover = Some(cb);
        self
    }

    pub fn with_exit_fn(mut self, cb: Arc<dyn Fn(i32) + Send + Sync>) -> Self {
        self.exit_fn = cb;
        self
    }

    pub fn is_probe_failed(&self) -> bool {
        self.probe_failed.load(Ordering::Relaxed)
    }

    pub fn actions(&self) -> Vec<String> {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .actions
            .clone()
    }

    /// Execute a single watchdog cycle (probe, stall checks, snapshot emission).
    pub async fn tick(&self) {
        let now = Instant::now();
        sd_notify_watchdog();

        let every = if self.probe_failed.load(Ordering::Relaxed) {
            self.cfg.interval
        } else {
            self.cfg.getme_every
        };

        let should_probe = {
            let mut st = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            let due = st
                .last_probe
                .is_none_or(|last| now.duration_since(last) >= every);
            if due {
                st.last_probe = Some(now);
            }
            due
        };

        if should_probe {
            match tokio::time::timeout(self.cfg.probe_timeout, self.probe.probe_get_me()).await {
                Ok(Ok(())) => {
                    self.metrics.on_getme_ok();
                    if self.probe_failed.swap(false, Ordering::Relaxed) {
                        {
                            let mut st = self.inner.lock().unwrap_or_else(|e| e.into_inner());
                            st.actions.push("recover".to_string());
                        }
                        info!("watchdog: Telegram reachable again -> restarting in-flight long-poll");
                        if let Some(ref cb) = self.on_recover {
                            cb();
                        }
                    }
                }
                Ok(Err(e)) => {
                    self.probe_failed.store(true, Ordering::Relaxed);
                    let msg = e.to_string();
                    self.metrics.on_getme_fail(&msg);
                    warn!(err = %msg, "watchdog getMe probe failed");
                }
                Err(_) => {
                    self.probe_failed.store(true, Ordering::Relaxed);
                    self.metrics.on_getme_fail("probe timeout");
                    warn!("watchdog getMe probe timed out");
                }
            }
        }

        let stall_s = self.metrics.stall_secs().max(0.0);
        let stall = Duration::from_secs_f64(stall_s);

        if stall > self.cfg.hard_stall && !(self.is_busy)() {
            {
                let mut st = self.inner.lock().unwrap_or_else(|e| e.into_inner());
                st.actions.push("exit".to_string());
            }
            error!(
                stall_s = format_args!("{stall_s:.0}"),
                "polling stalled past hard limit -> exiting for systemd restart"
            );
            let snap = WatchdogSnapshot {
                ts_epoch_secs: now_epoch_secs(),
                stall_s: round1(stall_s),
                rebuilds: self.pool.total_rebuilds(),
                probe_failed: self.probe_failed.load(Ordering::Relaxed),
                note: Some("watchdog exit".to_string()),
                proxy_pool: self.pool.snapshot(),
            };
            self.metrics.on_watchdog_snapshot(&snap);
            (self.exit_fn)(75);
            return;
        } else if stall > self.cfg.soft_stall {
            let should_rebuild = {
                let mut st = self.inner.lock().unwrap_or_else(|e| e.into_inner());
                let due = st
                    .last_rebuild
                    .is_none_or(|last| now.duration_since(last) > self.cfg.rebuild_cooldown);
                if due {
                    st.last_rebuild = Some(now);
                    st.actions.push("rebuild".to_string());
                }
                due
            };
            if should_rebuild {
                self.pool
                    .rebuild_all(&format!("watchdog: polling stalled {stall_s:.0}s"));
                if let Some(ref cb) = self.on_recover {
                    cb();
                }
            }
        }

        let snap = WatchdogSnapshot {
            ts_epoch_secs: now_epoch_secs(),
            stall_s: round1(stall_s),
            rebuilds: self.pool.total_rebuilds(),
            probe_failed: self.probe_failed.load(Ordering::Relaxed),
            note: None,
            proxy_pool: self.pool.snapshot(),
        };
        self.metrics.on_watchdog_snapshot(&snap);
    }

    /// Run the watchdog loop every `cfg.interval` until `shutdown` flips to `true`.
    pub async fn run(&self, mut shutdown: tokio::sync::watch::Receiver<bool>) {
        loop {
            if *shutdown.borrow() {
                break;
            }
            self.tick().await;
            tokio::select! {
                _ = tokio::time::sleep(self.cfg.interval) => {}
                res = shutdown.changed() => {
                    if res.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
            }
        }
    }
}

fn round1(v: f64) -> f64 {
    (v * 10.0).round() / 10.0
}

fn now_epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis().min(u64::MAX as u128) as u64)
        .unwrap_or(0)
}

fn now_epoch_secs() -> f64 {
    now_epoch_ms() as f64 / 1000.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::NetConfig;
    use agy_core::BridgeError;
    use std::os::unix::net::UnixDatagram;
    use std::sync::atomic::AtomicI32;

    struct FakeProbe {
        should_fail: AtomicBool,
    }

    impl ProbeTarget for FakeProbe {
        fn probe_get_me<'a>(&'a self) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
            Box::pin(async move {
                if self.should_fail.load(Ordering::Relaxed) {
                    Err(BridgeError::Network("down".into()))
                } else {
                    Ok(())
                }
            })
        }
    }

    #[tokio::test]
    async fn watchdog_healthy_soft_hard_and_busy_guard() {
        let pool = Arc::new(ProxyPool::new(NetConfig::default()).unwrap());
        let metrics = Arc::new(AtomicNetMetrics::new());
        let probe = Arc::new(FakeProbe {
            should_fail: AtomicBool::new(false),
        });
        let exit_code = Arc::new(AtomicI32::new(0));
        let busy = Arc::new(AtomicBool::new(false));

        let exit_clone = Arc::clone(&exit_code);
        let busy_clone = Arc::clone(&busy);
        let wd = Watchdog::new(
            WatchdogConfig::default(),
            metrics.clone(),
            pool.clone(),
            probe,
            Arc::new(move || busy_clone.load(Ordering::Relaxed)),
        )
        .with_exit_fn(Arc::new(move |c| {
            exit_clone.store(c, Ordering::Relaxed);
        }));

        // Healthy tick
        wd.tick().await;
        assert_eq!(exit_code.load(Ordering::Relaxed), 0);
        assert_eq!(pool.total_rebuilds(), 0);
        assert!(metrics.last_getme_ok_secs() > 0.0);
        assert!(metrics.last_snapshot().is_some());

        // Soft stall -> triggers rebuild once (rate-limited for 30s)
        metrics.set_last_poll_ok_ago(Duration::from_secs(100));
        wd.tick().await;
        assert_eq!(pool.total_rebuilds(), 1);
        assert_eq!(exit_code.load(Ordering::Relaxed), 0);
        wd.tick().await;
        assert_eq!(pool.total_rebuilds(), 1);

        // Hard stall while busy -> MUST NOT exit!
        busy.store(true, Ordering::Relaxed);
        metrics.set_last_poll_ok_ago(Duration::from_secs(400));
        wd.tick().await;
        assert_eq!(exit_code.load(Ordering::Relaxed), 0);

        // Hard stall while idle -> exits 75 with snapshot note
        busy.store(false, Ordering::Relaxed);
        wd.tick().await;
        assert_eq!(exit_code.load(Ordering::Relaxed), 75);
        assert_eq!(
            metrics.last_snapshot().unwrap().note.as_deref(),
            Some("watchdog exit")
        );
    }

    #[tokio::test]
    async fn watchdog_recover_kicks_poller() {
        let pool = Arc::new(ProxyPool::new(NetConfig::default()).unwrap());
        let metrics = Arc::new(AtomicNetMetrics::new());
        let probe = Arc::new(FakeProbe {
            should_fail: AtomicBool::new(true),
        });
        let kicks = Arc::new(AtomicU64::new(0));
        let kicks_cb = Arc::clone(&kicks);

        let wd = Watchdog::new(
            WatchdogConfig {
                interval: Duration::ZERO,
                getme_every: Duration::ZERO,
                ..Default::default()
            },
            metrics,
            pool,
            probe.clone(),
            Arc::new(|| false),
        )
        .with_on_recover(Arc::new(move || {
            kicks_cb.fetch_add(1, Ordering::Relaxed);
        }));

        wd.tick().await;
        assert!(wd.is_probe_failed());
        assert_eq!(kicks.load(Ordering::Relaxed), 0);

        probe.should_fail.store(false, Ordering::Relaxed);
        wd.tick().await;
        assert!(!wd.is_probe_failed());
        assert_eq!(kicks.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn sd_notify_unix_and_abstract_socket() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("notify.sock");
        let srv = UnixDatagram::bind(&sock_path).unwrap();
        assert!(sd_notify_to(sock_path.to_str().unwrap(), "WATCHDOG=1"));
        let mut buf = [0u8; 64];
        let n = srv.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"WATCHDOG=1");

        #[cfg(target_os = "linux")]
        {
            use std::os::linux::net::SocketAddrExt;
            use std::os::unix::net::SocketAddr;
            let name = format!("agy_net_test_{}", std::process::id());
            let sa = SocketAddr::from_abstract_name(name.as_bytes()).unwrap();
            let abs_srv = UnixDatagram::bind_addr(&sa).unwrap();
            assert!(sd_notify_to(&format!("@{name}"), "READY=1"));
            let n2 = abs_srv.recv(&mut buf).unwrap();
            assert_eq!(&buf[..n2], b"READY=1");
        }
    }
}
