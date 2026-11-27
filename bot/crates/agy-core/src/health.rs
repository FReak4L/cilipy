//! Thread-safe runtime health metrics and atomic `health.json` writer
//! compatible with `/opt/agy-telegram/healthcheck.sh`.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::atomic::atomic_write_json;
use crate::config::redact_proxy_url;
use crate::error::Result;

fn now_secs() -> f64 {
    crate::text::now_secs()
}

/// Serialized JSON snapshot written to `/var/lib/agy-telegram/health.json`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HealthSnapshot {
    pub ts: f64,
    pub mode: String,
    pub stall_s: f64,
    pub last_getme_ok: f64,
    pub poll_failures: u64,
    pub total_poll_failures: u64,
    pub updates: u64,
    pub pid: u32,
    pub note: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rebuilds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_active: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_health: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cron_jobs: Option<Value>,
}

#[derive(Debug)]
struct HealthState {
    started: f64,
    last_poll_ok: f64,
    last_getme_ok: f64,
    poll_failures: u64,
    total_poll_failures: u64,
    mode: String,
    updates: u64,
    note: String,
    rebuilds: Option<u64>,
    proxy_active: Option<String>,
    proxy_health: Option<Value>,
    cron_jobs: Option<Value>,
}

/// Thread-safe health metrics tracker and atomic `health.json` persistence handle.
pub struct HealthTracker {
    path: PathBuf,
    pid: u32,
    state: Mutex<HealthState>,
    write_lock: Mutex<()>,
}

impl HealthTracker {
    /// Creates a new `HealthTracker` targeting `path` (`health.json`).
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self::new_at(path, now_secs())
    }

    /// Deterministic timestamp constructor for tests.
    pub fn new_at(path: impl Into<PathBuf>, now: f64) -> Self {
        Self {
            path: path.into(),
            pid: std::process::id(),
            state: Mutex::new(HealthState {
                started: now,
                last_poll_ok: now,
                last_getme_ok: 0.0,
                poll_failures: 0,
                total_poll_failures: 0,
                mode: "polling".to_string(),
                updates: 0,
                note: String::new(),
                rebuilds: None,
                proxy_active: None,
                proxy_health: None,
                cron_jobs: None,
            }),
            write_lock: Mutex::new(()),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn started_at(&self) -> f64 {
        let g = self.lock_state();
        g.started
    }

    /// Marks a successful poll/update batch, resetting consecutive `poll_failures`.
    pub fn poll_ok(&self, update_count: u64) {
        self.poll_ok_at(update_count, now_secs());
    }

    /// Deterministic timestamp variant of [`Self::poll_ok`].
    pub fn poll_ok_at(&self, update_count: u64, now: f64) {
        let mut g = self.lock_state();
        g.last_poll_ok = now;
        g.poll_failures = 0;
        g.updates = g.updates.saturating_add(update_count);
    }

    /// Increments consecutive and monotonic total poll failure counters.
    pub fn poll_fail(&self) {
        let mut g = self.lock_state();
        g.poll_failures = g.poll_failures.saturating_add(1);
        g.total_poll_failures = g.total_poll_failures.saturating_add(1);
    }

    pub fn set_last_poll_ok(&self, ts: f64) {
        let mut g = self.lock_state();
        g.last_poll_ok = ts;
    }

    pub fn mark_getme_ok(&self) {
        self.set_getme_ok(now_secs());
    }

    pub fn set_getme_ok(&self, ts: f64) {
        let mut g = self.lock_state();
        g.last_getme_ok = ts;
    }

    pub fn set_mode(&self, mode: impl Into<String>) {
        let mut g = self.lock_state();
        g.mode = mode.into();
    }

    pub fn set_note(&self, note: impl Into<String>) {
        let mut g = self.lock_state();
        g.note = note.into();
    }

    pub fn set_rebuilds(&self, rebuilds: Option<u64>) {
        let mut g = self.lock_state();
        g.rebuilds = rebuilds;
    }

    /// Records active proxy label (with credentials redacted) and optional proxy pool health JSON.
    pub fn set_proxy_state(&self, active: Option<&str>, health: Option<Value>) {
        let mut g = self.lock_state();
        g.proxy_active = active.map(redact_proxy_url);
        g.proxy_health = health;
    }

    /// Records optional cron/sync scheduler status telemetry.
    pub fn set_cron_jobs(&self, cron_jobs: Option<Value>) {
        let mut g = self.lock_state();
        g.cron_jobs = cron_jobs;
    }

    /// Seconds elapsed since the last successful poll/heartbeat.
    pub fn stall_secs(&self) -> f64 {
        self.stall_secs_at(now_secs())
    }

    /// Deterministic timestamp variant of [`Self::stall_secs`].
    pub fn stall_secs_at(&self, now: f64) -> f64 {
        let g = self.lock_state();
        (now - g.last_poll_ok).max(0.0)
    }

    /// Builds a consistent [`HealthSnapshot`] without touching disk.
    pub fn snapshot(&self) -> HealthSnapshot {
        self.snapshot_at(now_secs())
    }

    /// Deterministic timestamp variant of [`Self::snapshot`].
    pub fn snapshot_at(&self, now: f64) -> HealthSnapshot {
        let g = self.lock_state();
        let stall_raw = (now - g.last_poll_ok).max(0.0);
        let stall_s = (stall_raw * 10.0).round() / 10.0;
        HealthSnapshot {
            ts: now,
            mode: g.mode.clone(),
            stall_s,
            last_getme_ok: g.last_getme_ok,
            poll_failures: g.poll_failures,
            total_poll_failures: g.total_poll_failures,
            updates: g.updates,
            pid: self.pid,
            note: g.note.clone(),
            rebuilds: g.rebuilds,
            proxy_active: g.proxy_active.clone(),
            proxy_health: g.proxy_health.clone(),
            cron_jobs: g.cron_jobs.clone(),
        }
    }

    /// Atomically writes `health.json` to disk and returns the written snapshot.
    pub fn write(&self) -> Result<HealthSnapshot> {
        self.write_at(now_secs())
    }

    /// Deterministic timestamp variant of [`Self::write`].
    pub fn write_at(&self, now: f64) -> Result<HealthSnapshot> {
        let _write_guard = match self.write_lock.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        let snap = self.snapshot_at(now);
        atomic_write_json(&self.path, &snap, false)?;
        Ok(snap)
    }

    /// Updates `note` and atomically writes `health.json`.
    pub fn write_with_note(&self, note: impl Into<String>) -> Result<HealthSnapshot> {
        self.set_note(note);
        self.write()
    }

    fn lock_state(&self) -> std::sync::MutexGuard<'_, HealthState> {
        match self.state.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn health_tracker_lifecycle_and_healthcheck_compatibility() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("health.json");
        let h = HealthTracker::new_at(&path, 1000.0);

        h.poll_fail();
        h.poll_fail();
        assert_eq!(h.snapshot_at(1010.0).poll_failures, 2);
        assert_eq!(h.snapshot_at(1010.0).total_poll_failures, 2);

        h.poll_ok_at(5, 1012.0);
        h.set_getme_ok(1012.0);
        h.set_mode("webhook");
        h.set_proxy_state(
            Some("socks5://user:secret_pass@10.0.0.1:1080"),
            Some(serde_json::json!({"active_latency_ms": 42})),
        );
        h.set_cron_jobs(Some(serde_json::json!([{"name": "models_sync", "ok": true}])));
        h.set_rebuilds(Some(1));

        let snap = h.write_at(1015.26).unwrap();
        assert_eq!(snap.mode, "webhook");
        assert_eq!(snap.stall_s, 3.3);
        assert_eq!(snap.poll_failures, 0);
        assert_eq!(snap.total_poll_failures, 2);
        assert_eq!(snap.updates, 5);
        assert_eq!(snap.last_getme_ok, 1012.0);
        assert_eq!(snap.pid, std::process::id());
        assert_eq!(
            snap.proxy_active.as_deref(),
            Some("socks5://[REDACTED]@10.0.0.1:1080")
        );

        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("secret_pass"));
        let parsed: Value = serde_json::from_str(&raw).unwrap();
        // Required keys read by /opt/agy-telegram/healthcheck.sh
        assert_eq!(parsed["ts"], serde_json::json!(1015.26));
        assert_eq!(parsed["stall_s"], serde_json::json!(3.3));
        assert_eq!(parsed["pid"], serde_json::json!(std::process::id()));
        assert_eq!(parsed["mode"], serde_json::json!("webhook"));
        assert_eq!(parsed["last_getme_ok"], serde_json::json!(1012.0));
        assert_eq!(parsed["poll_failures"], serde_json::json!(0));
        assert_eq!(parsed["total_poll_failures"], serde_json::json!(2));
        assert_eq!(parsed["updates"], serde_json::json!(5));
        assert_eq!(parsed["note"], serde_json::json!(""));
        assert!(parsed["proxy_health"].is_object());
        assert!(parsed["cron_jobs"].is_array());
    }

    #[test]
    fn health_tracker_write_with_note_omits_optional_none_fields() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("health.json");
        let h = HealthTracker::new(&path);

        let snap = h.write_with_note("watchdog exit").unwrap();
        assert_eq!(snap.note, "watchdog exit");
        let parsed: Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let obj = parsed.as_object().unwrap();
        assert!(!obj.contains_key("proxy_active"));
        assert!(!obj.contains_key("proxy_health"));
        assert!(!obj.contains_key("cron_jobs"));
        assert!(!obj.contains_key("rebuilds"));
    }

    #[test]
    fn health_tracker_concurrent_writes_stay_valid_json() {
        use std::sync::{Arc, Barrier};

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("health.json");
        let h = Arc::new(HealthTracker::new(&path));
        let barrier = Arc::new(Barrier::new(6));

        let mut handles = Vec::new();
        for idx in 0..6_u64 {
            let hc = Arc::clone(&h);
            let b = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                b.wait();
                hc.poll_fail();
                hc.poll_ok(idx + 1);
                hc.write().unwrap();
            }));
        }
        for handle in handles {
            handle.join().unwrap();
        }

        let snap: HealthSnapshot =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(snap.total_poll_failures, 6);
        assert_eq!(snap.updates, 21);
    }
}
