//! AWS full-jitter backoff and thread-safe persistent outgoing message queue (`outqueue.json`).

use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tracing::warn;

use crate::atomic::atomic_write_json;
use crate::error::{BridgeError, Result};

/// Default outbox TTL (6 hours, matching Python `OutQueue.max_age = 6 * 3600`).
pub const DEFAULT_MAX_AGE_SECS: f64 = 6.0 * 3600.0;

fn now_secs() -> f64 {
    crate::text::now_secs()
}

/// AWS "full jitter": `uniform(0, min(cap_secs, base_secs * 2^attempt))`.
pub fn full_jitter(attempt: u32, base_secs: f64, cap_secs: f64) -> f64 {
    let mut rng = rand::thread_rng();
    full_jitter_with(attempt, base_secs, cap_secs, &mut rng)
}

/// Deterministic/testable full-jitter helper accepting an explicit `Rng`.
pub fn full_jitter_with<R: Rng + ?Sized>(
    attempt: u32,
    base_secs: f64,
    cap_secs: f64,
    rng: &mut R,
) -> f64 {
    if !base_secs.is_finite() || !cap_secs.is_finite() || base_secs <= 0.0 || cap_secs <= 0.0 {
        return 0.0;
    }
    let exp = if attempt >= 63 {
        f64::INFINITY
    } else {
        (1_u64 << attempt) as f64
    };
    let upper = (base_secs * exp).min(cap_secs);
    if !upper.is_finite() || upper <= 0.0 {
        return 0.0;
    }
    rng.gen::<f64>() * upper
}

/// Computes the default SHA-256 dedupe key `{chat}:{sha256_hex}` for an outbox payload.
pub fn dedupe_key(chat: i64, text: &str) -> String {
    let digest = Sha256::digest(text.as_bytes());
    format!("{chat}:{}", hex::encode(digest))
}

/// Single queued outgoing message matching Python `outqueue.json` item schema.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OutboxItem {
    pub key: String,
    pub chat: i64,
    pub text: String,
    #[serde(default)]
    pub markup: Option<String>,
    pub ts: f64,
    #[serde(default)]
    pub tries: u32,
    #[serde(default)]
    pub next: f64,
}

/// Thread-safe persistent outgoing delivery queue with dedupe, TTL expiry, and atomic `0o600` save.
pub struct OutQueue {
    path: PathBuf,
    max_age_secs: f64,
    items: Mutex<Vec<OutboxItem>>,
}

impl OutQueue {
    /// Opens `outqueue.json` with the default 6-hour TTL, recovering cleanly on corrupt JSON.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self> {
        Self::open_with_max_age(path, DEFAULT_MAX_AGE_SECS)
    }

    /// Opens `outqueue.json` with a custom maximum item age in seconds.
    pub fn open_with_max_age(path: impl Into<PathBuf>, max_age_secs: f64) -> Result<Self> {
        let path = path.into();
        let items = load_items(&path)?;
        Ok(Self {
            path,
            max_age_secs,
            items: Mutex::new(items),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn max_age_secs(&self) -> f64 {
        self.max_age_secs
    }

    /// Enqueues a message for later retry, deduplicating by `key` (or `{chat}:{sha256(text)}`).
    pub fn push(
        &self,
        chat: i64,
        text: impl Into<String>,
        markup: Option<String>,
        key: Option<String>,
    ) -> Result<String> {
        self.push_at(chat, text, markup, key, now_secs())
    }

    /// Deterministic timestamp variant of [`Self::push`].
    pub fn push_at(
        &self,
        chat: i64,
        text: impl Into<String>,
        markup: Option<String>,
        key: Option<String>,
        now: f64,
    ) -> Result<String> {
        let text = text.into();
        let resolved_key = match key {
            Some(k) if !k.is_empty() => k,
            _ => dedupe_key(chat, &text),
        };

        let mut guard = self
            .items
            .lock()
            .map_err(|e| BridgeError::Internal(format!("outbox lock poisoned: {e}")))?;

        if guard.iter().any(|i| i.key == resolved_key) {
            return Ok(resolved_key);
        }

        guard.push(OutboxItem {
            key: resolved_key.clone(),
            chat,
            text,
            markup,
            ts: now,
            tries: 0,
            next: now,
        });
        atomic_write_json(&self.path, &*guard, false)?;
        Ok(resolved_key)
    }

    /// Prunes expired entries (`now - ts >= max_age_secs`) and returns items currently due (`next <= now`).
    pub fn due(&self) -> Result<Vec<OutboxItem>> {
        self.due_at(now_secs())
    }

    /// Deterministic timestamp variant of [`Self::due`].
    pub fn due_at(&self, now: f64) -> Result<Vec<OutboxItem>> {
        let mut guard = self
            .items
            .lock()
            .map_err(|e| BridgeError::Internal(format!("outbox lock poisoned: {e}")))?;

        let before = guard.len();
        guard.retain(|i| (now - i.ts) < self.max_age_secs);
        if guard.len() != before {
            atomic_write_json(&self.path, &*guard, false)?;
        }

        Ok(guard
            .iter()
            .filter(|i| i.next <= now)
            .cloned()
            .collect())
    }

    /// Marks `key` delivered and removes it from persistent storage.
    pub fn done(&self, key: &str) -> Result<bool> {
        let mut guard = self
            .items
            .lock()
            .map_err(|e| BridgeError::Internal(format!("outbox lock poisoned: {e}")))?;
        let before = guard.len();
        guard.retain(|i| i.key != key);
        let removed = guard.len() != before;
        if removed {
            atomic_write_json(&self.path, &*guard, false)?;
        }
        Ok(removed)
    }

    /// Records a failed delivery attempt for `key` and schedules exponential full-jitter backoff.
    pub fn failed(&self, key: &str) -> Result<bool> {
        self.failed_at(key, now_secs())
    }

    /// Deterministic timestamp variant of [`Self::failed`].
    pub fn failed_at(&self, key: &str, now: f64) -> Result<bool> {
        let mut guard = self
            .items
            .lock()
            .map_err(|e| BridgeError::Internal(format!("outbox lock poisoned: {e}")))?;
        let mut updated = false;
        for item in guard.iter_mut() {
            if item.key == key {
                item.tries = item.tries.saturating_add(1);
                item.next = now + 2.0 + full_jitter(item.tries, 2.0, 300.0);
                updated = true;
            }
        }
        if updated {
            atomic_write_json(&self.path, &*guard, false)?;
        }
        Ok(updated)
    }

    /// Attempts delivery of all due items via `sender`, never holding the mutex across `.await`.
    /// Returns `(delivered_count, failed_count)`.
    pub async fn drain<F, Fut>(&self, mut sender: F) -> Result<(usize, usize)>
    where
        F: FnMut(OutboxItem) -> Fut,
        Fut: Future<Output = bool>,
    {
        let due_items = self.due()?;
        let mut ok_count = 0usize;
        let mut fail_count = 0usize;
        for item in due_items {
            if sender(item.clone()).await {
                self.done(&item.key)?;
                ok_count += 1;
            } else {
                self.failed(&item.key)?;
                fail_count += 1;
            }
        }
        Ok((ok_count, fail_count))
    }

    pub fn len(&self) -> usize {
        match self.items.lock() {
            Ok(g) => g.len(),
            Err(p) => p.into_inner().len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn items(&self) -> Vec<OutboxItem> {
        match self.items.lock() {
            Ok(g) => g.clone(),
            Err(p) => p.into_inner().clone(),
        }
    }
}

fn load_items(path: &Path) -> Result<Vec<OutboxItem>> {
    let raw = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(BridgeError::io(format!("read {}", path.display()), e)),
    };

    let val: Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(e) => {
            warn!(path = %path.display(), error = %e, "corrupt outqueue.json; recovering empty queue");
            return Ok(Vec::new());
        }
    };

    let Some(arr) = val.as_array() else {
        warn!(path = %path.display(), "outqueue.json root is not an array; recovering empty queue");
        return Ok(Vec::new());
    };

    let mut out = Vec::with_capacity(arr.len());
    for (idx, elem) in arr.iter().enumerate() {
        match serde_json::from_value::<OutboxItem>(elem.clone()) {
            Ok(item) => out.push(item),
            Err(e) => {
                warn!(path = %path.display(), index = idx, error = %e, "skipping malformed outbox item");
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::mock::StepRng;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    #[test]
    fn full_jitter_bounds_and_edge_cases() {
        for attempt in 0..12_u32 {
            let cap = 30.0_f64.min((1_u64 << attempt) as f64);
            for _ in 0..200 {
                let d = full_jitter(attempt, 1.0, 30.0);
                assert!((0.0..=cap).contains(&d));
            }
        }

        // Huge attempt does not overflow or produce NaN
        let mut max_rng = StepRng::new(u64::MAX, 0);
        let d_huge = full_jitter_with(500, 1.0, 30.0, &mut max_rng);
        assert!(d_huge.is_finite() && (0.0..=30.0).contains(&d_huge));

        // Zero / negative / non-finite base or cap -> 0.0
        assert_eq!(full_jitter(3, 0.0, 30.0), 0.0);
        assert_eq!(full_jitter(3, -1.0, 30.0), 0.0);
        assert_eq!(full_jitter(3, 1.0, 0.0), 0.0);
        assert_eq!(full_jitter(3, f64::NAN, 30.0), 0.0);
    }

    #[test]
    fn outbox_persist_dedupe_expiry_and_backoff() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("outqueue.json");
        let q = OutQueue::open(&path).unwrap();

        let k1 = q.push_at(100, "hello", None, None, 1000.0).unwrap();
        assert!(k1.starts_with("100:"));
        assert_eq!(k1.len(), 4 + 64); // "100:" + sha256 hex

        // Duplicate payload returns same key without duplicating
        let k2 = q.push_at(100, "hello", None, None, 1001.0).unwrap();
        assert_eq!(k1, k2);
        assert_eq!(q.len(), 1);

        // Mode 0600 on disk
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        // Survives reload
        let q2 = OutQueue::open(&path).unwrap();
        assert_eq!(q2.len(), 1);
        assert_eq!(q2.due_at(1000.0).unwrap().len(), 1);

        // Failed attempt increments tries and pushes next >= now + 2.0
        assert!(q2.failed_at(&k1, 1005.0).unwrap());
        let item = &q2.items()[0];
        assert_eq!(item.tries, 1);
        assert!(item.next >= 1007.0 && item.next <= 1007.0 + 4.0);

        // Not due before item.next
        assert!(q2.due_at(1006.0).unwrap().is_empty());
        assert_eq!(q2.due_at(1015.0).unwrap().len(), 1);

        // Mark done removes and persists
        assert!(q2.done(&k1).unwrap());
        assert!(!q2.done(&k1).unwrap());
        assert!(q2.is_empty());

        let q3 = OutQueue::open(&path).unwrap();
        assert!(q3.is_empty());

        // Expiry after 6h
        let k_old = q3
            .push_at(200, "old", Some("{\"inline_keyboard\":[]}".into()), None, 100.0)
            .unwrap();
        let k_fresh = q3.push_at(200, "fresh", None, None, 21000.0).unwrap();
        let due = q3.due_at(100.0 + DEFAULT_MAX_AGE_SECS).unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].key, k_fresh);
        assert_eq!(q3.len(), 1);
        assert!(!q3.done(&k_old).unwrap());
    }

    #[test]
    fn corrupt_outqueue_recovers_gracefully() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("outqueue.json");
        std::fs::write(&path, "{{corrupt").unwrap();

        let q = OutQueue::open(&path).unwrap();
        assert!(q.is_empty());
        q.push(1, "recovered", None, None).unwrap();
        assert_eq!(q.len(), 1);
    }

    #[tokio::test]
    async fn async_drain_handles_success_and_failure_without_holding_lock() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("outqueue.json");
        let q = OutQueue::open(&path).unwrap();

        let k_ok = q.push(1, "ok-msg", None, Some("k-ok".into())).unwrap();
        let k_fail = q
            .push(2, "fail-msg", None, Some("k-fail".into()))
            .unwrap();

        let (sent, failed) = q
            .drain(|item| {
                let q_ref = &q;
                async move {
                    // Access queue lock inside sender callback to verify lock is NOT held across await
                    assert!(!q_ref.is_empty());
                    item.key == "k-ok"
                }
            })
            .await
            .unwrap();

        assert_eq!((sent, failed), (1, 1));
        assert_eq!(q.len(), 1);
        assert_eq!(q.items()[0].key, k_fail);
        assert_eq!(q.items()[0].tries, 1);
        assert_ne!(k_ok, k_fail);
    }
}
