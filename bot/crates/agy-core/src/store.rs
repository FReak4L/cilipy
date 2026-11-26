//! Thread-safe persistent user preferences and session state (`state.json`).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};
use tracing::warn;

use crate::atomic::atomic_write_json;
use crate::error::{BridgeError, Result};

/// Maximum number of recent sessions retained per user (matches Python `hist[:8]`).
pub const MAX_HISTORY_ENTRIES: usize = 8;

/// Maximum character length of a stored session title (matches Python `(job.text or "file")[:40]`).
pub const MAX_HISTORY_TITLE_CHARS: usize = 40;

fn default_true() -> bool {
    true
}

fn default_stream_mode() -> String {
    "semi".to_string()
}

fn default_render() -> String {
    "rich".to_string()
}

fn default_meta() -> Value {
    Value::Object(Map::new())
}

fn de_bool_true<'de, D>(deserializer: D) -> std::result::Result<bool, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(Option::<bool>::deserialize(deserializer)?.unwrap_or(true))
}

fn de_bool_false<'de, D>(deserializer: D) -> std::result::Result<bool, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(Option::<bool>::deserialize(deserializer)?.unwrap_or(false))
}

fn de_stream_mode<'de, D>(deserializer: D) -> std::result::Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(Option::<String>::deserialize(deserializer)?
        .filter(|s| !s.is_empty())
        .unwrap_or_else(default_stream_mode))
}

fn de_render<'de, D>(deserializer: D) -> std::result::Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(Option::<String>::deserialize(deserializer)?
        .filter(|s| !s.is_empty())
        .unwrap_or_else(default_render))
}

fn de_history<'de, D>(deserializer: D) -> std::result::Result<Vec<SessionEntry>, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(Option::<Vec<SessionEntry>>::deserialize(deserializer)?.unwrap_or_default())
}

fn de_i64_flexible<'de, D>(deserializer: D) -> std::result::Result<i64, D::Error>
where
    D: Deserializer<'de>,
{
    match Option::<Value>::deserialize(deserializer)? {
        Some(Value::Number(n)) => {
            if let Some(i) = n.as_i64() {
                Ok(i)
            } else if let Some(u) = n.as_u64() {
                Ok(i64::try_from(u).unwrap_or(i64::MAX))
            } else if let Some(f) = n.as_f64() {
                Ok(f as i64)
            } else {
                Ok(0)
            }
        }
        Some(Value::String(s)) => Ok(s.trim().parse::<i64>().unwrap_or(0)),
        _ => Ok(0),
    }
}

/// Recent conversation summary entry stored in `UserState::history`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionEntry {
    pub id: String,
    #[serde(default)]
    pub title: String,
    #[serde(default, deserialize_with = "de_i64_flexible")]
    pub ts: i64,
}

/// Per-user state matching Python `state.py` + `bot.py` defaults.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UserState {
    #[serde(default)]
    pub conversation_id: Option<String>,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub effort: Option<String>,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default, deserialize_with = "de_bool_false")]
    pub skip_permissions: bool,
    #[serde(default = "default_true", deserialize_with = "de_bool_true")]
    pub stream: bool,
    #[serde(default = "default_stream_mode", deserialize_with = "de_stream_mode")]
    pub stream_mode: String,
    #[serde(default = "default_render", deserialize_with = "de_render")]
    pub render: String,
    #[serde(default, deserialize_with = "de_bool_false")]
    pub trace: bool,
    #[serde(default)]
    pub cwd: Option<String>,
    #[serde(default)]
    pub agent: Option<String>,
    #[serde(default, deserialize_with = "de_history")]
    pub history: Vec<SessionEntry>,
    #[serde(default, flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl Default for UserState {
    fn default() -> Self {
        Self {
            conversation_id: None,
            model: None,
            effort: None,
            mode: None,
            skip_permissions: false,
            stream: true,
            stream_mode: default_stream_mode(),
            render: default_render(),
            trace: false,
            cwd: None,
            agent: None,
            history: Vec::new(),
            extra: BTreeMap::new(),
        }
    }
}

impl UserState {
    /// Updates active `conversation_id` and prepends a deduplicated session entry (capped at 8).
    pub fn push_session(&mut self, conversation_id: impl Into<String>, title: &str, ts: i64) {
        let conv_id = conversation_id.into();
        if conv_id.is_empty() {
            return;
        }
        self.conversation_id = Some(conv_id.clone());
        self.history.retain(|h| h.id != conv_id);
        let clean_title: String = if title.is_empty() {
            "file".to_string()
        } else {
            title.chars().take(MAX_HISTORY_TITLE_CHARS).collect()
        };
        self.history.insert(
            0,
            SessionEntry {
                id: conv_id,
                title: clean_title,
                ts,
            },
        );
        self.history.truncate(MAX_HISTORY_ENTRIES);
    }
}

/// Top-level JSON structure of `state.json`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StateData {
    #[serde(default)]
    pub users: BTreeMap<String, UserState>,
    #[serde(default = "default_meta")]
    pub meta: Value,
}

impl Default for StateData {
    fn default() -> Self {
        Self {
            users: BTreeMap::new(),
            meta: default_meta(),
        }
    }
}

/// Thread-safe JSON-backed store for per-user preferences and global bridge metadata.
pub struct StateStore {
    path: PathBuf,
    inner: RwLock<StateData>,
}

impl StateStore {
    /// Opens `state.json`, recovering gracefully on missing or corrupt JSON without panicking.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let data = load_state_data(&path)?;
        Ok(Self {
            path,
            inner: RwLock::new(data),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns a copy of `uid`'s state (or defaults if not yet persisted).
    pub fn get_user(&self, uid: i64) -> UserState {
        let key = uid.to_string();
        let guard = match self.inner.read() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.users.get(&key).cloned().unwrap_or_default()
    }

    /// Returns whether `uid` already has an entry in `users`.
    pub fn has_user(&self, uid: i64) -> bool {
        let key = uid.to_string();
        let guard = match self.inner.read() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.users.contains_key(&key)
    }

    /// Ensures `uid` exists with defaults, applies `f`, and atomically saves `state.json`.
    pub fn update_user<F, R>(&self, uid: i64, f: F) -> Result<R>
    where
        F: FnOnce(&mut UserState) -> R,
    {
        self.try_update_user(uid, |u| Ok(f(u)))
    }

    /// Ensures `uid` exists with defaults, applies fallible `f`, and atomically saves on `Ok`.
    pub fn try_update_user<F, R>(&self, uid: i64, f: F) -> Result<R>
    where
        F: FnOnce(&mut UserState) -> Result<R>,
    {
        let key = uid.to_string();
        let mut guard = self
            .inner
            .write()
            .map_err(|e| BridgeError::Internal(format!("state store write lock poisoned: {e}")))?;
        let entry = guard.users.entry(key).or_default();
        let out = f(entry)?;
        atomic_write_json(&self.path, &*guard, true)?;
        Ok(out)
    }

    /// Reads a single key from top-level `meta`.
    pub fn meta(&self, key: &str) -> Option<Value> {
        let guard = match self.inner.read() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.meta.as_object().and_then(|m| m.get(key)).cloned()
    }

    /// Returns a cloned copy of the top-level `meta` object.
    pub fn meta_all(&self) -> Value {
        let guard = match self.inner.read() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.meta.clone()
    }

    /// Sets `meta[key] = value` and atomically saves `state.json`.
    pub fn set_meta(&self, key: impl Into<String>, value: Value) -> Result<()> {
        let key = key.into();
        self.update_meta(|map| {
            map.insert(key, value);
        })
    }

    /// Mutates the `meta` JSON object and atomically saves `state.json`.
    pub fn update_meta<F, R>(&self, f: F) -> Result<R>
    where
        F: FnOnce(&mut Map<String, Value>) -> R,
    {
        let mut guard = self
            .inner
            .write()
            .map_err(|e| BridgeError::Internal(format!("state store write lock poisoned: {e}")))?;
        if !guard.meta.is_object() {
            guard.meta = default_meta();
        }
        let map = match guard.meta.as_object_mut() {
            Some(m) => m,
            None => {
                return Err(BridgeError::Internal(
                    "state meta invariant violated".to_string(),
                ))
            }
        };
        let out = f(map);
        atomic_write_json(&self.path, &*guard, true)?;
        Ok(out)
    }

    /// Atomically persists the current in-memory state to disk with mode `0o600`.
    pub fn save(&self) -> Result<()> {
        let guard = self
            .inner
            .read()
            .map_err(|e| BridgeError::Internal(format!("state store read lock poisoned: {e}")))?;
        atomic_write_json(&self.path, &*guard, true)
    }

    /// Returns a consistent snapshot of the entire state store.
    pub fn snapshot(&self) -> StateData {
        let guard = match self.inner.read() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.clone()
    }
}

fn load_state_data(path: &Path) -> Result<StateData> {
    let raw = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(StateData::default()),
        Err(e) => return Err(BridgeError::io(format!("read {}", path.display()), e)),
    };

    let parsed: Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(e) => {
            warn!(path = %path.display(), error = %e, "corrupt state.json; recovering empty state");
            return Ok(StateData::default());
        }
    };

    let Some(obj) = parsed.as_object() else {
        warn!(path = %path.display(), "state.json root is not an object; recovering empty state");
        return Ok(StateData::default());
    };

    let mut data = StateData::default();

    if let Some(raw_users) = obj.get("users").and_then(Value::as_object) {
        for (uid_key, val) in raw_users {
            match serde_json::from_value::<UserState>(val.clone()) {
                Ok(user_state) => {
                    data.users.insert(uid_key.clone(), user_state);
                }
                Err(e) => {
                    warn!(path = %path.display(), uid = %uid_key, error = %e, "skipping malformed user state entry");
                }
            }
        }
    }

    if let Some(meta_obj) = obj.get("meta").and_then(Value::as_object) {
        data.meta = Value::Object(meta_obj.clone());
    }

    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::{Arc, Barrier};
    use tempfile::TempDir;

    #[test]
    fn defaults_and_python_schema_compatibility() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("state.json");

        // Simulate legacy Python state.json missing newer fields (cwd, agent, trace, stream_mode)
        let python_json = serde_json::json!({
            "users": {
                "12345": {
                    "conversation_id": "conv-abc",
                    "model": "gpt-5",
                    "effort": null,
                    "mode": "plan",
                    "skip_permissions": true,
                    "stream": false,
                    "render": "html",
                    "history": [
                        {"id": "conv-abc", "title": "hello", "ts": 1700000000}
                    ]
                }
            },
            "meta": {
                "last_startup_notice": 1700000123.5
            }
        });
        std::fs::write(&path, serde_json::to_string_pretty(&python_json).unwrap()).unwrap();

        let store = StateStore::open(&path).unwrap();
        let u = store.get_user(12345);
        assert_eq!(u.conversation_id.as_deref(), Some("conv-abc"));
        assert_eq!(u.model.as_deref(), Some("gpt-5"));
        assert_eq!(u.effort, None);
        assert_eq!(u.mode.as_deref(), Some("plan"));
        assert!(u.skip_permissions);
        assert!(!u.stream);
        assert_eq!(u.stream_mode, "semi");
        assert_eq!(u.render, "html");
        assert!(!u.trace);
        assert_eq!(u.cwd, None);
        assert_eq!(u.agent, None);
        assert_eq!(u.history.len(), 1);
        assert_eq!(u.history[0].ts, 1_700_000_000);

        let missing = store.get_user(99999);
        assert_eq!(missing, UserState::default());
        assert!(!store.has_user(99999));

        assert_eq!(
            store.meta("last_startup_notice"),
            Some(serde_json::json!(1700000123.5))
        );
    }

    #[test]
    fn update_meta_and_history_persist_atomically_0600() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("state.json");
        let store = StateStore::open(&path).unwrap();

        store
            .update_user(42, |u| {
                u.trace = true;
                u.cwd = Some("/root/agy-workspace".into());
                for i in 0..10 {
                    u.push_session(format!("conv-{i}"), &format!("prompt number {i}"), 100 + i);
                }
                // Re-pushing conv-2 moves it to index 0 without duplication
                u.push_session("conv-2", "updated title", 999);
            })
            .unwrap();

        store
            .set_meta("premium_disabled", serde_json::json!("none"))
            .unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        let reloaded = StateStore::open(&path).unwrap();
        let u = reloaded.get_user(42);
        assert!(u.trace);
        assert_eq!(u.history.len(), 8);
        assert_eq!(u.history[0].id, "conv-2");
        assert_eq!(u.history[0].title, "updated title");
        assert_eq!(u.history[0].ts, 999);
        assert_eq!(
            reloaded.meta("premium_disabled"),
            Some(serde_json::json!("none"))
        );

        // Verify exact Python keys exist in serialized JSON (including nulls)
        let raw: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let u_obj = raw["users"]["42"].as_object().unwrap();
        for key in [
            "conversation_id",
            "model",
            "effort",
            "mode",
            "skip_permissions",
            "stream",
            "stream_mode",
            "render",
            "trace",
            "cwd",
            "agent",
            "history",
        ] {
            assert!(u_obj.contains_key(key), "missing key {key}");
        }
    }

    #[test]
    fn corrupt_json_recovers_without_panicking() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("state.json");
        std::fs::write(&path, "{not valid json").unwrap();

        let store = StateStore::open(&path).unwrap();
        assert_eq!(store.get_user(1), UserState::default());
        assert_eq!(store.meta_all(), serde_json::json!({}));

        store.save().unwrap();
        let raw: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert!(raw["users"].is_object());
        assert!(raw["meta"].is_object());
    }

    #[test]
    fn concurrent_updates_preserve_all_users() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("state.json");
        let store = Arc::new(StateStore::open(&path).unwrap());
        let barrier = Arc::new(Barrier::new(8));

        let mut handles = Vec::new();
        for idx in 0..8_i64 {
            let s = Arc::clone(&store);
            let b = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                b.wait();
                s.update_user(1000 + idx, |u| {
                    u.agent = Some(format!("agent-{idx}"));
                })
                .unwrap();
                s.set_meta(format!("k{idx}"), serde_json::json!(idx)).unwrap();
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        let reloaded = StateStore::open(&path).unwrap();
        for idx in 0..8_i64 {
            assert_eq!(
                reloaded.get_user(1000 + idx).agent.as_deref(),
                Some(format!("agent-{idx}").as_str())
            );
            assert_eq!(reloaded.meta(&format!("k{idx}")), Some(serde_json::json!(idx)));
        }
    }
}
