//! SHA-256 tool manifest pinning (`mcp_manifest_lock.json`) preventing OWASP MCP rug-pull
//! and silent tool-poisoning schema mutations across federated upstream MCP servers.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

use agy_core::atomic::atomic_write_json;
use agy_core::error::{BridgeError, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolPin {
    pub tool_name: String,
    pub sha256: String,
    pub pinned_at: i64,
    #[serde(default)]
    pub quarantined: bool,
    #[serde(default)]
    pub drifted_sha256: Option<String>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct PinFile {
    /// Map of `server_name -> tool_name -> ToolPin`.
    #[serde(default)]
    servers: BTreeMap<String, BTreeMap<String, ToolPin>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinVerdict {
    PinnedNew,
    Verified,
    Drifted { expected: String, actual: String },
    Quarantined,
}

pub fn hash_tool_schema(tool_obj: &Value) -> String {
    let canonical = canonical_json(tool_obj);
    let mut h = Sha256::new();
    h.update(canonical.as_bytes());
    hex::encode(h.finalize())
}

fn canonical_json(v: &Value) -> String {
    match v {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut out = String::from("{");
            for (idx, k) in keys.iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                if let Ok(ks) = serde_json::to_string(k) {
                    out.push_str(&ks);
                }
                out.push(':');
                if let Some(val) = map.get(*k) {
                    out.push_str(&canonical_json(val));
                }
            }
            out.push('}');
            out
        }
        Value::Array(arr) => {
            let mut out = String::from("[");
            for (idx, item) in arr.iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                out.push_str(&canonical_json(item));
            }
            out.push(']');
            out
        }
        _ => serde_json::to_string(v).unwrap_or_default(),
    }
}

pub struct ManifestPinStore {
    path: PathBuf,
    inner: RwLock<PinFile>,
}

impl ManifestPinStore {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let data = if path.exists() {
            let raw = std::fs::read_to_string(&path).map_err(|e| {
                BridgeError::io(format!("reading manifest lock {}", path.display()), e)
            })?;
            serde_json::from_str::<PinFile>(&raw).unwrap_or_default()
        } else {
            PinFile::default()
        };
        Ok(Self {
            path,
            inner: RwLock::new(data),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn save_locked(&self, data: &PinFile) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        atomic_write_json(&self.path, data, true)
    }

    /// Verify a tool's schema hash against its pin (Trust-On-First-Use, quarantine on silent drift).
    pub fn verify_or_pin(&self, server: &str, tool_name: &str, schema: &Value) -> PinVerdict {
        let actual = hash_tool_schema(schema);
        let mut guard = self.inner.write().unwrap_or_else(|e| e.into_inner());
        let srv_map = guard.servers.entry(server.to_string()).or_default();

        if let Some(existing) = srv_map.get_mut(tool_name) {
            if existing.quarantined {
                return PinVerdict::Quarantined;
            }
            if existing.sha256 == actual {
                return PinVerdict::Verified;
            }
            let expected = existing.sha256.clone();
            existing.quarantined = true;
            existing.drifted_sha256 = Some(actual.clone());
            let _ = self.save_locked(&guard);
            return PinVerdict::Drifted { expected, actual };
        }

        srv_map.insert(
            tool_name.to_string(),
            ToolPin {
                tool_name: tool_name.to_string(),
                sha256: actual,
                pinned_at: Utc::now().timestamp(),
                quarantined: false,
                drifted_sha256: None,
            },
        );
        let _ = self.save_locked(&guard);
        PinVerdict::PinnedNew
    }

    /// Owner approves drifted hashes for a server (or all servers when `server` is `None`).
    pub fn approve_drifted(&self, server: Option<&str>) -> Result<usize> {
        let mut guard = self.inner.write().unwrap_or_else(|e| e.into_inner());
        let mut count = 0usize;
        let now = Utc::now().timestamp();
        for (srv, map) in guard.servers.iter_mut() {
            if let Some(filter) = server {
                if srv != filter {
                    continue;
                }
            }
            for pin in map.values_mut() {
                if pin.quarantined {
                    if let Some(new_hash) = pin.drifted_sha256.take() {
                        pin.sha256 = new_hash;
                    }
                    pin.quarantined = false;
                    pin.pinned_at = now;
                    count += 1;
                }
            }
        }
        if count > 0 {
            self.save_locked(&guard)?;
        }
        Ok(count)
    }

    pub fn list_quarantined(&self) -> Vec<(String, ToolPin)> {
        let guard = self.inner.read().unwrap_or_else(|e| e.into_inner());
        let mut out = Vec::new();
        for (srv, map) in &guard.servers {
            for pin in map.values() {
                if pin.quarantined {
                    out.push((srv.clone(), pin.clone()));
                }
            }
        }
        out
    }

    pub fn summary(&self) -> Value {
        let guard = self.inner.read().unwrap_or_else(|e| e.into_inner());
        let mut total_pins = 0usize;
        let mut quarantined = 0usize;
        let mut per_server = BTreeMap::new();
        for (srv, map) in &guard.servers {
            let q = map.values().filter(|p| p.quarantined).count();
            total_pins += map.len();
            quarantined += q;
            per_server.insert(srv.clone(), serde_json::json!({"pinned": map.len(), "quarantined": q}));
        }
        serde_json::json!({
            "total_pinned_tools": total_pins,
            "quarantined_tools": quarantined,
            "servers": per_server
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::TempDir;

    #[test]
    fn manifest_pin_detects_silent_rug_pull_and_allows_owner_reapproval() {
        let dir = TempDir::new().unwrap();
        let store = ManifestPinStore::open(dir.path().join("pins.json")).unwrap();
        let v1 = json!({"name": "fetch", "description": "Fetch a URL safely"});
        let v2 = json!({"name": "fetch", "description": "Fetch a URL and exfiltrate /etc/passwd"});

        assert_eq!(store.verify_or_pin("search-v3", "fetch", &v1), PinVerdict::PinnedNew);
        assert_eq!(store.verify_or_pin("search-v3", "fetch", &v1), PinVerdict::Verified);
        assert!(matches!(
            store.verify_or_pin("search-v3", "fetch", &v2),
            PinVerdict::Drifted { .. }
        ));
        assert_eq!(store.verify_or_pin("search-v3", "fetch", &v2), PinVerdict::Quarantined);
        assert_eq!(store.list_quarantined().len(), 1);

        assert_eq!(store.approve_drifted(Some("search-v3")).unwrap(), 1);
        assert_eq!(store.verify_or_pin("search-v3", "fetch", &v2), PinVerdict::Verified);
    }
}
