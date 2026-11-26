//! Scoped Bearer API keys (salted SHA-256, never stored plaintext) & multi-client config generator.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

use agy_core::atomic::atomic_write_json;
use agy_core::error::{BridgeError, Result};
use chrono::Utc;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::config::SectionId;

/// Prefix of every generated API key (makes detection in secret scanners deterministic).
pub const API_KEY_PREFIX: &str = "agymcp_";

/// Preset access profiles for quick key provisioning in Telegram `/mcpgw`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyPreset {
    /// Read-only search, SkillHub, memory read, codeintel read, optimizer.
    ReadOnly,
    /// Search-v3 + SkillHub + Memory + CodeIntel + Optimizer + Sessions (no exec/models write).
    Research,
    /// Full coding developer: OpenHands + Search + SkillHub + Memory + CodeIntel + Models + Sessions + Optimizer.
    Developer,
    /// Full Owner key with all 9 sections, admin actions, and higher budgets.
    Owner,
}

impl KeyPreset {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReadOnly => "read_only",
            Self::Research => "research",
            Self::Developer => "developer",
            Self::Owner => "owner",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "read_only" | "readonly" | "ro" => Some(Self::ReadOnly),
            "research" | "res" => Some(Self::Research),
            "developer" | "dev" => Some(Self::Developer),
            "owner" | "full" | "admin" => Some(Self::Owner),
            _ => None,
        }
    }

    pub fn default_sections(self) -> BTreeSet<SectionId> {
        use SectionId::*;
        match self {
            Self::ReadOnly => [Search, Skillhub, Memory, Codeintel, Optimizer, Browser]
                .into_iter()
                .collect(),
            Self::Research => [Search, Skillhub, Memory, Codeintel, Sessions, Optimizer, Browser]
                .into_iter()
                .collect(),
            Self::Developer => [
                Openhands, Search, Skillhub, Memory, Codeintel, Models, Sessions, Optimizer, Browser,
            ]
            .into_iter()
            .collect(),
            Self::Owner => SectionId::ALL.into_iter().collect(),
        }
    }

    pub fn allow_write(self) -> bool {
        matches!(self, Self::Research | Self::Developer | Self::Owner)
    }

    pub fn allow_exec(self) -> bool {
        matches!(self, Self::Developer | Self::Owner)
    }

    pub fn allow_models_run(self) -> bool {
        matches!(self, Self::Developer | Self::Owner)
    }

    pub fn is_owner_level(self) -> bool {
        matches!(self, Self::Owner)
    }
}

/// Persisted API key record (secret is stored ONLY as salted SHA-256 hex digest).
#[derive(Clone, Serialize, Deserialize)]
pub struct KeyRecord {
    pub id: String,
    pub label: String,
    pub preset: KeyPreset,
    /// Non-secret visual prefix (`agymcp_a1b2c3d4...`) for identification in `/mcpgw`.
    pub key_hint: String,
    pub salt_hex: String,
    pub hash_hex: String,
    pub sections: BTreeSet<SectionId>,
    pub allow_write: bool,
    pub allow_exec: bool,
    pub allow_models_run: bool,
    pub allow_root_access: bool,
    pub is_owner: bool,
    pub enabled: bool,
    /// Optional per-key RPM override (`None` = global `limits.key_rpm`).
    #[serde(default)]
    pub rpm_override: Option<u32>,
    /// Optional daily AI model calls cap (`None` = global default; `Some(0)` = unlimited).
    #[serde(default)]
    pub daily_ai_cap: Option<u32>,
    pub created_at: i64,
    #[serde(default)]
    pub expires_at: Option<i64>,
    #[serde(default)]
    pub last_used_at: Option<i64>,
    #[serde(default)]
    pub total_calls: u64,
}

impl std::fmt::Debug for KeyRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyRecord")
            .field("id", &self.id)
            .field("label", &self.label)
            .field("preset", &self.preset)
            .field("key_hint", &self.key_hint)
            .field("enabled", &self.enabled)
            .field("is_owner", &self.is_owner)
            .finish()
    }
}

/// Authenticated caller identity attached to every verified MCP request.
#[derive(Debug, Clone)]
pub struct AuthenticatedPrincipal {
    pub principal_id: String,
    pub label: String,
    pub auth_kind: AuthKind,
    pub sections: BTreeSet<SectionId>,
    pub allow_write: bool,
    pub allow_exec: bool,
    pub allow_models_run: bool,
    pub allow_root_access: bool,
    pub is_owner: bool,
    pub rpm_override: Option<u32>,
    pub daily_ai_cap: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthKind {
    ApiKey,
    OAuth2,
}

impl AuthenticatedPrincipal {
    pub fn from_key(rec: &KeyRecord) -> Self {
        Self {
            principal_id: format!("key:{}", rec.id),
            label: rec.label.clone(),
            auth_kind: AuthKind::ApiKey,
            sections: rec.sections.clone(),
            allow_write: rec.allow_write,
            allow_exec: rec.allow_exec,
            allow_models_run: rec.allow_models_run,
            allow_root_access: rec.allow_root_access,
            is_owner: rec.is_owner,
            rpm_override: rec.rpm_override,
            daily_ai_cap: rec.daily_ai_cap,
        }
    }

    pub fn has_section(&self, sec: SectionId) -> bool {
        self.sections.contains(&sec)
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct KeyStoreFile {
    #[serde(default)]
    keys: Vec<KeyRecord>,
}

fn random_hex(n_bytes: usize) -> String {
    let mut buf = vec![0u8; n_bytes];
    rand::thread_rng().fill_bytes(&mut buf);
    hex::encode(buf)
}

pub fn hash_secret(salt_hex: &str, raw_secret: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(salt_hex.as_bytes());
    hasher.update(b":");
    hasher.update(raw_secret.as_bytes());
    hex::encode(hasher.finalize())
}

fn constant_time_hex_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

/// Thread-safe store for scoped MCP API keys (`$STATE_DIR/mcp_gateway_keys.json`, `0600`).
pub struct KeyStore {
    path: PathBuf,
    inner: RwLock<Vec<KeyRecord>>,
}

impl KeyStore {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let keys = if path.exists() {
            let raw = std::fs::read_to_string(&path).map_err(|e| {
                BridgeError::io(format!("reading key store {}", path.display()), e)
            })?;
            serde_json::from_str::<KeyStoreFile>(&raw)
                .map(|f| f.keys)
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        Ok(Self {
            path,
            inner: RwLock::new(keys),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn save_locked(&self, keys: &[KeyRecord]) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        atomic_write_json(
            &self.path,
            &KeyStoreFile {
                keys: keys.to_vec(),
            },
            true,
        )
    }

    pub fn list(&self) -> Vec<KeyRecord> {
        self.inner
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub fn get(&self, id: &str) -> Option<KeyRecord> {
        self.inner
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .find(|k| k.id == id)
            .cloned()
    }

    /// Create a new scoped API key and return `(KeyRecord, raw_plaintext_secret_once)`.
    pub fn create_key(
        &self,
        label: impl Into<String>,
        preset: KeyPreset,
        expires_in_days: Option<u32>,
    ) -> Result<(KeyRecord, String)> {
        let clean_label: String = label
            .into()
            .trim()
            .chars()
            .take(48)
            .collect();
        let label = if clean_label.is_empty() {
            format!("client-{}", &random_hex(2))
        } else {
            clean_label
        };

        let id = random_hex(4);
        let secret_body = random_hex(24);
        let raw_key = format!("{API_KEY_PREFIX}{id}_{secret_body}");
        let salt_hex = random_hex(16);
        let hash_hex = hash_secret(&salt_hex, &raw_key);
        let now = Utc::now().timestamp();
        let expires_at = expires_in_days.map(|d| now + i64::from(d) * 86_400);

        let rec = KeyRecord {
            id: id.clone(),
            label,
            preset,
            key_hint: format!("{API_KEY_PREFIX}{id}_••••"),
            salt_hex,
            hash_hex,
            sections: preset.default_sections(),
            allow_write: preset.allow_write(),
            allow_exec: preset.allow_exec(),
            allow_models_run: preset.allow_models_run(),
            allow_root_access: false,
            is_owner: preset.is_owner_level(),
            enabled: true,
            rpm_override: None,
            daily_ai_cap: if preset.is_owner_level() {
                Some(0)
            } else {
                None
            },
            created_at: now,
            expires_at,
            last_used_at: None,
            total_calls: 0,
        };

        let mut guard = self.inner.write().unwrap_or_else(|e| e.into_inner());
        guard.push(rec.clone());
        self.save_locked(&guard)?;
        Ok((rec, raw_key))
    }

    /// Verify a raw `Bearer` token in constant time and update usage telemetry.
    pub fn verify_bearer(&self, raw_token: &str) -> Option<AuthenticatedPrincipal> {
        let trimmed = raw_token.trim();
        if !trimmed.starts_with(API_KEY_PREFIX) {
            return None;
        }
        let now = Utc::now().timestamp();
        let mut matched: Option<AuthenticatedPrincipal> = None;
        let mut need_save = false;

        {
            let mut guard = self.inner.write().unwrap_or_else(|e| e.into_inner());
            for rec in guard.iter_mut() {
                let candidate = hash_secret(&rec.salt_hex, trimmed);
                if constant_time_hex_eq(&rec.hash_hex, &candidate) {
                    if !rec.enabled {
                        return None;
                    }
                    if let Some(exp) = rec.expires_at {
                        if now > exp {
                            return None;
                        }
                    }
                    let prev_ts = rec.last_used_at.unwrap_or(0);
                    rec.last_used_at = Some(now);
                    rec.total_calls = rec.total_calls.saturating_add(1);
                    if now.saturating_sub(prev_ts) >= 60 {
                        need_save = true;
                    }
                    matched = Some(AuthenticatedPrincipal::from_key(rec));
                    break;
                }
            }
            if need_save {
                let _ = self.save_locked(&guard);
            }
        }
        matched
    }

    pub fn set_enabled(&self, id: &str, enabled: bool) -> Result<bool> {
        let mut guard = self.inner.write().unwrap_or_else(|e| e.into_inner());
        let Some(rec) = guard.iter_mut().find(|k| k.id == id) else {
            return Ok(false);
        };
        rec.enabled = enabled;
        self.save_locked(&guard)?;
        Ok(true)
    }

    pub fn toggle_section(&self, id: &str, sec: SectionId) -> Result<Option<bool>> {
        let mut guard = self.inner.write().unwrap_or_else(|e| e.into_inner());
        let Some(rec) = guard.iter_mut().find(|k| k.id == id) else {
            return Ok(None);
        };
        let now_on = if rec.sections.contains(&sec) {
            rec.sections.remove(&sec);
            false
        } else {
            rec.sections.insert(sec);
            true
        };
        self.save_locked(&guard)?;
        Ok(Some(now_on))
    }

    pub fn revoke(&self, id: &str) -> Result<bool> {
        let mut guard = self.inner.write().unwrap_or_else(|e| e.into_inner());
        let before = guard.len();
        guard.retain(|k| k.id != id);
        if guard.len() == before {
            return Ok(false);
        }
        self.save_locked(&guard)?;
        Ok(true)
    }

    /// Rotate an existing key's secret in-place while preserving ID, label, and scopes.
    pub fn rotate(&self, id: &str) -> Result<Option<(KeyRecord, String)>> {
        let mut guard = self.inner.write().unwrap_or_else(|e| e.into_inner());
        let Some(rec) = guard.iter_mut().find(|k| k.id == id) else {
            return Ok(None);
        };
        let secret_body = random_hex(24);
        let raw_key = format!("{API_KEY_PREFIX}{}_{secret_body}", rec.id);
        let salt_hex = random_hex(16);
        rec.hash_hex = hash_secret(&salt_hex, &raw_key);
        rec.salt_hex = salt_hex;
        rec.enabled = true;
        let cloned = rec.clone();
        self.save_locked(&guard)?;
        Ok(Some((cloned, raw_key)))
    }
}

/// Ready-to-paste configurations for major global MCP clients.
#[derive(Debug, Clone)]
pub struct ClientConfigSnippets {
    pub vscode_mcp_json: String,
    pub claude_code_cmd: String,
    pub claude_web_url: String,
    pub gemini_cli_json: String,
    pub grok_api_json: String,
    pub grok_cli_toml: String,
}

/// Generate copy-ready configurations for VS Code, Claude, Gemini CLI, Grok API/CLI, and Cursor.
pub fn render_client_configs(
    primary_domain: &str,
    cdn_domain: &str,
    endpoint_path: &str,
    raw_token_or_placeholder: &str,
) -> ClientConfigSnippets {
    let path = if endpoint_path.starts_with('/') {
        endpoint_path
    } else {
        "/mcp"
    };
    let direct_url = format!("https://{primary_domain}{path}");
    let cdn_url = format!("https://{cdn_domain}{path}");

    let vscode_mcp_json = serde_json::to_string_pretty(&serde_json::json!({
        "servers": {
            "agy-hub": {
                "type": "http",
                "url": direct_url,
                "headers": {
                    "Authorization": format!("Bearer {raw_token_or_placeholder}")
                }
            }
        }
    }))
    .unwrap_or_default();

    let claude_code_cmd = format!(
        "claude mcp add --transport http agy-hub {direct_url} --header \"Authorization: Bearer {raw_token_or_placeholder}\""
    );

    let claude_web_url = format!("{cdn_url}  (OAuth 2.1 auto-discovery)");

    let gemini_cli_json = serde_json::to_string_pretty(&serde_json::json!({
        "mcpServers": {
            "agy-hub": {
                "httpUrl": direct_url,
                "headers": {
                    "Authorization": format!("Bearer {raw_token_or_placeholder}")
                }
            }
        }
    }))
    .unwrap_or_default();

    let grok_api_json = serde_json::to_string_pretty(&serde_json::json!({
        "type": "mcp",
        "server_url": direct_url,
        "server_label": "agy_hub",
        "server_description": "AGY Bot Unified MCP Gateway (OpenHands, Search-v3, SkillHub, Memory, Models, Optimizer)",
        "authorization": format!("Bearer {raw_token_or_placeholder}")
    }))
    .unwrap_or_default();

    let grok_cli_toml = format!(
        "[mcp_servers.agy_hub]\nurl = \"{direct_url}\"\nheaders = {{ Authorization = \"Bearer {raw_token_or_placeholder}\" }}"
    );

    ClientConfigSnippets {
        vscode_mcp_json,
        claude_code_cmd,
        claude_web_url,
        gemini_cli_json,
        grok_api_json,
        grok_cli_toml,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn key_store_hashes_verifies_rotates_and_never_leaks_plaintext() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("keys.json");
        let store = KeyStore::open(&path).unwrap();

        let (rec, raw) = store
            .create_key("vscode-laptop", KeyPreset::Developer, Some(30))
            .unwrap();
        assert!(raw.starts_with(API_KEY_PREFIX));
        assert!(!rec.is_owner);
        assert!(rec.allow_exec);

        // Plaintext secret MUST NOT appear on disk or in Debug output
        let disk = std::fs::read_to_string(&path).unwrap();
        assert!(!disk.contains(&raw));
        assert!(!format!("{rec:?}").contains(&raw));

        // Valid verification succeeds
        let princ = store.verify_bearer(&raw).expect("valid key should verify");
        assert_eq!(princ.label, "vscode-laptop");
        assert!(princ.has_section(SectionId::Openhands));

        // Wrong token fails
        assert!(store.verify_bearer("agymcp_wrong_secret").is_none());

        // Disabled key fails
        store.set_enabled(&rec.id, false).unwrap();
        assert!(store.verify_bearer(&raw).is_none());

        // Rotation invalidates old token and validates new token
        let (_rot, new_raw) = store.rotate(&rec.id).unwrap().unwrap();
        assert_ne!(raw, new_raw);
        assert!(store.verify_bearer(&raw).is_none());
        assert!(store.verify_bearer(&new_raw).is_some());

        // Revoke removes key
        assert!(store.revoke(&rec.id).unwrap());
        assert!(store.verify_bearer(&new_raw).is_none());
    }
}
