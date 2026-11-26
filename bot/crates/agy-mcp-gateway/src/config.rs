//! Persistent configuration store for the AGY Remote MCP Gateway (`mcp_gateway.json`).

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::RwLock;

use agy_core::atomic::atomic_write_json;
use agy_core::error::{BridgeError, Result};
use serde::{Deserialize, Serialize};
use tracing::warn;

/// Default local loopback bind port (isolated from `:8787` WebApp/Webhook).
pub const DEFAULT_MCP_GW_PORT: u16 = 8788;

/// Default primary direct domain (Cloudflare CDN OFF).
pub const DEFAULT_PRIMARY_DOMAIN: &str = "mcp.example.com";

/// Default Cloudflare-proxied domain (CDN ON).
pub const DEFAULT_CDN_DOMAIN: &str = "gateway.example.com";

/// Operational mode of the Remote MCP Gateway (Owner Kill Switch).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GatewayMode {
    /// Full operational mode respecting per-key scopes and policies.
    #[default]
    Active,
    /// Only read-only tools/resources allowed across all keys.
    ReadOnly,
    /// Hard kill switch: all external MCP calls rejected with `503`.
    Disabled,
}

impl GatewayMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::ReadOnly => "read_only",
            Self::Disabled => "disabled",
        }
    }

    pub fn fa_label(self) -> &'static str {
        match self {
            Self::Active => "🟢 فعال",
            Self::ReadOnly => "🟡 فقط خواندنی",
            Self::Disabled => "🔴 خاموش",
        }
    }
}

/// Modular tool sections exposed by the gateway.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SectionId {
    Openhands,
    Search,
    Skillhub,
    Memory,
    Codeintel,
    Models,
    Sessions,
    Optimizer,
    Federation,
    Browser,
}

impl SectionId {
    pub const ALL: [Self; 10] = [
        Self::Openhands,
        Self::Search,
        Self::Skillhub,
        Self::Memory,
        Self::Codeintel,
        Self::Models,
        Self::Sessions,
        Self::Optimizer,
        Self::Federation,
        Self::Browser,
    ];

    pub fn slug(self) -> &'static str {
        match self {
            Self::Openhands => "openhands",
            Self::Search => "search",
            Self::Skillhub => "skillhub",
            Self::Memory => "memory",
            Self::Codeintel => "codeintel",
            Self::Models => "models",
            Self::Sessions => "sessions",
            Self::Optimizer => "optimizer",
            Self::Federation => "federation",
            Self::Browser => "browser",
        }
    }

    pub fn parse_slug(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "openhands" | "oh" | "coding" => Some(Self::Openhands),
            "search" | "search-v3" | "search_v3" => Some(Self::Search),
            "skillhub" | "skills" => Some(Self::Skillhub),
            "memory" | "ai-memory" | "ai_memory" => Some(Self::Memory),
            "codeintel" | "code" | "gortex" | "graphify" => Some(Self::Codeintel),
            "models" | "model" | "ai" => Some(Self::Models),
            "sessions" | "session" => Some(Self::Sessions),
            "optimizer" | "opt" | "tokens" => Some(Self::Optimizer),
            "federation" | "fed" | "mcps" => Some(Self::Federation),
            "browser" | "web" | "moli" | "agent-browser" => Some(Self::Browser),
            _ => None,
        }
    }

    pub fn title(self) -> &'static str {
        match self {
            Self::Openhands => "OpenHands Pro Coding",
            Self::Search => "Search v3 (Web & Dork)",
            Self::Skillhub => "SkillHub + SkillPort + Catalog",
            Self::Memory => "AI Memory & Knowledge Graph",
            Self::Codeintel => "Code Intel (Gortex + Graphify + Context7)",
            Self::Models => "Multi-Model & Switcher (Agy/Grok/Venice)",
            Self::Sessions => "Sessions & Handoff Continuity",
            Self::Optimizer => "Token & Context Optimizers (0-Token)",
            Self::Federation => "Dynamic MCP Federation Proxy",
            Self::Browser => "Browser Automation (Moli + agent-browser)",
        }
    }
}

/// Human-in-the-Loop approval policy for high-risk tools (exec/write/destructive).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskAction {
    Allow,
    #[default]
    AskTelegram,
    Deny,
}

impl RiskAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::AskTelegram => "ask_telegram",
            Self::Deny => "deny",
        }
    }
}

/// Anti-DDoS, rate-limit, and anti-ban guard limits.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RateLimitConfig {
    /// Sustained per-IP requests per minute (`0` = disabled).
    pub ip_rpm: u32,
    /// Sustained per-key requests per minute (`0` = disabled).
    pub key_rpm: u32,
    /// Maximum concurrent in-flight HTTP/MCP requests across all clients.
    pub max_concurrency: usize,
    /// Maximum concurrent upstream AI model runs from MCP (anti-ban protection).
    pub max_mcp_ai_concurrency: usize,
    /// Default daily AI model call cap per non-owner key (`0` = unlimited).
    pub default_daily_ai_cap: u32,
    /// Consecutive 401/403 responses from an IP before auto-banning.
    pub auto_ban_threshold: u32,
    /// Temporary IP auto-ban duration in seconds.
    pub auto_ban_secs: u64,
    /// Maximum JSON-RPC request body size in bytes.
    pub max_body_bytes: usize,
    /// Loop circuit breaker threshold: identical tool+args calls allowed within 30s.
    pub loop_breaker_limit: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            ip_rpm: 120,
            key_rpm: 90,
            max_concurrency: 64,
            max_mcp_ai_concurrency: 2,
            default_daily_ai_cap: 40,
            auto_ban_threshold: 10,
            auto_ban_secs: 900,
            max_body_bytes: 2 * 1024 * 1024,
            loop_breaker_limit: 6,
        }
    }
}

impl RateLimitConfig {
    pub fn sanitized(mut self) -> Self {
        self.ip_rpm = self.ip_rpm.min(6000);
        self.key_rpm = self.key_rpm.min(6000);
        self.max_concurrency = self.max_concurrency.clamp(4, 1024);
        self.max_mcp_ai_concurrency = self.max_mcp_ai_concurrency.clamp(0, 8);
        self.auto_ban_threshold = self.auto_ban_threshold.clamp(3, 200);
        self.auto_ban_secs = self.auto_ban_secs.clamp(60, 86_400);
        self.max_body_bytes = self.max_body_bytes.clamp(16 * 1024, 16 * 1024 * 1024);
        self.loop_breaker_limit = self.loop_breaker_limit.clamp(2, 50);
        self
    }
}

/// Top-level persisted gateway configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayConfig {
    #[serde(default)]
    pub mode: GatewayMode,
    #[serde(default = "default_port")]
    pub bind_port: u16,
    #[serde(default = "default_primary_domain")]
    pub primary_domain: String,
    #[serde(default = "default_cdn_domain")]
    pub cdn_domain: String,
    /// Enable legacy `/sse` + `/messages` transport alongside Streamable HTTP.
    #[serde(default = "default_true")]
    pub legacy_sse_enabled: bool,
    /// Enable OAuth 2.1 + Dynamic Client Registration endpoints.
    #[serde(default = "default_true")]
    pub oauth_enabled: bool,
    /// Enable SHA-256 manifest pinning against upstream MCP rug-pull attacks.
    #[serde(default = "default_true")]
    pub manifest_pinning_enabled: bool,
    /// High-risk tool action for Owner keys (`allow` with `command_guard` by default).
    #[serde(default = "default_owner_risk")]
    pub owner_high_risk_action: RiskAction,
    /// High-risk tool action for non-owner keys (`ask_telegram` by default).
    #[serde(default = "default_non_owner_risk")]
    pub non_owner_high_risk_action: RiskAction,
    /// Global toggle per section.
    #[serde(default = "default_sections")]
    pub sections_enabled: BTreeMap<SectionId, bool>,
    /// Anti-DDoS & Anti-Ban limits.
    #[serde(default)]
    pub limits: RateLimitConfig,
    /// Optional explicit IP allowlist (empty = allow any non-banned IP).
    #[serde(default)]
    pub ip_allowlist: BTreeSet<String>,
    /// Permanent manually blocked IPs.
    #[serde(default)]
    pub ip_denylist: BTreeSet<String>,
    /// Additional allowed Host header values.
    #[serde(default)]
    pub extra_allowed_hosts: BTreeSet<String>,
}

fn default_port() -> u16 {
    DEFAULT_MCP_GW_PORT
}
fn default_primary_domain() -> String {
    DEFAULT_PRIMARY_DOMAIN.to_string()
}
fn default_cdn_domain() -> String {
    DEFAULT_CDN_DOMAIN.to_string()
}
fn default_true() -> bool {
    true
}
fn default_owner_risk() -> RiskAction {
    RiskAction::Allow
}
fn default_non_owner_risk() -> RiskAction {
    RiskAction::AskTelegram
}
fn default_sections() -> BTreeMap<SectionId, bool> {
    SectionId::ALL.into_iter().map(|s| (s, true)).collect()
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            mode: GatewayMode::Active,
            bind_port: DEFAULT_MCP_GW_PORT,
            primary_domain: DEFAULT_PRIMARY_DOMAIN.to_string(),
            cdn_domain: DEFAULT_CDN_DOMAIN.to_string(),
            legacy_sse_enabled: true,
            oauth_enabled: true,
            manifest_pinning_enabled: true,
            owner_high_risk_action: RiskAction::Allow,
            non_owner_high_risk_action: RiskAction::AskTelegram,
            sections_enabled: default_sections(),
            limits: RateLimitConfig::default(),
            ip_allowlist: BTreeSet::new(),
            ip_denylist: BTreeSet::new(),
            extra_allowed_hosts: BTreeSet::new(),
        }
    }
}

impl GatewayConfig {
    pub fn is_section_enabled(&self, sec: SectionId) -> bool {
        self.sections_enabled.get(&sec).copied().unwrap_or(true)
    }

    pub fn allowed_hosts(&self) -> BTreeSet<String> {
        let mut set = BTreeSet::new();
        for h in [
            self.primary_domain.as_str(),
            self.cdn_domain.as_str(),
            "127.0.0.1",
            "localhost",
            "[::1]",
        ] {
            let clean = h.trim().to_ascii_lowercase();
            if !clean.is_empty() {
                set.insert(clean);
            }
        }
        for h in &self.extra_allowed_hosts {
            let clean = h.trim().to_ascii_lowercase();
            if !clean.is_empty() {
                set.insert(clean);
            }
        }
        set
    }
}

/// Thread-safe JSON-backed gateway configuration store (`0600` atomic persistence).
pub struct GatewayConfigStore {
    path: PathBuf,
    inner: RwLock<GatewayConfig>,
}

impl GatewayConfigStore {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let cfg = if path.exists() {
            let raw = std::fs::read_to_string(&path).map_err(|e| {
                BridgeError::io(format!("reading gateway config {}", path.display()), e)
            })?;
            match serde_json::from_str::<GatewayConfig>(&raw) {
                Ok(mut c) => {
                    c.limits = c.limits.sanitized();
                    for s in SectionId::ALL {
                        c.sections_enabled.entry(s).or_insert(true);
                    }
                    c
                }
                Err(err) => {
                    warn!(error = %err, path = %path.display(), "invalid mcp_gateway.json; using defaults");
                    GatewayConfig::default()
                }
            }
        } else {
            let c = GatewayConfig::default();
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let _ = atomic_write_json(&path, &c, true);
            c
        };
        Ok(Self {
            path,
            inner: RwLock::new(cfg),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn snapshot(&self) -> GatewayConfig {
        self.inner
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub fn update<F, R>(&self, f: F) -> Result<R>
    where
        F: FnOnce(&mut GatewayConfig) -> R,
    {
        let mut guard = self.inner.write().unwrap_or_else(|e| e.into_inner());
        let out = f(&mut guard);
        guard.limits = guard.limits.clone().sanitized();
        atomic_write_json(&self.path, &*guard, true)?;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn config_store_creates_persists_and_sanitizes_bounds() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("mcp_gateway.json");
        let store = GatewayConfigStore::open(&path).unwrap();
        let snap = store.snapshot();
        assert_eq!(snap.bind_port, 8788);
        assert_eq!(snap.mode, GatewayMode::Active);
        assert_eq!(snap.limits.max_mcp_ai_concurrency, 2);
        assert_eq!(snap.owner_high_risk_action, RiskAction::Allow);
        assert_eq!(snap.non_owner_high_risk_action, RiskAction::AskTelegram);
        assert!(snap.legacy_sse_enabled);
        assert!(snap.allowed_hosts().contains("mcp.example.com"));
        assert!(snap.allowed_hosts().contains("gateway.example.com"));

        store
            .update(|c| {
                c.mode = GatewayMode::ReadOnly;
                c.limits.max_mcp_ai_concurrency = 999;
                c.sections_enabled.insert(SectionId::Openhands, false);
            })
            .unwrap();

        let reloaded = GatewayConfigStore::open(&path).unwrap().snapshot();
        assert_eq!(reloaded.mode, GatewayMode::ReadOnly);
        assert_eq!(reloaded.limits.max_mcp_ai_concurrency, 8);
        assert!(!reloaded.is_section_enabled(SectionId::Openhands));
        assert!(reloaded.is_section_enabled(SectionId::Skillhub));
    }
}
