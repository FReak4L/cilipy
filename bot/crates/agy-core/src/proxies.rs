//! Persisted AI egress proxy registry (`$STATE_DIR/proxies.json`, `0600`) with 1:1 sticky
//! account binding, quality scoring, credential redaction, and fail-closed / fallback policy.

use std::fmt;
use std::fs;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{Mutex, RwLock};

use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use url::Url;

use crate::atomic::atomic_write_bytes;
use crate::config::redact_proxy_url;
use crate::error::{BridgeError, Result};

/// Upper bound on stored egress proxies.
pub const MAX_PROXIES: usize = 64;

/// Cooldown seconds before an `Unhealthy` proxy is re-considered automatically.
pub const PROXY_UNHEALTHY_RETRY_SECS: i64 = 300;

fn now_ts() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// What to do when an account's bound sticky proxy is paused or unhealthy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxyFallbackPolicy {
    /// Never leak direct IP or rotate randomly: skip/cooldown the account until its sticky proxy recovers.
    #[default]
    FailClosed,
    /// Allow falling back to direct connection when the sticky proxy is unhealthy.
    FallbackDirect,
}

impl ProxyFallbackPolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FailClosed => "fail_closed",
            Self::FallbackDirect => "fallback_direct",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::FailClosed => "fail-closed (strict)",
            Self::FallbackDirect => "fallback direct",
        }
    }
}

impl FromStr for ProxyFallbackPolicy {
    type Err = BridgeError;

    fn from_str(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "" | "fail_closed" | "fail-closed" | "strict" | "closed" => Ok(Self::FailClosed),
            "fallback_direct" | "fallback-direct" | "direct" | "open" => Ok(Self::FallbackDirect),
            other => Err(BridgeError::Config(format!(
                "invalid ACCT_PROXY_FALLBACK '{other}' (expected fail_closed or fallback_direct)"
            ))),
        }
    }
}

/// Health classification for a stored egress proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxyHealthStatus {
    #[default]
    Unknown,
    Healthy,
    Degraded,
    Unhealthy,
}

impl ProxyHealthStatus {
    pub fn icon(self) -> &'static str {
        match self {
            Self::Healthy => "🟢",
            Self::Degraded => "🟡",
            Self::Unhealthy => "🔴",
            Self::Unknown => "⚪",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Degraded => "degraded",
            Self::Unhealthy => "unhealthy",
            Self::Unknown => "untested",
        }
    }
}

/// Persisted health & quality telemetry for a single proxy entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyEntryHealth {
    #[serde(default)]
    pub status: ProxyHealthStatus,
    #[serde(default)]
    pub latency_ms: Option<u64>,
    #[serde(default)]
    pub last_checked_ts: Option<i64>,
    #[serde(default)]
    pub last_ok_ts: Option<i64>,
    #[serde(default)]
    pub last_fail_ts: Option<i64>,
    #[serde(default)]
    pub consecutive_failures: u32,
    #[serde(default)]
    pub total_checks: u64,
    #[serde(default)]
    pub total_ok: u64,
    #[serde(default)]
    pub total_fail: u64,
    #[serde(default = "default_initial_score")]
    pub quality_score: u8,
    #[serde(default)]
    pub last_error: Option<String>,
}

fn default_initial_score() -> u8 {
    70
}

impl Default for ProxyEntryHealth {
    fn default() -> Self {
        Self {
            status: ProxyHealthStatus::Unknown,
            latency_ms: None,
            last_checked_ts: None,
            last_ok_ts: None,
            last_fail_ts: None,
            consecutive_failures: 0,
            total_checks: 0,
            total_ok: 0,
            total_fail: 0,
            quality_score: default_initial_score(),
            last_error: None,
        }
    }
}

impl ProxyEntryHealth {
    /// Deterministic quality score `0..=100` from success ratio, latency, and failure streak.
    pub fn recompute_score(&mut self) {
        if self.total_checks == 0 {
            self.quality_score = default_initial_score();
            return;
        }
        let ratio = (self.total_ok as f64) / (self.total_checks as f64);
        let base = ratio * 70.0;
        let lat_bonus = match self.latency_ms {
            Some(ms) if ms <= 150 => 30.0,
            Some(ms) if ms <= 400 => 24.0,
            Some(ms) if ms <= 800 => 16.0,
            Some(ms) if ms <= 1500 => 8.0,
            Some(_) => 2.0,
            None => 10.0,
        };
        let penalty = (self.consecutive_failures.min(5) as f64) * 22.0;
        let raw = (base + lat_bonus - penalty).round().clamp(0.0, 100.0);
        self.quality_score = raw as u8;
    }
}

/// Single persisted egress proxy entry with credential-safe Debug formatting.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyEntry {
    pub id: String,
    #[serde(default)]
    pub label: String,
    pub url: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub created_ts: i64,
    #[serde(default)]
    pub health: ProxyEntryHealth,
}

fn default_true() -> bool {
    true
}

impl fmt::Debug for ProxyEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxyEntry")
            .field("id", &self.id)
            .field("label", &self.label)
            .field("url", &self.safe_label())
            .field("enabled", &self.enabled)
            .field("health", &self.health)
            .finish()
    }
}

impl ProxyEntry {
    /// Credential-redacted URL safe for logs, UI, and health reports.
    pub fn safe_label(&self) -> String {
        redact_proxy_url(&self.url)
    }

    pub fn scheme(&self) -> &str {
        self.url.split("://").next().unwrap_or("proxy")
    }

    /// Compact display title (`px1 · Frankfurt`).
    pub fn display_name(&self) -> String {
        let l = self.label.trim();
        if l.is_empty() || l == self.id {
            format!("{} · {}", self.id, self.safe_label())
        } else {
            format!("{} · {}", self.id, l)
        }
    }

    /// True if enabled and either healthy/degraded/untested or past unhealthy retry cooldown.
    pub fn usable_at(&self, now: i64) -> bool {
        if !self.enabled {
            return false;
        }
        match self.health.status {
            ProxyHealthStatus::Healthy | ProxyHealthStatus::Degraded | ProxyHealthStatus::Unknown => true,
            ProxyHealthStatus::Unhealthy => self
                .health
                .last_fail_ts
                .is_none_or(|t| now.saturating_sub(t) >= PROXY_UNHEALTHY_RETRY_SECS),
        }
    }

    /// Redact this proxy's raw URL and embedded credentials from arbitrary text.
    pub fn redact_text(&self, input: &str) -> String {
        let safe = self.safe_label();
        let mut out = input.replace(&self.url, &safe);
        let no_slash = self.url.trim_end_matches('/');
        if !no_slash.is_empty() && out.contains(no_slash) {
            out = out.replace(no_slash, &safe);
        }
        if let Ok(parsed) = Url::parse(&self.url) {
            let user = parsed.username();
            if let Some(pass) = parsed.password() {
                if !user.is_empty() {
                    let pair = format!("{user}:{pass}@");
                    if out.contains(&pair) {
                        out = out.replace(&pair, "***@");
                    }
                }
                if pass.len() >= 4 && out.contains(pass) {
                    out = out.replace(pass, "***");
                }
            }
            if user.len() >= 4 && out.contains(user) {
                out = out.replace(user, "***");
            }
        }
        out
    }
}

/// Validate a proxy URL (`http`, `https`, `socks5`, `socks5h`) and derive a default safe host label.
pub fn validate_proxy_url(raw: &str) -> Result<(String, String)> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(BridgeError::Validation("proxy URL must not be empty".into()));
    }
    if trimmed.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(BridgeError::Validation(
            "proxy URL must not contain whitespace or control characters".into(),
        ));
    }
    let parsed = Url::parse(trimmed)
        .map_err(|e| BridgeError::Validation(format!("invalid proxy URL: {e}")))?;
    match parsed.scheme().to_ascii_lowercase().as_str() {
        "http" | "https" | "socks5" | "socks5h" => {}
        other => {
            return Err(BridgeError::Validation(format!(
                "unsupported proxy scheme '{other}' (use http, https, socks5, or socks5h)"
            )));
        }
    }
    let host = parsed
        .host_str()
        .filter(|h| !h.is_empty())
        .ok_or_else(|| BridgeError::Validation("proxy URL is missing a host".into()))?;
    let default_label = match parsed.port() {
        Some(p) => format!("{host}:{p}"),
        None => host.to_string(),
    };
    Ok((parsed.to_string(), default_label))
}

/// Outcome of resolving a sticky proxy binding for an account or engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedProxy {
    /// No proxy bound — use direct connection.
    Direct,
    /// Bound sticky proxy is usable — route exclusively through `url`.
    Use {
        id: String,
        safe_label: String,
        url: String,
    },
    /// Bound sticky proxy is paused/unhealthy and policy is `FailClosed` — do NOT leak direct IP.
    Blocked {
        id: String,
        safe_label: String,
        reason: String,
    },
    /// Bound sticky proxy is paused/unhealthy and policy is `FallbackDirect`.
    DirectFallback {
        id: String,
        safe_label: String,
        reason: String,
    },
}

impl ResolvedProxy {
    pub fn url(&self) -> Option<&str> {
        match self {
            Self::Use { url, .. } => Some(url.as_str()),
            _ => None,
        }
    }

    pub fn is_blocked(&self) -> bool {
        matches!(self, Self::Blocked { .. })
    }
}

/// Persisted JSON root (`$STATE_DIR/proxies.json`, `0600`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxiesData {
    #[serde(default)]
    pub proxies: Vec<ProxyEntry>,
    #[serde(default)]
    pub next_seq: u32,
    #[serde(default)]
    pub fallback_policy: ProxyFallbackPolicy,
    #[serde(default)]
    pub fallback_customized: bool,
    /// Optional sticky proxy ID bound to Grok Subscription OAuth.
    #[serde(default)]
    pub grok_proxy_id: Option<String>,
}

/// Thread-safe persisted egress proxy registry (`0600`).
pub struct ProxyRegistry {
    path: PathBuf,
    inner: RwLock<ProxiesData>,
    gen: std::sync::atomic::AtomicU64,
    saved_gen: Mutex<u64>,
}

impl ProxyRegistry {
    /// Open or initialize `$STATE_DIR/proxies.json`.
    pub fn open(path: impl Into<PathBuf>, default_fallback: ProxyFallbackPolicy) -> Result<Self> {
        let path = path.into();
        let mut data: ProxiesData = match fs::read(&path) {
            Ok(raw) => serde_json::from_slice(&raw).unwrap_or_else(|e| {
                warn!(error = %e, "proxies.json unreadable; starting with empty registry");
                ProxiesData::default()
            }),
            Err(_) => ProxiesData::default(),
        };
        if !data.fallback_customized {
            data.fallback_policy = default_fallback;
        }
        let reg = Self {
            path,
            inner: RwLock::new(data),
            gen: std::sync::atomic::AtomicU64::new(0),
            saved_gen: Mutex::new(0),
        };
        reg.save()?;
        Ok(reg)
    }

    /// Open `$STATE_DIR/proxies.json` read-only (never writes to disk; ideal for MCP subprocesses).
    pub fn open_readonly(path: impl Into<PathBuf>, default_fallback: ProxyFallbackPolicy) -> Self {
        let path = path.into();
        let mut data: ProxiesData = match fs::read(&path) {
            Ok(raw) => serde_json::from_slice(&raw).unwrap_or_default(),
            Err(_) => ProxiesData::default(),
        };
        if !data.fallback_customized {
            data.fallback_policy = default_fallback;
        }
        Self {
            path,
            inner: RwLock::new(data),
            gen: std::sync::atomic::AtomicU64::new(0),
            saved_gen: Mutex::new(0),
        }
    }

    /// Construct an empty registry without failing on initial disk I/O (fallback helper).
    pub fn empty(path: impl Into<PathBuf>, default_fallback: ProxyFallbackPolicy) -> Self {
        let data = ProxiesData {
            fallback_policy: default_fallback,
            ..Default::default()
        };
        Self {
            path: path.into(),
            inner: RwLock::new(data),
            gen: std::sync::atomic::AtomicU64::new(0),
            saved_gen: Mutex::new(0),
        }
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, ProxiesData> {
        self.inner.read().unwrap_or_else(|e| e.into_inner())
    }

    fn save(&self) -> Result<()> {
        let bytes = {
            let g = self.read();
            serde_json::to_vec_pretty(&*g).map_err(|e| BridgeError::json("proxies.json", e))?
        };
        atomic_write_bytes(&self.path, &bytes, 0o600)
    }

    fn mutate<R>(&self, f: impl FnOnce(&mut ProxiesData) -> Result<R>) -> Result<R> {
        let (out, bytes, gen) = {
            let mut g = self
                .inner
                .write()
                .map_err(|e| BridgeError::Internal(format!("proxies lock poisoned: {e}")))?;
            let out = f(&mut g)?;
            let bytes = serde_json::to_vec_pretty(&*g)
                .map_err(|e| BridgeError::json("proxies.json", e))?;
            let gen = self.gen.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
            (out, bytes, gen)
        };
        let mut last = self.saved_gen.lock().unwrap_or_else(|e| e.into_inner());
        if gen > *last {
            if let Err(e) = atomic_write_bytes(&self.path, &bytes, 0o600) {
                warn!(error = %e, "proxies.json save failed");
                return Err(e);
            }
            *last = gen;
        }
        Ok(out)
    }

    pub fn list(&self) -> Vec<ProxyEntry> {
        self.read().proxies.clone()
    }

    pub fn get(&self, id: &str) -> Option<ProxyEntry> {
        self.read().proxies.iter().find(|p| p.id == id).cloned()
    }

    pub fn len(&self) -> usize {
        self.read().proxies.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn healthy_count(&self) -> usize {
        let now = now_ts();
        self.read()
            .proxies
            .iter()
            .filter(|p| p.usable_at(now))
            .count()
    }

    pub fn fallback_policy(&self) -> ProxyFallbackPolicy {
        self.read().fallback_policy
    }

    pub fn set_fallback_policy(&self, policy: ProxyFallbackPolicy) -> Result<()> {
        self.mutate(|d| {
            d.fallback_policy = policy;
            d.fallback_customized = true;
            Ok(())
        })
    }

    pub fn grok_proxy_id(&self) -> Option<String> {
        self.read().grok_proxy_id.clone()
    }

    pub fn set_grok_proxy(&self, proxy_id: Option<&str>) -> Result<()> {
        self.mutate(|d| {
            if let Some(pid) = proxy_id {
                if !d.proxies.iter().any(|p| p.id == pid) {
                    return Err(BridgeError::Validation(format!("unknown proxy '{pid}'")));
                }
                d.grok_proxy_id = Some(pid.to_string());
            } else {
                d.grok_proxy_id = None;
            }
            Ok(())
        })
    }

    /// Add a new validated egress proxy entry (`px1`, `px2`, ...).
    pub fn add(&self, raw_url: &str, label: &str) -> Result<ProxyEntry> {
        let (norm_url, default_label) = validate_proxy_url(raw_url)?;
        let clean_label: String = {
            let trimmed = label.trim();
            if trimmed.is_empty() {
                default_label.chars().take(32).collect()
            } else {
                trimmed.chars().take(32).collect()
            }
        };
        let entry = self.mutate(|d| {
            if d.proxies.len() >= MAX_PROXIES {
                return Err(BridgeError::Validation(format!(
                    "proxy limit reached ({MAX_PROXIES})"
                )));
            }
            let mut seq = d.next_seq.max(1);
            let mut id = format!("px{seq}");
            while d.proxies.iter().any(|p| p.id == id) {
                seq += 1;
                id = format!("px{seq}");
            }
            d.next_seq = seq + 1;
            let entry = ProxyEntry {
                id,
                label: clean_label,
                url: norm_url,
                enabled: true,
                created_ts: now_ts(),
                health: ProxyEntryHealth::default(),
            };
            d.proxies.push(entry.clone());
            Ok(entry)
        })?;
        info!(id = %entry.id, route = %entry.safe_label(), "egress proxy added");
        Ok(entry)
    }

    pub fn set_enabled(&self, id: &str, enabled: bool) -> Result<()> {
        self.mutate(|d| {
            let p = d
                .proxies
                .iter_mut()
                .find(|p| p.id == id)
                .ok_or_else(|| BridgeError::Validation(format!("unknown proxy '{id}'")))?;
            p.enabled = enabled;
            Ok(())
        })
    }

    pub fn rename(&self, id: &str, label: &str) -> Result<()> {
        self.mutate(|d| {
            let p = d
                .proxies
                .iter_mut()
                .find(|p| p.id == id)
                .ok_or_else(|| BridgeError::Validation(format!("unknown proxy '{id}'")))?;
            p.label = label.trim().chars().take(32).collect();
            Ok(())
        })
    }

    pub fn remove(&self, id: &str) -> Result<()> {
        self.mutate(|d| {
            let before = d.proxies.len();
            d.proxies.retain(|p| p.id != id);
            if d.proxies.len() == before {
                return Err(BridgeError::Validation(format!("unknown proxy '{id}'")));
            }
            if d.grok_proxy_id.as_deref() == Some(id) {
                d.grok_proxy_id = None;
            }
            Ok(())
        })
    }

    pub fn record_probe_ok(&self, id: &str, latency_ms: u64) {
        let now = now_ts();
        let _ = self.mutate(|d| {
            if let Some(p) = d.proxies.iter_mut().find(|p| p.id == id) {
                p.health.last_checked_ts = Some(now);
                p.health.last_ok_ts = Some(now);
                // Smooth latency with EWMA (70% prior, 30% fresh sample) to resist single-packet jitter.
                let ewma_ms = match p.health.latency_ms {
                    Some(prev) => (prev.saturating_mul(7).saturating_add(latency_ms.saturating_mul(3))) / 10,
                    None => latency_ms,
                };
                p.health.latency_ms = Some(ewma_ms);
                p.health.consecutive_failures = 0;
                p.health.total_checks = p.health.total_checks.saturating_add(1);
                p.health.total_ok = p.health.total_ok.saturating_add(1);
                p.health.last_error = None;
                p.health.status = if ewma_ms <= 1500 {
                    ProxyHealthStatus::Healthy
                } else {
                    ProxyHealthStatus::Degraded
                };
                p.health.recompute_score();
            }
            Ok(())
        });
    }

    pub fn record_probe_fail(&self, id: &str, raw_err: &str) {
        let now = now_ts();
        let _ = self.mutate(|d| {
            if let Some(p) = d.proxies.iter_mut().find(|p| p.id == id) {
                let clean: String = p.redact_text(raw_err).chars().take(200).collect();
                p.health.last_checked_ts = Some(now);
                p.health.last_fail_ts = Some(now);
                p.health.consecutive_failures = p.health.consecutive_failures.saturating_add(1);
                p.health.total_checks = p.health.total_checks.saturating_add(1);
                p.health.total_fail = p.health.total_fail.saturating_add(1);
                p.health.last_error = Some(clean);
                p.health.status = if p.health.consecutive_failures >= 2 {
                    ProxyHealthStatus::Unhealthy
                } else {
                    ProxyHealthStatus::Degraded
                };
                p.health.recompute_score();
            }
            Ok(())
        });
    }

    /// Resolve a sticky proxy ID according to current health and `fallback_policy`.
    pub fn resolve(&self, proxy_id: Option<&str>) -> ResolvedProxy {
        self.resolve_at(proxy_id, now_ts())
    }

    pub fn resolve_at(&self, proxy_id: Option<&str>, now: i64) -> ResolvedProxy {
        let Some(pid) = proxy_id.map(str::trim).filter(|s| !s.is_empty()) else {
            return ResolvedProxy::Direct;
        };
        let g = self.read();
        let policy = g.fallback_policy;
        let Some(entry) = g.proxies.iter().find(|p| p.id == pid) else {
            return match policy {
                ProxyFallbackPolicy::FailClosed => ResolvedProxy::Blocked {
                    id: pid.to_string(),
                    safe_label: pid.to_string(),
                    reason: "bound proxy was removed".to_string(),
                },
                ProxyFallbackPolicy::FallbackDirect => ResolvedProxy::DirectFallback {
                    id: pid.to_string(),
                    safe_label: pid.to_string(),
                    reason: "bound proxy was removed".to_string(),
                },
            };
        };

        if entry.usable_at(now) {
            return ResolvedProxy::Use {
                id: entry.id.clone(),
                safe_label: entry.safe_label(),
                url: entry.url.clone(),
            };
        }

        let reason = if !entry.enabled {
            "bound proxy is paused".to_string()
        } else {
            entry
                .health
                .last_error
                .clone()
                .unwrap_or_else(|| "bound proxy is unhealthy".to_string())
        };
        match policy {
            ProxyFallbackPolicy::FailClosed => ResolvedProxy::Blocked {
                id: entry.id.clone(),
                safe_label: entry.safe_label(),
                reason,
            },
            ProxyFallbackPolicy::FallbackDirect => ResolvedProxy::DirectFallback {
                id: entry.id.clone(),
                safe_label: entry.safe_label(),
                reason,
            },
        }
    }

    /// Resolve the sticky proxy bound to Grok OAuth (if any).
    pub fn resolve_grok(&self) -> ResolvedProxy {
        let pid = self.grok_proxy_id();
        self.resolve(pid.as_deref())
    }

    /// Redact credentials of every stored proxy from `text`.
    pub fn redact_all(&self, text: &str) -> String {
        let g = self.read();
        let mut out = text.to_string();
        for p in &g.proxies {
            out = p.redact_text(&out);
        }
        out
    }

    /// Return sensitive literal substrings (raw credentialed URLs & passwords >= 10 chars)
    /// for outbox leak scanning. Never log or display the returned strings.
    pub fn secret_literals(&self) -> Vec<String> {
        let g = self.read();
        let mut out = Vec::new();
        for p in &g.proxies {
            if let Ok(parsed) = Url::parse(&p.url) {
                if let Some(pass) = parsed.password() {
                    if !p.url.is_empty() {
                        out.push(p.url.clone());
                    }
                    if pass.len() >= 10 {
                        out.push(pass.to_string());
                    }
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    #[test]
    fn crud_redaction_quality_score_and_fail_closed_policy() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("proxies.json");
        let reg = ProxyRegistry::open(&path, ProxyFallbackPolicy::FailClosed).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        // Invalid schemes rejected
        assert!(reg.add("ftp://1.2.3.4:21", "bad").is_err());
        assert!(reg.add("socks5h://host with space:1080", "").is_err());

        let px = reg
            .add("socks5h://alice:SuperSecret99@10.20.30.40:1080", "DE-1")
            .unwrap();
        assert_eq!(px.id, "px1");
        assert_eq!(px.label, "DE-1");
        assert_eq!(px.safe_label(), "socks5h://[REDACTED]@10.20.30.40:1080");
        let dbg = format!("{px:?}");
        assert!(!dbg.contains("SuperSecret99"));
        assert!(!dbg.contains("alice"));

        // Healthy probe updates latency + high quality score
        reg.record_probe_ok(&px.id, 110);
        let p1 = reg.get(&px.id).unwrap();
        assert_eq!(p1.health.status, ProxyHealthStatus::Healthy);
        assert_eq!(p1.health.quality_score, 100);
        assert!(matches!(reg.resolve(Some(&px.id)), ResolvedProxy::Use { .. }));

        // Two failures -> Unhealthy -> FailClosed blocks leak
        reg.record_probe_fail(&px.id, "connect failed via socks5h://alice:SuperSecret99@10.20.30.40:1080");
        assert_eq!(reg.get(&px.id).unwrap().health.status, ProxyHealthStatus::Degraded);
        reg.record_probe_fail(&px.id, "connect timeout SuperSecret99");
        let p2 = reg.get(&px.id).unwrap();
        assert_eq!(p2.health.status, ProxyHealthStatus::Unhealthy);
        assert!(!p2.health.last_error.as_deref().unwrap_or("").contains("SuperSecret99"));
        assert!(reg.resolve_at(Some(&px.id), now_ts()).is_blocked());

        // Switching to FallbackDirect returns DirectFallback instead of Blocked
        reg.set_fallback_policy(ProxyFallbackPolicy::FallbackDirect).unwrap();
        assert!(matches!(
            reg.resolve_at(Some(&px.id), now_ts()),
            ResolvedProxy::DirectFallback { .. }
        ));

        // Grok sticky proxy binding & removal cleanup
        reg.set_grok_proxy(Some(&px.id)).unwrap();
        assert_eq!(reg.grok_proxy_id().as_deref(), Some("px1"));
        reg.remove(&px.id).unwrap();
        assert!(reg.grok_proxy_id().is_none());
        assert!(reg.is_empty());
    }

    #[test]
    fn ewma_latency_smoothing_and_secret_literals() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("proxies.json");
        let reg = ProxyRegistry::open(&path, ProxyFallbackPolicy::FailClosed).unwrap();
        let px = reg
            .add("socks5h://bob:LongSuperSecretPass123@198.51.100.5:1080", "NL-1")
            .unwrap();

        reg.record_probe_ok(&px.id, 100);
        assert_eq!(reg.get(&px.id).unwrap().health.latency_ms, Some(100));

        // Second probe at 500ms -> EWMA = (100*7 + 500*3) / 10 = 220ms
        reg.record_probe_ok(&px.id, 500);
        assert_eq!(reg.get(&px.id).unwrap().health.latency_ms, Some(220));

        let lits = reg.secret_literals();
        assert!(lits.iter().any(|s| s == "LongSuperSecretPass123"));
        assert!(lits.iter().any(|s| s.contains("198.51.100.5:1080")));
    }
}
