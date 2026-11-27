//! Multi-proxy pooling, circuit breaker, health-scored/hedged racing, and credential redaction.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::RwLock;
use std::time::{Duration, Instant};

use agy_core::{BridgeError, Result};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};
use url::Url;

/// Routing strategy across configured egress routes (`direct` and/or proxies).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxyMode {
    /// Try healthy routes in configured order, failing over when a route fails or opens its circuit.
    #[default]
    Failover,
    /// Rotate starting route across requests while skipping open circuits.
    RoundRobin,
    /// Rank routes by EWMA latency + health score and hedge idempotent calls across top routes.
    Race,
}

impl FromStr for ProxyMode {
    type Err = BridgeError;

    fn from_str(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "" | "failover" | "priority" => Ok(Self::Failover),
            "round_robin" | "round-robin" | "roundrobin" | "rr" => Ok(Self::RoundRobin),
            "race" | "hedged" | "health" | "fastest" => Ok(Self::Race),
            other => Err(BridgeError::Config(format!(
                "unsupported proxy mode '{other}' (expected failover, round_robin, or race)"
            ))),
        }
    }
}

impl fmt::Display for ProxyMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Failover => f.write_str("failover"),
            Self::RoundRobin => f.write_str("round_robin"),
            Self::Race => f.write_str("race"),
        }
    }
}

/// Supported transport schemes for outbound Bot API connections.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxyScheme {
    Direct,
    Http,
    Https,
    Socks5,
    Socks5h,
}

impl ProxyScheme {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Http => "http",
            Self::Https => "https",
            Self::Socks5 => "socks5",
            Self::Socks5h => "socks5h",
        }
    }
}

impl fmt::Display for ProxyScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Parsed proxy or direct route specification with credentials stripped from `Display`/`Debug`.
#[derive(Clone)]
pub struct ProxyRouteConfig {
    scheme: ProxyScheme,
    raw_url: Option<String>,
    safe_label: String,
    username: Option<String>,
    password: Option<String>,
}

impl ProxyRouteConfig {
    /// Direct connection route bypassing any environment proxy variables.
    pub fn direct() -> Self {
        Self {
            scheme: ProxyScheme::Direct,
            raw_url: None,
            safe_label: "direct".to_string(),
            username: None,
            password: None,
        }
    }

    /// Parse a single route specification (`direct`, `http://...`, `https://...`, `socks5://...`, `socks5h://...`).
    pub fn parse(spec: &str) -> Result<Self> {
        let trimmed = spec.trim();
        if trimmed.is_empty() {
            return Err(BridgeError::Config("proxy route cannot be empty".into()));
        }
        if trimmed.eq_ignore_ascii_case("direct") {
            return Ok(Self::direct());
        }

        let parsed = Url::parse(trimmed)
            .map_err(|e| BridgeError::Config(format!("invalid proxy URL: {e}")))?;

        let scheme = match parsed.scheme().to_ascii_lowercase().as_str() {
            "http" => ProxyScheme::Http,
            "https" => ProxyScheme::Https,
            "socks5" => ProxyScheme::Socks5,
            "socks5h" => ProxyScheme::Socks5h,
            other => {
                return Err(BridgeError::Config(format!(
                    "unsupported proxy scheme '{other}' (expected direct, http, https, socks5, or socks5h)"
                )));
            }
        };

        let host = parsed
            .host_str()
            .filter(|h| !h.is_empty())
            .ok_or_else(|| BridgeError::Config("proxy URL is missing a host".into()))?;

        let has_auth = !parsed.username().is_empty() || parsed.password().is_some();
        let auth_prefix = if has_auth { "***@" } else { "" };
        let port_suffix = match parsed.port() {
            Some(p) => format!(":{p}"),
            None => String::new(),
        };
        let safe_label = format!("{}://{}{}{}", scheme.as_str(), auth_prefix, host, port_suffix);

        let username = (!parsed.username().is_empty()).then(|| parsed.username().to_string());
        let password = parsed.password().map(ToOwned::to_owned);

        Ok(Self {
            scheme,
            raw_url: Some(parsed.to_string()),
            safe_label,
            username,
            password,
        })
    }

    /// Parse a comma-, semicolon-, or whitespace-delimited list of proxy routes.
    /// Returns `[ProxyRouteConfig::direct()]` when the input contains no entries.
    pub fn parse_list(raw: &str) -> Result<Vec<Self>> {
        let mut routes = Vec::new();
        for part in raw.split([',', ';', '\n']) {
            let token = part.trim();
            if token.is_empty() {
                continue;
            }
            routes.push(Self::parse(token)?);
        }
        if routes.is_empty() {
            routes.push(Self::direct());
        }
        Ok(routes)
    }

    /// Credential-redacted route label safe for logs, UI, and telemetry snapshots.
    pub fn safe_label(&self) -> &str {
        &self.safe_label
    }

    pub fn scheme(&self) -> ProxyScheme {
        self.scheme
    }

    pub fn is_direct(&self) -> bool {
        self.scheme == ProxyScheme::Direct
    }

    pub(crate) fn raw_url(&self) -> Option<&str> {
        self.raw_url.as_deref()
    }

    /// Redact any credentials belonging to this route from an arbitrary error/log string.
    pub(crate) fn redact_text(&self, text: &str) -> String {
        let mut out = text.to_string();
        if let Some(raw) = &self.raw_url {
            if !raw.is_empty() && out.contains(raw) {
                out = out.replace(raw, &self.safe_label);
            }
            let raw_no_slash = raw.trim_end_matches('/');
            if !raw_no_slash.is_empty() && out.contains(raw_no_slash) {
                out = out.replace(raw_no_slash, &self.safe_label);
            }
        }
        if let (Some(u), Some(p)) = (&self.username, &self.password) {
            let pair = format!("{u}:{p}@");
            if out.contains(&pair) {
                out = out.replace(&pair, "***@");
            }
        }
        if let Some(pass) = &self.password {
            if pass.len() >= 4 && out.contains(pass) {
                out = out.replace(pass, "***");
            }
        }
        if let Some(user) = &self.username {
            if user.len() >= 4 && out.contains(user) {
                out = out.replace(user, "***");
            }
        }
        out
    }
}

impl fmt::Display for ProxyRouteConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.safe_label)
    }
}

impl fmt::Debug for ProxyRouteConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxyRouteConfig")
            .field("scheme", &self.scheme)
            .field("label", &self.safe_label)
            .finish()
    }
}

/// Self-contained networking and transport configuration for `agy-net`.
#[derive(Debug, Clone)]
pub struct NetConfig {
    pub api_base: String,
    pub force_ipv4: bool,
    pub connect_timeout: Duration,
    pub pool_idle_timeout: Duration,
    pub tcp_keepalive: Duration,
    pub tcp_keepalive_interval: Duration,
    pub tcp_keepalive_retries: u32,
    pub tcp_user_timeout: Duration,
    pub default_request_timeout: Duration,
    pub routes: Vec<ProxyRouteConfig>,
    pub proxy_mode: ProxyMode,
    pub cb_failure_threshold: u32,
    pub cb_open_cooldown: Duration,
    pub race_hedge_delay: Duration,
}

impl Default for NetConfig {
    fn default() -> Self {
        Self {
            api_base: "https://api.telegram.org".to_string(),
            force_ipv4: true,
            connect_timeout: Duration::from_secs(10),
            pool_idle_timeout: Duration::from_secs(30),
            tcp_keepalive: Duration::from_secs(20),
            tcp_keepalive_interval: Duration::from_secs(5),
            tcp_keepalive_retries: 3,
            tcp_user_timeout: Duration::from_secs(30),
            default_request_timeout: Duration::from_secs(40),
            routes: vec![ProxyRouteConfig::direct()],
            proxy_mode: ProxyMode::Failover,
            cb_failure_threshold: 2,
            cb_open_cooldown: Duration::from_secs(30),
            race_hedge_delay: Duration::from_millis(250),
        }
    }
}

impl NetConfig {
    pub fn with_api_base(mut self, base: impl Into<String>) -> Self {
        self.api_base = base.into();
        self
    }

    pub fn with_force_ipv4(mut self, force_ipv4: bool) -> Self {
        self.force_ipv4 = force_ipv4;
        self
    }

    pub fn with_routes(mut self, routes: Vec<ProxyRouteConfig>) -> Self {
        self.routes = routes;
        self
    }

    pub fn with_proxy_mode(mut self, mode: ProxyMode) -> Self {
        self.proxy_mode = mode;
        self
    }
}

/// Per-route circuit breaker state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    Closed,
    Open(Instant),
    HalfOpen,
}

impl CircuitState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Closed => "closed",
            Self::Open(_) => "open",
            Self::HalfOpen => "half_open",
        }
    }
}

/// Serializable route telemetry snapshot for `/net` dashboard and `health.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyStats {
    pub index: usize,
    pub label: String,
    pub scheme: String,
    pub state: String,
    pub cooldown_remaining_ms: u64,
    pub ewma_latency_ms: Option<f64>,
    pub consecutive_failures: u32,
    pub total_requests: u64,
    pub total_successes: u64,
    pub total_failures: u64,
    pub rebuilds: u64,
    pub last_error: Option<String>,
}

/// Aggregate pool telemetry snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyPoolSnapshot {
    pub mode: ProxyMode,
    pub total_rebuilds: u64,
    pub active_healthy: usize,
    pub routes: Vec<ProxyStats>,
}

struct RouteState {
    client: reqwest::Client,
    circuit: CircuitState,
    consecutive_failures: u32,
    ewma_latency_ms: Option<f64>,
    total_requests: u64,
    total_successes: u64,
    total_failures: u64,
    rebuilds: u64,
    last_error: Option<String>,
}

struct RouteSlot {
    config: ProxyRouteConfig,
    state: RwLock<RouteState>,
}

/// Multi-route HTTP client pool with circuit breaking, latency scoring, and client rebuilds.
pub struct ProxyPool {
    config: NetConfig,
    routes: Vec<RouteSlot>,
    rr_cursor: AtomicUsize,
    total_rebuilds: AtomicU64,
}

impl fmt::Debug for ProxyPool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxyPool")
            .field("mode", &self.config.proxy_mode)
            .field("routes", &self.routes.iter().map(|r| r.config.safe_label()).collect::<Vec<_>>())
            .field("total_rebuilds", &self.total_rebuilds.load(Ordering::Relaxed))
            .finish()
    }
}

impl ProxyPool {
    /// Construct a `ProxyPool` from `NetConfig`, building an isolated `reqwest::Client` per route.
    pub fn new(mut config: NetConfig) -> Result<Self> {
        if config.routes.is_empty() {
            config.routes.push(ProxyRouteConfig::direct());
        }
        if config.cb_failure_threshold == 0 {
            config.cb_failure_threshold = 1;
        }

        let mut routes = Vec::with_capacity(config.routes.len());
        for route_cfg in &config.routes {
            let client = build_client(route_cfg, &config)?;
            routes.push(RouteSlot {
                config: route_cfg.clone(),
                state: RwLock::new(RouteState {
                    client,
                    circuit: CircuitState::Closed,
                    consecutive_failures: 0,
                    ewma_latency_ms: None,
                    total_requests: 0,
                    total_successes: 0,
                    total_failures: 0,
                    rebuilds: 0,
                    last_error: None,
                }),
            });
        }

        Ok(Self {
            config,
            routes,
            rr_cursor: AtomicUsize::new(0),
            total_rebuilds: AtomicU64::new(0),
        })
    }

    pub fn mode(&self) -> ProxyMode {
        self.config.proxy_mode
    }

    pub fn race_hedge_delay(&self) -> Duration {
        self.config.race_hedge_delay
    }

    pub fn route_count(&self) -> usize {
        self.routes.len()
    }

    pub fn total_rebuilds(&self) -> u64 {
        self.total_rebuilds.load(Ordering::Relaxed)
    }

    /// Return candidate `(route_index, client, safe_label)` entries ordered according to `ProxyMode`.
    /// Open circuits are skipped unless every configured route is currently Open, in which case
    /// the earliest-expiring Open route is returned as a last-resort fallback.
    pub(crate) fn select_candidates(&self) -> Vec<(usize, reqwest::Client, String)> {
        let now = Instant::now();
        let n = self.routes.len();
        let mut healthy: Vec<(usize, reqwest::Client, f64)> = Vec::with_capacity(n);
        let mut open_fallback: Vec<(usize, reqwest::Client, Instant)> = Vec::new();

        for (idx, slot) in self.routes.iter().enumerate() {
            let mut st = slot.state.write().unwrap_or_else(|e| e.into_inner());
            if let CircuitState::Open(until) = st.circuit {
                if now >= until {
                    st.circuit = CircuitState::HalfOpen;
                    debug!(route = %slot.config, "circuit transitioned Open -> HalfOpen");
                }
            }

            match st.circuit {
                CircuitState::Closed | CircuitState::HalfOpen => {
                    let base_ewma = st.ewma_latency_ms.unwrap_or(50.0);
                    let half_open_penalty = if matches!(st.circuit, CircuitState::HalfOpen) {
                        100.0
                    } else {
                        0.0
                    };
                    let score = base_ewma
                        + (st.consecutive_failures as f64) * 250.0
                        + half_open_penalty;
                    healthy.push((idx, st.client.clone(), score));
                }
                CircuitState::Open(until) => {
                    open_fallback.push((idx, st.client.clone(), until));
                }
            }
        }

        if healthy.is_empty() {
            open_fallback.sort_by_key(|&(_, _, until)| until);
            return open_fallback
                .into_iter()
                .map(|(idx, client, _)| (idx, client, self.routes[idx].config.safe_label.clone()))
                .collect();
        }

        match self.config.proxy_mode {
            ProxyMode::Failover => {}
            ProxyMode::RoundRobin => {
                let start = self.rr_cursor.fetch_add(1, Ordering::Relaxed) % n;
                healthy.sort_by_key(|&(idx, _, _)| (idx + n - start) % n);
            }
            ProxyMode::Race => {
                healthy.sort_by(|a, b| {
                    a.2.total_cmp(&b.2).then_with(|| a.0.cmp(&b.0))
                });
            }
        }

        healthy
            .into_iter()
            .map(|(idx, client, _)| (idx, client, self.routes[idx].config.safe_label.clone()))
            .collect()
    }

    /// Record a successful Telegram transport exchange on route `idx`.
    pub(crate) fn record_success(&self, idx: usize, latency: Duration) {
        let Some(slot) = self.routes.get(idx) else {
            return;
        };
        let ms = latency.as_secs_f64() * 1000.0;
        let mut st = slot.state.write().unwrap_or_else(|e| e.into_inner());
        let was_degraded = !matches!(st.circuit, CircuitState::Closed) || st.consecutive_failures > 0;
        st.total_requests = st.total_requests.saturating_add(1);
        st.total_successes = st.total_successes.saturating_add(1);
        st.consecutive_failures = 0;
        st.circuit = CircuitState::Closed;
        st.last_error = None;
        st.ewma_latency_ms = Some(match st.ewma_latency_ms {
            Some(prev) => prev * 0.7 + ms * 0.3,
            None => ms,
        });
        if was_degraded {
            info!(route = %slot.config, latency_ms = format_args!("{ms:.1}"), "route recovered -> Closed");
        }
    }

    /// Record a transport/proxy failure on route `idx`, opening its circuit breaker and
    /// rebuilding its underlying `reqwest::Client` on power-of-two failure streaks.
    pub(crate) fn record_failure(&self, idx: usize, raw_err: &str) {
        let Some(slot) = self.routes.get(idx) else {
            return;
        };
        let safe_err = self.redact_secrets(raw_err);
        let safe_err_short = truncate_chars(&safe_err, 160);
        let now = Instant::now();

        let (failures, should_rebuild, opened) = {
            let mut st = slot.state.write().unwrap_or_else(|e| e.into_inner());
            st.total_requests = st.total_requests.saturating_add(1);
            st.total_failures = st.total_failures.saturating_add(1);
            st.consecutive_failures = st.consecutive_failures.saturating_add(1);
            st.last_error = Some(safe_err_short.clone());

            let n = st.consecutive_failures;
            let open_now = matches!(st.circuit, CircuitState::HalfOpen)
                || n >= self.config.cb_failure_threshold;
            if open_now {
                st.circuit = CircuitState::Open(now + self.config.cb_open_cooldown);
            }
            let rebuild = n >= 2 && (n & (n - 1)) == 0;
            (n, rebuild, open_now)
        };

        if opened {
            warn!(
                route = %slot.config,
                consecutive_failures = failures,
                cooldown_s = self.config.cb_open_cooldown.as_secs(),
                err = %safe_err_short,
                "proxy circuit opened"
            );
        }

        if should_rebuild {
            self.rebuild_route(
                idx,
                &format!("after {failures} consecutive failures"),
            );
        }
    }

    /// Rebuild the `reqwest::Client` for a specific route, dropping stale pooled sockets and DNS cache.
    pub fn rebuild_route(&self, idx: usize, reason: &str) -> bool {
        let Some(slot) = self.routes.get(idx) else {
            return false;
        };
        match build_client(&slot.config, &self.config) {
            Ok(fresh_client) => {
                let mut st = slot.state.write().unwrap_or_else(|e| e.into_inner());
                st.client = fresh_client;
                st.rebuilds = st.rebuilds.saturating_add(1);
                let total = self.total_rebuilds.fetch_add(1, Ordering::Relaxed) + 1;
                warn!(route = %slot.config, rebuilds = total, reason = %reason, "rebuilt HTTP client");
                true
            }
            Err(e) => {
                warn!(route = %slot.config, err = %e, "failed to rebuild HTTP client");
                false
            }
        }
    }

    /// Rebuild all route `reqwest::Client` instances (e.g., on watchdog soft stall).
    pub fn rebuild_all(&self, reason: &str) -> usize {
        let mut rebuilt = 0;
        for idx in 0..self.routes.len() {
            if self.rebuild_route(idx, reason) {
                rebuilt += 1;
            }
        }
        rebuilt
    }

    /// Snapshot current route health, circuit states, and EWMA latencies for `/net` and `health.json`.
    pub fn snapshot(&self) -> ProxyPoolSnapshot {
        let now = Instant::now();
        let mut routes = Vec::with_capacity(self.routes.len());
        let mut active_healthy = 0usize;

        for (index, slot) in self.routes.iter().enumerate() {
            let st = slot.state.read().unwrap_or_else(|e| e.into_inner());
            let (state_str, cooldown_remaining_ms) = match st.circuit {
                CircuitState::Closed => {
                    active_healthy += 1;
                    ("closed", 0)
                }
                CircuitState::HalfOpen => {
                    active_healthy += 1;
                    ("half_open", 0)
                }
                CircuitState::Open(until) => {
                    if now >= until {
                        active_healthy += 1;
                        ("half_open", 0)
                    } else {
                        (
                            "open",
                            until.saturating_duration_since(now).as_millis() as u64,
                        )
                    }
                }
            };

            routes.push(ProxyStats {
                index,
                label: slot.config.safe_label.clone(),
                scheme: slot.config.scheme.as_str().to_string(),
                state: state_str.to_string(),
                cooldown_remaining_ms,
                ewma_latency_ms: st.ewma_latency_ms.map(|v| (v * 100.0).round() / 100.0),
                consecutive_failures: st.consecutive_failures,
                total_requests: st.total_requests,
                total_successes: st.total_successes,
                total_failures: st.total_failures,
                rebuilds: st.rebuilds,
                last_error: st.last_error.clone(),
            });
        }

        ProxyPoolSnapshot {
            mode: self.config.proxy_mode,
            total_rebuilds: self.total_rebuilds(),
            active_healthy,
            routes,
        }
    }

    /// Inspect the current `CircuitState` for route `idx` (primarily for diagnostics/tests).
    pub fn route_circuit_state(&self, idx: usize) -> Option<CircuitState> {
        self.routes.get(idx).map(|slot| {
            slot.state
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .circuit
        })
    }

    /// Redact proxy credentials from all configured routes out of an error/log message.
    pub fn redact_secrets(&self, input: &str) -> String {
        let mut out = input.to_string();
        for slot in &self.routes {
            out = slot.config.redact_text(&out);
        }
        out
    }
}

/// Build a tuned `reqwest::Client` using pure-Rust `rustls-tls`, TCP keepalive, optional IPv4 binding,
/// and route-specific proxy configuration.
pub fn build_client(route: &ProxyRouteConfig, cfg: &NetConfig) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .use_rustls_tls()
        .connect_timeout(cfg.connect_timeout)
        .pool_idle_timeout(Some(cfg.pool_idle_timeout))
        .pool_max_idle_per_host(20)
        .tcp_nodelay(true)
        .tcp_keepalive(Some(cfg.tcp_keepalive))
        .tcp_keepalive_interval(Some(cfg.tcp_keepalive_interval))
        .tcp_keepalive_retries(Some(cfg.tcp_keepalive_retries));

    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    {
        builder = builder.tcp_user_timeout(Some(cfg.tcp_user_timeout));
    }

    if cfg.force_ipv4 {
        let is_ipv6_proxy = route
            .raw_url()
            .and_then(|u| Url::parse(u).ok())
            .is_some_and(|u| matches!(u.host(), Some(url::Host::Ipv6(_))));
        if !is_ipv6_proxy {
            builder = builder.local_address(Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
        }
    }

    match route.raw_url() {
        None => {
            builder = builder.no_proxy();
        }
        Some(raw) => {
            let proxy = reqwest::Proxy::all(raw).map_err(|e| {
                BridgeError::Config(format!(
                    "failed to configure proxy {}: {}",
                    route.safe_label(),
                    route.redact_text(&e.to_string())
                ))
            })?;
            builder = builder.proxy(proxy);
        }
    }

    builder.build().map_err(|e| {
        BridgeError::Network(format!(
            "failed to build HTTP client for {}: {}",
            route.safe_label(),
            route.redact_text(&e.to_string())
        ))
    })
}

/// Default lightweight HTTPS 204 connectivity probe target for proxy health checks.
pub const DEFAULT_PROXY_PROBE_URL: &str = "https://www.gstatic.com/generate_204";

/// Result of probing a single direct or proxy egress route.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyProbeResult {
    pub ok: bool,
    pub latency_ms: u64,
    pub status_code: Option<u16>,
    pub error: Option<String>,
}

/// Build a clean, pure-Rust `rustls-tls` HTTP client bound to an optional single proxy URL
/// (used for sticky AI egress proxies and connectivity probes).
pub fn build_egress_client(
    proxy_url: Option<&str>,
    force_ipv4: bool,
    timeout: Duration,
) -> Result<reqwest::Client> {
    let route = match proxy_url.map(str::trim).filter(|s| !s.is_empty()) {
        Some(raw) => ProxyRouteConfig::parse(raw)?,
        None => ProxyRouteConfig::direct(),
    };
    let mut cfg = NetConfig {
        force_ipv4,
        connect_timeout: timeout.min(Duration::from_secs(12)),
        default_request_timeout: timeout,
        ..Default::default()
    };
    cfg.routes = vec![route.clone()];

    let mut builder = reqwest::Client::builder()
        .use_rustls_tls()
        .connect_timeout(cfg.connect_timeout)
        .timeout(timeout)
        .pool_idle_timeout(Some(cfg.pool_idle_timeout))
        .tcp_nodelay(true)
        .tcp_keepalive(Some(cfg.tcp_keepalive))
        .tcp_keepalive_interval(Some(cfg.tcp_keepalive_interval))
        .tcp_keepalive_retries(Some(cfg.tcp_keepalive_retries));

    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    {
        builder = builder.tcp_user_timeout(Some(cfg.tcp_user_timeout));
    }

    if force_ipv4 {
        let is_ipv6_proxy = route
            .raw_url()
            .and_then(|u| Url::parse(u).ok())
            .is_some_and(|u| matches!(u.host(), Some(url::Host::Ipv6(_))));
        if !is_ipv6_proxy {
            builder = builder.local_address(Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
        }
    }

    match route.raw_url() {
        None => {
            builder = builder.no_proxy();
        }
        Some(raw) => {
            let proxy = reqwest::Proxy::all(raw).map_err(|e| {
                BridgeError::Config(format!(
                    "invalid egress proxy {}: {}",
                    route.safe_label(),
                    route.redact_text(&e.to_string())
                ))
            })?;
            builder = builder.proxy(proxy);
        }
    }

    builder.build().map_err(|e| {
        BridgeError::Network(format!(
            "failed to build egress HTTP client for {}: {}",
            route.safe_label(),
            route.redact_text(&e.to_string())
        ))
    })
}

/// Probe a proxy route (or direct) against a lightweight 204 HTTPS endpoint, measuring latency
/// and validating TLS handshake & proxy authentication without leaking credentials.
pub async fn probe_proxy_route(
    proxy_url: Option<&str>,
    target_url: Option<&str>,
    force_ipv4: bool,
    timeout: Duration,
) -> ProxyProbeResult {
    let route = match proxy_url.map(str::trim).filter(|s| !s.is_empty()) {
        Some(raw) => match ProxyRouteConfig::parse(raw) {
            Ok(r) => r,
            Err(e) => {
                return ProxyProbeResult {
                    ok: false,
                    latency_ms: 0,
                    status_code: None,
                    error: Some(e.to_string()),
                };
            }
        },
        None => ProxyRouteConfig::direct(),
    };

    let client = match build_egress_client(proxy_url, force_ipv4, timeout) {
        Ok(c) => c,
        Err(e) => {
            return ProxyProbeResult {
                ok: false,
                latency_ms: 0,
                status_code: None,
                error: Some(route.redact_text(&e.to_string())),
            };
        }
    };

    let target = target_url
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(DEFAULT_PROXY_PROBE_URL);
    let started = Instant::now();
    match client.get(target).send().await {
        Ok(resp) => {
            let ms = started.elapsed().as_millis() as u64;
            let code = resp.status().as_u16();
            if code == 407 {
                ProxyProbeResult {
                    ok: false,
                    latency_ms: ms,
                    status_code: Some(code),
                    error: Some("HTTP 407 Proxy Authentication Required".to_string()),
                }
            } else if (200..400).contains(&code) {
                ProxyProbeResult {
                    ok: true,
                    latency_ms: ms,
                    status_code: Some(code),
                    error: None,
                }
            } else {
                ProxyProbeResult {
                    ok: false,
                    latency_ms: ms,
                    status_code: Some(code),
                    error: Some(format!("unexpected HTTP {code} from probe target")),
                }
            }
        }
        Err(e) => {
            let ms = started.elapsed().as_millis() as u64;
            let clean = route.redact_text(&e.without_url().to_string());
            ProxyProbeResult {
                ok: false,
                latency_ms: ms,
                status_code: None,
                error: Some(truncate_chars(&clean, 160)),
            }
        }
    }
}

/// Parse an HTTP `Retry-After` delta-seconds header value (`"12"` or `"12.5"` -> clamped `1..=300`).
pub fn parse_retry_after_secs(raw: &str) -> Option<u64> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Ok(secs) = trimmed.parse::<u64>() {
        return Some(secs.clamp(1, 300));
    }
    if let Ok(secs_f) = trimmed.parse::<f64>() {
        if secs_f.is_finite() && secs_f > 0.0 {
            return Some((secs_f.ceil() as u64).clamp(1, 300));
        }
    }
    None
}

fn truncate_chars(s: &str, max_chars: usize) -> String {
    agy_core::text::truncate_chars(s, max_chars)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_routes_and_redact_credentials() {
        let direct = ProxyRouteConfig::parse("direct").unwrap();
        assert!(direct.is_direct());
        assert_eq!(direct.safe_label(), "direct");
        assert_eq!(format!("{direct}"), "direct");

        let http = ProxyRouteConfig::parse("http://alice:s3cretPass@proxy.local:8080").unwrap();
        assert_eq!(http.scheme(), ProxyScheme::Http);
        assert_eq!(http.safe_label(), "http://***@proxy.local:8080");
        assert!(!format!("{http:?}").contains("s3cretPass"));
        assert!(!format!("{http:?}").contains("alice"));

        let socks5h = ProxyRouteConfig::parse("socks5h://bob:tok99@127.0.0.1:1080").unwrap();
        assert_eq!(socks5h.scheme(), ProxyScheme::Socks5h);
        assert_eq!(socks5h.safe_label(), "socks5h://***@127.0.0.1:1080");
        assert!(!format!("{socks5h}").contains("tok99"));

        let https = ProxyRouteConfig::parse("https://proxy.example:443").unwrap();
        assert_eq!(https.scheme(), ProxyScheme::Https);
        assert_eq!(https.safe_label(), "https://proxy.example");

        let https_custom = ProxyRouteConfig::parse("https://u:p@proxy.example:8443").unwrap();
        assert_eq!(https_custom.safe_label(), "https://***@proxy.example:8443");

        let socks5_noport = ProxyRouteConfig::parse("socks5://127.0.0.1").unwrap();
        assert_eq!(socks5_noport.scheme(), ProxyScheme::Socks5);
        assert_eq!(socks5_noport.safe_label(), "socks5://127.0.0.1");

        assert!(ProxyRouteConfig::parse("").is_err());
        assert!(ProxyRouteConfig::parse("ftp://127.0.0.1:21").is_err());
        assert!(ProxyRouteConfig::parse("http://").is_err());
    }

    #[test]
    fn build_clients_all_schemes() {
        let cfg_v4 = NetConfig::default();
        let cfg_dual = NetConfig::default().with_force_ipv4(false);
        let routes = ProxyRouteConfig::parse_list(
            "direct, http://u:p@127.0.0.1:8080, https://127.0.0.1:8443, socks5://127.0.0.1:1080, socks5h://u:p@127.0.0.1:1081",
        )
        .unwrap();
        assert_eq!(routes.len(), 5);
        for route in &routes {
            build_client(route, &cfg_v4).expect("IPv4 client build should succeed");
            build_client(route, &cfg_dual).expect("dual-stack client build should succeed");
        }
    }

    #[test]
    fn circuit_breaker_and_power_of_two_rebuilds() {
        let routes = ProxyRouteConfig::parse_list("http://127.0.0.1:18080, direct").unwrap();
        let cfg = NetConfig {
            routes,
            cb_failure_threshold: 2,
            cb_open_cooldown: Duration::from_millis(40),
            ..Default::default()
        };
        let pool = ProxyPool::new(cfg).unwrap();

        // Initially both routes closed; Failover picks 0 then 1
        let cands: Vec<usize> = pool.select_candidates().into_iter().map(|c| c.0).collect();
        assert_eq!(cands, vec![0, 1]);

        // 1st failure: still Closed, 0 rebuilds
        pool.record_failure(0, "conn refused");
        assert_eq!(pool.route_circuit_state(0), Some(CircuitState::Closed));
        assert_eq!(pool.total_rebuilds(), 0);

        // 2nd failure: opens circuit AND triggers 1st rebuild (power of 2)
        pool.record_failure(0, "conn refused");
        assert!(matches!(pool.route_circuit_state(0), Some(CircuitState::Open(_))));
        assert_eq!(pool.total_rebuilds(), 1);

        // While Open, route 0 is skipped so only route 1 is selected
        let cands: Vec<usize> = pool.select_candidates().into_iter().map(|c| c.0).collect();
        assert_eq!(cands, vec![1]);

        // Wait for cooldown -> transitions to HalfOpen
        std::thread::sleep(Duration::from_millis(55));
        let cands: Vec<usize> = pool.select_candidates().into_iter().map(|c| c.0).collect();
        assert_eq!(cands, vec![0, 1]);
        assert_eq!(pool.route_circuit_state(0), Some(CircuitState::HalfOpen));

        // 3rd failure on HalfOpen re-opens immediately without rebuild (3 is not power of 2)
        pool.record_failure(0, "still dead");
        assert!(matches!(pool.route_circuit_state(0), Some(CircuitState::Open(_))));
        assert_eq!(pool.total_rebuilds(), 1);

        // 4th failure triggers 2nd rebuild
        pool.record_failure(0, "still dead");
        assert_eq!(pool.total_rebuilds(), 2);

        // Recovery closes circuit and clears consecutive failures
        pool.record_success(0, Duration::from_millis(12));
        assert_eq!(pool.route_circuit_state(0), Some(CircuitState::Closed));
        let snap = pool.snapshot();
        assert_eq!(snap.routes[0].state, "closed");
        assert_eq!(snap.routes[0].consecutive_failures, 0);
        assert!(snap.routes[0].ewma_latency_ms.is_some());
    }

    #[test]
    fn round_robin_and_race_scoring() {
        let routes = ProxyRouteConfig::parse_list(
            "http://127.0.0.1:18081, http://127.0.0.1:18082, direct",
        )
        .unwrap();

        let rr_pool = ProxyPool::new(NetConfig {
            routes: routes.clone(),
            proxy_mode: ProxyMode::RoundRobin,
            ..Default::default()
        })
        .unwrap();
        let first: Vec<usize> = (0..3)
            .map(|_| rr_pool.select_candidates()[0].0)
            .collect();
        assert_eq!(first, vec![0, 1, 2]);

        let race_pool = ProxyPool::new(NetConfig {
            routes,
            proxy_mode: ProxyMode::Race,
            ..Default::default()
        })
        .unwrap();
        race_pool.record_success(0, Duration::from_millis(200));
        race_pool.record_success(1, Duration::from_millis(10));
        race_pool.record_success(2, Duration::from_millis(90));
        let ordered: Vec<usize> = race_pool
            .select_candidates()
            .into_iter()
            .map(|c| c.0)
            .collect();
        assert_eq!(ordered, vec![1, 2, 0]);
    }
}
