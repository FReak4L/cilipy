//! Anti-DDoS, verified real-IP extraction, auto-ban, Host/Origin DNS-rebinding protection,
//! and security headers for the AGY Remote MCP Gateway (`127.0.0.1:8788`).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use agy_core::security::{KeyedTokenBucket, DEFAULT_MAX_BUCKET_KEYS};
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use dashmap::DashMap;
use serde_json::json;
use tokio::sync::Semaphore;
use tracing::warn;

use crate::config::GatewayConfigStore;

/// Official Cloudflare IPv4 CIDRs (used to validate `CF-Connecting-IP` when Caddy forwards
/// `X-Caddy-Peer-Ip` or `X-Forwarded-For` from the edge proxy).
const CF_IPV4_CIDRS: &[(Ipv4Addr, u8)] = &[
    (Ipv4Addr::new(173, 245, 48, 0), 20),
    (Ipv4Addr::new(103, 21, 244, 0), 22),
    (Ipv4Addr::new(103, 22, 200, 0), 22),
    (Ipv4Addr::new(103, 31, 4, 0), 22),
    (Ipv4Addr::new(141, 101, 64, 0), 18),
    (Ipv4Addr::new(108, 162, 192, 0), 18),
    (Ipv4Addr::new(190, 93, 240, 0), 20),
    (Ipv4Addr::new(188, 114, 96, 0), 20),
    (Ipv4Addr::new(197, 234, 240, 0), 22),
    (Ipv4Addr::new(198, 41, 128, 0), 17),
    (Ipv4Addr::new(162, 158, 0, 0), 15),
    (Ipv4Addr::new(104, 16, 0, 0), 13),
    (Ipv4Addr::new(104, 24, 0, 0), 14),
    (Ipv4Addr::new(172, 64, 0, 0), 13),
    (Ipv4Addr::new(131, 0, 72, 0), 22),
];

/// Official Cloudflare IPv6 CIDRs.
const CF_IPV6_CIDRS: &[(Ipv6Addr, u8)] = &[
    (Ipv6Addr::new(0x2400, 0xcb00, 0, 0, 0, 0, 0, 0), 32),
    (Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 0), 32),
    (Ipv6Addr::new(0x2803, 0xf800, 0, 0, 0, 0, 0, 0), 32),
    (Ipv6Addr::new(0x2405, 0xb500, 0, 0, 0, 0, 0, 0), 32),
    (Ipv6Addr::new(0x2405, 0x8100, 0, 0, 0, 0, 0, 0), 32),
    (Ipv6Addr::new(0x2a06, 0x98c0, 0, 0, 0, 0, 0, 0), 29),
    (Ipv6Addr::new(0x2c0f, 0xf248, 0, 0, 0, 0, 0, 0), 32),
];

pub fn is_cloudflare_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let bits = u32::from(v4);
            CF_IPV4_CIDRS.iter().any(|&(net, prefix)| {
                let mask = if prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - prefix)
                };
                (bits & mask) == (u32::from(net) & mask)
            })
        }
        IpAddr::V6(v6) => {
            let bits = u128::from(v6);
            CF_IPV6_CIDRS.iter().any(|&(net, prefix)| {
                let mask = if prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - prefix)
                };
                (bits & mask) == (u128::from(net) & mask)
            })
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpSource {
    Loopback,
    Direct,
    CloudflareEdge,
}

/// Extract verified client IP without allowing header spoofing.
///
/// Rules:
/// - Forwarding headers are ONLY read when direct TCP peer is loopback (local Caddy proxy).
/// - `CF-Connecting-IP` is ONLY trusted when Caddy's remote peer (`X-Real-IP` / `X-Caddy-Peer-Ip`)
///   belongs to official Cloudflare CIDR ranges! An attacker hitting `mcp.example.com` directly
///   and forging `CF-Connecting-IP` gets their real peer IP instead.
pub fn extract_verified_client_ip(
    peer: Option<SocketAddr>,
    headers: &HeaderMap,
) -> (String, IpSource) {
    let direct_is_loopback = peer.map(|a| a.ip().is_loopback()).unwrap_or(true);
    if !direct_is_loopback {
        if let Some(addr) = peer {
            return (addr.ip().to_string(), IpSource::Direct);
        }
    }

    let caddy_peer_ip = headers
        .get("x-real-ip")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .and_then(|s| s.parse::<IpAddr>().ok());

    if let Some(upstream_ip) = caddy_peer_ip {
        if is_cloudflare_ip(upstream_ip) {
            if let Some(cf_ip) = headers
                .get("cf-connecting-ip")
                .and_then(|v| v.to_str().ok())
                .map(str::trim)
                .and_then(|s| s.parse::<IpAddr>().ok())
            {
                return (cf_ip.to_string(), IpSource::CloudflareEdge);
            }
        }
        if upstream_ip.is_loopback() {
            return (upstream_ip.to_string(), IpSource::Loopback);
        }
        return (upstream_ip.to_string(), IpSource::Direct);
    }

    if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        for part in xff.rsplit(',') {
            if let Ok(ip) = part.trim().parse::<IpAddr>() {
                if !ip.is_loopback() {
                    return (ip.to_string(), IpSource::Direct);
                }
            }
        }
    }

    match peer {
        Some(addr) => {
            let src = if addr.ip().is_loopback() {
                IpSource::Loopback
            } else {
                IpSource::Direct
            };
            (addr.ip().to_string(), src)
        }
        None => ("127.0.0.1".to_string(), IpSource::Loopback),
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Debug, Clone)]
struct BanEntry {
    strikes: u32,
    banned_until: u64,
}

/// Live anti-DDoS guard metrics & state shared with `/mcpgw` dashboard.
pub struct McpGuardState {
    pub cfg_store: Arc<GatewayConfigStore>,
    pub ip_limiter: KeyedTokenBucket<String>,
    pub key_limiter: KeyedTokenBucket<String>,
    pub concurrency_sem: Arc<Semaphore>,
    bans: DashMap<String, BanEntry>,
    pub total_requests: AtomicU64,
    pub blocked_rate_limit: AtomicU64,
    pub blocked_banned: AtomicU64,
    pub blocked_auth: AtomicU64,
}

impl McpGuardState {
    pub fn new(cfg_store: Arc<GatewayConfigStore>) -> Self {
        let lim = cfg_store.snapshot().limits;
        let ip_burst = if lim.ip_rpm == 0 {
            0
        } else {
            (lim.ip_rpm / 4).clamp(20, 200)
        };
        let key_burst = if lim.key_rpm == 0 {
            0
        } else {
            (lim.key_rpm / 4).clamp(15, 200)
        };
        Self {
            cfg_store,
            ip_limiter: KeyedTokenBucket::new(lim.ip_rpm, ip_burst, DEFAULT_MAX_BUCKET_KEYS),
            key_limiter: KeyedTokenBucket::new(lim.key_rpm, key_burst, DEFAULT_MAX_BUCKET_KEYS),
            concurrency_sem: Arc::new(Semaphore::new(lim.max_concurrency)),
            bans: DashMap::new(),
            total_requests: AtomicU64::new(0),
            blocked_rate_limit: AtomicU64::new(0),
            blocked_banned: AtomicU64::new(0),
            blocked_auth: AtomicU64::new(0),
        }
    }

    pub fn sync_rates_from_config(&self) {
        let lim = self.cfg_store.snapshot().limits;
        let ip_burst = if lim.ip_rpm == 0 {
            0
        } else {
            (lim.ip_rpm / 4).clamp(20, 200)
        };
        let key_burst = if lim.key_rpm == 0 {
            0
        } else {
            (lim.key_rpm / 4).clamp(15, 200)
        };
        self.ip_limiter.set_rate(lim.ip_rpm, ip_burst);
        self.key_limiter.set_rate(lim.key_rpm, key_burst);
    }

    pub fn is_ip_banned(&self, ip: &str) -> bool {
        let cfg = self.cfg_store.snapshot();
        if cfg.ip_denylist.contains(ip) {
            return true;
        }
        if let Some(entry) = self.bans.get(ip) {
            if entry.banned_until > now_unix() {
                return true;
            }
        }
        false
    }

    pub fn record_auth_failure(&self, ip: &str) {
        if ip == "127.0.0.1" || ip == "::1" {
            return;
        }
        self.blocked_auth.fetch_add(1, Ordering::Relaxed);
        let lim = self.cfg_store.snapshot().limits;
        if self.bans.len() > 4096 {
            let now = now_unix();
            self.bans.retain(|_, v| v.banned_until > now);
        }
        let mut entry = self.bans.entry(ip.to_string()).or_insert(BanEntry {
            strikes: 0,
            banned_until: 0,
        });
        entry.strikes = entry.strikes.saturating_add(1);
        if entry.strikes >= lim.auto_ban_threshold {
            entry.banned_until = now_unix().saturating_add(lim.auto_ban_secs);
            entry.strikes = 0;
            warn!(ip = %ip, secs = lim.auto_ban_secs, "MCP guard auto-banned IP after repeated auth failures");
        }
    }

    pub fn clear_ip_ban(&self, ip: &str) {
        self.bans.remove(ip);
    }

    pub fn active_temp_bans(&self) -> Vec<(String, u64)> {
        let now = now_unix();
        self.bans
            .iter()
            .filter_map(|e| {
                if e.banned_until > now {
                    Some((e.key().clone(), e.banned_until - now))
                } else {
                    None
                }
            })
            .collect()
    }
}

fn normalize_host(raw: &str) -> String {
    let trimmed = raw.trim().to_ascii_lowercase();
    if trimmed.starts_with('[') {
        if let Some(end) = trimmed.find(']') {
            return trimmed[..=end].to_string();
        }
    }
    trimmed.split(':').next().unwrap_or("").to_string()
}

fn attach_mcp_headers(resp: &mut Response, allow_cors: bool, origin: Option<&str>) {
    let hdrs = resp.headers_mut();
    hdrs.entry(header::X_CONTENT_TYPE_OPTIONS)
        .or_insert_with(|| HeaderValue::from_static("nosniff"));
    hdrs.entry(header::REFERRER_POLICY)
        .or_insert_with(|| HeaderValue::from_static("no-referrer"));
    hdrs.entry(header::CACHE_CONTROL)
        .or_insert_with(|| HeaderValue::from_static("no-store"));
    hdrs.entry(HeaderName::from_static("x-frame-options"))
        .or_insert_with(|| HeaderValue::from_static("DENY"));
    if allow_cors {
        let cors_origin = origin
            .and_then(|o| HeaderValue::from_str(o).ok())
            .unwrap_or_else(|| HeaderValue::from_static("*"));
        hdrs.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, cors_origin);
        hdrs.insert(
            header::ACCESS_CONTROL_ALLOW_METHODS,
            HeaderValue::from_static("GET, POST, DELETE, OPTIONS"),
        );
        hdrs.insert(
            header::ACCESS_CONTROL_ALLOW_HEADERS,
            HeaderValue::from_static(
                "Authorization, Content-Type, Accept, Mcp-Session-Id, MCP-Protocol-Version, Last-Event-ID, Mcp-Method, Mcp-Name",
            ),
        );
        hdrs.insert(
            header::ACCESS_CONTROL_EXPOSE_HEADERS,
            HeaderValue::from_static("Mcp-Session-Id, MCP-Protocol-Version, WWW-Authenticate"),
        );
    }
}

async fn guard_middleware(
    State(state): State<Arc<McpGuardState>>,
    req: Request,
    next: Next,
) -> Response {
    let path = req.uri().path().to_string();
    let method = req.method().clone();
    let origin = req
        .headers()
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    // CORS preflight for OAuth discovery, registration, and Streamable HTTP clients (Claude.ai, web IDEs)
    if method == Method::OPTIONS {
        let mut resp = StatusCode::NO_CONTENT.into_response();
        attach_mcp_headers(&mut resp, true, origin.as_deref());
        return resp;
    }

    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0);
    let (client_ip, ip_src) = extract_verified_client_ip(peer, req.headers());

    // Localhost healthz bypass
    if path == "/healthz" && ip_src == IpSource::Loopback {
        let mut resp = next.run(req).await;
        attach_mcp_headers(&mut resp, false, None);
        return resp;
    }

    state.total_requests.fetch_add(1, Ordering::Relaxed);
    let cfg = state.cfg_store.snapshot();

    // DNS Rebinding Host check
    if let Some(host_val) = req.headers().get(header::HOST).and_then(|v| v.to_str().ok()) {
        let norm = normalize_host(host_val);
        if !norm.is_empty() && !cfg.allowed_hosts().contains(&norm) {
            warn!(host = %norm, ip = %client_ip, "MCP guard rejected disallowed Host header (DNS rebinding guard)");
            let mut resp = (
                StatusCode::FORBIDDEN,
                Json(json!({"error": "disallowed_host"})),
            )
                .into_response();
            attach_mcp_headers(&mut resp, false, None);
            return resp;
        }
    }

    // IP allowlist & ban checks
    if !cfg.ip_allowlist.is_empty()
        && ip_src != IpSource::Loopback
        && !cfg.ip_allowlist.contains(&client_ip)
    {
        state.blocked_banned.fetch_add(1, Ordering::Relaxed);
        let mut resp = (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "ip_not_allowed"})),
        )
            .into_response();
        attach_mcp_headers(&mut resp, true, origin.as_deref());
        return resp;
    }

    if state.is_ip_banned(&client_ip) {
        state.blocked_banned.fetch_add(1, Ordering::Relaxed);
        let mut resp = (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "ip_temporarily_banned"})),
        )
            .into_response();
        attach_mcp_headers(&mut resp, true, origin.as_deref());
        return resp;
    }

    // Per-IP rate limit
    let rl = state.ip_limiter.check(client_ip.clone(), 1);
    if !rl.allowed {
        state.blocked_rate_limit.fetch_add(1, Ordering::Relaxed);
        let mut resp = (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({
                "error": "rate_limited",
                "retry_after": rl.retry_after_secs
            })),
        )
            .into_response();
        if let Ok(hv) = HeaderValue::from_str(&rl.retry_after_secs.to_string()) {
            resp.headers_mut().insert(header::RETRY_AFTER, hv);
        }
        attach_mcp_headers(&mut resp, true, origin.as_deref());
        return resp;
    }

    // Content-Length body limit guard
    if let Some(cl) = req
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<usize>().ok())
    {
        if cl > cfg.limits.max_body_bytes {
            let mut resp = (
                StatusCode::PAYLOAD_TOO_LARGE,
                Json(json!({"error": "payload_too_large"})),
            )
                .into_response();
            attach_mcp_headers(&mut resp, true, origin.as_deref());
            return resp;
        }
    }

    // Concurrency cap
    let Ok(_permit) = state.concurrency_sem.clone().try_acquire_owned() else {
        let mut resp = (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "gateway_busy"})),
        )
            .into_response();
        resp.headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("2"));
        attach_mcp_headers(&mut resp, true, origin.as_deref());
        return resp;
    };

    let mut req = req;
    req.extensions_mut().insert(VerifiedClientIp(client_ip.clone()));

    let mut resp = next.run(req).await;
    if resp.status() == StatusCode::UNAUTHORIZED {
        // Don't penalize standard OAuth discovery 401 probe on first hit too harshly; still counted
        state.record_auth_failure(&client_ip);
    }
    attach_mcp_headers(&mut resp, true, origin.as_deref());
    resp
}

/// Request extension holding the verified client IP after `McpGuard`.
#[derive(Debug, Clone)]
pub struct VerifiedClientIp(pub String);

pub fn apply_mcp_guard(router: Router, state: Arc<McpGuardState>) -> Router {
    router.layer(middleware::from_fn_with_state(state, guard_middleware))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::routing::get;
    use tempfile::TempDir;
    use tower::ServiceExt;

    #[test]
    fn spoofed_cf_connecting_ip_is_ignored_when_peer_is_not_cloudflare() {
        let mut hdrs = HeaderMap::new();
        // Attacker hitting direct mcp.example.com: Caddy sets X-Real-IP to attacker IP
        hdrs.insert("x-real-ip", HeaderValue::from_static("203.0.113.55"));
        hdrs.insert("cf-connecting-ip", HeaderValue::from_static("1.1.1.1"));
        let loopback: SocketAddr = "127.0.0.1:40000".parse().unwrap();
        let (ip, src) = extract_verified_client_ip(Some(loopback), &hdrs);
        assert_eq!(ip, "203.0.113.55");
        assert_eq!(src, IpSource::Direct);

        // Real Cloudflare edge IP (104.16.1.2) -> CF-Connecting-IP IS trusted!
        let mut cf_hdrs = HeaderMap::new();
        cf_hdrs.insert("x-real-ip", HeaderValue::from_static("104.16.1.2"));
        cf_hdrs.insert("cf-connecting-ip", HeaderValue::from_static("198.51.100.77"));
        let (ip2, src2) = extract_verified_client_ip(Some(loopback), &cf_hdrs);
        assert_eq!(ip2, "198.51.100.77");
        assert_eq!(src2, IpSource::CloudflareEdge);
    }

    #[tokio::test]
    async fn guard_enforces_host_check_and_auto_ban_on_repeated_401() {
        let dir = TempDir::new().unwrap();
        let cfg_store = Arc::new(GatewayConfigStore::open(dir.path().join("gw.json")).unwrap());
        cfg_store
            .update(|c| {
                c.limits.auto_ban_threshold = 3;
                c.limits.ip_rpm = 100;
            })
            .unwrap();
        let guard = Arc::new(McpGuardState::new(cfg_store));

        let app = apply_mcp_guard(
            Router::new().route("/mcp", get(|| async { StatusCode::UNAUTHORIZED })),
            Arc::clone(&guard),
        );

        // Disallowed Host rejected (DNS rebinding guard)
        let bad_host = Request::builder()
            .uri("/mcp")
            .header(header::HOST, "evil.attacker.com")
            .header("x-real-ip", "203.0.113.9")
            .body(Body::empty())
            .unwrap();
        let r = app.clone().oneshot(bad_host).await.unwrap();
        assert_eq!(r.status(), StatusCode::FORBIDDEN);

        // 3 consecutive 401s trigger auto-ban on 4th request
        for _ in 0..3 {
            let req = Request::builder()
                .uri("/mcp")
                .header(header::HOST, "mcp.example.com")
                .header("x-real-ip", "203.0.113.88")
                .body(Body::empty())
                .unwrap();
            let resp = app.clone().oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        }
        let banned_req = Request::builder()
            .uri("/mcp")
            .header(header::HOST, "mcp.example.com")
            .header("x-real-ip", "203.0.113.88")
            .body(Body::empty())
            .unwrap();
        let banned_resp = app.clone().oneshot(banned_req).await.unwrap();
        assert_eq!(banned_resp.status(), StatusCode::FORBIDDEN);
    }
}
