//! Anti-DDoS and security-header middleware for the Axum HTTP server (`:8787`),
//! protecting `/w/*`, `/api/w/*`, `/tg/webhook`, and `/healthz`.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use agy_core::security::{KeyedTokenBucket, DEFAULT_MAX_BUCKET_KEYS};
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use serde_json::json;
use tokio::sync::Semaphore;
use tracing::warn;

/// Configuration for the HTTP anti-DDoS middleware layer.
#[derive(Debug, Clone, Copy)]
pub struct HttpGuardConfig {
    /// Sustained per-IP requests per minute (`0` = disabled).
    pub rl_per_min: u32,
    /// Maximum concurrent in-flight HTTP requests across all routes.
    pub max_concurrency: usize,
    /// Per-request processing timeout in seconds.
    pub req_timeout_secs: u64,
}

impl Default for HttpGuardConfig {
    fn default() -> Self {
        Self {
            rl_per_min: 120,
            max_concurrency: 64,
            req_timeout_secs: 30,
        }
    }
}

struct HttpGuardState {
    limiter: KeyedTokenBucket<String>,
    sem: Arc<Semaphore>,
    timeout: Duration,
}

impl HttpGuardState {
    fn new(cfg: HttpGuardConfig) -> Self {
        let burst = if cfg.rl_per_min == 0 {
            0
        } else {
            (cfg.rl_per_min / 4).clamp(15, 200)
        };
        Self {
            limiter: KeyedTokenBucket::new(cfg.rl_per_min, burst, DEFAULT_MAX_BUCKET_KEYS),
            sem: Arc::new(Semaphore::new(cfg.max_concurrency.clamp(1, 2048))),
            timeout: Duration::from_secs(cfg.req_timeout_secs.clamp(1, 300)),
        }
    }
}

/// Extract the effective client IP for rate limiting.
///
/// Forwarding headers (`X-Real-IP`, `X-Forwarded-For`) are ONLY trusted when the direct TCP
/// peer is loopback (e.g. local nginx reverse proxy), preventing external spoofing.
pub fn extract_client_ip(peer: Option<SocketAddr>, headers: &HeaderMap) -> (String, bool) {
    let is_loopback_peer = peer.map(|a| a.ip().is_loopback()).unwrap_or(true);
    if is_loopback_peer {
        if let Some(real) = headers
            .get("x-real-ip")
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
            .filter(|s| !s.is_empty() && s.parse::<IpAddr>().is_ok())
        {
            let lb = real.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback());
            return (real.to_string(), lb);
        }
        if let Some(xff) = headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
        {
            // Rightmost valid non-loopback hop added by our trusted local proxy.
            for part in xff.rsplit(',') {
                let candidate = part.trim();
                if let Ok(ip) = candidate.parse::<IpAddr>() {
                    if !ip.is_loopback() {
                        return (ip.to_string(), false);
                    }
                }
            }
        }
    }
    match peer {
        Some(addr) => (addr.ip().to_string(), addr.ip().is_loopback()),
        None => ("127.0.0.1".to_string(), true),
    }
}

fn attach_security_headers(resp: &mut Response) {
    let hdrs = resp.headers_mut();
    hdrs.entry(header::X_CONTENT_TYPE_OPTIONS)
        .or_insert_with(|| HeaderValue::from_static("nosniff"));
    hdrs.entry(header::REFERRER_POLICY)
        .or_insert_with(|| HeaderValue::from_static("no-referrer"));
    hdrs.entry(HeaderName::from_static("permissions-policy"))
        .or_insert_with(|| {
            HeaderValue::from_static("camera=(), microphone=(), geolocation=(), payment=()")
        });
    hdrs.entry(HeaderName::from_static("x-permitted-cross-domain-policies"))
        .or_insert_with(|| HeaderValue::from_static("none"));
}

async fn http_guard_middleware(
    State(state): State<Arc<HttpGuardState>>,
    req: Request,
    next: Next,
) -> Response {
    let path = req.uri().path().to_string();
    let peer = req.extensions().get::<ConnectInfo<SocketAddr>>().map(|ci| ci.0);
    let (client_ip, client_is_loopback) = extract_client_ip(peer, req.headers());

    // Localhost health checks bypass rate/concurrency caps so systemd & cutover probes stay reliable.
    if path == "/healthz" && client_is_loopback {
        let mut resp = next.run(req).await;
        attach_security_headers(&mut resp);
        return resp;
    }

    let Ok(_permit) = state.sem.clone().try_acquire_owned() else {
        warn!(ip = %client_ip, path = %path, "HTTP concurrency limit saturated; returning 503");
        let mut resp = (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "ok": false, "error": "server_busy" })),
        )
            .into_response();
        resp.headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("2"));
        attach_security_headers(&mut resp);
        return resp;
    };

    let rl = state.limiter.check(client_ip.clone(), 1);
    if !rl.allowed {
        warn!(
            ip = %client_ip,
            path = %path,
            retry_after = rl.retry_after_secs,
            "HTTP per-IP rate limit exceeded; returning 429"
        );
        let mut resp = (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({
                "ok": false,
                "error": "rate_limited",
                "retry_after": rl.retry_after_secs,
            })),
        )
            .into_response();
        if let Ok(hv) = HeaderValue::from_str(&rl.retry_after_secs.to_string()) {
            resp.headers_mut().insert(header::RETRY_AFTER, hv);
        }
        attach_security_headers(&mut resp);
        return resp;
    }

    let mut resp = match tokio::time::timeout(state.timeout, next.run(req)).await {
        Ok(r) => r,
        Err(_) => {
            warn!(ip = %client_ip, path = %path, "HTTP request timed out; returning 408");
            (
                StatusCode::REQUEST_TIMEOUT,
                Json(json!({ "ok": false, "error": "request_timeout" })),
            )
                .into_response()
        }
    };
    attach_security_headers(&mut resp);
    resp
}

/// Wrap an Axum [`Router`] with anti-DDoS concurrency cap, per-IP rate limiting, request timeout,
/// and security response headers.
pub fn apply_http_guard(router: Router, cfg: HttpGuardConfig) -> Router {
    let state = Arc::new(HttpGuardState::new(cfg));
    router.layer(middleware::from_fn_with_state(state, http_guard_middleware))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::routing::get;
    use tower::ServiceExt;

    #[test]
    fn extract_ip_trusts_headers_only_from_loopback() {
        let mut hdrs = HeaderMap::new();
        hdrs.insert("x-real-ip", HeaderValue::from_static("203.0.113.7"));

        let local_peer: SocketAddr = "127.0.0.1:45678".parse().unwrap();
        assert_eq!(
            extract_client_ip(Some(local_peer), &hdrs),
            ("203.0.113.7".to_string(), false)
        );

        let remote_peer: SocketAddr = "198.51.100.9:55555".parse().unwrap();
        assert_eq!(
            extract_client_ip(Some(remote_peer), &hdrs),
            ("198.51.100.9".to_string(), false)
        );
    }

    #[tokio::test]
    async fn http_guard_enforces_rate_limit_headers_healthz_bypass_and_timeout() {
        let base = Router::new()
            .route("/healthz", get(|| async { "ok" }))
            .route("/ping", get(|| async { "pong" }))
            .route(
                "/slow",
                get(|| async {
                    tokio::time::sleep(Duration::from_secs(3)).await;
                    "late"
                }),
            );
        let app = apply_http_guard(
            base,
            HttpGuardConfig {
                rl_per_min: 10, // burst clamps to 15
                max_concurrency: 2,
                req_timeout_secs: 1,
            },
        );

        // First 15 requests from same IP pass and receive security headers
        for _ in 0..15 {
            let req = Request::builder()
                .uri("/ping")
                .header("x-real-ip", "203.0.113.42")
                .body(Body::empty())
                .unwrap();
            let resp = app.clone().oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            assert_eq!(
                resp.headers().get(header::REFERRER_POLICY).unwrap(),
                "no-referrer"
            );
            assert!(resp.headers().contains_key("permissions-policy"));
            assert_eq!(
                resp.headers().get(header::X_CONTENT_TYPE_OPTIONS).unwrap(),
                "nosniff"
            );
        }

        // 16th immediate request hits 429 with Retry-After
        let req16 = Request::builder()
            .uri("/ping")
            .header("x-real-ip", "203.0.113.42")
            .body(Body::empty())
            .unwrap();
        let resp16 = app.clone().oneshot(req16).await.unwrap();
        assert_eq!(resp16.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(resp16.headers().contains_key(header::RETRY_AFTER));

        // Loopback /healthz bypasses rate limit cleanly
        for _ in 0..25 {
            let req = Request::builder()
                .uri("/healthz")
                .body(Body::empty())
                .unwrap();
            let resp = app.clone().oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
        }

        // Slow endpoint triggers 408 Request Timeout
        let slow_req = Request::builder()
            .uri("/slow")
            .header("x-real-ip", "203.0.113.99")
            .body(Body::empty())
            .unwrap();
        let slow_resp = app.clone().oneshot(slow_req).await.unwrap();
        assert_eq!(slow_resp.status(), StatusCode::REQUEST_TIMEOUT);

        // Concurrency cap returns 503 with Retry-After when saturated
        let conc_app = apply_http_guard(
            Router::new().route(
                "/hold",
                get(|| async {
                    tokio::time::sleep(Duration::from_millis(350)).await;
                    "held"
                }),
            ),
            HttpGuardConfig {
                rl_per_min: 120,
                max_concurrency: 1,
                req_timeout_secs: 5,
            },
        );
        let app_a = conc_app.clone();
        let t1 = tokio::spawn(async move {
            app_a
                .oneshot(
                    Request::builder()
                        .uri("/hold")
                        .header("x-real-ip", "198.51.100.1")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap()
        });
        tokio::time::sleep(Duration::from_millis(40)).await;
        let resp_busy = conc_app
            .oneshot(
                Request::builder()
                    .uri("/hold")
                    .header("x-real-ip", "198.51.100.2")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp_busy.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(resp_busy.headers().get(header::RETRY_AFTER).unwrap(), "2");
        assert_eq!(t1.await.unwrap().status(), StatusCode::OK);
    }
}
