//! Universal MCP Transport Layer:
//! - Streamable HTTP 2025 Stateful (`Mcp-Session-Id`, `Last-Event-ID`, `GET`/`POST`/`DELETE`)
//! - Streamable HTTP 2026 Stateless (`MCP-Protocol-Version`, `Mcp-Method`, `Mcp-Name`)
//! - Legacy HTTP+SSE (`GET /sse` + `POST /messages?sessionId=...`)
//! - 15-second SSE keep-alive heartbeats (`: ping\n\n`) for Cloudflare compatibility
//! - MCP Tools, Resources, and Prompts + Smart Hub Progressive Discovery + HITL + Audit.

use std::convert::Infallible;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use dashmap::DashMap;
use futures_util::stream;
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::sync::{mpsc, watch};
use uuid::Uuid;

use crate::audit::AuditLogger;
use crate::auth::{AuthenticatedPrincipal, KeyStore};
use crate::config::{GatewayConfigStore, GatewayMode, SectionId};
use crate::guard::{McpGuardState, VerifiedClientIp};
use crate::hitl::{HitlBroker, HitlDecision};
use crate::oauth::OAuthStore;
use crate::policy::{PolicyDecision, PolicyEngine};
use crate::registry::{discover_tools, smart_hub_meta_tools, ToolSpec};
use crate::sanitize::{sanitize_tool_output, DEFAULT_TOOL_OUTPUT_MAX_BYTES};
use crate::sections::{dispatch_section_tool, SectionEnv};
use crate::tasks::TaskManager;

const SUPPORTED_VERSIONS: &[&str] = &[
    "2026-07-28",
    "2025-11-25",
    "2025-06-18",
    "2025-03-26",
    "2024-11-05",
];

const PINNED_HUB_ESSENTIALS: &[&str] = &[
    "models_current",
    "models_switch",
    "session_list",
    "opt_classify_turn",
    "opt_prompt_analyze",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointScope {
    SmartHub,
    AllAllowed,
    Section(SectionId),
}

struct LegacySseSession {
    principal_id: String,
    tx: mpsc::Sender<String>,
}

/// Core shared state backing all MCP HTTP/SSE/OAuth endpoints.
pub struct McpRuntime {
    pub cfg_store: Arc<GatewayConfigStore>,
    pub keys: Arc<KeyStore>,
    pub oauth: Arc<OAuthStore>,
    pub guard: Arc<McpGuardState>,
    pub policy: Arc<PolicyEngine>,
    pub hitl: Arc<HitlBroker>,
    pub audit: Arc<AuditLogger>,
    pub tasks: Arc<TaskManager>,
    pub section_env: Arc<SectionEnv>,
    pub catalog: Arc<Vec<ToolSpec>>,
    /// Active stateful Streamable HTTP sessions (`Mcp-Session-Id -> principal_id`).
    pub sessions: DashMap<String, String>,
    /// Active legacy `/sse` channels (`session_id -> sender`).
    legacy_sse: DashMap<String, LegacySseSession>,
}

impl McpRuntime {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        cfg_store: Arc<GatewayConfigStore>,
        keys: Arc<KeyStore>,
        oauth: Arc<OAuthStore>,
        guard: Arc<McpGuardState>,
        policy: Arc<PolicyEngine>,
        hitl: Arc<HitlBroker>,
        audit: Arc<AuditLogger>,
        tasks: Arc<TaskManager>,
        section_env: Arc<SectionEnv>,
        catalog: Vec<ToolSpec>,
    ) -> Self {
        Self {
            cfg_store,
            keys,
            oauth,
            guard,
            policy,
            hitl,
            audit,
            tasks,
            section_env,
            catalog: Arc::new(catalog),
            sessions: DashMap::new(),
            legacy_sse: DashMap::new(),
        }
    }

    pub fn active_session_count(&self) -> usize {
        self.sessions.len() + self.legacy_sse.len()
    }

    fn base_url(&self, headers: &HeaderMap) -> String {
        let host = headers
            .get(header::HOST)
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| self.cfg_store.snapshot().primary_domain);
        let proto = headers
            .get("x-forwarded-proto")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("https");
        format!("{proto}://{host}")
    }

    /// Authenticate via Bearer API Key (`agymcp_...`) OR OAuth 2.1 access token (`agyoa_...`).
    fn authenticate(&self, headers: &HeaderMap) -> Option<AuthenticatedPrincipal> {
        let auth = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .map(str::trim)?;
        let token = auth
            .strip_prefix("Bearer ")
            .or_else(|| auth.strip_prefix("bearer "))?
            .trim();
        if token.is_empty() {
            return None;
        }
        if let Some(p) = self.keys.verify_bearer(token) {
            return Some(p);
        }
        let base = self.base_url(headers);
        self.oauth.verify_access_token(token, Some(&base))
    }

    fn unauthorized_response(&self, headers: &HeaderMap) -> Response {
        let base = self.base_url(headers);
        let www_val = format!(
            "Bearer resource_metadata=\"{base}/.well-known/oauth-protected-resource\""
        );
        let mut resp = (
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "unauthorized",
                "message": "Authentication required. Provide Authorization: Bearer <token> or complete OAuth 2.1 flow."
            })),
        )
            .into_response();
        if let Ok(hv) = HeaderValue::from_str(&www_val) {
            resp.headers_mut().insert(header::WWW_AUTHENTICATE, hv);
        }
        resp
    }
}

pub fn build_mcp_protocol_router(rt: Arc<McpRuntime>) -> Router {
    Router::new()
        .route("/healthz", get(handle_healthz))
        .route(
            "/mcp",
            post(handle_mcp_hub_post)
                .get(handle_mcp_get_sse)
                .delete(handle_mcp_delete),
        )
        .route(
            "/mcp/all",
            post(handle_mcp_all_post)
                .get(handle_mcp_get_sse)
                .delete(handle_mcp_delete),
        )
        .route(
            "/mcp/s/{section}",
            post(handle_mcp_section_post)
                .get(handle_mcp_get_sse)
                .delete(handle_mcp_delete),
        )
        .route("/sse", get(handle_legacy_sse))
        .route("/messages", post(handle_legacy_messages))
        .with_state(rt)
}

async fn handle_healthz(State(rt): State<Arc<McpRuntime>>) -> Response {
    let cfg = rt.cfg_store.snapshot();
    Json(json!({
        "ok": cfg.mode != GatewayMode::Disabled,
        "service": "agy-mcp-gateway",
        "mode": cfg.mode.as_str(),
        "active_sessions": rt.active_session_count(),
        "running_tasks": rt.tasks.running_count(),
        "tools_total": rt.catalog.len(),
        "protocols": SUPPORTED_VERSIONS
    }))
    .into_response()
}

async fn handle_mcp_hub_post(
    State(rt): State<Arc<McpRuntime>>,
    headers: HeaderMap,
    ext_ip: Option<axum::Extension<VerifiedClientIp>>,
    Json(body): Json<Value>,
) -> Response {
    handle_mcp_post_inner(rt, headers, ext_ip, EndpointScope::SmartHub, body).await
}

async fn handle_mcp_all_post(
    State(rt): State<Arc<McpRuntime>>,
    headers: HeaderMap,
    ext_ip: Option<axum::Extension<VerifiedClientIp>>,
    Json(body): Json<Value>,
) -> Response {
    handle_mcp_post_inner(rt, headers, ext_ip, EndpointScope::AllAllowed, body).await
}

async fn handle_mcp_section_post(
    State(rt): State<Arc<McpRuntime>>,
    Path(sec_slug): Path<String>,
    headers: HeaderMap,
    ext_ip: Option<axum::Extension<VerifiedClientIp>>,
    Json(body): Json<Value>,
) -> Response {
    let Some(sec) = SectionId::parse_slug(&sec_slug) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({
                "jsonrpc": "2.0",
                "error": {"code": -32601, "message": format!("Unknown MCP section '{sec_slug}'. Valid: openhands, search, skillhub, memory, codeintel, models, sessions, optimizer, federation, browser")}
            })),
        )
            .into_response();
    };
    handle_mcp_post_inner(rt, headers, ext_ip, EndpointScope::Section(sec), body).await
}

async fn handle_mcp_post_inner(
    rt: Arc<McpRuntime>,
    headers: HeaderMap,
    ext_ip: Option<axum::Extension<VerifiedClientIp>>,
    scope: EndpointScope,
    body: Value,
) -> Response {
    let cfg = rt.cfg_store.snapshot();
    if cfg.mode == GatewayMode::Disabled {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "gateway_disabled", "message": "AGY MCP Gateway is paused by owner kill switch"})),
        )
            .into_response();
    }

    let Some(principal) = rt.authenticate(&headers) else {
        return rt.unauthorized_response(&headers);
    };

    // Per-key rate limit check
    let rl = rt.guard.key_limiter.check(principal.principal_id.clone(), 1);
    if !rl.allowed {
        let mut resp = (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({"error": "key_rate_limited", "retry_after": rl.retry_after_secs})),
        )
            .into_response();
        if let Ok(hv) = HeaderValue::from_str(&rl.retry_after_secs.to_string()) {
            resp.headers_mut().insert(header::RETRY_AFTER, hv);
        }
        return resp;
    }

    // Validate MCP-Protocol-Version header when provided (2025/2026 spec compliance)
    let hdr_ver = headers
        .get("mcp-protocol-version")
        .and_then(|v| v.to_str().ok())
        .map(str::trim);
    if let Some(v) = hdr_ver {
        if !v.is_empty() && !SUPPORTED_VERSIONS.contains(&v) {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "jsonrpc": "2.0",
                    "id": body.get("id").cloned().unwrap_or(Value::Null),
                    "error": {"code": -32020, "message": format!("Unsupported MCP-Protocol-Version '{v}'. Supported: {}", SUPPORTED_VERSIONS.join(", "))}
                })),
            )
                .into_response();
        }
    }

    let client_ip = ext_ip
        .map(|e| e.0 .0)
        .unwrap_or_else(|| "127.0.0.1".to_string());

    // Handle JSON-RPC batch or single message
    let mut new_session_id: Option<String> = None;
    let negotiated_ver = hdr_ver.unwrap_or("2025-11-25").to_string();

    if let Some(arr) = body.as_array() {
        let mut responses = Vec::new();
        for item in arr {
            if let Some((resp_val, sid)) =
                process_jsonrpc_message(&rt, &principal, &client_ip, scope, item).await
            {
                if sid.is_some() {
                    new_session_id = sid;
                }
                responses.push(resp_val);
            }
        }
        if responses.is_empty() {
            return StatusCode::ACCEPTED.into_response();
        }
        let mut http_resp = Json(Value::Array(responses)).into_response();
        attach_protocol_headers(&mut http_resp, new_session_id.as_deref(), &negotiated_ver);
        return http_resp;
    }

    match process_jsonrpc_message(&rt, &principal, &client_ip, scope, &body).await {
        None => StatusCode::ACCEPTED.into_response(),
        Some((resp_val, sid)) => {
            let ver = resp_val
                .get("result")
                .and_then(|r| r.get("protocolVersion"))
                .and_then(Value::as_str)
                .unwrap_or(&negotiated_ver)
                .to_string();
            let mut http_resp = Json(resp_val).into_response();
            attach_protocol_headers(&mut http_resp, sid.as_deref(), &ver);
            http_resp
        }
    }
}

fn attach_protocol_headers(resp: &mut Response, session_id: Option<&str>, version: &str) {
    if let Some(sid) = session_id {
        if let Ok(hv) = HeaderValue::from_str(sid) {
            resp.headers_mut()
                .insert(HeaderName::from_static("mcp-session-id"), hv);
        }
    }
    if let Ok(hv) = HeaderValue::from_str(version) {
        resp.headers_mut()
            .insert(HeaderName::from_static("mcp-protocol-version"), hv);
    }
}

/// Streamable HTTP `GET /mcp` SSE stream with 15s keep-alive heartbeats (Cloudflare-safe).
async fn handle_mcp_get_sse(
    State(rt): State<Arc<McpRuntime>>,
    headers: HeaderMap,
) -> Response {
    if rt.cfg_store.snapshot().mode == GatewayMode::Disabled {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    let Some(_principal) = rt.authenticate(&headers) else {
        return rt.unauthorized_response(&headers);
    };

    let init_evt = stream::once(async {
        Ok::<Event, Infallible>(Event::default().comment("agy-mcp-gateway stream ready"))
    });
    let pending = stream::pending::<std::result::Result<Event, Infallible>>();
    let combined = futures_util::StreamExt::chain(init_evt, pending);

    Sse::new(combined)
        .keep_alive(
            KeepAlive::new()
                .interval(Duration::from_secs(15))
                .text("ping"),
        )
        .into_response()
}

/// Streamable HTTP `DELETE /mcp` session teardown.
async fn handle_mcp_delete(
    State(rt): State<Arc<McpRuntime>>,
    headers: HeaderMap,
) -> Response {
    let Some(principal) = rt.authenticate(&headers) else {
        return rt.unauthorized_response(&headers);
    };
    if let Some(sid) = headers.get("mcp-session-id").and_then(|v| v.to_str().ok()) {
        if let Some(entry) = rt.sessions.get(sid) {
            if *entry == principal.principal_id || principal.is_owner {
                drop(entry);
                rt.sessions.remove(sid);
            }
        }
    }
    StatusCode::NO_CONTENT.into_response()
}

/// Legacy HTTP+SSE `GET /sse` endpoint (for older MCP clients).
async fn handle_legacy_sse(
    State(rt): State<Arc<McpRuntime>>,
    headers: HeaderMap,
) -> Response {
    let cfg = rt.cfg_store.snapshot();
    if cfg.mode == GatewayMode::Disabled || !cfg.legacy_sse_enabled {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "legacy_sse_disabled", "hint": "Use Streamable HTTP at POST /mcp"})),
        )
            .into_response();
    }
    let Some(principal) = rt.authenticate(&headers) else {
        return rt.unauthorized_response(&headers);
    };

    let sid = Uuid::new_v4().simple().to_string();
    let (tx, rx) = mpsc::channel::<String>(32);
    rt.legacy_sse.insert(
        sid.clone(),
        LegacySseSession {
            principal_id: principal.principal_id,
            tx,
        },
    );

    let endpoint_uri = format!("/messages?sessionId={sid}");
    let rt_cleanup = Arc::clone(&rt);
    let sid_cleanup = sid.clone();

    let s = async_stream_channel(endpoint_uri, rx, move || {
        rt_cleanup.legacy_sse.remove(&sid_cleanup);
    });

    Sse::new(s)
        .keep_alive(
            KeepAlive::new()
                .interval(Duration::from_secs(15))
                .text("ping"),
        )
        .into_response()
}

fn async_stream_channel<F>(
    endpoint_uri: String,
    rx: mpsc::Receiver<String>,
    on_drop: F,
) -> impl futures_util::Stream<Item = std::result::Result<Event, Infallible>>
where
    F: FnOnce() + Send + 'static,
{
    struct DropGuard<F: FnOnce()>(Option<F>);
    impl<F: FnOnce()> Drop for DropGuard<F> {
        fn drop(&mut self) {
            if let Some(f) = self.0.take() {
                f();
            }
        }
    }

    let first = stream::once(async move {
        Ok::<Event, Infallible>(Event::default().event("endpoint").data(endpoint_uri))
    });
    let guard = DropGuard(Some(on_drop));
    let rest = stream::unfold((rx, guard), |(mut rx, guard)| async move {
        rx.recv().await.map(|msg| {
            (
                Ok::<Event, Infallible>(Event::default().event("message").data(msg)),
                (rx, guard),
            )
        })
    });
    futures_util::StreamExt::chain(first, rest)
}

#[derive(Debug, Deserialize)]
struct LegacyMsgQuery {
    #[serde(rename = "sessionId")]
    session_id: Option<String>,
}

async fn handle_legacy_messages(
    State(rt): State<Arc<McpRuntime>>,
    Query(q): Query<LegacyMsgQuery>,
    headers: HeaderMap,
    ext_ip: Option<axum::Extension<VerifiedClientIp>>,
    Json(body): Json<Value>,
) -> Response {
    let cfg = rt.cfg_store.snapshot();
    if cfg.mode == GatewayMode::Disabled {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "gateway_disabled", "message": "AGY MCP Gateway is paused by owner kill switch"})),
        )
            .into_response();
    }
    if !cfg.legacy_sse_enabled {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "legacy_sse_disabled", "hint": "Use Streamable HTTP at POST /mcp"})),
        )
            .into_response();
    }
    let Some(principal) = rt.authenticate(&headers) else {
        return rt.unauthorized_response(&headers);
    };
    let rl = rt.guard.key_limiter.check(principal.principal_id.clone(), 1);
    if !rl.allowed {
        let mut resp = (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({"error": "key_rate_limited", "retry_after": rl.retry_after_secs})),
        )
            .into_response();
        if let Ok(hv) = HeaderValue::from_str(&rl.retry_after_secs.to_string()) {
            resp.headers_mut().insert(header::RETRY_AFTER, hv);
        }
        return resp;
    }
    let Some(sid) = q.session_id.as_deref() else {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "missing sessionId"}))).into_response();
    };
    let sender = rt
        .legacy_sse
        .get(sid)
        .filter(|s| s.principal_id == principal.principal_id || principal.is_owner)
        .map(|s| s.tx.clone());
    let Some(tx) = sender else {
        return (StatusCode::NOT_FOUND, Json(json!({"error": "unknown_sse_session"}))).into_response();
    };
    let client_ip = ext_ip
        .map(|e| e.0 .0)
        .unwrap_or_else(|| "127.0.0.1".to_string());
    if let Some(arr) = body.as_array() {
        for item in arr {
            if let Some((resp_val, _)) =
                process_jsonrpc_message(&rt, &principal, &client_ip, EndpointScope::SmartHub, item).await
            {
                if let Ok(line) = serde_json::to_string(&resp_val) {
                    let _ = tx.send(line).await;
                }
            }
        }
    } else if let Some((resp_val, _)) =
        process_jsonrpc_message(&rt, &principal, &client_ip, EndpointScope::SmartHub, &body).await
    {
        if let Ok(line) = serde_json::to_string(&resp_val) {
            let _ = tx.send(line).await;
        }
    }
    StatusCode::ACCEPTED.into_response()
}

/// Process a single JSON-RPC 2.0 MCP message and return `Option<(response_json, optional_new_session_id)>`.
async fn process_jsonrpc_message(
    rt: &Arc<McpRuntime>,
    principal: &AuthenticatedPrincipal,
    client_ip: &str,
    scope: EndpointScope,
    msg: &Value,
) -> Option<(Value, Option<String>)> {
    let method = msg.get("method").and_then(Value::as_str).unwrap_or("");
    let id = msg.get("id").cloned();

    // JSON-RPC notifications have no `id` and expect no reply
    if id.is_none() || method.starts_with("notifications/") {
        return None;
    }
    let id = id.unwrap_or(Value::Null);
    let params = msg.get("params").cloned().unwrap_or_else(|| json!({}));

    match method {
        "initialize" => {
            let req_ver = params
                .get("protocolVersion")
                .and_then(Value::as_str)
                .unwrap_or("2025-11-25");
            let chosen_ver = if SUPPORTED_VERSIONS.contains(&req_ver) {
                req_ver
            } else {
                "2025-11-25"
            };
            let sid = Uuid::new_v4().simple().to_string();
            if rt.sessions.len() > 2048 {
                rt.sessions.clear();
            }
            rt.sessions.insert(sid.clone(), principal.principal_id.clone());
            let scope_name = match scope {
                EndpointScope::SmartHub => "agy-mcp-hub",
                EndpointScope::AllAllowed => "agy-mcp-all",
                EndpointScope::Section(s) => s.slug(),
            };
            Some((
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "protocolVersion": chosen_ver,
                        "capabilities": {
                            "tools": { "listChanged": true },
                            "resources": { "subscribe": false, "listChanged": false },
                            "prompts": { "listChanged": false }
                        },
                        "serverInfo": {
                            "name": format!("agy-telegram-{scope_name}"),
                            "version": env!("CARGO_PKG_VERSION")
                        },
                        "instructions": "AGY Remote MCP Gateway. On /mcp (Smart Hub), use hub_discover_tools -> hub_tool_schema -> hub_call_tool to reach 120+ tools across 10 modular sections without context bloat, or connect directly to /mcp/s/<section>."
                    }
                }),
                Some(sid),
            ))
        }
        "ping" => Some((json!({"jsonrpc": "2.0", "id": id, "result": {}}), None)),
        "tools/list" => {
            let cfg = rt.cfg_store.snapshot();
            let tools = build_tools_list(&rt.catalog, &cfg, principal, scope);
            Some((
                json!({"jsonrpc": "2.0", "id": id, "result": {"tools": tools}}),
                None,
            ))
        }
        "tools/call" => {
            let name = params
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim();
            let args = params
                .get("arguments")
                .cloned()
                .unwrap_or_else(|| json!({}));
            let t0 = Instant::now();
            let res = execute_tool_call(rt, principal, client_ip, scope, name, args).await;
            let ms = t0.elapsed().as_millis() as u64;
            match res {
                Ok(text) => {
                    rt.audit.record(
                        &principal.label,
                        client_ip,
                        scope_slug(scope),
                        name,
                        "ok",
                        ms,
                        &text,
                    );
                    Some((
                        json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "result": {
                                "content": [{"type": "text", "text": text}],
                                "isError": false
                            }
                        }),
                        None,
                    ))
                }
                Err(err_msg) => {
                    let clean_err = agy_ext::mcp_client::redact_secrets_in_text(&err_msg);
                    rt.audit.record(
                        &principal.label,
                        client_ip,
                        scope_slug(scope),
                        name,
                        "error",
                        ms,
                        &clean_err,
                    );
                    Some((
                        json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "result": {
                                "content": [{"type": "text", "text": format!("Error: {clean_err}")}],
                                "isError": true
                            }
                        }),
                        None,
                    ))
                }
            }
        }
        "resources/list" => Some((
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "resources": [
                        {"uri": "agy://gateway/status", "name": "Gateway Status", "mimeType": "application/json", "description": "Live gateway health, enabled sections, and limits"},
                        {"uri": "agy://models/catalog", "name": "Models Catalog", "mimeType": "application/json", "description": "Available Antigravity, Grok, and Venice Uncensored models"},
                        {"uri": "agy://sessions/recent", "name": "Recent Sessions", "mimeType": "application/json", "description": "Recent bot conversations and active session ID"},
                        {"uri": "agy://sessions/handoff", "name": "Session Handoff", "mimeType": "text/markdown", "description": "Current .handoff continuity summary"},
                        {"uri": "agy://skillhub/roster", "name": "SkillHub Roster", "mimeType": "text/markdown", "description": "Superpowers, Anthropic Official Skills, and source matrix"},
                        {"uri": "agy://optimizer/telemetry", "name": "Optimizer Telemetry", "mimeType": "application/json", "description": "RO cache hit rate, AI concurrency slots, and pool health"}
                    ]
                }
            }),
            None,
        )),
        "resources/read" => {
            let uri = params.get("uri").and_then(Value::as_str).unwrap_or("");
            match read_resource(rt, uri).await {
                Ok((mime, text)) => Some((
                    json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": {
                            "contents": [{"uri": uri, "mimeType": mime, "text": text}]
                        }
                    }),
                    None,
                )),
                Err(e) => Some((
                    json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32602, "message": e}}),
                    None,
                )),
            }
        }
        "prompts/list" => Some((
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "prompts": [
                        {
                            "name": "skillhub_workflow",
                            "description": "Load a proven engineering workflow from SkillHub (e.g. test-driven-development, systematic-debugging, security-review).",
                            "arguments": [{"name": "topic", "required": true, "description": "Workflow or skill topic"}]
                        },
                        {
                            "name": "strategic_compact_handoff",
                            "description": "Generate a compact, lossless phase-transition handoff note following ECC strategic-compact.",
                            "arguments": [{"name": "next_phase", "required": true, "description": "What comes next"}]
                        },
                        {
                            "name": "optimize_prompt",
                            "description": "Analyze and upgrade a draft prompt using the 6-phase ECC prompt-optimizer framework.",
                            "arguments": [{"name": "draft", "required": true, "description": "Draft user prompt"}]
                        },
                        {
                            "name": "three_stage_codegen",
                            "description": "Structure a complex multi-file coding task with repo map, plan, and chunked <agy_slot> assembly.",
                            "arguments": [{"name": "goal", "required": true, "description": "Engineering goal"}]
                        }
                    ]
                }
            }),
            None,
        )),
        "prompts/get" => {
            let pname = params.get("name").and_then(Value::as_str).unwrap_or("");
            let pargs = params.get("arguments").cloned().unwrap_or_else(|| json!({}));
            match build_prompt_response(rt, pname, &pargs).await {
                Ok(res) => Some((json!({"jsonrpc": "2.0", "id": id, "result": res}), None)),
                Err(e) => Some((
                    json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32602, "message": e}}),
                    None,
                )),
            }
        }
        other => Some((
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {"code": -32601, "message": format!("Method not found: {other}")}
            }),
            None,
        )),
    }
}

fn scope_slug(scope: EndpointScope) -> &'static str {
    match scope {
        EndpointScope::SmartHub => "hub",
        EndpointScope::AllAllowed => "all",
        EndpointScope::Section(s) => s.slug(),
    }
}

fn build_tools_list(
    catalog: &[ToolSpec],
    cfg: &crate::config::GatewayConfig,
    principal: &AuthenticatedPrincipal,
    scope: EndpointScope,
) -> Vec<Value> {
    match scope {
        EndpointScope::SmartHub => {
            let mut list = smart_hub_meta_tools();
            for spec in catalog {
                if PINNED_HUB_ESSENTIALS.contains(&spec.name.as_str())
                    && cfg.is_section_enabled(spec.section)
                    && (principal.is_owner || principal.has_section(spec.section))
                {
                    list.push(spec.to_mcp_json());
                }
            }
            list
        }
        EndpointScope::AllAllowed => catalog
            .iter()
            .filter(|t| {
                cfg.is_section_enabled(t.section)
                    && (principal.is_owner || principal.has_section(t.section))
            })
            .map(ToolSpec::to_mcp_json)
            .collect(),
        EndpointScope::Section(sec) => {
            if !cfg.is_section_enabled(sec) || (!principal.is_owner && !principal.has_section(sec)) {
                return Vec::new();
            }
            catalog
                .iter()
                .filter(|t| t.section == sec)
                .map(ToolSpec::to_mcp_json)
                .collect()
        }
    }
}

async fn execute_tool_call(
    rt: &Arc<McpRuntime>,
    principal: &AuthenticatedPrincipal,
    client_ip: &str,
    scope: EndpointScope,
    name: &str,
    args: Value,
) -> std::result::Result<String, String> {
    // Handle Smart Hub meta-tools first
    match name {
        "hub_discover_tools" => {
            let query = args.get("query").and_then(Value::as_str).unwrap_or("");
            let sec = args
                .get("section")
                .and_then(Value::as_str)
                .and_then(SectionId::parse_slug);
            let lim = args
                .get("limit")
                .and_then(Value::as_u64)
                .unwrap_or(10)
                .clamp(1, 30) as usize;
            let cfg = rt.cfg_store.snapshot();
            let hits = discover_tools(&rt.catalog, &cfg, principal, query, sec, lim);
            return serde_json::to_string_pretty(&json!({
                "query": query,
                "count": hits.len(),
                "tools": hits
            }))
            .map_err(|e| e.to_string());
        }
        "hub_tool_schema" => {
            let names: Vec<String> = args
                .get("names")
                .and_then(Value::as_array)
                .map(|arr| {
                    arr.iter()
                        .filter_map(Value::as_str)
                        .take(10)
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default();
            let cfg = rt.cfg_store.snapshot();
            let schemas: Vec<Value> = names
                .iter()
                .filter_map(|n| {
                    rt.catalog.iter().find(|t| {
                        t.name == *n
                            && cfg.is_section_enabled(t.section)
                            && (principal.is_owner || principal.has_section(t.section))
                    })
                })
                .map(ToolSpec::to_mcp_json)
                .collect();
            return serde_json::to_string_pretty(&json!({"schemas": schemas}))
                .map_err(|e| e.to_string());
        }
        "hub_list_sections" => {
            let cfg = rt.cfg_store.snapshot();
            let items: Vec<Value> = SectionId::ALL
                .iter()
                .map(|&s| {
                    let cnt = rt.catalog.iter().filter(|t| t.section == s).count();
                    json!({
                        "section": s.slug(),
                        "title": s.title(),
                        "direct_url": format!("https://{}/mcp/s/{}", cfg.primary_domain, s.slug()),
                        "cdn_url": format!("https://{}/mcp/s/{}", cfg.cdn_domain, s.slug()),
                        "enabled_globally": cfg.is_section_enabled(s),
                        "authorized_for_key": principal.is_owner || principal.has_section(s),
                        "tool_count": cnt
                    })
                })
                .collect();
            return serde_json::to_string_pretty(&json!({"sections": items}))
                .map_err(|e| e.to_string());
        }
        "hub_status" => {
            let cfg = rt.cfg_store.snapshot();
            let (hits, misses) = agy_ext::mcp_client::global_mcp_pool().ro_cache_stats();
            return serde_json::to_string_pretty(&json!({
                "mode": cfg.mode.as_str(),
                "principal": principal.label,
                "active_sessions": rt.active_session_count(),
                "running_async_tasks": rt.tasks.running_count(),
                "ai_slots_available": rt.policy.active_ai_slots_available(),
                "ro_cache": {"hits": hits, "misses": misses},
                "pool_health": rt.section_env.host.pool_health_summary()
            }))
            .map_err(|e| e.to_string());
        }
        "hub_task_status" => {
            let tid = args
                .get("task_id")
                .and_then(Value::as_str)
                .ok_or_else(|| "task_id is required".to_string())?;
            let snap = rt
                .tasks
                .get(tid, &principal.principal_id, principal.is_owner)
                .ok_or_else(|| format!("task '{tid}' not found"))?;
            return serde_json::to_string_pretty(&snap).map_err(|e| e.to_string());
        }
        "hub_task_cancel" => {
            let tid = args
                .get("task_id")
                .and_then(Value::as_str)
                .ok_or_else(|| "task_id is required".to_string())?;
            let ok = rt
                .tasks
                .cancel(tid, &principal.principal_id, principal.is_owner);
            return serde_json::to_string_pretty(&json!({"task_id": tid, "cancelled": ok}))
                .map_err(|e| e.to_string());
        }
        "hub_call_tool" => {
            let target = args
                .get("tool")
                .and_then(Value::as_str)
                .ok_or_else(|| "tool is required".to_string())?;
            let inner_args = args
                .get("arguments")
                .cloned()
                .unwrap_or_else(|| json!({}));
            let async_mode = args
                .get("async_mode")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            return execute_catalog_tool(
                rt,
                principal,
                client_ip,
                EndpointScope::AllAllowed,
                target,
                inner_args,
                async_mode,
            )
            .await;
        }
        _ => {}
    }

    execute_catalog_tool(rt, principal, client_ip, scope, name, args, false).await
}

async fn execute_catalog_tool(
    rt: &Arc<McpRuntime>,
    principal: &AuthenticatedPrincipal,
    client_ip: &str,
    scope: EndpointScope,
    name: &str,
    args: Value,
    async_mode: bool,
) -> std::result::Result<String, String> {
    let Some(spec) = rt.catalog.iter().find(|t| t.name == name).cloned() else {
        return Err(format!(
            "Unknown tool '{name}'. Use hub_discover_tools to search available tools."
        ));
    };

    if let EndpointScope::Section(req_sec) = scope {
        if spec.section != req_sec {
            return Err(format!(
                "Tool '{name}' belongs to section '{}', not '{}'",
                spec.section.slug(),
                req_sec.slug()
            ));
        }
    }

    // Policy & RBAC & Anti-Ban evaluation
    match rt
        .policy
        .evaluate(principal, spec.section, &spec.name, spec.risk, &args)
    {
        PolicyDecision::Allow => {}
        PolicyDecision::Deny { reason } => return Err(reason),
        PolicyDecision::RequireHitl { reason } => {
            if !rt.hitl.has_session_grant(&principal.principal_id, &spec.name) {
                let (req_id, rx) = rt
                    .hitl
                    .create_request(&principal.principal_id, &spec.name);
                let args_preview = agy_ext::mcp_client::redact_secrets_in_text(
                    &serde_json::to_string(&args).unwrap_or_default(),
                );
                let preview: String = args_preview.chars().take(240).collect();
                rt.section_env
                    .host
                    .notify_owner_hitl(&req_id, &principal.label, &spec.name, &preview, client_ip)
                    .await;
                let dec = rt.hitl.wait_for(&req_id, rx, Duration::from_secs(90)).await;
                match dec {
                    HitlDecision::AllowOnce | HitlDecision::AllowSession => {}
                    HitlDecision::Deny => {
                        return Err(format!("Denied by Owner in Telegram ({reason})"));
                    }
                    HitlDecision::TimedOut => {
                        return Err(format!(
                            "Owner approval timed out after 90s ({reason})"
                        ));
                    }
                }
            }
        }
    }

    if async_mode {
        let env = Arc::clone(&rt.section_env);
        let princ = principal.clone();
        let spec_c = spec.clone();
        let tid = rt.tasks.spawn_tracked(&principal.principal_id, &spec.name, move |cancel| async move {
            let val = dispatch_section_tool(&env, &princ, &spec_c, args, cancel).await?;
            let raw_txt = value_to_text(&val);
            let clean = sanitize_tool_output(&raw_txt, spec_c.untrusted_output, DEFAULT_TOOL_OUTPUT_MAX_BYTES);
            Ok(json!({"text": clean}))
        });
        return serde_json::to_string_pretty(&json!({
            "async": true,
            "task_id": tid,
            "status": "running",
            "hint": "Poll hub_task_status(task_id) for completion."
        }))
        .map_err(|e| e.to_string());
    }

    let (_tx, rx) = watch::channel(false);
    let val = dispatch_section_tool(&rt.section_env, principal, &spec, args, rx).await?;
    let raw_txt = value_to_text(&val);
    Ok(sanitize_tool_output(
        &raw_txt,
        spec.untrusted_output,
        DEFAULT_TOOL_OUTPUT_MAX_BYTES,
    ))
}

fn value_to_text(v: &Value) -> String {
    if let Some(s) = v.get("text").and_then(Value::as_str) {
        return s.to_string();
    }
    if let Some(arr) = v.get("content").and_then(Value::as_array) {
        let parts: Vec<&str> = arr
            .iter()
            .filter_map(|c| c.get("text").and_then(Value::as_str))
            .collect();
        if !parts.is_empty() {
            return parts.join("\n");
        }
    }
    serde_json::to_string_pretty(v).unwrap_or_else(|_| v.to_string())
}

async fn read_resource(rt: &Arc<McpRuntime>, uri: &str) -> std::result::Result<(&'static str, String), String> {
    match uri {
        "agy://gateway/status" => {
            let cfg = rt.cfg_store.snapshot();
            let txt = serde_json::to_string_pretty(&json!({
                "mode": cfg.mode.as_str(),
                "primary_domain": cfg.primary_domain,
                "cdn_domain": cfg.cdn_domain,
                "sections_enabled": cfg.sections_enabled,
                "active_sessions": rt.active_session_count(),
                "tools_total": rt.catalog.len()
            }))
            .map_err(|e| e.to_string())?;
            Ok(("application/json", txt))
        }
        "agy://models/catalog" => {
            let (_tx, rx) = watch::channel(false);
            let val = crate::sections::models::call_models_tool(
                &rt.section_env.host,
                &rt.policy,
                &rt.section_env.state_dir,
                &rt.section_env.workspace,
                &rt.section_env.mcp_config,
                &rt.section_env.skills_dir,
                "models_list",
                &json!({"engine": "all"}),
                rx,
            )
            .await?;
            Ok(("application/json", serde_json::to_string_pretty(&val).unwrap_or_default()))
        }
        "agy://sessions/recent" => {
            let val = rt.section_env.host.list_sessions(10);
            Ok(("application/json", serde_json::to_string_pretty(&val).unwrap_or_default()))
        }
        "agy://sessions/handoff" => {
            let val = crate::sections::sessions::call_sessions_tool(
                &*rt.section_env.host,
                &rt.section_env.state_dir,
                &rt.section_env.workspace,
                "session_handoff_read",
                &json!({}),
            )?;
            Ok((
                "text/markdown",
                val.get("content").and_then(Value::as_str).unwrap_or("").to_string(),
            ))
        }
        "agy://skillhub/roster" => {
            let txt = agy_ext::skill_hub::call_hub_tool(
                &rt.section_env.state_dir,
                "skillhub_catalog",
                &json!({}),
            )
            .await?;
            Ok(("text/markdown", txt))
        }
        "agy://optimizer/telemetry" => {
            let (hits, misses) = agy_ext::mcp_client::global_mcp_pool().ro_cache_stats();
            let txt = serde_json::to_string_pretty(&json!({
                "ro_cache_hits": hits,
                "ro_cache_misses": misses,
                "ai_slots_available": rt.policy.active_ai_slots_available(),
                "pool_health": rt.section_env.host.pool_health_summary()
            }))
            .map_err(|e| e.to_string())?;
            Ok(("application/json", txt))
        }
        _ => Err(format!("Unknown resource URI: {uri}")),
    }
}

async fn build_prompt_response(
    rt: &Arc<McpRuntime>,
    name: &str,
    args: &Value,
) -> std::result::Result<Value, String> {
    match name {
        "skillhub_workflow" => {
            let topic = args.get("topic").and_then(Value::as_str).unwrap_or("tdd");
            let search = agy_ext::skill_hub::call_hub_tool(
                &rt.section_env.state_dir,
                "skillhub_search",
                &json!({"query": topic, "limit": 5}),
            )
            .await
            .unwrap_or_else(|e| format!("SkillHub unavailable: {e}"));
            Ok(json!({
                "description": format!("Curated SkillHub workflows matching '{topic}'"),
                "messages": [{
                    "role": "user",
                    "content": {
                        "type": "text",
                        "text": format!("Apply the best matching SkillHub workflow for '{topic}'. Top local matches:\n\n{search}\n\nUse skillhub_get(id) to read the exact workflow before acting.")
                    }
                }]
            }))
        }
        "strategic_compact_handoff" => {
            let next_phase = args.get("next_phase").and_then(Value::as_str).unwrap_or("implementation");
            Ok(json!({
                "description": "ECC Strategic Compact handoff template",
                "messages": [{
                    "role": "user",
                    "content": {
                        "type": "text",
                        "text": format!("Prepare a lossless <=60-line handoff note before compacting for phase '{next_phase}':\n1. Goal of next phase\n2. Verified State (Done / In flight / Blocked)\n3. Open decisions\n4. Exact file paths & artifacts (never secrets)\nSave it via session_handoff_write and ai-memory before compacting.")
                    }
                }]
            }))
        }
        "optimize_prompt" => {
            let draft = args.get("draft").and_then(Value::as_str).unwrap_or("");
            let analysis = crate::sections::optimizer::call_optimizer_tool(
                &*rt.section_env.host,
                "opt_prompt_analyze",
                &json!({"draft_prompt": draft}),
            )
            .unwrap_or_else(|_| json!({}));
            Ok(json!({
                "description": "6-phase ECC prompt optimizer",
                "messages": [{
                    "role": "user",
                    "content": {
                        "type": "text",
                        "text": format!("Rewrite the following draft prompt to be unambiguous, verifiable, and token-efficient (advisory only):\n\nDraft:\n{draft}\n\nZero-token pre-analysis:\n{analysis}")
                    }
                }]
            }))
        }
        "three_stage_codegen" => {
            let goal = args.get("goal").and_then(Value::as_str).unwrap_or("Implement feature");
            Ok(json!({
                "description": "3-Stage chunked codegen workflow with <agy_slot>",
                "messages": [{
                    "role": "user",
                    "content": {
                        "type": "text",
                        "text": format!("Execute '{goal}' in 3 disciplined stages:\nStage 1: Map repo symbols via codeintel/openhands & recall ai-memory.\nStage 2: Load 1-2 relevant SkillHub skills & write a compact plan.\nStage 3: Implement surgically (or via <agy_slot> assembly) and verify with fresh test output.")
                    }
                }]
            }))
        }
        _ => Err(format!("Unknown prompt: {name}")),
    }
}
