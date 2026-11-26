//! OAuth 2.1 Authorization Server for Remote MCP clients (Claude.ai, ChatGPT Connectors,
//! VS Code, Gemini, Grok) with RFC 9728 Protected Resource Metadata, RFC 8414 AS Metadata,
//! RFC 7591 Dynamic Client Registration, mandatory PKCE S256, RFC 8707 audience binding,
//! defensive JSON + form-urlencoded parsing, and Telegram Owner 2FA approval.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use agy_core::atomic::atomic_write_json;
use agy_core::error::Result;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::Utc;
use dashmap::DashMap;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::auth::{hash_secret, AuthKind, AuthenticatedPrincipal, KeyPreset};
use crate::config::{GatewayConfigStore, SectionId};
use crate::guard::VerifiedClientIp;
use crate::host::GatewayHostBridge;

const MAX_REGISTERED_CLIENTS: usize = 128;
const ACCESS_TOKEN_TTL_SECS: i64 = 1800; // 30 minutes (short-lived per OAuth 2.1 best practice)
const REFRESH_TOKEN_TTL_SECS: i64 = 30 * 86_400; // 30 days
const AUTH_CODE_TTL_SECS: i64 = 300; // 5 minutes
const PENDING_CONSENT_TTL_SECS: i64 = 300;
const OAUTH_TOKEN_PREFIX: &str = "agyoa_";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthClient {
    pub client_id: String,
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub created_at: i64,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct OAuthTokenRecord {
    pub id: String,
    pub client_id: String,
    pub client_name: String,
    pub salt_hex: String,
    pub access_hash: String,
    pub refresh_hash: String,
    pub resource: String,
    pub preset: KeyPreset,
    pub sections: BTreeSet<SectionId>,
    pub issued_at: i64,
    pub access_expires_at: i64,
    pub refresh_expires_at: i64,
    pub revoked: bool,
}

impl std::fmt::Debug for OAuthTokenRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuthTokenRecord")
            .field("id", &self.id)
            .field("client_id", &self.client_id)
            .field("client_name", &self.client_name)
            .field("preset", &self.preset)
            .field("revoked", &self.revoked)
            .finish()
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct OAuthPersistFile {
    #[serde(default)]
    clients: Vec<OAuthClient>,
    #[serde(default)]
    tokens: Vec<OAuthTokenRecord>,
}

#[derive(Debug, Clone)]
pub struct PendingConsent {
    pub req_id: String,
    pub client_id: String,
    pub client_name: String,
    pub redirect_uri: String,
    pub state: Option<String>,
    pub code_challenge: String,
    pub resource: String,
    pub scope: String,
    pub created_at: i64,
    pub status: ConsentStatus,
    pub issued_code: Option<String>,
    pub approved_preset: KeyPreset,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsentStatus {
    Pending,
    Approved,
    Denied,
}

#[derive(Debug, Clone)]
struct AuthCodeRecord {
    client_id: String,
    client_name: String,
    redirect_uri: String,
    code_challenge: String,
    resource: String,
    preset: KeyPreset,
    expires_at: i64,
}

fn random_b64url(n_bytes: usize) -> String {
    let mut buf = vec![0u8; n_bytes];
    rand::thread_rng().fill_bytes(&mut buf);
    base64url_encode(&buf)
}

/// Zero-dependency RFC 4648 base64url encoder (no padding) for PKCE `S256` & tokens.
pub fn base64url_encode(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity((input.len() * 4).div_ceil(3));
    let mut i = 0;
    while i < input.len() {
        let b0 = input[i];
        let b1 = if i + 1 < input.len() { input[i + 1] } else { 0 };
        let b2 = if i + 2 < input.len() { input[i + 2] } else { 0 };
        out.push(TABLE[(b0 >> 2) as usize] as char);
        out.push(TABLE[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        if i + 1 < input.len() {
            out.push(TABLE[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char);
        }
        if i + 2 < input.len() {
            out.push(TABLE[(b2 & 0x3f) as usize] as char);
        }
        i += 3;
    }
    out
}

pub fn verify_pkce_s256(code_verifier: &str, expected_challenge: &str) -> bool {
    if code_verifier.len() < 43 || code_verifier.len() > 128 {
        return false;
    }
    let digest = Sha256::digest(code_verifier.as_bytes());
    let computed = base64url_encode(&digest);
    if computed.len() != expected_challenge.len() {
        return false;
    }
    computed.as_bytes().ct_eq(expected_challenge.as_bytes()).into()
}

fn ct_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

pub struct OAuthStore {
    path: PathBuf,
    cfg_store: Arc<GatewayConfigStore>,
    host: Arc<dyn GatewayHostBridge>,
    persist: RwLock<OAuthPersistFile>,
    pending_consents: DashMap<String, PendingConsent>,
    auth_codes: DashMap<String, AuthCodeRecord>,
}

impl OAuthStore {
    pub fn open(
        path: impl Into<PathBuf>,
        cfg_store: Arc<GatewayConfigStore>,
        host: Arc<dyn GatewayHostBridge>,
    ) -> Result<Self> {
        let path = path.into();
        let data = if path.exists() {
            std::fs::read_to_string(&path)
                .ok()
                .and_then(|s| serde_json::from_str::<OAuthPersistFile>(&s).ok())
                .unwrap_or_default()
        } else {
            OAuthPersistFile::default()
        };
        Ok(Self {
            path,
            cfg_store,
            host,
            persist: RwLock::new(data),
            pending_consents: DashMap::new(),
            auth_codes: DashMap::new(),
        })
    }

    fn save_locked(&self, data: &OAuthPersistFile) {
        if let Some(parent) = self.path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = atomic_write_json(&self.path, data, true);
    }

    pub fn list_clients(&self) -> Vec<OAuthClient> {
        self.persist
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clients
            .clone()
    }

    pub fn list_active_tokens(&self) -> Vec<(String, String, KeyPreset, i64)> {
        let now = Utc::now().timestamp();
        self.persist
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .tokens
            .iter()
            .filter(|t| !t.revoked && t.refresh_expires_at > now)
            .map(|t| (t.id.clone(), t.client_name.clone(), t.preset, t.issued_at))
            .collect()
    }

    pub fn revoke_token_by_id(&self, id: &str) -> bool {
        let mut g = self.persist.write().unwrap_or_else(|e| e.into_inner());
        let mut found = false;
        for t in g.tokens.iter_mut() {
            if t.id == id {
                t.revoked = true;
                found = true;
            }
        }
        if found {
            self.save_locked(&g);
        }
        found
    }

    pub fn revoke_all_tokens(&self) -> usize {
        let mut g = self.persist.write().unwrap_or_else(|e| e.into_inner());
        let mut n = 0;
        for t in g.tokens.iter_mut() {
            if !t.revoked {
                t.revoked = true;
                n += 1;
            }
        }
        self.save_locked(&g);
        n
    }

    /// Resolve a pending OAuth consent from the Telegram Owner inline button (`mcpgw:oauth:...`).
    pub fn resolve_consent(&self, req_id: &str, approve: bool, preset: KeyPreset) -> bool {
        let Some(mut entry) = self.pending_consents.get_mut(req_id) else {
            return false;
        };
        if entry.status != ConsentStatus::Pending {
            return false;
        }
        if !approve {
            entry.status = ConsentStatus::Denied;
            return true;
        }
        let code = format!("code_{}", random_b64url(24));
        self.auth_codes.insert(
            code.clone(),
            AuthCodeRecord {
                client_id: entry.client_id.clone(),
                client_name: entry.client_name.clone(),
                redirect_uri: entry.redirect_uri.clone(),
                code_challenge: entry.code_challenge.clone(),
                resource: entry.resource.clone(),
                preset,
                expires_at: Utc::now().timestamp() + AUTH_CODE_TTL_SECS,
            },
        );
        entry.approved_preset = preset;
        entry.issued_code = Some(code);
        entry.status = ConsentStatus::Approved;
        true
    }

    /// Verify an OAuth 2.1 Bearer access token with RFC 8707 resource/audience binding.
    pub fn verify_access_token(
        &self,
        raw_token: &str,
        request_origin_base: Option<&str>,
    ) -> Option<AuthenticatedPrincipal> {
        let trimmed = raw_token.trim();
        if !trimmed.starts_with(OAUTH_TOKEN_PREFIX) {
            return None;
        }
        let now = Utc::now().timestamp();
        let g = self.persist.read().unwrap_or_else(|e| e.into_inner());
        for tok in &g.tokens {
            if tok.revoked || now > tok.access_expires_at {
                continue;
            }
            let cand = hash_secret(&tok.salt_hex, trimmed);
            if ct_eq(&tok.access_hash, &cand) {
                // RFC 8707 audience check when both token resource and request base are present
                if let Some(req_base) = request_origin_base {
                    if !tok.resource.is_empty()
                        && !req_base.is_empty()
                        && !tok.resource.starts_with(req_base)
                        && !req_base.starts_with(&tok.resource)
                    {
                        // Also allow same-gateway cross-domain (mcp.example.com <-> gateway.example.com)
                        let cfg = self.cfg_store.snapshot();
                        let known_res = tok.resource.contains(&cfg.primary_domain)
                            || tok.resource.contains(&cfg.cdn_domain);
                        if !known_res {
                            return None;
                        }
                    }
                }
                return Some(AuthenticatedPrincipal {
                    principal_id: format!("oauth:{}", tok.id),
                    label: format!("OAuth:{}", tok.client_name),
                    auth_kind: AuthKind::OAuth2,
                    sections: tok.sections.clone(),
                    allow_write: tok.preset.allow_write(),
                    allow_exec: tok.preset.allow_exec(),
                    allow_models_run: tok.preset.allow_models_run(),
                    allow_root_access: false,
                    is_owner: tok.preset.is_owner_level(),
                    rpm_override: None,
                    daily_ai_cap: if tok.preset.is_owner_level() {
                        Some(0)
                    } else {
                        None
                    },
                });
            }
        }
        None
    }

    fn base_url_for_headers(&self, headers: &HeaderMap) -> String {
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
}

/// Parse request body defensively as either `application/json` or `application/x-www-form-urlencoded`
/// (prevents Claude.ai & automated MCP client Content-Type mismatch 400/415 failures).
fn parse_flexible_params(bytes: &[u8]) -> BTreeMap<String, String> {
    if let Ok(val) = serde_json::from_slice::<Value>(bytes) {
        if let Some(obj) = val.as_object() {
            let mut map = BTreeMap::new();
            for (k, v) in obj {
                match v {
                    Value::String(s) => {
                        map.insert(k.clone(), s.clone());
                    }
                    Value::Array(arr) => {
                        let joined = arr
                            .iter()
                            .filter_map(Value::as_str)
                            .collect::<Vec<_>>()
                            .join(",");
                        map.insert(k.clone(), joined);
                    }
                    other => {
                        map.insert(k.clone(), other.to_string());
                    }
                }
            }
            return map;
        }
    }
    url::form_urlencoded::parse(bytes)
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

pub fn build_oauth_router(store: Arc<OAuthStore>) -> Router {
    Router::new()
        .route(
            "/.well-known/oauth-protected-resource",
            get(handle_protected_resource_meta),
        )
        .route(
            "/.well-known/oauth-protected-resource/{*rest}",
            get(handle_protected_resource_meta),
        )
        .route(
            "/.well-known/oauth-authorization-server",
            get(handle_as_meta),
        )
        .route(
            "/.well-known/openid-configuration",
            get(handle_as_meta),
        )
        .route("/oauth/register", post(handle_dcr_register))
        .route("/oauth/authorize", get(handle_authorize_get))
        .route("/oauth/poll/{req_id}", get(handle_consent_poll))
        .route("/oauth/token", post(handle_token))
        .route("/oauth/revoke", post(handle_revoke))
        .with_state(store)
}

async fn handle_protected_resource_meta(
    State(store): State<Arc<OAuthStore>>,
    headers: HeaderMap,
) -> Response {
    let base = store.base_url_for_headers(&headers);
    Json(json!({
        "resource": format!("{base}/mcp"),
        "authorization_servers": [base],
        "bearer_methods_supported": ["header"],
        "scopes_supported": [
            "mcp:read",
            "mcp:research",
            "mcp:developer",
            "mcp:owner"
        ]
    }))
    .into_response()
}

async fn handle_as_meta(State(store): State<Arc<OAuthStore>>, headers: HeaderMap) -> Response {
    let base = store.base_url_for_headers(&headers);
    Json(json!({
        "issuer": base,
        "authorization_endpoint": format!("{base}/oauth/authorize"),
        "token_endpoint": format!("{base}/oauth/token"),
        "registration_endpoint": format!("{base}/oauth/register"),
        "revocation_endpoint": format!("{base}/oauth/revoke"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none", "client_secret_post"],
        "scopes_supported": ["mcp:read", "mcp:research", "mcp:developer", "mcp:owner"]
    }))
    .into_response()
}

async fn handle_dcr_register(State(store): State<Arc<OAuthStore>>, body: Bytes) -> Response {
    if !store.cfg_store.snapshot().oauth_enabled {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "oauth_disabled"})),
        )
            .into_response();
    }
    let val: Value = serde_json::from_slice(&body).unwrap_or_else(|_| {
        let map = parse_flexible_params(&body);
        serde_json::to_value(map).unwrap_or_else(|_| json!({}))
    });

    let client_name = val
        .get("client_name")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("MCP Client")
        .chars()
        .take(64)
        .collect::<String>();

    let redirect_uris: Vec<String> = match val.get("redirect_uris") {
        Some(Value::Array(arr)) => arr
            .iter()
            .filter_map(Value::as_str)
            .map(str::trim)
            .filter(|s| s.starts_with("https://") || s.starts_with("http://127.0.0.1") || s.starts_with("http://localhost") || s.starts_with("vscode://") || s.starts_with("cursor://"))
            .map(str::to_string)
            .collect(),
        Some(Value::String(s)) => s
            .split(',')
            .map(str::trim)
            .filter(|u| !u.is_empty())
            .map(str::to_string)
            .collect(),
        _ => Vec::new(),
    };
    if redirect_uris.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "invalid_redirect_uri", "error_description": "At least one valid https/localhost redirect_uri is required"})),
        )
            .into_response();
    }

    let client_id = format!("mcpc_{}", random_b64url(12));
    let now = Utc::now().timestamp();
    let rec = OAuthClient {
        client_id: client_id.clone(),
        client_name: client_name.clone(),
        redirect_uris: redirect_uris.clone(),
        grant_types: vec!["authorization_code".to_string(), "refresh_token".to_string()],
        created_at: now,
    };

    {
        let mut g = store.persist.write().unwrap_or_else(|e| e.into_inner());
        while g.clients.len() >= MAX_REGISTERED_CLIENTS {
            g.clients.remove(0);
        }
        g.clients.push(rec);
        store.save_locked(&g);
    }

    (
        StatusCode::CREATED,
        Json(json!({
            "client_id": client_id,
            "client_id_issued_at": now,
            "client_name": client_name,
            "redirect_uris": redirect_uris,
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none"
        })),
    )
        .into_response()
}

#[derive(Debug, Deserialize)]
struct AuthorizeQuery {
    client_id: Option<String>,
    redirect_uri: Option<String>,
    response_type: Option<String>,
    state: Option<String>,
    scope: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    resource: Option<String>,
}

async fn handle_authorize_get(
    State(store): State<Arc<OAuthStore>>,
    headers: HeaderMap,
    ext_ip: Option<axum::Extension<VerifiedClientIp>>,
    Query(q): Query<AuthorizeQuery>,
) -> Response {
    if !store.cfg_store.snapshot().oauth_enabled {
        return (StatusCode::FORBIDDEN, "OAuth is disabled by owner").into_response();
    }
    if q.response_type.as_deref() != Some("code") {
        return (StatusCode::BAD_REQUEST, "response_type must be 'code'").into_response();
    }
    let Some(client_id) = q.client_id.as_deref().filter(|s| !s.is_empty()) else {
        return (StatusCode::BAD_REQUEST, "missing client_id").into_response();
    };
    let Some(redirect_uri) = q.redirect_uri.as_deref().filter(|s| !s.is_empty()) else {
        return (StatusCode::BAD_REQUEST, "missing redirect_uri").into_response();
    };
    if q.code_challenge_method.as_deref() != Some("S256") {
        return (
            StatusCode::BAD_REQUEST,
            "OAuth 2.1 requires PKCE code_challenge_method=S256",
        )
            .into_response();
    }
    let Some(code_challenge) = q.code_challenge.as_deref().filter(|s| s.len() >= 32) else {
        return (StatusCode::BAD_REQUEST, "missing or invalid code_challenge").into_response();
    };

    // Look up client (or accept CIMD-style HTTPS client_id if redirect is safe)
    let client_name = {
        let g = store.persist.read().unwrap_or_else(|e| e.into_inner());
        if let Some(c) = g.clients.iter().find(|c| c.client_id == client_id) {
            if !c.redirect_uris.iter().any(|u| u == redirect_uri) {
                return (StatusCode::BAD_REQUEST, "redirect_uri mismatch").into_response();
            }
            c.client_name.clone()
        } else {
            return (StatusCode::BAD_REQUEST, "unknown client_id; register via /oauth/register first").into_response();
        }
    };

    let req_id = random_b64url(12);
    let base = store.base_url_for_headers(&headers);
    let resource = q
        .resource
        .clone()
        .unwrap_or_else(|| format!("{base}/mcp"));
    let scope = q.scope.clone().unwrap_or_else(|| "mcp:developer".to_string());
    let client_ip = ext_ip
        .map(|e| e.0 .0)
        .unwrap_or_else(|| "unknown".to_string());

    // Prune stale pending consents
    let now = Utc::now().timestamp();
    store
        .pending_consents
        .retain(|_, v| now.saturating_sub(v.created_at) < PENDING_CONSENT_TTL_SECS);

    store.pending_consents.insert(
        req_id.clone(),
        PendingConsent {
            req_id: req_id.clone(),
            client_id: client_id.to_string(),
            client_name: client_name.clone(),
            redirect_uri: redirect_uri.to_string(),
            state: q.state.clone(),
            code_challenge: code_challenge.to_string(),
            resource: resource.clone(),
            scope: scope.clone(),
            created_at: now,
            status: ConsentStatus::Pending,
            issued_code: None,
            approved_preset: KeyPreset::Developer,
        },
    );

    // Trigger Telegram Owner 2FA inline approval immediately!
    let host = Arc::clone(&store.host);
    let rid_c = req_id.clone();
    let cname_c = client_name.clone();
    let scope_c = scope.clone();
    let ip_c = client_ip.clone();
    let res_c = resource.clone();
    tokio::spawn(async move {
        host.notify_owner_oauth(&rid_c, &cname_c, &scope_c, &ip_c, &res_c)
            .await;
    });

    let safe_name = client_name.replace('<', "&lt;").replace('>', "&gt;");
    let safe_scope = scope.replace('<', "&lt;").replace('>', "&gt;");
    let html = format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AGY MCP OAuth 2.1 Approval</title>
<style>body{{font-family:system-ui,-apple-system,sans-serif;background:#0b1020;color:#e8eefc;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}}
.card{{max-width:440px;width:92%;background:#131b31;border:1px solid #26355c;border-radius:16px;padding:24px;box-shadow:0 16px 40px rgba(0,0,0,.4)}}
h1{{font-size:20px;margin:0 0 12px}}p{{color:#a6b5d8;line-height:1.5;font-size:14px}}code{{background:#0b1020;padding:2px 6px;border-radius:6px;color:#7dd3fc}}
.status{{margin-top:16px;padding:12px;border-radius:10px;background:#1b2644;font-weight:600;text-align:center}}</style></head>
<body><div class="card"><h1>AGY MCP Gateway — Telegram 2FA</h1>
<p>Client: <b>{safe_name}</b><br>Requested scope: <code>{safe_scope}</code><br>Request ID: <code>{req_id}</code></p>
<p>An inline approval request has been sent to the bot Owner on Telegram. Approve it there to finish connecting.</p>
<div id="st" class="status">Waiting for Owner approval in Telegram...</div></div>
<script>
async function poll(){{
  try{{
    const r = await fetch('/oauth/poll/{req_id}');
    const d = await r.json();
    if(d.status==='approved' && d.redirect_to){{
      document.getElementById('st').textContent='Approved! Redirecting...';
      window.location.href=d.redirect_to;
      return;
    }}
    if(d.status==='denied'){{
      document.getElementById('st').textContent='Denied by Owner.';
      if(d.redirect_to) window.location.href=d.redirect_to;
      return;
    }}
    if(d.status==='expired'){{
      document.getElementById('st').textContent='Approval timed out.';
      return;
    }}
  }}catch(e){{}}
  setTimeout(poll, 1500);
}}
setTimeout(poll, 1000);
</script></body></html>"#
    );

    Html(html).into_response()
}

async fn handle_consent_poll(
    State(store): State<Arc<OAuthStore>>,
    Path(req_id): Path<String>,
) -> Response {
    let Some(entry) = store.pending_consents.get(&req_id) else {
        return Json(json!({"status": "expired"})).into_response();
    };
    let now = Utc::now().timestamp();
    if now.saturating_sub(entry.created_at) > PENDING_CONSENT_TTL_SECS {
        drop(entry);
        store.pending_consents.remove(&req_id);
        return Json(json!({"status": "expired"})).into_response();
    }
    match entry.status {
        ConsentStatus::Pending => Json(json!({"status": "pending"})).into_response(),
        ConsentStatus::Approved => {
            let mut u = match url::Url::parse(&entry.redirect_uri) {
                Ok(u) => u,
                Err(_) => return Json(json!({"status": "expired"})).into_response(),
            };
            {
                let mut qp = u.query_pairs_mut();
                if let Some(ref code) = entry.issued_code {
                    qp.append_pair("code", code);
                }
                if let Some(ref st) = entry.state {
                    qp.append_pair("state", st);
                }
            }
            let target = u.to_string();
            drop(entry);
            store.pending_consents.remove(&req_id);
            Json(json!({"status": "approved", "redirect_to": target})).into_response()
        }
        ConsentStatus::Denied => {
            let mut u = match url::Url::parse(&entry.redirect_uri) {
                Ok(u) => u,
                Err(_) => return Json(json!({"status": "denied"})).into_response(),
            };
            {
                let mut qp = u.query_pairs_mut();
                qp.append_pair("error", "access_denied");
                if let Some(ref st) = entry.state {
                    qp.append_pair("state", st);
                }
            }
            let target = u.to_string();
            drop(entry);
            store.pending_consents.remove(&req_id);
            Json(json!({"status": "denied", "redirect_to": target})).into_response()
        }
    }
}

async fn handle_token(State(store): State<Arc<OAuthStore>>, body: Bytes) -> Response {
    let params = parse_flexible_params(&body);
    let grant_type = params.get("grant_type").map(String::as_str).unwrap_or("");
    let now = Utc::now().timestamp();

    match grant_type {
        "authorization_code" => {
            let Some(code) = params.get("code") else {
                return (StatusCode::BAD_REQUEST, Json(json!({"error": "invalid_request"}))).into_response();
            };
            let Some(verifier) = params.get("code_verifier") else {
                return (StatusCode::BAD_REQUEST, Json(json!({"error": "invalid_grant", "error_description": "PKCE code_verifier required"}))).into_response();
            };
            let Some((_, rec)) = store.auth_codes.remove(code) else {
                return (StatusCode::BAD_REQUEST, Json(json!({"error": "invalid_grant"}))).into_response();
            };
            if now > rec.expires_at {
                return (StatusCode::BAD_REQUEST, Json(json!({"error": "invalid_grant", "error_description": "code expired"}))).into_response();
            }
            if let Some(cid) = params.get("client_id") {
                if cid != &rec.client_id {
                    return (StatusCode::BAD_REQUEST, Json(json!({"error": "invalid_client"}))).into_response();
                }
            }
            if let Some(ruri) = params.get("redirect_uri") {
                if ruri != &rec.redirect_uri {
                    return (StatusCode::BAD_REQUEST, Json(json!({"error": "invalid_grant", "error_description": "redirect_uri mismatch"}))).into_response();
                }
            }
            if !verify_pkce_s256(verifier, &rec.code_challenge) {
                return (StatusCode::BAD_REQUEST, Json(json!({"error": "invalid_grant", "error_description": "PKCE S256 verification failed"}))).into_response();
            }

            let access_token = format!("{OAUTH_TOKEN_PREFIX}{}", random_b64url(28));
            let refresh_token = format!("agyrf_{}", random_b64url(32));
            let salt = random_b64url(16);
            let tok_rec = OAuthTokenRecord {
                id: random_b64url(8),
                client_id: rec.client_id,
                client_name: rec.client_name,
                access_hash: hash_secret(&salt, &access_token),
                refresh_hash: hash_secret(&salt, &refresh_token),
                salt_hex: salt,
                resource: rec.resource,
                preset: rec.preset,
                sections: rec.preset.default_sections(),
                issued_at: now,
                access_expires_at: now + ACCESS_TOKEN_TTL_SECS,
                refresh_expires_at: now + REFRESH_TOKEN_TTL_SECS,
                revoked: false,
            };
            {
                let mut g = store.persist.write().unwrap_or_else(|e| e.into_inner());
                g.tokens.push(tok_rec);
                store.save_locked(&g);
            }

            Json(json!({
                "access_token": access_token,
                "token_type": "Bearer",
                "expires_in": ACCESS_TOKEN_TTL_SECS,
                "refresh_token": refresh_token,
                "scope": format!("mcp:{}", rec.preset.as_str())
            }))
            .into_response()
        }
        "refresh_token" => {
            let Some(rt) = params.get("refresh_token") else {
                return (StatusCode::BAD_REQUEST, Json(json!({"error": "invalid_request"}))).into_response();
            };
            let mut g = store.persist.write().unwrap_or_else(|e| e.into_inner());
            let mut found_idx = None;
            for (idx, tok) in g.tokens.iter().enumerate() {
                if !tok.revoked && now <= tok.refresh_expires_at {
                    let cand = hash_secret(&tok.salt_hex, rt);
                    if ct_eq(&tok.refresh_hash, &cand) {
                        found_idx = Some(idx);
                        break;
                    }
                }
            }
            let Some(idx) = found_idx else {
                return (StatusCode::BAD_REQUEST, Json(json!({"error": "invalid_grant"}))).into_response();
            };
            // Rotate both access and refresh tokens (OAuth 2.1 sender-constrained rotation)
            let new_access = format!("{OAUTH_TOKEN_PREFIX}{}", random_b64url(28));
            let new_refresh = format!("agyrf_{}", random_b64url(32));
            let new_salt = random_b64url(16);
            let preset = g.tokens[idx].preset;
            g.tokens[idx].access_hash = hash_secret(&new_salt, &new_access);
            g.tokens[idx].refresh_hash = hash_secret(&new_salt, &new_refresh);
            g.tokens[idx].salt_hex = new_salt;
            g.tokens[idx].access_expires_at = now + ACCESS_TOKEN_TTL_SECS;
            g.tokens[idx].refresh_expires_at = now + REFRESH_TOKEN_TTL_SECS;
            store.save_locked(&g);

            Json(json!({
                "access_token": new_access,
                "token_type": "Bearer",
                "expires_in": ACCESS_TOKEN_TTL_SECS,
                "refresh_token": new_refresh,
                "scope": format!("mcp:{}", preset.as_str())
            }))
            .into_response()
        }
        _ => (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "unsupported_grant_type"})),
        )
            .into_response(),
    }
}

async fn handle_revoke(State(store): State<Arc<OAuthStore>>, body: Bytes) -> Response {
    let params = parse_flexible_params(&body);
    if let Some(tok) = params.get("token") {
        let mut g = store.persist.write().unwrap_or_else(|e| e.into_inner());
        let mut changed = false;
        for rec in g.tokens.iter_mut() {
            let cand = hash_secret(&rec.salt_hex, tok);
            if ct_eq(&rec.access_hash, &cand) || ct_eq(&rec.refresh_hash, &cand) {
                rec.revoked = true;
                changed = true;
            }
        }
        if changed {
            store.save_locked(&g);
        }
    }
    StatusCode::OK.into_response()
}

/// Helper used by `/oauth` callers if direct redirect is ever needed.
#[allow(dead_code)]
fn _redirect_unused(url: &str) -> Redirect {
    Redirect::temporary(url)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::NullHostBridge;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tempfile::TempDir;
    use tower::ServiceExt;

    #[tokio::test]
    async fn oauth21_full_dcr_pkce_s256_and_dual_content_type_token_flow() {
        let dir = TempDir::new().unwrap();
        let cfg = Arc::new(GatewayConfigStore::open(dir.path().join("gw.json")).unwrap());
        let store = Arc::new(
            OAuthStore::open(dir.path().join("oauth.json"), cfg, Arc::new(NullHostBridge)).unwrap(),
        );
        let app = build_oauth_router(Arc::clone(&store));

        // 1. RFC 9728 Protected Resource Metadata
        let meta_req = Request::builder()
            .uri("/.well-known/oauth-protected-resource")
            .header(header::HOST, "mcp.example.com")
            .body(Body::empty())
            .unwrap();
        let meta_resp = app.clone().oneshot(meta_req).await.unwrap();
        assert_eq!(meta_resp.status(), StatusCode::OK);
        let meta_bytes = meta_resp.into_body().collect().await.unwrap().to_bytes();
        let meta_json: Value = serde_json::from_slice(&meta_bytes).unwrap();
        assert_eq!(meta_json["resource"], "https://mcp.example.com/mcp");

        // 2. Dynamic Client Registration (RFC 7591)
        let dcr_body = serde_json::to_vec(&json!({
            "client_name": "Claude.ai",
            "redirect_uris": ["https://claude.ai/api/mcp/auth_callback"]
        }))
        .unwrap();
        let dcr_req = Request::builder()
            .method("POST")
            .uri("/oauth/register")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(dcr_body))
            .unwrap();
        let dcr_resp = app.clone().oneshot(dcr_req).await.unwrap();
        assert_eq!(dcr_resp.status(), StatusCode::CREATED);
        let dcr_json: Value =
            serde_json::from_slice(&dcr_resp.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        let client_id = dcr_json["client_id"].as_str().unwrap().to_string();

        // 3. Authorize with PKCE S256
        let verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        let challenge = base64url_encode(&Sha256::digest(verifier.as_bytes()));
        let auth_uri = format!(
            "/oauth/authorize?client_id={client_id}&redirect_uri=https://claude.ai/api/mcp/auth_callback&response_type=code&code_challenge={challenge}&code_challenge_method=S256&state=xyz"
        );
        let auth_resp = app
            .clone()
            .oneshot(Request::builder().uri(&auth_uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(auth_resp.status(), StatusCode::OK);

        // Simulate Owner clicking Approve in Telegram
        let req_id = store
            .pending_consents
            .iter()
            .next()
            .unwrap()
            .key()
            .clone();
        assert!(store.resolve_consent(&req_id, true, KeyPreset::Developer));

        // Poll returns redirect containing code
        let poll_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/oauth/poll/{req_id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let poll_json: Value =
            serde_json::from_slice(&poll_resp.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(poll_json["status"], "approved");
        let redir = url::Url::parse(poll_json["redirect_to"].as_str().unwrap()).unwrap();
        let code = redir
            .query_pairs()
            .find(|(k, _)| k == "code")
            .unwrap()
            .1
            .into_owned();

        // 4. Token exchange using application/json (defensive dual-parser!)
        let tok_body = serde_json::to_vec(&json!({
            "grant_type": "authorization_code",
            "code": code,
            "client_id": client_id,
            "redirect_uri": "https://claude.ai/api/mcp/auth_callback",
            "code_verifier": verifier
        }))
        .unwrap();
        let tok_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/oauth/token")
                    .body(Body::from(tok_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(tok_resp.status(), StatusCode::OK);
        let tok_json: Value =
            serde_json::from_slice(&tok_resp.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        let access_token = tok_json["access_token"].as_str().unwrap();
        let princ = store
            .verify_access_token(access_token, Some("https://mcp.example.com"))
            .expect("valid OAuth access token should verify");
        assert_eq!(princ.auth_kind, AuthKind::OAuth2);
        assert!(princ.has_section(SectionId::Openhands));
    }
}
