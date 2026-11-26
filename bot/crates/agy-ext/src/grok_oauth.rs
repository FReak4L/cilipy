//! xAI Grok Subscription OAuth 2.0 (RFC 8628 Device Authorization Grant — NO API key needed!).
//!
//! Verified against live Nov 2026 primary sources:
//! - OIDC Discovery: `https://auth.x.ai/.well-known/openid-configuration` (host-pinned to `*.x.ai` HTTPS)
//! - Device Code flow (`client_id = b1a00492-073a-47ea-816f-4c329264a828`) for headless Telegram login
//! - Serialized single-use `refresh_token` rotation behind a Tokio `Mutex` + atomic `0600` persistence
//! - Adaptive proactive refresh skew based on JWT `exp` lifetime (120s for <=45m tokens, else 300s)
//! - Dynamic `x-grok-client-version` header from `https://x.ai/cli/stable` (12h cache, auto-refreshed on HTTP 426)
//! - Dual endpoint routing: `https://cli-chat-proxy.grok.com/v1` (OAuth default) or `https://api.x.ai/v1`
//! - Full multi-turn autonomous Agent + Chat execution via [`crate::agent_runtime`].

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use agy_core::atomic::atomic_write_json;
use agy_core::error::{BridgeError, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::sync::{watch, Mutex, RwLock};
use tracing::{info, warn};
use url::Url;

use crate::agent_runtime::{
    run_openai_agent_turn, session_conv_id, AgentTurnConfig, AuthHeaderProvider,
    RequestAuthFuture, DEFAULT_JOB_TIMEOUT_SECS, DEFAULT_MAX_AGENT_STEPS, DEFAULT_MAX_TOKENS,
};
use crate::engines::{JobResult, ProgressCallback};
use crate::mcp_client::redact_secrets_in_text;

pub const XAI_OIDC_DISCOVERY_URL: &str = "https://auth.x.ai/.well-known/openid-configuration";
pub const DEFAULT_XAI_DEVICE_AUTH_ENDPOINT: &str = "https://auth.x.ai/oauth2/device/code";
pub const DEFAULT_XAI_TOKEN_ENDPOINT: &str = "https://auth.x.ai/oauth2/token";
pub const DEFAULT_XAI_USERINFO_ENDPOINT: &str = "https://auth.x.ai/oauth2/userinfo";
pub const DEFAULT_XAI_OAUTH_CLIENT_ID: &str = "b1a00492-073a-47ea-816f-4c329264a828";
pub const XAI_OAUTH_SCOPE: &str = "openid profile email offline_access grok-cli:access api:access";

pub const GROK_CLI_PROXY_BASE: &str = "https://cli-chat-proxy.grok.com/v1";
pub const GROK_OFFICIAL_API_BASE: &str = "https://api.x.ai/v1";
pub const XAI_CLI_STABLE_URL: &str = "https://x.ai/cli/stable";
pub const DEFAULT_GROK_CLI_VERSION: &str = "1.0.92";
pub const DEFAULT_GROK_MODEL: &str = "grok-4.7";

const CLI_VERSION_TTL: Duration = Duration::from_secs(12 * 3600);
const OIDC_CACHE_TTL: Duration = Duration::from_secs(24 * 3600);

pub const GROK_AGENT_SYSTEM_PROMPT: &str = "\
You are Grok (xAI), operating as an action-first, OpenHands-grade autonomous AI software engineering agent on an Ubuntu server.\n\
Core Pro Coding & Speed Tools (31 live tools):\n\
- Programmatic Batching (5-10x FASTER): execute_code (Python 3 Unix-socket RPC with 24 agy_tools functions, up to 150 calls in ONE turn, 300s timeout — collapse multi-file reads/greps/edits/git/MCP/verify into 1 turn!)\n\
- Code Editing & Rollback: batch_read (read up to 20 files concurrently in 1 call), multi_edit (apply up to 25 surgical edits across files in 1 call w/ undo_edit snapshots), file_editor (OpenHands str_replace_editor: view, create, str_replace, insert at line, undo_edit rollback stack), read_file, write_file (append=true for large files), patch_file/edit_file (unique/fuzzy/unified diff + differential syntax check)\n\
- Codebase Discovery & Git: glob_files (**/*.rs, *.py), find_symbols (multi-language fn/struct/class/trait indexer), grep_files (regex + glob + context_lines), list_dir, git_ops (status, diff, log, branch, checkpoint, restore)\n\
- Planning & Project Packs: task_tracker (plan/update/view checklist preserved across compaction), think, finish, code_to_md (.zip/dir -> .md), md_to_code (.md -> disk), verify_project (auto-detect Rust/Python/TS/Go/PHP/Bash -> PASS or errors.md)\n\
- Shell & Persistent PTYs: run_command (bash, builds, tests, timeout 600s, background/pty tmux, optional bubblewrap sandbox), process_manage (list/poll/wait/log/write/kill persistent tmux sessions)\n\
- Vision, Memory, Skills & MCPs: inspect_image (multimodal vision), web_search & fetch_url (search-v3), memory_search & memory_store (ai-memory), search_skills/load_skill/skillhub_*, call_mcp_tool (up to 50/turn: context7, gortex, graphify, search-v3, openhands, ai-memory, skillport, skillhub)\n\
Execution & Speed Discipline:\n\
1. ACT IMMEDIATELY & BATCH PARALLEL: Never stall in planning mode or ask permission when the user already asked you to inspect/write/fix/test/send code. Emit independent read/search/git-inspect calls together in ONE turn (they execute in parallel waves of up to 12) or batch 10-150 ops inside ONE execute_code Python RPC script.\n\
2. TELEGRAM FILE DELIVERY: Whenever the user asks for code, a fixed file, a project, or a report, write it directly into the `outbox/.../` folder path given in the prompt so Telegram delivers it automatically.\n\
3. SURGICAL EDITS & VERIFICATION: Prefer file_editor (str_replace/insert/undo_edit) or patch_file over full rewrites; use task_tracker for multi-file tasks; always run verify_project or tests before calling finish.\n\
4. ZERO GUESSING & NO LOOPS: Ground every claim in fresh tool output. Never repeat a failing call twice; roll back bad edits with undo_edit if needed, and never reveal secrets/keys.";

pub const GROK_CHAT_SYSTEM_PROMPT: &str = "\
You are Grok connected via xAI OAuth subscription to Telegram. Be accurate, direct, concise, and helpful.";

/// Inference endpoint selection for Grok OAuth.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrokEndpointMode {
    /// Subscription OAuth proxy (`https://cli-chat-proxy.grok.com/v1`) with CLI identity headers.
    #[default]
    CliProxy,
    /// Official xAI OpenAI-compatible API (`https://api.x.ai/v1`) with OAuth bearer token.
    OfficialApi,
}

impl GrokEndpointMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CliProxy => "cli_proxy",
            Self::OfficialApi => "official_api",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::CliProxy => "CLI Proxy (cli-chat-proxy.grok.com)",
            Self::OfficialApi => "Official API (api.x.ai)",
        }
    }

    pub fn api_base(self) -> &'static str {
        match self {
            Self::CliProxy => GROK_CLI_PROXY_BASE,
            Self::OfficialApi => GROK_OFFICIAL_API_BASE,
        }
    }
}

/// Persisted xAI Grok OAuth credentials (`$STATE_DIR/grok_oauth.json`, `0600`).
#[derive(Clone, Serialize, Deserialize)]
pub struct GrokOAuthCreds {
    pub access_token: String,
    pub refresh_token: String,
    #[serde(default)]
    pub id_token: Option<String>,
    /// Unix epoch seconds when `access_token` expires.
    #[serde(default)]
    pub expires_at: i64,
    /// Observed lifetime in seconds of the current token (used for adaptive proactive skew).
    #[serde(default)]
    pub token_lifetime_secs: i64,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub subject: Option<String>,
    #[serde(default)]
    pub endpoint_mode: GrokEndpointMode,
    #[serde(default)]
    pub quarantined_reason: Option<String>,
    #[serde(default)]
    pub updated_at: i64,
}

impl fmt::Debug for GrokOAuthCreds {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GrokOAuthCreds")
            .field("access_token", &"[REDACTED]")
            .field("refresh_token", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .field("email", &self.masked_email())
            .field("endpoint_mode", &self.endpoint_mode)
            .field("quarantined_reason", &self.quarantined_reason)
            .finish()
    }
}

impl GrokOAuthCreds {
    pub fn masked_email(&self) -> Option<String> {
        self.email.as_deref().map(agy_core::accounts::mask_email)
    }

    /// Adaptive proactive refresh skew (seconds): 120s for short <=45m tokens, else 300s.
    pub fn proactive_skew_secs(&self) -> i64 {
        if self.token_lifetime_secs > 0 && self.token_lifetime_secs <= 45 * 60 {
            120
        } else {
            300
        }
    }

    pub fn needs_refresh_at(&self, now_unix: i64) -> bool {
        if self.access_token.trim().is_empty() {
            return true;
        }
        if self.expires_at <= 0 {
            return false;
        }
        now_unix + self.proactive_skew_secs() >= self.expires_at
    }
}

/// Discovered OIDC endpoints (strictly host-pinned to HTTPS `x.ai` / `*.x.ai`).
#[derive(Debug, Clone)]
pub struct XaiOidcEndpoints {
    pub device_authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
}

impl Default for XaiOidcEndpoints {
    fn default() -> Self {
        Self {
            device_authorization_endpoint: DEFAULT_XAI_DEVICE_AUTH_ENDPOINT.to_string(),
            token_endpoint: DEFAULT_XAI_TOKEN_ENDPOINT.to_string(),
            userinfo_endpoint: DEFAULT_XAI_USERINFO_ENDPOINT.to_string(),
        }
    }
}

/// Device Authorization response (RFC 8628) shown to the owner in Telegram.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrokDeviceAuth {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    #[serde(default)]
    pub verification_uri_complete: Option<String>,
    #[serde(default = "default_device_expires")]
    pub expires_in: u64,
    #[serde(default = "default_device_interval")]
    pub interval: u64,
}

fn default_device_expires() -> u64 {
    600
}
fn default_device_interval() -> u64 {
    5
}

/// Single device-token poll result.
#[derive(Debug, Clone)]
pub enum DevicePollOutcome {
    Pending,
    SlowDown(u64),
    Authorized(GrokOAuthCreds),
    Expired,
    Denied(String),
}

/// Model descriptor for Grok models.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GrokModel {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub context_length: Option<u64>,
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub fn grok_oauth_client_id() -> String {
    std::env::var("XAI_OAUTH_CLIENT_ID")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_XAI_OAUTH_CLIENT_ID.to_string())
}

pub fn grok_oauth_path(state_dir: &Path) -> PathBuf {
    state_dir.join("grok_oauth.json")
}

pub fn grok_models_path(state_dir: &Path) -> PathBuf {
    state_dir.join("grok_models.json")
}

/// Validate that a discovered/configured xAI OAuth endpoint uses HTTPS on `x.ai` or `*.x.ai`.
pub fn validate_xai_endpoint(raw: &str) -> Result<String> {
    let parsed = Url::parse(raw.trim())
        .map_err(|e| BridgeError::Validation(format!("invalid xAI endpoint URL: {e}")))?;
    if parsed.scheme() != "https" {
        return Err(BridgeError::Validation(format!(
            "refusing non-HTTPS xAI endpoint scheme '{}'",
            parsed.scheme()
        )));
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| BridgeError::Validation("xAI endpoint missing host".to_string()))?
        .to_ascii_lowercase();
    if host != "x.ai" && !host.ends_with(".x.ai") {
        return Err(BridgeError::Validation(format!(
            "refusing untrusted xAI OAuth host '{host}' (expected x.ai or *.x.ai)"
        )));
    }
    Ok(parsed.to_string())
}

/// Pure-Rust Base64URL decoder for inspecting JWT claims (`exp`, `iat`, `email`, `sub`) without
/// requiring external base64 crates.
fn decode_base64url(input: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut buf: u32 = 0;
    let mut bits: u8 = 0;
    for b in input.bytes() {
        let val = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'-' | b'+' => 62,
            b'_' | b'/' => 63,
            b'=' | b'\n' | b'\r' | b' ' => continue,
            _ => return None,
        };
        buf = (buf << 6) | (val as u32);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xff) as u8);
        }
    }
    Some(out)
}

/// Decode the middle payload segment of a JWT into a JSON object (no signature verification needed
/// here because the token was just received directly over TLS from `auth.x.ai`).
pub fn decode_jwt_claims(jwt: &str) -> Option<Value> {
    let payload_b64 = jwt.split('.').nth(1)?;
    let decoded = decode_base64url(payload_b64)?;
    serde_json::from_slice::<Value>(&decoded).ok()
}

fn oidc_cache() -> &'static RwLock<Option<(Instant, XaiOidcEndpoints)>> {
    static CACHE: OnceLock<RwLock<Option<(Instant, XaiOidcEndpoints)>>> = OnceLock::new();
    CACHE.get_or_init(|| RwLock::new(None))
}

fn cli_version_cache() -> &'static RwLock<Option<(Instant, String)>> {
    static CACHE: OnceLock<RwLock<Option<(Instant, String)>>> = OnceLock::new();
    CACHE.get_or_init(|| RwLock::new(None))
}

/// Process-wide mutex serializing single-use xAI refresh token rotations.
fn refresh_mutex() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn build_http_client_with_proxy(
    timeout_secs: u64,
    proxy_url: Option<&str>,
) -> Result<reqwest::Client> {
    let mut b = reqwest::Client::builder()
        .use_rustls_tls()
        .tcp_keepalive(Duration::from_secs(30))
        .timeout(Duration::from_secs(timeout_secs));
    if let Some(px) = proxy_url.map(str::trim).filter(|s| !s.is_empty()) {
        let proxy = reqwest::Proxy::all(px).map_err(|e| {
            BridgeError::Network(format!(
                "invalid Grok egress proxy {}: {e}",
                agy_core::redact_proxy_url(px)
            ))
        })?;
        b = b.proxy(proxy);
    }
    b.build()
        .map_err(|e| BridgeError::Network(format!("grok HTTP client failed: {e}")))
}

/// Discover `auth.x.ai` OIDC endpoints (cached 24h, strictly `*.x.ai` HTTPS validated).
pub async fn discover_xai_oidc() -> XaiOidcEndpoints {
    discover_xai_oidc_via(None).await
}

/// Discover `auth.x.ai` OIDC endpoints using an optional sticky egress proxy.
pub async fn discover_xai_oidc_via(proxy_url: Option<&str>) -> XaiOidcEndpoints {
    {
        let g = oidc_cache().read().await;
        if let Some((at, ref eps)) = *g {
            if at.elapsed() < OIDC_CACHE_TTL {
                return eps.clone();
            }
        }
    }

    let mut eps = XaiOidcEndpoints::default();
    if let Ok(client) = build_http_client_with_proxy(15, proxy_url) {
        if let Ok(resp) = client.get(XAI_OIDC_DISCOVERY_URL).send().await {
            if resp.status().is_success() {
                if let Ok(doc) = resp.json::<Value>().await {
                    if let Some(u) = doc
                        .get("device_authorization_endpoint")
                        .and_then(Value::as_str)
                        .and_then(|s| validate_xai_endpoint(s).ok())
                    {
                        eps.device_authorization_endpoint = u;
                    }
                    if let Some(u) = doc
                        .get("token_endpoint")
                        .and_then(Value::as_str)
                        .and_then(|s| validate_xai_endpoint(s).ok())
                    {
                        eps.token_endpoint = u;
                    }
                    if let Some(u) = doc
                        .get("userinfo_endpoint")
                        .and_then(Value::as_str)
                        .and_then(|s| validate_xai_endpoint(s).ok())
                    {
                        eps.userinfo_endpoint = u;
                    }
                }
            }
        }
    }

    *oidc_cache().write().await = Some((Instant::now(), eps.clone()));
    eps
}

/// Fetch the current Grok CLI client version from `https://x.ai/cli/stable` (cached 12h) to avoid
/// HTTP 426 Upgrade Required rejections from `cli-chat-proxy.grok.com`.
pub async fn resolve_grok_cli_version(force_refresh: bool) -> String {
    resolve_grok_cli_version_via(force_refresh, None).await
}

pub async fn resolve_grok_cli_version_via(
    force_refresh: bool,
    proxy_url: Option<&str>,
) -> String {
    if let Ok(override_ver) = std::env::var("XAI_GROK_CLI_VERSION") {
        let t = override_ver.trim();
        if !t.is_empty() {
            return t.to_string();
        }
    }
    if !force_refresh {
        let g = cli_version_cache().read().await;
        if let Some((at, ref v)) = *g {
            if at.elapsed() < CLI_VERSION_TTL {
                return v.clone();
            }
        }
    }

    let mut version = DEFAULT_GROK_CLI_VERSION.to_string();
    if let Ok(client) = build_http_client_with_proxy(10, proxy_url) {
        if let Ok(resp) = client.get(XAI_CLI_STABLE_URL).send().await {
            if resp.status().is_success() {
                if let Ok(txt) = resp.text().await {
                    let cand = txt.trim();
                    let valid = !cand.is_empty()
                        && cand.len() <= 32
                        && cand.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'));
                    if valid {
                        version = cand.to_string();
                        info!(version = %version, "fetched latest Grok CLI version from x.ai/cli/stable");
                    }
                }
            }
        }
    }

    *cli_version_cache().write().await = Some((Instant::now(), version.clone()));
    version
}

/// Load persisted Grok OAuth credentials from `$STATE_DIR/grok_oauth.json`, if present.
pub fn load_grok_creds(state_dir: &Path) -> Option<GrokOAuthCreds> {
    let path = grok_oauth_path(state_dir);
    let raw = std::fs::read_to_string(path).ok()?;
    serde_json::from_str::<GrokOAuthCreds>(&raw).ok()
}

/// Atomically save Grok OAuth credentials with `0600` permissions.
pub fn save_grok_creds(state_dir: &Path, creds: &GrokOAuthCreds) -> Result<()> {
    let path = grok_oauth_path(state_dir);
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    atomic_write_json(&path, creds, true)
}

/// Disconnect / delete saved Grok OAuth credentials.
pub fn delete_grok_creds(state_dir: &Path) -> bool {
    let path = grok_oauth_path(state_dir);
    if path.exists() {
        std::fs::remove_file(path).is_ok()
    } else {
        false
    }
}

/// Toggle or update endpoint mode (`CliProxy` vs `OfficialApi`) on persisted credentials.
pub fn set_grok_endpoint_mode(state_dir: &Path, mode: GrokEndpointMode) -> Result<GrokOAuthCreds> {
    let mut creds = load_grok_creds(state_dir).ok_or_else(|| {
        BridgeError::NotFound("Grok OAuth is not connected yet. Use /grok to sign in.".to_string())
    })?;
    creds.endpoint_mode = mode;
    creds.updated_at = now_unix();
    save_grok_creds(state_dir, &creds)?;
    Ok(creds)
}

/// Start RFC 8628 Device Authorization Grant against `auth.x.ai/oauth2/device/code`.
pub async fn start_device_auth() -> Result<GrokDeviceAuth> {
    start_device_auth_via(None).await
}

/// Start RFC 8628 Device Authorization Grant using an optional sticky egress proxy.
pub async fn start_device_auth_via(proxy_url: Option<&str>) -> Result<GrokDeviceAuth> {
    let eps = discover_xai_oidc_via(proxy_url).await;
    start_device_auth_at_via(
        &eps.device_authorization_endpoint,
        &grok_oauth_client_id(),
        proxy_url,
    )
    .await
}

pub async fn start_device_auth_at(device_endpoint: &str, client_id: &str) -> Result<GrokDeviceAuth> {
    start_device_auth_at_via(device_endpoint, client_id, None).await
}

pub async fn start_device_auth_at_via(
    device_endpoint: &str,
    client_id: &str,
    proxy_url: Option<&str>,
) -> Result<GrokDeviceAuth> {
    let client = build_http_client_with_proxy(20, proxy_url)?;
    let resp = client
        .post(device_endpoint)
        .form(&[("client_id", client_id), ("scope", XAI_OAUTH_SCOPE)])
        .send()
        .await
        .map_err(|e| BridgeError::Network(format!("xAI device auth request failed: {e}")))?;

    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(BridgeError::Auth(format!(
            "xAI device authorization failed (HTTP {}): {}",
            status.as_u16(),
            redact_secrets_in_text(&body).chars().take(300).collect::<String>()
        )));
    }

    let parsed: GrokDeviceAuth = serde_json::from_str(&body)
        .map_err(|e| BridgeError::json("parsing xAI device auth response", e))?;
    if parsed.device_code.is_empty() || parsed.user_code.is_empty() {
        return Err(BridgeError::Auth(
            "xAI device auth response missing device_code or user_code".to_string(),
        ));
    }
    Ok(parsed)
}

fn parse_token_response(
    doc: &Value,
    prev: Option<&GrokOAuthCreds>,
) -> Result<GrokOAuthCreds> {
    let access_token = doc
        .get("access_token")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| BridgeError::Auth("xAI token response missing access_token".to_string()))?
        .to_string();
    let refresh_token = doc
        .get("refresh_token")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .or_else(|| prev.map(|p| p.refresh_token.clone()))
        .unwrap_or_default();
    let id_token = doc
        .get("id_token")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .or_else(|| prev.and_then(|p| p.id_token.clone()));

    let now = now_unix();
    let jwt_claims = decode_jwt_claims(&access_token)
        .or_else(|| id_token.as_deref().and_then(decode_jwt_claims));
    let id_claims = id_token.as_deref().and_then(decode_jwt_claims);

    let expires_in = doc.get("expires_in").and_then(Value::as_i64).unwrap_or(0);
    let jwt_exp = jwt_claims
        .as_ref()
        .and_then(|c| c.get("exp").and_then(Value::as_i64))
        .unwrap_or(0);
    let jwt_iat = jwt_claims
        .as_ref()
        .and_then(|c| c.get("iat").and_then(Value::as_i64))
        .unwrap_or(0);

    let expires_at = if jwt_exp > now {
        jwt_exp
    } else if expires_in > 0 {
        now + expires_in
    } else {
        now + 900
    };
    let token_lifetime_secs = if jwt_exp > jwt_iat && jwt_iat > 0 {
        jwt_exp - jwt_iat
    } else if expires_in > 0 {
        expires_in
    } else {
        (expires_at - now).max(60)
    };

    let email = id_claims
        .as_ref()
        .and_then(|c| c.get("email").and_then(Value::as_str))
        .or_else(|| {
            jwt_claims
                .as_ref()
                .and_then(|c| c.get("email").and_then(Value::as_str))
        })
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .or_else(|| prev.and_then(|p| p.email.clone()));

    let subject = id_claims
        .as_ref()
        .and_then(|c| c.get("sub").and_then(Value::as_str))
        .or_else(|| {
            jwt_claims
                .as_ref()
                .and_then(|c| c.get("sub").and_then(Value::as_str))
        })
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .or_else(|| prev.and_then(|p| p.subject.clone()));

    Ok(GrokOAuthCreds {
        access_token,
        refresh_token,
        id_token,
        expires_at,
        token_lifetime_secs,
        email,
        subject,
        endpoint_mode: prev.map(|p| p.endpoint_mode).unwrap_or_default(),
        quarantined_reason: None,
        updated_at: now,
    })
}

async fn fetch_userinfo_email_via(
    userinfo_endpoint: &str,
    access_token: &str,
    proxy_url: Option<&str>,
) -> Option<String> {
    let client = build_http_client_with_proxy(10, proxy_url).ok()?;
    let resp = client
        .get(userinfo_endpoint)
        .bearer_auth(access_token)
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let val: Value = resp.json().await.ok()?;
    val.get("email")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Perform one poll against `auth.x.ai/oauth2/token` for an active Device Code session.
pub async fn poll_device_token_once(
    device_code: &str,
    current_interval: u64,
) -> Result<DevicePollOutcome> {
    poll_device_token_once_via(device_code, current_interval, None).await
}

/// Perform one poll against `auth.x.ai/oauth2/token` using an optional sticky egress proxy.
pub async fn poll_device_token_once_via(
    device_code: &str,
    current_interval: u64,
    proxy_url: Option<&str>,
) -> Result<DevicePollOutcome> {
    let eps = discover_xai_oidc_via(proxy_url).await;
    poll_device_token_once_at_via(
        &eps.token_endpoint,
        &eps.userinfo_endpoint,
        &grok_oauth_client_id(),
        device_code,
        current_interval,
        proxy_url,
    )
    .await
}

pub async fn poll_device_token_once_at(
    token_endpoint: &str,
    userinfo_endpoint: &str,
    client_id: &str,
    device_code: &str,
    current_interval: u64,
) -> Result<DevicePollOutcome> {
    poll_device_token_once_at_via(
        token_endpoint,
        userinfo_endpoint,
        client_id,
        device_code,
        current_interval,
        None,
    )
    .await
}

pub async fn poll_device_token_once_at_via(
    token_endpoint: &str,
    userinfo_endpoint: &str,
    client_id: &str,
    device_code: &str,
    current_interval: u64,
    proxy_url: Option<&str>,
) -> Result<DevicePollOutcome> {
    let client = build_http_client_with_proxy(20, proxy_url)?;
    let resp = client
        .post(token_endpoint)
        .form(&[
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("client_id", client_id),
            ("device_code", device_code),
        ])
        .send()
        .await
        .map_err(|e| BridgeError::Network(format!("xAI token poll failed: {e}")))?;

    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    let doc: Value = serde_json::from_str(&body).unwrap_or_else(|_| json!({}));

    if status.is_success() {
        let mut creds = parse_token_response(&doc, None)?;
        if creds.email.is_none() && !userinfo_endpoint.is_empty() {
            creds.email =
                fetch_userinfo_email_via(userinfo_endpoint, &creds.access_token, proxy_url).await;
        }
        return Ok(DevicePollOutcome::Authorized(creds));
    }

    let err_code = doc
        .get("error")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_ascii_lowercase();
    let err_desc = doc
        .get("error_description")
        .and_then(Value::as_str)
        .unwrap_or("");

    match err_code.as_str() {
        "authorization_pending" => Ok(DevicePollOutcome::Pending),
        "slow_down" => Ok(DevicePollOutcome::SlowDown(current_interval.saturating_add(5))),
        "expired_token" => Ok(DevicePollOutcome::Expired),
        "access_denied" => Ok(DevicePollOutcome::Denied(if err_desc.is_empty() {
            "Authorization was denied in x.ai".to_string()
        } else {
            err_desc.to_string()
        })),
        _ => Err(BridgeError::Auth(format!(
            "xAI OAuth token error (HTTP {}): {} {}",
            status.as_u16(),
            err_code,
            redact_secrets_in_text(err_desc).chars().take(200).collect::<String>()
        ))),
    }
}

/// Ensure we have a fresh valid Grok OAuth credential, serializing single-use refresh token
/// rotation behind a Tokio mutex so concurrent requests never double-spend a refresh token.
pub async fn ensure_valid_grok_creds(
    state_dir: &Path,
    force_refresh: bool,
) -> Result<GrokOAuthCreds> {
    ensure_valid_grok_creds_via(state_dir, force_refresh, None).await
}

/// Ensure we have a fresh valid Grok OAuth credential using an optional sticky egress proxy.
pub async fn ensure_valid_grok_creds_via(
    state_dir: &Path,
    force_refresh: bool,
    proxy_url: Option<&str>,
) -> Result<GrokOAuthCreds> {
    let now = now_unix();
    if !force_refresh {
        if let Some(c) = load_grok_creds(state_dir) {
            if c.quarantined_reason.is_none() && !c.needs_refresh_at(now) {
                return Ok(c);
            }
        }
    }

    let _lock = refresh_mutex().lock().await;
    // Double-check under lock (another task may have just rotated the refresh token!)
    let current = load_grok_creds(state_dir).ok_or_else(|| {
        BridgeError::Auth(
            "Grok OAuth is not connected. Run /grok and tap 'Connect Grok (OAuth)'.".to_string(),
        )
    })?;
    let now2 = now_unix();
    if !force_refresh && current.quarantined_reason.is_none() && !current.needs_refresh_at(now2) {
        return Ok(current);
    }
    if current.refresh_token.trim().is_empty() {
        return Err(BridgeError::Auth(
            "Grok OAuth session has no refresh token — please reconnect via /grok.".to_string(),
        ));
    }

    let eps = discover_xai_oidc_via(proxy_url).await;
    refresh_grok_creds_at_via(
        state_dir,
        &current,
        &eps.token_endpoint,
        &grok_oauth_client_id(),
        proxy_url,
    )
    .await
}

pub async fn refresh_grok_creds_at(
    state_dir: &Path,
    current: &GrokOAuthCreds,
    token_endpoint: &str,
    client_id: &str,
) -> Result<GrokOAuthCreds> {
    refresh_grok_creds_at_via(state_dir, current, token_endpoint, client_id, None).await
}

pub async fn refresh_grok_creds_at_via(
    state_dir: &Path,
    current: &GrokOAuthCreds,
    token_endpoint: &str,
    client_id: &str,
    proxy_url: Option<&str>,
) -> Result<GrokOAuthCreds> {
    let client = build_http_client_with_proxy(20, proxy_url)?;
    let mut attempt: u32 = 0;
    let (status, body) = loop {
        attempt += 1;
        let resp = client
            .post(token_endpoint)
            .form(&[
                ("grant_type", "refresh_token"),
                ("client_id", client_id),
                ("refresh_token", current.refresh_token.as_str()),
            ])
            .send()
            .await
            .map_err(|e| BridgeError::Network(format!("xAI token refresh failed: {e}")))?;

        let status = resp.status();
        let retry_after_hdr = resp
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.trim().parse::<u64>().ok())
            .map(|s| s.clamp(1, 30));
        let body = resp.text().await.unwrap_or_default();

        // Only retry transient rate-limit / upstream gateway codes (never 400/401/403).
        if matches!(status.as_u16(), 429 | 502 | 503 | 504) && attempt < 2 {
            let wait_s = retry_after_hdr.unwrap_or(2);
            warn!(
                status = status.as_u16(),
                wait_s,
                "xAI OAuth token refresh hit transient error; backing off politely"
            );
            tokio::time::sleep(Duration::from_secs(wait_s)).await;
            continue;
        }
        break (status, body);
    };
    let doc: Value = serde_json::from_str(&body).unwrap_or_else(|_| json!({}));

    if status.is_success() {
        let refreshed = parse_token_response(&doc, Some(current))?;
        save_grok_creds(state_dir, &refreshed)?;
        info!(
            email = ?refreshed.masked_email(),
            expires_in = refreshed.expires_at - now_unix(),
            "Grok OAuth token refreshed and rotated atomically"
        );
        return Ok(refreshed);
    }

    let err_code = doc
        .get("error")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_ascii_lowercase();
    let err_desc = doc
        .get("error_description")
        .and_then(Value::as_str)
        .unwrap_or("");
    let terminal = matches!(status.as_u16(), 400 | 401 | 403)
        && (err_code == "invalid_grant" || err_code == "invalid_token" || err_code == "unauthorized_client");

    let reason = format!(
        "xAI OAuth refresh rejected (HTTP {}): {} {}",
        status.as_u16(),
        err_code,
        redact_secrets_in_text(err_desc).chars().take(200).collect::<String>()
    );
    if terminal {
        let mut q = current.clone();
        q.quarantined_reason = Some(reason.clone());
        q.updated_at = now_unix();
        let _ = save_grok_creds(state_dir, &q);
        warn!(reason = %reason, "Grok OAuth refresh token quarantined; user must re-authenticate");
    }
    Err(BridgeError::Auth(format!(
        "{reason}. Please reconnect your Grok account via /grok."
    )))
}

/// Build the exact verified CLI / API headers for a Grok OAuth request.
pub fn build_grok_headers(
    creds: &GrokOAuthCreds,
    cli_version: &str,
    conv_id: Option<&str>,
) -> Vec<(String, String)> {
    let mut hdrs = vec![(
        "Authorization".to_string(),
        format!("Bearer {}", creds.access_token),
    )];
    if creds.endpoint_mode == GrokEndpointMode::CliProxy {
        hdrs.push(("X-XAI-Token-Auth".to_string(), "xai-grok-cli".to_string()));
        hdrs.push(("x-grok-client-version".to_string(), cli_version.to_string()));
        hdrs.push(("x-grok-client-identifier".to_string(), "grok-shell".to_string()));
        hdrs.push((
            "x-authenticateresponse".to_string(),
            "authenticate-response".to_string(),
        ));
        hdrs.push((
            "User-Agent".to_string(),
            format!("xai-grok-workspace/{cli_version}"),
        ));
    }
    if let Some(cid) = conv_id.filter(|s| !s.is_empty()) {
        hdrs.push(("x-grok-conv-id".to_string(), cid.to_string()));
    }
    hdrs
}

/// Curated Nov 2026 fallback model list for xAI Grok subscriptions.
pub fn fallback_grok_models() -> Vec<GrokModel> {
    vec![
        GrokModel {
            id: "grok-4.7".to_string(),
            name: "Grok 4.7 (Frontier Agentic · 500k)".to_string(),
            context_length: Some(500_000),
        },
        GrokModel {
            id: "grok-build-0.1".to_string(),
            name: "Grok Build 0.1 (Coding Agent)".to_string(),
            context_length: Some(256_000),
        },
        GrokModel {
            id: "grok-4.5".to_string(),
            name: "Grok 4.5 (Fast Reasoning)".to_string(),
            context_length: Some(256_000),
        },
        GrokModel {
            id: "grok-4.20-0309-reasoning".to_string(),
            name: "Grok 4.20 Reasoning".to_string(),
            context_length: Some(256_000),
        },
        GrokModel {
            id: "grok-4.20-0309-non-reasoning".to_string(),
            name: "Grok 4.20 Fast".to_string(),
            context_length: Some(256_000),
        },
        GrokModel {
            id: "grok-4.20-multi-agent-0309".to_string(),
            name: "Grok 4.20 Multi-Agent".to_string(),
            context_length: Some(256_000),
        },
    ]
}

pub fn is_grok_model(model: &str) -> bool {
    let low = model.trim().to_ascii_lowercase();
    low.starts_with("grok-") || low.starts_with("xai/") || low.starts_with("grok/")
}

pub fn clean_grok_model_id(model: &str) -> String {
    let t = model.trim();
    t.strip_prefix("xai/")
        .or_else(|| t.strip_prefix("grok/"))
        .unwrap_or(t)
        .to_string()
}

pub fn load_cached_grok_models(state_dir: &Path) -> Vec<GrokModel> {
    let p = grok_models_path(state_dir);
    if let Ok(raw) = std::fs::read_to_string(&p) {
        if let Ok(list) = serde_json::from_str::<Vec<GrokModel>>(&raw) {
            if !list.is_empty() {
                return list;
            }
        }
    }
    fallback_grok_models()
}

/// Refresh available Grok models live from the active OAuth endpoint (`GET /v1/models`).
pub async fn refresh_grok_models(state_dir: &Path) -> Vec<GrokModel> {
    refresh_grok_models_via(state_dir, None).await
}

/// Refresh available Grok models live using an optional sticky egress proxy.
pub async fn refresh_grok_models_via(
    state_dir: &Path,
    proxy_url: Option<&str>,
) -> Vec<GrokModel> {
    let Ok(creds) = ensure_valid_grok_creds_via(state_dir, false, proxy_url).await else {
        return load_cached_grok_models(state_dir);
    };
    let ver = resolve_grok_cli_version_via(false, proxy_url).await;
    let Ok(client) = build_http_client_with_proxy(15, proxy_url) else {
        return load_cached_grok_models(state_dir);
    };
    let url = format!("{}/models", creds.endpoint_mode.api_base());
    let mut req = client.get(&url);
    for (k, v) in build_grok_headers(&creds, &ver, None) {
        req = req.header(k, v);
    }

    let Ok(resp) = req.send().await else {
        return load_cached_grok_models(state_dir);
    };
    if !resp.status().is_success() {
        return load_cached_grok_models(state_dir);
    }
    let Ok(doc) = resp.json::<Value>().await else {
        return load_cached_grok_models(state_dir);
    };
    let Some(arr) = doc.get("data").and_then(Value::as_array) else {
        return load_cached_grok_models(state_dir);
    };

    let mut models: Vec<GrokModel> = arr
        .iter()
        .filter_map(|item| {
            let id = item.get("id").and_then(Value::as_str)?.trim();
            if id.is_empty() || !id.to_ascii_lowercase().contains("grok") {
                return None;
            }
            let name = item
                .get("name")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .unwrap_or(id)
                .to_string();
            let context_length = item
                .get("context_length")
                .or_else(|| item.get("max_context_length"))
                .and_then(Value::as_u64);
            Some(GrokModel {
                id: id.to_string(),
                name,
                context_length,
            })
        })
        .collect();

    if models.is_empty() {
        return load_cached_grok_models(state_dir);
    }
    models.sort_by(|a, b| a.id.cmp(&b.id));
    let _ = atomic_write_json(&grok_models_path(state_dir), &models, true);
    models
}

struct GrokOAuthProvider {
    state_dir: PathBuf,
    conv_id: String,
    proxy_url: Option<String>,
}

impl AuthHeaderProvider for GrokOAuthProvider {
    fn resolve_request<'a>(
        &'a self,
        force_refresh_auth: bool,
        force_refresh_version: bool,
    ) -> RequestAuthFuture<'a> {
        Box::pin(async move {
            let px = self.proxy_url.as_deref();
            let creds = ensure_valid_grok_creds_via(&self.state_dir, force_refresh_auth, px).await?;
            let ver = resolve_grok_cli_version_via(force_refresh_version, px).await;
            let url = format!("{}/chat/completions", creds.endpoint_mode.api_base());
            let hdrs = build_grok_headers(&creds, &ver, Some(&self.conv_id));
            Ok((url, hdrs))
        })
    }

    fn format_http_error(&self, status: u16, body: &str) -> String {
        let excerpt: String = redact_secrets_in_text(body).chars().take(450).collect();
        match status {
            401 => format!(
                "Grok OAuth unauthorized (HTTP 401): {excerpt}. Reconnect your account via /grok."
            ),
            403 => format!(
                "Grok Subscription access denied (HTTP 403): {excerpt}. Ensure your x.ai account has an active SuperGrok or X Premium+ subscription with Grok CLI access, or try switching endpoints in /grok."
            ),
            426 => format!(
                "Grok CLI client version rejected (HTTP 426): {excerpt}. Try again or set XAI_GROK_CLI_VERSION."
            ),
            _ => format!("Grok API error (HTTP {status}): {excerpt}"),
        }
    }
}

/// Run a multi-turn Grok Subscription OAuth autonomous agent (or chat) turn.
#[allow(clippy::too_many_arguments)]
pub async fn run_grok_agent(
    state_dir: &Path,
    model: &str,
    user_prompt: &str,
    cwd: &Path,
    workspace_root: &Path,
    mcp_config_path: &Path,
    skills_dir: &Path,
    session_key: Option<String>,
    allow_root: bool,
    allow_sandbox: bool,
    agent_mode: bool,
    on_progress: Option<ProgressCallback>,
    cancel: watch::Receiver<bool>,
) -> Result<JobResult> {
    run_grok_agent_via(
        state_dir,
        model,
        user_prompt,
        cwd,
        workspace_root,
        mcp_config_path,
        skills_dir,
        session_key,
        allow_root,
        allow_sandbox,
        agent_mode,
        None,
        on_progress,
        cancel,
    )
    .await
}

/// Run a multi-turn Grok Subscription OAuth turn routed through an optional sticky egress proxy.
#[allow(clippy::too_many_arguments)]
pub async fn run_grok_agent_via(
    state_dir: &Path,
    model: &str,
    user_prompt: &str,
    cwd: &Path,
    workspace_root: &Path,
    mcp_config_path: &Path,
    skills_dir: &Path,
    session_key: Option<String>,
    allow_root: bool,
    allow_sandbox: bool,
    agent_mode: bool,
    proxy_url: Option<String>,
    on_progress: Option<ProgressCallback>,
    cancel: watch::Receiver<bool>,
) -> Result<JobResult> {
    run_grok_agent_with_options(
        state_dir,
        model,
        user_prompt,
        cwd,
        workspace_root,
        mcp_config_path,
        skills_dir,
        session_key,
        allow_root,
        allow_sandbox,
        agent_mode,
        None,
        None,
        proxy_url,
        on_progress,
        cancel,
    )
    .await
}

/// Run a multi-turn Grok Subscription OAuth turn with custom `max_steps` & `system_prompt` overrides
/// (full OpenHands V1 parity with Venice Uncensored, also used by `openhands` MCP delegation).
#[allow(clippy::too_many_arguments)]
pub async fn run_grok_agent_with_options(
    state_dir: &Path,
    model: &str,
    user_prompt: &str,
    cwd: &Path,
    workspace_root: &Path,
    mcp_config_path: &Path,
    skills_dir: &Path,
    session_key: Option<String>,
    allow_root: bool,
    allow_sandbox: bool,
    agent_mode: bool,
    max_steps_opt: Option<usize>,
    custom_system_prompt: Option<&str>,
    proxy_url: Option<String>,
    on_progress: Option<ProgressCallback>,
    cancel: watch::Receiver<bool>,
) -> Result<JobResult> {
    let conv_id = session_key
        .as_deref()
        .map(|k| session_conv_id(state_dir, k))
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    let provider = GrokOAuthProvider {
        state_dir: state_dir.to_path_buf(),
        conv_id,
        proxy_url: proxy_url.clone(),
    };

    let clean_model = clean_grok_model_id(if model.trim().is_empty() {
        DEFAULT_GROK_MODEL
    } else {
        model
    });

    let system_prompt = match custom_system_prompt.filter(|s| !s.trim().is_empty()) {
        Some(s) => s.to_string(),
        None if agent_mode => crate::openhands::build_openhands_agent_prompt("Grok (xAI)"),
        None => GROK_CHAT_SYSTEM_PROMPT.to_string(),
    };

    let cfg = AgentTurnConfig {
        engine_id: "grok".to_string(),
        model: clean_model,
        system_prompt,
        cwd: cwd.to_path_buf(),
        workspace_root: workspace_root.to_path_buf(),
        allow_root,
        allow_sandbox: allow_sandbox || allow_root,
        agent_mode,
        mcp_config_path: mcp_config_path.to_path_buf(),
        skills_dir: skills_dir.to_path_buf(),
        state_dir: state_dir.to_path_buf(),
        session_key,
        max_steps: max_steps_opt.unwrap_or(DEFAULT_MAX_AGENT_STEPS),
        max_tokens: 32_768.max(DEFAULT_MAX_TOKENS),
        job_timeout_secs: DEFAULT_JOB_TIMEOUT_SECS,
        proxy_url,
        three_stage_mode: crate::agent_runtime::ThreeStageMode::Off,
    };

    run_openai_agent_turn(&provider, &cfg, user_prompt, on_progress, cancel).await
}

/// Active background OAuth device-flow cancellation handle.
pub struct GrokAuthSession {
    pub user_code: String,
    pub verification_url: String,
    cancel_tx: watch::Sender<bool>,
}

impl GrokAuthSession {
    pub fn new(user_code: String, verification_url: String) -> (Arc<Self>, watch::Receiver<bool>) {
        let (tx, rx) = watch::channel(false);
        (
            Arc::new(Self {
                user_code,
                verification_url,
                cancel_tx: tx,
            }),
            rx,
        )
    }

    pub fn cancel(&self) {
        let _ = self.cancel_tx.send(true);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    #[test]
    fn xai_endpoint_pinning_blocks_untrusted_hosts() {
        assert!(validate_xai_endpoint("https://auth.x.ai/oauth2/token").is_ok());
        assert!(validate_xai_endpoint("https://x.ai/oauth2/device/code").is_ok());
        assert!(validate_xai_endpoint("http://auth.x.ai/oauth2/token").is_err());
        assert!(validate_xai_endpoint("https://evil-x.ai/oauth2/token").is_err());
        assert!(validate_xai_endpoint("https://auth.x.ai.evil.com/token").is_err());
    }

    #[test]
    fn jwt_decode_adaptive_skew_and_secret_redaction() {
        // {"sub":"u123","email":"grokuser@example.com","iat":1000,"exp":1900}
        let jwt = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1MTIzIiwiZW1haWwiOiJncm9rdXNlckBleGFtcGxlLmNvbSIsImlhdCI6MTAwMCwiZXhwIjoxOTAwfQ.sig";
        let claims = decode_jwt_claims(jwt).unwrap();
        assert_eq!(claims["email"], "grokuser@example.com");
        assert_eq!(claims["exp"], 1900);

        let creds = GrokOAuthCreds {
            access_token: "secret-access-tok".into(),
            refresh_token: "secret-refresh-tok".into(),
            id_token: None,
            expires_at: 1900,
            token_lifetime_secs: 900, // 15m -> 120s skew
            email: Some("grokuser@example.com".into()),
            subject: Some("u123".into()),
            endpoint_mode: GrokEndpointMode::CliProxy,
            quarantined_reason: None,
            updated_at: 1000,
        };
        assert_eq!(creds.proactive_skew_secs(), 120);
        assert!(!creds.needs_refresh_at(1700));
        assert!(creds.needs_refresh_at(1785));

        let dbg = format!("{creds:?}");
        assert!(!dbg.contains("secret-access-tok"));
        assert!(!dbg.contains("secret-refresh-tok"));
        assert!(!dbg.contains("grokuser@example.com"));

        let hdrs = build_grok_headers(&creds, "1.0.92", Some("conv-42"));
        assert!(hdrs.iter().any(|(k, v)| k == "X-XAI-Token-Auth" && v == "xai-grok-cli"));
        assert!(hdrs.iter().any(|(k, v)| k == "x-grok-client-version" && v == "1.0.92"));
        assert!(hdrs.iter().any(|(k, v)| k == "x-grok-conv-id" && v == "conv-42"));

        let dir = TempDir::new().unwrap();
        save_grok_creds(dir.path(), &creds).unwrap();
        let mode = std::fs::metadata(grok_oauth_path(dir.path()))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        let reloaded = load_grok_creds(dir.path()).unwrap();
        assert_eq!(reloaded.email.as_deref(), Some("grokuser@example.com"));
    }

    #[test]
    fn grok_model_detection_and_cleaning() {
        assert!(is_grok_model("grok-4.7"));
        assert!(is_grok_model("xai/grok-4.5"));
        assert!(!is_grok_model("veniceai/deepseek-v4-1-flash-1017-uncensored"));
        assert_eq!(clean_grok_model_id("xai/grok-4.7"), "grok-4.7");
        assert!(GROK_AGENT_SYSTEM_PROMPT.contains("file_editor"));
        assert!(GROK_AGENT_SYSTEM_PROMPT.contains("execute_code"));
        assert!(GROK_AGENT_SYSTEM_PROMPT.contains("verify_project"));
        assert!(GROK_AGENT_SYSTEM_PROMPT.contains("150 calls"));
    }
}
