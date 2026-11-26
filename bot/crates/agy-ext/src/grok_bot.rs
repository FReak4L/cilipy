//! Grok Bot (`x.ai/bot` / Cursor Sand backend) PKCE OAuth 2.0 & ConnectRPC client.
//!
//! Deliberately separate from [`crate::grok_oauth`] (Grok CLI / `auth.x.ai`):
//! - Grok CLI uses RFC 8628 Device Code on `auth.x.ai` -> `cli-chat-proxy.grok.com/v1`.
//! - Grok Bot uses headless PKCE Deep-Control polling (`cursor.com/loginDeepControl` +
//!   `api2.cursor.sh/auth/poll`), Sand token refresh (`POST /oauth/token`), and
//!   ConnectRPC JSON over HTTPS (`https://api2.cursor.sh/aiserver.v1.GrokBotService/*`).
//! - Redirects are disabled (`Policy::none()`) on all credentialed requests, and hosts are
//!   strictly pinned to HTTPS `cursor.sh` / `*.cursor.sh` / `cursor.com` / `*.cursor.com`.

use std::collections::HashSet;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use agy_core::atomic::atomic_write_json;
use agy_core::error::{BridgeError, Result};
use rand::rngs::OsRng;
use rand::RngCore;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::sync::{watch, Mutex};
use tracing::{info, warn};
use url::Url;

use crate::engines::{JobResult, Progress, ProgressCallback};
use crate::mcp_client::redact_secrets_in_text;

pub const GROK_BOT_LOGIN_BASE: &str = "https://cursor.com";
pub const DEFAULT_GROK_BOT_BACKEND: &str = "https://api2.cursor.sh";
pub const DEFAULT_GROK_BOT_CLIENT_ID: &str = "KbZUR41cY7W6zRSdpSUJ7I7mLYBKOCmB";
pub const DEFAULT_GROK_BOT_CLIENT_VERSION: &str = "0.75.0";
pub const DEFAULT_POLL_TIMEOUT_SECS: u64 = 300;
pub const DEFAULT_TURN_TIMEOUT_SECS: u64 = 600;
pub const GROK_BOT_SVC: &str = "GrokBotService";
pub const DASHBOARD_SVC: &str = "DashboardService";

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub fn grok_bot_oauth_path(state_dir: &Path) -> PathBuf {
    state_dir.join("grok_bot_oauth.json")
}

pub fn grok_bot_agents_path(state_dir: &Path) -> PathBuf {
    state_dir.join("grok_bot_agents.json")
}

pub fn grok_bot_client_id() -> String {
    std::env::var("GROK_BOT_OAUTH_CLIENT_ID")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_GROK_BOT_CLIENT_ID.to_string())
}

pub fn grok_bot_client_version() -> String {
    std::env::var("GROK_BOT_CLIENT_VERSION")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_GROK_BOT_CLIENT_VERSION.to_string())
}

/// Validate that a Grok Bot backend URL uses HTTPS on `cursor.sh` / `*.cursor.sh` /
/// `cursor.com` / `*.cursor.com`.
pub fn validate_grok_bot_backend(raw: &str) -> Result<String> {
    let parsed = Url::parse(raw.trim())
        .map_err(|e| BridgeError::Validation(format!("invalid Grok Bot backend URL: {e}")))?;
    if parsed.scheme() != "https" {
        return Err(BridgeError::Validation(format!(
            "refusing non-HTTPS Grok Bot backend scheme '{}'",
            parsed.scheme()
        )));
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| BridgeError::Validation("Grok Bot backend URL missing host".to_string()))?
        .to_ascii_lowercase();
    let trusted = host == "cursor.sh"
        || host.ends_with(".cursor.sh")
        || host == "cursor.com"
        || host.ends_with(".cursor.com");
    if !trusted {
        return Err(BridgeError::Validation(format!(
            "refusing untrusted Grok Bot backend host '{host}'"
        )));
    }
    Ok(parsed.to_string().trim_end_matches('/').to_string())
}

pub fn grok_bot_backend_url() -> Result<String> {
    match std::env::var("GROK_BOT_BACKEND_URL") {
        Ok(raw) if !raw.trim().is_empty() => validate_grok_bot_backend(&raw),
        _ => Ok(DEFAULT_GROK_BOT_BACKEND.to_string()),
    }
}

/// Pure-Rust Base64URL encoder without `=` padding (RFC 4648 §5).
pub fn encode_base64url_nopad(input: &[u8]) -> String {
    const TABLE: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    let mut i = 0;
    while i < input.len() {
        let b0 = input[i] as u32;
        let b1 = if i + 1 < input.len() {
            input[i + 1] as u32
        } else {
            0
        };
        let b2 = if i + 2 < input.len() {
            input[i + 2] as u32
        } else {
            0
        };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[((triple >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((triple >> 12) & 0x3f) as usize] as char);
        if i + 1 < input.len() {
            out.push(TABLE[((triple >> 6) & 0x3f) as usize] as char);
        }
        if i + 2 < input.len() {
            out.push(TABLE[(triple & 0x3f) as usize] as char);
        }
        i += 3;
    }
    out
}

/// Pure-Rust Base64 / Base64URL decoder (handles both padded standard and unpadded URL-safe).
pub fn decode_base64_any(input: &str) -> Option<Vec<u8>> {
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

pub fn decode_jwt_claims(jwt: &str) -> Option<Value> {
    let payload_b64 = jwt.split('.').nth(1)?;
    let decoded = decode_base64_any(payload_b64)?;
    serde_json::from_slice::<Value>(&decoded).ok()
}

/// Generate a fresh 64-char hex machine identifier (`SHA256(32 random bytes)`).
pub fn new_machine_id() -> String {
    let mut raw = [0u8; 32];
    OsRng.fill_bytes(&mut raw);
    hex::encode(Sha256::digest(raw))
}

/// Compute `x-cursor-checksum` for an arbitrary epoch millisecond timestamp and `machine_id`.
pub fn checksum_at(ms: u64, machine_id: &str) -> String {
    let t = ms / 1_000_000;
    let mut bytes: Vec<u8> = (0..6).rev().map(|i| (t >> (i * 8)) as u8).collect();
    let mut prev = 165u8;
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = (*b ^ prev).wrapping_add((i % 256) as u8);
        prev = *b;
    }
    format!("{}{machine_id}", encode_base64url_nopad(&bytes))
}

pub fn cursor_checksum(machine_id: &str) -> String {
    checksum_at(now_ms(), machine_id)
}

/// Persisted Grok Bot OAuth credentials (`$STATE_DIR/grok_bot_oauth.json`, `0600`).
#[derive(Clone, Serialize, Deserialize)]
pub struct GrokBotCreds {
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: String,
    #[serde(default)]
    pub auth_id: Option<String>,
    #[serde(default)]
    pub expires_at: i64,
    #[serde(default)]
    pub token_lifetime_secs: i64,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub first_name: Option<String>,
    #[serde(default)]
    pub team_name: Option<String>,
    #[serde(default)]
    pub subject: Option<String>,
    #[serde(default = "new_machine_id")]
    pub machine_id: String,
    #[serde(default)]
    pub quarantined_reason: Option<String>,
    #[serde(default)]
    pub updated_at: i64,
}

impl fmt::Debug for GrokBotCreds {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GrokBotCreds")
            .field("access_token", &"[REDACTED]")
            .field("refresh_token", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .field("email", &self.masked_email())
            .field("team_name", &self.team_name)
            .field("quarantined_reason", &self.quarantined_reason)
            .finish()
    }
}

impl GrokBotCreds {
    pub fn masked_email(&self) -> Option<String> {
        self.email.as_deref().map(agy_core::accounts::mask_email)
    }

    pub fn proactive_skew_secs(&self) -> i64 {
        if self.token_lifetime_secs > 0 && self.token_lifetime_secs <= 45 * 60 {
            120
        } else {
            300
        }
    }

    pub fn is_expired_at(&self, now: i64) -> bool {
        self.access_token.trim().is_empty() || (self.expires_at > 0 && now >= self.expires_at)
    }

    pub fn needs_refresh_at(&self, now: i64) -> bool {
        if self.access_token.trim().is_empty() {
            return true;
        }
        if self.expires_at <= 0 {
            return false;
        }
        now + self.proactive_skew_secs() >= self.expires_at
    }
}

/// Generated PKCE Deep-Control login challenge for Telegram interactive sign-in.
#[derive(Debug, Clone)]
pub struct GrokBotPkceLogin {
    pub uuid: String,
    pub verifier: String,
    pub challenge: String,
    pub login_url: String,
    pub short_code: String,
    pub expires_in: u64,
}

/// Single poll outcome from `GET /auth/poll`.
#[derive(Debug, Clone)]
pub enum GrokBotPollOutcome {
    Pending,
    Authorized(GrokBotCreds),
    Expired(String),
    Denied(String),
}

/// Active background Grok Bot OAuth session handle for cancellation & replacement.
pub struct GrokBotAuthSession {
    pub short_code: String,
    pub login_url: String,
    cancel_tx: watch::Sender<bool>,
}

impl GrokBotAuthSession {
    pub fn new(short_code: String, login_url: String) -> (Arc<Self>, watch::Receiver<bool>) {
        let (tx, rx) = watch::channel(false);
        (
            Arc::new(Self {
                short_code,
                login_url,
                cancel_tx: tx,
            }),
            rx,
        )
    }

    pub fn cancel(&self) {
        let _ = self.cancel_tx.send(true);
    }
}

/// Deserialize protobuf-JSON int64/uint64 arriving as either JSON string or integer.
pub fn i64_str<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<i64, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum N {
        S(String),
        I(i64),
    }
    match N::deserialize(d)? {
        N::S(s) => s.trim().parse().map_err(serde::de::Error::custom),
        N::I(i) => Ok(i),
    }
}

pub fn opt_i64_str<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<Option<i64>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum N {
        Null,
        S(String),
        I(i64),
    }
    match Option::<N>::deserialize(d)? {
        None | Some(N::Null) => Ok(None),
        Some(N::S(s)) => {
            let t = s.trim();
            if t.is_empty() {
                Ok(None)
            } else {
                t.parse().map(Some).map_err(serde::de::Error::custom)
            }
        }
        Some(N::I(i)) => Ok(Some(i)),
    }
}

/// Strip protobuf enum `SCREAMING_SNAKE` prefix: `GROK_BOT_SEND_STATUS_ACCEPTED` -> `accepted`.
pub fn enum_suffix(value: &str, prefix: &str) -> String {
    value
        .strip_prefix(prefix)
        .unwrap_or(value)
        .trim_start_matches('_')
        .to_ascii_lowercase()
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct GrokBotMe {
    pub email: Option<String>,
    pub first_name: Option<String>,
    pub team_name: Option<String>,
    pub public_user_id: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct GrokBotUsage {
    pub usage_percent: Option<f64>,
    pub has_available_usage: Option<bool>,
    pub next_reset_timestamp_utc: Option<String>,
    pub grok_plan_label: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", default)]
pub struct GrokBotAgent {
    pub id: String,
    pub agent_id: String,
    pub name: String,
    pub description: String,
    pub kind: String,
    pub visibility: Option<String>,
    pub viewer_is_owner: Option<bool>,
    pub owner_display_name: Option<String>,
    #[serde(deserialize_with = "i64_str")]
    pub updated_at_ms: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct GrokBotLiveActivity {
    pub kind: String,
    pub tool: String,
    pub detail: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct GrokBotAwaiting {
    pub reason: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct GrokBotTurnSettlement {
    pub turn_id: String,
    pub outcome: String,
    #[serde(deserialize_with = "i64_str")]
    pub settled_at_ms: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct GrokBotLiveState {
    pub is_running: bool,
    pub is_composing_message: bool,
    pub activity: Option<GrokBotLiveActivity>,
    pub awaiting: Option<GrokBotAwaiting>,
    pub has_running_subagents: bool,
    pub working_task_ids: Vec<String>,
    pub last_turn_settlement: Option<GrokBotTurnSettlement>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct GrokBotAgentStatus {
    pub agent_id: String,
    pub is_running: bool,
    pub live: Option<GrokBotLiveState>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct RawTranscriptEntry {
    #[serde(deserialize_with = "i64_str")]
    pub seq: i64,
    pub entry_kind: String,
    pub entry_id: Option<String>,
    pub body: Option<String>,
    pub body_omitted: bool,
}

#[derive(Debug, Clone)]
pub struct DecodedTranscriptEntry {
    pub seq: i64,
    pub id: String,
    pub kind: String,
    pub timestamp_ms: i64,
    pub request_id: Option<String>,
    pub body: Value,
    pub body_omitted: bool,
}

pub enum GrokBotEntryView<'a> {
    User { text: &'a str, nonce: Option<&'a str> },
    Reply { text: &'a str },
    NeedsInput { what: String, answered: bool },
    AgentMessage { to: Option<&'a str>, text: &'a str },
    Attachment { name: &'a str },
    Event { summary: String },
    Other,
}

impl DecodedTranscriptEntry {
    pub fn decode(raw: &RawTranscriptEntry) -> Self {
        let body: Value = raw
            .body
            .as_deref()
            .and_then(decode_base64_any)
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or(Value::Null);
        Self {
            seq: raw.seq,
            id: raw
                .entry_id
                .clone()
                .or_else(|| body.get("id").and_then(Value::as_str).map(str::to_owned))
                .unwrap_or_default(),
            kind: raw.entry_kind.clone(),
            timestamp_ms: body.get("timestampMs").and_then(Value::as_i64).unwrap_or(0),
            request_id: body
                .get("requestId")
                .and_then(Value::as_str)
                .map(str::to_owned),
            body,
            body_omitted: raw.body_omitted,
        }
    }

    pub fn view(&self) -> GrokBotEntryView<'_> {
        let b = &self.body;
        match self.kind.as_str() {
            "message" if b.get("role").and_then(Value::as_str) == Some("user") => {
                GrokBotEntryView::User {
                    text: b.get("content").and_then(Value::as_str).unwrap_or(""),
                    nonce: b.get("clientNonce").and_then(Value::as_str),
                }
            }
            "message" => GrokBotEntryView::AgentMessage {
                to: b
                    .get("toAgent")
                    .and_then(|a| a.get("name"))
                    .and_then(Value::as_str),
                text: b.get("content").and_then(Value::as_str).unwrap_or(""),
            },
            "send-message" => {
                let m = b.get("message").unwrap_or(&Value::Null);
                let m_type = m.get("type").and_then(Value::as_str).unwrap_or("");
                match m_type {
                    "text" => GrokBotEntryView::Reply {
                        text: m.get("content").and_then(Value::as_str).unwrap_or(""),
                    },
                    "widget" => {
                        let w = m.get("widget").unwrap_or(&Value::Null);
                        let prompt = w
                            .get("prompt")
                            .and_then(Value::as_str)
                            .unwrap_or("choose an option");
                        let opts = w
                            .get("options")
                            .and_then(Value::as_array)
                            .map(|arr| {
                                arr.iter()
                                    .filter_map(|o| o.get("label").and_then(Value::as_str))
                                    .collect::<Vec<_>>()
                                    .join(" / ")
                            })
                            .unwrap_or_default();
                        GrokBotEntryView::NeedsInput {
                            what: if opts.is_empty() {
                                prompt.to_string()
                            } else {
                                format!("{prompt} [{opts}]")
                            },
                            answered: b.get("respondedValue").is_some(),
                        }
                    }
                    "secret-request" => {
                        let lbl = m
                            .get("secretRequest")
                            .and_then(|s| s.get("label"))
                            .and_then(Value::as_str)
                            .unwrap_or("?");
                        GrokBotEntryView::NeedsInput {
                            what: format!("secret: {lbl}"),
                            answered: b.get("secretProvided").is_some(),
                        }
                    }
                    t if t.ends_with("-draft") => GrokBotEntryView::NeedsInput {
                        what: format!("{t} to review"),
                        answered: b.get("draftSendState").is_some(),
                    },
                    t if t.ends_with("-approval") => GrokBotEntryView::NeedsInput {
                        what: t.to_owned(),
                        answered: b.get("respondedValue").is_some()
                            || b.get("resolution").is_some(),
                    },
                    _ => GrokBotEntryView::Other,
                }
            }
            "user-attachment" => GrokBotEntryView::Attachment {
                name: b.get("file_name").and_then(Value::as_str).unwrap_or("?"),
            },
            "event" => {
                let e = b.get("event").unwrap_or(&Value::Null);
                let name = e
                    .get("automationName")
                    .and_then(Value::as_str)
                    .or_else(|| e.get("name").and_then(Value::as_str))
                    .unwrap_or("");
                let ev_type = e.get("type").and_then(Value::as_str).unwrap_or("event");
                let action = e.get("action").and_then(Value::as_str).unwrap_or("");
                GrokBotEntryView::Event {
                    summary: format!("{ev_type} {action} {name}").trim().to_owned(),
                }
            }
            _ => GrokBotEntryView::Other,
        }
    }
}

fn grok_bot_refresh_mutex() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn build_http_client(timeout_secs: u64, proxy_url: Option<&str>) -> Result<reqwest::Client> {
    let mut b = reqwest::Client::builder()
        .use_rustls_tls()
        .redirect(reqwest::redirect::Policy::none())
        .tcp_keepalive(Duration::from_secs(30))
        .timeout(Duration::from_secs(timeout_secs));
    if let Some(px) = proxy_url.map(str::trim).filter(|s| !s.is_empty()) {
        let proxy = reqwest::Proxy::all(px).map_err(|e| {
            BridgeError::Network(format!(
                "invalid Grok Bot egress proxy {}: {e}",
                agy_core::redact_proxy_url(px)
            ))
        })?;
        b = b.proxy(proxy);
    }
    b.build()
        .map_err(|e| BridgeError::Network(format!("Grok Bot HTTP client failed: {e}")))
}

fn build_sand_headers(token: &str, machine_id: &str) -> Result<HeaderMap> {
    let ver = grok_bot_client_version();
    let mut h = HeaderMap::new();
    let pairs = [
        ("content-type", "application/json".to_string()),
        ("connect-protocol-version", "1".to_string()),
        ("authorization", format!("Bearer {token}")),
        (
            "user-agent",
            format!(
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Sand/{ver} Safari/537.36"
            ),
        ),
        ("x-cursor-client-type", "sand".to_string()),
        ("x-cursor-client-version", ver),
        ("x-cursor-client-os", "linux".to_string()),
        ("x-cursor-client-source", "sand-desktop".to_string()),
        ("x-sand-box-namespace", "prod".to_string()),
        ("x-ghost-mode", "true".to_string()),
        ("x-cursor-checksum", cursor_checksum(machine_id)),
        ("x-request-id", uuid::Uuid::new_v4().to_string()),
    ];
    for (k, v) in pairs {
        let name = HeaderName::from_bytes(k.as_bytes())
            .map_err(|e| BridgeError::Internal(format!("invalid header name '{k}': {e}")))?;
        let val = HeaderValue::from_str(&v)
            .map_err(|e| BridgeError::Internal(format!("invalid header value for '{k}': {e}")))?;
        h.insert(name, val);
    }
    Ok(h)
}

pub fn load_grok_bot_creds(state_dir: &Path) -> Option<GrokBotCreds> {
    let raw = std::fs::read_to_string(grok_bot_oauth_path(state_dir)).ok()?;
    serde_json::from_str::<GrokBotCreds>(&raw).ok()
}

pub fn save_grok_bot_creds(state_dir: &Path, creds: &GrokBotCreds) -> Result<()> {
    let path = grok_bot_oauth_path(state_dir);
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    atomic_write_json(&path, creds, true)
}

pub fn delete_grok_bot_creds(state_dir: &Path) -> bool {
    let path = grok_bot_oauth_path(state_dir);
    if path.exists() {
        std::fs::remove_file(path).is_ok()
    } else {
        false
    }
}

pub fn load_cached_grok_bot_agents(state_dir: &Path) -> Vec<GrokBotAgent> {
    let path = grok_bot_agents_path(state_dir);
    std::fs::read_to_string(path)
        .ok()
        .and_then(|raw| serde_json::from_str::<Vec<GrokBotAgent>>(&raw).ok())
        .unwrap_or_default()
}

/// Start a fresh PKCE Deep-Control login link for Grok Bot (can be called anytime to
/// regenerate an expired or stalled login session).
pub fn start_pkce_login() -> Result<GrokBotPkceLogin> {
    let mut raw = [0u8; 32];
    OsRng.fill_bytes(&mut raw);
    let verifier = encode_base64url_nopad(&raw);
    let challenge = encode_base64url_nopad(&Sha256::digest(verifier.as_bytes()));
    let uuid = uuid::Uuid::new_v4().to_string();
    let short_code: String = uuid
        .chars()
        .filter(|c| *c != '-')
        .take(8)
        .collect::<String>()
        .to_ascii_uppercase();
    let login_url = format!(
        "{GROK_BOT_LOGIN_BASE}/loginDeepControl?challenge={challenge}&uuid={uuid}&mode=login&redirectTarget=cli"
    );
    Ok(GrokBotPkceLogin {
        uuid,
        verifier,
        challenge,
        login_url,
        short_code,
        expires_in: DEFAULT_POLL_TIMEOUT_SECS,
    })
}

fn build_creds_from_tokens(
    access_token: String,
    refresh_token: String,
    auth_id: Option<String>,
    prev: Option<&GrokBotCreds>,
) -> GrokBotCreds {
    let now = now_unix();
    let claims = decode_jwt_claims(&access_token);
    let jwt_exp = claims
        .as_ref()
        .and_then(|c| c.get("exp").and_then(Value::as_i64))
        .unwrap_or(0);
    let jwt_iat = claims
        .as_ref()
        .and_then(|c| c.get("iat").and_then(Value::as_i64))
        .unwrap_or(0);
    let expires_at = if jwt_exp > now {
        jwt_exp
    } else {
        now + 3600
    };
    let token_lifetime_secs = if jwt_exp > jwt_iat && jwt_iat > 0 {
        jwt_exp - jwt_iat
    } else {
        (expires_at - now).max(60)
    };
    let email = claims
        .as_ref()
        .and_then(|c| c.get("email").and_then(Value::as_str))
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .or_else(|| prev.and_then(|p| p.email.clone()));
    let subject = claims
        .as_ref()
        .and_then(|c| c.get("sub").and_then(Value::as_str))
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .or_else(|| prev.and_then(|p| p.subject.clone()));

    GrokBotCreds {
        access_token,
        refresh_token,
        auth_id: auth_id.or_else(|| prev.and_then(|p| p.auth_id.clone())),
        expires_at,
        token_lifetime_secs,
        email,
        first_name: prev.and_then(|p| p.first_name.clone()),
        team_name: prev.and_then(|p| p.team_name.clone()),
        subject,
        machine_id: prev
            .map(|p| p.machine_id.clone())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(new_machine_id),
        quarantined_reason: None,
        updated_at: now,
    }
}

async fn fetch_me_with_token(
    backend: &str,
    access_token: &str,
    machine_id: &str,
    proxy_url: Option<&str>,
) -> Option<GrokBotMe> {
    let client = build_http_client(15, proxy_url).ok()?;
    let headers = build_sand_headers(access_token, machine_id).ok()?;
    let url = format!("{backend}/aiserver.v1.{DASHBOARD_SVC}/GetMe");
    let resp = client
        .post(&url)
        .headers(headers)
        .body("{}")
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    resp.json::<GrokBotMe>().await.ok()
}

/// Poll `GET {backend}/auth/poll?uuid=...&verifier=...` once.
pub async fn poll_pkce_login_once_via(
    uuid: &str,
    verifier: &str,
    proxy_url: Option<&str>,
) -> Result<GrokBotPollOutcome> {
    let backend = grok_bot_backend_url()?;
    poll_pkce_login_once_at_via(&backend, uuid, verifier, proxy_url).await
}

pub async fn poll_pkce_login_once_at_via(
    backend: &str,
    uuid: &str,
    verifier: &str,
    proxy_url: Option<&str>,
) -> Result<GrokBotPollOutcome> {
    let backend = validate_grok_bot_backend(backend)?;
    let client = build_http_client(20, proxy_url)?;
    let resp = client
        .get(format!("{backend}/auth/poll"))
        .query(&[("uuid", uuid), ("verifier", verifier)])
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|e| BridgeError::Network(format!("Grok Bot auth poll request failed: {e}")))?;

    let status = resp.status();
    let code = status.as_u16();
    let body = resp.text().await.unwrap_or_default();

    if code == 404 {
        return Ok(GrokBotPollOutcome::Pending);
    }
    if code == 403 {
        let excerpt: String = redact_secrets_in_text(&body).chars().take(180).collect();
        return Ok(GrokBotPollOutcome::Denied(if excerpt.is_empty() {
            "Sign-in was refused by server (HTTP 403)".to_string()
        } else {
            format!("HTTP 403: {excerpt}")
        }));
    }
    if code == 400 || code == 410 {
        let excerpt: String = redact_secrets_in_text(&body).chars().take(180).collect();
        return Ok(GrokBotPollOutcome::Expired(if excerpt.is_empty() {
            format!("Login link expired (HTTP {code})")
        } else {
            excerpt
        }));
    }
    if !status.is_success() {
        let excerpt: String = redact_secrets_in_text(&body).chars().take(200).collect();
        return Err(BridgeError::Network(format!(
            "Grok Bot auth poll failed (HTTP {code}): {excerpt}"
        )));
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct PollResp {
        access_token: Option<String>,
        refresh_token: Option<String>,
        auth_id: Option<String>,
    }

    let parsed: PollResp = serde_json::from_str(&body)
        .map_err(|e| BridgeError::json("parsing Grok Bot /auth/poll response", e))?;
    let Some(access_token) = parsed.access_token.filter(|s| !s.trim().is_empty()) else {
        return Err(BridgeError::Auth(
            "Grok Bot /auth/poll returned HTTP 200 without accessToken".to_string(),
        ));
    };
    let refresh_token = parsed.refresh_token.unwrap_or_default();
    let mut creds = build_creds_from_tokens(access_token, refresh_token, parsed.auth_id, None);
    if let Some(me) = fetch_me_with_token(&backend, &creds.access_token, &creds.machine_id, proxy_url).await {
        if me.email.as_deref().is_some_and(|s| !s.is_empty()) {
            creds.email = me.email;
        }
        if me.first_name.as_deref().is_some_and(|s| !s.is_empty()) {
            creds.first_name = me.first_name;
        }
        if me.team_name.as_deref().is_some_and(|s| !s.is_empty()) {
            creds.team_name = me.team_name;
        }
        if creds.subject.is_none() && me.public_user_id.as_deref().is_some_and(|s| !s.is_empty()) {
            creds.subject = me.public_user_id;
        }
    }
    Ok(GrokBotPollOutcome::Authorized(creds))
}

/// Ensure we have fresh valid Grok Bot credentials, serializing refresh behind a mutex.
pub async fn ensure_valid_grok_bot_creds_via(
    state_dir: &Path,
    force_refresh: bool,
    proxy_url: Option<&str>,
) -> Result<GrokBotCreds> {
    let now = now_unix();
    if !force_refresh {
        if let Some(c) = load_grok_bot_creds(state_dir) {
            if c.quarantined_reason.is_none() && !c.needs_refresh_at(now) {
                return Ok(c);
            }
        }
    }

    let _lock = grok_bot_refresh_mutex().lock().await;
    let current = load_grok_bot_creds(state_dir).ok_or_else(|| {
        BridgeError::Auth(
            "Grok Bot is not connected. Run /gbot (or /grok -> Grok Bot) to generate an OAuth login link."
                .to_string(),
        )
    })?;
    let now2 = now_unix();
    if !force_refresh && current.quarantined_reason.is_none() && !current.needs_refresh_at(now2) {
        return Ok(current);
    }
    if !force_refresh {
        if let Some(ref why) = current.quarantined_reason {
            return Err(BridgeError::Auth(format!(
                "Grok Bot OAuth session needs re-login ({why}). Tap 'New Login Link' in /gbot."
            )));
        }
    }
    if current.refresh_token.trim().is_empty() {
        if !force_refresh && !current.is_expired_at(now2) {
            return Ok(current);
        }
        let mut q = current;
        q.quarantined_reason =
            Some("session expired and no refresh_token was issued".to_string());
        q.updated_at = now2;
        let _ = save_grok_bot_creds(state_dir, &q);
        return Err(BridgeError::Auth(
            "Grok Bot OAuth session expired without a refresh token — tap 'New Login Link' in /gbot."
                .to_string(),
        ));
    }

    let backend = grok_bot_backend_url()?;
    refresh_grok_bot_creds_at_via(state_dir, &current, &backend, &grok_bot_client_id(), proxy_url)
        .await
}

pub async fn refresh_grok_bot_creds_at_via(
    state_dir: &Path,
    current: &GrokBotCreds,
    backend: &str,
    client_id: &str,
    proxy_url: Option<&str>,
) -> Result<GrokBotCreds> {
    let backend = validate_grok_bot_backend(backend)?;
    let client = build_http_client(25, proxy_url)?;
    let mut attempt: u32 = 0;
    let (status, body) = loop {
        attempt += 1;
        let resp = client
            .post(format!("{backend}/oauth/token"))
            .json(&json!({
                "client_id": client_id,
                "grant_type": "refresh_token",
                "refresh_token": current.refresh_token,
            }))
            .send()
            .await
            .map_err(|e| BridgeError::Network(format!("Grok Bot token refresh failed: {e}")))?;

        let status = resp.status();
        let retry_after_hdr = resp
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.trim().parse::<u64>().ok())
            .map(|s| s.clamp(1, 30));
        let body = resp.text().await.unwrap_or_default();

        if matches!(status.as_u16(), 429 | 502 | 503 | 504) && attempt < 2 {
            let wait_s = retry_after_hdr.unwrap_or(2);
            warn!(
                status = status.as_u16(),
                wait_s,
                "Grok Bot OAuth refresh hit transient error; backing off"
            );
            tokio::time::sleep(Duration::from_secs(wait_s)).await;
            continue;
        }
        break (status, body);
    };

    #[derive(Deserialize)]
    struct RefreshResp {
        access_token: Option<String>,
        refresh_token: Option<String>,
        #[serde(rename = "shouldLogout", default)]
        should_logout: bool,
        error: Option<String>,
        error_description: Option<String>,
    }

    let parsed: RefreshResp = serde_json::from_str(&body).unwrap_or(RefreshResp {
        access_token: None,
        refresh_token: None,
        should_logout: false,
        error: None,
        error_description: None,
    });

    if status.is_success() && !parsed.should_logout {
        if let Some(new_at) = parsed.access_token.filter(|s| !s.trim().is_empty()) {
            let new_rt = parsed
                .refresh_token
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(|| current.refresh_token.clone());
            let refreshed = build_creds_from_tokens(new_at, new_rt, None, Some(current));
            save_grok_bot_creds(state_dir, &refreshed)?;
            info!(
                email = ?refreshed.masked_email(),
                "Grok Bot OAuth token refreshed atomically"
            );
            return Ok(refreshed);
        }
    }

    let err_detail = parsed
        .error_description
        .or(parsed.error)
        .unwrap_or_else(|| redact_secrets_in_text(&body).chars().take(180).collect());
    let terminal = parsed.should_logout || matches!(status.as_u16(), 400 | 401 | 403);
    let reason = if parsed.should_logout {
        "server requested re-login (shouldLogout)".to_string()
    } else {
        format!(
            "Grok Bot OAuth refresh rejected (HTTP {}): {}",
            status.as_u16(),
            redact_secrets_in_text(&err_detail)
        )
    };
    if terminal {
        let mut q = current.clone();
        q.quarantined_reason = Some(reason.clone());
        q.updated_at = now_unix();
        let _ = save_grok_bot_creds(state_dir, &q);
        warn!(reason = %reason, "Grok Bot OAuth token quarantined; user must generate new login link");
        return Err(BridgeError::Auth(format!(
            "{reason}. Tap 'New Login Link' in /gbot to re-authenticate."
        )));
    }
    Err(BridgeError::Network(reason))
}

#[derive(Debug, Deserialize)]
struct ConnectErrBody {
    #[serde(default)]
    code: String,
    #[serde(default)]
    message: String,
}

fn format_connect_error(method: &str, status: u16, raw_body: &str) -> BridgeError {
    let parsed: ConnectErrBody = serde_json::from_str(raw_body).unwrap_or(ConnectErrBody {
        code: String::new(),
        message: String::new(),
    });
    let safe_msg = redact_secrets_in_text(if parsed.message.is_empty() {
        raw_body
    } else {
        &parsed.message
    });
    let excerpt: String = safe_msg.chars().take(300).collect();
    if status == 401 || parsed.code == "unauthenticated" {
        return BridgeError::Auth(format!(
            "Grok Bot session unauthorized ({method}, HTTP {status}): {excerpt}. Generate a new login link in /gbot."
        ));
    }
    if status == 403 || parsed.code == "permission_denied" {
        return BridgeError::PermissionDenied(format!(
            "Grok Bot access denied ({method}, HTTP {status}): {excerpt}. Confirm your account has an active Grok Bot / SuperGrok / X Premium+ plan."
        ));
    }
    if status == 429 || parsed.code == "resource_exhausted" {
        return BridgeError::Network(format!(
            "Grok Bot rate/quota limit reached ({method}, HTTP {status}): {excerpt}"
        ));
    }
    BridgeError::Network(format!(
        "Grok Bot RPC {method} failed (HTTP {status} {}): {excerpt}",
        if parsed.code.is_empty() {
            "unknown"
        } else {
            &parsed.code
        }
    ))
}

/// Call `POST {backend}/aiserver.v1.{method}` using ConnectRPC JSON codec.
///
/// `allow_retry` MUST be `true` ONLY for idempotent read-only RPCs; write RPCs like
/// `SendGrokBotUserMessage` pass `false` so messages are never duplicated.
pub async fn connect_call_via(
    state_dir: &Path,
    method: &str,
    payload: &Value,
    proxy_url: Option<&str>,
    allow_retry: bool,
) -> Result<Value> {
    let backend = grok_bot_backend_url()?;
    let client = build_http_client(45, proxy_url)?;
    let path = if method.starts_with("aiserver.") {
        method.to_string()
    } else {
        format!("aiserver.v1.{method}")
    };
    let url = format!("{backend}/{path}");

    let mut force_refresh = false;
    let mut transient_attempts = 0u32;
    let mut auth_retried = false;

    loop {
        let creds = ensure_valid_grok_bot_creds_via(state_dir, force_refresh, proxy_url).await?;
        force_refresh = false;
        let headers = build_sand_headers(&creds.access_token, &creds.machine_id)?;

        let resp = match client.post(&url).headers(headers).json(payload).send().await {
            Ok(r) => r,
            Err(e) => {
                if allow_retry && transient_attempts < 2 {
                    transient_attempts += 1;
                    tokio::time::sleep(Duration::from_millis(500 * u64::from(transient_attempts)))
                        .await;
                    continue;
                }
                return Err(BridgeError::Network(format!(
                    "Grok Bot RPC {method} transport error: {e}"
                )));
            }
        };

        let status = resp.status();
        let retry_after_hdr = resp
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.trim().parse::<u64>().ok())
            .map(|s| s.clamp(1, 15));
        let text = resp.text().await.unwrap_or_default();

        if status.is_success() {
            if text.trim().is_empty() {
                return Ok(json!({}));
            }
            return serde_json::from_str::<Value>(&text)
                .map_err(|e| BridgeError::json(format!("decoding {method} response"), e));
        }

        let code = status.as_u16();
        let is_unauth = code == 401
            || serde_json::from_str::<ConnectErrBody>(&text)
                .ok()
                .is_some_and(|e| e.code == "unauthenticated");

        if is_unauth && allow_retry && !auth_retried {
            auth_retried = true;
            force_refresh = true;
            continue;
        }

        if allow_retry && matches!(code, 429 | 502 | 503 | 504) && transient_attempts < 2 {
            transient_attempts += 1;
            let wait_s = retry_after_hdr.unwrap_or(u64::from(transient_attempts));
            tokio::time::sleep(Duration::from_secs(wait_s)).await;
            continue;
        }

        return Err(format_connect_error(method, code, &text));
    }
}

pub async fn fetch_grok_bot_me_via(
    state_dir: &Path,
    proxy_url: Option<&str>,
) -> Result<GrokBotMe> {
    let val = connect_call_via(state_dir, &format!("{DASHBOARD_SVC}/GetMe"), &json!({}), proxy_url, true).await?;
    serde_json::from_value(val).map_err(|e| BridgeError::json("decoding GetMe response", e))
}

pub async fn fetch_grok_bot_usage_via(
    state_dir: &Path,
    proxy_url: Option<&str>,
) -> Result<GrokBotUsage> {
    let val = connect_call_via(
        state_dir,
        &format!("{DASHBOARD_SVC}/GetSandUsageStatus"),
        &json!({}),
        proxy_url,
        true,
    )
    .await?;
    serde_json::from_value(val)
        .map_err(|e| BridgeError::json("decoding GetSandUsageStatus response", e))
}

pub async fn list_grok_bot_agents_via(
    state_dir: &Path,
    proxy_url: Option<&str>,
) -> Result<Vec<GrokBotAgent>> {
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct Resp {
        agents: Vec<GrokBotAgent>,
    }
    let val = connect_call_via(
        state_dir,
        &format!("{GROK_BOT_SVC}/ListGrokBotAgents"),
        &json!({ "includeTeamAgents": true }),
        proxy_url,
        true,
    )
    .await?;
    let mut parsed: Resp = serde_json::from_value(val)
        .map_err(|e| BridgeError::json("decoding ListGrokBotAgents response", e))?;
    parsed.agents.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    let _ = atomic_write_json(&grok_bot_agents_path(state_dir), &parsed.agents, true);
    Ok(parsed.agents)
}

pub async fn list_grok_bot_statuses_via(
    state_dir: &Path,
    agent_ids: &[String],
    proxy_url: Option<&str>,
) -> Result<Vec<GrokBotAgentStatus>> {
    if agent_ids.is_empty() {
        return Ok(Vec::new());
    }
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct Resp {
        statuses: Vec<GrokBotAgentStatus>,
    }
    let val = connect_call_via(
        state_dir,
        &format!("{GROK_BOT_SVC}/ListGrokBotAgentStatuses"),
        &json!({ "agentIds": agent_ids }),
        proxy_url,
        true,
    )
    .await?;
    let parsed: Resp = serde_json::from_value(val)
        .map_err(|e| BridgeError::json("decoding ListGrokBotAgentStatuses response", e))?;
    Ok(parsed.statuses)
}

pub async fn resolve_main_session_via(
    state_dir: &Path,
    agent_id: &str,
    proxy_url: Option<&str>,
) -> Result<String> {
    #[derive(Deserialize, Default)]
    #[serde(rename_all = "camelCase", default)]
    struct SessionItem {
        session_id: String,
        kind: Value,
    }
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct Resp {
        sessions: Vec<SessionItem>,
    }
    let val = connect_call_via(
        state_dir,
        &format!("{GROK_BOT_SVC}/ListGrokBotAgentSessions"),
        &json!({ "agentId": agent_id }),
        proxy_url,
        true,
    )
    .await?;
    let parsed: Resp = serde_json::from_value(val)
        .map_err(|e| BridgeError::json("decoding ListGrokBotAgentSessions response", e))?;
    if parsed.sessions.is_empty() {
        return Ok(String::new());
    }
    let main_sessions: Vec<&SessionItem> = parsed
        .sessions
        .iter()
        .filter(|s| {
            s.kind.as_i64() == Some(1)
                || s.kind.as_str() == Some("GROK_BOT_AGENT_SESSION_KIND_MAIN")
        })
        .collect();
    if main_sessions.len() == 1 {
        Ok(main_sessions[0].session_id.clone())
    } else if main_sessions.is_empty() {
        Ok(String::new())
    } else {
        Ok(main_sessions[0].session_id.clone())
    }
}

pub async fn list_transcript_entries_via(
    state_dir: &Path,
    agent_id: &str,
    session_id: &str,
    limit: u32,
    before_seq: Option<i64>,
    proxy_url: Option<&str>,
) -> Result<Vec<DecodedTranscriptEntry>> {
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct Resp {
        entries: Vec<RawTranscriptEntry>,
    }
    let mut body = json!({
        "agentId": agent_id,
        "limit": limit,
    });
    if !session_id.is_empty() {
        body["sessionId"] = json!(session_id);
    }
    if let Some(b) = before_seq {
        body["beforeSeq"] = json!(b.to_string());
    }
    let val = connect_call_via(
        state_dir,
        &format!("{GROK_BOT_SVC}/ListGrokBotTranscriptEntries"),
        &body,
        proxy_url,
        true,
    )
    .await?;
    let parsed: Resp = serde_json::from_value(val)
        .map_err(|e| BridgeError::json("decoding ListGrokBotTranscriptEntries response", e))?;
    Ok(parsed
        .entries
        .iter()
        .map(DecodedTranscriptEntry::decode)
        .collect())
}

async fn entries_since_via(
    state_dir: &Path,
    agent_id: &str,
    session_id: &str,
    after_seq: i64,
    proxy_url: Option<&str>,
) -> Result<Vec<DecodedTranscriptEntry>> {
    const PAGE: u32 = 50;
    let mut out = Vec::new();
    let mut before = None;
    for _ in 0..8 {
        let entries =
            list_transcript_entries_via(state_dir, agent_id, session_id, PAGE, before, proxy_url)
                .await?;
        let n = entries.len();
        let mut done = n < PAGE as usize;
        for e in entries {
            if e.seq <= after_seq {
                done = true;
                break;
            }
            before = Some(e.seq);
            out.push(e);
        }
        if done {
            break;
        }
    }
    out.reverse();
    Ok(out)
}

pub async fn interrupt_grok_bot_run_via(
    state_dir: &Path,
    agent_id: &str,
    session_id: &str,
    proxy_url: Option<&str>,
) -> Result<bool> {
    #[derive(Deserialize, Default)]
    #[serde(rename_all = "camelCase", default)]
    struct Resp {
        had_active_run: bool,
    }
    let mut body = json!({
        "agentId": agent_id,
        "reason": "user_interrupt",
    });
    if !session_id.is_empty() {
        body["sessionId"] = json!(session_id);
    }
    let val = connect_call_via(
        state_dir,
        &format!("{GROK_BOT_SVC}/InterruptGrokBotAgentRun"),
        &body,
        proxy_url,
        false,
    )
    .await?;
    let parsed: Resp = serde_json::from_value(val).unwrap_or_default();
    Ok(parsed.had_active_run)
}

async fn emit_progress(
    cb: Option<&ProgressCallback>,
    started: Instant,
    steps: usize,
    last_step: &str,
    partial: &str,
    conv_id: &str,
) {
    let Some(cb) = cb else { return };
    let prog = Progress {
        started,
        steps,
        last_step: last_step.to_string(),
        tools: Vec::new(),
        trace: Vec::new(),
        partial: partial.to_string(),
        conversation_id: Some(format!("grokbot-{conv_id}")),
    };
    cb(prog).await;
}

/// Send one prompt to a cloud Grok Bot agent and stream its progress until turn settlement.
#[allow(clippy::too_many_arguments)]
pub async fn run_grok_bot_turn_via(
    state_dir: &Path,
    agent_id: &str,
    agent_name: &str,
    user_prompt: &str,
    proxy_url: Option<String>,
    timeout_secs: u64,
    on_progress: Option<ProgressCallback>,
    mut cancel: watch::Receiver<bool>,
) -> Result<JobResult> {
    let started = Instant::now();
    let px = proxy_url.as_deref();
    if *cancel.borrow() {
        return Ok(JobResult {
            stopped: true,
            ..Default::default()
        });
    }

    emit_progress(
        on_progress.as_ref(),
        started,
        1,
        &format!("Connecting to Grok Bot {agent_name}…"),
        "",
        agent_id,
    )
    .await;

    let session_id = resolve_main_session_via(state_dir, agent_id, px).await?;
    let baseline = list_transcript_entries_via(state_dir, agent_id, &session_id, 1, None, px)
        .await?
        .first()
        .map_or(0, |e| e.seq);

    let message_id = uuid::Uuid::new_v4().to_string();
    let mut send_body = json!({
        "agentId": agent_id,
        "messageId": message_id,
        "text": user_prompt,
        "sentAtMs": now_ms().to_string(),
        "source": "GROK_BOT_CLIENT_SURFACE_DESKTOP",
        "initiator": "GROK_BOT_USER_MESSAGE_INITIATOR_USER",
        "sendSource": "GROK_BOT_SEND_SOURCE_CHAT",
    });
    if !session_id.is_empty() {
        send_body["sessionId"] = json!(session_id);
    }

    #[derive(Deserialize, Default)]
    #[serde(rename_all = "camelCase", default)]
    struct Refusal {
        failure_code: String,
        message: String,
    }
    #[derive(Deserialize, Default)]
    #[serde(rename_all = "camelCase", default)]
    struct SendResp {
        delivery: Value,
        refusal: Option<Refusal>,
    }

    let send_val = connect_call_via(
        state_dir,
        &format!("{GROK_BOT_SVC}/SendGrokBotUserMessage"),
        &send_body,
        px,
        false,
    )
    .await?;
    let send_resp: SendResp = serde_json::from_value(send_val)
        .map_err(|e| BridgeError::json("decoding SendGrokBotUserMessage response", e))?;
    let delivery_str = send_resp
        .delivery
        .as_str()
        .map(|s| enum_suffix(s, "GROK_BOT_USER_MESSAGE_DELIVERY"))
        .unwrap_or_default();
    if send_resp.refusal.is_some() || delivery_str == "refused" {
        let r = send_resp.refusal.unwrap_or_default();
        return Err(BridgeError::Network(format!(
            "Grok Bot refused message: {} {}",
            r.failure_code, r.message
        )));
    }

    emit_progress(
        on_progress.as_ref(),
        started,
        2,
        &format!("Waiting for Grok Bot {agent_name}…"),
        "",
        agent_id,
    )
    .await;

    let deadline = Instant::now() + Duration::from_secs(timeout_secs.max(30));
    let mut cursor = baseline;
    let mut accepted_at: Option<i64> = None;
    let mut echo_id: Option<String> = None;
    let mut turn_id: Option<String> = None;
    let mut replies: Vec<String> = Vec::new();
    let mut pending_input: Vec<String> = Vec::new();
    let mut seen: HashSet<i64> = HashSet::new();
    let mut settled_once = false;
    let mut steps = 2usize;

    loop {
        if *cancel.borrow() {
            let _ = interrupt_grok_bot_run_via(state_dir, agent_id, &session_id, px).await;
            return Ok(JobResult {
                text: replies.join("\n\n"),
                conversation_id: Some(format!("grokbot-{agent_id}")),
                stopped: true,
                steps,
                ..Default::default()
            });
        }

        if turn_id.is_none() && echo_id.is_none() {
            #[derive(Deserialize, Default)]
            #[serde(rename_all = "camelCase", default)]
            struct SendStatusResp {
                status: Value,
                echo_entry_id: Option<String>,
                rejection_code: Option<String>,
                #[serde(deserialize_with = "opt_i64_str")]
                accepted_at_ms: Option<i64>,
            }
            let mut st_req = json!({
                "agentId": agent_id,
                "messageId": message_id,
            });
            if !session_id.is_empty() {
                st_req["sessionId"] = json!(session_id);
            }
            if let Ok(st_val) = connect_call_via(
                state_dir,
                &format!("{GROK_BOT_SVC}/GetGrokBotSendStatus"),
                &st_req,
                px,
                true,
            )
            .await
            {
                if let Ok(st) = serde_json::from_value::<SendStatusResp>(st_val) {
                    let st_s = st
                        .status
                        .as_str()
                        .map(|s| enum_suffix(s, "GROK_BOT_SEND_STATUS"))
                        .unwrap_or_default();
                    if st_s == "accepted" || st.status.as_i64() == Some(2) {
                        echo_id = st.echo_entry_id;
                        accepted_at = st.accepted_at_ms;
                    } else if st_s == "rejected" {
                        return Err(BridgeError::Network(format!(
                            "Grok Bot message rejected: {}",
                            st.rejection_code.unwrap_or_else(|| "unknown".to_string())
                        )));
                    }
                }
            }
        }

        if let Ok(entries) = entries_since_via(state_dir, agent_id, &session_id, cursor, px).await {
            for e in entries {
                cursor = cursor.max(e.seq);
                if !seen.insert(e.seq) {
                    continue;
                }
                if let GrokBotEntryView::User { nonce, .. } = e.view() {
                    if nonce == Some(message_id.as_str())
                        || echo_id.as_deref() == Some(e.id.as_str())
                    {
                        turn_id = e.request_id.clone();
                        accepted_at = accepted_at.or(Some(e.timestamp_ms));
                        continue;
                    }
                }
                if turn_id.is_none() || e.request_id != turn_id {
                    continue;
                }
                match e.view() {
                    GrokBotEntryView::Reply { text } => {
                        if !text.trim().is_empty() {
                            replies.push(text.to_string());
                            steps += 1;
                            emit_progress(
                                on_progress.as_ref(),
                                started,
                                steps,
                                &format!("Grok Bot {agent_name} replied"),
                                &replies.join("\n\n"),
                                agent_id,
                            )
                            .await;
                        }
                    }
                    GrokBotEntryView::NeedsInput {
                        what,
                        answered: false,
                    } => {
                        if !pending_input.contains(&what) {
                            pending_input.push(what);
                        }
                    }
                    _ => {}
                }
            }
        }

        if let Some(ref turn) = turn_id {
            if let Ok(statuses) =
                list_grok_bot_statuses_via(state_dir, &[agent_id.to_string()], px).await
            {
                let st = statuses.into_iter().next().unwrap_or_default();
                let live = st.live.clone().unwrap_or_default();
                let running = live.is_running || st.is_running;
                if let Some(ref act) = live.activity {
                    if !act.tool.is_empty() || !act.detail.is_empty() {
                        let step_msg = format!("{} {}", act.tool, act.detail).trim().to_string();
                        emit_progress(
                            on_progress.as_ref(),
                            started,
                            steps,
                            &step_msg,
                            &replies.join("\n\n"),
                            agent_id,
                        )
                        .await;
                    }
                }
                let settlement = live.last_turn_settlement.clone();
                let ours = settlement.as_ref().is_some_and(|s| {
                    s.turn_id == *turn
                        || accepted_at.is_some_and(|a| s.settled_at_ms >= a)
                });
                if let Some(ref aw) = live.awaiting {
                    if !running {
                        let what = format!("awaiting you ({})", aw.reason);
                        if !pending_input.contains(&what) {
                            pending_input.push(what);
                        }
                    }
                }
                if (ours && !running) || !pending_input.is_empty() {
                    if !settled_once {
                        settled_once = true;
                        continue;
                    }
                    let mut final_text = replies.join("\n\n");
                    if !pending_input.is_empty() {
                        if !final_text.is_empty() {
                            final_text.push_str("\n\n");
                        }
                        final_text.push_str(&format!(
                            "⚠️ Grok Bot is waiting for input/approval in the app: {}",
                            pending_input.join("; ")
                        ));
                    }
                    let outcome = settlement.map(|s| s.outcome).unwrap_or_default();
                    if !outcome.is_empty() && outcome != "success" && final_text.is_empty() {
                        return Err(BridgeError::Network(format!(
                            "Grok Bot turn ended with outcome '{outcome}'"
                        )));
                    }
                    if final_text.trim().is_empty() {
                        final_text = format!(
                            "(Grok Bot {agent_name} finished with no text reply; outcome: {})",
                            if outcome.is_empty() { "ok" } else { &outcome }
                        );
                    }
                    return Ok(JobResult {
                        text: final_text,
                        conversation_id: Some(format!("grokbot-{agent_id}")),
                        finished_reason: Some(if outcome.is_empty() {
                            "stop".to_string()
                        } else {
                            outcome
                        }),
                        steps,
                        ..Default::default()
                    });
                }
            }
        }

        if Instant::now() >= deadline {
            let mut partial = replies.join("\n\n");
            if !partial.is_empty() {
                partial.push_str("\n\n");
            }
            partial.push_str(&format!(
                "⏱ Timed out waiting for Grok Bot {agent_name}; check `/gbot log` or `/gbot status`."
            ));
            return Ok(JobResult {
                text: partial,
                conversation_id: Some(format!("grokbot-{agent_id}")),
                timed_out: true,
                steps,
                ..Default::default()
            });
        }

        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(1500)) => {}
            res = cancel.changed() => {
                if res.is_err() || *cancel.borrow() {
                    let _ = interrupt_grok_bot_run_via(state_dir, agent_id, &session_id, px).await;
                    return Ok(JobResult {
                        text: replies.join("\n\n"),
                        conversation_id: Some(format!("grokbot-{agent_id}")),
                        stopped: true,
                        steps,
                        ..Default::default()
                    });
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    #[test]
    fn checksum_matches_app_algorithm() {
        assert_eq!(checksum_at(1_792_637_601_155, "abc"), "paaotvCSabc");
    }

    #[test]
    fn backend_host_pinning() {
        assert!(validate_grok_bot_backend("https://api2.cursor.sh").is_ok());
        assert!(validate_grok_bot_backend("https://cursor.com/").is_ok());
        assert!(validate_grok_bot_backend("http://api2.cursor.sh").is_err());
        assert!(validate_grok_bot_backend("https://evil-cursor.sh").is_err());
        assert!(validate_grok_bot_backend("https://api2.cursor.sh.evil.com").is_err());
    }

    #[test]
    fn pkce_login_generates_valid_s256_challenge_and_regenerates_distinct_codes() {
        let a = start_pkce_login().unwrap();
        let b = start_pkce_login().unwrap();
        assert_eq!(a.verifier.len(), 43);
        let expected_challenge = encode_base64url_nopad(&Sha256::digest(a.verifier.as_bytes()));
        assert_eq!(a.challenge, expected_challenge);
        assert!(a.login_url.starts_with("https://cursor.com/loginDeepControl?"));
        assert!(a.login_url.contains("redirectTarget=cli"));
        assert_ne!(a.uuid, b.uuid);
        assert_ne!(a.verifier, b.verifier);
        assert_eq!(a.short_code.len(), 8);
    }

    #[test]
    fn creds_redaction_skew_and_0600_storage() {
        let creds = GrokBotCreds {
            access_token: "secret-gb-access".into(),
            refresh_token: "secret-gb-refresh".into(),
            auth_id: Some("auth_1".into()),
            expires_at: 2000,
            token_lifetime_secs: 900,
            email: Some("botowner@example.com".into()),
            first_name: Some("Bot".into()),
            team_name: None,
            subject: Some("user_42".into()),
            machine_id: new_machine_id(),
            quarantined_reason: None,
            updated_at: 1000,
        };
        assert_eq!(creds.proactive_skew_secs(), 120);
        assert!(!creds.needs_refresh_at(1800));
        assert!(creds.needs_refresh_at(1890));
        let dbg = format!("{creds:?}");
        assert!(!dbg.contains("secret-gb-access"));
        assert!(!dbg.contains("secret-gb-refresh"));
        assert!(!dbg.contains("botowner@example.com"));

        let dir = TempDir::new().unwrap();
        save_grok_bot_creds(dir.path(), &creds).unwrap();
        let mode = std::fs::metadata(grok_bot_oauth_path(dir.path()))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        let loaded = load_grok_bot_creds(dir.path()).unwrap();
        assert_eq!(loaded.email.as_deref(), Some("botowner@example.com"));
        assert!(delete_grok_bot_creds(dir.path()));
        assert!(load_grok_bot_creds(dir.path()).is_none());
    }

    #[test]
    fn transcript_decoding_handles_replies_widgets_and_malformed_bodies() {
        let mk = |kind: &str, v: Value| {
            let b64 = encode_base64url_nopad(v.to_string().as_bytes());
            DecodedTranscriptEntry::decode(&RawTranscriptEntry {
                seq: 11,
                entry_kind: kind.into(),
                entry_id: Some("e1".into()),
                body: Some(b64),
                body_omitted: false,
            })
        };
        let reply = mk(
            "send-message",
            json!({"requestId": "turn-1", "message": {"type": "text", "content": "hello world"}}),
        );
        assert_eq!(reply.request_id.as_deref(), Some("turn-1"));
        assert!(matches!(reply.view(), GrokBotEntryView::Reply { text: "hello world" }));

        let widget = mk(
            "send-message",
            json!({"message": {"type": "widget", "widget": {"prompt": "Approve?", "options": [{"label": "Yes"}, {"label": "No"}]}}}),
        );
        match widget.view() {
            GrokBotEntryView::NeedsInput { what, answered } => {
                assert_eq!(what, "Approve? [Yes / No]");
                assert!(!answered);
            }
            _ => panic!("expected NeedsInput"),
        }

        let bad = DecodedTranscriptEntry::decode(&RawTranscriptEntry {
            seq: 1,
            entry_kind: "message".into(),
            entry_id: None,
            body: Some("!!!not-base64!!!".into()),
            body_omitted: false,
        });
        assert!(bad.body.is_null());
        assert!(matches!(bad.view(), GrokBotEntryView::AgentMessage { text: "", .. }));
    }
}
