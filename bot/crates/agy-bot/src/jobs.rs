//! Per-user serialized job queue, security boundary enforcement, live draft streaming,
//! process supervision cancellation, and final result + outbox delivery.

use std::collections::hash_map::DefaultHasher;
use std::collections::HashSet;
use std::future::Future;
use std::hash::{Hash, Hasher};
use std::path::{Component, Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use agy_core::accounts::{
    classify_failure, format_tokens_compact, Account, AccountStore, FailureAction, FailureClass,
    HealthStatus,
};
use agy_core::acl::AclStore;
use agy_core::config::{Config, EngineKind as CoreEngineKind};
use agy_core::proxies::{ProxyRegistry, ResolvedProxy};
use agy_core::store::{StateStore, UserState};
use agy_core::tg::{InlineKeyboardButton, InlineKeyboardMarkup, InputRichMessage};
use agy_core::{BridgeError, Result};
use agy_ext::engines::{
    build_runner, EngineKind as ExtEngineKind, EngineRequest, EngineRunner, JobResult,
    JobStopHandle, Progress, ProgressCallback,
};
use agy_net::{
    tg_retry, BotApiClient, EditMessageTextParams, SendMessageDraftParams,
    SendRichMessageDraftParams, SendRichMessageParams, MAX_UPLOAD_BYTES,
};
use agy_render::{
    esc, is_rtl_dominant, md_to_html, normalize_rich_markdown, sanitize_rich_buttons, split_html,
    strip_custom_emoji, strip_md_custom_emoji, utf16_len, PremiumState, DEFAULT_HTML_SPLIT_LIMIT,
};
use dashmap::mapref::entry::Entry;
use dashmap::DashMap;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::sync::{mpsc, watch};
use tracing::{info, warn};

use crate::handoff::{self, Continuity};

#[path = "parallel.rs"]
pub mod parallel;
#[path = "model_pick.rs"]
pub mod model_pick;
use model_pick::{ModelDecision, ModelWait};
use crate::render_bridge::RenderBridge;

/// Maximum pending jobs queued behind an active job for a single user.
pub const MAX_QUEUE_PER_USER: usize = 3;

/// Upper bound on engine attempts (account failovers + continuity downgrades) per job.
pub const MAX_ENGINE_ATTEMPTS: usize = 8;

/// TTL in seconds for [`AwaitingInput`] prompts (15 minutes).
pub const AWAITING_INPUT_TTL_SECS: f64 = 900.0;

static NEXT_REQ_COUNTER: AtomicI64 = AtomicI64::new(1);

fn now_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

fn generate_req_id() -> i64 {
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| (d.as_millis() % 1_000_000_000) as i64)
        .unwrap_or(1);
    let seq = NEXT_REQ_COUNTER.fetch_add(1, Ordering::Relaxed) % 1_000_000;
    let id = (ms + seq) % 2_000_000_000;
    if id <= 0 {
        1
    } else {
        id
    }
}

fn flat_tag_regex() -> Option<&'static Regex> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"</?(pre|code|blockquote)[^>]*>").ok())
        .as_ref()
}

/// Interactive multi-step user prompt expectation (e.g. awaiting MCP JSON or skill query) with 900s TTL.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AwaitingInput {
    pub kind: String,
    pub data: Value,
    pub ts: f64,
}

impl AwaitingInput {
    pub fn new(kind: impl Into<String>, data: Value) -> Self {
        Self::new_at(kind, data, now_secs())
    }

    pub fn new_at(kind: impl Into<String>, data: Value, ts: f64) -> Self {
        Self {
            kind: kind.into(),
            data,
            ts,
        }
    }

    /// Return `true` when the awaiting prompt has exceeded [`AWAITING_INPUT_TTL_SECS`] (900s).
    pub fn is_expired(&self, now: f64) -> bool {
        now < self.ts || (now - self.ts) > AWAITING_INPUT_TTL_SECS
    }
}

/// Optional per-request execution overrides (isolated session, mode, retry flags).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JobOverride {
    pub isolated: bool,
    pub owner_approved_mcp: bool,
    pub skip_permissions: Option<bool>,
    pub mode: Option<String>,
    pub conversation_id: Option<String>,
    /// One-off Parallel mode width (`/parallel N <task>`).
    pub parallel: Option<u8>,
    /// Pin execution to a specific engine (`"agy"`, `"uncensored"`, `"grok"`).
    pub force_engine: Option<String>,
    /// Override autonomous agent tool-calling mode (`Some(true)` = agent, `Some(false)` = chat).
    pub force_agent_mode: Option<bool>,
}

/// Incoming execution request submitted to [`JobManager::enqueue`].
#[derive(Debug, Clone)]
pub struct JobRequest {
    pub req_id: i64,
    pub uid: i64,
    pub chat_id: i64,
    pub user_label: String,
    pub text: String,
    pub attachments: Vec<PathBuf>,
    pub overrides: JobOverride,
}

impl JobRequest {
    pub fn new(
        uid: i64,
        chat_id: i64,
        user_label: impl Into<String>,
        text: impl Into<String>,
        attachments: Vec<PathBuf>,
    ) -> Self {
        Self {
            req_id: generate_req_id(),
            uid,
            chat_id,
            user_label: user_label.into(),
            text: text.into(),
            attachments,
            overrides: JobOverride::default(),
        }
    }
}

/// Outcome of [`JobManager::enqueue`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnqueueOutcome {
    StartedImmediately,
    Queued(usize),
    QueueFull,
}

/// Public snapshot of an actively running user job.
#[derive(Debug, Clone)]
pub struct ActiveJobInfo {
    pub req_id: i64,
    pub uid: i64,
    pub chat_id: i64,
    pub prompt: String,
    pub started: Instant,
    pub progress: Progress,
}

struct ActiveJobEntry {
    req_id: i64,
    uid: i64,
    chat_id: i64,
    prompt: String,
    started: Instant,
    progress: Mutex<Progress>,
    stop_handle: Mutex<Option<JobStopHandle>>,
    stop_requested: AtomicBool,
    cancel_tx: watch::Sender<bool>,
}

struct AbortOnDrop(tokio::task::JoinHandle<()>);
impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl ActiveJobEntry {
    fn snapshot(&self) -> ActiveJobInfo {
        let progress = self
            .progress
            .lock()
            .map(|g| g.clone())
            .unwrap_or_default();
        ActiveJobInfo {
            req_id: self.req_id,
            uid: self.uid,
            chat_id: self.chat_id,
            prompt: self.prompt.clone(),
            started: self.started,
            progress,
        }
    }
}

#[derive(Default)]
struct UserQueueState {
    running: bool,
    queued: usize,
}

fn lock_queue_state(
    m: &std::sync::Mutex<UserQueueState>,
) -> std::sync::MutexGuard<'_, UserQueueState> {
    match m.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    }
}

struct UserQueueHandle {
    tx: mpsc::Sender<JobRequest>,
    state: Arc<std::sync::Mutex<UserQueueState>>,
}

/// Convert [`agy_core::EngineKind`] to [`agy_ext::engines::EngineKind`].
pub fn to_ext_engine_kind(kind: &CoreEngineKind) -> Result<ExtEngineKind> {
    match kind {
        CoreEngineKind::Agy => Ok(ExtEngineKind::Agy),
        CoreEngineKind::Custom(spec) => ExtEngineKind::from_spec(spec),
    }
}

/// Effective streaming mode (`"semi"`, `"live"`, or `"off"`).
pub fn effective_stream_mode(u: &UserState) -> &'static str {
    let m = u.stream_mode.as_str();
    if !u.stream && m == "live" {
        return "off";
    }
    match m {
        "live" => "live",
        "off" => "off",
        _ => "semi",
    }
}

/// Lexical path normalization without requiring target existence (resolves `.` and `..`).
fn normalize_lexical(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::Prefix(p) => out.push(p.as_os_str()),
            Component::RootDir => out.push(comp.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() {
                    // Do not allow escaping above root
                }
            }
            Component::Normal(seg) => out.push(seg),
        }
    }
    out
}

/// Resolve safe working directory enforcing workspace containment when `!allow_root`.
pub fn resolve_safe_cwd(requested: Option<&str>, workspace: &Path, allow_root: bool) -> PathBuf {
    let ws_fallback = if workspace.exists() {
        std::fs::canonicalize(workspace).unwrap_or_else(|_| normalize_lexical(workspace))
    } else {
        normalize_lexical(workspace)
    };

    let Some(raw) = requested.map(str::trim).filter(|s| !s.is_empty()) else {
        return ws_fallback;
    };
    let req_path = Path::new(raw);
    if !req_path.is_dir() {
        return ws_fallback;
    }
    if allow_root {
        return req_path.to_path_buf();
    }

    let Ok(canon_req) = std::fs::canonicalize(req_path) else {
        return ws_fallback;
    };
    if canon_req.starts_with(&ws_fallback) {
        canon_req
    } else {
        warn!(
            requested = %canon_req.display(),
            workspace = %ws_fallback.display(),
            "cwd outside workspace rejected for non-root user; clamping to workspace"
        );
        ws_fallback
    }
}

/// Construct the full bridge prompt delivered on initial turns, isolated runs, or failovers.
pub fn build_bridge_prompt(
    req: &JobRequest,
    outdir: &Path,
    workspace: &Path,
    allow_root: bool,
) -> String {
    build_bridge_prompt_ex(req, outdir, workspace, allow_root, false)
}

/// Construct the bridge prompt with optional Phase 4 compact 1-line header for resumed turns
/// (`compact_resume = true`), eliminating repeated boilerplate while keeping security boundaries
/// and attachment paths intact.
pub fn build_bridge_prompt_ex(
    req: &JobRequest,
    outdir: &Path,
    workspace: &Path,
    allow_root: bool,
    compact_resume: bool,
) -> String {
    let mut parts = if compact_resume {
        vec![format!(
            "[telegram-bridge] {} · outbox: {}/",
            req.user_label,
            outdir.display()
        )]
    } else {
        vec![
            format!(
                "[telegram-bridge] Request from {} via Telegram (@your_agy_bot).",
                req.user_label
            ),
            "Follow ~/.gemini/config/rules/telegram-output.md (details: /root/agy-workspace/telegram-docs/)."
                .to_string(),
            format!(
                "Put any file you want delivered to the user in: {}/",
                outdir.display()
            ),
            format!(
                "Session handoff: this chat may move between Antigravity accounts; at milestones keep {} current and store an ai-memory note `handoff tg-{}` (rule: ~/.gemini/config/rules/session-handoff.md).",
                crate::handoff::handoff_note_path(workspace, req.uid).display(),
                req.uid
            ),
        ]
    };

    if !allow_root {
        parts.push(format!(
            "Security boundary: Restrict all file reads/writes and commands strictly to workspace {}; do not modify system services, root configs, ACL state, or MCP/skills configs unless explicitly authorized.",
            workspace.display()
        ));
    }

    if !req.attachments.is_empty() {
        parts.push("User attachments (local paths):".to_string());
        for p in &req.attachments {
            parts.push(format!("- {}", p.display()));
        }
    }

    parts.push("---".to_string());
    if req.text.trim().is_empty() {
        parts.push("Please look at the attached file(s) and tell me what they contain.".to_string());
    } else {
        parts.push(req.text.clone());
    }

    parts.join("\n")
}

/// Safely clamp streaming Markdown to `<= max_chars` UTF-16 units and `<= max_lines` lines,
/// balancing code fences and `<details>` tags.
pub fn safe_partial_md(md: &str, max_chars: usize, max_lines: usize) -> String {
    let trimmed = md.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let all_lines: Vec<&str> = trimmed.split('\n').collect();
    let mut cut = false;
    let slice = if all_lines.len() > max_lines {
        cut = true;
        &all_lines[all_lines.len() - max_lines..]
    } else {
        &all_lines[..]
    };

    let mut out = slice.join("\n");
    if utf16_len(&out) > max_chars {
        out = tail_utf16(&out, max_chars).to_string();
        if let Some(pos) = out.find('\n') {
            out = out[pos + 1..].to_string();
        }
        cut = true;
    }

    let mut fences = out
        .split('\n')
        .filter(|l| {
            let t = l.trim_start();
            t.starts_with("```") || t.starts_with("~~~")
        })
        .count();
    if cut && fences % 2 == 1 {
        out = format!("```\n{out}");
        fences += 1;
    }
    if fences % 2 == 1 {
        out.push_str("\n```");
    }

    let opened = out.matches("<details").count();
    let closed = out.matches("</details>").count();
    if opened > closed {
        for _ in 0..(opened - closed) {
            out.push_str("\n</details>");
        }
    }

    // Balance dangling display-math `$$` fences during live streaming
    let math_fences = out
        .split('\n')
        .filter(|l| l.trim() == "$$")
        .count();
    if math_fences % 2 == 1 {
        out.push_str("\n$$");
    }

    // Drop any incomplete `<tg-button` / `<tg-button-row` tail mid-stream so Rich draft doesn't 400
    if let Some(pos) = out.rfind("<tg-button") {
        let tail = &out[pos..];
        let is_closed = tail.contains("</tg-button-row>") || (!tail.contains("<tg-button-row") && tail.contains("</tg-button>"));
        if !is_closed {
            out.truncate(pos);
            out = out.trim_end().to_string();
        }
    }

    if cut {
        format!("…\n\n{out}")
    } else {
        out
    }
}

fn tail_utf16(s: &str, max_units: usize) -> &str {
    if utf16_len(s) <= max_units {
        return s;
    }
    let mut used = 0usize;
    let mut start_idx = s.len();
    for (idx, ch) in s.char_indices().rev() {
        let w = ch.len_utf16();
        if used + w > max_units {
            break;
        }
        used += w;
        start_idx = idx;
    }
    &s[start_idx..]
}

fn status_html(p: &Progress, premium: &PremiumState) -> String {
    let el = p.started.elapsed().as_secs();
    let tools = if p.tools.is_empty() {
        "<i>thinking…</i>".to_string()
    } else {
        let start = p.tools.len().saturating_sub(4);
        p.tools[start..]
            .iter()
            .map(|t| format!("<code>{}</code>", esc(t)))
            .collect::<Vec<_>>()
            .join(" → ")
    };
    format!(
        "{} <b>Working</b> · {}:{:02}\n<blockquote>{}\n<i>steps: {}</i></blockquote>",
        premium.e("work"),
        el / 60,
        el % 60,
        tools,
        p.steps
    )
}

fn status_md_head(p: &Progress, premium: &PremiumState) -> String {
    let el = p.started.elapsed().as_secs();
    let tools = if p.tools.is_empty() {
        "_thinking…_".to_string()
    } else {
        let start = p.tools.len().saturating_sub(4);
        p.tools[start..]
            .iter()
            .map(|t| format!("`{}`", t.replace('`', "")))
            .collect::<Vec<_>>()
            .join(" → ")
    };
    format!(
        "{} **Working** · {}:{:02} · steps {}\n\n> {}",
        premium.md("work"),
        el / 60,
        el % 60,
        p.steps,
        tools
    )
}

fn status_md(p: &Progress, premium: &PremiumState) -> String {
    let head = status_md_head(p, premium);
    if p.partial.trim().is_empty() {
        head
    } else {
        format!("{head}\n\n---\n\n{}", safe_partial_md(&p.partial, 24_000, 380))
    }
}

fn semi_html(p: &Progress, premium: &PremiumState) -> String {
    let head = status_html(p, premium);
    if p.partial.trim().is_empty() {
        return head;
    }
    let tail_part = safe_partial_md(&p.partial, 2500, 60);
    let html_body = md_to_html(&tail_part, 6);
    let flat_body = match flat_tag_regex() {
        Some(re) => re.replace_all(&html_body, "").into_owned(),
        None => html_body,
    };
    let mut text = format!("{head}\n<b>Draft</b>\n<blockquote expandable>{flat_body}</blockquote>");
    if !premium.active() {
        text = strip_custom_emoji(&text);
    }
    if utf16_len(&text) <= 4000 {
        text
    } else {
        head
    }
}

fn hash_str(s: &str) -> u64 {
    let mut h = DefaultHasher::new();
    s.hash(&mut h);
    h.finish()
}

pub fn error_html_for(err: &Value, premium: &PremiumState, engine_label: &str) -> String {
    let obj = err.as_object();
    let code = obj
        .and_then(|m| {
            m.get("code")
                .or_else(|| m.get("http_status"))
                .or_else(|| m.get("status_code"))
        })
        .map(val_to_str)
        .unwrap_or_default();
    let status = obj
        .and_then(|m| m.get("status").or_else(|| m.get("canonical_status")))
        .map(val_to_str)
        .unwrap_or_default();
    let msg_full = obj
        .and_then(|m| m.get("message").or_else(|| m.get("error")))
        .map(val_to_str)
        .unwrap_or_else(|| val_to_str(err));
    let msg: String = msg_full.chars().take(1500).collect();

    let mut hint = String::new();
    let low = msg.to_ascii_lowercase();
    if engine_label == "Antigravity" {
        if msg.contains("Terms of Service")
            || msg.contains("disabled in this account")
            || code == "403"
        {
            hint = "\n<i>The Antigravity account signed in on the server is blocked or ineligible. Sign in on the server with a working account (or appeal), then retry.</i>".to_string();
        } else if low.contains("quota") || low.contains("rate") {
            hint = "\n<i>Quota or rate limit — try later or pick another model.</i>".to_string();
        }
    } else if engine_label == "Grok OAuth" {
        if low.contains("not connected") || low.contains("401") || low.contains("invalid_grant") {
            hint = "\n<i>Open /grok and reconnect your x.ai OAuth subscription (no API key needed).</i>".to_string();
        } else if low.contains("403") {
            hint = "\n<i>Check your SuperGrok / X Premium+ subscription or toggle the endpoint in /grok.</i>".to_string();
        } else if low.contains("quota") || low.contains("rate") || code == "429" {
            hint = "\n<i>Grok rate limit reached — wait a moment or try another model in /grok.</i>".to_string();
        }
    } else if low.contains("quota") || low.contains("rate") || code == "429" {
        hint = "\n<i>Rate limit reached — try again shortly or switch models.</i>".to_string();
    }

    let head_parts: Vec<&str> = [code.as_str(), status.as_str()]
        .into_iter()
        .filter(|s| !s.is_empty())
        .collect();
    let head = if head_parts.is_empty() {
        String::new()
    } else {
        format!(" · <code>{}</code>", esc(&head_parts.join(" · ")))
    };

    format!(
        "{} <b>{} error</b>{}\n<blockquote expandable>{}</blockquote>{}",
        premium.e("err"),
        esc(engine_label),
        head,
        esc(&msg),
        hint
    )
}

fn val_to_str(v: &Value) -> String {
    match v {
        Value::Null => String::new(),
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

fn trace_html(p: &Progress, res: &JobResult) -> String {
    let lines: Vec<String> = if p.trace.is_empty() {
        vec!["(no tool calls)".to_string()]
    } else {
        let start = p.trace.len().saturating_sub(40);
        p.trace[start..]
            .iter()
            .map(|(t, name)| {
                let secs = (*t).max(0.0) as u64;
                format!("{}:{:02}  {}", secs / 60, secs % 60, name)
            })
            .collect()
    };
    let el = p.started.elapsed().as_secs();
    let mut usage_str = String::new();
    if let Some(obj) = res.usage.as_ref().and_then(Value::as_object) {
        let mut parts = Vec::new();
        for k in ["input_tokens", "output_tokens", "cache_read_tokens"] {
            if let Some(v) = obj.get(k) {
                let short_k = k.split('_').next().unwrap_or(k);
                parts.push(format!("{short_k} {v}"));
            }
        }
        if !parts.is_empty() {
            usage_str = format!(" · {}", parts.join(" · "));
        }
    }
    format!(
        "🧭 <b>Trace</b> · {} steps · {}:{:02}{}\n<blockquote expandable>{}</blockquote>",
        res.steps,
        el / 60,
        el % 60,
        esc(&usage_str),
        esc(&lines.join("\n"))
    )
}

struct StreamUiState {
    chat_id: i64,
    draft_id: i64,
    mode: &'static str,
    stream_interval_secs: f64,
    status_msg_id: Option<i64>,
    status_rich: bool,
    rich_edit_ok: AtomicBool,
    draft_ok: AtomicBool,
    editing: AtomicBool,
    last_digest: Mutex<Option<u64>>,
    last_draft_digest: Mutex<Option<u64>>,
    last_status_ts: Mutex<f64>,
    last_draft_ts: Mutex<f64>,
    last_typing_ts: Mutex<f64>,
}

impl StreamUiState {
    fn now_mono(anchor: Instant) -> f64 {
        anchor.elapsed().as_secs_f64()
    }

    async fn tick(&self, anchor: Instant, p: &Progress, client: &BotApiClient, premium: &PremiumState, stop_mk: &InlineKeyboardMarkup) {
        let now = Self::now_mono(anchor);
        let typing_every = if self.mode == "live" { 4.5 } else { 9.0 };
        let do_typing = {
            if let Ok(mut g) = self.last_typing_ts.lock() {
                if now - *g > typing_every {
                    *g = now;
                    true
                } else {
                    false
                }
            } else {
                false
            }
        };
        if do_typing {
            let _ = tokio::time::timeout(
                Duration::from_secs(5),
                client.send_chat_action(self.chat_id, "typing"),
            )
            .await;
        }

        match self.mode {
            "semi" => {
                let Some(mid) = self.status_msg_id else {
                    return;
                };
                let due = self
                    .last_status_ts
                    .lock()
                    .map(|mut g| {
                        if now - *g >= self.stream_interval_secs && !self.editing.load(Ordering::Relaxed) {
                            *g = now;
                            true
                        } else {
                            false
                        }
                    })
                    .unwrap_or(false);
                if due {
                    self.edit_status(anchor, mid, p, true, client, premium, stop_mk).await;
                }
            }
            "live" => {
                if let Some(mid) = self.status_msg_id {
                    let status_due = self
                        .last_status_ts
                        .lock()
                        .map(|mut g| {
                            if now - *g > 3.0 && !self.editing.load(Ordering::Relaxed) {
                                *g = now;
                                true
                            } else {
                                false
                            }
                        })
                        .unwrap_or(false);
                    if status_due {
                        self.edit_status(anchor, mid, p, false, client, premium, stop_mk).await;
                    }
                }
                if self.draft_ok.load(Ordering::Relaxed) && !p.partial.trim().is_empty() {
                    let draft_due = self
                        .last_draft_ts
                        .lock()
                        .map(|mut g| {
                            if now - *g > 1.2 {
                                *g = now;
                                true
                            } else {
                                false
                            }
                        })
                        .unwrap_or(false);
                    if draft_due {
                        self.send_draft(anchor, p, client).await;
                    }
                }
            }
            _ => {
                let Some(mid) = self.status_msg_id else {
                    return;
                };
                let due = self
                    .last_status_ts
                    .lock()
                    .map(|mut g| {
                        if now - *g >= 60.0 && !self.editing.load(Ordering::Relaxed) {
                            *g = now;
                            true
                        } else {
                            false
                        }
                    })
                    .unwrap_or(false);
                if due {
                    self.edit_status(anchor, mid, p, false, client, premium, stop_mk).await;
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn edit_status(
        &self,
        anchor: Instant,
        mid: i64,
        p: &Progress,
        with_partial: bool,
        client: &BotApiClient,
        premium: &PremiumState,
        stop_mk: &InlineKeyboardMarkup,
    ) {
        if self.editing.swap(true, Ordering::SeqCst) {
            return;
        }
        struct ResetFlag<'a>(&'a AtomicBool);
        impl Drop for ResetFlag<'_> {
            fn drop(&mut self) {
                self.0.store(false, Ordering::SeqCst);
            }
        }
        let _reset = ResetFlag(&self.editing);

        let md = if with_partial {
            status_md(p, premium)
        } else {
            status_md_head(p, premium)
        };
        let digest = hash_str(&md);
        if self
            .last_digest
            .lock()
            .ok()
            .is_some_and(|g| *g == Some(digest))
        {
            return;
        }

        if self.status_rich && self.rich_edit_ok.load(Ordering::Relaxed) {
            let plain_md = strip_md_custom_emoji(&md);
            let plain_mk = premium.strip_markup_icons(stop_mk.clone());
            let variants: Vec<(String, InlineKeyboardMarkup)> = if plain_md != md || stop_mk.has_custom_icons() {
                vec![(md.clone(), stop_mk.clone()), (plain_md, plain_mk)]
            } else {
                vec![(md.clone(), stop_mk.clone())]
            };
            let mut permanent_rich_fail = false;
            for (cur_md, cur_mk) in variants {
                let has_custom = cur_md.contains("tg://emoji") || cur_mk.has_custom_icons();
                let rtl = is_rtl_dominant(&cur_md);
                let params = EditMessageTextParams {
                    chat_id: Some(self.chat_id),
                    message_id: Some(mid),
                    rich_message: Some(InputRichMessage::markdown_with_rtl(cur_md, rtl)),
                    reply_markup: Some(cur_mk),
                    ..Default::default()
                };
                match tokio::time::timeout(Duration::from_secs(15), client.edit_message_text(&params)).await {
                    Ok(Ok(_)) => {
                        if let Ok(mut g) = self.last_digest.lock() {
                            *g = Some(digest);
                        }
                        return;
                    }
                    Ok(Err(err)) if err.is_not_modified() => {
                        if let Ok(mut g) = self.last_digest.lock() {
                            *g = Some(digest);
                        }
                        return;
                    }
                    Ok(Err(BridgeError::RateLimited { retry_after_secs, .. })) => {
                        if let Ok(mut g) = self.last_status_ts.lock() {
                            *g = Self::now_mono(anchor) + retry_after_secs as f64;
                        }
                        return;
                    }
                    Ok(Err(BridgeError::BotApi { code: 400, .. })) => {
                        if has_custom {
                            continue;
                        }
                        if !with_partial {
                            permanent_rich_fail = true;
                        }
                        break;
                    }
                    Ok(Err(_)) | Err(_) => return,
                }
            }
            if permanent_rich_fail {
                self.rich_edit_ok.store(false, Ordering::Relaxed);
            }
        }

        let html = if with_partial {
            semi_html(p, premium)
        } else {
            status_html(p, premium)
        };
        let stripped = strip_custom_emoji(&html);
        let plain_mk = premium.strip_markup_icons(stop_mk.clone());
        let params = EditMessageTextParams {
            chat_id: Some(self.chat_id),
            message_id: Some(mid),
            text: Some(stripped),
            parse_mode: Some("HTML".to_string()),
            reply_markup: Some(plain_mk),
            ..Default::default()
        };
        match tokio::time::timeout(Duration::from_secs(15), client.edit_message_text(&params)).await {
            Ok(Ok(_)) => {
                if let Ok(mut g) = self.last_digest.lock() {
                    *g = Some(digest);
                }
            }
            Ok(Err(err)) if err.is_not_modified() => {
                if let Ok(mut g) = self.last_digest.lock() {
                    *g = Some(digest);
                }
            }
            Ok(Err(BridgeError::RateLimited { retry_after_secs, .. })) => {
                if let Ok(mut g) = self.last_status_ts.lock() {
                    *g = Self::now_mono(anchor) + retry_after_secs as f64;
                }
            }
            _ => {}
        }
    }

    async fn send_draft(&self, anchor: Instant, p: &Progress, client: &BotApiClient) {
        let tail = safe_partial_md(&p.partial, 24_000, 380);
        if tail.is_empty() {
            return;
        }
        let digest = hash_str(&tail);
        if self
            .last_draft_digest
            .lock()
            .ok()
            .is_some_and(|g| *g == Some(digest))
        {
            return;
        }
        let norm_tail = sanitize_rich_buttons(&normalize_rich_markdown(&tail), |_| None);
        let rtl = is_rtl_dominant(&norm_tail);
        let rich_params = SendRichMessageDraftParams {
            chat_id: self.chat_id,
            draft_id: self.draft_id,
            rich_message: InputRichMessage::markdown_with_rtl(norm_tail, rtl),
            can_stop: Some(true),
            ..Default::default()
        };
        match tokio::time::timeout(
            Duration::from_secs(10),
            client.send_rich_message_draft(&rich_params),
        )
        .await
        {
            Ok(Ok(_)) => {
                if let Ok(mut g) = self.last_draft_digest.lock() {
                    *g = Some(digest);
                }
            }
            Ok(Err(BridgeError::RateLimited { retry_after_secs, .. })) => {
                if let Ok(mut g) = self.last_draft_ts.lock() {
                    *g = Self::now_mono(anchor) + retry_after_secs as f64;
                }
            }
            Ok(Err(BridgeError::BotApi { .. })) => {
                let html = md_to_html(&tail, 6);
                let chunk = split_html(&html, DEFAULT_HTML_SPLIT_LIMIT)
                    .into_iter()
                    .last()
                    .unwrap_or(html);
                let html_params = SendMessageDraftParams {
                    chat_id: self.chat_id,
                    draft_id: self.draft_id,
                    text: Some(chunk),
                    parse_mode: Some("HTML".to_string()),
                    can_stop: Some(true),
                    ..Default::default()
                };
                match tokio::time::timeout(
                    Duration::from_secs(10),
                    client.send_message_draft(&html_params),
                )
                .await
                {
                    Ok(Ok(_)) => {
                        if let Ok(mut g) = self.last_draft_digest.lock() {
                            *g = Some(digest);
                        }
                    }
                    Ok(Err(BridgeError::RateLimited { retry_after_secs, .. })) => {
                        if let Ok(mut g) = self.last_draft_ts.lock() {
                            *g = Self::now_mono(anchor) + retry_after_secs as f64;
                        }
                    }
                    Ok(Err(BridgeError::BotApi { .. })) => {
                        self.draft_ok.store(false, Ordering::Relaxed);
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }
}

/// Optional async bridge allowing [`JobManager`] to extract/deliver widgets without cyclic deps.
pub trait JobWidgetSink: Send + Sync {
    /// Extract inline `<tg-widget>` / `<tg-shared-widget>` blocks from markdown and deliver them,
    /// returning the cleaned markdown text.
    fn extract_markdown_widgets<'a>(
        &'a self,
        chat_id: i64,
        md: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<String>> + Send + 'a>>;

    /// Deliver `.widget.json` / `.widget.html` files from `outdir` and return their canonical paths.
    fn deliver_outbox_widgets<'a>(
        &'a self,
        chat_id: i64,
        outdir: &'a Path,
    ) -> Pin<Box<dyn Future<Output = HashSet<PathBuf>> + Send + 'a>>;
}

/// Extract `(message, code)` from an engine error value for classification.
pub fn error_parts(err: Option<&Value>) -> (String, Option<String>) {
    let Some(err) = err else {
        return (String::new(), None);
    };
    let obj = err.as_object();
    let code = obj
        .and_then(|m| {
            m.get("code")
                .or_else(|| m.get("http_status"))
                .or_else(|| m.get("status_code"))
        })
        .map(val_to_str)
        .filter(|s| !s.is_empty());
    let status = obj
        .and_then(|m| m.get("status").or_else(|| m.get("canonical_status")))
        .map(val_to_str)
        .unwrap_or_default();
    let msg = obj
        .and_then(|m| m.get("message").or_else(|| m.get("error")))
        .map(val_to_str)
        .unwrap_or_else(|| val_to_str(err));
    let full = if status.is_empty() { msg } else { format!("{status}: {msg}") };
    (full, code)
}

/// Compact human duration (`3h 12m`, `45s`).
pub fn human_secs(secs: u64) -> String {
    let (d, h, m, s) = (secs / 86400, (secs % 86400) / 3600, (secs % 3600) / 60, secs % 60);
    if d > 0 {
        format!("{d}d {h}h")
    } else if h > 0 {
        format!("{h}h {m}m")
    } else if m > 0 {
        format!("{m}m")
    } else {
        format!("{s}s")
    }
}

fn account_reason(
    cls: &agy_core::accounts::Classified,
    id: &str,
    p: &AccountStore,
) -> String {
    let mut r = cls.class.label().to_string();
    if let Some(a) = p.get(id) {
        if a.health.status == HealthStatus::Cooldown {
            if let Some(u) = a.health.until_ts {
                let secs = (u - now_secs() as i64).max(0) as u64;
                r.push_str(&format!(", retry in {}", human_secs(secs)));
            }
        } else if a.health.status == HealthStatus::Disabled {
            r.push_str(", disabled");
        }
    }
    r
}

/// Concurrent job supervisor managing per-user serialized queues, security boundaries,
/// live draft streaming, cancellation, and delivery.
/// Holds one in-flight slot on an account; released on drop (also when the task is aborted).
pub(crate) struct InFlightGuard(pub(crate) Arc<AccountStore>, pub(crate) String);
impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.0.end(&self.1);
    }
}

pub(crate) fn clear_proxy_env(env: &mut std::collections::BTreeMap<String, String>) {
    for k in [
        "HTTPS_PROXY",
        "HTTP_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "https_proxy",
        "http_proxy",
        "all_proxy",
        "no_proxy",
    ] {
        env.remove(k);
    }
}

pub(crate) fn inject_proxy_env(
    env: &mut std::collections::BTreeMap<String, String>,
    proxy_url: &str,
) {
    let px = proxy_url.trim();
    if px.is_empty() {
        return;
    }
    for k in [
        "HTTPS_PROXY",
        "HTTP_PROXY",
        "ALL_PROXY",
        "https_proxy",
        "http_proxy",
        "all_proxy",
    ] {
        env.insert(k.to_string(), px.to_string());
    }
    for k in ["NO_PROXY", "no_proxy"] {
        env.insert(k.to_string(), "127.0.0.1,localhost,::1".to_string());
    }
}

pub(crate) fn polite_jitter_ms(seed: u64, max_ms: u64) -> u64 {
    if max_ms == 0 {
        return 0;
    }
    let sub = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_millis() as u64)
        .unwrap_or(0);
    (sub.wrapping_mul(31) ^ seed.wrapping_mul(97)) % max_ms
}

fn default_runtime_global_jobs() -> usize {
    4
}
fn default_runtime_queue_per_user() -> usize {
    MAX_QUEUE_PER_USER
}

/// Runtime-tunable execution guard & safety limit knobs (hydrated from `Config` + `StateStore` meta).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeLimits {
    pub max_tool_steps: usize,
    pub tool_repeat_limit: usize,
    pub max_tools_per_min: usize,
    pub job_timeout_secs: u64,
    pub tg_user_rl_per_min: u32,
    pub outbox_secret_scan: bool,
    #[serde(default = "default_runtime_global_jobs")]
    pub max_global_ai_jobs: usize,
    #[serde(default = "default_runtime_queue_per_user")]
    pub max_queue_per_user: usize,
}

impl RuntimeLimits {
    pub fn from_config(cfg: &Config) -> Self {
        Self {
            max_tool_steps: cfg.agy_max_steps_per_turn,
            tool_repeat_limit: cfg.agy_tool_repeat_limit,
            max_tools_per_min: cfg.agy_max_tools_per_min,
            job_timeout_secs: cfg.agy_job_timeout,
            tg_user_rl_per_min: cfg.tg_user_rl_per_min,
            outbox_secret_scan: cfg.outbox_secret_scan,
            max_global_ai_jobs: cfg.max_global_ai_jobs.clamp(1, 32),
            max_queue_per_user: MAX_QUEUE_PER_USER,
        }
    }

    pub fn sanitized(mut self) -> Self {
        if self.max_tool_steps > 0 {
            self.max_tool_steps = self.max_tool_steps.clamp(5, 1000);
        }
        if self.tool_repeat_limit > 0 {
            self.tool_repeat_limit = self.tool_repeat_limit.clamp(2, 50);
        }
        if self.max_tools_per_min > 0 {
            self.max_tools_per_min = self.max_tools_per_min.clamp(5, 300);
        }
        self.job_timeout_secs = self.job_timeout_secs.clamp(60, 7200);
        if self.tg_user_rl_per_min > 0 {
            self.tg_user_rl_per_min = self.tg_user_rl_per_min.clamp(5, 300);
        }
        self.max_global_ai_jobs = self.max_global_ai_jobs.clamp(1, 32);
        self.max_queue_per_user = self.max_queue_per_user.clamp(1, 10);
        self
    }
}

struct GlobalSlotGuard {
    active: Arc<std::sync::atomic::AtomicUsize>,
    notify: Arc<tokio::sync::Notify>,
}

impl Drop for GlobalSlotGuard {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::AcqRel);
        self.notify.notify_waiters();
    }
}

pub struct JobManager {
    cfg: Arc<Config>,
    acl: Arc<AclStore>,
    store: Arc<StateStore>,
    render: Arc<RenderBridge>,
    client: Arc<BotApiClient>,
    runner: Arc<dyn EngineRunner>,
    active: DashMap<i64, Arc<ActiveJobEntry>>,
    last_prompts: DashMap<i64, (String, Vec<PathBuf>)>,
    awaiting: DashMap<i64, AwaitingInput>,
    queues: DashMap<i64, UserQueueHandle>,
    widget_sink: RwLock<Option<Arc<dyn JobWidgetSink>>>,
    accounts: RwLock<Option<Arc<AccountStore>>>,
    proxies: RwLock<Option<Arc<ProxyRegistry>>>,
    parallel_runs: DashMap<String, Arc<parallel::ParallelRun>>,
    model_waits: DashMap<i64, Arc<ModelWait>>,
    model_choice: DashMap<(i64, String, String), String>,
    model_pick_lock: tokio::sync::Mutex<()>,
    model_pick_timeout: std::sync::atomic::AtomicU64,
    active_global: Arc<std::sync::atomic::AtomicUsize>,
    global_slot_notify: Arc<tokio::sync::Notify>,
    runtime_limits: RwLock<RuntimeLimits>,
    #[allow(clippy::type_complexity)]
    mem_probe: RwLock<Option<Arc<dyn Fn() -> Option<u64> + Send + Sync>>>,
}

impl JobManager {
    /// Create a [`JobManager`] using the engine configured by `cfg.agy_engine`.
    pub fn new(
        cfg: Arc<Config>,
        acl: Arc<AclStore>,
        store: Arc<StateStore>,
        render: Arc<RenderBridge>,
        client: Arc<BotApiClient>,
    ) -> Result<Self> {
        let ext_kind = to_ext_engine_kind(&cfg.agy_engine)?;
        let runner = build_runner(
            ext_kind,
            Some(cfg.agy_bin.to_string_lossy().to_string()),
            Some(cfg.agy_workspace.clone()),
        );
        Ok(Self::with_runner(cfg, acl, store, render, client, runner))
    }

    /// Create a [`JobManager`] with an explicit [`EngineRunner`] implementation (useful in tests).
    pub fn with_runner(
        cfg: Arc<Config>,
        acl: Arc<AclStore>,
        store: Arc<StateStore>,
        render: Arc<RenderBridge>,
        client: Arc<BotApiClient>,
        runner: Arc<dyn EngineRunner>,
    ) -> Self {
        let mut initial_limits = store
            .meta("runtime_limits")
            .and_then(|v| serde_json::from_value::<RuntimeLimits>(v).ok())
            .unwrap_or_else(|| RuntimeLimits::from_config(&cfg))
            .sanitized();
        if store
            .meta("runtime_limits")
            .is_none_or(|v| v.get("max_global_ai_jobs").is_none())
        {
            initial_limits.max_global_ai_jobs = cfg.max_global_ai_jobs.clamp(1, 32);
        }
        Self {
            cfg,
            acl,
            store,
            render,
            client,
            runner,
            active: DashMap::new(),
            last_prompts: DashMap::new(),
            awaiting: DashMap::new(),
            queues: DashMap::new(),
            widget_sink: RwLock::new(None),
            accounts: RwLock::new(None),
            proxies: RwLock::new(None),
            parallel_runs: DashMap::new(),
            model_waits: DashMap::new(),
            model_choice: DashMap::new(),
            model_pick_lock: tokio::sync::Mutex::new(()),
            model_pick_timeout: std::sync::atomic::AtomicU64::new(model_pick::MODEL_PICK_TIMEOUT_SECS),
            active_global: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            global_slot_notify: Arc::new(tokio::sync::Notify::new()),
            runtime_limits: RwLock::new(initial_limits),
            mem_probe: RwLock::new(None),
        }
    }

    /// Snapshot current live runtime limits (`agy` guards, timeout, anti-flood, secret scan, global/queue caps).
    pub fn runtime_limits(&self) -> RuntimeLimits {
        self.runtime_limits
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Persist & apply updated runtime limits to `StateStore::meta("runtime_limits")`.
    pub fn set_runtime_limits(&self, limits: RuntimeLimits) -> RuntimeLimits {
        let clean = limits.sanitized();
        {
            let mut g = self.runtime_limits.write().unwrap_or_else(|e| e.into_inner());
            *g = clean.clone();
        }
        if let Ok(v) = serde_json::to_value(&clean) {
            let _ = self.store.set_meta("runtime_limits", v);
        }
        self.global_slot_notify.notify_waiters();
        clean
    }

    /// Reset runtime limits back to startup env/`Config` defaults.
    pub fn reset_runtime_limits(&self) -> RuntimeLimits {
        let def = RuntimeLimits::from_config(&self.cfg).sanitized();
        self.set_runtime_limits(def)
    }

    /// Number of currently occupied global AI execution slots (`<= max_global_jobs()`).
    pub fn active_global_jobs(&self) -> usize {
        self.active_global.load(Ordering::Acquire)
    }

    /// Configured server-wide cap on concurrent AI jobs (`RuntimeLimits::max_global_ai_jobs`).
    pub fn max_global_jobs(&self) -> usize {
        self.runtime_limits().max_global_ai_jobs.clamp(1, 32)
    }

    fn try_acquire_global_slot(&self) -> Option<GlobalSlotGuard> {
        let limit = self.max_global_jobs();
        let mut cur = self.active_global.load(Ordering::Acquire);
        loop {
            if cur >= limit {
                return None;
            }
            match self.active_global.compare_exchange_weak(
                cur,
                cur + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Some(GlobalSlotGuard {
                        active: Arc::clone(&self.active_global),
                        notify: Arc::clone(&self.global_slot_notify),
                    });
                }
                Err(actual) => cur = actual,
            }
        }
    }

    /// Attach the multi-account pool (enables per-account `HOME`, failover and continuity).
    pub fn set_accounts(&self, store: Arc<AccountStore>) {
        if let Ok(mut g) = self.accounts.write() {
            *g = Some(store);
        }
    }

    /// The attached account pool, if any.
    pub fn accounts(&self) -> Option<Arc<AccountStore>> {
        self.accounts.read().ok().and_then(|g| g.clone())
    }

    /// Attach the sticky egress proxy registry (per-account & Grok bindings).
    pub fn set_proxies(&self, reg: Arc<ProxyRegistry>) {
        if let Ok(mut g) = self.proxies.write() {
            *g = Some(reg);
        }
    }

    /// The attached sticky proxy registry, if any.
    pub fn proxies(&self) -> Option<Arc<ProxyRegistry>> {
        self.proxies.read().ok().and_then(|g| g.clone())
    }

    /// `true` when `a`'s bound proxy (if any) is allowed to transmit (i.e. not blocked by `FailClosed`).
    pub(crate) fn account_proxy_allowed(&self, a: &Account) -> bool {
        let Some(reg) = self.proxies() else {
            return true;
        };
        !matches!(
            reg.resolve(a.proxy_id.as_deref()),
            ResolvedProxy::Blocked { .. }
        )
    }

    /// Attach a [`JobWidgetSink`] for extracting inline markdown widgets and outbox widget files.
    pub fn set_widget_sink(&self, sink: Arc<dyn JobWidgetSink>) {
        if let Ok(mut g) = self.widget_sink.write() {
            *g = Some(sink);
        }
    }

    fn get_widget_sink(&self) -> Option<Arc<dyn JobWidgetSink>> {
        self.widget_sink.read().ok().and_then(|g| g.clone())
    }

    pub fn active_count(&self) -> usize {
        self.active.len()
    }

    pub fn is_busy(&self) -> bool {
        !self.active.is_empty()
    }

    pub fn is_user_busy(&self, uid: i64) -> bool {
        self.active.contains_key(&uid)
    }

    pub fn active_job_info(&self, uid: i64) -> Option<ActiveJobInfo> {
        self.active.get(&uid).map(|e| e.snapshot())
    }

    pub fn last_prompt(&self, uid: i64) -> Option<(String, Vec<PathBuf>)> {
        self.last_prompts.get(&uid).map(|r| r.value().clone())
    }

    pub fn set_awaiting(&self, uid: i64, input: AwaitingInput) {
        self.awaiting.insert(uid, input);
    }

    pub fn peek_awaiting(&self, uid: i64) -> Option<AwaitingInput> {
        self.awaiting.get(&uid).map(|v| v.value().clone())
    }

    pub fn clear_awaiting(&self, uid: i64) -> bool {
        self.awaiting.remove(&uid).is_some()
    }

    pub fn take_awaiting(&self, uid: i64) -> Option<AwaitingInput> {
        self.take_awaiting_at(uid, now_secs())
    }

    pub fn take_awaiting_at(&self, uid: i64, now: f64) -> Option<AwaitingInput> {
        let (_, item) = self.awaiting.remove(&uid)?;
        if item.is_expired(now) {
            None
        } else {
            Some(item)
        }
    }

    /// Stop the currently running job for `uid` (`SIGINT -> SIGTERM -> SIGKILL` on process group,
    /// plus instant watch cancellation for HTTP/API agents like Venice Uncensored & Grok OAuth).
    /// Returns `true` if an active job existed for `uid`.
    pub async fn stop_user(&self, uid: i64) -> bool {
        let Some(entry) = self.active.get(&uid).map(|r| Arc::clone(r.value())) else {
            return false;
        };
        entry.stop_requested.store(true, Ordering::SeqCst);
        let _ = entry.cancel_tx.send(true);
        let runs: Vec<String> = self.parallel_runs_of(uid).iter().map(|r| r.run_id.clone()).collect();
        for run_id in runs {
            self.stop_parallel(uid, &run_id, None).await;
        }
        let handle = entry
            .stop_handle
            .lock()
            .ok()
            .and_then(|g| g.clone());
        if let Some(h) = handle {
            h.stop().await;
        }
        true
    }

    /// Stop every active user job cleanly (called on graceful bridge shutdown).
    pub async fn stop_all(&self) {
        let uids: Vec<i64> = self.active.iter().map(|r| *r.key()).collect();
        for uid in uids {
            let _ = self.stop_user(uid).await;
        }
    }

    /// Cancel the running job for `uid` only if its draft ID matches `draft_id`.
    pub async fn stop_user_draft(&self, uid: i64, draft_id: i64) -> bool {
        let matched = self
            .active
            .get(&uid)
            .is_some_and(|e| e.req_id == draft_id);
        if !matched {
            return false;
        }
        self.stop_user(uid).await
    }

    /// Build retry keyboard for denied actions, omitting `retry:all` when `!root_access`.
    pub fn build_retry_markup(&self, uid: i64) -> InlineKeyboardMarkup {
        let accept_btn = InlineKeyboardButton {
            style: Some("primary".to_string()),
            ..self
                .render
                .premium()
                .callback_button(None, "↻ Retry · accept edits", "retry:edits")
        };
        let mut row = vec![accept_btn];
        if self.acl.has_perm(uid, "root_access") {
            let allow_all = InlineKeyboardButton {
                style: Some("danger".to_string()),
                ..self
                    .render
                    .premium()
                    .callback_button(None, "⚠️ Retry · allow all", "retry:all")
            };
            row.push(allow_all);
        }
        InlineKeyboardMarkup::new(vec![row])
    }

    pub fn stop_kb_for(&self, uid: i64) -> InlineKeyboardMarkup {
        let lang = crate::i18n::lang_for(&self.acl, &self.store, uid);
        let btn = InlineKeyboardButton {
            style: Some("danger".to_string()),
            ..self
                .render
                .premium()
                .callback_button(Some("stop"), crate::i18n::t(lang, crate::i18n::Tx::BtnStop), "stop")
        };
        InlineKeyboardMarkup::new(vec![vec![btn]])
    }

    pub fn stop_kb(&self) -> InlineKeyboardMarkup {
        let btn = InlineKeyboardButton {
            style: Some("danger".to_string()),
            ..self
                .render
                .premium()
                .callback_button(Some("stop"), "Stop", "stop")
        };
        InlineKeyboardMarkup::new(vec![vec![btn]])
    }

    pub fn answer_kb_for(&self, uid: i64) -> InlineKeyboardMarkup {
        let lang = crate::i18n::lang_for(&self.acl, &self.store, uid);
        let p = self.render.premium();
        let right = if self.acl.is_owner(uid) || self.acl.has_perm(uid, "dashboard_access") {
            p.callback_button(Some("menu"), crate::i18n::t(lang, crate::i18n::Tx::BtnMenu), "home")
        } else {
            p.callback_button(None, crate::i18n::t(lang, crate::i18n::Tx::BtnLanguage), "lang:menu")
        };
        InlineKeyboardMarkup::new(vec![vec![
            p.callback_button(Some("new"), crate::i18n::t(lang, crate::i18n::Tx::BtnNewChat), "new"),
            right,
        ]])
    }

    pub fn answer_kb(&self) -> InlineKeyboardMarkup {
        let p = self.render.premium();
        InlineKeyboardMarkup::new(vec![vec![
            p.callback_button(Some("new"), "New chat", "new"),
            p.callback_button(Some("menu"), "Menu", "home"),
        ]])
    }

    /// Build [`EngineRequest`] applying ACL `root_access` security boundaries.
    pub fn build_engine_request(&self, req: &JobRequest, outdir: &Path) -> EngineRequest {
        let user_state = self.store.get_user(req.uid);
        let has_root_perm = self.acl.has_perm(req.uid, "root_access");
        let allow_root = has_root_perm || req.overrides.owner_approved_mcp;

        // When root_access == false (and not owner_approved_mcp), force skip_permissions = false
        let skip_permissions = if !has_root_perm && !req.overrides.owner_approved_mcp {
            false
        } else {
            req.overrides
                .skip_permissions
                .unwrap_or(user_state.skip_permissions)
                && allow_root
        };

        let cwd = resolve_safe_cwd(
            user_state.cwd.as_deref(),
            &self.cfg.agy_workspace,
            allow_root,
        );
        let prompt = build_bridge_prompt(req, outdir, &self.cfg.agy_workspace, allow_root);

        let conversation_id = if req.overrides.isolated {
            None
        } else {
            req.overrides
                .conversation_id
                .clone()
                .or(user_state.conversation_id)
        };

        let mode = req.overrides.mode.clone().or(user_state.mode);
        let mut effort = user_state.effort;
        let mut extra_flags: Vec<String> = Vec::new();
        if self.cfg.agy_dynamic_profile {
            let profile = crate::turn_profile::classify_turn_profile(
                &req.text,
                !req.attachments.is_empty(),
                req.overrides.isolated,
            );
            tracing::debug!(uid = req.uid, profile = profile.as_str(), "dynamic turn profile selected");
            if profile == crate::turn_profile::TurnProfile::Lite {
                // Keep all MCPs, skills, and .md rules intact; trim only unused slash-command
                // expansion and default thinking effort when the user has not chosen one.
                if effort.as_deref().is_none_or(str::is_empty) {
                    effort = Some("low".to_string());
                }
                extra_flags.push("--disable-slash-commands".to_string());
            }
        }

        let lim = self.runtime_limits();
        EngineRequest {
            prompt,
            bin: Some(self.cfg.agy_bin.to_string_lossy().to_string()),
            cwd: Some(cwd),
            model: user_state.model,
            effort,
            mode,
            conversation_id,
            skip_permissions,
            timeout_secs: lim.job_timeout_secs,
            agent: user_state.agent,
            add_dirs: Vec::new(),
            env_overrides: Default::default(),
            hard_grace_secs: None,
            extra_flags,
            guard: agy_ext::engines::AgyGuardConfig {
                max_tool_steps: lim.max_tool_steps,
                tool_repeat_limit: lim.tool_repeat_limit,
                max_tools_per_min: lim.max_tools_per_min,
            },
        }
    }

    /// Enqueue a prompt/file job on `req.uid`'s serialized per-user worker.
    pub async fn enqueue(self: &Arc<Self>, req: JobRequest) -> Result<EnqueueOutcome> {
        let uid = req.uid;
        let mut pending_req = req;
        for _attempt in 0..2 {
            let handle = self.ensure_user_queue(uid);
            let (queue_full, is_queued, pos) = {
                let mut st = lock_queue_state(&handle.state);
                let busy = st.running || self.is_user_busy(uid);
                let active_or_pending = busy || st.queued > 0;
                let waiting_ahead = if busy {
                    st.queued
                } else {
                    st.queued.saturating_sub(1)
                };
                let max_user_q = self.runtime_limits().max_queue_per_user.clamp(1, 10);
                if active_or_pending && waiting_ahead >= max_user_q {
                    (true, true, 0)
                } else {
                    st.queued += 1;
                    let pos = if busy {
                        st.queued
                    } else {
                        st.queued.saturating_sub(1)
                    };
                    (false, active_or_pending, pos)
                }
            };

            if queue_full {
                let lang = crate::i18n::lang_for(&self.acl, &self.store, uid);
                let msg = format!(
                    "{} <b>{}</b>",
                    self.render.premium().e("warn"),
                    crate::i18n::t(lang, crate::i18n::Tx::QueueBusyNotice),
                );
                let _ = self
                    .render
                    .send_html_simple(pending_req.chat_id, &msg, Some(self.stop_kb_for(uid)))
                    .await;
                return Ok(EnqueueOutcome::QueueFull);
            }

            let req_chat_id = pending_req.chat_id;
            match handle.tx.send(pending_req).await {
                Ok(()) => {
                    if is_queued {
                        let lang = crate::i18n::lang_for(&self.acl, &self.store, uid);
                        let msg = format!(
                            "🕒 <b>#{pos}</b> — {}",
                            crate::i18n::t(lang, crate::i18n::Tx::QueuedNotice),
                        );
                        let _ = self.render.send_html_simple(req_chat_id, &msg, None).await;
                        return Ok(EnqueueOutcome::Queued(pos));
                    }
                    return Ok(EnqueueOutcome::StartedImmediately);
                }
                Err(mpsc::error::SendError(returned)) => {
                    {
                        let mut st = lock_queue_state(&handle.state);
                        st.queued = st.queued.saturating_sub(1);
                    }
                    self.queues.remove(&uid);
                    pending_req = returned;
                }
            }
        }

        Err(BridgeError::Internal(format!(
            "failed to enqueue job for user {uid}"
        )))
    }

    fn ensure_user_queue(self: &Arc<Self>, uid: i64) -> Arc<UserQueueHandle> {
        match self.queues.entry(uid) {
            Entry::Occupied(occ) => {
                let existing = occ.get();
                Arc::new(UserQueueHandle {
                    tx: existing.tx.clone(),
                    state: Arc::clone(&existing.state),
                })
            }
            Entry::Vacant(vac) => {
                let (tx, mut rx) = mpsc::channel::<JobRequest>(16);
                let state = Arc::new(std::sync::Mutex::new(UserQueueState::default()));
                vac.insert(UserQueueHandle {
                    tx: tx.clone(),
                    state: Arc::clone(&state),
                });

                let mgr = Arc::clone(self);
                let st_ref = Arc::clone(&state);
                tokio::spawn(async move {
                    while let Some(req) = rx.recv().await {
                        {
                            let mut st = lock_queue_state(&st_ref);
                            st.running = true;
                            st.queued = st.queued.saturating_sub(1);
                        }
                        mgr.execute_one_job(req).await;
                        {
                            let mut st = lock_queue_state(&st_ref);
                            st.running = false;
                        }
                    }
                });

                Arc::new(UserQueueHandle { tx, state })
            }
        }
    }

    async fn execute_one_job(&self, req: JobRequest) {
        let uid = req.uid;
        let chat_id = req.chat_id;
        let (cancel_tx, cancel_rx) = watch::channel(false);

        let active_entry = Arc::new(ActiveJobEntry {
            req_id: req.req_id,
            uid,
            chat_id,
            prompt: req.text.clone(),
            started: Instant::now(),
            progress: Mutex::new(Progress::default()),
            stop_handle: Mutex::new(None),
            stop_requested: AtomicBool::new(false),
            cancel_tx,
        });
        self.active.insert(uid, Arc::clone(&active_entry));

        struct ActiveCleanup<'a> {
            map: &'a DashMap<i64, Arc<ActiveJobEntry>>,
            uid: i64,
        }
        impl Drop for ActiveCleanup<'_> {
            fn drop(&mut self) {
                self.map.remove(&self.uid);
            }
        }
        let _active_guard = ActiveCleanup {
            map: &self.active,
            uid,
        };

        // Server-wide concurrency cap (live RuntimeLimits::max_global_ai_jobs) with cancellable wait.
        let mut cancel_slot_rx = cancel_rx.clone();
        let _global_permit = match self.try_acquire_global_slot() {
            Some(p) => p,
            None => {
                let wait_msg_id = self
                    .render
                    .send_html(
                        chat_id,
                        &format!(
                            "⏳ <i>Server AI queue is busy ({}/{} active) — waiting for a free slot…</i>",
                            self.active_global_jobs(),
                            self.max_global_jobs()
                        ),
                        Some(self.stop_kb_for(uid)),
                        None,
                        Some(true),
                        false,
                    )
                    .await
                    .ok()
                    .flatten()
                    .map(|m| m.message_id);

                let mut acquired: Option<GlobalSlotGuard> = None;
                while acquired.is_none() && !active_entry.stop_requested.load(Ordering::SeqCst) {
                    let notified = self.global_slot_notify.notified();
                    if let Some(p) = self.try_acquire_global_slot() {
                        acquired = Some(p);
                        break;
                    }
                    tokio::select! {
                        _ = notified => {
                            acquired = self.try_acquire_global_slot();
                        }
                        _ = cancel_slot_rx.changed() => break,
                    }
                }
                if let Some(mid) = wait_msg_id {
                    let _ = self.client.delete_message(chat_id, mid).await;
                }
                match acquired {
                    Some(p) if !active_entry.stop_requested.load(Ordering::SeqCst) => p,
                    _ => {
                        let _ = self
                            .render
                            .send_html_simple(chat_id, "⏹ <i>Cancelled while waiting in queue.</i>", None)
                            .await;
                        return;
                    }
                }
            }
        };

        if let Err(err) = self
            .run_job_inner(req, Arc::clone(&active_entry), cancel_rx)
            .await
        {
            warn!(uid, error = %err, "job execution failed");
            let msg = format!(
                "{} <b>Internal bridge error</b> — see <code>journalctl -u agy-telegram</code>.",
                self.render.premium().e("err")
            );
            let _ = self.render.send_html_simple(chat_id, &msg, None).await;
        }
    }

    async fn run_job_inner(
        &self,
        req: JobRequest,
        active_entry: Arc<ActiveJobEntry>,
        mut cancel_rx: watch::Receiver<bool>,
    ) -> Result<()> {
        let user_state = self.store.get_user(req.uid);
        let outdir = self
            .cfg
            .outbox_dir()
            .join(req.uid.to_string())
            .join(req.req_id.to_string());
        if let Err(e) = std::fs::create_dir_all(&outdir) {
            warn!(path = %outdir.display(), error = %e, "failed to create job outdir");
        }

        self.last_prompts
            .insert(req.uid, (req.text.clone(), req.attachments.clone()));

        let allow_uncensored = self.acl.has_perm(req.uid, "uncensored");
        let allow_grok = self.acl.has_perm(req.uid, "grok");
        let backend: &str = match req.overrides.force_engine.as_deref() {
            Some("uncensored") => {
                if !allow_uncensored {
                    let lang = crate::i18n::lang_for(&self.acl, &self.store, req.uid);
                    let txt = format!(
                        "{} <b>{}</b> <code>{}</code>",
                        self.render.premium().e("lock"),
                        crate::i18n::t(lang, crate::i18n::Tx::ModuleRequiredHdr),
                        crate::i18n::perm_label(lang, "uncensored"),
                    );
                    let _ = self.render.send_html_simple(req.chat_id, &txt, None).await;
                    return Ok(());
                }
                "uncensored"
            }
            Some("grok") => {
                if !allow_grok {
                    let lang = crate::i18n::lang_for(&self.acl, &self.store, req.uid);
                    let txt = format!(
                        "{} <b>{}</b> <code>{}</code>",
                        self.render.premium().e("lock"),
                        crate::i18n::t(lang, crate::i18n::Tx::ModuleRequiredHdr),
                        crate::i18n::perm_label(lang, "grok"),
                    );
                    let _ = self.render.send_html_simple(req.chat_id, &txt, None).await;
                    return Ok(());
                }
                "grok"
            }
            Some("grok_bot") => {
                if !allow_grok {
                    let lang = crate::i18n::lang_for(&self.acl, &self.store, req.uid);
                    let txt = format!(
                        "{} <b>{}</b> <code>{}</code>",
                        self.render.premium().e("lock"),
                        crate::i18n::t(lang, crate::i18n::Tx::ModuleRequiredHdr),
                        crate::i18n::perm_label(lang, "grok"),
                    );
                    let _ = self.render.send_html_simple(req.chat_id, &txt, None).await;
                    return Ok(());
                }
                "grok_bot"
            }
            Some("agy") => "agy",
            _ => match user_state.extra.get("engine").and_then(|v| v.as_str()) {
                Some("uncensored") if allow_uncensored => "uncensored",
                Some("grok_bot") if allow_grok => "grok_bot",
                Some("grok") if allow_grok => "grok",
                _ if allow_uncensored
                    && user_state
                        .model
                        .as_deref()
                        .is_some_and(agy_ext::uncensored::is_uncensored_model) =>
                {
                    "uncensored"
                }
                _ if allow_grok
                    && user_state
                        .model
                        .as_deref()
                        .is_some_and(agy_ext::grok_oauth::is_grok_model) =>
                {
                    "grok"
                }
                _ => "agy",
            },
        };
        let engine_label = match backend {
            "uncensored" => "Venice Uncensored",
            "grok" => "Grok OAuth",
            "grok_bot" => "Grok Bot",
            _ => "Antigravity",
        };

        if backend == "agy" {
            if let Some(n) = self.parallel_width(&req, &user_state) {
                return self
                    .run_parallel(&req, &active_entry, n, &outdir, &user_state)
                    .await;
            }
        }

        let stop_mk = self.stop_kb_for(req.uid);
        let initial_prog = Progress::default();
        let initial_md = status_md(&initial_prog, self.render.premium());
        let plain_initial_md = strip_md_custom_emoji(&initial_md);
        let cur_md = if self.render.premium().active() {
            initial_md
        } else {
            plain_initial_md
        };
        let cur_mk = if self.render.premium().active() {
            stop_mk.clone()
        } else {
            self.render.premium().strip_markup_icons(stop_mk.clone())
        };

        let (status_msg_id, status_rich) = match tg_retry(1, 2.0, || {
            self.client.send_rich_message(SendRichMessageParams {
                chat_id: req.chat_id,
                rich_message: InputRichMessage::markdown(cur_md.clone()),
                disable_notification: Some(true),
                reply_markup: Some(cur_mk.clone()),
                ..Default::default()
            })
        })
        .await
        {
            Ok(m) => (Some(m.message_id), true),
            Err(_) => {
                let html = status_html(&initial_prog, self.render.premium());
                let m_opt = self
                    .render
                    .send_html(
                        req.chat_id,
                        &html,
                        Some(stop_mk.clone()),
                        None,
                        Some(true),
                        false,
                    )
                    .await
                    .ok()
                    .flatten();
                (m_opt.map(|m| m.message_id), false)
            }
        };

        let _ = tokio::time::timeout(
            Duration::from_secs(5),
            self.client.send_chat_action(req.chat_id, "typing"),
        )
        .await;

        let anchor = Instant::now();
        let stream_ui = Arc::new(StreamUiState {
            chat_id: req.chat_id,
            draft_id: req.req_id,
            mode: effective_stream_mode(&user_state),
            stream_interval_secs: self.cfg.stream_interval.max(1.0),
            status_msg_id,
            status_rich,
            rich_edit_ok: AtomicBool::new(true),
            draft_ok: AtomicBool::new(true),
            editing: AtomicBool::new(false),
            last_digest: Mutex::new(None),
            last_draft_digest: Mutex::new(None),
            last_status_ts: Mutex::new(0.0),
            last_draft_ts: Mutex::new(0.0),
            last_typing_ts: Mutex::new(0.0),
        });

        let mut base_req = self.build_engine_request(&req, &outdir);
        if backend == "agy"
            && base_req.model.as_deref().is_some_and(|m| {
                agy_ext::uncensored::is_uncensored_model(m)
                    || agy_ext::grok_oauth::is_grok_model(m)
            })
        {
            base_req.model = None;
        }
        let allow_root =
            self.acl.has_perm(req.uid, "root_access") || req.overrides.owner_approved_mcp;
        let allow_sandbox = allow_root || self.acl.has_perm(req.uid, "sandbox_exec");
        let pool = self.accounts();
        let is_agy = matches!(self.cfg.agy_engine, CoreEngineKind::Agy);
        let mut tried: HashSet<String> = HashSet::new();
        let mut extra_notes: Vec<String> = Vec::new();
        let mut same_retries: u32 = 0;
        let mut continuity = Continuity::Resume;
        let mut cid_target: Option<String> = base_req.conversation_id.clone();
        let mut prev_steps: usize = 0;
        let mut prev_account: Option<String> = None;
        let mut used_account: Option<String> = None;
        let mut last: Option<(JobResult, Progress)> = None;

        // Primary continuity method needs the conversation in the shared local store;
        // `agy` silently starts a NEW conversation for an unknown id, so check first.
        // Also strip non-AGY session IDs (`venice-*`, `grok-*`) when switching back to AGY.
        if backend == "agy" {
            if let Some(c) = cid_target.as_deref() {
                if c.starts_with("venice-") || c.starts_with("grok-") || c.starts_with("grokbot-") {
                    cid_target = None;
                }
            }
            if let (Some(p), Some(c)) = (pool.as_ref(), cid_target.as_deref()) {
                if is_agy && !p.conversation_exists(c) {
                    warn!(uid = req.uid, cid = c, "conversation not in local store; using replay");
                    continuity = Continuity::Replay;
                }
            }
        }

        let mut attempt: usize = 0;
        let mut resume_mismatch_retried = false;
        let mut model_refresh_needed: HashSet<String> = HashSet::new();
        let mut model_retry_done: HashSet<String> = HashSet::new();
        let mut pinned_account: Option<String> = None;
        let mut pending_switch: Option<(String, String)> = None;
        let mut inflight: Option<InFlightGuard> = None;

        let (mut res, final_progress) = if backend == "uncensored" || backend == "grok" || backend == "grok_bot" {
            let entry_cb = Arc::clone(&active_entry);
            let ui_cb = Arc::clone(&stream_ui);
            let client_cb = Arc::clone(&self.client);
            let prem_cb = Arc::clone(self.render.premium());
            let mk_cb = stop_mk.clone();

            let progress_cb: ProgressCallback = Arc::new(move |p: Progress| {
                let entry = Arc::clone(&entry_cb);
                let ui = Arc::clone(&ui_cb);
                let client = Arc::clone(&client_cb);
                let prem = Arc::clone(&prem_cb);
                let mk = mk_cb.clone();
                Box::pin(async move {
                    if let Ok(mut g) = entry.progress.lock() {
                        *g = p.clone();
                    }
                    ui.tick(anchor, &p, &client, &prem, &mk).await;
                })
            });

            let _ticker_guard = AbortOnDrop({
                let entry_t = Arc::clone(&active_entry);
                let ui_t = Arc::clone(&stream_ui);
                let client_t = Arc::clone(&self.client);
                let prem_t = Arc::clone(self.render.premium());
                let mk_t = stop_mk.clone();
                tokio::spawn(async move {
                    loop {
                        tokio::time::sleep(Duration::from_secs(5)).await;
                        let p = entry_t
                            .progress
                            .lock()
                            .map(|g| g.clone())
                            .unwrap_or_default();
                        ui_t.tick(anchor, &p, &client_t, &prem_t, &mk_t).await;
                    }
                })
            });

            let cwd = base_req
                .cwd
                .as_deref()
                .unwrap_or_else(|| Path::new(&self.cfg.agy_workspace));

            let run_res = if backend == "uncensored" {
                used_account = Some("venice-uncensored".to_string());
                let model_choice = base_req
                    .model
                    .as_deref()
                    .filter(|m| agy_ext::uncensored::is_uncensored_model(m))
                    .unwrap_or(agy_ext::uncensored::DEFAULT_UNCENSORED_MODEL);
                let agent_mode = req.overrides.force_agent_mode.unwrap_or_else(|| {
                    crate::handlers_uncensored::uncensored_agent_mode(&user_state)
                });
                let mode_tag = if agent_mode { "Agent" } else { "Chat" };
                extra_notes.push(format!(
                    "🔥 <i>Venice Uncensored ({mode_tag}) · <code>{}</code></i>",
                    esc(&agy_ext::uncensored::clean_model_id(model_choice))
                ));
                let sess_key = (!req.overrides.isolated)
                    .then(|| crate::handlers_uncensored::uncensored_session_key(req.uid));
                let three_stage_mode =
                    crate::handlers_uncensored::uncensored_three_stage_mode(&user_state);
                let custom_sys =
                    agy_ext::uncensored::load_custom_sysprompt(&self.cfg.state_dir, req.uid);
                let enriched_prompt = agy_ext::uncensored::enrich_prompt_with_attachments(
                    &base_req.prompt,
                    &req.attachments,
                    agent_mode,
                )
                .await;

                agy_ext::uncensored::run_uncensored_agent_with_stage(
                    &self.cfg.venice_api_base,
                    &self.cfg.venice_api_key,
                    model_choice,
                    &enriched_prompt,
                    cwd,
                    &self.cfg.agy_workspace,
                    &self.cfg.mcp_config_path,
                    &self.cfg.agy_skills_dir,
                    &self.cfg.state_dir,
                    sess_key,
                    allow_root,
                    allow_sandbox,
                    agent_mode,
                    None,
                    custom_sys.as_deref(),
                    three_stage_mode,
                    Some(progress_cb),
                    cancel_rx.clone(),
                )
                .await
            } else if backend == "grok" {
                used_account = Some("grok-oauth".to_string());
                let model_choice = base_req
                    .model
                    .as_deref()
                    .filter(|m| agy_ext::grok_oauth::is_grok_model(m))
                    .unwrap_or(agy_ext::grok_oauth::DEFAULT_GROK_MODEL);
                let agent_mode = req.overrides.force_agent_mode.unwrap_or_else(|| {
                    crate::handlers_grok::grok_agent_mode(&user_state)
                });
                let mode_tag = if agent_mode { "Agent" } else { "Chat" };
                extra_notes.push(format!(
                    "⚡ <i>Grok OAuth ({mode_tag}) · <code>{}</code></i>",
                    esc(&agy_ext::grok_oauth::clean_grok_model_id(model_choice))
                ));
                let sess_key = (!req.overrides.isolated)
                    .then(|| crate::handlers_grok::grok_session_key(req.uid));

                let grok_proxy = match self.proxies().map(|r| r.resolve_grok()) {
                    Some(ResolvedProxy::Blocked { reason, .. }) => Err(BridgeError::Network(
                        format!(
                            "Grok sticky proxy blocked (fail-closed): {reason}. Check /proxies."
                        ),
                    )),
                    Some(ResolvedProxy::Use { url, .. }) => Ok(Some(url)),
                    _ => Ok(None),
                };

                match grok_proxy {
                    Err(e) => Err(e),
                    Ok(proxy_url) => {
                        agy_ext::grok_oauth::run_grok_agent_via(
                            &self.cfg.state_dir,
                            model_choice,
                            &base_req.prompt,
                            cwd,
                            &self.cfg.agy_workspace,
                            &self.cfg.mcp_config_path,
                            &self.cfg.agy_skills_dir,
                            sess_key,
                            allow_root,
                            allow_sandbox,
                            agent_mode,
                            proxy_url,
                            Some(progress_cb),
                            cancel_rx.clone(),
                        )
                        .await
                    }
                }
            } else {
                used_account = Some("grok-bot-oauth".to_string());
                let grok_proxy = match self.proxies().map(|r| r.resolve_grok()) {
                    Some(ResolvedProxy::Blocked { reason, .. }) => Err(BridgeError::Network(
                        format!(
                            "Grok sticky proxy blocked (fail-closed): {reason}. Check /proxies."
                        ),
                    )),
                    Some(ResolvedProxy::Use { url, .. }) => Ok(Some(url)),
                    _ => Ok(None),
                };

                match grok_proxy {
                    Err(e) => Err(e),
                    Ok(proxy_url) => {
                        let picked = crate::handlers_grok_bot::selected_grok_bot(&user_state)
                            .or_else(|| {
                                agy_ext::grok_bot::load_cached_grok_bot_agents(&self.cfg.state_dir)
                                    .into_iter()
                                    .next()
                                    .map(|b| (b.agent_id, b.name))
                            });
                        let resolved_bot = match picked {
                            Some(pair) => Ok(pair),
                            None => match agy_ext::grok_bot::list_grok_bot_agents_via(
                                &self.cfg.state_dir,
                                proxy_url.as_deref(),
                            )
                            .await
                            {
                                Ok(list) => list
                                    .into_iter()
                                    .next()
                                    .map(|b| (b.agent_id, b.name))
                                    .ok_or_else(|| {
                                        BridgeError::NotFound(
                                            "No Grok Bot found on this account. Create one in Grok Bot first or tap Sync Bots in /gbot."
                                                .to_string(),
                                        )
                                    }),
                                Err(e) => Err(e),
                            },
                        };
                        match resolved_bot {
                            Err(e) => Err(e),
                            Ok((agent_id, agent_name)) => {
                                extra_notes.push(format!(
                                    "🤖 <i>Grok Bot · <code>{}</code></i>",
                                    esc(&agent_name)
                                ));
                                agy_ext::grok_bot::run_grok_bot_turn_via(
                                    &self.cfg.state_dir,
                                    &agent_id,
                                    &agent_name,
                                    &base_req.prompt,
                                    proxy_url,
                                    agy_ext::grok_bot::DEFAULT_TURN_TIMEOUT_SECS,
                                    Some(progress_cb),
                                    cancel_rx.clone(),
                                )
                                .await
                            }
                        }
                    }
                }
            };

            drop(_ticker_guard);

            let prog = active_entry
                .progress
                .lock()
                .map(|g| g.clone())
                .unwrap_or_default();
            let r = match run_res {
                Ok(r) => r,
                Err(e) => JobResult {
                    error: Some(json!({ "message": e.to_string() })),
                    steps: prog.steps,
                    ..Default::default()
                },
            };
            (r, prog)
        } else {
            let max_attempts = pool
                .as_ref()
                .map(|p| p.policy().max_failover_attempts.clamp(1, MAX_ENGINE_ATTEMPTS))
                .unwrap_or(MAX_ENGINE_ATTEMPTS);
            let mut blocked_skips: usize = 0;
            loop {
            attempt += 1;
            if active_entry.stop_requested.load(Ordering::SeqCst) && last.is_some() {
                break last.take().unwrap_or_default();
            }
            if let Some(p) = pool.as_ref() {
                if let Some(brk) = p.breaker_status() {
                    if let Some(prev) = last.take() {
                        extra_notes.push(self.pool_breaker_note(&brk));
                        break prev;
                    }
                    if let Some(mid) = status_msg_id {
                        let _ = self.client.delete_message(req.chat_id, mid).await;
                    }
                    let note = self.pool_breaker_note(&brk);
                    let mk = if self.acl.is_owner(req.uid) {
                        InlineKeyboardMarkup::new(vec![vec![self
                            .render
                            .premium()
                            .callback_button(Some("admin"), "Accounts / Resume", "acct:list")]])
                    } else {
                        self.answer_kb_for(req.uid)
                    };
                    let _ = self.render.send_html_simple(req.chat_id, &note, Some(mk)).await;
                    return Ok(());
                }
            }
            let acct: Option<Account> = match pool.as_ref() {
                Some(p) => {
                    let mut picked = pinned_account
                        .take()
                        .and_then(|id| p.pick_pinned_begin_with_filter(&id, &tried, |a| self.account_proxy_allowed(a)))
                        .or_else(|| p.pick_begin_with_filter(req.uid, &tried, |a| self.account_proxy_allowed(a)));

                    // Under strict_safe (max 1 concurrent run/account), if eligible accounts exist
                    // but are currently busy with another user's job, wait politely instead of failing fast.
                    if picked.is_none() && p.breaker_status().is_none() {
                        let wait_deadline = Instant::now() + Duration::from_secs(45);
                        while picked.is_none()
                            && Instant::now() < wait_deadline
                            && !active_entry.stop_requested.load(Ordering::SeqCst)
                        {
                            let now_i = now_secs() as i64;
                            let pol = p.policy();
                            let any_busy_eligible = p.list().iter().any(|a| {
                                !tried.contains(&a.id)
                                    && a.available_at_with_policy(now_i, &pol)
                                    && self.account_proxy_allowed(a)
                                    && p.in_flight(&a.id) > 0
                            });
                            if !any_busy_eligible {
                                break;
                            }
                            tokio::select! {
                                _ = tokio::time::sleep(Duration::from_millis(1500)) => {}
                                _ = cancel_rx.changed() => {
                                    if active_entry.stop_requested.load(Ordering::SeqCst) {
                                        break;
                                    }
                                }
                            }
                            if p.breaker_status().is_some() {
                                break;
                            }
                            picked = p.pick_begin_with_filter(req.uid, &tried, |a| self.account_proxy_allowed(a));
                        }
                    }

                    match picked {
                    Some(a) => {
                        // counted as in-flight from the pick on; released when dropped
                        inflight = Some(InFlightGuard(Arc::clone(p), a.id.clone()));
                        if let Some((from, reason)) = pending_switch.take() {
                            let _ = self
                                .render
                                .send_html(
                                    req.chat_id,
                                    &format!(
                                        "🔁 <b>Switching account</b> · <code>{}</code> → <code>{}</code> — <i>{}</i>",
                                        esc(&from),
                                        esc(&self.account_public_name(req.uid, &a)),
                                        esc(&reason)
                                    ),
                                    None,
                                    None,
                                    Some(true),
                                    false,
                                )
                                .await;
                        }
                        Some(a)
                    }
                    None => {
                        if let Some(prev) = last.take() {
                            extra_notes.push(self.pool_exhausted_note(p));
                            break prev;
                        }
                        if let Some(mid) = status_msg_id {
                            let _ = self.client.delete_message(req.chat_id, mid).await;
                        }
                        let note = self.pool_exhausted_note(p);
                        let _ = self
                            .render
                            .send_html_simple(req.chat_id, &note, Some(self.answer_kb_for(req.uid)))
                            .await;
                        return Ok(());
                    }
                    }
                }
                None => None,
            };

            let mut engine_req = base_req.clone();
            match continuity {
                Continuity::Resume => {
                    engine_req.conversation_id = cid_target.clone();
                    if attempt > 1 && prev_steps > 0 {
                        engine_req.prompt = format!(
                            "[failover] The previous attempt of this same turn stopped after {prev_steps} step(s) because its Antigravity account failed. You are continuing the same conversation on another account: check what was already done and continue from there; do not redo completed steps.\n{}",
                            base_req.prompt
                        );
                    } else if attempt == 1
                        && is_agy
                        && self.cfg.prompt_compact_resume
                        && !req.overrides.isolated
                        && cid_target.as_deref().is_some_and(|c| !c.is_empty())
                    {
                        engine_req.prompt = build_bridge_prompt_ex(
                            &req,
                            &outdir,
                            &self.cfg.agy_workspace,
                            allow_root,
                            true,
                        );
                    }
                }
                Continuity::Replay => {
                    engine_req.conversation_id = None;
                    match handoff::context_pack(
                        &self.cfg.state_dir,
                        &self.cfg.agy_workspace,
                        req.uid,
                        cid_target.as_deref(),
                        handoff::DEFAULT_PACK_CHARS,
                    ) {
                        Some(pack) => {
                            engine_req.prompt = format!("{pack}\n{}", base_req.prompt);
                        }
                        None => {
                            continuity = Continuity::Recall;
                            engine_req.prompt = format!(
                                "{}\n{}",
                                handoff::recall_directive(&self.cfg.agy_workspace, req.uid, cid_target.as_deref()),
                                base_req.prompt
                            );
                        }
                    }
                }
                Continuity::Recall => {
                    engine_req.conversation_id = None;
                    engine_req.prompt = format!(
                        "{}\n{}",
                        handoff::recall_directive(&self.cfg.agy_workspace, req.uid, cid_target.as_deref()),
                        base_req.prompt
                    );
                }
            }
            // The account must offer the user's model; otherwise pause and let the user pick.
            if let (Some(_), Some(a)) = (pool.as_ref(), acct.as_ref()) {
                if is_agy {
                    let ent = Arc::clone(&active_entry);
                    let stop = move || ent.stop_requested.load(Ordering::SeqCst);
                    let force = model_refresh_needed.remove(&a.id);
                    match self
                        .resolve_model_for_account(req.uid, req.chat_id, a, engine_req.model.as_deref(), &stop, force)
                        .await
                    {
                        ModelDecision::Keep => {
                            // always pass an explicit --model: the shared settings.json default
                            // may not exist on this account
                            if engine_req.model.as_deref().is_none_or(str::is_empty) {
                                engine_req.model = self.account_default_model(a);
                            }
                        }
                        ModelDecision::Use(m) => {
                            if engine_req.model.as_deref() != Some(m.as_str()) {
                                extra_notes.push(format!(
                                    "🧩 <i>Model on account <code>{}</code>: <code>{}</code> (your choice; this account doesn't offer your default).</i>",
                                    esc(&self.account_public_name(req.uid, a)),
                                    esc(&m)
                                ));
                            }
                            engine_req.model = Some(m);
                        }
                        ModelDecision::Cancelled(why) => {
                            info!(uid = req.uid, account = %a.id, why, "job cancelled at model choice");
                            if let Some(mid) = status_msg_id {
                                let _ = self.client.delete_message(req.chat_id, mid).await;
                            }
                            return Ok(());
                        }
                    }
                }
            }
            if let (Some(p), Some(a)) = (pool.as_ref(), acct.as_ref()) {
                if let Err(e) = p.prepare_home(a) {
                    warn!(account = %a.id, error = %e, "shadow home refresh failed");
                }
                engine_req
                    .env_overrides
                    .insert("HOME".to_string(), a.home.to_string_lossy().into_owned());
                if let Some(reg) = self.proxies() {
                    match reg.resolve(a.proxy_id.as_deref()) {
                        ResolvedProxy::Use { url, .. } => {
                            inject_proxy_env(&mut engine_req.env_overrides, &url);
                        }
                        ResolvedProxy::Direct | ResolvedProxy::DirectFallback { .. } => {}
                        ResolvedProxy::Blocked { reason, .. } => {
                            warn!(account = %a.id, reason = %reason, "account sticky proxy blocked (fail-closed); skipping");
                            drop(inflight.take());
                            tried.insert(a.id.clone());
                            blocked_skips += 1;
                            if blocked_skips <= agy_core::accounts::MAX_ACCOUNTS {
                                attempt = attempt.saturating_sub(1);
                            }
                            continue;
                        }
                    }
                }
                let pace_s = p.pacing_wait_secs(&a.id);
                if pace_s > 0 {
                    let wait = Duration::from_secs(pace_s)
                        + Duration::from_millis(polite_jitter_ms(
                            (req.req_id as u64).wrapping_add(attempt as u64),
                            1500,
                        ));
                    info!(uid = req.uid, account = %a.id, wait_ms = wait.as_millis() as u64, "gentle account pacing delay");
                    tokio::select! {
                        _ = tokio::time::sleep(wait) => {}
                        _ = cancel_rx.changed() => {
                            if active_entry.stop_requested.load(Ordering::SeqCst) {
                                drop(inflight.take());
                                break last.take().unwrap_or_default();
                            }
                        }
                    }
                }
                info!(uid = req.uid, account = %a.id, attempt, continuity = continuity.label(), "engine attempt");
            }

            let entry_cb = Arc::clone(&active_entry);
            let ui_cb = Arc::clone(&stream_ui);
            let client_cb = Arc::clone(&self.client);
            let prem_cb = Arc::clone(self.render.premium());
            let mk_cb = stop_mk.clone();

            let progress_cb: ProgressCallback = Arc::new(move |p: Progress| {
                let entry = Arc::clone(&entry_cb);
                let ui = Arc::clone(&ui_cb);
                let client = Arc::clone(&client_cb);
                let prem = Arc::clone(&prem_cb);
                let mk = mk_cb.clone();
                Box::pin(async move {
                    if let Ok(mut g) = entry.progress.lock() {
                        *g = p.clone();
                    }
                    ui.tick(anchor, &p, &client, &prem, &mk).await;
                })
            });

            let proc_job = self.runner.create_job(&engine_req, Some(progress_cb));
            let stop_handle = proc_job.stop_handle();
            if let Ok(mut g) = active_entry.stop_handle.lock() {
                *g = Some(stop_handle.clone());
            }
            if active_entry.stop_requested.load(Ordering::SeqCst) {
                stop_handle.stop().await;
            }

            // 5-second background ticker keeping elapsed time & typing fresh
            let _ticker_guard = AbortOnDrop({
                let entry_t = Arc::clone(&active_entry);
                let ui_t = Arc::clone(&stream_ui);
                let client_t = Arc::clone(&self.client);
                let prem_t = Arc::clone(self.render.premium());
                let mk_t = stop_mk.clone();
                tokio::spawn(async move {
                    loop {
                        tokio::time::sleep(Duration::from_secs(5)).await;
                        let p = entry_t
                            .progress
                            .lock()
                            .map(|g| g.clone())
                            .unwrap_or_default();
                        ui_t.tick(anchor, &p, &client_t, &prem_t, &mk_t).await;
                    }
                })
            });

            let run_res = proc_job.run().await;
            drop(_ticker_guard);
            drop(inflight.take());

            let prog = proc_job.progress_snapshot();
            if let Ok(mut g) = active_entry.progress.lock() {
                *g = prog.clone();
            }

            let res = match run_res {
                Ok(r) => r,
                Err(e) => {
                    if let Some(mid) = status_msg_id {
                        let _ = self.client.delete_message(req.chat_id, mid).await;
                    }
                    return Err(e);
                }
            };

            let (Some(p), Some(a)) = (pool.as_ref(), acct.as_ref()) else {
                break (res, prog);
            };
            p.record_run_finished(&a.id);
            if let Some(ref usage_val) = res.usage {
                if p.record_usage(&a.id, usage_val) {
                    self.alert_owner_weekly_reserved(a, p).await;
                }
            }

            let stopped = res.stopped || active_entry.stop_requested.load(Ordering::SeqCst);

            if continuity == Continuity::Resume {
                if let (Some(want), Some(got)) = (cid_target.as_deref(), res.conversation_id.as_deref()) {
                    if !got.is_empty() && want != got {
                        warn!(uid = req.uid, want, got, steps = res.steps, "agy did not resume the requested conversation");
                        // The answer was produced WITHOUT the conversation history. If it was a
                        // plain answer (no tool steps -> no side effects to duplicate), redo the
                        // turn with fallback 1 (Replay pack); otherwise keep it and warn.
                        if !stopped && !res.timed_out && res.steps <= 1 && !resume_mismatch_retried && attempt < max_attempts {
                            resume_mismatch_retried = true;
                            continuity = Continuity::Replay;
                            last = Some((res, prog));
                            continue;
                        }
                        extra_notes.push("⚠️ <i>The previous conversation could not be resumed; a new one was started.</i>".to_string());
                    }
                }
            }

            // A print timeout or live AI safety guard stop is never an account fault: never rotate,
            // and do not reset `consecutive_failures` on a tripped loop/burst guard.
            if (res.timed_out || res.guard_tripped.is_some()) && !stopped {
                used_account = Some(a.id.clone());
                break (res, prog);
            }
            let failed = res.error.is_some()
                || (res.exit_code != Some(0) && res.text.trim().is_empty() && !res.timed_out);
            if stopped || !failed {
                p.record_success(&a.id, Some(req.uid));
                used_account = Some(a.id.clone());
                if prev_account.is_some() || continuity != Continuity::Resume {
                    extra_notes.push(self.switch_note(req.uid, prev_account.as_deref(), a, continuity, None));
                }
                break (res, prog);
            }

            let (msg, code) = error_parts(res.error.as_ref());
            let cls = classify_failure(&msg, code.as_deref(), res.exit_code, !res.text.trim().is_empty());

            // agy rejected the model for this account (print mode hard-fails, listing models):
            // refresh this account's list and ask the user, then retry (no auto-substitution).
            if is_agy && crate::models_pool::is_model_unavailable_error(&msg) && model_retry_done.insert(a.id.clone()) && attempt < max_attempts {
                warn!(uid = req.uid, account = %a.id, "model not available on account; asking user");
                model_refresh_needed.insert(a.id.clone());
                pinned_account = Some(a.id.clone());
                last = Some((res, prog));
                continue;
            }
            warn!(uid = req.uid, account = %a.id, class = cls.class.label(), action = ?cls.action, "engine attempt failed");

            match cls.action {
                FailureAction::Deliver => {
                    if cls.class == FailureClass::ContextProblem && attempt < max_attempts {
                        if let Some(nx) = continuity.next() {
                            // Resume rejected (e.g. history too large) -> downgrade continuity
                            // on the SAME account; not the account's fault.
                            continuity = nx;
                            last = Some((res, prog));
                            continue;
                        }
                    }
                    used_account = Some(a.id.clone());
                    break (res, prog);
                }
                FailureAction::RetrySame { delay_s } => {
                    p.record_failure(&a.id, &cls, &msg);
                    if same_retries < 1 && attempt < max_attempts {
                        same_retries += 1;
                        prev_steps = prev_steps.max(res.steps);
                        if res.steps > 0 {
                            if let Some(c) = res.conversation_id.clone().filter(|c| p.conversation_exists(c)) {
                                cid_target = Some(c);
                                continuity = Continuity::Resume;
                            }
                        }
                        last = Some((res, prog));
                        tokio::select! {
                            _ = tokio::time::sleep(Duration::from_secs(delay_s)) => {}
                            _ = cancel_rx.changed() => {
                                if active_entry.stop_requested.load(Ordering::SeqCst) {
                                    break last.take().unwrap_or_default();
                                }
                            }
                        }
                        continue;
                    }
                    if cls.class == FailureClass::Network {
                        // host network problem: another account would fail the same way
                        used_account = Some(a.id.clone());
                        break (res, prog);
                    }
                    tried.insert(a.id.clone());
                }
                FailureAction::Cooldown { .. } | FailureAction::Disable => {
                    let was_tripped = p.breaker_status().is_some();
                    let st = p.record_failure(&a.id, &cls, &msg);
                    tried.insert(a.id.clone());
                    if st == HealthStatus::Disabled {
                        self.alert_owner_disabled(a, cls.class, &msg).await;
                    }
                    if !was_tripped {
                        if let Some(brk) = p.breaker_status() {
                            self.alert_owner_breaker(&brk).await;
                            used_account = Some(a.id.clone());
                            extra_notes.push(self.pool_breaker_note(&brk));
                            break (res, prog);
                        }
                    }
                }
            }

            if attempt >= max_attempts {
                used_account = Some(a.id.clone());
                break (res, prog);
            }
            same_retries = 0;
            prev_steps = res.steps;
            // If this attempt created/continued a conversation, the next account resumes it.
            if let Some(c) = res.conversation_id.clone().filter(|c| !c.is_empty()) {
                if is_agy && p.conversation_exists(&c) && res.steps > 0 {
                    cid_target = Some(c);
                    continuity = Continuity::Resume;
                }
            }
            let reason = account_reason(&cls, &a.id, p);
            extra_notes.push(self.switch_note(req.uid, Some(&a.id), a, continuity, Some(&reason)));
            // announced once the next account is known ("A → B")
            pending_switch = Some((self.account_public_name(req.uid, a), reason));
            prev_account = Some(a.id.clone());
            last = Some((res, prog));
            let switch_delay = p.policy().switch_delay_secs;
            if switch_delay > 0 {
                let wait = Duration::from_secs(switch_delay)
                    + Duration::from_millis(polite_jitter_ms(attempt as u64, 1200));
                tokio::select! {
                    _ = tokio::time::sleep(wait) => {}
                    _ = cancel_rx.changed() => {
                        if active_entry.stop_requested.load(Ordering::SeqCst) {
                            break last.take().unwrap_or_default();
                        }
                    }
                }
            }
        }
        };

        if active_entry.stop_requested.load(Ordering::SeqCst) {
            res.stopped = true;
        }

        if let Some(mid) = status_msg_id {
            let _ = self.client.delete_message(req.chat_id, mid).await;
        }

        if backend == "agy" && !req.overrides.isolated {
            if let Some(ref cid) = res.conversation_id {
                if !cid.is_empty() && user_state.conversation_id.as_deref() != Some(cid.as_str()) {
                    let title = if req.text.trim().is_empty() {
                        "file"
                    } else {
                        req.text.trim()
                    };
                    let ts = now_secs() as i64;
                    if let Err(err) = self.store.update_user(req.uid, |u| {
                        u.push_session(cid.clone(), title, ts);
                    }) {
                        warn!(uid = req.uid, error = %err, "failed to save session in StateStore");
                    }
                }
            }
        }

        if backend == "agy" && pool.is_some() && !req.overrides.isolated && !res.text.trim().is_empty() {
            handoff::append_turn(
                &self.cfg.state_dir,
                req.uid,
                res.conversation_id.as_deref(),
                used_account.as_deref(),
                &req.text,
                &res.text,
            );
        }

        self.deliver_result_with_notes(
            &req,
            &user_state,
            &final_progress,
            &res,
            &outdir,
            &extra_notes,
            engine_label,
        )
        .await
    }

    fn account_public_name(&self, uid: i64, a: &Account) -> String {
        if self.acl.is_owner(uid) {
            a.display_name()
        } else {
            a.id.clone()
        }
    }

    fn switch_note(
        &self,
        uid: i64,
        from: Option<&str>,
        to: &Account,
        continuity: Continuity,
        reason: Option<&str>,
    ) -> String {
        let to_name = self.account_public_name(uid, to);
        match (from, reason) {
            (Some(f), Some(r)) => format!(
                "🔁 <i>Account <code>{}</code> failed ({}) — session {}.</i>",
                esc(f),
                esc(r),
                esc(continuity.label())
            ),
            (Some(f), None) => format!(
                "🔁 <i>Answered by account <code>{}</code> after <code>{}</code> failed · session {}.</i>",
                esc(&to_name),
                esc(f),
                esc(continuity.label())
            ),
            _ => format!(
                "♻️ <i>Session {} on account <code>{}</code>.</i>",
                esc(continuity.label()),
                esc(&to_name)
            ),
        }
    }

    pub(crate) fn pool_breaker_note(&self, brk: &(i64, String)) -> String {
        let (until_ts, ref reason) = *brk;
        let rem = (until_ts - now_secs() as i64).max(0) as u64;
        format!(
            "🛡 <b>Account Pool Safety Breaker is ACTIVE</b> ({})\n\
            Automatic account rotation is paused to protect remaining accounts.\n\
            <blockquote><b>Trigger:</b> {}</blockquote>\n\
            <i>Owner: inspect accounts &amp; proxies, then press Resume Pool in /accounts.</i>",
            human_secs(rem),
            esc(reason)
        )
    }

    pub(crate) fn pool_exhausted_note(&self, p: &AccountStore) -> String {
        if let Some(brk) = p.breaker_status() {
            return self.pool_breaker_note(&brk);
        }
        let now = now_secs() as i64;
        let policy = p.policy();
        let reserved = p.weekly_reserved_count();
        let proxy_blocked = p
            .list()
            .iter()
            .filter(|a| a.available_at_with_policy(now, &policy) && !self.account_proxy_allowed(a))
            .count();
        let busy_slots = p
            .list()
            .iter()
            .filter(|a| {
                a.available_at_with_policy(now, &policy)
                    && self.account_proxy_allowed(a)
                    && p.in_flight(&a.id) >= policy.max_concurrency_per_account.max(1)
            })
            .count();
        let mut details = Vec::new();
        if busy_slots > 0 {
            details.push(format!(
                "⏳ <b>{busy_slots}</b> account(s) currently busy (safety limit: {}/account) — try again in a moment",
                policy.max_concurrency_per_account
            ));
        }
        if reserved > 0 {
            details.push(format!(
                "🛡 <b>{reserved}</b> account(s) holding their <b>{:.1}% weekly reserve</b>",
                policy.weekly_reserve_pct
            ));
        }
        if proxy_blocked > 0 {
            details.push(format!(
                "🌐 <b>{proxy_blocked}</b> account(s) paused because their sticky proxy is unhealthy (fail-closed — check /proxies)"
            ));
        }
        let detail_line = if details.is_empty() {
            String::new()
        } else {
            format!("\n{}", details.join("\n"))
        };
        let when = p
            .next_available_ts()
            .map(|ts| {
                let secs = (ts - now).max(0) as u64;
                format!(" Next account frees up in <b>{}</b>.", human_secs(secs))
            })
            .unwrap_or_default();
        format!(
            "{} <b>No Antigravity account is available right now.</b>{when}{detail_line}\n<i>The owner can inspect accounts, proxies, or reserve policy in /accounts.</i>",
            self.render.premium().e("warn")
        )
    }

    pub(crate) async fn alert_owner_breaker(&self, brk: &(i64, String)) {
        let owner = self.cfg.owner_id;
        if owner == 0 {
            return;
        }
        let html = self.pool_breaker_note(brk);
        let mk = InlineKeyboardMarkup::new(vec![vec![
            self.render
                .premium()
                .callback_button(None, "🛡 Open /accounts", "acct:list"),
            self.render
                .premium()
                .callback_button(None, "🌐 Open /proxies", "px:list"),
        ]]);
        let _ = self.render.send_html_simple(owner, &html, Some(mk)).await;
    }

    pub(crate) async fn alert_owner_weekly_reserved(&self, a: &Account, p: &AccountStore) {
        let owner = self.cfg.owner_id;
        if owner == 0 {
            return;
        }
        let pol = p.policy();
        let fresh = p.get(&a.id).unwrap_or_else(|| a.clone());
        let pct = fresh
            .usage
            .weekly_used_pct_at(now_secs() as i64, &pol)
            .map(|v| format!("{v:.1}%"))
            .unwrap_or_else(|| "≥99%".to_string());
        let html = format!(
            "🛡 <b>Weekly reserve reached</b> · <code>{}</code>\n\
            Parked automatically at <b>{pct}</b> weekly usage (keeping <b>{:.1}%</b> reserve · 7d: <code>{}</code>, 5h: <code>{}</code>).\n\
            <i>5-hour usage never triggers this guard. Adjust caps in /accounts.</i>",
            esc(&format!("{} ({})", fresh.display_name(), fresh.id)),
            pol.weekly_reserve_pct,
            esc(&format_tokens_compact(fresh.usage.tokens_week)),
            esc(&format_tokens_compact(fresh.usage.tokens_5h)),
        );
        let mk = InlineKeyboardMarkup::new(vec![vec![self
            .render
            .premium()
            .callback_button(None, "Accounts", format!("acct:v:{}", fresh.id))]]);
        let _ = self.render.send_html_simple(owner, &html, Some(mk)).await;
    }

    async fn alert_owner_disabled(&self, a: &Account, class: FailureClass, msg: &str) {
        let owner = self.cfg.owner_id;
        if owner == 0 {
            return;
        }
        let detail: String = msg.chars().take(400).collect();
        let html = format!(
            "{} <b>Account disabled</b> · <code>{}</code>\n<b>Reason:</b> {}\n<blockquote expandable>{}</blockquote>\n<i>Fix it (re-login / appeal) then press Reset in /accounts.</i>",
            self.render.premium().e("err"),
            esc(&format!("{} ({})", a.display_name(), a.id)),
            esc(class.label()),
            esc(&detail)
        );
        let mk = InlineKeyboardMarkup::new(vec![vec![self
            .render
            .premium()
            .callback_button(None, "Accounts", "acct:list")]]);
        let _ = self.render.send_html_simple(owner, &html, Some(mk)).await;
    }

    #[allow(clippy::too_many_arguments)]
    async fn deliver_result_with_notes(
        &self,
        req: &JobRequest,
        user_state: &UserState,
        progress: &Progress,
        res: &JobResult,
        outdir: &Path,
        extra_notes: &[String],
        engine_label: &str,
    ) -> Result<()> {
        let chat = req.chat_id;
        let prem = self.render.premium();

        if let Some(ref err) = res.error {
            if res.text.trim().is_empty() {
                let mut err_h = error_html_for(err, prem, engine_label);
                if !extra_notes.is_empty() {
                    err_h = format!("{}\n{err_h}", extra_notes.join("\n"));
                }
                self.render
                    .send_html_simple(chat, &err_h, Some(self.answer_kb_for(req.uid)))
                    .await?;
                // Even if an error occurred late in the turn, deliver any completed files already written to outdir!
                if outdir.is_dir() {
                    let mut extra_secrets: Vec<String> = Vec::new();
                    if !self.cfg.bot_token.is_empty() {
                        extra_secrets.push(self.cfg.bot_token.clone());
                    }
                    if !self.cfg.venice_api_key.is_empty() {
                        extra_secrets.push(self.cfg.venice_api_key.clone());
                    }
                    let _ = self
                        .render
                        .deliver_outbox_files_guarded(
                            chat,
                            outdir,
                            10,
                            MAX_UPLOAD_BYTES,
                            &HashSet::new(),
                            self.runtime_limits().outbox_secret_scan,
                            &extra_secrets,
                        )
                        .await;
                    let _ = std::fs::remove_dir(outdir);
                }
                return Ok(());
            }
        }

        let mut text = res.text.trim().to_string();
        let mut notes: Vec<String> = extra_notes.to_vec();
        if res.stopped {
            notes.push("⏹ <i>Stopped — partial output.</i>".to_string());
        }
        if let Some(ref reason) = res.guard_tripped {
            let lim = self.runtime_limits();
            notes.push(format!(
                "🛡 <b>AI Safety Guard stopped this turn</b> — <code>{}</code>.\n<i>Active limits: steps ≤ {}, repeat ≤ {}x, burst ≤ {}/m (owner: /limits).</i>",
                esc(reason),
                lim.max_tool_steps,
                lim.tool_repeat_limit,
                lim.max_tools_per_min,
            ));
        }
        if res.timed_out {
            let lim = self.runtime_limits();
            notes.push(format!(
                "⌛ <i>Time limit ({} min) reached — partial output.</i>",
                lim.job_timeout_secs / 60
            ));
        }
        if !res.denied_actions.is_empty() {
            notes.push(format!(
                "🚫 <i>{} action(s) denied by permissions (Settings).</i>",
                res.denied_actions.len()
            ));
        }
        if let Some(ref err) = res.error {
            notes.push(error_html_for(err, prem, engine_label));
        }
        if text.is_empty() && notes.is_empty() {
            let lang = crate::i18n::lang_for(&self.acl, &self.store, req.uid);
            text = format!("_{}_", crate::i18n::t(lang, crate::i18n::Tx::EmptyReplyNotice));
        }

        let sink = self.get_widget_sink();
        if !text.is_empty() {
            if let Some(ref s) = sink {
                if let Ok(cleaned) = s.extract_markdown_widgets(chat, &text).await {
                    text = cleaned;
                }
            }
            if !text.trim().is_empty() {
                let use_rich = user_state.render == "rich";
                self.render
                    .send_markdown(chat, &text, Some(self.answer_kb_for(req.uid)), use_rich, true)
                    .await?;
            }
        }

        if !notes.is_empty() {
            let mk = if !res.denied_actions.is_empty() {
                Some(self.build_retry_markup(req.uid))
            } else {
                None
            };
            self.render
                .send_html_simple(chat, &notes.join("\n"), mk)
                .await?;
        }

        if user_state.trace && res.steps > 0 {
            let trace = trace_html(progress, res);
            let _ = self
                .render
                .send_html(chat, &trace, None, None, Some(true), true)
                .await;
        }

        let skip_paths = match sink {
            Some(ref s) if outdir.is_dir() => s.deliver_outbox_widgets(chat, outdir).await,
            _ => HashSet::new(),
        };

        let mut extra_secrets: Vec<String> = Vec::new();
        if !self.cfg.bot_token.is_empty() {
            extra_secrets.push(self.cfg.bot_token.clone());
        }
        if !self.cfg.venice_api_key.is_empty() {
            extra_secrets.push(self.cfg.venice_api_key.clone());
        }
        if let Some(ref ws) = self.cfg.webhook_secret {
            if !ws.is_empty() {
                extra_secrets.push(ws.clone());
            }
        }
        if let Some(reg) = self.proxies() {
            extra_secrets.extend(reg.secret_literals());
        }

        let report = self
            .render
            .deliver_outbox_files_guarded(
                chat,
                outdir,
                10,
                MAX_UPLOAD_BYTES,
                &skip_paths,
                self.runtime_limits().outbox_secret_scan,
                &extra_secrets,
            )
            .await?;
        if !report.blocked_secrets.is_empty() {
            warn!(
                uid = req.uid,
                blocked = report.blocked_secrets.len(),
                "outbox secret scanner blocked one or more files"
            );
        }
        if !report.delivered.is_empty() {
            info!(
                uid = req.uid,
                count = report.delivered.len(),
                "delivered outbox files"
            );
        }

        // Remove empty per-request outdir cleanly
        if outdir.exists() {
            let _ = std::fs::remove_dir(outdir);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agy_core::acl::AclStore;
    use agy_core::outbox::OutQueue;
    use agy_core::tg::{Chat, Message, User};
    use agy_ext::engines::AgyProcessJob;
    use agy_net::NetConfig;
    use axum::extract::{Path as AxumPath, Request, State};
    use axum::http::StatusCode;
    use axum::response::{IntoResponse, Response};
    use axum::routing::post;
    use axum::{Json, Router};
    use serde_json::json;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;
    use tokio::net::TcpListener;
    use tokio::sync::Mutex as TokioMutex;

    const OWNER: i64 = 1_000_000_001;
    const STD_USER: i64 = 10_001;

    #[derive(Clone, Default)]
    struct MockApi {
        calls: Arc<TokioMutex<Vec<(String, Value)>>>,
        multipart_methods: Arc<TokioMutex<Vec<String>>>,
    }

    fn sample_msg(id: i64) -> Message {
        Message {
            message_id: id,
            from_user: Some(User {
                id: 42,
                is_bot: true,
                first_name: "Bot".into(),
                last_name: None,
                username: None,
                language_code: None,
                is_premium: Some(false),
            }),
            chat: Chat {
                id: 100,
                kind: "private".into(),
                username: None,
                first_name: None,
            },
            message_thread_id: None,
            text: Some("ok".into()),
            caption: None,
            entities: None,
            effect_id: None,
            reply_to_message: None,
            photo: None,
            document: None,
            video: None,
            audio: None,
            voice: None,
            animation: None,
            video_note: None,
            sticker: None,
            widget: None,
            business_connection_id: None,
            sender_business_bot: None,
        }
    }

    async fn mock_handler(
        State(st): State<MockApi>,
        AxumPath((_tok, method)): AxumPath<(String, String)>,
        req: Request,
    ) -> Response {
        let is_mp = req
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|ct| ct.starts_with("multipart/form-data"));

        if is_mp {
            let _ = axum::body::to_bytes(req.into_body(), 10 * 1024 * 1024).await;
            st.multipart_methods.lock().await.push(method.clone());
            return (
                StatusCode::OK,
                Json(json!({ "ok": true, "result": sample_msg(88) })),
            )
                .into_response();
        }

        let bytes = axum::body::to_bytes(req.into_body(), 2 * 1024 * 1024)
            .await
            .unwrap_or_default();
        let val: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        st.calls.lock().await.push((method.clone(), val));

        match method.as_str() {
            "sendRichMessage" | "sendMessage" => (
                StatusCode::OK,
                Json(json!({ "ok": true, "result": sample_msg(77) })),
            )
                .into_response(),
            _ => (StatusCode::OK, Json(json!({ "ok": true, "result": true }))).into_response(),
        }
    }

    struct ScriptedRunner {
        script_path: PathBuf,
        kind: ExtEngineKind,
    }

    impl EngineRunner for ScriptedRunner {
        fn kind(&self) -> &ExtEngineKind {
            &self.kind
        }
        fn build_args(&self, req: &EngineRequest) -> Vec<String> {
            vec![self.script_path.to_string_lossy().to_string(), req.prompt.clone()]
        }
        fn create_job(
            &self,
            req: &EngineRequest,
            on_progress: Option<ProgressCallback>,
        ) -> Arc<AgyProcessJob> {
            Arc::new(AgyProcessJob::new(
                self.build_args(req),
                req.cwd.clone(),
                on_progress,
            ))
        }
        fn run(
            &self,
            req: EngineRequest,
            on_progress: Option<ProgressCallback>,
        ) -> agy_ext::engines::BoxFuture<'static, Result<JobResult>> {
            let j = self.create_job(&req, on_progress);
            Box::pin(async move { j.run().await })
        }
    }

    async fn setup_test_env(dir: &TempDir) -> (MockApi, Arc<Config>, Arc<AclStore>, Arc<StateStore>, Arc<RenderBridge>, Arc<BotApiClient>) {
        let st = MockApi::default();
        let app = Router::new()
            .route("/bot{token}/{method}", post(mock_handler))
            .with_state(st.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let ws = dir.path().join("ws");
        let state_dir = dir.path().join("state");
        std::fs::create_dir_all(&ws).unwrap();
        std::fs::create_dir_all(&state_dir).unwrap();

        let cfg = Arc::new(Config {
            bot_token: "123:TOK".into(),
            state_dir: state_dir.clone(),
            agy_workspace: ws,
            owner_id: OWNER,
            allowed_user_ids: vec![STD_USER],
            stream_interval: 1.0,
            ..Default::default()
        });
        let acl = Arc::new(AclStore::open(cfg.acl_path(), OWNER, &[STD_USER], 300).unwrap());
        let store = Arc::new(StateStore::open(cfg.state_path()).unwrap());
        let client = Arc::new(
            BotApiClient::new(
                "123:TOK",
                NetConfig::default().with_api_base(format!("http://{addr}")),
            )
            .unwrap(),
        );
        let premium = Arc::new(PremiumState::new(false));
        let outq = Arc::new(OutQueue::open(cfg.outbox_path()).unwrap());
        let render = Arc::new(RenderBridge::new(Arc::clone(&client), premium, outq).with_retry_config(1, 0.01));
        (st, cfg, acl, store, render, client)
    }

    #[test]
    fn awaiting_input_ttl_safe_partial_md_and_security_boundary() {
        let inp = AwaitingInput::new_at("mcp_ejson", json!({"name": "s1"}), 1000.0);
        assert!(!inp.is_expired(1900.0));
        assert!(inp.is_expired(1900.1));

        let md = format!("intro\n```python\n{}", "x = 1\n".repeat(5000));
        let out = safe_partial_md(&md, 24_000, 380);
        assert!(utf16_len(&out) <= 24_100);
        assert!(out.split('\n').count() <= 400);
        assert_eq!(
            out.split('\n').filter(|l| l.trim_start().starts_with("```")).count() % 2,
            0
        );
        assert!(safe_partial_md("<details><summary>a</summary>\nb", 24_000, 380).ends_with("</details>"));
    }

    #[tokio::test]
    async fn security_boundary_enforced_for_non_root_and_retry_buttons() {
        let dir = TempDir::new().unwrap();
        let (_st, cfg, acl, store, render, client) = setup_test_env(&dir).await;
        let outside_dir = dir.path().join("outside");
        let inside_dir = cfg.agy_workspace.join("sub");
        let sibling_evil = dir.path().join("ws_evil");
        std::fs::create_dir_all(&outside_dir).unwrap();
        std::fs::create_dir_all(&inside_dir).unwrap();
        std::fs::create_dir_all(&sibling_evil).unwrap();

        // Set non-root user cwd outside workspace and skip_permissions = true
        store
            .update_user(STD_USER, |u| {
                u.cwd = Some(outside_dir.to_string_lossy().to_string());
                u.skip_permissions = true;
            })
            .unwrap();

        let mgr = JobManager::new(
            Arc::clone(&cfg),
            Arc::clone(&acl),
            Arc::clone(&store),
            Arc::clone(&render),
            Arc::clone(&client),
        )
        .unwrap();

        let req = JobRequest::new(STD_USER, STD_USER, "@std", "hello", vec![]);
        let outdir = cfg.outbox_dir().join("10001/1");
        let eng_req = mgr.build_engine_request(&req, &outdir);

        assert!(!eng_req.skip_permissions);
        assert_eq!(
            eng_req.cwd.unwrap(),
            std::fs::canonicalize(&cfg.agy_workspace).unwrap()
        );
        assert!(eng_req.prompt.contains(&format!(
            "Security boundary: Restrict all file reads/writes and commands strictly to workspace {}",
            cfg.agy_workspace.display()
        )));

        // Sibling prefix path `/.../ws_evil` MUST also be clamped!
        assert_eq!(
            resolve_safe_cwd(Some(sibling_evil.to_str().unwrap()), &cfg.agy_workspace, false),
            std::fs::canonicalize(&cfg.agy_workspace).unwrap()
        );
        // Subdirectory inside workspace is allowed
        assert_eq!(
            resolve_safe_cwd(Some(inside_dir.to_str().unwrap()), &cfg.agy_workspace, false),
            std::fs::canonicalize(&inside_dir).unwrap()
        );

        // Retry buttons omit retry:all for non-root, include for owner
        let mk_std = mgr.build_retry_markup(STD_USER);
        assert_eq!(mk_std.inline_keyboard[0].len(), 1);
        assert_eq!(mk_std.inline_keyboard[0][0].callback_data.as_deref(), Some("retry:edits"));

        let mk_owner = mgr.build_retry_markup(OWNER);
        assert_eq!(mk_owner.inline_keyboard[0].len(), 2);
        assert_eq!(mk_owner.inline_keyboard[0][1].callback_data.as_deref(), Some("retry:all"));

        // Owner keeps skip_permissions & outside cwd
        store
            .update_user(OWNER, |u| {
                u.cwd = Some(outside_dir.to_string_lossy().to_string());
                u.skip_permissions = true;
            })
            .unwrap();
        let owner_req = JobRequest::new(OWNER, OWNER, "@owner", "hello", vec![]);
        let owner_eng = mgr.build_engine_request(&owner_req, &outdir);
        assert!(owner_eng.skip_permissions);
        assert_eq!(owner_eng.cwd.unwrap(), outside_dir);
        assert!(!owner_eng.prompt.contains("Security boundary: Restrict"));
    }

    #[tokio::test]
    async fn serialized_per_user_queue_streaming_session_and_outbox_delivery() {
        let dir = TempDir::new().unwrap();
        let (st, cfg, acl, store, render, client) = setup_test_env(&dir).await;

        store
            .update_user(OWNER, |u| {
                u.stream_mode = "live".to_string();
                u.stream = true;
                u.trace = true;
            })
            .unwrap();

        let script = dir.path().join("mock_agy.sh");
        let log_file = dir.path().join("exec.log");
        let script_body = format!(
            "#!/bin/sh\np_one=$(printf '%s' \"$1\" | tr '\\n' ' ')\nprintf 'start:%s\\n' \"$p_one\" >> {log}\nprintf '{{\"type\":\"init\",\"conversation_id\":\"conv-live-1\"}}\\n'\nprintf '{{\"type\":\"step_update\",\"step_type\":\"tool_use\",\"tool_name\":\"read_file\"}}\\n'\nprintf '{{\"type\":\"step_update\",\"step_type\":\"agent_response\",\"delta\":\"Hello streaming \"}}\\n'\nprintf '{{\"type\":\"step_update\",\"step_type\":\"agent_response\",\"delta\":\"world!\"}}\\n'\nsleep 0.08\nprintf '{{\"type\":\"result\",\"conversation_id\":\"conv-live-1\",\"result\":\"Final **Markdown** answer\",\"usage\":{{\"input_tokens\":10,\"output_tokens\":5}}}}\\n'\nprintf 'end:%s\\n' \"$p_one\" >> {log}\n",
            log = log_file.display()
        );
        std::fs::write(&script, script_body).unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();

        let runner = Arc::new(ScriptedRunner {
            script_path: script,
            kind: ExtEngineKind::Agy,
        });
        let mgr = Arc::new(JobManager::with_runner(
            Arc::clone(&cfg),
            acl,
            Arc::clone(&store),
            render,
            client,
            runner,
        ));

        let r1 = JobRequest::new(OWNER, OWNER, "@owner", "first task", vec![]);
        // Pre-seed an output file in r1's outbox directory to test automatic delivery
        let outdir1 = cfg.outbox_dir().join(OWNER.to_string()).join(r1.req_id.to_string());
        std::fs::create_dir_all(&outdir1).unwrap();
        std::fs::write(outdir1.join("report.txt"), b"report body").unwrap();

        let r2 = JobRequest::new(OWNER, OWNER, "@owner", "second task", vec![]);

        let out1 = mgr.enqueue(r1).await.unwrap();
        let out2 = mgr.enqueue(r2).await.unwrap();
        assert_eq!(out1, EnqueueOutcome::StartedImmediately);
        assert_eq!(out2, EnqueueOutcome::Queued(1));

        // Wait until both serialized jobs finish
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if !mgr.is_busy() && std::fs::read_to_string(&log_file).unwrap_or_default().lines().count() >= 4 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();

        let log_lines: Vec<String> = std::fs::read_to_string(&log_file)
            .unwrap()
            .lines()
            .map(ToString::to_string)
            .collect();
        // Serialized execution: start1 -> end1 -> start2 -> end2
        assert!(log_lines[0].starts_with("start:"));
        assert!(log_lines[1].starts_with("end:"));
        assert!(log_lines[2].starts_with("start:"));
        assert!(log_lines[3].starts_with("end:"));

        let u = store.get_user(OWNER);
        assert_eq!(u.conversation_id.as_deref(), Some("conv-live-1"));
        assert_eq!(u.history.len(), 1);
        assert_eq!(mgr.last_prompt(OWNER).unwrap().0, "second task");

        let mps = st.multipart_methods.lock().await.clone();
        assert!(mps.contains(&"sendDocument".to_string()));
        let calls = st.calls.lock().await;
        assert!(calls.iter().any(|(m, _)| m == "sendRichMessage"));
        assert!(calls.iter().any(|(m, _)| m == "deleteMessage"));
    }

    #[tokio::test]
    async fn stop_user_cancels_running_process_group() {
        let dir = TempDir::new().unwrap();
        let (_st, cfg, acl, store, render, client) = setup_test_env(&dir).await;

        let script = dir.path().join("slow_agy.sh");
        std::fs::write(
            &script,
            "#!/bin/sh\ntrap 'exit 0' INT TERM\nsleep 30\n",
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();

        let runner = Arc::new(ScriptedRunner {
            script_path: script,
            kind: ExtEngineKind::Agy,
        });
        let mgr = Arc::new(JobManager::with_runner(
            Arc::clone(&cfg),
            acl,
            store,
            render,
            client,
            runner,
        ));

        let r = JobRequest::new(OWNER, OWNER, "@owner", "sleep", vec![]);
        mgr.enqueue(r).await.unwrap();

        tokio::time::timeout(Duration::from_secs(2), async {
            while !mgr.is_user_busy(OWNER) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();

        // Wait slightly so child pgid is registered
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert!(mgr.stop_user(OWNER).await);

        tokio::time::timeout(Duration::from_secs(5), async {
            while mgr.is_user_busy(OWNER) {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(mgr.active_count(), 0);
    }
    fn write_token(home: &Path, email: &str) {
        let d = home.join(".gemini/antigravity-cli");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(
            d.join("antigravity-oauth-token"),
            format!("{{\"token\":{{\"refresh_token\":\"r\"}},\"id_token_email\":\"{email}\"}}"),
        )
        .unwrap();
    }

    fn set_behavior(home: &Path, b: &str) {
        let d = home.join(".gemini/antigravity-cli/cache");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("behavior"), b).unwrap();
    }

    async fn wait_idle(mgr: &Arc<JobManager>, log: &Path, lines: usize) {
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                let n = std::fs::read_to_string(log).unwrap_or_default().lines().count();
                if !mgr.is_busy() && n >= lines {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(30)).await;
            }
        })
        .await
        .expect("job did not finish");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    /// End-to-end failover with a FAKE `agy` (no network, no real accounts):
    /// quota -> cooldown + resume on next account; ban -> disable + owner alert + resume;
    /// missing conversation -> replay context pack; pool exhausted -> clear message.
    #[tokio::test]
    async fn multi_account_failover_and_session_continuity_with_fake_agy() {
        let dir = TempDir::new().unwrap();
        let (st, cfg0, acl, store, render, client) = setup_test_env(&dir).await;
        let primary = dir.path().join("rootb");
        std::fs::create_dir_all(primary.join(".gemini/antigravity-cli/conversations")).unwrap();
        std::fs::create_dir_all(primary.join(".gemini/config")).unwrap();
        write_token(&primary, "p@x.io");
        set_behavior(&primary, "ok");
        let log = dir.path().join("agy-calls.log");
        let fake = dir.path().join("fake-agy");
        std::fs::write(
            &fake,
            format!(
                r#"#!/bin/bash
conv=""; prompt=""
while [ $# -gt 0 ]; do
  case "$1" in
    --conversation) conv="$2"; shift 2;;
    -p) prompt="$2"; shift 2;;
    *) shift;;
  esac
done
C="$HOME/.gemini/antigravity-cli"
tok="$C/antigravity-oauth-token"
email=$(sed -n 's/.*"id_token_email":"\([^"]*\)".*/\1/p' "$tok" 2>/dev/null)
beh=$(cat "$C/cache/behavior" 2>/dev/null)
pack=no; case "$prompt" in *"[session-handoff]"*) pack=yes;; esac
fo=no; case "$prompt" in *"[failover]"*) fo=yes;; esac
echo "acct=$email conv=$conv beh=$beh pack=$pack failover=$fo" >> {log}
if [ ! -s "$tok" ]; then echo '{{"event":"result","result":{{"status":"ERROR","response":"","error":"authentication failed or timed out"}}}}'; exit 1; fi
case "$beh" in
  quota) echo '{{"type":"result","is_error":true,"error":"RESOURCE_EXHAUSTED (code 429): Individual quota reached. Resets in 2h."}}'; exit 1;;
  ban) echo 'Error: Permission denied (code 403): This service has been disabled in this account for violation of Terms of Service.' >&2; exit 1;;
esac
if [ "$beh" = "noresume" ]; then conv=""; fi
if [ -n "$conv" ] && [ -f "$C/conversations/$conv.db" ]; then cid="$conv"; else cid="conv-$RANDOM$RANDOM"; touch "$C/conversations/$cid.db"; fi
echo "{{\"type\":\"init\",\"conversation_id\":\"$cid\"}}"
echo "{{\"type\":\"result\",\"conversation_id\":\"$cid\",\"result\":\"answered-by $email\"}}"
"#,
                log = log.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();

        let cfg = Arc::new(Config {
            agy_bin: fake.clone(),
            agy_job_timeout: 0,
            ..(*cfg0).clone()
        });
        let pool = Arc::new(
            AccountStore::open(
                cfg.state_dir.join("accounts.json"),
                cfg.state_dir.join("accounts"),
                &primary,
            )
            .unwrap(),
        );
        let a1 = pool.add_slot("backup").unwrap();
        write_token(&a1.home, "a1@x.io");
        assert!(matches!(pool.finish_login(&a1.id).unwrap(), agy_core::accounts::TokenState::Present { .. }));
        set_behavior(&a1.home, "ok");

        let mgr = Arc::new(
            JobManager::new(Arc::clone(&cfg), acl, Arc::clone(&store), render, client).unwrap(),
        );
        mgr.set_accounts(Arc::clone(&pool));

        // 1) normal run on primary creates conversation in the shared store
        mgr.enqueue(JobRequest::new(OWNER, OWNER, "@o", "task one", vec![])).await.unwrap();
        wait_idle(&mgr, &log, 1).await;
        let c1 = store.get_user(OWNER).conversation_id.clone().expect("conversation saved");
        assert!(pool.conversation_exists(&c1));

        // 2) primary hits quota -> cooldown; acc1 resumes the SAME conversation
        set_behavior(&primary, "quota");
        mgr.enqueue(JobRequest::new(OWNER, OWNER, "@o", "task two", vec![])).await.unwrap();
        wait_idle(&mgr, &log, 3).await;
        let lines: Vec<String> = std::fs::read_to_string(&log).unwrap().lines().map(String::from).collect();
        assert!(lines[1].starts_with("acct=p@x.io") && lines[1].contains(&format!("conv={c1}")), "{lines:?}");
        assert!(lines[2].starts_with("acct=a1@x.io") && lines[2].contains(&format!("conv={c1}")) && lines[2].contains("pack=no"), "{lines:?}");
        assert_eq!(store.get_user(OWNER).conversation_id.as_deref(), Some(c1.as_str()));
        let p = pool.get("primary").unwrap();
        assert_eq!(p.health.status, HealthStatus::Cooldown);
        let left = p.health.until_ts.unwrap() - chrono::Utc::now().timestamp();
        assert!((7000..=7300).contains(&left), "parsed 2h reset, got {left}");
        {
            let calls = st.calls.lock().await;
            assert!(calls.iter().any(|(m, v)| m == "sendMessage" && v["text"].as_str().unwrap_or("").contains("Switching account")));
        }

        // 3) acc1 (sticky) gets banned -> disabled + owner alert -> primary (reset) resumes
        set_behavior(&a1.home, "ban");
        set_behavior(&primary, "ok");
        pool.reset_health("primary").unwrap();
        mgr.enqueue(JobRequest::new(OWNER, OWNER, "@o", "task three", vec![])).await.unwrap();
        wait_idle(&mgr, &log, 5).await;
        let lines: Vec<String> = std::fs::read_to_string(&log).unwrap().lines().map(String::from).collect();
        assert!(lines[3].starts_with("acct=a1@x.io"), "sticky account first: {lines:?}");
        assert!(lines[4].starts_with("acct=p@x.io") && lines[4].contains(&format!("conv={c1}")), "{lines:?}");
        assert_eq!(pool.get(&a1.id).unwrap().health.status, HealthStatus::Disabled);
        {
            let calls = st.calls.lock().await;
            assert!(calls.iter().any(|(m, v)| m == "sendMessage" && v["chat_id"] == json!(OWNER) && v["text"].as_str().unwrap_or("").contains("Account disabled")));
        }

        // 4) conversation file lost -> replay context pack in a new conversation
        std::fs::remove_file(pool.shared_conversations_dir().join(format!("{c1}.db"))).unwrap();
        mgr.enqueue(JobRequest::new(OWNER, OWNER, "@o", "task four", vec![])).await.unwrap();
        wait_idle(&mgr, &log, 6).await;
        let lines: Vec<String> = std::fs::read_to_string(&log).unwrap().lines().map(String::from).collect();
        assert!(lines[5].contains("conv= ") && lines[5].contains("pack=yes"), "{lines:?}");
        let tr = std::fs::read_to_string(handoff::transcript_path(&cfg.state_dir, OWNER)).unwrap();
        assert!(tr.lines().count() >= 4);

        // 4b) agy silently ignores --conversation (returns another id) -> redo with Replay pack
        let c2 = store.get_user(OWNER).conversation_id.clone().expect("conv after replay");
        assert_ne!(c2, c1);
        set_behavior(&primary, "noresume");
        mgr.enqueue(JobRequest::new(OWNER, OWNER, "@o", "task 4b", vec![])).await.unwrap();
        wait_idle(&mgr, &log, 8).await;
        let lines: Vec<String> = std::fs::read_to_string(&log).unwrap().lines().map(String::from).collect();
        assert!(lines[6].contains(&format!("conv={c2}")) && lines[6].contains("pack=no"), "{lines:?}");
        assert!(lines[7].contains("conv= ") && lines[7].contains("pack=yes"), "mismatch must fall back to replay: {lines:?}");
        assert_eq!(lines.len(), 8);
        set_behavior(&primary, "ok");

        // 5) everything down -> explicit "no account" message, agy not invoked
        set_behavior(&primary, "quota");
        mgr.enqueue(JobRequest::new(OWNER, OWNER, "@o", "task five", vec![])).await.unwrap();
        wait_idle(&mgr, &log, 9).await;
        mgr.enqueue(JobRequest::new(OWNER, OWNER, "@o", "task six", vec![])).await.unwrap();
        tokio::time::sleep(Duration::from_millis(800)).await;
        let n = std::fs::read_to_string(&log).unwrap().lines().count();
        assert_eq!(n, 9, "no agy call when pool exhausted");
        let calls = st.calls.lock().await;
        assert!(calls.iter().any(|(_, v)| v["text"].as_str().unwrap_or("").contains("No Antigravity account is available")));
    }

    #[tokio::test]
    async fn failover_pauses_for_model_choice_with_fake_agy() {
        let dir = TempDir::new().unwrap();
        let (st, cfg0, acl, store, render, client) = setup_test_env(&dir).await;
        let primary = dir.path().join("rootm");
        std::fs::create_dir_all(primary.join(".gemini/antigravity-cli/conversations")).unwrap();
        std::fs::create_dir_all(primary.join(".gemini/config")).unwrap();
        write_token(&primary, "p@x.io");
        set_behavior(&primary, "ok");
        let log = dir.path().join("agy-calls.log");
        let fake = dir.path().join("fake-agy");
        std::fs::write(
            &fake,
            format!(
                r#"#!/bin/bash
if [ "$1" = models ]; then cat "$HOME/.gemini/antigravity-cli/cache/models.json"; exit 0; fi
conv=""; model=""
while [ $# -gt 0 ]; do
  case "$1" in
    --conversation) conv="$2"; shift 2;;
    --model) model="$2"; shift 2;;
    *) shift;;
  esac
done
C="$HOME/.gemini/antigravity-cli"
email=$(sed -n 's/.*"id_token_email":"\([^"]*\)".*/\1/p' "$C/antigravity-oauth-token" 2>/dev/null)
beh=$(cat "$C/cache/behavior" 2>/dev/null)
echo "acct=$email conv=$conv model=$model" >> {log}
if [ "$beh" = "quota" ]; then echo '{{"type":"result","is_error":true,"error":"RESOURCE_EXHAUSTED (code 429): quota. Resets in 2h."}}'; exit 1; fi
rej=$(cat "$C/cache/reject" 2>/dev/null)
if [ -n "$rej" ] && [ "$model" = "$rej" ]; then echo "Error: Invalid model \"$model\" (valid choices: m-other, m-new)" >&2; exit 1; fi
if [ -n "$conv" ] && [ -f "$C/conversations/$conv.db" ]; then cid="$conv"; else cid="conv-$RANDOM$RANDOM"; touch "$C/conversations/$cid.db"; fi
echo "{{\"type\":\"result\",\"conversation_id\":\"$cid\",\"result\":\"ok $email $model\"}}"
"#,
                log = log.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        let cfg = Arc::new(Config { agy_bin: fake.clone(), agy_job_timeout: 0, ..(*cfg0).clone() });
        let pool = Arc::new(
            AccountStore::open(cfg.state_dir.join("accounts.json"), cfg.state_dir.join("accounts"), &primary).unwrap(),
        );
        let a1 = pool.add_slot("backup").unwrap();
        write_token(&a1.home, "a1@x.io");
        pool.finish_login(&a1.id).unwrap();
        set_behavior(&a1.home, "ok");
        // per-account model lists (fresh, so no `agy models` call is needed)
        let ml = |ids: &[&str]| {
            serde_json::to_string(&ids.iter().map(|i| json!({"id": i, "name": format!("Name {i}")})).collect::<Vec<_>>()).unwrap()
        };
        let pp = crate::models_pool::models_path(&cfg.state_dir, "primary");
        std::fs::create_dir_all(pp.parent().unwrap()).unwrap();
        std::fs::write(&pp, ml(&["m-pro", "m-flash", "m-pro2", "m-pro3"])).unwrap();
        let ap = crate::models_pool::models_path(&cfg.state_dir, &a1.id);
        std::fs::create_dir_all(ap.parent().unwrap()).unwrap();
        std::fs::write(&ap, ml(&["m-flash", "m-other"])).unwrap();
        store.update_user(OWNER, |u| u.model = Some("m-pro".into())).unwrap();

        let mgr = Arc::new(JobManager::new(Arc::clone(&cfg), acl, Arc::clone(&store), render, client).unwrap());
        mgr.set_accounts(Arc::clone(&pool));
        let lines = || -> Vec<String> { std::fs::read_to_string(&log).unwrap_or_default().lines().map(String::from).collect() };
        let wait_pause = |mgr: Arc<JobManager>| async move {
            tokio::time::timeout(Duration::from_secs(10), async {
                while !mgr.is_waiting_model(OWNER) {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
            .await
            .expect("job never paused for model choice");
        };
        // nonce of the pending pause, once its picker message reached Telegram
        let pick_nonce = |st: &MockApi, mgr: &Arc<JobManager>| {
            let st = st.clone();
            let nonce = mgr.model_waits.get(&OWNER).map(|w| w.nonce.clone()).expect("pause pending");
            async move {
                for _ in 0..200 {
                    let sent = st.calls.lock().await.iter().any(|(_, v)| {
                        let v = v.to_string();
                        v.contains("Choose a model") && v.contains(&format!("mpk:{nonce}:"))
                    });
                    if sent {
                        return nonce;
                    }
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
                panic!("model picker message not sent");
            }
        };

        // 1) primary works with m-pro, conversation created
        mgr.enqueue(JobRequest::new(OWNER, OWNER, "@o", "one", vec![])).await.unwrap();
        wait_idle(&mgr, &log, 1).await;
        let c1 = store.get_user(OWNER).conversation_id.clone().unwrap();
        assert!(lines()[0].contains("acct=p@x.io") && lines()[0].contains("model=m-pro"));

        // 2) primary quota -> a1 lacks m-pro -> PAUSE (no agy call on a1) -> user picks m-other -> same conversation
        set_behavior(&primary, "quota");
        mgr.enqueue(JobRequest::new(OWNER, OWNER, "@o", "two", vec![])).await.unwrap();
        wait_pause(Arc::clone(&mgr)).await;
        assert_eq!(lines().len(), 2, "a1 must not run before the user picks: {:?}", lines());
        let nonce = pick_nonce(&st, &mgr).await;
        {
            let calls = st.calls.lock().await;
            let v = calls.iter().rev().find(|(_, v)| v.to_string().contains("Choose a model")).unwrap().1.to_string();
            assert!(v.contains("Name m-flash") && v.contains("Name m-other") && v.contains(&format!("mpk:{nonce}:x")), "{v}");
            assert!(!v.contains("Name m-pro\""), "only the target account's models: {v}");
        }
        assert_eq!(mgr.resolve_model_pick(OWNER, "stale", "m-other"), None);
        assert_eq!(mgr.resolve_model_pick(OWNER, &nonce, "m-pro"), None, "ids not on this account are refused");
        assert_eq!(mgr.resolve_model_pick(OWNER, &nonce, "m-other"), Some("Model selected"));
        wait_idle(&mgr, &log, 3).await;
        let l = lines();
        assert!(l[2].contains("acct=a1@x.io") && l[2].contains(&format!("conv={c1}")) && l[2].contains("model=m-other"), "{l:?}");
        assert_eq!(store.get_user(OWNER).model.as_deref(), Some("m-pro"), "user's own choice is untouched");

        // 3) next message stays on a1 with the remembered choice, no second question
        let asked = st.calls.lock().await.iter().filter(|(_, v)| v.to_string().contains("Choose a model")).count();
        mgr.enqueue(JobRequest::new(OWNER, OWNER, "@o", "three", vec![])).await.unwrap();
        wait_idle(&mgr, &log, 4).await;
        assert!(lines()[3].contains("acct=a1@x.io") && lines()[3].contains("model=m-other"), "{:?}", lines());
        assert_eq!(st.calls.lock().await.iter().filter(|(_, v)| v.to_string().contains("Choose a model")).count(), asked);

        // 4) Cancel button -> task dropped, no agy call, session kept
        store.update_user(OWNER, |u| u.model = Some("m-pro2".into())).unwrap();
        mgr.enqueue(JobRequest::new(OWNER, OWNER, "@o", "four", vec![])).await.unwrap();
        wait_pause(Arc::clone(&mgr)).await;
        let nonce = pick_nonce(&st, &mgr).await;
        assert_eq!(mgr.resolve_model_pick(OWNER, &nonce, "x"), Some("Cancelled"));
        tokio::time::timeout(Duration::from_secs(10), async { while mgr.is_busy() { tokio::time::sleep(Duration::from_millis(30)).await; } }).await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(lines().len(), 4);
        assert_eq!(store.get_user(OWNER).conversation_id.as_deref(), Some(c1.as_str()));
        assert!(st.calls.lock().await.iter().any(|(_, v)| v.to_string().contains("Task cancelled")));

        // 5) no answer -> timeout -> task dropped, no agy call
        mgr.set_model_pick_timeout(1);
        store.update_user(OWNER, |u| u.model = Some("m-pro3".into())).unwrap();
        mgr.enqueue(JobRequest::new(OWNER, OWNER, "@o", "five", vec![])).await.unwrap();
        wait_pause(Arc::clone(&mgr)).await;
        tokio::time::timeout(Duration::from_secs(10), async { while mgr.is_busy() { tokio::time::sleep(Duration::from_millis(30)).await; } }).await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(lines().len(), 4);
        assert!(!mgr.is_waiting_model(OWNER));
        assert!(st.calls.lock().await.iter().any(|(_, v)| v.to_string().contains("No model chosen in time")));

        // 6) agy itself rejects a listed model on a1 -> list refreshed (`agy models`, list-only),
        //    user asked even though the id was listed, picks m-new -> SAME conversation, no cooldown
        mgr.set_model_pick_timeout(600);
        store.update_user(OWNER, |u| u.model = Some("m-flash".into())).unwrap();
        std::fs::write(a1.home.join(".gemini/antigravity-cli/cache/reject"), "m-flash").unwrap();
        std::fs::write(a1.home.join(".gemini/antigravity-cli/cache/models.json"), ml(&["m-flash", "m-other", "m-new"])).unwrap();
        mgr.enqueue(JobRequest::new(OWNER, OWNER, "@o", "six", vec![])).await.unwrap();
        wait_pause(Arc::clone(&mgr)).await;
        assert!(lines()[4].contains("acct=a1@x.io") && lines()[4].contains("model=m-flash"), "{:?}", lines());
        assert_eq!(crate::models_pool::load(&cfg.state_dir, &a1.id).len(), 3, "a1 list refreshed after the rejection");
        let nonce = pick_nonce(&st, &mgr).await;
        assert_eq!(mgr.resolve_model_pick(OWNER, &nonce, "m-new"), Some("Model selected"));
        wait_idle(&mgr, &log, 6).await;
        let l = lines();
        assert!(l[5].contains("acct=a1@x.io") && l[5].contains("model=m-new") && l[5].contains(&format!("conv={c1}")), "{l:?}");
        assert_eq!(pool.get(&a1.id).unwrap().health.status, HealthStatus::Ok, "a model problem never cools an account down");
        assert_eq!(store.get_user(OWNER).conversation_id.as_deref(), Some(c1.as_str()));
    }

    #[tokio::test]
    async fn parallel_mode_plan_fanout_failover_merge_stop_and_ram_guard_with_fake_agy() {
        let dir = TempDir::new().unwrap();
        let (st, cfg0, acl, store, render, client) = setup_test_env(&dir).await;
        let primary = dir.path().join("rootp");
        std::fs::create_dir_all(primary.join(".gemini/antigravity-cli/conversations")).unwrap();
        std::fs::create_dir_all(primary.join(".gemini/config")).unwrap();
        write_token(&primary, "p@x.io");
        set_behavior(&primary, "ok");
        let log = dir.path().join("agy-calls.log");
        let conc = dir.path().join("conc.log");
        let act = dir.path().join("active");
        std::fs::create_dir_all(&act).unwrap();
        let slp = dir.path().join("sleep");
        std::fs::write(&slp, "0.6").unwrap();
        let plan = json!({"parallel": true, "reason": "independent", "merge_instructions": "combine",
            "subtasks": [
                {"id": "1", "title": "alpha", "brief": "do a", "owns": ["a/"]},
                {"id": "2", "title": "beta", "brief": "do b", "owns": ["b/"]},
                {"id": "3", "title": "gamma", "brief": "do c", "readonly": true}
            ]});
        let plan_line = json!({"type": "result", "conversation_id": "CID", "result": plan.to_string()}).to_string();
        let plan_file = dir.path().join("plan.line");
        std::fs::write(&plan_file, plan_line).unwrap();
        let fake = dir.path().join("fake-agy");
        let script = r#"#!/bin/bash
conv=""; prompt=""
while [ $# -gt 0 ]; do
  case "$1" in
    --conversation) conv="$2"; shift 2;;
    -p) prompt="$2"; shift 2;;
    *) shift;;
  esac
done
C="$HOME/.gemini/antigravity-cli"
email=$(sed -n 's/.*"id_token_email":"\([^"]*\)".*/\1/p' "$C/antigravity-oauth-token" 2>/dev/null)
beh=$(cat "$C/cache/behavior" 2>/dev/null)
mode=plain
case "$prompt" in *"[parallel-plan"*) mode=plan;; *"[parallel-worker"*) mode=worker;; *"[parallel-merge"*) mode=merge;; esac
case "$prompt" in *"/swarm"*"NEVER"*|*"NEVER start /swarm"*) noswarm=yes;; *) noswarm=no;; esac
k=$(printf '%s' "$prompt" | sed -n 's/.*\[parallel-worker \([0-9]*\)\/.*/\1/p' | head -1)
echo "acct=$email mode=$mode k=$k conv=$conv noswarm=$noswarm" >> __LOG__
if [ "$beh" = "quota" ] || { [ "$beh" = "quota-workers" ] && [ "$mode" = "worker" ]; }; then
  echo '{"type":"result","is_error":true,"error":"RESOURCE_EXHAUSTED (code 429): Individual quota reached. Resets in 2h."}'; exit 1
fi
if [ -n "$conv" ] && [ -f "$C/conversations/$conv.db" ]; then cid="$conv"; else cid="conv-$RANDOM$RANDOM"; touch "$C/conversations/$cid.db"; fi
case "$mode" in
  plan) sed "s/CID/$cid/" __PLAN__;;
  worker)
    touch __ACT__/$$; ls __ACT__ | wc -l >> __CONC__
    sleep $(cat __SLP__)
    rm -f __ACT__/$$
    echo "{\"type\":\"result\",\"conversation_id\":\"$cid\",\"result\":\"{\\\"status\\\":\\\"done\\\",\\\"summary\\\":\\\"w$k by $email\\\"}\"}";;
  *) echo "{\"type\":\"result\",\"conversation_id\":\"$cid\",\"result\":\"MERGED-ANSWER $mode\"}";;
esac
"#
        .replace("__LOG__", &log.display().to_string())
        .replace("__PLAN__", &plan_file.display().to_string())
        .replace("__ACT__", &act.display().to_string())
        .replace("__CONC__", &conc.display().to_string())
        .replace("__SLP__", &slp.display().to_string());
        std::fs::write(&fake, script).unwrap();
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        let cfg = Arc::new(Config { agy_bin: fake.clone(), agy_job_timeout: 0, ..(*cfg0).clone() });
        let pool = Arc::new(
            AccountStore::open(cfg.state_dir.join("accounts.json"), cfg.state_dir.join("accounts"), &primary).unwrap(),
        );
        let a1 = pool.add_slot("backup").unwrap();
        write_token(&a1.home, "a1@x.io");
        pool.finish_login(&a1.id).unwrap();
        set_behavior(&a1.home, "ok");
        let mgr = Arc::new(JobManager::new(Arc::clone(&cfg), acl, Arc::clone(&store), render, client).unwrap());
        mgr.set_accounts(Arc::clone(&pool));
        mgr.set_mem_probe(Arc::new(|| Some(100_000)));
        let lines = || -> Vec<String> { std::fs::read_to_string(&log).unwrap_or_default().lines().map(String::from).collect() };
        let preq = |text: &str| {
            let mut r = JobRequest::new(OWNER, OWNER, "@o", text, vec![]);
            r.overrides.parallel = Some(3);
            r
        };

        // A) plan on primary -> 3 mothers; primary quota for workers -> they fail over to a1; merge
        set_behavior(&primary, "quota-workers");
        mgr.enqueue(preq("build it")).await.unwrap();
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                if !mgr.is_busy() && lines().iter().any(|l| l.contains("mode=merge")) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("parallel run did not finish");
        tokio::time::sleep(Duration::from_millis(200)).await;
        let l = lines();
        assert!(l[0].contains("mode=plan") && l[0].contains("acct=p@x.io"), "{l:?}");
        let workers_ok: Vec<&String> = l.iter().filter(|x| x.contains("mode=worker") && x.contains("acct=a1@x.io")).collect();
        assert_eq!(workers_ok.len(), 3, "every mother finished on the failover account: {l:?}");
        assert!(l.iter().filter(|x| x.contains("mode=worker")).all(|x| x.contains("noswarm=yes") && x.contains("conv= ")), "{l:?}");
        assert!(l.iter().any(|x| x.contains("mode=worker") && x.contains("acct=p@x.io")), "first mother hit quota on primary: {l:?}");
        let merge = l.iter().find(|x| x.contains("mode=merge")).unwrap();
        let lead = store.get_user(OWNER).conversation_id.clone().expect("lead conversation saved");
        assert!(merge.contains(&format!("conv={lead}")), "merge resumes the lead conversation: {merge} vs {lead}");
        let max_conc: usize = std::fs::read_to_string(&conc).unwrap().lines().filter_map(|x| x.trim().parse().ok()).max().unwrap();
        assert!(max_conc >= 2, "mothers ran concurrently ({max_conc})");
        {
            let calls = st.calls.lock().await;
            let all = calls.iter().map(|(_, v)| v.to_string()).collect::<Vec<_>>().join("\n");
            assert!(all.contains("MERGED-ANSWER"), "merged answer delivered");
            assert!(all.contains("par:stop:"), "single progress message with Stop buttons");
        }

        // B) RAM guard: low memory -> never more than one mother at a time
        set_behavior(&primary, "ok");
        pool.reset_health("primary").unwrap();
        std::fs::write(&conc, "").unwrap();
        mgr.set_mem_probe(Arc::new(|| Some(10)));
        let n0 = lines().len();
        mgr.enqueue(preq("build again")).await.unwrap();
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                if !mgr.is_busy() && lines().len() > n0 && lines()[n0..].iter().any(|l| l.contains("mode=merge")) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("guarded run did not finish");
        let max_conc: usize = std::fs::read_to_string(&conc).unwrap().lines().filter_map(|x| x.trim().parse().ok()).max().unwrap();
        assert_eq!(max_conc, 1, "RAM guard keeps one mother at a time");

        // C) Stop all while mothers run -> no merge, no leftover processes
        mgr.set_mem_probe(Arc::new(|| Some(100_000)));
        std::fs::write(&slp, "30").unwrap();
        let n1 = lines().len();
        mgr.enqueue(preq("long one")).await.unwrap();
        let run_id = tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                let runs = mgr.parallel_runs_of(OWNER);
                if let Some(r) = runs.first() {
                    if std::fs::read_dir(&act).map(|d| d.count()).unwrap_or(0) >= 2 {
                        return r.run_id.clone();
                    }
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("mothers never started");
        assert!(mgr.stop_parallel(OWNER, &run_id, None).await);
        tokio::time::timeout(Duration::from_secs(20), async {
            while mgr.is_busy() {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("stop did not end the run");
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(!lines()[n1..].iter().any(|l| l.contains("mode=merge")), "no merge after Stop all");
        let out = std::process::Command::new("pgrep").arg("-f").arg(fake.to_string_lossy().as_ref()).output().unwrap();
        assert!(String::from_utf8_lossy(&out.stdout).trim().is_empty(), "no fake-agy process left");
        assert!(mgr.parallel_runs_of(OWNER).is_empty());
        assert!(st.calls.lock().await.iter().any(|(_, v)| v.to_string().contains("Parallel run stopped")));
    }

    #[tokio::test]
    async fn parallel_distinct_accounts_worktrees_ownership_and_agent_with_fake_agy() {
        let dir = TempDir::new().unwrap();
        let (st, cfg0, acl, store, render, client) = setup_test_env(&dir).await;
        let ws = cfg0.agy_workspace.clone();
        let sh = |args: &[&str]| {
            let o = std::process::Command::new("git").arg("-C").arg(&ws)
                .args(["-c", "user.name=t", "-c", "user.email=t@t"]).args(args).output().unwrap();
            assert!(o.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&o.stderr));
            String::from_utf8_lossy(&o.stdout).into_owned()
        };
        sh(&["init", "-q", "-b", "master"]);
        std::fs::create_dir_all(ws.join("src")).unwrap();
        std::fs::write(ws.join("src/base.txt"), "base\n").unwrap();
        sh(&["add", "-A"]);
        sh(&["commit", "-q", "-m", "init"]);
        std::fs::create_dir_all(ws.join(".agents/agents/tg-mother")).unwrap();
        std::fs::write(ws.join(".agents/agents/tg-mother/agent.md"), "---\nname: tg-mother\n---\n# tg-mother\nx\n").unwrap();

        let primary = dir.path().join("rootp");
        std::fs::create_dir_all(primary.join(".gemini/antigravity-cli/conversations")).unwrap();
        std::fs::create_dir_all(primary.join(".gemini/config")).unwrap();
        write_token(&primary, "p@x.io");
        set_behavior(&primary, "ok");
        let log = dir.path().join("agy-calls.log");
        // 1 and 2 overlap on src/ -> isolated worktrees; 3 owns docs/ but also touches rogue.txt
        let plan = json!({"parallel": true, "reason": "r", "merge_instructions": "m",
            "subtasks": [
                {"id": "1", "title": "one", "brief": "a", "owns": ["src/"]},
                {"id": "2", "title": "two", "brief": "b", "owns": ["src/"]},
                {"id": "3", "title": "three", "brief": "c", "owns": ["docs/"]}
            ]});
        let plan_file = dir.path().join("plan.line");
        std::fs::write(&plan_file, json!({"type": "result", "conversation_id": "CID", "result": plan.to_string()}).to_string()).unwrap();
        let fake = dir.path().join("fake-agy");
        let script = r#"#!/bin/bash
conv=""; prompt=""; agent=""; model=""
while [ $# -gt 0 ]; do
  case "$1" in
    --conversation) conv="$2"; shift 2;;
    --agent) agent="$2"; shift 2;;
    --model) model="$2"; shift 2;;
    -p) prompt="$2"; shift 2;;
    *) shift;;
  esac
done
C="$HOME/.gemini/antigravity-cli"
email=$(sed -n 's/.*"id_token_email":"\([^"]*\)".*/\1/p' "$C/antigravity-oauth-token" 2>/dev/null)
mode=plain
case "$prompt" in *"[parallel-plan"*) mode=plan;; *"[parallel-worker"*) mode=worker;; *"[parallel-merge"*) mode=merge;; esac
k=$(printf '%s' "$prompt" | sed -n 's/.*\[parallel-worker \([0-9]*\)\/.*/\1/p' | head -1)
echo "acct=$email mode=$mode k=$k agent=$agent pwd=$PWD" >> __LOG__
G="git -c user.name=f -c user.email=f@f"
case "$mode" in
  plan) sed "s/CID/c$RANDOM/" __PLAN__;;
  worker)
    sleep 0.8
    if [ "$k" = "3" ]; then mkdir -p docs; echo d > docs/d.txt; echo r > rogue.txt
    else echo "w$k" > "src/w$k.txt"; if [ "$k" = "1" ]; then $G add -A >/dev/null; $G commit -qm "w1"; fi; fi
    echo "{\"type\":\"result\",\"conversation_id\":\"c$RANDOM\",\"result\":\"{\\\"status\\\":\\\"done\\\",\\\"summary\\\":\\\"w$k\\\"}\"}";;
  *)
    b=$(printf '%s' "$prompt" | grep -o 'git merge --no-ff par/[^ `]*/1' | head -1 | awk '{print $4}')
    printf '%s' "$prompt" > __LOG__.merge
    [ -n "$b" ] && $G merge -q --no-ff -m merge "$b" >> __LOG__.merge 2>&1
    echo "{\"type\":\"result\",\"conversation_id\":\"c$RANDOM\",\"result\":\"MERGED $b\"}";;
esac
"#
        .replace("__LOG__", &log.display().to_string())
        .replace("__PLAN__", &plan_file.display().to_string());
        std::fs::write(&fake, script).unwrap();
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        let cfg = Arc::new(Config { agy_bin: fake.clone(), agy_job_timeout: 0, ..(*cfg0).clone() });
        let pool = Arc::new(
            AccountStore::open(cfg.state_dir.join("accounts.json"), cfg.state_dir.join("accounts"), &primary).unwrap(),
        );
        let a1 = pool.add_slot("backup").unwrap();
        write_token(&a1.home, "a1@x.io");
        pool.finish_login(&a1.id).unwrap();
        set_behavior(&a1.home, "ok");
        let mgr = Arc::new(JobManager::new(Arc::clone(&cfg), acl, Arc::clone(&store), render, client).unwrap());
        mgr.set_accounts(Arc::clone(&pool));
        mgr.set_mem_probe(Arc::new(|| Some(100_000)));
        let lines = || -> Vec<String> { std::fs::read_to_string(&log).unwrap_or_default().lines().map(String::from).collect() };
        let mut r = JobRequest::new(OWNER, OWNER, "@o", "go", vec![]);
        r.overrides.parallel = Some(3);
        mgr.enqueue(r).await.unwrap();
        tokio::time::timeout(Duration::from_secs(40), async {
            loop {
                if !mgr.is_busy() && lines().iter().any(|l| l.contains("mode=merge")) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("parallel run did not finish");
        tokio::time::sleep(Duration::from_millis(300)).await;
        let l = lines();
        let workers: Vec<&String> = l.iter().filter(|x| x.contains("mode=worker")).collect();
        assert_eq!(workers.len(), 3, "{l:?}");
        // the first two concurrent mothers got distinct accounts
        let acct = |k: &str| workers.iter().find(|x| x.contains(&format!("k={k} "))).unwrap().split_whitespace().next().unwrap().to_string();
        assert_ne!(acct("1"), acct("2"), "distinct accounts: {l:?}");
        // all mothers run as the tg-mother project agent
        assert!(workers.iter().all(|x| x.contains("agent=tg-mother")), "{l:?}");
        // 1 and 2 ran in their own worktrees, 3 in the shared tree
        for k in ["1", "2"] {
            let w = workers.iter().find(|x| x.contains(&format!("k={k} "))).unwrap();
            assert!(w.contains(&format!("/wt/{k}")), "worktree for {k}: {w}");
        }
        let w3 = workers.iter().find(|x| x.contains("k=3 ")).unwrap();
        assert!(w3.ends_with(&format!("pwd={}", ws.display())), "{w3}");
        // branch 1 merged by the lead and deleted; branch 2 auto-committed, unmerged, kept
        assert!(ws.join("src/w1.txt").is_file(), "branch 1 merged: {}", std::fs::read_to_string(format!("{}.merge", log.display())).unwrap_or_default());
        let branches = sh(&["branch", "--list", "par/*"]);
        assert!(!branches.contains("/1"), "{branches}");
        assert!(branches.contains("/2"), "{branches}");
        let b2 = branches.lines().find(|b| b.contains("/2")).unwrap().trim().trim_start_matches("* ").to_string();
        assert!(sh(&["show", "--name-only", "--format=", &b2]).contains("src/w2.txt"), "auto-commit kept w2");
        assert_eq!(sh(&["worktree", "list"]).lines().count(), 1, "worktrees removed");
        // ownership report: rogue.txt flagged for agent 3, docs/d.txt not
        let calls = st.calls.lock().await;
        let all = calls.iter().map(|(_, v)| v.to_string()).collect::<Vec<_>>().join("\n");
        assert!(all.contains("outside its ownership: rogue.txt"), "violation reported");
        assert!(!all.contains("docs/d.txt"), "owned file not flagged");
        assert!(all.contains("Unmerged worktree branches kept"), "kept branch reported");
    }

    #[tokio::test]
    async fn explicit_per_account_default_model_with_fake_agy() {
        let dir = TempDir::new().unwrap();
        let (_st, cfg0, acl, store, render, client) = setup_test_env(&dir).await;
        let primary = dir.path().join("rootm");
        std::fs::create_dir_all(primary.join(".gemini/antigravity-cli/conversations")).unwrap();
        std::fs::create_dir_all(primary.join(".gemini/config")).unwrap();
        write_token(&primary, "p@x.io");
        let settings = primary.join(".gemini/antigravity-cli/settings.json");
        let log = dir.path().join("agy-calls.log");
        let fake = dir.path().join("fake-agy");
        let script = r#"#!/bin/bash
model=""
while [ $# -gt 0 ]; do case "$1" in --model) model="$2"; shift 2;; *) shift;; esac; done
echo "model=$model" >> __LOG__
echo '{"type":"result","conversation_id":"c1","result":"ok"}'
"#
        .replace("__LOG__", &log.display().to_string());
        std::fs::write(&fake, script).unwrap();
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        let cfg = Arc::new(Config { agy_bin: fake.clone(), agy_job_timeout: 0, ..(*cfg0).clone() });
        let pool = Arc::new(
            AccountStore::open(cfg.state_dir.join("accounts.json"), cfg.state_dir.join("accounts"), &primary).unwrap(),
        );
        let a1 = pool.add_slot("b").unwrap();
        write_token(&a1.home, "a1@x.io");
        pool.finish_login(&a1.id).unwrap();
        std::fs::write(cfg.state_dir.join("models.json"), r#"[{"id":"m-a","name":"Model A"},{"id":"m-b","name":"Model B"}]"#).unwrap();
        let a1_models = crate::models_pool::models_path(&cfg.state_dir, &a1.id);
        std::fs::create_dir_all(a1_models.parent().unwrap()).unwrap();
        std::fs::write(&a1_models, r#"[{"id":"m-c","name":"Model C"},{"id":"m-b","name":"Model B"}]"#).unwrap();
        let mgr = Arc::new(JobManager::new(Arc::clone(&cfg), acl, Arc::clone(&store), render, client).unwrap());
        mgr.set_accounts(Arc::clone(&pool));
        let prim = pool.get("primary").unwrap();
        // shared default is on both lists (by name) -> used everywhere
        std::fs::write(&settings, r#"{"model":"Model B"}"#).unwrap();
        assert_eq!(mgr.account_default_model(&prim).as_deref(), Some("m-b"));
        assert_eq!(mgr.account_default_model(&a1).as_deref(), Some("m-b"));
        // shared default unknown to the accounts -> each account's own first model
        std::fs::write(&settings, r#"{"model":"Gemini 4 Hydrogen (XHigh)"}"#).unwrap();
        assert_eq!(mgr.account_default_model(&prim).as_deref(), Some("m-a"));
        assert_eq!(mgr.account_default_model(&a1).as_deref(), Some("m-c"));
        // a real job always passes an explicit --model
        mgr.enqueue(JobRequest::new(OWNER, OWNER, "@o", "hi", vec![])).await.unwrap();
        wait_idle(&mgr, &log, 1).await;
        let l = std::fs::read_to_string(&log).unwrap();
        let first = l.lines().next().unwrap();
        assert!(first == "model=m-a" || first == "model=m-c", "explicit model passed: {l}");
    }

    #[tokio::test]
    async fn phase12_weekly_reserve_sticky_proxy_fail_closed_and_breaker_e2e() {
        use agy_core::accounts::AccountPolicy;
        use agy_core::proxies::{ProxyFallbackPolicy, ProxyRegistry};

        let dir = TempDir::new().unwrap();
        let (st, cfg0, acl, store, render, client) = setup_test_env(&dir).await;
        let primary = dir.path().join("root_p12");
        std::fs::create_dir_all(primary.join(".gemini/antigravity-cli/conversations")).unwrap();
        std::fs::create_dir_all(primary.join(".gemini/config")).unwrap();
        write_token(&primary, "p@x.io");
        set_behavior(&primary, "heavy_weekly");

        let log = dir.path().join("p12-calls.log");
        let fake = dir.path().join("fake-agy-p12");
        let script = r#"#!/bin/bash
C="$HOME/.gemini/antigravity-cli"
email=$(sed -n 's/.*"id_token_email":"\([^"]*\)".*/\1/p' "$C/antigravity-oauth-token" 2>/dev/null)
beh=$(cat "$C/cache/behavior" 2>/dev/null)
echo "acct=$email proxy=${HTTPS_PROXY:-direct} noproxy=${NO_PROXY:-}" >> __LOG__
case "$beh" in
  heavy_weekly)
    echo '{"type":"result","conversation_id":"c1","result":"ok-primary","usage":{"input_tokens":991000,"output_tokens":0}}'
    ;;
  tos_ban)
    echo '{"type":"result","is_error":true,"error":"PERMISSION_DENIED (code 403): Terms of Service violation — disabled in this account"}'
    exit 1
    ;;
  *)
    echo '{"type":"result","conversation_id":"c2","result":"ok-backup","usage":{"input_tokens":500,"output_tokens":100}}'
    ;;
esac
"#
        .replace("__LOG__", &log.display().to_string());
        std::fs::write(&fake, script).unwrap();
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();

        let cfg = Arc::new(Config {
            agy_bin: fake.clone(),
            agy_job_timeout: 0,
            ..(*cfg0).clone()
        });
        let pool = Arc::new(
            AccountStore::open(
                cfg.state_dir.join("accounts.json"),
                cfg.state_dir.join("accounts"),
                &primary,
            )
            .unwrap(),
        );
        let mut pol = AccountPolicy::strict_safe();
        pol.min_gap_secs = 0; // keep test fast while keeping strict reserve/concurrency/breaker active
        pol.switch_delay_secs = 0;
        pol.weekly_reserve_pct = 1.0;
        pol.pool_breaker_threshold = 2;
        pool.set_policy(pol).unwrap();
        pool.set_weekly_budget("primary", Some(1_000_000)).unwrap();

        let a1 = pool.add_slot("acc-proxy").unwrap();
        write_token(&a1.home, "a1@x.io");
        pool.finish_login(&a1.id).unwrap();
        set_behavior(&a1.home, "ok");

        let a2 = pool.add_slot("acc-third").unwrap();
        write_token(&a2.home, "a2@x.io");
        pool.finish_login(&a2.id).unwrap();
        set_behavior(&a2.home, "ok");

        let proxies = Arc::new(
            ProxyRegistry::open(cfg.proxies_path(), ProxyFallbackPolicy::FailClosed).unwrap(),
        );
        let px1 = proxies
            .add("socks5h://u:secretpass@198.51.100.22:1080", "DE-1")
            .unwrap();
        proxies.record_probe_ok(&px1.id, 120);
        pool.set_account_proxy(&a1.id, Some(&px1.id)).unwrap();

        let mgr = Arc::new(
            JobManager::new(Arc::clone(&cfg), acl, Arc::clone(&store), render, client).unwrap(),
        );
        mgr.set_accounts(Arc::clone(&pool));
        mgr.set_proxies(Arc::clone(&proxies));

        let read_lines = || -> Vec<String> {
            std::fs::read_to_string(&log)
                .unwrap_or_default()
                .lines()
                .map(String::from)
                .collect()
        };

        // 1) Turn 1 runs on primary (direct), consumes 99.1% of 1M weekly budget -> parks in 1% weekly reserve!
        mgr.enqueue(JobRequest::new(OWNER, OWNER, "@o", "turn 1", vec![]))
            .await
            .unwrap();
        wait_idle(&mgr, &log, 1).await;
        assert!(read_lines()[0].contains("acct=p@x.io proxy=direct"), "{:?}", read_lines());
        assert_eq!(pool.weekly_reserved_count(), 1, "primary must park at 99.1% weekly");
        assert!(
            st.calls
                .lock()
                .await
                .iter()
                .any(|(_, v)| v.to_string().contains("Weekly reserve reached")),
            "owner must receive weekly reserve alert"
        );

        // 2) Turn 2 skips weekly-reserved primary -> runs on a1 WITH sticky proxy env injected!
        mgr.enqueue(JobRequest::new(OWNER, OWNER, "@o", "turn 2", vec![]))
            .await
            .unwrap();
        wait_idle(&mgr, &log, 2).await;
        let l2 = read_lines();
        assert!(
            l2[1].contains("acct=a1@x.io")
                && l2[1].contains("proxy=socks5h://u:secretpass@198.51.100.22:1080")
                && l2[1].contains("noproxy=127.0.0.1,localhost,::1"),
            "sticky proxy env not injected properly: {l2:?}"
        );

        // 3) Mark px1 Unhealthy (2 consecutive failures) under FailClosed -> a1 MUST BE SKIPPED (never leak direct IP) -> uses a2!
        proxies.record_probe_fail(&px1.id, "timeout");
        proxies.record_probe_fail(&px1.id, "timeout");
        mgr.enqueue(JobRequest::new(OWNER, OWNER, "@o", "turn 3", vec![]))
            .await
            .unwrap();
        wait_idle(&mgr, &log, 3).await;
        let l3 = read_lines();
        assert!(
            l3[2].contains("acct=a2@x.io proxy=direct"),
            "fail-closed unhealthy proxy must skip a1 and never leak direct IP: {l3:?}"
        );

        // 4) Pool Safety Breaker: restore px1 & primary cap; sticky a2 & primary both hit ToS ban ->
        //    after 2nd severe ban breaker trips & PROTECTS healthy 3rd account (a1)!
        proxies.record_probe_ok(&px1.id, 90);
        pool.set_weekly_budget("primary", None).unwrap();
        set_behavior(&a2.home, "tos_ban");
        set_behavior(&primary, "tos_ban");
        set_behavior(&a1.home, "ok");
        let before_n = read_lines().len();
        mgr.enqueue(JobRequest::new(OWNER, OWNER, "@o", "turn 4", vec![]))
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(15), async {
            while mgr.is_busy() || read_lines().len() < before_n + 2 {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("turn 4 did not finish");
        tokio::time::sleep(Duration::from_millis(150)).await;
        let l4 = read_lines();
        assert!(pool.breaker_status().is_some(), "pool safety breaker must trip after 2 severe ToS bans");
        assert_eq!(
            l4.len(),
            before_n + 2,
            "breaker must halt failover before risking the 3rd healthy account (a1): {l4:?}"
        );
        assert!(
            !l4[before_n..].iter().any(|line| line.contains("acct=a1@x.io")),
            "healthy a1 must remain untouched once breaker trips: {l4:?}"
        );
        assert!(
            st.calls
                .lock()
                .await
                .iter()
                .any(|(_, v)| v.to_string().contains("Account Pool Safety Breaker is ACTIVE")),
            "owner must receive breaker alert"
        );

        // 5) Next turn while breaker is active makes ZERO agy calls; after reset_breaker() it runs on healthy a1!
        let count_at_trip = read_lines().len();
        mgr.enqueue(JobRequest::new(OWNER, OWNER, "@o", "turn 5 blocked", vec![]))
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(10), async {
            while mgr.is_busy() {
                tokio::time::sleep(Duration::from_millis(30)).await;
            }
        })
        .await
        .expect("turn 5 did not finish");
        tokio::time::sleep(Duration::from_millis(120)).await;
        assert_eq!(read_lines().len(), count_at_trip, "active breaker must block all agy runs");

        pool.reset_breaker().unwrap();
        mgr.enqueue(JobRequest::new(OWNER, OWNER, "@o", "turn 6 resumed", vec![]))
            .await
            .unwrap();
        wait_idle(&mgr, &log, count_at_trip + 1).await;
        let l6 = read_lines();
        assert!(
            l6.last().unwrap().contains("acct=a1@x.io")
                && l6.last().unwrap().contains("proxy=socks5h://u:secretpass@198.51.100.22:1080"),
            "after breaker reset, healthy a1 must resume with its sticky proxy: {l6:?}"
        );
    }

    #[tokio::test]
    async fn phase3_live_stream_guard_global_cap_and_outbox_secret_scanner_e2e() {
        let dir = TempDir::new().unwrap();
        let (st, mut cfg_arc, acl, store, render, client) = setup_test_env(&dir).await;
        let log = dir.path().join("calls.log");
        let active_cnt_file = dir.path().join("active.cnt");
        let peak_cnt_file = dir.path().join("peak.cnt");
        let bot_tok = cfg_arc.bot_token.clone();

        let script = dir.path().join("fake_agy_p3.py");
        let py = format!(
            r#"#!/usr/bin/env python3
import fcntl, json, os, re, sys, time

if len(sys.argv) > 1 and sys.argv[1] == "models":
    print("m1\tM1")
    sys.exit(0)

prompt = sys.argv[-1]
home = os.environ.get("HOME", "")
log_path = {log:?}
act_path = {act:?}
peak_path = {peak:?}
lock_path = act_path + ".lock"

def bump(delta):
    with open(lock_path, "a+") as lf:
        fcntl.flock(lf, fcntl.LOCK_EX)
        cur = int(open(act_path).read().strip()) if os.path.exists(act_path) else 0
        nxt = cur + delta
        open(act_path, "w").write(str(nxt))
        pk = int(open(peak_path).read().strip()) if os.path.exists(peak_path) else 0
        if nxt > pk:
            open(peak_path, "w").write(str(nxt))

bump(1)
try:
    with open(log_path, "a") as f:
        f.write(f"home={{os.path.basename(home)}} prompt={{prompt[:40]!r}}\n")

    if "LOOP_ATTACK" in prompt:
        print(json.dumps({{"type": "step_update", "step_type": "agent_response", "delta": "starting work"}}), flush=True)
        for i in range(1, 20):
            print(json.dumps({{
                "type": "step_update",
                "step_index": i,
                "step_type": "tool_use",
                "tool_name": "run_command",
                "tool_info": {{"name": "run_command", "CommandLine": "rm -rf /nope"}}
            }}), flush=True)
            time.sleep(0.03)
        time.sleep(10)
    elif "OUTBOX_LEAK" in prompt:
        m = re.search(r"Put any file you want delivered to the user in:\s*(\S+)", prompt)
        if m:
            od = m.group(1)
            os.makedirs(od, exist_ok=True)
            open(os.path.join(od, "leaked.env"), "w").write("BOT_TOKEN={tok}\n-----BEGIN PRIVATE KEY-----\n")
            open(os.path.join(od, "report.txt"), "w").write("all systems nominal\n")
        print(json.dumps({{"type": "result", "result": "wrote files"}}), flush=True)
    else:
        time.sleep(0.35)
        print(json.dumps({{"type": "result", "result": "slow ok"}}), flush=True)
finally:
    bump(-1)
"#,
            log = log.to_string_lossy(),
            act = active_cnt_file.to_string_lossy(),
            peak = peak_cnt_file.to_string_lossy(),
            tok = bot_tok,
        );
        std::fs::write(&script, py).unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();

        let mut cfg = (*cfg_arc).clone();
        cfg.agy_bin = script.clone();
        cfg.agy_max_steps_per_turn = 20;
        cfg.agy_tool_repeat_limit = 2;
        cfg.agy_max_tools_per_min = 30;
        cfg.max_global_ai_jobs = 1;
        cfg.outbox_secret_scan = true;
        cfg_arc = Arc::new(cfg);

        // Two healthy accounts in pool
        let primary = dir.path().join("home_primary");
        std::fs::create_dir_all(primary.join(".gemini/antigravity-cli")).unwrap();
        std::fs::write(
            primary.join(".gemini/antigravity-cli/antigravity-oauth-token"),
            r#"{"access_token":"t","email":"p@x.io"}"#,
        )
        .unwrap();
        let pool = Arc::new(
            AccountStore::open(
                cfg_arc.state_dir.join("accounts.json"),
                cfg_arc.state_dir.join("accounts"),
                &primary,
            )
            .unwrap(),
        );
        let mut pol = agy_core::AccountPolicy::strict_safe();
        pol.min_gap_secs = 0;
        pol.switch_delay_secs = 0;
        pool.set_policy(pol).unwrap();
        let a1 = pool.add_slot("acc-second").unwrap();
        std::fs::create_dir_all(a1.home.join(".gemini/antigravity-cli")).unwrap();
        std::fs::write(
            a1.home.join(".gemini/antigravity-cli/antigravity-oauth-token"),
            r#"{"access_token":"t","email":"a1@x.io"}"#,
        )
        .unwrap();
        pool.finish_login(&a1.id).unwrap();

        let mgr = Arc::new(
            JobManager::new(
                Arc::clone(&cfg_arc),
                Arc::clone(&acl),
                Arc::clone(&store),
                Arc::clone(&render),
                Arc::clone(&client),
            )
            .unwrap(),
        );
        mgr.set_accounts(Arc::clone(&pool));

        // 1) Live stream loop guard stops runaway child, NEVER penalizes or rotates account!
        mgr.enqueue(JobRequest::new(OWNER, OWNER, "@o", "LOOP_ATTACK now", vec![]))
            .await
            .unwrap();
        wait_idle(&mgr, &log, 1).await;
        let log1 = std::fs::read_to_string(&log).unwrap_or_default();
        assert_eq!(log1.lines().count(), 1, "loop guard must NOT failover to a second account: {log1}");
        assert_eq!(
            pool.get("primary").unwrap().health.status,
            HealthStatus::Ok,
            "local AI loop guard trip must NEVER penalize account health"
        );
        assert!(
            st.calls
                .lock()
                .await
                .iter()
                .any(|(_, v)| v.to_string().contains("AI Safety Guard stopped this turn")),
            "user must be notified when AI Safety Guard stops a turn"
        );

        // 2) Outbox secret scanner blocks leaked.env while delivering clean report.txt
        mgr.enqueue(JobRequest::new(OWNER, OWNER, "@o", "OUTBOX_LEAK test", vec![]))
            .await
            .unwrap();
        wait_idle(&mgr, &log, 2).await;
        let mp = st.multipart_methods.lock().await.clone();
        assert_eq!(
            mp,
            vec!["sendDocument".to_string()],
            "only the clean report.txt should be uploaded (leaked.env blocked): {mp:?}"
        );
        let calls_txt: String = st
            .calls
            .lock()
            .await
            .iter()
            .map(|(_, v)| v.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            calls_txt.contains("Blocked outbox file") && calls_txt.contains("leaked.env"),
            "chat must receive blocked-secret notice"
        );
        assert!(
            !calls_txt.contains(&bot_tok),
            "secret scanner notice must NEVER echo the leaked token value"
        );

        // 3) Global AI concurrency semaphore (MAX_GLOBAL_AI_JOBS=1) serializes two distinct users
        std::fs::write(&peak_cnt_file, "0").unwrap();
        mgr.enqueue(JobRequest::new(OWNER, OWNER, "@o", "slow job A", vec![]))
            .await
            .unwrap();
        mgr.enqueue(JobRequest::new(STD_USER, STD_USER, "@u", "slow job B", vec![]))
            .await
            .unwrap();
        wait_idle(&mgr, &log, 4).await;
        let peak: usize = std::fs::read_to_string(&peak_cnt_file)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert_eq!(
            peak, 1,
            "MAX_GLOBAL_AI_JOBS=1 must strictly cap simultaneous AI executions at 1"
        );
    }

    #[tokio::test]
    async fn phase4_compact_resume_prompt_and_dynamic_turn_profile_e2e() {
        let dir = TempDir::new().unwrap();
        let (_st, cfg_arc, acl, store, render, client) = setup_test_env(&dir).await;
        let log = dir.path().join("p4_calls.jsonl");

        let script = dir.path().join("fake_agy_p4.py");
        let py = format!(
            r#"#!/usr/bin/env python3
import json, os, sys
args = sys.argv[1:]
if args and args[0] == "models":
    print("m1\tM1")
    sys.exit(0)
home = os.environ.get("HOME", "")
conv_dir = os.path.join(home, ".gemini", "antigravity-cli", "conversations")
os.makedirs(conv_dir, exist_ok=True)
open(os.path.join(conv_dir, "cid-p4-1.db"), "wb").write(b"ok")
with open({log:?}, "a") as f:
    f.write(json.dumps({{"args": args, "prompt": args[-1]}}) + "\n")
print(json.dumps({{"type": "result", "conversation_id": "cid-p4-1", "result": "ok"}}), flush=True)
"#,
            log = log.to_string_lossy(),
        );
        std::fs::write(&script, py).unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();

        let mut cfg = (*cfg_arc).clone();
        cfg.agy_bin = script;
        cfg.prompt_compact_resume = true;
        cfg.agy_dynamic_profile = true;
        let cfg_arc = Arc::new(cfg);

        let primary = dir.path().join("home_primary");
        std::fs::create_dir_all(primary.join(".gemini/antigravity-cli")).unwrap();
        std::fs::write(
            primary.join(".gemini/antigravity-cli/antigravity-oauth-token"),
            r#"{"access_token":"t","email":"p@x.io"}"#,
        )
        .unwrap();
        let pool = Arc::new(
            AccountStore::open(
                cfg_arc.state_dir.join("accounts.json"),
                cfg_arc.state_dir.join("accounts"),
                &primary,
            )
            .unwrap(),
        );
        let mut pol = agy_core::AccountPolicy::strict_safe();
        pol.min_gap_secs = 0;
        pool.set_policy(pol).unwrap();

        let mgr = Arc::new(
            JobManager::new(
                Arc::clone(&cfg_arc),
                Arc::clone(&acl),
                Arc::clone(&store),
                Arc::clone(&render),
                Arc::clone(&client),
            )
            .unwrap(),
        );
        mgr.set_accounts(Arc::clone(&pool));

        // 1) First turn (no conversation yet, Lite chat prompt): FULL bridge header + --effort low + --disable-slash-commands
        mgr.enqueue(JobRequest::new(OWNER, OWNER, "@o", "سلام چطوری؟", vec![]))
            .await
            .unwrap();
        wait_idle(&mgr, &log, 1).await;

        // 2) Second turn (resumed cid-p4-1, Lite prompt): COMPACT 1-line header (no repeated session-handoff boilerplate!)
        mgr.enqueue(JobRequest::new(OWNER, OWNER, "@o", "ممنون!", vec![]))
            .await
            .unwrap();
        wait_idle(&mgr, &log, 2).await;

        // 3) Third turn (resumed cid-p4-1, Full engineering prompt): COMPACT header, NO --effort low, NO --disable-slash-commands!
        mgr.enqueue(JobRequest::new(OWNER, OWNER, "@o", "فاز ۴ و سرویس MCP را دیباگ کن", vec![]))
            .await
            .unwrap();
        wait_idle(&mgr, &log, 3).await;

        let lines: Vec<Value> = std::fs::read_to_string(&log)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(lines.len(), 3);

        let p1 = lines[0]["prompt"].as_str().unwrap();
        let a1: Vec<&str> = lines[0]["args"].as_array().unwrap().iter().filter_map(Value::as_str).collect();
        assert!(p1.contains("telegram-output.md") && p1.contains("session-handoff.md"), "turn 1 must carry full header");
        assert!(a1.contains(&"--disable-slash-commands"), "Lite turn should pass --disable-slash-commands");
        assert!(a1.windows(2).any(|w| w == ["--effort", "low"]), "Lite turn without explicit effort should use low");

        let p2 = lines[1]["prompt"].as_str().unwrap();
        assert!(p2.starts_with("[telegram-bridge] @o · outbox:"), "resumed turn 2 must use compact 1-line header: {p2}");
        assert!(!p2.contains("session-handoff.md"), "resumed turn 2 must not repeat handoff boilerplate");
        assert!(p2.len() + 250 < p1.len(), "compact resume header should save substantial tokens");

        let a3: Vec<&str> = lines[2]["args"].as_array().unwrap().iter().filter_map(Value::as_str).collect();
        assert!(!a3.contains(&"--disable-slash-commands"), "Full engineering turn must never disable slash commands");
        assert!(!a3.windows(2).any(|w| w == ["--effort", "low"]), "Full engineering turn must not downgrade effort");
    }
}
