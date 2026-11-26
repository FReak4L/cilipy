//! Shared multi-turn autonomous agent runtime for OpenAI-compatible LLM backends
//! (used by both Venice Uncensored and xAI Grok Subscription OAuth).
//!
//! Phase 1 Hermes-grade coding execution upgrades:
//! - Persistent per-user/per-engine conversation history (`$STATE_DIR/agent_sessions/<key>.json`, `0600`)
//! - 17 live server/coding/workspace/MCP tools:
//!   - Execution: `run_command` (zero-SIGPIPE head+tail ring buffer, timeout up to 600s with
//!     partial output preservation, `background`/`pty` tmux sessions, `bubblewrap` OS sandbox),
//!     `process_manage` (`list`/`poll`/`wait`/`log`/`write`/`kill`), `execute_code` (Python
//!     programmatic tool calling over Unix Domain Socket RPC, up to 50 calls per turn)
//!   - Files & search: `read_file`, `write_file`, `patch_file` / `edit_file` (uniqueness check,
//!     fuzzy line-block fallback, unified diff, atomic write, stale read-baseline guard, fast
//!     differential syntax diagnostics), non-blocking `list_dir` & `grep_files`
//!   - Research/memory/MCP: `web_search`, `fetch_url`, `list_mcp_servers`, `call_mcp_tool`
//!     (backed by persistent warm `McpClientPool`), `memory_search`, `memory_store`,
//!     `search_skills`, `load_skill`
//! - Three-gate [`crate::command_guard`] firewall (hardline secret/service protection, SHA-256
//!   script-body inspection, Airlock taint defense after web reads, anti-loop breaker)
//! - Fine-grained ACL containment: `allow_root` (host) vs `allow_sandbox` (`bubblewrap` OS sandbox)
//! - Parallel execution for read-only tool batches, real SSE streaming with plain-JSON fallback,
//!   and mid-turn tool-output compaction (keeping KV-cache prefix static).

use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex, OnceLock};
use std::time::{Duration, Instant, SystemTime};

use agy_core::atomic::atomic_write_json;
use agy_core::error::{BridgeError, Result};
use futures_util::StreamExt;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::process::Command;
use tokio::sync::{watch, Semaphore};
use tracing::{debug, info, warn};

use crate::code_exec::{run_execute_code, CodeExecRequest, RpcToolDispatcher, MAX_CODE_EXEC_TIMEOUT_SECS};
use crate::command_guard::{
    evaluate_command, CommandGuardContext, CommandVerdict, DENIAL_BREAKER_THRESHOLD,
};
use crate::engines::{JobResult, Progress, ProgressCallback};
use crate::exec_backend::{
    run_exec_command, scrub_command_env, ExecOptions, DEFAULT_COMMAND_TIMEOUT_SECS,
    MAX_COMMAND_TIMEOUT_SECS,
};
use crate::mcp_client::{global_mcp_pool, redact_secrets_in_text};
use crate::mcp_config::{get_mcp_server_raw, list_mcp_servers};
use crate::openhands::{self, EditHistory, TaskTracker};
use crate::pty_manager::{
    kill_session, list_sessions, poll_session, start_session, wait_session, write_session,
    StartPtyRequest,
};
use crate::skills::validate_skill_slug;

pub const DEFAULT_MAX_AGENT_STEPS: usize = 40;
pub const MAX_AGENT_STEPS_CAP: usize = 100;
pub const DEFAULT_MAX_TOKENS: u32 = 16384;
pub const DEFAULT_JOB_TIMEOUT_SECS: u64 = 600;
pub const MAX_TOOL_OUTPUT_BYTES: usize = 64 * 1024;
/// Phase 4 default early head+tail compaction cap for heavy tool outputs (24 KiB).
pub const DEFAULT_EARLY_TOOL_OUTPUT_BYTES: usize = 24 * 1024;
pub const MAX_FILE_READ_BYTES: usize = 128 * 1024;
const MAX_SESSION_MESSAGES: usize = 30;
const MAX_SESSION_BYTES: usize = 120 * 1024;
const MAX_STORED_MSG_CHARS: usize = 6000;
/// In-turn context high-watermark before batch-compacting old tool outputs (160 KiB ≈ 40k tokens;
/// prevents Context Rot while compacting down to a 65% low-watermark to preserve KV-cache prefix hits).
const MAX_IN_TURN_CONTEXT_BYTES: usize = 160 * 1024;

static AGENT_TOOL_OUTPUT_CAP: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(DEFAULT_EARLY_TOOL_OUTPUT_BYTES);

/// Configure the process-wide early head+tail tool-output compaction cap (clamped `4 KiB..=64 KiB`).
pub fn set_agent_tool_output_cap(bytes: usize) {
    AGENT_TOOL_OUTPUT_CAP.store(
        bytes.clamp(4096, MAX_TOOL_OUTPUT_BYTES),
        std::sync::atomic::Ordering::Relaxed,
    );
}

fn active_tool_output_cap() -> usize {
    AGENT_TOOL_OUTPUT_CAP.load(std::sync::atomic::Ordering::Relaxed)
}

/// Smart UTF-8-safe head (70%) + tail (25%) early compaction for heavy tool outputs.
/// Preserves both top headers/context and bottom errors/summaries while shedding middle noise.
pub fn compact_tool_output(s: &str, max_bytes: usize) -> String {
    let cap = max_bytes.max(512);
    if s.len() <= cap {
        return s.to_string();
    }
    let head_budget = (cap * 70) / 100;
    let tail_budget = (cap * 25) / 100;
    let mut head_end = head_budget.min(s.len());
    while head_end > 0 && !s.is_char_boundary(head_end) {
        head_end -= 1;
    }
    let mut tail_start = s.len().saturating_sub(tail_budget);
    while tail_start < s.len() && !s.is_char_boundary(tail_start) {
        tail_start += 1;
    }
    if tail_start <= head_end {
        return s.to_string();
    }
    let omitted = tail_start.saturating_sub(head_end);
    format!(
        "{}
... [early-compacted {omitted} bytes of {} bytes] ...
{}",
        &s[..head_end],
        s.len(),
        &s[tail_start..]
    )
}
/// Number of most recent tool results preserved verbatim during mid-turn compaction.
const PRESERVE_RECENT_TOOL_MSGS: usize = 4;
/// Maximum concurrent read-only tool calls per parallel wave (doubled to 12 for speed).
const MAX_PARALLEL_READ_TOOLS: usize = 12;

/// Pooled direct HTTP client reused across turns & vision calls to eliminate cold TLS handshakes.
/// Uses connect + per-chunk idle read timeout instead of a hard total timeout so long streaming
/// completions are never aborted mid-generation.
fn shared_direct_http_client() -> Result<reqwest::Client> {
    static CLIENT: OnceLock<std::result::Result<reqwest::Client, String>> = OnceLock::new();
    let res = CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .use_rustls_tls()
            .tcp_keepalive(Duration::from_secs(30))
            .pool_max_idle_per_host(16)
            .pool_idle_timeout(Duration::from_secs(90))
            .connect_timeout(Duration::from_secs(20))
            .read_timeout(Duration::from_secs(90))
            .build()
            .map_err(|e| format!("shared agent HTTP client build failed: {e}"))
    });
    res.clone().map_err(BridgeError::Network)
}

/// Safe read-only/research MCP servers non-root users may invoke via `call_mcp_tool`.
const NON_ROOT_ALLOWED_MCPS: &[&str] = &[
    "search-v3",
    "skillport",
    "skills-catalog",
    "context7",
    "graphify",
];

/// Boxed future returning `(chat_completions_url, extra_headers)`.
pub type RequestAuthFuture<'a> =
    Pin<Box<dyn Future<Output = Result<(String, Vec<(String, String)>)>> + Send + 'a>>;

/// Dynamic endpoint & header provider invoked on each LLM turn (and on 401/426 recovery).
pub trait AuthHeaderProvider: Send + Sync {
    /// Return `(chat_completions_url, extra_headers)` for the request.
    /// `force_refresh_auth` is set after HTTP 401; `force_refresh_version` after HTTP 426.
    fn resolve_request<'a>(
        &'a self,
        force_refresh_auth: bool,
        force_refresh_version: bool,
    ) -> RequestAuthFuture<'a>;

    /// Optional backend-specific formatting for HTTP error statuses (e.g. xAI 403 tier guidance).
    fn format_http_error(&self, status: u16, body: &str) -> String {
        let excerpt: String = redact_secrets_in_text(body).chars().take(600).collect();
        format!("API error (HTTP {status}): {excerpt}")
    }
}

/// Static bearer-token provider for OpenAI-compatible endpoints (e.g. Venice).
pub struct StaticBearerProvider {
    pub api_base: String,
    pub api_key: String,
    pub extra_headers: Vec<(String, String)>,
}

impl AuthHeaderProvider for StaticBearerProvider {
    fn resolve_request<'a>(
        &'a self,
        _force_refresh_auth: bool,
        _force_refresh_version: bool,
    ) -> RequestAuthFuture<'a> {
        Box::pin(async move {
            let base = self.api_base.trim().trim_end_matches('/');
            if base.is_empty() {
                return Err(BridgeError::Config("API base URL is empty".to_string()));
            }
            if self.api_key.trim().is_empty() {
                return Err(BridgeError::Config(
                    "API key is not configured (set VENICE_API_KEY in environment)".to_string(),
                ));
            }
            let url = format!("{base}/chat/completions");
            let mut hdrs = vec![(
                "Authorization".to_string(),
                format!("Bearer {}", self.api_key.trim()),
            )];
            hdrs.extend(self.extra_headers.clone());
            Ok((url, hdrs))
        })
    }
}

/// Controls the 3-stage background pre-analysis, chat memory & SkillHub pipeline for Venice Web Chat.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreeStageMode {
    #[default]
    Auto,
    Always,
    Off,
}

/// Configuration for a single autonomous agent or chat turn.
#[derive(Debug, Clone)]
pub struct AgentTurnConfig {
    pub engine_id: String,
    pub model: String,
    pub system_prompt: String,
    pub cwd: PathBuf,
    pub workspace_root: PathBuf,
    pub allow_root: bool,
    /// Allows executing shell/PTY/`execute_code` inside the Linux `bubblewrap` sandbox without host root.
    pub allow_sandbox: bool,
    pub agent_mode: bool,
    pub mcp_config_path: PathBuf,
    pub skills_dir: PathBuf,
    pub state_dir: PathBuf,
    /// Persistent multi-turn session key (e.g. `"uncensored_1000000001"`). `None` = one-shot isolated.
    pub session_key: Option<String>,
    pub max_steps: usize,
    pub max_tokens: u32,
    pub job_timeout_secs: u64,
    /// Optional sticky egress proxy URL (`http(s)://...` or `socks5(h)://...`) for this turn.
    pub proxy_url: Option<String>,
    /// Controls automated 3-stage background memory + SkillHub + chunked coding pipeline (`Auto` / `Always` / `Off`).
    pub three_stage_mode: ThreeStageMode,
}

impl AgentTurnConfig {
    pub fn can_exec(&self) -> bool {
        self.allow_root || self.allow_sandbox
    }
}

/// Per-turn mutable runtime state shared across tool invocations & `execute_code` RPC calls.
#[derive(Default)]
pub struct TurnRuntimeState {
    /// `(mtime, size)` snapshot captured when `read_file` or a successful edit touches a path.
    read_baselines: StdMutex<HashMap<PathBuf, (Option<SystemTime>, u64)>>,
    /// OpenHands per-file edit snapshot history for `file_editor(command="undo_edit")` & condenser tracking.
    edit_history: EditHistory,
    /// OpenHands structured multi-step plan checklist preserved across context compaction.
    task_tracker: TaskTracker,
    /// Active contract-first target file path and remaining unfilled `<<<AGY_SLOT:id>>>` markers.
    active_slot_target: StdMutex<Option<PathBuf>>,
    open_slots: StdMutex<HashMap<PathBuf, Vec<String>>>,
    /// Set once untrusted external content (`web_search`/`fetch_url`) enters this turn (`airlock`).
    tainted: AtomicBool,
    /// Consecutive `CommandGuard` denials (anti-loop breaker).
    denial_streak: AtomicUsize,
    mcp_calls: AtomicUsize,
    dirty_since_verify: AtomicBool,
}

impl TurnRuntimeState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn update_file_slots(&self, path: &Path, content: &str) {
        let slots = extract_slot_markers_from_text(content);
        if let Ok(mut map) = self.open_slots.lock() {
            if slots.is_empty() {
                map.remove(path);
            } else {
                map.insert(path.to_path_buf(), slots.clone());
            }
        }
        if !slots.is_empty() {
            if let Ok(mut act) = self.active_slot_target.lock() {
                *act = Some(path.to_path_buf());
            }
        }
    }

    pub fn set_active_slot_target(&self, path: &Path) {
        if let Ok(mut act) = self.active_slot_target.lock() {
            *act = Some(path.to_path_buf());
        }
    }

    pub fn active_slot_target(&self) -> Option<PathBuf> {
        self.active_slot_target
            .lock()
            .ok()
            .and_then(|g| g.clone())
            .or_else(|| {
                self.open_slots
                    .lock()
                    .ok()
                    .and_then(|m| m.keys().next().cloned())
            })
    }

    pub fn has_open_slots(&self) -> bool {
        self.open_slots
            .lock()
            .ok()
            .is_some_and(|m| m.values().any(|v| !v.is_empty()))
    }

    pub fn open_slots_snapshot(&self) -> Vec<(PathBuf, Vec<String>)> {
        let mut items: Vec<(PathBuf, Vec<String>)> = self
            .open_slots
            .lock()
            .ok()
            .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
            .unwrap_or_default();
        items.sort_by(|a, b| a.0.cmp(&b.0));
        items
    }

    pub fn open_slots_compact_label(&self) -> String {
        let items = self.open_slots_snapshot();
        if items.is_empty() {
            return String::new();
        }
        let parts: Vec<String> = items
            .into_iter()
            .take(3)
            .map(|(p, slots)| {
                let name = p.file_name().and_then(|s| s.to_str()).unwrap_or("file");
                format!("{name}:[{}]", slots.into_iter().take(4).collect::<Vec<_>>().join(","))
            })
            .collect();
        parts.join("; ")
    }

    pub fn record_edit_snapshot(&self, path: &Path) {
        self.edit_history.record_before_write(path);
    }

    pub fn undo_edit(&self, path: &Path) -> std::result::Result<String, String> {
        self.edit_history.undo_last(path)
    }

    pub fn modified_files(&self) -> Vec<String> {
        self.edit_history.modified_files()
    }

    pub fn task_tracker(&self) -> &TaskTracker {
        &self.task_tracker
    }

    fn record_file_baseline(&self, path: &Path) {
        if let Ok(meta) = std::fs::metadata(path) {
            let sig = (meta.modified().ok(), meta.len());
            if let Ok(mut map) = self.read_baselines.lock() {
                map.insert(path.to_path_buf(), sig);
            }
        }
    }

    /// Returns `Err(reason)` if `path` was previously read during this turn and has since been
    /// modified externally on disk (Hermes read-baseline stale-clobber guard).
    fn check_file_baseline(&self, path: &Path) -> std::result::Result<(), String> {
        let prev = {
            let map = self.read_baselines.lock().ok();
            map.and_then(|m| m.get(path).copied())
        };
        let Some((prev_mtime, prev_len)) = prev else {
            return Ok(());
        };
        if let Ok(meta) = std::fs::metadata(path) {
            let cur_mtime = meta.modified().ok();
            let cur_len = meta.len();
            if cur_mtime != prev_mtime || cur_len != prev_len {
                return Err(format!(
                    "Error: {} changed on disk since you last read it (stale baseline). Call read_file again before overwriting.",
                    path.display()
                ));
            }
        }
        Ok(())
    }

    pub fn mark_tainted(&self) {
        self.tainted.store(true, Ordering::SeqCst);
    }

    pub fn is_tainted(&self) -> bool {
        self.tainted.load(Ordering::SeqCst)
    }

    fn record_denial(&self) -> usize {
        self.denial_streak.fetch_add(1, Ordering::SeqCst) + 1
    }

    fn reset_denials(&self) {
        self.denial_streak.store(0, Ordering::SeqCst);
    }

    fn record_mcp_call(&self) -> usize {
        self.mcp_calls.fetch_add(1, Ordering::SeqCst) + 1
    }

    pub fn reset_mcp_calls(&self) {
        self.mcp_calls.store(0, Ordering::SeqCst);
    }

    pub fn record_file_mutated(&self) {
        self.dirty_since_verify.store(true, Ordering::SeqCst);
    }

    pub fn clear_dirty(&self) {
        self.dirty_since_verify.store(false, Ordering::SeqCst);
    }

    pub fn is_dirty(&self) -> bool {
        self.dirty_since_verify.load(Ordering::SeqCst)
    }
}

/// Compact reasoning/grounding/loop discipline appended to every agent-mode system prompt.
/// Full procedures stay on disk as skills and are pulled on demand via `load_skill`.
pub const AGENT_CORE_DISCIPLINE: &str = "<kernel>\n\
<invariants>\n\
- GROUNDING: every claim MUST cite fresh tool output from this turn; never invent paths/APIs/flags/versions/results.\n\
- CODE: locate -> read exact lines -> smallest reversible patch -> narrowest check -> widen; report cmd + result.\n\
</invariants>\n\
<tool_ladder>\n\
- TIER_0: steps>=3 | log_filter | zip | multi_grep_edit_verify -> execute_code(python3+agy_tools; print() <=4KB).\n\
- TIER_1: batch_read, multi_edit, file_editor, repo_map, verify_project, web_search(strict_ast=false,allow_relax=true), memory_search(tags:[\"tg-<uid>\"]).\n\
- TIER_2: single native read/edit ONLY for trivial 1-file ops or CommandGuard-blocked paths.\n\
</tool_ladder>\n\
<lenses skip_if=\"simple_qa\">\n\
- bug/edit: FIRST_PRINCIPLES(hard constraints) + SKEPTIC(>=1 disconfirming test).\n\
- arch/risky: + PRE_MORTEM(top 2 prod failures+guards) + BUILDER(smallest reversible win) + SECOND_ORDER(KV-cache/tokens/failover/security).\n\
</lenses>\n\
<emergency>\n\
- fail>=2|loop -> STOP identical retry, state stderr, switch hypothesis or undo_edit/git_ops restore (load_skill: loop-escape).\n\
- 429|timeout|0_hits -> narrow scope/batch via execute_code; search fallback strict_ast=false,allow_relax=true.\n\
- skills_on_demand: load_skill(code-change-protocol|grounded-answers|loop-escape|systematic-debugging|verification-before-completion|cognitive-lenses); external: skillhub_search.\n\
</emergency>\n\
</kernel>";

/// Identical tool calls allowed per unchanged workspace state before the third is blocked.
const LOOP_REPEAT_LIMIT: usize = 2;
/// Consecutive failed tool results that trigger a re-plan nudge.
const LOOP_FAIL_STREAK_NUDGE: usize = 4;

fn exit_code_re() -> Option<&'static Regex> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"Exit code: (-?\d+)").ok()).as_ref()
}

/// Consecutive failed tool results before hard escape-hatch triggers.
const LOOP_HARD_FAIL_LIMIT: usize = 6;
/// Consecutive blocked duplicate calls before hard escape-hatch triggers.
const LOOP_HARD_BLOCK_LIMIT: usize = 3;
/// Maximum `call_mcp_tool` invocations per turn (expanded to 50 for deep research & coding).
const MAX_MCP_CALLS_PER_TURN: usize = 50;
/// Consecutive `think`-only monologue calls before OpenHands Pattern 3 triggers.
const LOOP_MONOLOGUE_LIMIT: usize = 4;
/// Repeated context-window overflow errors before OpenHands Pattern 5 triggers.
const LOOP_CONTEXT_ERROR_LIMIT: usize = 2;

/// Consecutive failures on the same (tool, target) family before hard escape-hatch triggers.
const LOOP_FAMILY_FAIL_LIMIT: usize = 3;

/// Runtime OpenHands 5-Pattern StuckDetector + loop guard:
/// 1) Repeating identical calls, 2) Repeating errors/family fails, 3) Agent monologue (`think`-only drift),
/// 4) Alternating ping-pong (A-B-A-B), 5) Repeated context-window errors.
#[derive(Default)]
pub struct LoopGuard {
    seen: HashMap<String, usize>,
    family_fails: HashMap<String, usize>,
    recent_failures: Vec<String>,
    recent_sigs: Vec<String>,
    fail_streak: usize,
    blocked_streak: usize,
    think_streak: usize,
    context_error_count: usize,
    force_escape: bool,
}

impl LoopGuard {
    /// Returns `true` when the agent is stuck in an unrecoverable loop and must wrap up.
    pub fn should_escape(&self) -> bool {
        self.force_escape
    }

    /// OpenHands `StuckDetector.mark_resumed()`: reset streaks after a corrective intervention.
    pub fn mark_resumed(&mut self) {
        self.seen.clear();
        self.family_fails.clear();
        self.recent_sigs.clear();
        self.fail_streak = 0;
        self.blocked_streak = 0;
        self.think_streak = 0;
        self.context_error_count = 0;
        self.force_escape = false;
    }

    /// OpenHands StuckDetector Pattern 5: record a context-window 400/413 overflow error.
    /// Returns `true` once the loop threshold is reached and execution should escape cleanly.
    pub fn record_context_error(&mut self) -> bool {
        self.context_error_count += 1;
        if self.context_error_count >= LOOP_CONTEXT_ERROR_LIMIT {
            self.force_escape = true;
            true
        } else {
            false
        }
    }

    /// Compact summary of recent failures for synthesis / introspection reporting.
    pub fn failure_capture(&self) -> String {
        if self.recent_failures.is_empty() {
            String::new()
        } else {
            format!("Recent failures:\n- {}", self.recent_failures.join("\n- "))
        }
    }

    fn family_key(name: &str, args: &Value) -> String {
        let target = args
            .get("path")
            .or_else(|| args.get("project_dir"))
            .or_else(|| args.get("target_dir"))
            .or_else(|| args.get("server"))
            .and_then(Value::as_str)
            .unwrap_or("*");
        format!("{name}:{target}")
    }

    /// Returns `Some(message)` when this exact call must not run again (duplicate, monologue, or A-B-A-B oscillation).
    pub fn check(&mut self, name: &str, args: &Value) -> Option<String> {
        if name == "think" {
            self.think_streak += 1;
            if self.think_streak >= LOOP_MONOLOGUE_LIMIT {
                self.force_escape = true;
                return Some(format!(
                    "[loop-guard:escape] Agent monologue detected ({} consecutive `think` calls with no action). Execute a concrete tool call or finish now.",
                    self.think_streak
                ));
            }
            return None;
        }
        self.think_streak = 0;

        if matches!(name, "process_manage" | "finish" | "task_tracker") {
            return None; // polling, task tracking, or finishing is never a loop
        }
        let sig = format!("{name}:{}", serde_json::to_string(args).unwrap_or_default());
        self.recent_sigs.push(sig.clone());
        if self.recent_sigs.len() > 6 {
            self.recent_sigs.remove(0);
        }
        // OpenHands StuckDetector Pattern 4: alternating ping-pong (A -> B -> A -> B)
        if self.recent_sigs.len() >= 4 {
            let n = self.recent_sigs.len();
            if self.recent_sigs[n - 1] == self.recent_sigs[n - 3]
                && self.recent_sigs[n - 2] == self.recent_sigs[n - 4]
                && self.recent_sigs[n - 1] != self.recent_sigs[n - 2]
            {
                self.force_escape = true;
                return Some(format!(
                    "[loop-guard:escape] Alternating ping-pong pattern detected on `{name}` (A-B-A-B). Stopping loop to summarize verified state."
                ));
            }
        }
        let count = self.seen.entry(sig).or_insert(0);
        *count += 1;
        if *count > LOOP_REPEAT_LIMIT {
            self.blocked_streak += 1;
            if self.blocked_streak >= LOOP_HARD_BLOCK_LIMIT {
                self.force_escape = true;
            }
            Some(format!(
                "[loop-guard] Identical `{name}` call already ran {LOOP_REPEAT_LIMIT}x with no file change in between; not executed again. \
                 Use the earlier result, change approach, or answer with what you have."
            ))
        } else {
            None
        }
    }

    fn is_failure(output: &str) -> bool {
        let t = output.trim_start();
        if ["Error", "CommandGuard", "Permission denied", "MCP Error", "[loop-guard]", "[status: error]"]
            .iter()
            .any(|p| t.starts_with(p))
        {
            return true;
        }
        let head: String = t.chars().take(200).collect();
        if head.contains("TIMED OUT") {
            return true;
        }
        exit_code_re()
            .and_then(|re| re.captures(&head))
            .and_then(|c| c.get(1))
            .is_some_and(|m| m.as_str() != "0")
    }

    /// Records a tool result with argument context (tracks family-level repeated failures).
    pub fn observe_with_args(&mut self, name: &str, args: &Value, output: String) -> String {
        if Self::is_failure(&output) {
            // External web lookups & third-party MCP servers frequently hit 404/429/daemon locks;
            // never abort coding tasks via force_escape — give a constructive recovery nudge instead.
            if matches!(name, "web_search" | "fetch_url") {
                let fcnt = self.family_fails.entry("web_lookup:*".to_string()).or_insert(0);
                *fcnt += 1;
                if *fcnt >= 2 {
                    return format!(
                        "{output}\n[loop-guard] Web lookup returned an error/404/429. Do NOT keep searching; stop calling web_search/fetch_url and proceed immediately to write and verify the requested code/output file with the information you already have."
                    );
                }
                return output;
            }
            if matches!(name, "call_mcp_tool" | "discover_mcp_tools") {
                let fkey = Self::family_key(name, args);
                let fcnt = self.family_fails.entry(fkey).or_insert(0);
                *fcnt += 1;
                if *fcnt >= 2 {
                    return format!(
                        "{output}\n[loop-guard] MCP server call failed repeatedly. Do NOT keep retrying this failing MCP server; record the observed blocker and proceed immediately with built-in tools or other working servers to complete & save your output file."
                    );
                }
                return output;
            }
            let fkey = Self::family_key(name, args);
            let is_wildcard = fkey.ends_with(":*");
            let fcnt = self.family_fails.entry(fkey.clone()).or_insert(0);
            *fcnt += 1;
            let first_line: String = output.lines().next().unwrap_or("").chars().take(160).collect();
            self.recent_failures.push(format!("{fkey} -> {first_line}"));
            if self.recent_failures.len() > 3 {
                self.recent_failures.remove(0);
            }
            // Wildcard tools (execute_code:*, run_command:*) naturally run iterative test/fix cycles,
            // so allow up to 5 consecutive failures (with a soft re-plan nudge at 3) before hard escape.
            let family_limit = if is_wildcard {
                LOOP_FAMILY_FAIL_LIMIT + 2
            } else {
                LOOP_FAMILY_FAIL_LIMIT
            };
            if *fcnt >= family_limit {
                self.force_escape = true;
            } else if is_wildcard && *fcnt == LOOP_FAMILY_FAIL_LIMIT {
                let nudged = format!(
                    "{output}\n[loop-guard] {name} returned {fcnt} consecutive errors. Inspect the exact error/paths first (e.g. list_dir/glob_files) before retrying so you do not exhaust the escape limit."
                );
                return self.observe(name, nudged);
            }
        } else {
            let fkey = Self::family_key(name, args);
            self.family_fails.remove(&fkey);
        }
        self.observe(name, output)
    }

    /// Records a tool result and returns it, possibly with an appended re-plan nudge or escape trigger.
    pub fn observe(&mut self, name: &str, output: String) -> String {
        if Self::is_failure(&output) {
            self.fail_streak += 1;
            if self.fail_streak >= LOOP_HARD_FAIL_LIMIT {
                self.force_escape = true;
                return format!(
                    "{output}\n[loop-guard:escape] {} consecutive failures reached. Stopping tool execution to report verified findings and blockers honestly.",
                    self.fail_streak
                );
            }
            if self.fail_streak.is_multiple_of(LOOP_FAIL_STREAK_NUDGE) {
                return format!(
                    "{output}\n[loop-guard] {} consecutive failed tool calls. Stop retrying variations: restate the goal and exact error, test a different hypothesis, or report blocked with evidence.",
                    self.fail_streak
                );
            }
        } else {
            self.fail_streak = 0;
            self.blocked_streak = 0;
            if matches!(
                name,
                "write_file" | "patch_file" | "edit_file" | "file_editor" | "multi_edit" | "md_to_code"
            ) {
                self.seen.clear(); // files changed: re-running checks is legitimate again
            }
        }
        output
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct StoredAgentSession {
    #[serde(default)]
    session_id: String,
    #[serde(default)]
    updated_at: i64,
    #[serde(default)]
    messages: Vec<Value>,
}

fn sanitize_session_key(key: &str) -> String {
    let cleaned: String = key
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();
    if cleaned.is_empty() {
        "default".to_string()
    } else {
        cleaned.chars().take(80).collect()
    }
}

pub fn session_file_path(state_dir: &Path, session_key: &str) -> PathBuf {
    state_dir
        .join("agent_sessions")
        .join(format!("{}.json", sanitize_session_key(session_key)))
}

fn load_session(state_dir: &Path, session_key: &str) -> StoredAgentSession {
    let path = session_file_path(state_dir, session_key);
    let mut sess = std::fs::read_to_string(&path)
        .ok()
        .and_then(|raw| serde_json::from_str::<StoredAgentSession>(&raw).ok())
        .unwrap_or_default();
    if sess.session_id.is_empty() {
        sess.session_id = uuid::Uuid::new_v4().to_string();
    }
    sess
}

fn save_session(state_dir: &Path, session_key: &str, sess: &StoredAgentSession) {
    let path = session_file_path(state_dir, session_key);
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Err(err) = atomic_write_json(&path, sess, true) {
        warn!(key = session_key, error = %err, "failed persisting agent session history");
    }
}

/// Clear a persisted agent session history (used on `/new` and panel "Clear session").
pub fn clear_session_history(state_dir: &Path, session_key: &str) -> bool {
    let path = session_file_path(state_dir, session_key);
    if path.exists() {
        std::fs::remove_file(&path).is_ok()
    } else {
        false
    }
}

/// Read the stable conversation UUID for a session (used for Grok `x-grok-conv-id` prompt caching).
pub fn session_conv_id(state_dir: &Path, session_key: &str) -> String {
    load_session(state_dir, session_key).session_id
}

/// Count stored messages in a persisted session (for UI display).
pub fn session_message_count(state_dir: &Path, session_key: &str) -> usize {
    load_session(state_dir, session_key).messages.len()
}

fn truncate_utf8_safe(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_string();
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    format!(
        "{}\n... [truncated, {} bytes total]",
        &s[..end],
        s.len()
    )
}

fn clip_chars(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        s.to_string()
    } else {
        let head: String = s.chars().take(max_chars).collect();
        format!("{head}…")
    }
}

fn prune_session_messages(messages: &mut Vec<Value>) {
    if messages.len() > MAX_SESSION_MESSAGES {
        let drop_n = messages.len() - MAX_SESSION_MESSAGES;
        messages.drain(..drop_n);
    }
    loop {
        let total_bytes: usize = messages
            .iter()
            .map(|m| m.to_string().len())
            .sum();
        if total_bytes <= MAX_SESSION_BYTES || messages.len() <= 2 {
            break;
        }
        messages.remove(0);
    }
}

/// Compact older `role == "tool"` messages inside an active multi-step turn when total payload
/// bytes exceed `budget_bytes`, preserving the system prompt, user turns, and the newest
/// `PRESERVE_RECENT_TOOL_MSGS` tool responses verbatim.
pub fn compact_in_turn_messages(messages: &mut [Value], budget_bytes: usize) -> usize {
    let total: usize = messages.iter().map(|m| m.to_string().len()).sum();
    if total <= budget_bytes {
        return 0;
    }

    let tool_indices: Vec<usize> = messages
        .iter()
        .enumerate()
        .filter_map(|(idx, m)| (m.get("role").and_then(Value::as_str) == Some("tool")).then_some(idx))
        .collect();

    let mut compacted = 0usize;
    let mut current_total = total;
    // Hysteresis low-watermark (65%): compact a full batch once triggered so subsequent steps stay
    // below `budget_bytes` and preserve KV-cache prefix hits instead of thrashing every turn.
    let low_watermark = (budget_bytes * 65) / 100;

    // Pass 1: compact older tool outputs down to low_watermark while keeping newest PRESERVE_RECENT_TOOL_MSGS intact.
    if tool_indices.len() > PRESERVE_RECENT_TOOL_MSGS {
        let compact_upto = tool_indices.len() - PRESERVE_RECENT_TOOL_MSGS;
        for &idx in &tool_indices[..compact_upto] {
            if current_total <= low_watermark {
                break;
            }
            let Some(content) = messages[idx].get("content").and_then(Value::as_str) else {
                continue;
            };
            if content.len() <= 1000 {
                continue;
            }
            let orig_len = content.len();
            let head: String = content.chars().take(400).collect();
            let total_chars = content.chars().count();
            let tail: String = content
                .chars()
                .skip(total_chars.saturating_sub(400))
                .collect();
            let summary = format!(
                "{head}\n... [compacted older tool output: {orig_len} bytes] ...\n{tail}"
            );
            let saved = orig_len.saturating_sub(summary.len());
            messages[idx]["content"] = Value::String(summary);
            current_total = current_total.saturating_sub(saved);
            compacted += 1;
        }
    }

    // Pass 2 (emergency 413 / single-turn overflow): if STILL over budget, trim oversized `tool`
    // payloads first, and only trim `user` payloads if `tool` trimming alone wasn't enough.
    for target_role in ["tool", "user"] {
        if current_total <= budget_bytes {
            break;
        }
        for idx in 0..messages.len() {
            if current_total <= budget_bytes {
                break;
            }
            let role = messages[idx].get("role").and_then(Value::as_str).unwrap_or("");
            if role != target_role {
                continue;
            }
            let Some(content) = messages[idx].get("content").and_then(Value::as_str) else {
                continue;
            };
            if content.len() <= 4_000 {
                continue;
            }
            let orig_len = content.len();
            let keep_each = if budget_bytes <= 20_000 { 800 } else { 1_800 };
            let head: String = content.chars().take(keep_each).collect();
            let total_chars = content.chars().count();
            let tail: String = content
                .chars()
                .skip(total_chars.saturating_sub(keep_each))
                .collect();
            let summary = format!(
                "{head}\n... [compacted oversized {role} payload from {orig_len} bytes to fit context limit] ...\n{tail}"
            );
            let saved = orig_len.saturating_sub(summary.len());
            messages[idx]["content"] = Value::String(summary);
            current_total = current_total.saturating_sub(saved);
            compacted += 1;
        }
    }
    compacted
}

/// Resolve a file/dir path against `cwd`, enforcing canonical workspace containment when `!allow_root`.
fn resolve_tool_path(
    raw_path: &str,
    cwd: &Path,
    workspace_root: &Path,
    allow_root: bool,
    must_exist: bool,
) -> std::result::Result<PathBuf, String> {
    let trimmed = raw_path.trim();
    if trimmed.is_empty() {
        return Err("Error: path must not be empty".to_string());
    }
    let candidate = if Path::new(trimmed).is_absolute() {
        PathBuf::from(trimmed)
    } else {
        cwd.join(trimmed)
    };

    if allow_root {
        return Ok(candidate);
    }

    let canon_ws = std::fs::canonicalize(workspace_root)
        .unwrap_or_else(|_| workspace_root.to_path_buf());

    if must_exist {
        let canon = std::fs::canonicalize(&candidate)
            .map_err(|e| format!("Error resolving path {}: {e}", candidate.display()))?;
        if !canon.starts_with(&canon_ws) {
            return Err(format!(
                "Permission denied: path escapes workspace {} (requires root_access)",
                canon_ws.display()
            ));
        }
        return Ok(canon);
    }

    // For write_file on not-yet-existing targets, canonicalize the deepest existing ancestor.
    let mut probe = candidate.as_path();
    let mut suffix_parts: Vec<std::ffi::OsString> = Vec::new();
    while !probe.exists() {
        if let Some(name) = probe.file_name() {
            suffix_parts.push(name.to_os_string());
        } else {
            return Err("Permission denied: invalid target path".to_string());
        }
        match probe.parent() {
            Some(p) if !p.as_os_str().is_empty() => probe = p,
            _ => return Err("Permission denied: path has no existing parent".to_string()),
        }
    }
    let mut resolved = std::fs::canonicalize(probe)
        .map_err(|e| format!("Error resolving parent {}: {e}", probe.display()))?;
    for part in suffix_parts.into_iter().rev() {
        if part == ".." {
            return Err("Permission denied: '..' not allowed in new file path".to_string());
        }
        resolved.push(part);
    }
    if !resolved.starts_with(&canon_ws) {
        return Err(format!(
            "Permission denied: write path escapes workspace {} (requires root_access)",
            canon_ws.display()
        ));
    }
    Ok(resolved)
}

/// Atomically write UTF-8 text to `path`, preserving existing UNIX file mode if present.
async fn atomic_write_text(path: &Path, content: &str) -> std::result::Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("Invalid target path {}", path.display()))?;
    tokio::fs::create_dir_all(parent)
        .await
        .map_err(|e| format!("Error creating parent dir {}: {e}", parent.display()))?;

    let existing_mode = std::fs::metadata(path)
        .ok()
        .map(|m| m.permissions().mode() & 0o777);

    let tmp_name = format!(
        ".{}.agy-tmp-{}",
        path.file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("file"),
        &uuid::Uuid::new_v4().simple().to_string()[..10]
    );
    let tmp_path = parent.join(tmp_name);

    tokio::fs::write(&tmp_path, content.as_bytes())
        .await
        .map_err(|e| format!("Error writing temp file {}: {e}", tmp_path.display()))?;
    if let Some(mode) = existing_mode {
        let _ = std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(mode));
    }
    if let Err(e) = tokio::fs::rename(&tmp_path, path).await {
        let _ = tokio::fs::remove_file(&tmp_path).await;
        return Err(format!("Error renaming {} into {}: {e}", tmp_path.display(), path.display()));
    }
    Ok(())
}

/// Apply a simple unified diff (`@@ -old,n +new,m @@` hunks) to `existing` in-memory.
fn apply_unified_diff(existing: &str, diff_text: &str) -> std::result::Result<(String, usize), String> {
    let had_trailing_nl = existing.ends_with('\n');
    let mut lines: Vec<String> = existing.lines().map(String::from).collect();
    let diff_lines: Vec<&str> = diff_text.lines().collect();

    let mut i = 0usize;
    let mut hunks_applied = 0usize;
    let mut line_offset: isize = 0;

    while i < diff_lines.len() {
        let l = diff_lines[i];
        if !l.starts_with("@@") {
            i += 1;
            continue;
        }
        // Parse `@@ -start[,count] +start[,count] @@`
        let old_start = l
            .split_whitespace()
            .find(|tok| tok.starts_with('-'))
            .and_then(|tok| tok.trim_start_matches('-').split(',').next())
            .and_then(|num| num.parse::<usize>().ok())
            .ok_or_else(|| format!("Invalid unified diff hunk header: {l}"))?;
        i += 1;

        let mut expected_old: Vec<String> = Vec::new();
        let mut replacement_new: Vec<String> = Vec::new();

        while i < diff_lines.len() && !diff_lines[i].starts_with("@@") {
            let hl = diff_lines[i];
            if hl.starts_with("\\ No newline") {
                i += 1;
                continue;
            }
            if let Some(rest) = hl.strip_prefix(' ') {
                expected_old.push(rest.to_string());
                replacement_new.push(rest.to_string());
            } else if let Some(rest) = hl.strip_prefix('-') {
                expected_old.push(rest.to_string());
            } else if let Some(rest) = hl.strip_prefix('+') {
                replacement_new.push(rest.to_string());
            } else if hl.starts_with("diff ") || hl.starts_with("--- ") || hl.starts_with("+++ ") {
                break;
            } else {
                // Treat unprefixed line as context if benign
                expected_old.push(hl.to_string());
                replacement_new.push(hl.to_string());
            }
            i += 1;
        }

        let target_idx = ((old_start.saturating_sub(1) as isize) + line_offset).max(0) as usize;
        let match_pos = if target_idx + expected_old.len() <= lines.len()
            && lines[target_idx..target_idx + expected_old.len()] == expected_old[..]
        {
            Some(target_idx)
        } else {
            // Search nearby window (+/- 40 lines) for unique match
            let lo = target_idx.saturating_sub(40);
            let hi = (target_idx + 40).min(lines.len().saturating_sub(expected_old.len()));
            let mut found = Vec::new();
            for pos in lo..=hi {
                if pos + expected_old.len() <= lines.len()
                    && lines[pos..pos + expected_old.len()] == expected_old[..]
                {
                    found.push(pos);
                }
            }
            if found.len() == 1 {
                Some(found[0])
            } else {
                None
            }
        };

        let Some(pos) = match_pos else {
            return Err(format!(
                "Error: unified diff hunk #{} at line {old_start} did not match cleanly.",
                hunks_applied + 1
            ));
        };
        let old_len = expected_old.len();
        let new_len = replacement_new.len();
        lines.splice(pos..pos + old_len, replacement_new);
        line_offset += (new_len as isize) - (old_len as isize);
        hunks_applied += 1;
    }

    if hunks_applied == 0 {
        return Err("Error: no valid '@@' unified diff hunks found in 'diff'.".to_string());
    }
    let mut joined = lines.join("\n");
    if had_trailing_nl && !joined.ends_with('\n') {
        joined.push('\n');
    }
    Ok((joined, hunks_applied))
}

/// Unique fuzzy whitespace-trimmed line-block matcher (fallback when exact substring fails).
fn fuzzy_trimmed_line_replace(
    existing: &str,
    target: &str,
    replacement: &str,
) -> Option<String> {
    let file_lines: Vec<&str> = existing.lines().collect();
    let target_lines: Vec<&str> = target.lines().map(str::trim).collect();
    if target_lines.is_empty() || target_lines.len() > file_lines.len() {
        return None;
    }
    let mut match_starts = Vec::new();
    for start in 0..=file_lines.len() - target_lines.len() {
        let all_match = target_lines
            .iter()
            .enumerate()
            .all(|(off, tl)| file_lines[start + off].trim() == *tl);
        if all_match {
            match_starts.push(start);
        }
    }
    if match_starts.len() != 1 {
        return None;
    }
    let start = match_starts[0];
    let mut out_lines: Vec<String> = file_lines[..start].iter().map(|s| (*s).to_string()).collect();
    for rline in replacement.lines() {
        out_lines.push(rline.to_string());
    }
    out_lines.extend(
        file_lines[start + target_lines.len()..]
            .iter()
            .map(|s| (*s).to_string()),
    );
    let mut joined = out_lines.join("\n");
    if existing.ends_with('\n') && !joined.ends_with('\n') {
        joined.push('\n');
    }
    Some(joined)
}

/// Suggest up to 5 likely matching source lines when `patch_file` / `multi_edit` reports `target not found`.
fn find_nearest_lines_hint(existing: &str, target: &str) -> String {
    let mut tokens: Vec<String> = target
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .filter(|s| s.len() >= 3)
        .map(|s| s.to_ascii_lowercase())
        .collect();
    tokens.sort();
    tokens.dedup();
    if tokens.is_empty() {
        return String::new();
    }
    let mut scored: Vec<(usize, usize, String)> = Vec::new();
    for (idx, line) in existing.lines().enumerate() {
        let low = line.to_ascii_lowercase();
        let hits = tokens.iter().filter(|tok| low.contains(tok.as_str())).count();
        if hits > 0 {
            scored.push((hits, idx + 1, clip_chars(line.trim(), 120)));
        }
    }
    if scored.is_empty() {
        return String::new();
    }
    scored.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    let lines: Vec<String> = scored
        .into_iter()
        .take(5)
        .map(|(_, ln, txt)| format!("  L{ln}: {txt}"))
        .collect();
    format!("\nNearest matching lines:\n{}", lines.join("\n"))
}

fn slot_marker_re() -> Option<&'static Regex> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"<<<AGY_SLOT:([A-Za-z0-9_.-]+)>>>").ok())
        .as_ref()
}

/// Extract ordered unique `<<<AGY_SLOT:id>>>` marker identifiers present in `text`.
pub fn extract_slot_markers_from_text(text: &str) -> Vec<String> {
    let Some(re) = slot_marker_re() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for cap in re.captures_iter(text) {
        if let Some(m) = cap.get(1) {
            let id = m.as_str().to_string();
            if !out.contains(&id) {
                out.push(id);
            }
        }
    }
    out
}

/// Deterministically splice a named chunk (`slot_name` -> `code`) into a skeleton file containing
/// `# <<<AGY_SLOT:id>>>`, `// <<<AGY_SLOT:id>>>`, `/* <<<AGY_SLOT:id>>> */`, or bare `<<<AGY_SLOT:id>>>`.
/// Preserves marker line indentation cleanly when chunk lines are unindented.
pub fn splice_slot_into_text(
    existing: &str,
    slot_name: &str,
    code: &str,
) -> std::result::Result<(String, Vec<String>), String> {
    let needle = format!("<<<AGY_SLOT:{slot_name}>>>");
    let lines: Vec<&str> = existing.lines().collect();
    let hit_indices: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter_map(|(i, l)| l.contains(&needle).then_some(i))
        .collect();

    if hit_indices.is_empty() {
        let avail = extract_slot_markers_from_text(existing);
        return Err(if avail.is_empty() {
            format!("Error: slot '{slot_name}' not found and file has no remaining `<<<AGY_SLOT:...>>>` markers.")
        } else {
            format!(
                "Error: slot '{slot_name}' not found. Remaining slot(s) in file: [{}].",
                avail.join(", ")
            )
        });
    }
    if hit_indices.len() > 1 {
        return Err(format!(
            "Error: slot '{slot_name}' appears multiple times ({} occurrences); slot names must be unique.",
            hit_indices.len()
        ));
    }

    let line_idx = hit_indices[0];
    let marker_line = lines[line_idx];
    let indent: String = marker_line
        .chars()
        .take_while(|c| *c == ' ' || *c == '\t')
        .collect();

    let norm_code = code.replace("\r\n", "\n");
    let trimmed_code = norm_code.trim_matches('\n');
    let first_non_empty = trimmed_code.lines().find(|l| !l.trim().is_empty());
    let needs_indent = !indent.is_empty()
        && first_non_empty.is_some_and(|l| !l.starts_with(' ') && !l.starts_with('\t'));

    let replacement_lines: Vec<String> = if trimmed_code.is_empty() {
        Vec::new()
    } else {
        trimmed_code
            .lines()
            .map(|l| {
                if !needs_indent || l.trim().is_empty() {
                    l.to_string()
                } else {
                    format!("{indent}{l}")
                }
            })
            .collect()
    };

    let mut out_lines: Vec<String> = Vec::with_capacity(lines.len() + replacement_lines.len());
    for l in &lines[..line_idx] {
        out_lines.push((*l).to_string());
    }
    out_lines.extend(replacement_lines);
    for l in &lines[line_idx + 1..] {
        out_lines.push((*l).to_string());
    }
    let mut joined = out_lines.join("\n");
    if existing.ends_with('\n') && !joined.ends_with('\n') {
        joined.push('\n');
    }
    let remaining = extract_slot_markers_from_text(&joined);
    Ok((joined, remaining))
}

/// Run a fast (< 200ms) syntax diagnostic check for common languages (`json`, `py`, `js`/`mjs`, `sh`)
/// so `write_file`/`patch_file` immediately surfaces newly introduced syntax errors (Hermes LSP spirit).
async fn fast_syntax_check(path: &Path, text: &str) -> Option<String> {
    let ext = path
        .extension()
        .and_then(|s| s.to_str())
        .map(|s| s.to_ascii_lowercase())?;

    if ext == "json" {
        return serde_json::from_str::<Value>(text)
            .err()
            .map(|e| format!("JSON syntax error: {e}"));
    }

    let (bin, args): (&str, Vec<String>) = match ext.as_str() {
        "py" => (
            "python3",
            vec![
                "-c".into(),
                "import ast, sys; ast.parse(open(sys.argv[1], 'rb').read(), filename=sys.argv[1])".into(),
                path.to_string_lossy().into_owned(),
            ],
        ),
        "php" => ("php", vec!["-l".into(), path.to_string_lossy().into_owned()]),
        "js" | "mjs" | "cjs" => ("node", vec!["--check".into(), path.to_string_lossy().into_owned()]),
        "sh" | "bash" => ("bash", vec!["-n".into(), path.to_string_lossy().into_owned()]),
        _ => return None,
    };

    let mut cmd = Command::new(bin);
    cmd.args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    scrub_command_env(&mut cmd);

    let output = tokio::time::timeout(Duration::from_millis(1500), cmd.output())
        .await
        .ok()?
        .ok()?;
    if output.status.success() {
        None
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let combined = if stderr.trim().is_empty() {
            stdout.trim().to_string()
        } else if stdout.trim().is_empty() {
            stderr.trim().to_string()
        } else {
            format!("{}\n{}", stderr.trim(), stdout.trim())
        };
        if combined.is_empty() {
            None
        } else {
            Some(clip_chars(&combined, 450))
        }
    }
}

/// Variant of `fast_syntax_check` used on files still containing active `<<<AGY_SLOT:...>>>` markers:
/// for Python, replaces unfilled `# <<<AGY_SLOT:...>>>` marker lines with `<indent>pass` in memory
/// so partial class/function skeletons don't trigger false `IndentationError` warnings mid-assembly.
async fn fast_syntax_check_slotted(path: &Path, text: &str) -> Option<String> {
    let ext = path
        .extension()
        .and_then(|s| s.to_str())
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();
    if ext != "py" || extract_slot_markers_from_text(text).is_empty() {
        return fast_syntax_check(path, text).await;
    }

    let mut stubbed = String::with_capacity(text.len() + 32);
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(after_hash) = trimmed.strip_prefix('#') {
            if after_hash.trim_start().starts_with("<<<AGY_SLOT:") {
                let indent_len = line.len() - line.trim_start().len();
                stubbed.push_str(&line[..indent_len]);
                stubbed.push_str("pass\n");
                continue;
            }
        }
        stubbed.push_str(line);
        stubbed.push('\n');
    }

    let mut cmd = Command::new("python3");
    cmd.args([
        "-c",
        "import ast, sys; ast.parse(sys.stdin.read(), filename=sys.argv[1])",
        &path.to_string_lossy(),
    ])
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .kill_on_drop(true);
    scrub_command_env(&mut cmd);
    let Ok(mut child) = cmd.spawn() else {
        return None;
    };
    if let Some(mut stdin) = child.stdin.take() {
        use tokio::io::AsyncWriteExt;
        let _ = stdin.write_all(stubbed.as_bytes()).await;
        drop(stdin);
    }
    let output = tokio::time::timeout(Duration::from_millis(1500), child.wait_with_output())
        .await
        .ok()?
        .ok()?;
    if output.status.success() {
        None
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        if stderr.is_empty() {
            None
        } else {
            Some(clip_chars(&stderr, 450))
        }
    }
}

/// Detect lazy LLM truncation/omission placeholder lines inside generated code files.
fn detect_lazy_code_placeholders(text: &str) -> Option<&'static str> {
    const MARKERS: &[&str] = &[
        "// ... existing",
        "// ... rest",
        "// rest of the code",
        "// rest of code unchanged",
        "// existing code unchanged",
        "// same as before",
        "/* ... rest",
        "/* ... existing",
        "# ... rest of",
        "# ... unchanged",
        "// todo: implement",
    ];
    for line in text.lines() {
        let low = line.trim().to_ascii_lowercase();
        for &m in MARKERS {
            if low.contains(m) {
                return Some(m);
            }
        }
    }
    None
}

/// Return the number of tools exposed in `agent_tools_schema_for(allow_root, allow_sandbox)`.
pub fn agent_tool_count(allow_root: bool, allow_sandbox: bool) -> usize {
    agent_tools_schema_for(allow_root, allow_sandbox).len()
}

/// Build the OpenAI-compatible JSON schema for the autonomous server toolset (compat wrapper).
pub fn agent_tools_schema(allow_root: bool) -> Vec<Value> {
    agent_tools_schema_for(allow_root, allow_root)
}

/// Build the OpenAI-compatible JSON schema for `allow_root` and/or `allow_sandbox` capabilities.
pub fn agent_tools_schema_for(allow_root: bool, allow_sandbox: bool) -> Vec<Value> {
    let mut tools = Vec::new();
    let can_exec = allow_root || allow_sandbox;

    if can_exec {
        let exec_note = if allow_root {
            "Execute a bash command on the Ubuntu server (zero-SIGPIPE head+tail capture, timeout up to 600s, partial output preserved on timeout). Set background=true or pty=true to launch a persistent tmux PTY session managed via process_manage, or sandbox=true to isolate untrusted code in bubblewrap."
        } else {
            "Execute a bash command inside an isolated Linux bubblewrap sandbox (read-write ONLY inside workspace, no host secrets, timeout up to 600s). Set background=true or pty=true for persistent tmux PTY builds/servers."
        };
        tools.push(json!({
            "type": "function",
            "function": {
                "name": "run_command",
                "description": exec_note,
                "parameters": {
                    "type": "object",
                    "properties": {
                        "command": { "type": "string", "description": "Shell command to run via bash -c" },
                        "timeout_secs": { "type": "integer", "description": "Timeout in seconds (default 60, max 600)" },
                        "background": { "type": "boolean", "description": "Run detached in a persistent tmux PTY session (returns session_id)" },
                        "pty": { "type": "boolean", "description": "Allocate an interactive tmux PTY (implies background session)" },
                        "session_name": { "type": "string", "description": "Optional short name for the background/PTY session" },
                        "sandbox": { "type": "boolean", "description": "Force Linux bubblewrap sandbox isolation even with root_access" }
                    },
                    "required": ["command"]
                }
            }
        }));
        tools.push(json!({
            "type": "function",
            "function": {
                "name": "process_manage",
                "description": "Manage persistent tmux PTY and background processes started with run_command(background=true/pty=true).",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "action": {
                            "type": "string",
                            "enum": ["list", "poll", "wait", "log", "write", "kill"],
                            "description": "Action to perform on background/PTY sessions"
                        },
                        "session_id": { "type": "string", "description": "Session ID (required for poll/wait/log/write/kill)" },
                        "input": { "type": "string", "description": "Text to send when action='write'" },
                        "send_enter": { "type": "boolean", "description": "Press Enter after input (default true)" },
                        "ctrl_c": { "type": "boolean", "description": "Send Ctrl-C interrupt before input" },
                        "lines": { "type": "integer", "description": "Lines of terminal output to capture (default 100, max 400)" },
                        "timeout_secs": { "type": "integer", "description": "Wait timeout in seconds for action='wait' (default 30, max 180)" }
                    },
                    "required": ["action"]
                }
            }
        }));
        tools.push(json!({
            "type": "function",
            "function": {
                "name": "execute_code",
                "description": "Programmatic Tool Calling (OpenHands/CodeAct): run a Python 3 script importing `agy_tools` (22 RPC tools: `read_file`, `write_file`, `patch_file`, `file_editor`, `list_dir`, `glob_files`, `grep_files`, `find_symbols`, `git_ops`, `run_command`, `process_manage`, `verify_project`, `code_to_md`, `md_to_code`, `inspect_image`, `web_search`, `fetch_url`, `memory_search`, `memory_store`, `call_mcp_tool`, `task_tracker`) over a local Unix socket RPC (up to 150 calls in ONE turn, timeout up to 300s). Only print() enters context.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "code": { "type": "string", "description": "Python 3 script importing agy_tools and printing a concise summary" },
                        "timeout_secs": { "type": "integer", "description": "Timeout in seconds (default 60, max 300)" },
                        "allow_network": { "type": "boolean", "description": "Allow outbound network in script (default true for root_access, false in sandbox)" }
                    },
                    "required": ["code"]
                }
            }
        }));
    }

    tools.extend([
        json!({
            "type": "function",
            "function": {
                "name": "read_file",
                "description": "Read a text file with optional 1-based line range (also records read baseline for safe editing).",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": { "type": "string", "description": "File path (relative to cwd or absolute)" },
                        "start_line": { "type": "integer", "description": "1-based start line (default 1)" },
                        "end_line": { "type": "integer", "description": "1-based inclusive end line (optional)" }
                    },
                    "required": ["path"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "batch_read",
                "description": "Read up to 20 files or line ranges concurrently in ONE single tool call (records read baselines for every file; huge speedup over sequential read_file).",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "files": {
                            "type": "array",
                            "description": "List of file requests: either path strings or objects {path, start_line?, end_line?}",
                            "items": {
                                "anyOf": [
                                    { "type": "string" },
                                    {
                                        "type": "object",
                                        "properties": {
                                            "path": { "type": "string" },
                                            "start_line": { "type": "integer" },
                                            "end_line": { "type": "integer" }
                                        },
                                        "required": ["path"]
                                    }
                                ]
                            }
                        }
                    },
                    "required": ["files"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "multi_edit",
                "description": "Apply up to 25 surgical text edits across one or more files in ONE tool call (records EditHistory snapshots for undo_edit, checks baselines, writes atomically, and runs syntax checks).",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "edits": {
                            "type": "array",
                            "description": "Ordered list of edits: {path, target, replacement, replace_all?}",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "path": { "type": "string" },
                                    "target": { "type": "string" },
                                    "replacement": { "type": "string" },
                                    "replace_all": { "type": "boolean" }
                                },
                                "required": ["path", "target", "replacement"]
                            }
                        }
                    },
                    "required": ["edits"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "write_file",
                "description": "Atomically create, overwrite, or append (append=true) to a UTF-8 file (checks read baseline and runs fast syntax check).",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": { "type": "string", "description": "Target file path" },
                        "content": { "type": "string", "description": "File contents (or chunk to append when append=true)" },
                        "append": { "type": "boolean", "description": "Append content to end of file instead of overwriting (default false; useful for writing very large files in chunks)" }
                    },
                    "required": ["path", "content"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "patch_file",
                "description": "Safely edit an existing file via unique target/replacement (with fuzzy line fallback and replace_all option) OR unified diff (`diff`), using atomic write and fast differential syntax diagnostics.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": { "type": "string", "description": "Existing file path" },
                        "target": { "type": "string", "description": "Exact unique existing text to replace" },
                        "replacement": { "type": "string", "description": "Replacement text" },
                        "replace_all": { "type": "boolean", "description": "Replace all occurrences (default false; refuses ambiguous >1 matches otherwise)" },
                        "diff": { "type": "string", "description": "Alternative to target/replacement: unified diff (`@@ -old +new @@`) hunks" }
                    },
                    "required": ["path"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "list_dir",
                "description": "List entries (files and subdirectories with sizes) in a directory.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": { "type": "string", "description": "Directory path (default '.')" }
                    }
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "file_editor",
                "description": "OpenHands str_replace_editor: view (line range), create, str_replace (unique/fuzzy), insert (at 0-based line number), or undo_edit (revert last edit to this file).",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "command": { "type": "string", "enum": ["view", "create", "str_replace", "insert", "undo_edit"], "description": "Editor operation" },
                        "path": { "type": "string", "description": "Target file path" },
                        "view_range": { "type": "array", "items": { "type": "integer" }, "description": "Optional [start_line, end_line] for command='view' (1-based; -1 for EOF)" },
                        "file_text": { "type": "string", "description": "Full file text for command='create'" },
                        "old_str": { "type": "string", "description": "Exact existing text for command='str_replace'" },
                        "new_str": { "type": "string", "description": "Replacement text for 'str_replace' or inserted text for 'insert'" },
                        "insert_line": { "type": "integer", "description": "Line number after which to insert (0 = top of file) for command='insert'" },
                        "replace_all": { "type": "boolean", "description": "Replace all occurrences for command='str_replace' (default false)" }
                    },
                    "required": ["command", "path"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "glob_files",
                "description": "Fast recursive file discovery by glob pattern (e.g. '**/*.rs', 'src/*.{ts,tsx}', 'test_*.py'), automatically skipping .git/target/node_modules/.venv.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "pattern": { "type": "string", "description": "Glob pattern (supports *, ?, **, {a,b})" },
                        "path": { "type": "string", "description": "Root directory to search (default '.')" },
                        "max_results": { "type": "integer", "description": "Max files to return (default 100, max 300)" }
                    },
                    "required": ["pattern"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "find_symbols",
                "description": "Fast multi-language code symbol indexer (Rust, Python, TS/JS, Go, PHP, Java, C/C++, Ruby, Shell): locates functions, structs, classes, traits, impls, interfaces with file:line.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "query": { "type": "string", "description": "Optional substring filter on symbol declaration line" },
                        "path": { "type": "string", "description": "Directory or file to scan (default '.')" },
                        "file_glob": { "type": "string", "description": "Optional file glob filter (e.g. '*.rs', 'src/**/*.py')" },
                        "max_results": { "type": "integer", "description": "Max symbols to return (default 100, max 200)" }
                    }
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "git_ops",
                "description": "First-class Git workflow tool: inspect status, diff (staged/stat/path), log, branches, create a safe stash checkpoint, or restore a single file.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "action": { "type": "string", "enum": ["status", "diff", "log", "branch", "checkpoint", "restore"], "description": "Git operation" },
                        "path": { "type": "string", "description": "Optional file path for diff or required path for restore" },
                        "staged": { "type": "boolean", "description": "Show staged diff (default false)" },
                        "stat": { "type": "boolean", "description": "Show --stat summary for diff (default false)" },
                        "limit": { "type": "integer", "description": "Commit count for log (default 15, max 50)" },
                        "message": { "type": "string", "description": "Label for action='checkpoint'" }
                    },
                    "required": ["action"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "task_tracker",
                "description": "OpenHands structured task planner & milestone tracker (preserved across context compaction). Use command='plan' to set tasks, 'update' to change one task's status/notes, or 'view' to inspect.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "command": { "type": "string", "enum": ["view", "plan", "update"], "description": "Tracker action" },
                        "task_list": {
                            "type": "array",
                            "description": "Full task list for command='plan'",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "id": { "type": "string" },
                                    "title": { "type": "string" },
                                    "status": { "type": "string", "enum": ["todo", "in_progress", "done", "blocked"] },
                                    "notes": { "type": "string" }
                                },
                                "required": ["title"]
                            }
                        },
                        "id": { "type": "string", "description": "Task id for command='update'" },
                        "status": { "type": "string", "enum": ["todo", "in_progress", "done", "blocked"], "description": "New status for command='update'" },
                        "notes": { "type": "string", "description": "Optional notes for command='update'" }
                    },
                    "required": ["command"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "grep_files",
                "description": "Search recursively for a text or regex pattern across files in a directory (supports glob filter, context_lines, and case_sensitive).",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "pattern": { "type": "string", "description": "Text or regex pattern" },
                        "path": { "type": "string", "description": "Directory or file to search (default '.')" },
                        "glob": { "type": "string", "description": "Optional file glob filter (e.g. '*.rs', '*.py')" },
                        "context_lines": { "type": "integer", "description": "Lines of surrounding context (0..5, default 0)" },
                        "case_sensitive": { "type": "boolean", "description": "Case-sensitive search (default false)" }
                    },
                    "required": ["pattern"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "web_search",
                "description": "Search the live web using the local search-v3 hybrid federated search MCP (supports Google/Yahoo/DDG/SearXNG and Boolean dorks).",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "query": { "type": "string", "description": "Search query or Boolean dork" },
                        "profile": { "type": "string", "description": "Engine profile: hybrid (default), fast, direct, api, all" },
                        "limit": { "type": "integer", "description": "Max results (default 10)" },
                        "strict_ast": { "type": "boolean", "description": "Strict snippet AST match (default false for broader recall; true for exact dorks)" },
                        "allow_relax": { "type": "boolean", "description": "Auto-relax query on zero results (default true)" }
                    },
                    "required": ["query"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "fetch_url",
                "description": "Fetch and read a webpage, JSON API, or GitHub README using search-v3 BoringSSL fetcher.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "url": { "type": "string", "description": "http(s) URL to fetch" },
                        "max_chars": { "type": "integer", "description": "Max chars to return (default 12000)" }
                    },
                    "required": ["url"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "list_mcp_servers",
                "description": "List available MCP servers configured on this machine.",
                "parameters": { "type": "object", "properties": {} }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "call_mcp_tool",
                "description": "Invoke any tool on a configured stdio MCP server (uses warm persistent MCP pool; e.g. search-v3, ai-memory, graphify, context7, skillport, skills-catalog).",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "server": { "type": "string", "description": "MCP server name" },
                        "tool": { "type": "string", "description": "Tool name on that MCP server" },
                        "arguments": { "type": "object", "description": "JSON arguments object" },
                        "timeout_secs": { "type": "integer", "description": "Optional timeout in seconds (default 30, max 300)" }
                    },
                    "required": ["server", "tool"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "memory_search",
                "description": "Search durable cross-session AI-Memory for past decisions, preferences, and context.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "query": { "type": "string", "description": "Search query" },
                        "limit": { "type": "integer", "description": "Max results (default 5)" },
                        "tags": { "type": "array", "items": { "type": "string" }, "description": "Optional tag filter (note: ai-memory matches ANY tag; pass a single user tag like [\"tg-<uid>\"] for isolation)" }
                    },
                    "required": ["query"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "search_skills",
                "description": "Search local SkillPort library for procedural skills (use 1-3 short keywords).",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "query": { "type": "string", "description": "Short keyword query" }
                    },
                    "required": ["query"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "skillhub_search",
                "description": "Search the local Claude Code ecosystem hub (Superpowers, Anthropic skills, ECC, wshobson, Matt Pocock, VoltAgent, Composio, system prompts). Syntax: terms, +must, -not, \"phrase\", /regex/i, prefix*, fuzzy~ / fuzzy~2, name:/desc:/tag:/body:/source:/kind:skill|agent|command|rule|prompt|doc/path: (including name:/regex/ and name:\"phrase\"), lines:<200, chars:>1000, tokens:<1500, sort:-lines, dedup:off.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "query": { "type": "string", "description": "Search query" },
                        "limit": { "type": "integer", "description": "Max hits (default 10, max 50)" }
                    },
                    "required": ["query"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "skillhub_catalog",
                "description": "Browse the Skill Hub ecosystem roster (Superpowers, Anthropic skills, source/kind matrix) or list paginated entries filtered by source and/or kind.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "source": { "type": "string", "description": "Optional source id (e.g. superpowers, anthropic-skills, ecc, mattpocock-skills, wshobson-agents)" },
                        "kind": { "type": "string", "description": "Optional kind: skill, agent, command, rule, prompt, or doc" },
                        "offset": { "type": "integer", "description": "Pagination offset (default 0)" },
                        "limit": { "type": "integer", "description": "Max items (default 50, max 200)" }
                    }
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "skillhub_get",
                "description": "Read a skill hub document by id (from skillhub_search/skillhub_catalog) or exact name. Supports reading specific sections or line ranges.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "id": { "type": "string", "description": "Document id or name" },
                        "max_chars": { "type": "integer", "description": "Default 20000" },
                        "start_line": { "type": "integer", "description": "Optional 1-based start line" },
                        "end_line": { "type": "integer", "description": "Optional 1-based end line" },
                        "section": { "type": "string", "description": "Optional markdown heading name to extract" }
                    },
                    "required": ["id"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "load_skill",
                "description": "Load a skill's SKILL.md instructions by slug or skillport ID.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "skill_id": { "type": "string", "description": "Skill slug or SkillPort ID" }
                    },
                    "required": ["skill_id"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "code_to_md",
                "description": "Convert a code file, directory, or .zip archive into a structured .md bundle with directory tree, folder-to-file map, symbol map (functions/structs/classes), and syntax-highlighted code blocks. Essential for inspecting .zip projects or preparing codebases for Venice API.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": { "type": "string", "description": "Path to a .zip archive, directory, or file" },
                        "output_path": { "type": "string", "description": "Optional .md file path to save the full bundle" },
                        "include_extensions": { "type": "array", "items": { "type": "string" }, "description": "Optional extension filter (e.g. [\"rs\", \"py\"])" },
                        "exclude_patterns": { "type": "array", "items": { "type": "string" }, "description": "Optional path/name substrings to exclude" },
                        "include_line_numbers": { "type": "boolean", "description": "Include line numbers in code blocks (default true)" },
                        "include_symbols": { "type": "boolean", "description": "Include symbol/structure map (default true)" }
                    },
                    "required": ["path"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "md_to_code",
                "description": "Unpack/apply file blocks from a structured .md bundle (### `rel/path` + fenced code) safely onto disk, updating only files present in the markdown without touching unrelated files.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target_dir": { "type": "string", "description": "Project root directory to write files into" },
                        "markdown": { "type": "string", "description": "Markdown content containing ### `path` code blocks (or provide markdown_path)" },
                        "markdown_path": { "type": "string", "description": "Path to a .md file to unpack instead of inline markdown" },
                        "dry_run": { "type": "boolean", "description": "Preview changes without writing to disk (default false)" }
                    },
                    "required": ["target_dir"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "verify_project",
                "description": "Auto-detect project toolchain (Rust/Python/TS/Go/PHP/Bash) or run custom checks with timeout, returning PASS or a structured errors.md with source context around every error line.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "project_dir": { "type": "string", "description": "Project root directory to verify" },
                        "commands": { "type": "array", "items": { "type": "string" }, "description": "Optional custom shell check commands (auto-detected if omitted)" },
                        "run_tests": { "type": "boolean", "description": "Also run unit tests if detected (default false)" },
                        "timeout_secs": { "type": "integer", "description": "Timeout per check in seconds (default 45, max 300)" },
                        "errors_md_path": { "type": "string", "description": "Optional path to save errors.md" }
                    },
                    "required": ["project_dir"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "inspect_image",
                "description": "Analyze a local image file (.png, .jpg, .webp, .gif) using Venice multimodal vision.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": { "type": "string", "description": "Path to the image file" },
                        "question": { "type": "string", "description": "What to inspect or extract from the image (default: describe in detail)" },
                        "model": { "type": "string", "description": "Optional vision-capable uncensored model ID" }
                    },
                    "required": ["path"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "discover_mcp_tools",
                "description": "Query a configured MCP server's live tools/list catalog to inspect exact tool names, descriptions, and required parameters before calling call_mcp_tool. Pass server=\"all\" to list enabled servers and summaries.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "server": { "type": "string", "description": "MCP server name (e.g. 'openhands', 'graphify', 'gortex', 'context7', 'search-v3', 'ai-memory') or 'all'" },
                        "filter": { "type": "string", "description": "Optional substring filter on tool name/description" }
                    },
                    "required": ["server"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "repo_map",
                "description": "Generate an Aider-style .gitignore-aware structural Repository Map of a directory (files, line counts, classes/structs/traits/functions ranked by structural density) in ONE fast call.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": { "type": "string", "description": "Root directory to map (default '.')" },
                        "max_files": { "type": "integer", "description": "Maximum files to include (default 60, max 200)" },
                        "max_chars": { "type": "integer", "description": "Maximum output chars (default 14000, max 30000)" }
                    }
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "diff_files",
                "description": "Compute a unified Myers diff AND executable non-comment diff stats between two local files (e.g. original attached file vs edited outbox file) for hunk-by-hunk self-review before finishing.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "original_path": { "type": "string", "description": "Path to the original/baseline file" },
                        "modified_path": { "type": "string", "description": "Path to the modified/output file" },
                        "context_lines": { "type": "integer", "description": "Unified diff context lines (default 3, max 10)" }
                    },
                    "required": ["original_path", "modified_path"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "assemble_slots",
                "description": "Deterministically splice chunked code into a skeleton file containing `# <<<AGY_SLOT:id>>>` / `// <<<AGY_SLOT:id>>>` markers across 3-10 turns, preventing truncation and standalone snippets while validating syntax after EVERY chunk.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "command": {
                            "type": "string",
                            "enum": ["replace", "status", "finalize"],
                            "description": "Action: 'replace' (default, splice slot chunk), 'status' (list remaining slots), or 'finalize' (assert 0 remaining slots & run syntax check)"
                        },
                        "path": { "type": "string", "description": "Target skeleton file path (defaults to current active slotted file)" },
                        "slot": { "type": "string", "description": "Slot marker ID (matches `<<<AGY_SLOT:id>>>`) for command='replace'" },
                        "code": { "type": "string", "description": "Integrated code body for this slot (no standalone imports/boilerplate)" },
                        "slots": {
                            "type": "array",
                            "description": "Optional batch list of slot replacements [{slot, code}]",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "slot": { "type": "string" },
                                    "code": { "type": "string" }
                                },
                                "required": ["slot", "code"]
                            }
                        }
                    }
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "think",
                "description": "Log an internal reasoning/planning thought without executing commands or modifying files. Use after reading errors/tests to compare hypotheses before editing.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "thought": { "type": "string", "description": "Your structured reasoning or plan" }
                    },
                    "required": ["thought"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "finish",
                "description": "Explicitly signal task completion (or honest blocker) with the final verified summary for the user.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "message": { "type": "string", "description": "Final verified answer or blocker report" }
                    },
                    "required": ["message"]
                }
            }
        }),
    ]);

    if allow_root {
        tools.push(json!({
            "type": "function",
            "function": {
                "name": "memory_store",
                "description": "Store a durable fact, decision, or preference in AI-Memory (never store secrets).",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "title": { "type": "string", "description": "Short title (<= 180 chars)" },
                        "summary": { "type": "string", "description": "Concise summary (<= 200 chars)" },
                        "type": { "type": "string", "description": "fact, decision, preference, insight, error, or context" },
                        "tags": { "type": "array", "items": { "type": "string" }, "description": "Tags list" }
                    },
                    "required": ["title", "summary"]
                }
            }
        }));
    }

    tools
}

pub(crate) async fn invoke_configured_mcp(
    mcp_config_path: &Path,
    server_name: &str,
    tool_name: &str,
    arguments: Value,
    timeout_secs: f64,
    allow_root: bool,
) -> String {
    if !allow_root && !NON_ROOT_ALLOWED_MCPS.contains(&server_name) {
        return format!(
            "Permission denied: calling MCP server '{server_name}' requires root_access."
        );
    }
    let srv_opt = match get_mcp_server_raw(mcp_config_path, server_name) {
        Ok(s) => s,
        Err(e) => return format!("Error reading MCP config: {}", redact_secrets_in_text(&e.to_string())),
    };
    let Some(srv) = srv_opt else {
        return format!("Error: MCP server '{server_name}' not found in configuration.");
    };
    if !srv.enabled {
        return format!("Error: MCP server '{server_name}' is currently disabled.");
    }
    if srv.server_type != "stdio" || srv.command.is_empty() {
        return format!(
            "Error: MCP server '{server_name}' is type '{}' (only stdio MCP servers can be invoked directly).",
            srv.server_type
        );
    }

    let mut cmd_vec = vec![srv.command.clone()];
    cmd_vec.extend(srv.args.clone());
    let env_map: HashMap<String, String> = srv.env.into_iter().collect();
    let env_opt = (!env_map.is_empty()).then_some(&env_map);

    match global_mcp_pool()
        .call_pooled_stdio_mcp_cmd(&cmd_vec, tool_name, arguments, env_opt, timeout_secs)
        .await
    {
        Ok(val) => {
            let txt = match val {
                Value::String(s) => s,
                other => serde_json::to_string_pretty(&other).unwrap_or_else(|_| other.to_string()),
            };
            compact_tool_output(&redact_secrets_in_text(&txt), active_tool_output_cap())
        }
        Err(e) => format!(
            "MCP Error ({server_name}:{tool_name}): {}",
            redact_secrets_in_text(&e.to_string())
        ),
    }
}

/// Inspect live tools & parameter schemas exposed by a configured stdio MCP server (`server` or `"all"`).
async fn discover_configured_mcp_tools(
    mcp_config_path: &Path,
    server: &str,
    filter: Option<&str>,
    allow_root: bool,
) -> String {
    if server.eq_ignore_ascii_case("all") {
        let Ok(srvs) = list_mcp_servers(mcp_config_path) else {
            return "Error reading MCP config.".to_string();
        };
        let mut lines = Vec::new();
        for s in srvs.into_iter().filter(|s| s.enabled && s.server_type == "stdio") {
            let allowed = allow_root || NON_ROOT_ALLOWED_MCPS.contains(&s.name.as_str());
            lines.push(format!(
                "- `{}` (allowed={allowed}): call `discover_mcp_tools(server=\"{}\")` for exact tool schemas",
                s.name, s.name
            ));
        }
        return if lines.is_empty() {
            "No enabled stdio MCP servers configured.".to_string()
        } else {
            format!("Enabled MCP servers:\n{}", lines.join("\n"))
        };
    }

    if !allow_root && !NON_ROOT_ALLOWED_MCPS.contains(&server) {
        return format!("Permission denied: inspecting MCP server '{server}' requires root_access.");
    }
    let srv = match get_mcp_server_raw(mcp_config_path, server) {
        Ok(Some(s)) if s.enabled && s.server_type == "stdio" && !s.command.is_empty() => s,
        Ok(Some(s)) => {
            return format!(
                "MCP server '{server}' is disabled or non-stdio (type='{}').",
                s.server_type
            );
        }
        Ok(None) => return format!("Error: MCP server '{server}' not found in configuration."),
        Err(e) => {
            return format!(
                "Error reading MCP config: {}",
                redact_secrets_in_text(&e.to_string())
            );
        }
    };
    let mut cmd_vec = vec![srv.command.clone()];
    cmd_vec.extend(srv.args.clone());
    let env_map: HashMap<String, String> = srv.env.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    let env_opt = (!env_map.is_empty()).then_some(&env_map);
    match crate::mcp_client::list_stdio_mcp_tools(&cmd_vec, env_opt, 15.0).await {
        Ok(tools) => {
            let filt_low = filter.map(|f| f.to_ascii_lowercase());
            let mut rows = Vec::new();
            for t in tools {
                let name = t.get("name").and_then(Value::as_str).unwrap_or("");
                let desc = t.get("description").and_then(Value::as_str).unwrap_or("");
                if let Some(ref f) = filt_low {
                    if !name.to_ascii_lowercase().contains(f) && !desc.to_ascii_lowercase().contains(f) {
                        continue;
                    }
                }
                let req_keys: Vec<String> = t
                    .pointer("/inputSchema/required")
                    .and_then(Value::as_array)
                    .map(|arr| {
                        arr.iter()
                            .filter_map(Value::as_str)
                            .map(str::to_string)
                            .collect()
                    })
                    .unwrap_or_default();
                let prop_keys: Vec<String> = t
                    .pointer("/inputSchema/properties")
                    .and_then(Value::as_object)
                    .map(|obj| obj.keys().take(8).cloned().collect())
                    .unwrap_or_default();
                rows.push(format!(
                    "- `{name}`(required=[{}], params=[{}]) — {}",
                    req_keys.join(", "),
                    prop_keys.join(", "),
                    clip_chars(desc.lines().next().unwrap_or(""), 110)
                ));
            }
            if rows.is_empty() {
                format!("MCP server '{server}' returned 0 matching tools.")
            } else {
                compact_tool_output(
                    &format!("MCP `{server}` tools ({}):\n{}", rows.len(), rows.join("\n")),
                    active_tool_output_cap(),
                )
            }
        }
        Err(e) => format!(
            "MCP tools/list error ({server}): {}",
            redact_secrets_in_text(&e.to_string())
        ),
    }
}

/// Generate an Aider-inspired `.gitignore`-aware structural Repository Map using `ignore::WalkBuilder`.
fn build_repo_map(root: &Path, max_files: usize, max_chars: usize) -> String {
    if !root.exists() {
        return format!("Error: path does not exist: {}", root.display());
    }
    let mut entries: Vec<(usize, String, usize, Vec<String>)> = Vec::new();
    let walker = ignore::WalkBuilder::new(root)
        .hidden(true)
        .git_ignore(true)
        .git_global(true)
        .git_exclude(true)
        .max_depth(Some(6))
        .build();

    for dent in walker.flatten() {
        let p = dent.path();
        if !p.is_file() {
            continue;
        }
        let ext = p
            .extension()
            .and_then(|s| s.to_str())
            .map(|s| s.to_ascii_lowercase())
            .unwrap_or_default();
        if !matches!(
            ext.as_str(),
            "rs" | "py" | "php" | "js" | "mjs" | "cjs" | "ts" | "tsx" | "jsx" | "go" | "c" | "h" | "cpp" | "hpp" | "java" | "sh" | "bash"
        ) {
            continue;
        }
        let Ok(meta) = p.metadata() else {
            continue;
        };
        if meta.len() == 0 || meta.len() > 512 * 1024 {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(p) else {
            continue;
        };
        let line_count = text.lines().count();
        let mut syms = Vec::new();
        for line in text.lines() {
            let t = line.trim();
            let hit = t.starts_with("pub fn ")
                || t.starts_with("pub async fn ")
                || t.starts_with("fn ")
                || t.starts_with("async fn ")
                || t.starts_with("pub struct ")
                || t.starts_with("struct ")
                || t.starts_with("pub enum ")
                || t.starts_with("enum ")
                || t.starts_with("pub trait ")
                || t.starts_with("trait ")
                || t.starts_with("impl ")
                || t.starts_with("class ")
                || t.starts_with("def ")
                || t.starts_with("async def ")
                || t.starts_with("function ")
                || t.starts_with("export function ")
                || t.starts_with("export class ")
                || t.starts_with("export interface ")
                || t.starts_with("interface ")
                || t.starts_with("public function ")
                || t.starts_with("func ");
            if hit {
                let sig = t
                    .split(['{', ':'])
                    .next()
                    .unwrap_or(t)
                    .trim();
                if !sig.is_empty() && syms.len() < 24 {
                    syms.push(clip_chars(sig, 80));
                }
            }
        }
        let rel = p
            .strip_prefix(root)
            .unwrap_or(p)
            .to_string_lossy()
            .to_string();
        let score = syms.len() * 10 + (line_count / 40).min(10);
        entries.push((score, rel, line_count, syms));
    }

    // Rank by structural richness (Aider-style) while keeping deterministic tie-breaking by path
    entries.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    let total_found = entries.len();
    entries.truncate(max_files);

    let mut out = format!(
        "Repository Map for `{}` ({} mapped of {} code files):\n",
        root.display(),
        entries.len(),
        total_found
    );
    for (_, rel, lc, syms) in entries {
        let block = if syms.is_empty() {
            format!("\n{rel} ({lc} lines)\n")
        } else {
            format!("\n{rel} ({lc} lines):\n  - {}\n", syms.join("\n  - "))
        };
        if out.len() + block.len() > max_chars {
            out.push_str("\n... [repo_map truncated to max_chars budget]");
            break;
        }
        out.push_str(&block);
    }
    out
}

/// Compute a unified Myers diff + executable non-comment diff summary using the `similar` crate.
fn compute_unified_file_diff(orig_path: &Path, mod_path: &Path, context_lines: usize) -> String {
    let orig = match std::fs::read_to_string(orig_path) {
        Ok(s) => s,
        Err(e) => return format!("Error reading {}: {e}", orig_path.display()),
    };
    let modified = match std::fs::read_to_string(mod_path) {
        Ok(s) => s,
        Err(e) => return format!("Error reading {}: {e}", mod_path.display()),
    };

    let diff = similar::TextDiff::from_lines(&orig, &modified);
    let mut added = 0usize;
    let mut removed = 0usize;
    for change in diff.iter_all_changes() {
        match change.tag() {
            similar::ChangeTag::Insert => added += 1,
            similar::ChangeTag::Delete => removed += 1,
            similar::ChangeTag::Equal => {}
        }
    }
    let orig_exec = normalize_executable_code(&orig);
    let mod_exec = normalize_executable_code(&modified);
    let exec_identical = orig_exec == mod_exec;
    let unified = diff
        .unified_diff()
        .context_radius(context_lines)
        .header(&orig_path.display().to_string(), &mod_path.display().to_string())
        .to_string();

    let mut summary = format!(
        "Diff summary: +{added} / -{removed} lines | executable non-comment lines: {} -> {}{}\n\n",
        orig_exec.len(),
        mod_exec.len(),
        if exec_identical {
            " [WARNING: ZERO executable code changes — comment/whitespace only!]"
        } else {
            ""
        }
    );
    if unified.trim().is_empty() {
        summary.push_str("(Files are byte-for-byte identical.)");
    } else {
        summary.push_str(&unified);
    }
    compact_tool_output(&redact_secrets_in_text(&summary), active_tool_output_cap())
}

/// Parse GLM-4.7-Heretic / Qwen / Anthropic direct XML tool invocations:
/// 1. `<function=tool_name><parameter=k>v</parameter></function>`
/// 2. `<tool_name attr="val" ...>optional body</tool_name>` or `<tool_name attr="val" />`
/// Strictly gated by `is_known_agent_tool_name` so normal HTML/code never false-triggers.
fn extract_direct_xml_tool_calls(text: &str, parsed: &mut Vec<(String, String, Value)>) {
    static FN_RE: OnceLock<Option<Regex>> = OnceLock::new();
    static PARAM_RE: OnceLock<Option<Regex>> = OnceLock::new();
    static TAG_RE: OnceLock<Option<Regex>> = OnceLock::new();
    static ATTR_RE: OnceLock<Option<Regex>> = OnceLock::new();

    let fn_re = FN_RE.get_or_init(|| Regex::new(r"(?s)<function=([a-z_]+)>(.*?)</function>").ok()).as_ref();
    let param_re = PARAM_RE.get_or_init(|| Regex::new(r"(?s)<parameter=([a-z0-9_]+)>(.*?)</parameter>").ok()).as_ref();
    if let (Some(fre), Some(pre)) = (fn_re, param_re) {
        for cap in fre.captures_iter(text) {
            let name = cap.get(1).map_or("", |m| m.as_str()).trim();
            if !is_known_agent_tool_name(name) {
                continue;
            }
            let inner = cap.get(2).map_or("", |m| m.as_str());
            let mut map = serde_json::Map::new();
            for pcap in pre.captures_iter(inner) {
                let k = pcap.get(1).map_or("", |m| m.as_str()).trim();
                let v_raw = pcap.get(2).map_or("", |m| m.as_str()).trim();
                if !k.is_empty() {
                    map.insert(k.to_string(), coerce_xml_attr_value(v_raw));
                }
            }
            let idx = parsed.len();
            parsed.push((format!("xmlfn_call_{idx}"), name.to_string(), Value::Object(map)));
        }
    }
    if !parsed.is_empty() {
        return;
    }

    let tag_re = TAG_RE
        .get_or_init(|| {
            Regex::new(r#"(?s)<([a-z][a-z0-9_]{2,28})(?:\s+((?:[^>"']|"[^"]*"|'[^']*')*?))?(?:/>|>(.*?)</([a-z][a-z0-9_]{2,28})>)"#)
                .ok()
        })
        .as_ref();
    let attr_re = ATTR_RE
        .get_or_init(|| {
            Regex::new(r#"(?s)([a-z][a-z0-9_]*)\s*=\s*(?:"([^"]*)"|'([^']*)')"#).ok()
        })
        .as_ref();

    if let (Some(tre), Some(are)) = (tag_re, attr_re) {
        for cap in tre.captures_iter(text) {
            let name = cap.get(1).map_or("", |m| m.as_str()).trim();
            if !is_known_agent_tool_name(name) {
                continue;
            }
            if let Some(close_name) = cap.get(4).map(|m| m.as_str().trim()) {
                if close_name != name {
                    continue;
                }
            }
            let attr_blob = cap.get(2).map_or("", |m| m.as_str());
            let mut map = serde_json::Map::new();
            for acap in are.captures_iter(attr_blob) {
                let k = acap.get(1).map_or("", |m| m.as_str()).trim();
                let v_raw = acap
                    .get(2)
                    .or_else(|| acap.get(3))
                    .map_or("", |m| m.as_str());
                if !k.is_empty() {
                    map.insert(k.to_string(), coerce_xml_attr_value(v_raw));
                }
            }
            if let Some(body_m) = cap.get(3) {
                let body = body_m.as_str().trim_matches('\n');
                if !body.trim().is_empty() {
                    if name == "write_file" && !map.contains_key("content") {
                        map.insert("content".to_string(), Value::String(body.to_string()));
                    } else if name == "execute_code" && !map.contains_key("code") {
                        map.insert("code".to_string(), Value::String(body.to_string()));
                    }
                }
            }
            if !map.is_empty() {
                let idx = parsed.len();
                parsed.push((format!("xmltag_call_{idx}"), name.to_string(), Value::Object(map)));
            }
        }
    }
}

fn coerce_xml_attr_value(raw: &str) -> Value {
    let t = raw.trim();
    if t.eq_ignore_ascii_case("true") {
        return Value::Bool(true);
    }
    if t.eq_ignore_ascii_case("false") {
        return Value::Bool(false);
    }
    if let Ok(n) = t.parse::<i64>() {
        return Value::Number(n.into());
    }
    if (t.starts_with('{') && t.ends_with('}')) || (t.starts_with('[') && t.ends_with(']')) {
        if let Ok(v) = serde_json::from_str::<Value>(t) {
            return v;
        }
    }
    Value::String(raw.to_string())
}

/// True when a tool is always read-only / side-effect free and safe to run concurrently in a batch.
pub fn is_parallel_safe_tool(name: &str) -> bool {
    matches!(
        name,
        "read_file"
            | "batch_read"
            | "list_dir"
            | "glob_files"
            | "find_symbols"
            | "grep_files"
            | "web_search"
            | "fetch_url"
            | "memory_search"
            | "search_skills"
            | "load_skill"
            | "list_mcp_servers"
            | "discover_mcp_tools"
            | "repo_map"
            | "diff_files"
            | "skillhub_search"
            | "skillhub_catalog"
            | "skillhub_get"
            | "inspect_image"
            | "think"
    )
}

/// Argument-aware parallel-safety check: also allows read-only sub-commands of multi-action tools
/// (`file_editor(view)`, `git_ops(status|diff|log|branch)`, `task_tracker(view)`,
/// `process_manage(list|poll|log)`, `code_to_md` without `output_path`) to execute in parallel waves.
pub fn is_parallel_safe_call(name: &str, args: &Value) -> bool {
    if is_parallel_safe_tool(name) {
        return true;
    }
    match name {
        "file_editor" => args
            .get("command")
            .and_then(Value::as_str)
            .is_some_and(|c| c.eq_ignore_ascii_case("view")),
        "git_ops" => args
            .get("action")
            .and_then(Value::as_str)
            .is_some_and(|a| matches!(a.to_ascii_lowercase().as_str(), "status" | "diff" | "log" | "branch")),
        "task_tracker" => args
            .get("command")
            .and_then(Value::as_str)
            .map(|c| c.eq_ignore_ascii_case("view"))
            .unwrap_or(true),
        "process_manage" => args
            .get("action")
            .and_then(Value::as_str)
            .is_some_and(|a| matches!(a.to_ascii_lowercase().as_str(), "list" | "poll" | "log")),
        "code_to_md" => args
            .get("output_path")
            .and_then(Value::as_str)
            .map(|s| s.trim().is_empty())
            .unwrap_or(true),
        _ => false,
    }
}

/// Execute one agent tool call with ACL boundaries, CommandGuard, sandbox, and secret redaction.
pub async fn execute_agent_tool(
    name: &str,
    args: &Value,
    cfg: &AgentTurnConfig,
) -> String {
    let state = Arc::new(TurnRuntimeState::new());
    execute_agent_tool_with_state(name, args, cfg, &state).await
}

/// Execute one agent tool call with shared per-turn state (baselines, airlock taint, denial breaker).
pub async fn execute_agent_tool_with_state(
    name: &str,
    args: &Value,
    cfg: &AgentTurnConfig,
    state: &Arc<TurnRuntimeState>,
) -> String {
    if name == "execute_code" {
        if !cfg.can_exec() {
            return "Permission denied: execute_code requires sandbox_exec or root_access."
                .to_string();
        }
        let code = args.get("code").and_then(Value::as_str).unwrap_or("");
        if code.trim().is_empty() {
            return "Error: 'code' must not be empty.".to_string();
        }
        let guard_ctx = CommandGuardContext {
            allow_root: cfg.allow_root,
            cwd: &cfg.cwd,
            workspace_root: &cfg.workspace_root,
            tainted: state.is_tainted(),
            interactive: false,
        };
        if let CommandVerdict::Denied { rule, reason } = evaluate_command(code, &guard_ctx) {
            return format!("CommandGuard DENIED execute_code ({rule}): {reason}");
        }

        let timeout = args
            .get("timeout_secs")
            .and_then(Value::as_u64)
            .unwrap_or(60)
            .clamp(5, MAX_CODE_EXEC_TIMEOUT_SECS);
        let allow_network = args
            .get("allow_network")
            .and_then(Value::as_bool)
            .unwrap_or(cfg.allow_root);

        let cfg_clone = cfg.clone();
        let state_clone = Arc::clone(state);
        let dispatcher: RpcToolDispatcher = Arc::new(move |tool_name, tool_args| {
            let c = cfg_clone.clone();
            let st = Arc::clone(&state_clone);
            Box::pin(async move {
                execute_core_agent_tool(&tool_name, &tool_args, &c, &st).await
            })
        });

        let out = run_execute_code(
            &CodeExecRequest {
                code,
                cwd: &cfg.cwd,
                workspace_root: &cfg.workspace_root,
                allow_root: cfg.allow_root,
                allow_network,
                timeout_secs: timeout,
            },
            dispatcher,
        )
        .await;
        if out.contains("Exit code: 0 (")
            && !state.has_open_slots()
            && (out.contains("rpc_calls=0/")
                || code.contains("py_compile")
                || code.contains("ast.parse")
                || code.contains("unittest")
                || code.contains("pytest")
                || code.contains("assert ")
                || code.contains("subprocess")
                || code.contains("php ")
                || code.contains("node "))
        {
            state.clear_dirty();
        }
        return compact_tool_output(&out, active_tool_output_cap());
    }

    execute_core_agent_tool(name, args, cfg, state).await
}

/// Non-recursive core tool dispatcher (callable directly from `execute_code` RPC without future cycles).
/// Resolve an array argument even when a smaller model serialized it as a JSON string.
fn arg_array(args: &Value, key: &str) -> Option<Vec<Value>> {
    match args.get(key) {
        Some(Value::Array(arr)) => Some(arr.clone()),
        Some(Value::String(s)) => parse_tool_json_relaxed(s)
            .ok()
            .and_then(|v| v.as_array().cloned()),
        _ => None,
    }
}

/// Resolve an object argument even when a smaller model serialized it as a JSON string.
fn arg_object(args: &Value, key: &str) -> Option<Value> {
    match args.get(key) {
        Some(v @ Value::Object(_)) => Some(v.clone()),
        Some(Value::String(s)) => parse_tool_json_relaxed(s)
            .ok()
            .filter(|v| v.is_object()),
        _ => None,
    }
}

async fn execute_core_agent_tool(
    name: &str,
    args: &Value,
    cfg: &AgentTurnConfig,
    state: &Arc<TurnRuntimeState>,
) -> String {
    if let Some(parse_err) = args.get("__parse_error").and_then(Value::as_str) {
        return format!("Error: {parse_err}");
    }
    match name {
        "run_command" => {
            if !cfg.can_exec() {
                return "Permission denied: run_command requires sandbox_exec or root_access permission."
                    .to_string();
            }
            let cmd_str = args.get("command").and_then(Value::as_str).unwrap_or("");
            if cmd_str.trim().is_empty() {
                return "Error: empty command".to_string();
            }

            // Three-gate CommandGuard check
            let guard_ctx = CommandGuardContext {
                allow_root: cfg.allow_root,
                cwd: &cfg.cwd,
                workspace_root: &cfg.workspace_root,
                tainted: state.is_tainted(),
                interactive: false,
            };
            match evaluate_command(cmd_str, &guard_ctx) {
                CommandVerdict::Allowed => {
                    state.reset_denials();
                }
                CommandVerdict::Denied { rule, reason } => {
                    let streak = state.record_denial();
                    let breaker = if streak >= DENIAL_BREAKER_THRESHOLD {
                        "\n[denial-breaker] Repeated blocked commands detected — change approach and do not retry blocked patterns."
                    } else {
                        ""
                    };
                    return format!("CommandGuard DENIED ({rule}): {reason}{breaker}");
                }
                CommandVerdict::NeedsApproval {
                    risk,
                    reason,
                    script_sha256,
                } => {
                    let streak = state.record_denial();
                    let sha_note = script_sha256
                        .as_deref()
                        .map(|s| format!(" [script sha256:{}…]", &s[..12.min(s.len())]))
                        .unwrap_or_default();
                    let breaker = if streak >= DENIAL_BREAKER_THRESHOLD {
                        "\n[denial-breaker] Stop retrying dangerous commands; ask the user for explicit confirmation."
                    } else {
                        ""
                    };
                    return format!(
                        "CommandGuard APPROVAL REQUIRED ({risk}){sha_note}: {reason}\n\
                         Fail-closed in autonomous mode — ask the user to confirm or use a safer non-destructive alternative.{breaker}"
                    );
                }
            }

            let want_bg = args.get("background").and_then(Value::as_bool).unwrap_or(false)
                || args.get("pty").and_then(Value::as_bool).unwrap_or(false);
            let force_sandbox =
                !cfg.allow_root || args.get("sandbox").and_then(Value::as_bool).unwrap_or(false);

            if want_bg {
                let owner_tag = cfg
                    .session_key
                    .clone()
                    .unwrap_or_else(|| cfg.engine_id.clone());
                let req = StartPtyRequest {
                    command: cmd_str.to_string(),
                    cwd: cfg.cwd.clone(),
                    workspace_root: cfg.workspace_root.clone(),
                    allow_root: cfg.allow_root,
                    force_sandbox,
                    owner_tag,
                    session_name: args
                        .get("session_name")
                        .and_then(Value::as_str)
                        .map(str::to_string),
                };
                return match start_session(&cfg.state_dir, &req).await {
                    Ok(msg) => compact_tool_output(&msg, active_tool_output_cap()),
                    Err(e) => e,
                };
            }

            let timeout = args
                .get("timeout_secs")
                .and_then(Value::as_u64)
                .unwrap_or(DEFAULT_COMMAND_TIMEOUT_SECS)
                .clamp(5, MAX_COMMAND_TIMEOUT_SECS);
            let mut opts = ExecOptions::for_shell(
                cmd_str,
                cfg.cwd.clone(),
                cfg.workspace_root.clone(),
                timeout,
                cfg.allow_root,
            );
            opts.force_sandbox = force_sandbox;
            let outcome = run_exec_command(&opts).await;
            if outcome.exit_code == Some(0) {
                state.clear_dirty();
            }
            compact_tool_output(&outcome.format_for_agent(), active_tool_output_cap())
        }

        "process_manage" => {
            if !cfg.can_exec() {
                return "Permission denied: process_manage requires sandbox_exec or root_access."
                    .to_string();
            }
            let action = args.get("action").and_then(Value::as_str).unwrap_or("list");
            let session_id = args.get("session_id").and_then(Value::as_str).unwrap_or("");
            let lines = args.get("lines").and_then(Value::as_u64).unwrap_or(100) as usize;
            let owner_tag = cfg
                .session_key
                .clone()
                .unwrap_or_else(|| cfg.engine_id.clone());

            match action {
                "list" => list_sessions(&cfg.state_dir, &owner_tag).await,
                "poll" | "log" => {
                    if session_id.trim().is_empty() {
                        return "Error: 'session_id' is required for poll/log.".to_string();
                    }
                    match poll_session(&cfg.state_dir, session_id, lines).await {
                        Ok(s) => compact_tool_output(&s, active_tool_output_cap()),
                        Err(e) => e,
                    }
                }
                "wait" => {
                    if session_id.trim().is_empty() {
                        return "Error: 'session_id' is required for wait.".to_string();
                    }
                    let timeout = args.get("timeout_secs").and_then(Value::as_u64).unwrap_or(30);
                    match wait_session(&cfg.state_dir, session_id, timeout, lines).await {
                        Ok(s) => compact_tool_output(&s, active_tool_output_cap()),
                        Err(e) => e,
                    }
                }
                "write" => {
                    if session_id.trim().is_empty() {
                        return "Error: 'session_id' is required for write.".to_string();
                    }
                    let input = args.get("input").and_then(Value::as_str).unwrap_or("");
                    let send_enter = args.get("send_enter").and_then(Value::as_bool).unwrap_or(true);
                    let ctrl_c = args.get("ctrl_c").and_then(Value::as_bool).unwrap_or(false);
                    match write_session(&cfg.state_dir, session_id, input, send_enter, ctrl_c).await
                    {
                        Ok(s) => compact_tool_output(&s, active_tool_output_cap()),
                        Err(e) => e,
                    }
                }
                "kill" => {
                    if session_id.trim().is_empty() {
                        return "Error: 'session_id' is required for kill.".to_string();
                    }
                    match kill_session(&cfg.state_dir, session_id).await {
                        Ok(s) => s,
                        Err(e) => e,
                    }
                }
                other => format!("Error: unknown process_manage action '{other}' (use list|poll|wait|log|write|kill)."),
            }
        }

        "execute_code" => "Error: recursive execute_code is forbidden.".to_string(),

        "batch_read" => {
            let Some(arr) = arg_array(args, "files").or_else(|| arg_array(args, "paths")) else {
                return "Error: 'files' (or 'paths') array is required for batch_read.".to_string();
            };
            if arr.is_empty() {
                return "Error: 'files' array must not be empty.".to_string();
            }
            let mut futs = Vec::with_capacity(arr.len().min(20));
            for item in arr.iter().take(20) {
                let (raw, start_line, end_line) = if let Some(s) = item.as_str() {
                    (s.to_string(), 1usize, None)
                } else {
                    let p = item
                        .get("path")
                        .or_else(|| item.get("file"))
                        .or_else(|| item.get("file_path"))
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    let sl = item
                        .get("start_line")
                        .and_then(Value::as_u64)
                        .unwrap_or(1)
                        .max(1) as usize;
                    let el = item.get("end_line").and_then(Value::as_u64).map(|v| v as usize);
                    (p, sl, el)
                };
                let cwd = cfg.cwd.clone();
                let ws = cfg.workspace_root.clone();
                let allow_root = cfg.allow_root;
                let st = Arc::clone(state);
                futs.push(async move {
                    let path = match resolve_tool_path(&raw, &cwd, &ws, allow_root, true) {
                        Ok(p) => p,
                        Err(e) => return format!("=== {raw} ===\n{e}"),
                    };
                    match tokio::fs::read(&path).await {
                        Ok(bytes) => {
                            if bytes.iter().take(4096).any(|&b| b == 0) {
                                return format!(
                                    "=== {} ===\nError: binary file ({} bytes). Do not use batch_read/read_file on binary files; use code_to_md or execute_code (Python zipfile) for archives, or inspect_image for images.",
                                    path.display(),
                                    bytes.len()
                                );
                            }
                            st.record_file_baseline(&path);
                            let text = String::from_utf8_lossy(&bytes);
                            let lines: Vec<&str> = text.lines().collect();
                            let total = lines.len();
                            let start = start_line.saturating_sub(1).min(total);
                            let end = end_line.unwrap_or(total).min(total).max(start);
                            let numbered: Vec<String> = lines[start..end]
                                .iter()
                                .enumerate()
                                .map(|(idx, l)| format!("{}: {l}", start + idx + 1))
                                .collect();
                            format!(
                                "=== {} (lines {}-{} of {total}) ===\n{}",
                                path.display(),
                                start + 1,
                                end,
                                numbered.join("\n")
                            )
                        }
                        Err(e) => format!("=== {} ===\nError reading: {e}", path.display()),
                    }
                });
            }
            let sections = futures_util::future::join_all(futs).await;
            let joined = sections.join("\n\n");
            let cap = active_tool_output_cap().clamp(24 * 1024, 48 * 1024);
            compact_tool_output(&redact_secrets_in_text(&joined), cap)
        }

        "multi_edit" => {
            let Some(arr) = arg_array(args, "edits")
                .or_else(|| arg_array(args, "changes"))
                .or_else(|| arg_array(args, "patches"))
            else {
                return "Error: 'edits' array is required for multi_edit (each item: {path, target/old_str, replacement/new_str}).".to_string();
            };
            if arr.is_empty() {
                return "Error: 'edits' array must not be empty.".to_string();
            }
            let mut results = Vec::with_capacity(arr.len().min(25));
            let mut ok_count = 0usize;
            let mut fail_count = 0usize;
            for (idx, item) in arr.iter().take(25).enumerate() {
                let raw = item
                    .get("path")
                    .or_else(|| item.get("file"))
                    .or_else(|| item.get("file_path"))
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let target = item
                    .get("target")
                    .or_else(|| item.get("old_str"))
                    .or_else(|| item.get("old_text"))
                    .or_else(|| item.get("search"))
                    .or_else(|| item.get("find"))
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let replacement = item
                    .get("replacement")
                    .or_else(|| item.get("new_str"))
                    .or_else(|| item.get("new_text"))
                    .or_else(|| item.get("replace"))
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let replace_all = item.get("replace_all").and_then(Value::as_bool).unwrap_or(false);
                if raw.trim().is_empty() || target.is_empty() {
                    fail_count += 1;
                    results.push(format!("#{}: ERROR missing path or target/old_str", idx + 1));
                    continue;
                }
                let path = match resolve_tool_path(raw, &cfg.cwd, &cfg.workspace_root, cfg.allow_root, true) {
                    Ok(p) => p,
                    Err(e) => {
                        fail_count += 1;
                        results.push(format!("#{} ({raw}): ERROR {e}", idx + 1));
                        continue;
                    }
                };
                if let Err(stale_err) = state.check_file_baseline(&path) {
                    fail_count += 1;
                    results.push(format!("#{} ({raw}): ERROR {stale_err}", idx + 1));
                    continue;
                }
                let existing = match tokio::fs::read_to_string(&path).await {
                    Ok(s) => s,
                    Err(e) => {
                        fail_count += 1;
                        results.push(format!("#{} ({raw}): ERROR reading: {e}", idx + 1));
                        continue;
                    }
                };
                let pre_diag = fast_syntax_check(&path, &existing).await;
                let matches = existing.matches(target).count();
                let updated_res: std::result::Result<(String, String), String> = if matches == 1 {
                    Ok((existing.replacen(target, replacement, 1), "1 exact match".to_string()))
                } else if matches > 1 && replace_all {
                    Ok((existing.replace(target, replacement), format!("{matches} occurrences")))
                } else if matches > 1 {
                    Err(format!("ambiguous target ({matches} matches); pass replace_all=true or more context"))
                } else if let Some(fuzzy_out) = fuzzy_trimmed_line_replace(&existing, target, replacement) {
                    Ok((fuzzy_out, "fuzzy trimmed-line match".to_string()))
                } else {
                    let hint = find_nearest_lines_hint(&existing, target);
                    Err(format!("target text not found{hint}"))
                };
                match updated_res {
                    Ok((updated, desc)) => {
                        state.record_edit_snapshot(&path);
                        if let Err(e) = atomic_write_text(&path, &updated).await {
                            fail_count += 1;
                            results.push(format!("#{} ({raw}): ERROR write: {e}", idx + 1));
                            continue;
                        }
                        state.record_file_baseline(&path);
                        state.record_file_mutated();
                        state.update_file_slots(&path, &updated);
                        let post_diag = fast_syntax_check(&path, &updated).await;
                        let diag_note = match (pre_diag, post_diag) {
                            (_, None) => String::new(),
                            (Some(pre), Some(post)) if pre == post => String::new(),
                            (_, Some(post)) => format!(" [syntax warning: {post}]"),
                        };
                        ok_count += 1;
                        results.push(format!("#{} ({raw}): OK ({desc}){diag_note}", idx + 1));
                    }
                    Err(e) => {
                        fail_count += 1;
                        results.push(format!("#{} ({raw}): ERROR {e}", idx + 1));
                    }
                }
            }
            format!(
                "multi_edit summary: {ok_count} succeeded, {fail_count} failed\n{}",
                results.join("\n")
            )
        }

        "read_file" => {
            let raw = args
                .get("path")
                .or_else(|| args.get("file"))
                .or_else(|| args.get("file_path"))
                .and_then(Value::as_str)
                .unwrap_or("");
            let path = match resolve_tool_path(raw, &cfg.cwd, &cfg.workspace_root, cfg.allow_root, true)
            {
                Ok(p) => p,
                Err(e) => return e,
            };
            let start_line = args
                .get("start_line")
                .and_then(Value::as_u64)
                .unwrap_or(1)
                .max(1) as usize;
            let end_line = args.get("end_line").and_then(Value::as_u64).map(|v| v as usize);

            match tokio::fs::read(&path).await {
                Ok(bytes) => {
                    if bytes.iter().take(4096).any(|&b| b == 0) {
                        return format!(
                            "Error: {} appears to be a binary file ({} bytes, e.g. .zip archive or image). Do NOT use read_file on binary files — use code_to_md or execute_code (Python zipfile) for .zip archives, or inspect_image for images.",
                            path.display(),
                            bytes.len()
                        );
                    }
                    state.record_file_baseline(&path);
                    let text = String::from_utf8_lossy(&bytes);
                    let lines: Vec<&str> = text.lines().collect();
                    let total = lines.len();
                    let start = start_line.saturating_sub(1).min(total);
                    // Clamp end >= start to prevent slice panic when model passes start_line > end_line!
                    let end = end_line.unwrap_or(total).min(total).max(start);
                    let slice = &lines[start..end];
                    let numbered: Vec<String> = slice
                        .iter()
                        .enumerate()
                        .map(|(idx, l)| format!("{}: {l}", start + idx + 1))
                        .collect();
                    let out = format!(
                        "File: {} (lines {}-{} of {total})\n{}",
                        path.display(),
                        start + 1,
                        end,
                        numbered.join("\n")
                    );
                    let cap = active_tool_output_cap().clamp(32 * 1024, 48 * 1024);
                    truncate_utf8_safe(&redact_secrets_in_text(&out), cap)
                }
                Err(e) => format!("Error reading {}: {e}", path.display()),
            }
        }

        "write_file" => {
            let raw = args.get("path").and_then(Value::as_str).unwrap_or("");
            let content_opt = args.get("content").and_then(Value::as_str);
            let append = args.get("append").and_then(Value::as_bool).unwrap_or(false);
            let allow_empty = args
                .get("allow_empty")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if !append && !allow_empty && content_opt.is_none_or(|s| s.trim().is_empty()) {
                return "Error: write_file requires non-empty 'content' (refusing to create an empty 0-byte file). Pass the full file body inside <agy_write path=\"...\">...</agy_write> or as a non-empty \"content\" string.".to_string();
            }
            let content = content_opt.unwrap_or("");
            let path =
                match resolve_tool_path(raw, &cfg.cwd, &cfg.workspace_root, cfg.allow_root, false)
                {
                    Ok(p) => p,
                    Err(e) => return e,
                };
            if !append && path.exists() {
                if let Err(stale_err) = state.check_file_baseline(&path) {
                    return stale_err;
                }
            }
            let final_content = if append && path.exists() {
                let mut existing = tokio::fs::read_to_string(&path).await.unwrap_or_default();
                existing.push_str(content);
                existing
            } else {
                content.to_string()
            };
            state.record_edit_snapshot(&path);
            if let Err(e) = atomic_write_text(&path, &final_content).await {
                return e;
            }
            state.record_file_baseline(&path);
            state.record_file_mutated();
            state.update_file_slots(&path, &final_content);
            let diag = fast_syntax_check_slotted(&path, &final_content).await;
            let lazy_warn = detect_lazy_code_placeholders(&final_content);
            let open_slots = extract_slot_markers_from_text(&final_content);
            let verb = if append { "appended to" } else { "wrote" };
            let mut msg = format!(
                "Successfully {verb} {} (chunk {} bytes, total {} bytes)",
                path.display(),
                content.len(),
                final_content.len()
            );
            if !open_slots.is_empty() {
                msg.push_str(&format!(
                    "\n[open slots ({}): {}] — fill each via `<agy_slot name=\"...\">...</agy_slot>`",
                    open_slots.len(),
                    open_slots.join(", ")
                ));
            }
            if let Some(d) = diag {
                msg.push_str(&format!("\n[syntax warning] {d}"));
            }
            if let Some(m) = lazy_warn {
                msg.push_str(&format!(
                    "\n[quality warning] Detected lazy omission placeholder (`{m}`). Replace placeholders with complete, working code!"
                ));
            }
            msg
        }

        "patch_file" | "edit_file" => {
            let raw = args
                .get("path")
                .or_else(|| args.get("file"))
                .or_else(|| args.get("file_path"))
                .and_then(Value::as_str)
                .unwrap_or("");
            let path = match resolve_tool_path(raw, &cfg.cwd, &cfg.workspace_root, cfg.allow_root, true)
            {
                Ok(p) => p,
                Err(e) => return e,
            };
            if let Err(stale_err) = state.check_file_baseline(&path) {
                return stale_err;
            }
            let existing = match tokio::fs::read_to_string(&path).await {
                Ok(s) => s,
                Err(e) => return format!("Error reading {}: {e}", path.display()),
            };
            let pre_diag = fast_syntax_check(&path, &existing).await;

            let diff_opt = args.get("diff").and_then(Value::as_str).filter(|s| !s.trim().is_empty());
            let (updated, summary_desc) = if let Some(diff_text) = diff_opt {
                match apply_unified_diff(&existing, diff_text) {
                    Ok((u, hunks)) => (u, format!("Applied {hunks} unified diff hunk(s)")),
                    Err(e) => return e,
                }
            } else {
                let target = args
                    .get("target")
                    .or_else(|| args.get("old_str"))
                    .or_else(|| args.get("old_text"))
                    .or_else(|| args.get("search"))
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let replacement = args
                    .get("replacement")
                    .or_else(|| args.get("new_str"))
                    .or_else(|| args.get("new_text"))
                    .or_else(|| args.get("replace"))
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let replace_all = args.get("replace_all").and_then(Value::as_bool).unwrap_or(false);
                if target.is_empty() {
                    return "Error: 'target' (or 'old_str'/'diff') must not be empty".to_string();
                }

                let matches = existing.matches(target).count();
                if matches == 1 {
                    (existing.replacen(target, replacement, 1), "Replaced 1 occurrence".to_string())
                } else if matches > 1 {
                    if replace_all {
                        (
                            existing.replace(target, replacement),
                            format!("Replaced {matches} occurrence(s) (replace_all=true)"),
                        )
                    } else {
                        // Report line numbers where target appears to prevent silent multi-site corruption!
                        let mut hit_lines = Vec::new();
                        let mut offset = 0usize;
                        while let Some(pos) = existing[offset..].find(target) {
                            let abs = offset + pos;
                            let line_no = existing[..abs].bytes().filter(|&b| b == b'\n').count() + 1;
                            hit_lines.push(line_no.to_string());
                            offset = abs + target.len();
                            if hit_lines.len() >= 10 {
                                break;
                            }
                        }
                        return format!(
                            "Error: target block matched {matches} locations in {} (lines: {}). \
                             Provide more surrounding context for a unique match, or pass replace_all=true.",
                            path.display(),
                            hit_lines.join(", ")
                        );
                    }
                } else if let Some(fuzzy_updated) =
                    fuzzy_trimmed_line_replace(&existing, target, replacement)
                {
                    (
                        fuzzy_updated,
                        "Replaced 1 occurrence (unique trimmed-whitespace fallback)".to_string(),
                    )
                } else {
                    let hint = find_nearest_lines_hint(&existing, target);
                    return format!(
                        "Error: target block not found in {}. Read the file again or use nearest lines below:{hint}",
                        path.display()
                    );
                }
            };

            state.record_edit_snapshot(&path);
            if let Err(e) = atomic_write_text(&path, &updated).await {
                return e;
            }
            state.record_file_baseline(&path);
            state.record_file_mutated();
            state.update_file_slots(&path, &updated);

            // Differential diagnostics: report ONLY newly introduced syntax errors
            let post_diag = fast_syntax_check(&path, &updated).await;
            let diag_note = match (pre_diag, post_diag) {
                (None, Some(new_err)) => format!("\n[new syntax error] {new_err}"),
                (Some(old_err), Some(new_err)) if old_err != new_err => {
                    format!("\n[syntax error changed] {new_err}")
                }
                _ => String::new(),
            };

            format!(
                "{summary_desc} in {} ({} bytes){diag_note}",
                path.display(),
                updated.len()
            )
        }

        "list_dir" => {
            let raw = args.get("path").and_then(Value::as_str).unwrap_or(".");
            let path = match resolve_tool_path(raw, &cfg.cwd, &cfg.workspace_root, cfg.allow_root, true)
            {
                Ok(p) => p,
                Err(e) => return e,
            };
            tokio::task::spawn_blocking(move || {
                let mut entries_out = Vec::new();
                match std::fs::read_dir(&path) {
                    Ok(rd) => {
                        for ent in rd.flatten().take(200) {
                            let name = ent.file_name().to_string_lossy().into_owned();
                            let meta = std::fs::symlink_metadata(ent.path()).ok();
                            let kind = match meta.as_ref() {
                                Some(m) if m.file_type().is_symlink() => "symlink",
                                Some(m) if m.is_dir() => "dir",
                                _ => "file",
                            };
                            let size = meta.map(|m| m.len()).unwrap_or(0);
                            entries_out.push(format!("{kind:<7} {size:>10}  {name}"));
                        }
                        entries_out.sort();
                        if entries_out.is_empty() {
                            format!("{} (empty directory)", path.display())
                        } else {
                            format!(
                                "Directory: {} ({} entries)\n{}",
                                path.display(),
                                entries_out.len(),
                                entries_out.join("\n")
                            )
                        }
                    }
                    Err(e) => format!("Error listing {}: {e}", path.display()),
                }
            })
            .await
            .unwrap_or_else(|e| format!("Error listing directory: {e}"))
        }

        "file_editor" => {
            let cmd = args
                .get("command")
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase();
            let raw = args.get("path").and_then(Value::as_str).unwrap_or("");
            match cmd.as_str() {
                "view" => {
                    let path = match resolve_tool_path(raw, &cfg.cwd, &cfg.workspace_root, cfg.allow_root, true) {
                        Ok(p) => p,
                        Err(e) => return e,
                    };
                    if path.is_dir() {
                        let sub = json!({ "path": raw });
                        return Box::pin(execute_core_agent_tool("list_dir", &sub, cfg, state)).await;
                    }
                    let mut start_line = 1u64;
                    let mut end_line: Option<u64> = None;
                    if let Some(arr) = arg_array(args, "view_range") {
                        if let Some(s) = arr.first().and_then(Value::as_i64) {
                            start_line = s.max(1) as u64;
                        }
                        if let Some(e) = arr.get(1).and_then(Value::as_i64) {
                            if e > 0 {
                                end_line = Some(e as u64);
                            }
                        }
                    }
                    let mut sub = json!({ "path": raw, "start_line": start_line });
                    if let Some(el) = end_line {
                        sub["end_line"] = json!(el);
                    }
                    Box::pin(execute_core_agent_tool("read_file", &sub, cfg, state)).await
                }
                "create" => {
                    let content = args
                        .get("file_text")
                        .or_else(|| args.get("content"))
                        .and_then(Value::as_str)
                        .unwrap_or("");
                    let sub = json!({ "path": raw, "content": content, "append": false });
                    Box::pin(execute_core_agent_tool("write_file", &sub, cfg, state)).await
                }
                "str_replace" => {
                    let target = args
                        .get("old_str")
                        .or_else(|| args.get("target"))
                        .and_then(Value::as_str)
                        .unwrap_or("");
                    let replacement = args
                        .get("new_str")
                        .or_else(|| args.get("replacement"))
                        .and_then(Value::as_str)
                        .unwrap_or("");
                    let replace_all = args.get("replace_all").and_then(Value::as_bool).unwrap_or(false);
                    let sub = json!({
                        "path": raw,
                        "target": target,
                        "replacement": replacement,
                        "replace_all": replace_all
                    });
                    Box::pin(execute_core_agent_tool("patch_file", &sub, cfg, state)).await
                }
                "insert" => {
                    let path = match resolve_tool_path(raw, &cfg.cwd, &cfg.workspace_root, cfg.allow_root, true) {
                        Ok(p) => p,
                        Err(e) => return e,
                    };
                    if let Err(stale_err) = state.check_file_baseline(&path) {
                        return stale_err;
                    }
                    let Some(insert_line) = args.get("insert_line").and_then(Value::as_u64) else {
                        return "Error: 'insert_line' (0-based integer) is required for file_editor(command='insert').".to_string();
                    };
                    let new_str = args
                        .get("new_str")
                        .or_else(|| args.get("content"))
                        .and_then(Value::as_str)
                        .unwrap_or("");
                    let existing = match tokio::fs::read_to_string(&path).await {
                        Ok(s) => s,
                        Err(e) => return format!("Error reading {}: {e}", path.display()),
                    };
                    let pre_diag = fast_syntax_check(&path, &existing).await;
                    let updated = match openhands::insert_at_line(&existing, insert_line as usize, new_str) {
                        Ok(u) => u,
                        Err(e) => return e,
                    };
                    state.record_edit_snapshot(&path);
                    if let Err(e) = atomic_write_text(&path, &updated).await {
                        return e;
                    }
                    state.record_file_baseline(&path);
                    state.record_file_mutated();
                    let post_diag = fast_syntax_check(&path, &updated).await;
                    let diag_note = match (pre_diag, post_diag) {
                        (None, Some(new_err)) => format!("\n[new syntax error] {new_err}"),
                        (Some(old_err), Some(new_err)) if old_err != new_err => {
                            format!("\n[syntax error changed] {new_err}")
                        }
                        _ => String::new(),
                    };
                    format!(
                        "Inserted after line {insert_line} in {} ({} bytes){diag_note}",
                        path.display(),
                        updated.len()
                    )
                }
                "undo_edit" => {
                    let path = match resolve_tool_path(raw, &cfg.cwd, &cfg.workspace_root, cfg.allow_root, false) {
                        Ok(p) => p,
                        Err(e) => return e,
                    };
                    match state.undo_edit(&path) {
                        Ok(msg) => {
                            state.record_file_baseline(&path);
                            state.record_file_mutated();
                            msg
                        }
                        Err(e) => e,
                    }
                }
                other => format!(
                    "Error: unknown file_editor command '{other}' (use view|create|str_replace|insert|undo_edit)."
                ),
            }
        }

        "glob_files" => {
            let pattern = args.get("pattern").and_then(Value::as_str).unwrap_or("").to_string();
            if pattern.trim().is_empty() {
                return "Error: 'pattern' must not be empty.".to_string();
            }
            let raw = args.get("path").and_then(Value::as_str).unwrap_or(".");
            let root = match resolve_tool_path(raw, &cfg.cwd, &cfg.workspace_root, cfg.allow_root, true) {
                Ok(p) => p,
                Err(e) => return e,
            };
            let max_results = args.get("max_results").and_then(Value::as_u64).unwrap_or(100) as usize;
            let out = tokio::task::spawn_blocking(move || openhands::glob_files(&root, &pattern, max_results))
                .await
                .unwrap_or_else(|e| format!("Error running glob_files: {e}"));
            compact_tool_output(&redact_secrets_in_text(&out), active_tool_output_cap())
        }

        "find_symbols" => {
            let query = args.get("query").and_then(Value::as_str).map(str::to_string);
            let file_glob = args.get("file_glob").and_then(Value::as_str).map(str::to_string);
            let raw = args.get("path").and_then(Value::as_str).unwrap_or(".");
            let root = match resolve_tool_path(raw, &cfg.cwd, &cfg.workspace_root, cfg.allow_root, true) {
                Ok(p) => p,
                Err(e) => return e,
            };
            let max_results = args.get("max_results").and_then(Value::as_u64).unwrap_or(100) as usize;
            let out = tokio::task::spawn_blocking(move || {
                openhands::find_symbols(&root, query.as_deref(), file_glob.as_deref(), max_results)
            })
            .await
            .unwrap_or_else(|e| format!("Error running find_symbols: {e}"));
            compact_tool_output(&redact_secrets_in_text(&out), active_tool_output_cap())
        }

        "git_ops" => {
            let action = args.get("action").and_then(Value::as_str).unwrap_or("status");
            let out = openhands::run_git_ops(
                action,
                args,
                &cfg.cwd,
                &cfg.workspace_root,
                cfg.allow_root,
                cfg.can_exec(),
            )
            .await;
            compact_tool_output(&out, active_tool_output_cap())
        }

        "task_tracker" => {
            if let Some(Value::String(_)) = args.get("task_list") {
                if let Some(arr) = arg_array(args, "task_list") {
                    let mut coerced = args.clone();
                    coerced["task_list"] = Value::Array(arr);
                    return state.task_tracker().handle_command(&coerced);
                }
            }
            state.task_tracker().handle_command(args)
        }

        "grep_files" => {
            let pattern = args
                .get("pattern")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            if pattern.trim().is_empty() {
                return "Error: pattern must not be empty".to_string();
            }
            let raw = args.get("path").and_then(Value::as_str).unwrap_or(".");
            let root = match resolve_tool_path(raw, &cfg.cwd, &cfg.workspace_root, cfg.allow_root, true)
            {
                Ok(p) => p,
                Err(e) => return e,
            };
            let glob_filter = args
                .get("glob")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string);
            let context_lines = args
                .get("context_lines")
                .and_then(Value::as_u64)
                .unwrap_or(0)
                .min(5) as usize;
            let case_sensitive = args
                .get("case_sensitive")
                .and_then(Value::as_bool)
                .unwrap_or(false);

            tokio::task::spawn_blocking(move || {
                let re = regex::RegexBuilder::new(&pattern)
                    .case_insensitive(!case_sensitive)
                    .build()
                    .or_else(|_| {
                        regex::RegexBuilder::new(&regex::escape(&pattern))
                            .case_insensitive(!case_sensitive)
                            .build()
                    });
                let Ok(re) = re else {
                    return "Error: invalid search pattern".to_string();
                };
                let glob_re = match glob_filter.as_deref() {
                    Some(g) => match openhands::glob_to_regex(g) {
                        Ok(r) => Some(r),
                        Err(e) => return format!("Error: {e}"),
                    },
                    None => None,
                };

                let mut hits = Vec::new();
                let mut stack = vec![root.clone()];
                let mut files_scanned = 0usize;
                while let Some(cur) = stack.pop() {
                    if hits.len() >= 100 || files_scanned >= 4000 {
                        break;
                    }
                    let Ok(meta) = std::fs::symlink_metadata(&cur) else {
                        continue;
                    };
                    if meta.file_type().is_symlink() {
                        continue;
                    }
                    if meta.is_dir() {
                        let skip = cur
                            .file_name()
                            .and_then(|s| s.to_str())
                            .is_some_and(|n| matches!(n, ".git" | "target" | "node_modules" | ".venv" | "__pycache__"));
                        if skip && cur != root {
                            continue;
                        }
                        if let Ok(rd) = std::fs::read_dir(&cur) {
                            for ent in rd.flatten() {
                                stack.push(ent.path());
                            }
                        }
                    } else if meta.is_file() && meta.len() <= 512 * 1024 {
                        let rel_str = cur
                            .strip_prefix(&root)
                            .unwrap_or(&cur)
                            .to_string_lossy()
                            .replace('\\', "/");
                        if let Some(ref gre) = glob_re {
                            if !gre.is_match(&rel_str) {
                                continue;
                            }
                        }
                        files_scanned += 1;
                        let Ok(raw_text) = std::fs::read_to_string(&cur) else {
                            continue;
                        };
                        let all_lines: Vec<&str> = raw_text.lines().collect();
                        for (idx, line) in all_lines.iter().enumerate() {
                            if re.is_match(line) {
                                if context_lines == 0 {
                                    hits.push(format!(
                                        "{rel_str}:{}: {}",
                                        idx + 1,
                                        clip_chars(line.trim(), 180)
                                    ));
                                } else {
                                    let lo = idx.saturating_sub(context_lines);
                                    let hi = (idx + context_lines + 1).min(all_lines.len());
                                    let mut block = format!("-- {rel_str}:{} --", idx + 1);
                                    for (j, l) in all_lines[lo..hi].iter().enumerate() {
                                        let ln = lo + j + 1;
                                        let mark = if lo + j == idx { '>' } else { ' ' };
                                        block.push_str(&format!("\n{mark}{ln}: {}", clip_chars(l, 180)));
                                    }
                                    hits.push(block);
                                }
                                if hits.len() >= 100 {
                                    break;
                                }
                            }
                        }
                    }
                }
                if hits.is_empty() {
                    format!(
                        "No matches for '{pattern}' in {} ({files_scanned} files scanned).",
                        root.display()
                    )
                } else {
                    compact_tool_output(
                        &redact_secrets_in_text(&format!(
                            "Found {} match(es) ({files_scanned} files scanned):\n{}",
                            hits.len(),
                            hits.join("\n")
                        )),
                        active_tool_output_cap(),
                    )
                }
            })
            .await
            .unwrap_or_else(|e| format!("Error searching files: {e}"))
        }

        "web_search" => {
            state.mark_tainted();
            let query = args.get("query").and_then(Value::as_str).unwrap_or("");
            if query.trim().is_empty() {
                return "Error: query must not be empty".to_string();
            }
            let profile = args.get("profile").and_then(Value::as_str).unwrap_or("hybrid");
            let max_results = args
                .get("max_results")
                .or_else(|| args.get("limit"))
                .and_then(Value::as_u64)
                .unwrap_or(10)
                .clamp(1, 30);
            let strict_ast = args
                .get("strict_ast")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let allow_relax = args
                .get("allow_relax")
                .and_then(Value::as_bool)
                .unwrap_or(true);
            invoke_configured_mcp(
                &cfg.mcp_config_path,
                "search-v3",
                "search_web_v3",
                json!({
                    "query": query,
                    "profile": profile,
                    "max_results": max_results,
                    "strict_ast": strict_ast,
                    "allow_relax": allow_relax
                }),
                45.0,
                cfg.allow_root,
            )
            .await
        }

        "fetch_url" => {
            state.mark_tainted();
            let url = args.get("url").and_then(Value::as_str).unwrap_or("");
            if url.trim().is_empty() {
                return "Error: url must not be empty".to_string();
            }
            let max_chars = args
                .get("max_chars")
                .and_then(Value::as_u64)
                .unwrap_or(12_000)
                .clamp(500, 40_000);
            invoke_configured_mcp(
                &cfg.mcp_config_path,
                "search-v3",
                "fetch_url",
                json!({ "url": url, "max_chars": max_chars }),
                30.0,
                cfg.allow_root,
            )
            .await
        }

        "list_mcp_servers" => match list_mcp_servers(&cfg.mcp_config_path) {
            Ok(srvs) => {
                let rows: Vec<Value> = srvs
                    .into_iter()
                    .map(|s| {
                        let allowed = cfg.allow_root || NON_ROOT_ALLOWED_MCPS.contains(&s.name.as_str());
                        let guide = match s.name.as_str() {
                            "openhands" => "Unified OpenHands toolkit: oh_file_editor, oh_execute_code, oh_glob_files, oh_find_symbols, oh_git_ops, oh_pty_start, oh_process_manage, oh_verify, oh_pack_md, oh_apply_md, oh_delegate_agent",
                            "search-v3" => "Web search & URL fetch: search_web_v3, fetch_url, crawl_urls",
                            "context7" => "Up-to-date library docs: resolve-library-id, query-docs",
                            "gortex" => "Live code index: search, relations, change, trace, analyze",
                            "graphify" => "Codebase graph & architecture: query_graph, get_node, god_nodes, shortest_path",
                            "ai-memory" => "Durable cross-session knowledge: memory_search, memory_store",
                            "skillport" => "Procedural skills: search_skills, load_skill",
                            "skillhub" => "Claude Code ecosystem hub: skillhub_search, skillhub_catalog, skillhub_get",
                            "skills-catalog" => "Skill catalog discovery: search_skills, recommend_skills",
                            "venice-uncensored" => "Venice Uncensored delegation: uncensored_models, uncensored_chat, uncensored_agent, uncensored_dev_loop",
                            _ => "Configured MCP server (callable via call_mcp_tool when allowed)",
                        };
                        json!({
                            "name": s.name,
                            "type": s.server_type,
                            "enabled": s.enabled,
                            "allowed_in_agent": allowed,
                            "recommended_tools": guide
                        })
                    })
                    .collect();
                serde_json::to_string_pretty(&rows).unwrap_or_else(|_| "[]".to_string())
            }
            Err(e) => format!("Error listing MCP servers: {e}"),
        },

        "call_mcp_tool" => {
            let server = args.get("server").and_then(Value::as_str).unwrap_or("");
            let tool = args.get("tool").and_then(Value::as_str).unwrap_or("");
            let arguments = arg_object(args, "arguments").unwrap_or_else(|| json!({}));
            if server.is_empty() || tool.is_empty() {
                return "Error: both 'server' and 'tool' are required.".to_string();
            }
            let mcp_count = state.record_mcp_call();
            if mcp_count > MAX_MCP_CALLS_PER_TURN {
                return format!(
                    "Error: MCP call budget exceeded ({MAX_MCP_CALLS_PER_TURN} calls per turn). Use gathered data or built-in tools to finish."
                );
            }
            if server == "search-v3" {
                state.mark_tainted();
            }
            let timeout = args
                .get("timeout_secs")
                .and_then(Value::as_u64)
                .unwrap_or(30)
                .clamp(5, 300) as f64;
            let res = invoke_configured_mcp(
                &cfg.mcp_config_path,
                server,
                tool,
                arguments,
                timeout,
                cfg.allow_root,
            )
            .await;
            let res_low = res.to_ascii_lowercase();
            if res.starts_with("MCP Error")
                && (res_low.contains("unknown tool")
                    || res_low.contains("not found")
                    || res_low.contains("-32601")
                    || res_low.contains("-32602")
                    || res_low.contains("invalid param"))
            {
                let hint = discover_configured_mcp_tools(
                    &cfg.mcp_config_path,
                    server,
                    None,
                    cfg.allow_root,
                )
                .await;
                format!("{res}\n\n[auto-discovery for MCP server '{server}']\n{hint}")
            } else {
                res
            }
        }

        "discover_mcp_tools" => {
            let server = args.get("server").and_then(Value::as_str).unwrap_or("all").trim();
            let filter = args.get("filter").and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty());
            discover_configured_mcp_tools(&cfg.mcp_config_path, server, filter, cfg.allow_root).await
        }

        "repo_map" => {
            let raw = args.get("path").and_then(Value::as_str).unwrap_or(".");
            let root = match resolve_tool_path(raw, &cfg.cwd, &cfg.workspace_root, cfg.allow_root, true) {
                Ok(p) => p,
                Err(e) => return e,
            };
            let max_files = args.get("max_files").and_then(Value::as_u64).unwrap_or(60).clamp(5, 200) as usize;
            let max_chars = args.get("max_chars").and_then(Value::as_u64).unwrap_or(14_000).clamp(1_000, 30_000) as usize;
            build_repo_map(&root, max_files, max_chars)
        }

        "diff_files" => {
            let orig_raw = args.get("original_path").and_then(Value::as_str).unwrap_or("");
            let mod_raw = args.get("modified_path").and_then(Value::as_str).unwrap_or("");
            if orig_raw.trim().is_empty() || mod_raw.trim().is_empty() {
                return "Error: both 'original_path' and 'modified_path' are required.".to_string();
            }
            let orig_p = match resolve_tool_path(orig_raw, &cfg.cwd, &cfg.workspace_root, cfg.allow_root, true) {
                Ok(p) => p,
                Err(e) => return e,
            };
            let mod_p = match resolve_tool_path(mod_raw, &cfg.cwd, &cfg.workspace_root, cfg.allow_root, true) {
                Ok(p) => p,
                Err(e) => return e,
            };
            let ctx = args.get("context_lines").and_then(Value::as_u64).unwrap_or(3).clamp(0, 10) as usize;
            compute_unified_file_diff(&orig_p, &mod_p, ctx)
        }

        "assemble_slots" => {
            let cmd = args
                .get("command")
                .or_else(|| args.get("action"))
                .and_then(Value::as_str)
                .unwrap_or("replace")
                .trim()
                .to_ascii_lowercase();
            let raw_opt = args
                .get("path")
                .or_else(|| args.get("file"))
                .or_else(|| args.get("file_path"))
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty());
            let path = if let Some(raw) = raw_opt {
                match resolve_tool_path(raw, &cfg.cwd, &cfg.workspace_root, cfg.allow_root, true) {
                    Ok(p) => p,
                    Err(e) => return e,
                }
            } else if let Some(active_p) = state.active_slot_target() {
                active_p
            } else {
                return "Error: 'path' is required for assemble_slots (no active slotted skeleton file recorded yet; write a skeleton file containing `# <<<AGY_SLOT:id>>>` first).".to_string();
            };

            let mut existing = match tokio::fs::read_to_string(&path).await {
                Ok(s) => s,
                Err(e) => return format!("Error reading {}: {e}", path.display()),
            };
            state.set_active_slot_target(&path);

            match cmd.as_str() {
                "status" => {
                    let rem = extract_slot_markers_from_text(&existing);
                    state.update_file_slots(&path, &existing);
                    let diag = fast_syntax_check_slotted(&path, &existing).await;
                    let diag_str = diag.map(|d| format!("\n[syntax warning] {d}")).unwrap_or_default();
                    if rem.is_empty() {
                        format!("{} has 0 remaining slots (assembly complete, {} bytes).{diag_str}", path.display(), existing.len())
                    } else {
                        format!("{} remaining slots ({}): [{}]{diag_str}", path.display(), rem.len(), rem.join(", "))
                    }
                }
                "finalize" => {
                    let rem = extract_slot_markers_from_text(&existing);
                    state.update_file_slots(&path, &existing);
                    if !rem.is_empty() {
                        return format!(
                            "Error: cannot finalize {} — {} unfilled slot(s) remain: [{}]. Emit `<agy_slot name=\"...\">` for each remaining slot.",
                            path.display(),
                            rem.len(),
                            rem.join(", ")
                        );
                    }
                    if let Some(m) = detect_lazy_code_placeholders(&existing) {
                        return format!(
                            "Error: {} still contains lazy placeholder (`{m}`). Replace it before finalizing.",
                            path.display()
                        );
                    }
                    if let Some(syn) = fast_syntax_check(&path, &existing).await {
                        return format!("Error: {} failed final syntax check: {syn}", path.display());
                    }
                    format!(
                        "[ALL SLOTS ASSEMBLED & SYNTAX PASS] {} ({} bytes, {} lines)",
                        path.display(),
                        existing.len(),
                        existing.lines().count()
                    )
                }
                "replace" => {
                    let mut pairs: Vec<(String, String)> = Vec::new();
                    if let Some(arr) = arg_array(args, "slots") {
                        for item in arr {
                            let sname = item
                                .get("slot")
                                .or_else(|| item.get("name"))
                                .and_then(Value::as_str)
                                .unwrap_or("")
                                .trim();
                            let scode = item
                                .get("code")
                                .or_else(|| item.get("content"))
                                .and_then(Value::as_str)
                                .unwrap_or("");
                            if !sname.is_empty() {
                                pairs.push((sname.to_string(), scode.to_string()));
                            }
                        }
                    } else {
                        let sname = args
                            .get("slot")
                            .or_else(|| args.get("name"))
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .trim();
                        let scode = args
                            .get("code")
                            .or_else(|| args.get("content"))
                            .and_then(Value::as_str)
                            .unwrap_or("");
                        if !sname.is_empty() {
                            pairs.push((sname.to_string(), scode.to_string()));
                        }
                    }
                    if pairs.is_empty() {
                        return "Error: assemble_slots requires ('slot' + 'code') or non-empty 'slots' array.".to_string();
                    }
                    let mut applied = Vec::new();
                    for (sname, scode) in &pairs {
                        if let Some(lazy) = detect_lazy_code_placeholders(scode) {
                            return format!(
                                "Error: slot '{sname}' rejected because chunk contains lazy omission placeholder (`{lazy}`). Write complete working code."
                            );
                        }
                        match splice_slot_into_text(&existing, sname, scode) {
                            Ok((updated, _)) => {
                                existing = updated;
                                applied.push(sname.clone());
                            }
                            Err(e) => return e,
                        }
                    }
                    state.record_edit_snapshot(&path);
                    if let Err(e) = atomic_write_text(&path, &existing).await {
                        return e;
                    }
                    state.record_file_baseline(&path);
                    state.record_file_mutated();
                    state.update_file_slots(&path, &existing);
                    let remaining = extract_slot_markers_from_text(&existing);
                    let diag = fast_syntax_check_slotted(&path, &existing).await;
                    let diag_note = diag.map(|d| format!("\n[syntax warning] {d}")).unwrap_or_default();
                    let rem_note = if remaining.is_empty() {
                        "[ALL SLOTS COMPLETE] Run runtime tests and verify before finishing.".to_string()
                    } else {
                        format!(
                            "[remaining slots ({}): {}] — continue with next `<agy_slot name=\"{}\">...</agy_slot>`",
                            remaining.len(),
                            remaining.join(", "),
                            remaining[0]
                        )
                    };
                    format!(
                        "Spliced slot(s) [{}] into {} ({} bytes)\n{rem_note}{diag_note}",
                        applied.join(", "),
                        path.display(),
                        existing.len()
                    )
                }
                other => format!("Error: unknown assemble_slots command '{other}' (use replace|status|finalize)."),
            }
        }

        "memory_search" => {
            let query = args.get("query").and_then(Value::as_str).unwrap_or("");
            let limit = args.get("limit").and_then(Value::as_u64).unwrap_or(5).clamp(1, 20);
            let mut payload = json!({ "query": query, "limit": limit });
            if let Some(tags) = args.get("tags").and_then(Value::as_array) {
                let clean: Vec<String> = tags
                    .iter()
                    .filter_map(Value::as_str)
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                if !clean.is_empty() {
                    payload["tags"] = json!(clean);
                }
            }
            invoke_configured_mcp(
                &cfg.mcp_config_path,
                "ai-memory",
                "memory_search",
                payload,
                15.0,
                true, // read-only search is safe
            )
            .await
        }

        "memory_store" => {
            if !cfg.allow_root {
                return "Permission denied: memory_store requires root_access.".to_string();
            }
            let title = args.get("title").and_then(Value::as_str).unwrap_or("");
            let summary = args.get("summary").and_then(Value::as_str).unwrap_or("");
            let mtype = args.get("type").and_then(Value::as_str).unwrap_or("fact");
            let tags = args
                .get("tags")
                .cloned()
                .unwrap_or_else(|| json!([cfg.engine_id]));
            invoke_configured_mcp(
                &cfg.mcp_config_path,
                "ai-memory",
                "memory_store",
                json!({
                    "content": { "title": clip_chars(title, 200), "summary": clip_chars(summary, 200) },
                    "type": mtype,
                    "source": format!("agy-{}", cfg.engine_id),
                    "confidence": 0.9,
                    "tags": tags
                }),
                15.0,
                true,
            )
            .await
        }

        "search_skills" => {
            let query = args.get("query").and_then(Value::as_str).unwrap_or("");
            invoke_configured_mcp(
                &cfg.mcp_config_path,
                "skillport",
                "search_skills",
                json!({ "query": query }),
                15.0,
                true,
            )
            .await
        }

        "load_skill" => {
            let skill_id = args.get("skill_id").and_then(Value::as_str).unwrap_or("").trim();
            if skill_id.is_empty() {
                return "Error: skill_id must not be empty".to_string();
            }
            if let Ok(safe_slug) = validate_skill_slug(skill_id) {
                let local_md = cfg.skills_dir.join(&safe_slug).join("SKILL.md");
                if local_md.is_file() {
                    if let Ok(text) = tokio::fs::read_to_string(&local_md).await {
                        return compact_tool_output(&text, active_tool_output_cap());
                    }
                }
            }
            invoke_configured_mcp(
                &cfg.mcp_config_path,
                "skillport",
                "load_skill",
                json!({ "skill_id": skill_id }),
                15.0,
                true,
            )
            .await
        }

        "skillhub_search" | "skillhub_get" | "skillhub_catalog" => {
            match crate::skill_hub::call_hub_tool(&cfg.state_dir, name, args).await {
                Ok(s) => compact_tool_output(&s, active_tool_output_cap()),
                Err(e) => format!("Error: {}", compact_tool_output(&e, active_tool_output_cap())),
            }
        }

        "code_to_md" => {
            let raw_path = args.get("path").and_then(Value::as_str).unwrap_or("");
            let target = match resolve_tool_path(raw_path, &cfg.cwd, &cfg.workspace_root, cfg.allow_root, true) {
                Ok(p) => p,
                Err(e) => return format!("Error: {e}"),
            };
            let mut opts = crate::code_to_md::PackOptions::new(target);
            if let Some(out_raw) = args.get("output_path").and_then(Value::as_str).filter(|s| !s.trim().is_empty()) {
                match resolve_tool_path(out_raw, &cfg.cwd, &cfg.workspace_root, cfg.allow_root, false) {
                    Ok(p) => opts.output_path = Some(p),
                    Err(e) => return format!("Error resolving output_path: {e}"),
                }
            }
            if let Some(arr) = arg_array(args, "include_extensions") {
                opts.include_extensions = arr.iter().filter_map(|v| v.as_str().map(str::to_string)).collect();
            }
            if let Some(arr) = arg_array(args, "exclude_patterns") {
                opts.exclude_patterns = arr.iter().filter_map(|v| v.as_str().map(str::to_string)).collect();
            }
            if let Some(v) = args.get("include_line_numbers").and_then(Value::as_bool) {
                opts.include_line_numbers = v;
            }
            if let Some(v) = args.get("include_symbols").and_then(Value::as_bool) {
                opts.include_symbols = v;
            }
            match crate::code_to_md::pack_to_markdown(&opts).await {
                Ok(res) => {
                    if let Some(ref saved) = res.output_path {
                        format!(
                            "Packed {} ({}) into {}\nFolders: {}, Files: {} ({} included, {} skipped), Lines: {}, Raw bytes: {}\n\nPreview:\n{}",
                            raw_path,
                            res.source_kind,
                            saved.display(),
                            res.total_folders,
                            res.total_files,
                            res.included_files,
                            res.skipped_files,
                            res.total_lines,
                            res.total_bytes,
                            compact_tool_output(&res.markdown, active_tool_output_cap().min(8000))
                        )
                    } else {
                        let cap = active_tool_output_cap().min(32 * 1024);
                        format!(
                            "{}\n\n[Hint: pass output_path=\"bundle.md\" to pack large trees cleanly to disk instead of returning inline markdown.]",
                            truncate_utf8_safe(&redact_secrets_in_text(&res.markdown), cap)
                        )
                    }
                }
                Err(e) => format!("Error packing to markdown: {e}"),
            }
        }

        "inspect_image" => {
            let raw_path = args.get("path").and_then(Value::as_str).unwrap_or("");
            let target = match resolve_tool_path(raw_path, &cfg.cwd, &cfg.workspace_root, cfg.allow_root, true) {
                Ok(p) => p,
                Err(e) => return format!("Error: {e}"),
            };
            let question = args
                .get("question")
                .and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty())
                .unwrap_or("Describe this image in detail, including any visible text, code, or UI elements.");
            let model = args
                .get("model")
                .and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty())
                .unwrap_or("veniceai/deepseek-v4-1-flash-1017-uncensored");
            inspect_image_via_venice(&target, question, model, &cfg.mcp_config_path).await
        }

        "think" => {
            let thought = args.get("thought").and_then(Value::as_str).unwrap_or("").trim();
            if thought.is_empty() {
                "Thought logged (empty).".to_string()
            } else {
                "Your thought has been logged. Proceed with the next minimal action.".to_string()
            }
        }

        "finish" => {
            args.get("message")
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim()
                .to_string()
        }

        "md_to_code" => {
            let raw_dir = args.get("target_dir").and_then(Value::as_str).unwrap_or("");
            let target_dir = match resolve_tool_path(raw_dir, &cfg.cwd, &cfg.workspace_root, cfg.allow_root, false) {
                Ok(p) => p,
                Err(e) => return format!("[status: error] {e}"),
            };
            let md_text = if let Some(md) = args.get("markdown").and_then(Value::as_str).filter(|s| !s.trim().is_empty()) {
                md.to_string()
            } else if let Some(mdp) = args.get("markdown_path").and_then(Value::as_str).filter(|s| !s.trim().is_empty()) {
                let p = match resolve_tool_path(mdp, &cfg.cwd, &cfg.workspace_root, cfg.allow_root, true) {
                    Ok(p) => p,
                    Err(e) => return format!("[status: error] {e}"),
                };
                match tokio::fs::read_to_string(&p).await {
                    Ok(s) => s,
                    Err(e) => return format!("[status: error] reading {}: {e}", p.display()),
                }
            } else {
                return "[status: error] provide either 'markdown' or 'markdown_path'".to_string();
            };
            let dry_run = args.get("dry_run").and_then(Value::as_bool).unwrap_or(false);
            match crate::code_to_md::unpack_from_markdown(&crate::code_to_md::UnpackOptions {
                target_dir,
                markdown: md_text,
                dry_run,
            }).await {
                Ok(res) => {
                    if !dry_run && (res.created > 0 || res.updated > 0) {
                        state.record_file_mutated();
                    }
                    let summary = serde_json::to_string_pretty(&res).unwrap_or_else(|_| "ok".to_string());
                    format!(
                        "[status: ok] created={} updated={} unchanged={} skipped={} | next: run verify_project if files changed\n{summary}",
                        res.created, res.updated, res.unchanged, res.skipped
                    )
                }
                Err(e) => format!("[status: error] unpacking markdown: {e}"),
            }
        }

        "verify_project" => {
            let raw_dir = args.get("project_dir").and_then(Value::as_str).unwrap_or("");
            let project_dir = match resolve_tool_path(raw_dir, &cfg.cwd, &cfg.workspace_root, cfg.allow_root, true) {
                Ok(p) => p,
                Err(e) => return format!("[status: error] {e}"),
            };
            let mut opts = crate::code_to_md::VerifyOptions::new(project_dir);
            if let Some(arr) = arg_array(args, "commands") {
                opts.commands = arr.iter().filter_map(|v| v.as_str().map(str::to_string)).collect();
            }
            if let Some(rt) = args.get("run_tests").and_then(Value::as_bool) {
                opts.run_tests = rt;
            }
            if let Some(ts) = args.get("timeout_secs").and_then(Value::as_u64) {
                opts.timeout_secs = ts;
            }
            if let Some(ep) = args.get("errors_md_path").and_then(Value::as_str).filter(|s| !s.trim().is_empty()) {
                match resolve_tool_path(ep, &cfg.cwd, &cfg.workspace_root, cfg.allow_root, false) {
                    Ok(p) => opts.errors_md_path = Some(p),
                    Err(e) => return format!("[status: error] {e}"),
                }
            }
            match crate::code_to_md::verify_project(&opts).await {
                Ok(res) => {
                    if res.passed {
                        state.clear_dirty();
                        format!("[status: ok] all verification checks passed\n{}", compact_tool_output(&res.errors_md, active_tool_output_cap()))
                    } else {
                        format!("[status: error] verification failed | next: fix errors in errors.md and re-run verify_project\n{}", compact_tool_output(&res.errors_md, active_tool_output_cap()))
                    }
                }
                Err(e) => format!("[status: error] verifying project: {e}"),
            }
        }

        other => format!("Error: unknown tool '{other}'"),
    }
}

fn encode_base64(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[((triple >> 18) & 0x3F) as usize] as char);
        out.push(TABLE[((triple >> 12) & 0x3F) as usize] as char);
        out.push(if chunk.len() > 1 {
            TABLE[((triple >> 6) & 0x3F) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[(triple & 0x3F) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// Resolve `(api_base, api_key)` for Venice from process env with automatic fallback to
/// `mcp_config.json`'s `venice-uncensored` entry so Grok and Gemini (`openhands` MCP) can use
/// Venice vision & delegation seamlessly.
pub fn resolve_venice_credentials(mcp_config_path: &Path) -> (String, String) {
    let mut api_key = std::env::var("VENICE_API_KEY").unwrap_or_default();
    let mut api_base = std::env::var("VENICE_API_BASE")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_default();

    if api_key.trim().is_empty() || api_base.trim().is_empty() {
        if let Ok(Some(srv)) = get_mcp_server_raw(mcp_config_path, "venice-uncensored") {
            if api_key.trim().is_empty() {
                if let Some(k) = srv.env.get("VENICE_API_KEY") {
                    api_key = k.clone();
                }
            }
            if api_base.trim().is_empty() {
                if let Some(b) = srv.env.get("VENICE_API_BASE") {
                    api_base = b.clone();
                }
            }
        }
    }
    if api_base.trim().is_empty() {
        api_base = crate::uncensored::DEFAULT_VENICE_API_BASE.to_string();
    }
    (api_base, api_key)
}

async fn inspect_image_via_venice(
    path: &Path,
    question: &str,
    model: &str,
    mcp_config_path: &Path,
) -> String {
    let (api_base, api_key) = resolve_venice_credentials(mcp_config_path);
    if api_key.trim().is_empty() {
        return "Error: VENICE_API_KEY is not configured in env or mcp_config.json for inspect_image."
            .to_string();
    }

    let bytes = match tokio::fs::read(path).await {
        Ok(b) => b,
        Err(e) => return format!("Error reading image {}: {e}", path.display()),
    };
    if bytes.len() > 10 * 1024 * 1024 {
        return format!("Error: image {} exceeds 10 MB limit ({} bytes)", path.display(), bytes.len());
    }
    let mime = match path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase()
        .as_str()
    {
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "webp" => "image/webp",
        "gif" => "image/gif",
        _ => "image/png",
    };
    let data_url = format!("data:{mime};base64,{}", encode_base64(&bytes));
    let client = match shared_direct_http_client() {
        Ok(c) => c,
        Err(e) => return format!("Error building HTTP client: {e}"),
    };
    let url = format!("{}/chat/completions", api_base.trim_end_matches('/'));
    let payload = json!({
        "model": crate::uncensored::clean_model_id(model),
        "messages": [{
            "role": "user",
            "content": [
                { "type": "text", "text": question },
                { "type": "image_url", "image_url": { "url": data_url } }
            ]
        }],
        "max_tokens": 1024
    });
    let resp = match client
        .post(&url)
        .bearer_auth(api_key.trim())
        .json(&payload)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => return format!("Error calling vision API: {e}"),
    };
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return format!(
            "Vision API HTTP {}: {}",
            status.as_u16(),
            redact_secrets_in_text(&body).chars().take(400).collect::<String>()
        );
    }
    let Ok(doc) = serde_json::from_str::<Value>(&body) else {
        return "Error: invalid JSON from vision API".to_string();
    };
    let answer = doc
        .get("choices")
        .and_then(|c| c.get(0))
        .and_then(|c| c.get("message"))
        .and_then(|m| m.get("content"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    if answer.is_empty() {
        "Vision API returned an empty description.".to_string()
    } else {
        compact_tool_output(answer, active_tool_output_cap())
    }
}

const MAX_TOOL_CALLS_PER_TURN: usize = 8;

fn agy_call_re() -> Option<&'static Regex> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?s)<agy_call>\s*(.*?)\s*</agy_call>").ok()
    })
    .as_ref()
}

fn agy_write_re() -> Option<&'static Regex> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    RE.get_or_init(|| {
        // Supports attributes in any order (`path="..."` and optional `append="true|false"`), single or double quotes
        Regex::new(r#"(?s)<agy_write\b([^>]*)>(?:\r?\n)?(.*?)</agy_write>"#).ok()
    })
    .as_ref()
}

fn agy_exec_re() -> Option<&'static Regex> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    RE.get_or_init(|| {
        // Raw escape-free Python 3 script block -> execute_code (optional timeout_secs/allow_network attrs)
        Regex::new(r#"(?s)<agy_exec(?:\s+([^>]*))?>(?:\r?\n)?(.*?)</agy_exec>"#).ok()
    })
    .as_ref()
}

fn agy_slot_re() -> Option<&'static Regex> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    RE.get_or_init(|| {
        // Raw escape-free slot chunk -> assemble_slots (`name="..."` or `slot="..."`, optional `path="..."`)
        Regex::new(r#"(?s)<agy_slot\b([^>]*)>(?:\r?\n)?(.*?)</agy_slot>"#).ok()
    })
    .as_ref()
}

fn parse_agy_slot_attrs(attrs: &str) -> (String, String) {
    static NAME_RE: OnceLock<Option<Regex>> = OnceLock::new();
    static PATH_RE: OnceLock<Option<Regex>> = OnceLock::new();
    let name_re = NAME_RE.get_or_init(|| Regex::new(r#"(?:name|slot)\s*=\s*(?:"([^"]+)"|'([^']+)')"#).ok());
    let path_re = PATH_RE.get_or_init(|| Regex::new(r#"path\s*=\s*(?:"([^"]+)"|'([^']+)')"#).ok());
    let slot_name = name_re
        .as_ref()
        .and_then(|re| re.captures(attrs))
        .and_then(|c| c.get(1).or_else(|| c.get(2)))
        .map(|m| m.as_str().trim().to_string())
        .unwrap_or_default();
    let path = path_re
        .as_ref()
        .and_then(|re| re.captures(attrs))
        .and_then(|c| c.get(1).or_else(|| c.get(2)))
        .map(|m| m.as_str().trim().to_string())
        .unwrap_or_default();
    (slot_name, path)
}

fn parse_agy_exec_attrs(attrs: &str) -> (Option<u64>, Option<bool>) {
    static TIMEOUT_RE: OnceLock<Option<Regex>> = OnceLock::new();
    static NET_RE: OnceLock<Option<Regex>> = OnceLock::new();
    let timeout_re = TIMEOUT_RE.get_or_init(|| Regex::new(r#"timeout_secs\s*=\s*["']?(\d+)["']?"#).ok());
    let net_re = NET_RE.get_or_init(|| Regex::new(r#"allow_network\s*=\s*["']?(true|false)["']?"#).ok());
    let timeout = timeout_re
        .as_ref()
        .and_then(|re| re.captures(attrs))
        .and_then(|c| c.get(1))
        .and_then(|m| m.as_str().parse::<u64>().ok());
    let allow_net = net_re
        .as_ref()
        .and_then(|re| re.captures(attrs))
        .and_then(|c| c.get(1))
        .map(|m| m.as_str() == "true");
    (timeout, allow_net)
}

fn parse_agy_write_attrs(attrs: &str) -> (String, bool) {
    static PATH_RE: OnceLock<Option<Regex>> = OnceLock::new();
    static APPEND_RE: OnceLock<Option<Regex>> = OnceLock::new();
    let path_re = PATH_RE.get_or_init(|| Regex::new(r#"path\s*=\s*(?:"([^"]+)"|'([^']+)')"#).ok());
    let append_re = APPEND_RE.get_or_init(|| Regex::new(r#"append\s*=\s*(?:"(true|false)"|'(true|false)')"#).ok());
    let path = path_re
        .as_ref()
        .and_then(|re| re.captures(attrs))
        .and_then(|c| c.get(1).or_else(|| c.get(2)))
        .map(|m| m.as_str().trim().to_string())
        .unwrap_or_default();
    let append = append_re
        .as_ref()
        .and_then(|re| re.captures(attrs))
        .and_then(|c| c.get(1).or_else(|| c.get(2)))
        .is_some_and(|m| m.as_str() == "true");
    (path, append)
}

fn xml_tool_call_re() -> Option<&'static Regex> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    RE.get_or_init(|| {
        // Accept standard </tool_call> as well as DeepSeek's tokenizer-collided </｜DSML｜...> closing tag
        Regex::new(r"(?s)<tool_call>\s*(\{.*?\})\s*(?:</tool_call>|</[｜|]DSML[｜|][^>]*>)").ok()
    })
    .as_ref()
}

fn fenced_tool_call_re() -> Option<&'static Regex> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?s)```(?:agy_call|tool_call)\s*\r?\n(\{.*?\})\s*\r?\n```").ok()
    })
    .as_ref()
}

fn dsml_invoke_re() -> Option<&'static Regex> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?s)<[｜|]DSML[｜|]\s*invoke\s+name=["']([^"']+)["']\s*>(.*?)</[｜|]DSML[｜|]\s*invoke>"#).ok()
    })
    .as_ref()
}

fn dsml_param_re() -> Option<&'static Regex> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?s)<[｜|]DSML[｜|]\s*parameter\s+name=["']([^"']+)["'](?:\s+string=["'](true|false)["'])?\s*>(.*?)</[｜|]DSML[｜|]\s*parameter>"#).ok()
    })
    .as_ref()
}

fn strip_markup_re() -> Option<&'static Regex> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(concat!(
            r"(?s)",
            r"<agy_call\b[^>]*>.*?(?:</agy_call>|$)|",
            r"<agy_write\b[^>]*>.*?(?:</agy_write>|$)|",
            r"<agy_exec\b[^>]*>.*?(?:</agy_exec>|$)|",
            r"<agy_slot\b[^>]*>.*?(?:</agy_slot>|$)|",
            r"<tool_call\b[^>]*>.*?(?:</tool_call>|</[｜|]DSML[｜|][^>]*>|$)|",
            r"```(?:agy_call|tool_call)\s*\r?\n.*?```|",
            r"<[｜|]DSML[｜|]\s*(?:function_)?calls>.*?(?:</[｜|]DSML[｜|]\s*(?:function_)?calls>|$)|",
            r"<[｜|]DSML[｜|]\s*invoke\b[^>]*>.*?(?:</[｜|]DSML[｜|]\s*invoke>|$)|",
            // Orphan closing/opening protocol tags (e.g. `</agy_call> </agy_call>` stutter)
            r"</?(?:agy_call|agy_write|agy_exec|agy_slot|tool_call)\b[^>]*>|",
            r"</?[｜|]DSML[｜|][^>]*>|",
            // GLM/Qwen/Heretic XML function-call formats (strictly complete self-closing or matched closing tags so normal prose mentioning `<read_file>` is NEVER truncated!)
            r"<function=[a-z_]+>.*?(?:</function>|$)|",
            r#"<(?:execute_code|read_file|write_file|patch_file|edit_file|run_command|list_dir|grep_files|glob_files|repo_map|diff_files|assemble_slots|discover_mcp_tools|call_mcp_tool|batch_read|multi_edit|file_editor|search_skills|load_skill)\b(?:[^>"']|"[^"]*"|'[^']*')*?(?:/>|>.*?</(?:execute_code|read_file|write_file|patch_file|edit_file|run_command|list_dir|grep_files|glob_files|repo_map|diff_files|assemble_slots|discover_mcp_tools|call_mcp_tool|batch_read|multi_edit|file_editor|search_skills|load_skill)>)"#
        ))
        .ok()
    })
    .as_ref()
}

/// Strip all internal tool-call markup (`<agy_call>`, `<agy_write>`, `<agy_exec>`, `<agy_slot>`, `<tool_call>`, DeepSeek DSML,
/// orphan closing tags, and any trailing partial tag fragment like `<` or `</agy`) so raw protocol
/// syntax never leaks into user-facing Telegram messages.
pub fn strip_tool_call_markup(text: &str) -> String {
    let mut cleaned = match strip_markup_re() {
        Some(re) => re.replace_all(text, "").into_owned(),
        None => text.to_string(),
    };
    // Trim any half-streamed opening/closing tag, trailing `<`, or partial fence iteratively.
    let partial_tag = [
        "<agy_call",
        "</agy_call",
        "<agy_write",
        "</agy_write",
        "<agy_exec",
        "</agy_exec",
        "<agy_slot",
        "</agy_slot",
        "<tool_call",
        "</tool_call",
        "<｜dsml｜",
        "</｜dsml｜",
        "<|dsml|",
        "</|dsml|",
    ];
    loop {
        let before_len = cleaned.len();
        let trimmed_len = cleaned.trim_end().len();
        cleaned.truncate(trimmed_len);
        if let Some(last_lt) = cleaned.rfind('<') {
            let tail = &cleaned[last_lt..];
            let tail_low = tail.to_ascii_lowercase();
            if !tail.contains('>')
                && (tail == "<"
                    || tail == "</"
                    || partial_tag
                        .iter()
                        .any(|p| p.starts_with(&tail_low) || tail_low.starts_with(p)))
            {
                cleaned.truncate(last_lt);
            }
        }
        for prefix in ["```agy_call", "```tool_call", "```agy", "```tool"] {
            if let Some(pos) = cleaned.rfind(prefix) {
                if !cleaned[pos + prefix.len()..].contains('\n') {
                    cleaned.truncate(pos);
                }
            }
        }
        if cleaned.len() == before_len {
            break;
        }
    }
    cleaned.trim().to_string()
}

/// Detect whether streamed text currently contains or is opening a prompt-based tool tag.
fn text_has_tool_markup(text: &str) -> bool {
    text.contains("<agy_call")
        || text.contains("</agy_call")
        || text.contains("<agy_write")
        || text.contains("</agy_write")
        || text.contains("<agy_exec")
        || text.contains("</agy_exec")
        || text.contains("<agy_slot")
        || text.contains("</agy_slot")
        || text.contains("<tool_call")
        || text.contains("</tool_call")
        || text.contains("<｜DSML｜")
        || text.contains("<|DSML|")
        || text.contains("```agy_call")
}

/// Structural silent-truncation detector for Venice Web Chat, where the upstream wrapper ALWAYS
/// emits `finish_reason: "stop"` even when output was cut off mid-tag or mid-code-block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SilentTruncation {
    UnclosedAgyWrite { path: String, partial_bytes: usize },
    UnclosedAgyExec { partial_bytes: usize },
    UnclosedAgySlot { slot: String, partial_bytes: usize },
    UnclosedAgyCall,
    UnclosedCodeFence,
}

pub fn detect_silent_venice_truncation(raw: &str) -> Option<SilentTruncation> {
    if let Some(open_idx) = raw.rfind("<agy_write") {
        let tail = &raw[open_idx..];
        if !tail.contains("</agy_write>") {
            let (path, _) = tail
                .find('>')
                .map(|gt| parse_agy_write_attrs(&tail["<agy_write".len()..gt]))
                .unwrap_or_default();
            let partial_bytes = tail
                .find('>')
                .map(|gt| tail[gt + 1..].len())
                .unwrap_or(0);
            return Some(SilentTruncation::UnclosedAgyWrite { path, partial_bytes });
        }
    }
    if let Some(open_idx) = raw.rfind("<agy_exec") {
        let tail = &raw[open_idx..];
        if !tail.contains("</agy_exec>") {
            let partial_bytes = tail
                .find('>')
                .map(|gt| tail[gt + 1..].len())
                .unwrap_or(0);
            return Some(SilentTruncation::UnclosedAgyExec { partial_bytes });
        }
    }
    if let Some(open_idx) = raw.rfind("<agy_slot") {
        let tail = &raw[open_idx..];
        if !tail.contains("</agy_slot>") {
            let (slot, _) = tail
                .find('>')
                .map(|gt| parse_agy_slot_attrs(&tail["<agy_slot".len()..gt]))
                .unwrap_or_default();
            let partial_bytes = tail
                .find('>')
                .map(|gt| tail[gt + 1..].len())
                .unwrap_or(0);
            return Some(SilentTruncation::UnclosedAgySlot { slot, partial_bytes });
        }
    }
    if let Some(open_idx) = raw.rfind("<agy_call>") {
        let tail = &raw[open_idx + "<agy_call>".len()..];
        if !tail.contains("</agy_call>") && extract_balanced_json_object(tail).is_none() {
            return Some(SilentTruncation::UnclosedAgyCall);
        }
    }
    let fence_lines = raw
        .lines()
        .filter(|l| l.trim_start().starts_with("```"))
        .count();
    if fence_lines % 2 == 1 {
        return Some(SilentTruncation::UnclosedCodeFence);
    }
    None
}

fn nth_tag_end(content: &str, tag: &str, nth_1based: usize) -> Option<usize> {
    let mut search_from = 0usize;
    let mut count = 0usize;
    while let Some(rel) = content[search_from..].find(tag) {
        let abs_end = search_from + rel + tag.len();
        count += 1;
        if count == nth_1based {
            return Some(abs_end);
        }
        search_from = abs_end;
    }
    None
}

fn is_inside_open_agy_write(content: &str) -> bool {
    let open_write = match content.rfind("<agy_write") {
        Some(open_idx) => !content[open_idx..].contains("</agy_write>"),
        None => false,
    };
    let open_exec = match content.rfind("<agy_exec") {
        Some(open_idx) => !content[open_idx..].contains("</agy_exec>"),
        None => false,
    };
    let open_slot = match content.rfind("<agy_slot") {
        Some(open_idx) => !content[open_idx..].contains("</agy_slot>"),
        None => false,
    };
    open_write || open_exec || open_slot
}

/// Real-time SSE & post-response circuit breaker for degenerate tool-tag loops:
/// 1. Orphan/repeated closing tags (`</agy_call> </agy_call>...`, `</agy_write>`, `</agy_exec>`, `</agy_slot>`, `</tool_call>`)
/// 2. Runaway tool-call flood (> `MAX_TOOL_CALLS_PER_TURN` completed calls in one turn)
/// 3. Consecutive repeated tail token/substring loop (>= 6 repeats outside `<agy_write>`/`<agy_exec>`/`<agy_slot>` body)
///
/// Returns `Some((clean_truncate_byte_idx, reason))` when triggered.
pub fn detect_tool_stream_degeneration(content: &str) -> Option<(usize, &'static str)> {
    // 1. Orphan/repeated closing tags
    for (open_prefix, close_tag, reason) in [
        ("<agy_call", "</agy_call>", "repeated orphan </agy_call> closing tag"),
        ("<agy_write", "</agy_write>", "repeated orphan </agy_write> closing tag"),
        ("<agy_exec", "</agy_exec>", "repeated orphan </agy_exec> closing tag"),
        ("<agy_slot", "</agy_slot>", "repeated orphan </agy_slot> closing tag"),
        ("<tool_call", "</tool_call>", "repeated orphan </tool_call> closing tag"),
    ] {
        let open_n = content.matches(open_prefix).count();
        let close_n = content.matches(close_tag).count();
        if close_n > open_n {
            if open_n > 0 {
                if let Some(end_idx) = nth_tag_end(content, close_tag, open_n) {
                    return Some((end_idx, reason));
                }
            } else if close_n >= 2 {
                if let Some(first_close) = content.find(close_tag) {
                    return Some((first_close, reason));
                }
            }
        }
    }

    // 2. Runaway tool-call flood (> MAX_TOOL_CALLS_PER_TURN completed calls)
    let total_closed = content.matches("</agy_call>").count()
        + content.matches("</agy_write>").count()
        + content.matches("</agy_exec>").count()
        + content.matches("</agy_slot>").count()
        + content.matches("</tool_call>").count();
    if total_closed >= MAX_TOOL_CALLS_PER_TURN {
        let mut positions = Vec::with_capacity(total_closed);
        for tag in ["</agy_call>", "</agy_write>", "</agy_exec>", "</agy_slot>", "</tool_call>"] {
            let mut pos = 0usize;
            while let Some(rel) = content[pos..].find(tag) {
                let end = pos + rel + tag.len();
                positions.push(end);
                pos = end;
            }
        }
        positions.sort_unstable();
        if positions.len() >= MAX_TOOL_CALLS_PER_TURN {
            // Only cut if there is trailing content after the 8th tag (or at MAX_TOOL_CALLS_PER_TURN + 1)
            if positions.len() > MAX_TOOL_CALLS_PER_TURN
                || content[positions[MAX_TOOL_CALLS_PER_TURN - 1]..].len() > 24
            {
                return Some((positions[MAX_TOOL_CALLS_PER_TURN - 1], "runaway tool call flood (>8 calls/turn)"));
            }
        }
    }

    // 3. Consecutive repeated tail phrase/token loop (skip inside <agy_write> file body)
    if content.len() >= 200 && !is_inside_open_agy_write(content) {
        let mut win_start = content.len().saturating_sub(320);
        while win_start < content.len() && !content.is_char_boundary(win_start) {
            win_start += 1;
        }
        let tail = content[win_start..].trim_end();
        if tail.len() >= 36 {
            for unit_len in 4usize..=48 {
                if unit_len * 6 > tail.len() {
                    break;
                }
                let unit_start = tail.len() - unit_len;
                if !tail.is_char_boundary(unit_start) {
                    continue;
                }
                let unit = &tail[unit_start..];
                if unit.trim().is_empty() {
                    continue;
                }
                let mut reps = 1usize;
                let mut cursor = unit_start;
                while cursor >= unit_len {
                    let prev_slice = tail[..cursor].trim_end_matches([' ', '\t', '\r', '\n']);
                    if prev_slice.ends_with(unit) {
                        reps += 1;
                        cursor = prev_slice.len() - unit_len;
                    } else {
                        break;
                    }
                }
                if reps >= 6 {
                    let cut_abs = win_start + cursor;
                    if cut_abs <= content.len() && content.is_char_boundary(cut_abs) {
                        return Some((cut_abs, "repetitive token loop detected"));
                    }
                }
            }
        }
    }

    None
}

/// Sanitize a complete (streaming or non-streaming) model response by applying the degeneration
/// circuit breaker so runaway `</agy_call>` repeats never pollute history or downstream parsing.
pub fn sanitize_degenerate_tool_response(content: &str) -> String {
    let mut cur = content.to_string();
    for _ in 0..2 {
        if let Some((cut_idx, _)) = detect_tool_stream_degeneration(&cur) {
            if cut_idx < cur.len() && cur.is_char_boundary(cut_idx) {
                cur.truncate(cut_idx);
                continue;
            }
        }
        break;
    }
    cur
}

/// Escape literal control characters (`\n`, `\r`, `\t`) appearing inside JSON string literals
/// and strip trailing commas before `}`/`]` — recovers the #1 LLM JSON failure mode when writing code.
fn repair_json_control_chars(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len() + 32);
    let mut in_str = false;
    let mut escaped = false;
    for ch in raw.chars() {
        if in_str {
            if escaped {
                out.push(ch);
                escaped = false;
                continue;
            }
            match ch {
                '\\' => {
                    out.push(ch);
                    escaped = true;
                }
                '"' => {
                    out.push(ch);
                    in_str = false;
                }
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
                other => out.push(other),
            }
        } else {
            if ch == '"' {
                in_str = true;
            }
            out.push(ch);
        }
    }
    // Remove trailing commas right before `}` or `]` outside strings
    let mut final_out = String::with_capacity(out.len());
    let chars: Vec<char> = out.chars().collect();
    let mut i = 0usize;
    let mut in_s = false;
    let mut esc = false;
    while i < chars.len() {
        let c = chars[i];
        if in_s {
            final_out.push(c);
            if esc {
                esc = false;
            } else if c == '\\' {
                esc = true;
            } else if c == '"' {
                in_s = false;
            }
            i += 1;
            continue;
        }
        if c == '"' {
            in_s = true;
            final_out.push(c);
            i += 1;
            continue;
        }
        if c == ',' {
            let mut j = i + 1;
            while j < chars.len() && chars[j].is_whitespace() {
                j += 1;
            }
            if j < chars.len() && matches!(chars[j], '}' | ']') {
                i += 1;
                continue;
            }
        }
        final_out.push(c);
        i += 1;
    }
    final_out
}

/// Extract the first balanced JSON object `{...}` slice from `s` (respecting string escapes).
fn extract_balanced_json_object(s: &str) -> Option<&str> {
    let start = s.find('{')?;
    let mut depth = 0i32;
    let mut in_str = false;
    let mut escaped = false;
    for (rel, ch) in s[start..].char_indices() {
        if in_str {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_str = false;
            }
            continue;
        }
        match ch {
            '"' => in_str = true,
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&s[start..start + rel + ch.len_utf8()]);
                }
            }
            _ => {}
        }
    }
    None
}

/// Parse a tool JSON payload strictly first, then with control-character/trailing-comma repair.
fn parse_tool_json_relaxed(raw: &str) -> std::result::Result<Value, String> {
    let trimmed = raw.trim();
    if let Ok(v) = serde_json::from_str::<Value>(trimmed) {
        return Ok(v);
    }
    let repaired = repair_json_control_chars(trimmed);
    if let Ok(v) = serde_json::from_str::<Value>(&repaired) {
        return Ok(v);
    }
    if let Some(obj) = extract_balanced_json_object(&repaired) {
        if let Ok(v) = serde_json::from_str::<Value>(obj) {
            return Ok(v);
        }
    }
    let err = serde_json::from_str::<Value>(trimmed).unwrap_err();
    Err(err.to_string())
}

fn push_parsed_envelope(
    parsed: &mut Vec<(String, String, Value)>,
    prefix: &str,
    raw_json: &str,
) {
    match parse_tool_json_relaxed(raw_json) {
        Ok(v) => {
            if let Some(name) = v
                .get("name")
                .or_else(|| v.get("tool"))
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                let args = match v.get("arguments").or_else(|| v.get("parameters")).or_else(|| v.get("args")) {
                    Some(Value::String(s)) => parse_tool_json_relaxed(s).unwrap_or_else(|e| {
                        json!({
                            "__parse_error": format!(
                                "tool `{name}` arguments JSON invalid ({} bytes: {e}). Use <agy_write path=\"...\">...</agy_write> for full files or valid compact JSON.",
                                s.len()
                            )
                        })
                    }),
                    Some(obj @ Value::Object(_)) => obj.clone(),
                    _ => json!({}),
                };
                let idx = parsed.len();
                parsed.push((format!("{prefix}_{idx}"), name.to_string(), args));
            }
        }
        Err(e) => {
            // Try to salvage the tool name for an actionable self-healing error message
            let guessed_name = Regex::new(r#""name"\s*:\s*"([A-Za-z0-9_]+)""#)
                .ok()
                .and_then(|re| re.captures(raw_json))
                .and_then(|c| c.get(1))
                .map(|m| m.as_str().to_string());
            if let Some(name) = guessed_name {
                let idx = parsed.len();
                parsed.push((
                    format!("{prefix}_err_{idx}"),
                    name.clone(),
                    json!({
                        "__parse_error": format!(
                            "tool `{name}` JSON payload was malformed/truncated ({} bytes: {e}). For writing files, prefer <agy_write path=\"/path/file\">raw code</agy_write> (zero JSON escaping needed) or write_file(append=true).",
                            raw_json.len()
                        )
                    }),
                ));
            }
        }
    }
}

fn is_known_agent_tool_name(name: &str) -> bool {
    matches!(
        name,
        "run_command"
            | "process_manage"
            | "execute_code"
            | "read_file"
            | "batch_read"
            | "multi_edit"
            | "write_file"
            | "patch_file"
            | "edit_file"
            | "list_dir"
            | "file_editor"
            | "glob_files"
            | "find_symbols"
            | "git_ops"
            | "task_tracker"
            | "grep_files"
            | "web_search"
            | "fetch_url"
            | "list_mcp_servers"
            | "discover_mcp_tools"
            | "call_mcp_tool"
            | "repo_map"
            | "diff_files"
            | "assemble_slots"
            | "memory_search"
            | "memory_store"
            | "search_skills"
            | "load_skill"
            | "skillhub_search"
            | "skillhub_catalog"
            | "skillhub_get"
            | "code_to_md"
            | "md_to_code"
            | "verify_project"
            | "inspect_image"
            | "think"
            | "finish"
    )
}

fn push_parsed_envelope_with_offset(
    positioned: &mut Vec<(usize, String, String, Value)>,
    offset: usize,
    prefix: &str,
    raw_json: &str,
) {
    let mut tmp = Vec::with_capacity(1);
    push_parsed_envelope(&mut tmp, prefix, raw_json);
    for (id, name, args) in tmp {
        positioned.push((offset, id, name, args));
    }
}

/// Extract parsed tool calls in **exact document order** from:
/// 1. Standard OpenAI `msg["tool_calls"]` (string or object arguments, with relaxed JSON repair),
/// 2. Escape-free `<agy_write path="...">...</agy_write>` + neutral `<agy_call>{...}</agy_call>` (sorted by byte offset),
/// 3. `<tool_call>{...}</tool_call>` (including DeepSeek broken closing tag) & fenced ` ```agy_call `,
/// 4. DeepSeek native DSML XML `<｜DSML｜ invoke name="...">...</｜DSML｜ invoke>`,
/// 5. Bare single JSON object `{"name": "<known_tool>", "arguments": {...}}` fallback.
///
/// Deduplicates exact duplicate tool calls in the same turn and caps at `MAX_TOOL_CALLS_PER_TURN`.
pub fn extract_tool_calls(msg: &Value, content_text: &str) -> Vec<(String, String, Value)> {
    let mut parsed = Vec::new();
    if let Some(arr) = msg.get("tool_calls").and_then(Value::as_array) {
        for (idx, tc) in arr.iter().enumerate() {
            let id = tc
                .get("id")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .unwrap_or_else(|| format!("call_{idx}"));
            let func = tc.get("function");
            let name = func
                .and_then(|f| f.get("name"))
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim()
                .to_string();
            if name.is_empty() {
                continue;
            }
            let args_val = match func.and_then(|f| f.get("arguments")) {
                Some(Value::String(s)) => parse_tool_json_relaxed(s).unwrap_or_else(|e| {
                    json!({
                        "__parse_error": format!(
                            "tool `{name}` arguments JSON was truncated or invalid ({} bytes: {e}). For large files, use <agy_write path=\"...\">...</agy_write>, write_file with append=true in chunks, patch_file, or execute_code.",
                            s.len()
                        )
                    })
                }),
                Some(v @ Value::Object(_)) => v.clone(),
                _ => json!({}),
            };
            parsed.push((id, name, args_val));
        }
    }

    if !parsed.is_empty() || content_text.trim().is_empty() {
        return parsed;
    }

    let cleaned_text = sanitize_degenerate_tool_response(content_text);
    let mut positioned: Vec<(usize, String, String, Value)> = Vec::new();

    // 2. Escape-free <agy_write ...>...</agy_write> -> write_file (tracked with byte offset)
    if cleaned_text.contains("<agy_write") {
        if let Some(re) = agy_write_re() {
            for cap in re.captures_iter(&cleaned_text) {
                let offset = cap.get(0).map_or(0, |m| m.start());
                let attrs = cap.get(1).map_or("", |m| m.as_str());
                let body = cap.get(2).map_or("", |m| m.as_str());
                let (path, append) = parse_agy_write_attrs(attrs);
                if !path.is_empty() {
                    let idx = positioned.len();
                    positioned.push((
                        offset,
                        format!("agy_write_{idx}"),
                        "write_file".to_string(),
                        json!({
                            "path": path,
                            "content": body,
                            "append": append,
                        }),
                    ));
                }
            }
        }
    }

    // 2b. Escape-free <agy_exec>...</agy_exec> -> execute_code (zero JSON escaping errors for Python scripts!)
    if cleaned_text.contains("<agy_exec") {
        if let Some(re) = agy_exec_re() {
            for cap in re.captures_iter(&cleaned_text) {
                let offset = cap.get(0).map_or(0, |m| m.start());
                let attrs = cap.get(1).map_or("", |m| m.as_str());
                let code = cap.get(2).map_or("", |m| m.as_str()).trim_matches('\n');
                if !code.trim().is_empty() {
                    let (timeout_secs, allow_network) = parse_agy_exec_attrs(attrs);
                    let mut args_map = serde_json::Map::new();
                    args_map.insert("code".to_string(), Value::String(code.to_string()));
                    if let Some(t) = timeout_secs {
                        args_map.insert("timeout_secs".to_string(), json!(t));
                    }
                    if let Some(net) = allow_network {
                        args_map.insert("allow_network".to_string(), json!(net));
                    }
                    let idx = positioned.len();
                    positioned.push((
                        offset,
                        format!("agy_exec_{idx}"),
                        "execute_code".to_string(),
                        Value::Object(args_map),
                    ));
                }
            }
        }
    }

    // 2c. Escape-free <agy_slot name="..." path?="...">...</agy_slot> -> assemble_slots (Contract-First chunks)
    if cleaned_text.contains("<agy_slot") {
        if let Some(re) = agy_slot_re() {
            for cap in re.captures_iter(&cleaned_text) {
                let offset = cap.get(0).map_or(0, |m| m.start());
                let attrs = cap.get(1).map_or("", |m| m.as_str());
                let code = cap.get(2).map_or("", |m| m.as_str());
                let (slot_name, path) = parse_agy_slot_attrs(attrs);
                if !slot_name.is_empty() {
                    let mut args_map = serde_json::Map::new();
                    args_map.insert("command".to_string(), json!("replace"));
                    args_map.insert("slot".to_string(), json!(slot_name));
                    args_map.insert("code".to_string(), json!(code));
                    if !path.is_empty() {
                        args_map.insert("path".to_string(), json!(path));
                    }
                    let idx = positioned.len();
                    positioned.push((
                        offset,
                        format!("agy_slot_{idx}"),
                        "assemble_slots".to_string(),
                        Value::Object(args_map),
                    ));
                }
            }
        }
    }

    // 3. Primary neutral <agy_call>{...}</agy_call> (tracked with byte offset)
    if cleaned_text.contains("<agy_call>") {
        let before = positioned.len();
        if let Some(re) = agy_call_re() {
            for cap in re.captures_iter(&cleaned_text) {
                let offset = cap.get(0).map_or(0, |m| m.start());
                let raw_json = cap.get(1).map_or("", |m| m.as_str());
                push_parsed_envelope_with_offset(&mut positioned, offset, "agy_call", raw_json);
            }
        }
        // Fallback for an unclosed trailing <agy_call>{...} without closing tag
        if positioned.len() == before {
            if let Some(pos) = cleaned_text.find("<agy_call>") {
                let tail = &cleaned_text[pos + "<agy_call>".len()..];
                if let Some(obj) = extract_balanced_json_object(tail) {
                    push_parsed_envelope_with_offset(&mut positioned, pos, "agy_call", obj);
                }
            }
        }
    }

    // Preserve exact document order across <agy_call> and <agy_write>
    if !positioned.is_empty() {
        positioned.sort_by_key(|(off, _, _, _)| *off);
        parsed = positioned
            .into_iter()
            .map(|(_, id, name, args)| (id, name, args))
            .collect();
    }

    // 4. <tool_call>{...}</tool_call> (including DeepSeek </｜DSML｜...> collision) & fenced blocks
    if parsed.is_empty() && cleaned_text.contains("<tool_call>") {
        if let Some(re) = xml_tool_call_re() {
            for cap in re.captures_iter(&cleaned_text) {
                let raw_json = cap.get(1).map_or("", |m| m.as_str());
                push_parsed_envelope(&mut parsed, "xml_call", raw_json);
            }
        }
        if parsed.is_empty() {
            if let Some(pos) = cleaned_text.find("<tool_call>") {
                let tail = &cleaned_text[pos + "<tool_call>".len()..];
                if let Some(obj) = extract_balanced_json_object(tail) {
                    push_parsed_envelope(&mut parsed, "xml_call", obj);
                }
            }
        }
    }

    if parsed.is_empty() && (cleaned_text.contains("```agy_call") || cleaned_text.contains("```tool_call")) {
        if let Some(re) = fenced_tool_call_re() {
            for cap in re.captures_iter(&cleaned_text) {
                let raw_json = cap.get(1).map_or("", |m| m.as_str());
                push_parsed_envelope(&mut parsed, "fence_call", raw_json);
            }
        }
    }

    // 5. DeepSeek native DSML XML
    if parsed.is_empty() && (cleaned_text.contains("DSML") && cleaned_text.contains("invoke")) {
        if let (Some(inv_re), Some(param_re)) = (dsml_invoke_re(), dsml_param_re()) {
            for cap in inv_re.captures_iter(&cleaned_text) {
                let name = cap.get(1).map_or("", |m| m.as_str()).trim();
                let inner = cap.get(2).map_or("", |m| m.as_str());
                if name.is_empty() {
                    continue;
                }
                let mut map = serde_json::Map::new();
                for pcap in param_re.captures_iter(inner) {
                    let pname = pcap.get(1).map_or("", |m| m.as_str()).trim();
                    let is_str = pcap.get(2).map_or("true", |m| m.as_str()) != "false";
                    let raw_val = pcap.get(3).map_or("", |m| m.as_str());
                    if pname.is_empty() {
                        continue;
                    }
                    let val = if !is_str {
                        serde_json::from_str::<Value>(raw_val.trim())
                            .unwrap_or_else(|_| Value::String(raw_val.to_string()))
                    } else {
                        Value::String(raw_val.to_string())
                    };
                    map.insert(pname.to_string(), val);
                }
                let idx = parsed.len();
                parsed.push((format!("dsml_call_{idx}"), name.to_string(), Value::Object(map)));
            }
        }
    }

    // 6. Bare JSON fallback when open models emit a standalone {"name": "<known_tool>", "arguments": {...}}
    if parsed.is_empty() {
        let trimmed = cleaned_text.trim();
        if trimmed.starts_with('{') && trimmed.ends_with('}') {
            if let Ok(v) = parse_tool_json_relaxed(trimmed) {
                if let Some(name) = v.get("name").and_then(Value::as_str).map(str::trim) {
                    if is_known_agent_tool_name(name) {
                        push_parsed_envelope(&mut parsed, "json_call", trimmed);
                    }
                }
            }
        }
    }

    // 7. Direct XML tool tags (GLM-4.7-Heretic / Qwen / Anthropic-style XML):
    //    e.g. `<execute_code allow_network="false" code="..."/>`, `<write_file path="...">body</write_file>`,
    //    or `<function=read_file><parameter=path>a.py</parameter></function>`.
    if parsed.is_empty() && cleaned_text.contains('<') {
        extract_direct_xml_tool_calls(&cleaned_text, &mut parsed);
    }

    // Deduplicate identical tool calls within a single turn & cap at MAX_TOOL_CALLS_PER_TURN
    let mut seen_sigs: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut deduped = Vec::with_capacity(parsed.len().min(MAX_TOOL_CALLS_PER_TURN));
    for (id, name, args) in parsed {
        if !matches!(name.as_str(), "think" | "process_manage") {
            let sig = format!("{name}:{}", serde_json::to_string(&args).unwrap_or_default());
            if !seen_sigs.insert(sig) {
                continue;
            }
        }
        deduped.push((id, name, args));
        if deduped.len() >= MAX_TOOL_CALLS_PER_TURN {
            break;
        }
    }
    deduped
}

/// Whether this engine talks to Venice Web / OmniRoute (`/api/inference/chat`) where OpenAI
/// `tools` arrays are stripped upstream and empty assistant messages trigger HTTP 400.
fn is_venice_engine(cfg: &AgentTurnConfig) -> bool {
    cfg.engine_id == "uncensored"
        || cfg.model.starts_with("veniceai/")
        || cfg.model.starts_with("venice-web/")
        || cfg.model.starts_with("ven/")
}

fn is_venice_prompt_engine(cfg: &AgentTurnConfig) -> bool {
    is_venice_engine(cfg) || cfg.engine_id == "gemini_web"
}

/// Render a single parameter type concisely while PRESERVING `enum` values and nested array item keys
/// (Venice Web Chat strips OpenAI `tools` JSON, so this text is the model's ONLY schema source).
fn render_compact_param_type(v: &Value) -> String {
    if let Some(en) = v.get("enum").and_then(Value::as_array) {
        let vals: Vec<&str> = en.iter().filter_map(Value::as_str).collect();
        if !vals.is_empty() {
            return vals.join("|");
        }
    }
    let ty = v.get("type").and_then(Value::as_str).unwrap_or("any");
    if ty == "array" {
        if let Some(items) = v.get("items") {
            if let Some(props) = items.get("properties").and_then(Value::as_object) {
                let req: Vec<&str> = items
                    .get("required")
                    .and_then(Value::as_array)
                    .map(|a| a.iter().filter_map(Value::as_str).collect())
                    .unwrap_or_default();
                let mut keys = Vec::new();
                for (ik, iv) in props {
                    let opt = if req.contains(&ik.as_str()) { "" } else { "?" };
                    if let Some(ien) = iv.get("enum").and_then(Value::as_array) {
                        let ivs: Vec<&str> = ien.iter().filter_map(Value::as_str).collect();
                        if !ivs.is_empty() {
                            keys.push(format!("{ik}{opt}:{}", ivs.join("|")));
                            continue;
                        }
                    }
                    keys.push(format!("{ik}{opt}"));
                }
                return format!("[{{{}}}]", keys.join(","));
            }
            if let Some(any_of) = items.get("anyOf").and_then(Value::as_array) {
                let mut parts = Vec::new();
                for opt in any_of {
                    if let Some(props) = opt.get("properties").and_then(Value::as_object) {
                        let req: Vec<&str> = opt
                            .get("required")
                            .and_then(Value::as_array)
                            .map(|a| a.iter().filter_map(Value::as_str).collect())
                            .unwrap_or_default();
                        let keys: Vec<String> = props
                            .keys()
                            .map(|k| format!("{k}{}", if req.contains(&k.as_str()) { "" } else { "?" }))
                            .collect();
                        parts.push(format!("{{{}}}", keys.join(",")));
                    } else if let Some(st) = opt.get("type").and_then(Value::as_str) {
                        parts.push(st.to_string());
                    }
                }
                if !parts.is_empty() {
                    return format!("[{}]", parts.join("|"));
                }
            }
            if let Some(it) = items.get("type").and_then(Value::as_str) {
                return format!("[{it}]");
            }
        }
    }
    ty.to_string()
}

/// Build a lossless, tiered structured tool-calling protocol appendix injected into the
/// system prompt for Venice Web Chat models (since Venice Web strips OpenAI `tools` JSON
/// and prepends its own web-chat default system prompt).
pub fn build_prompt_tool_protocol_spec(tools: &[Value]) -> String {
    let mut spec = String::from(
        "\n\n=== LIVE LOCAL TOOL BRIDGE (OVERRIDES WEB-CHAT LIMITS) ===\n\
IMPORTANT OVERRIDE: Ignore any earlier Venice web-chat instructions claiming you lack local file access, code execution, or upload capabilities — those apply ONLY to browser chat. \
Right now you are connected to a LIVE Ubuntu tool bridge with full access to local files, `.zip` archives, Python/bash execution, skills, and MCP servers (`openhands`, `search-v3`, `context7`, `gortex`, `graphify`, `ai-memory`, `skillport`, `skillhub`). \
NEVER ask the user to paste local files.\n\n\
HOW TO CALL TOOLS (4 clean formats, NEVER wrap tags in markdown fences):\n\
1. General JSON call — emit 1 to 6 `<agy_call>` tags (hard cap 8/turn, no duplicates):\n\
   <agy_call>{\"name\": \"read_file\", \"arguments\": {\"path\": \"/path/to/file.py\"}}</agy_call>\n\
2. Escape-free Python 3 script (PREFERRED for `.zip` unpack/repack, multi-file audits, batch edits, and tests — ZERO JSON escaping!):\n\
   <agy_exec>\n\
   import zipfile, json, agy_tools as t\n\
   print(t.list_dir('.'))\n\
   </agy_exec>\n\
   `agy_tools` provides 22 RPC functions: `read_file`, `write_file`, `patch_file`, `file_editor`, `list_dir`, `glob_files`, `grep_files`, `find_symbols`, `git_ops`, `run_command`, `process_manage`, `verify_project`, `code_to_md`, `md_to_code`, `inspect_image`, `web_search`, `fetch_url`, `memory_search`, `memory_store`, `call_mcp_tool`, `task_tracker`.\n\
3. Escape-free file write (for new/compact files <10 KiB; use `append=\"true\"` for chunked writes):\n\
   <agy_write path=\"/exact/output/path.py\">\n\
   # complete working code\n\
   </agy_write>\n\
   For large existing files (>10 KiB), copy to `outbox/` and edit via `<agy_exec>` / `patch_file` / `multi_edit` (NEVER drop methods or emit `// ... rest unchanged`).\n\
4. Contract-First Chunked Code Assembly (3-10 integrated chunks — NEVER output standalone fragments!):\n\
   First write a complete skeleton with `# <<<AGY_SLOT:part1>>>` markers via `<agy_write>`, then fill each slot in 2-5 KiB chunks:\n\
   <agy_slot name=\"part1\">\n\
   # integrated code body ONLY (no repeated file-header boilerplate)\n\
   </agy_slot>\n\
5. STRICT STOP RULE: STOP generating IMMEDIATELY after your final `</agy_call>`, `</agy_write>`, `</agy_exec>`, or `</agy_slot>` tag and wait for `[Tool Result]`. NEVER repeat closing tags or fabricate outputs.\n\
6. MANDATORY OUTBOX DELIVERY: When an `outbox/.../` path is given and file creation/fixes are requested, write verified files inside that exact `outbox/.../` directory and run real syntax/runtime checks (`python3`, `node --check`, `php -l`, `bash -n`) BEFORE giving your final prose reply (with NO tool tags).\n",
    );

    const CORE_TOOLS: &[&str] = &[
        "execute_code",
        "assemble_slots",
        "read_file",
        "batch_read",
        "write_file",
        "patch_file",
        "multi_edit",
        "file_editor",
        "run_command",
        "repo_map",
        "diff_files",
        "discover_mcp_tools",
        "call_mcp_tool",
    ];

    let format_tool_line = |f: &Value, desc_cap: usize| -> Option<String> {
        let name = f.get("name").and_then(Value::as_str).unwrap_or("");
        if name.is_empty() || name == "edit_file" {
            // `edit_file` is kept as a silent runtime alias for `patch_file` to save prompt budget.
            return None;
        }
        let desc = f
            .get("description")
            .and_then(Value::as_str)
            .unwrap_or("")
            .lines()
            .next()
            .unwrap_or("");
        let required: Vec<&str> = f
            .pointer("/parameters/required")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        let mut params_str = Vec::new();
        if let Some(props) = f.pointer("/parameters/properties").and_then(Value::as_object) {
            for (k, v) in props {
                let ty = render_compact_param_type(v);
                let opt = if required.contains(&k.as_str()) { "" } else { "?" };
                params_str.push(format!("{k}{opt}:{ty}"));
            }
        }
        let short_desc = clip_chars(desc, desc_cap);
        Some(format!("- `{name}({})` — {short_desc}\n", params_str.join(", ")))
    };

    spec.push_str("\nCORE TOOLS (exact lossless schemas):\n");
    for &core_name in CORE_TOOLS {
        if let Some(f) = tools
            .iter()
            .filter_map(|t| t.get("function"))
            .find(|f| f.get("name").and_then(Value::as_str) == Some(core_name))
        {
            if let Some(line) = format_tool_line(f, 200) {
                spec.push_str(&line);
            }
        }
    }

    spec.push_str("\nEXTENDED TOOLS (search, skills, git, packs, verify, memory):\n");
    for t in tools {
        let Some(f) = t.get("function") else {
            continue;
        };
        let name = f.get("name").and_then(Value::as_str).unwrap_or("");
        if CORE_TOOLS.contains(&name) {
            continue;
        }
        if let Some(line) = format_tool_line(f, 150) {
            spec.push_str(&line);
        }
    }
    spec
}

/// Hard per-message byte cap for Venice Web Chat (`~128 KB` triggers upstream `HTTP 413 userPromptTooLong`).
const VENICE_MAX_SINGLE_MSG_BYTES: usize = 72 * 1024;

/// Sanitize OpenAI message history for Venice Web / OmniRoute (`/api/inference/chat`):
/// - Keeps ONLY the primary `role == "system"` message at index 0; converts later system notices
///   (e.g. condenser snapshots) into `role: "user"` so Venice's single `systemPrompt` is never overwritten.
/// - Enforces STRICT `user ↔ assistant` alternation (coalesces adjacent `user` AND adjacent `assistant`
///   messages, guarantees first non-system is `user` and last message is `user`) to prevent Venice
///   Web Chat's silent conversation-history wipe on malformed role sequences.
/// - Caps every single message cleanly at `VENICE_MAX_SINGLE_MSG_BYTES` (72 KiB) so coalesced parallel
///   tool results NEVER hit Venice's ~128 KiB `HTTP 413 userPromptTooLong` wall.
fn sanitize_venice_message_text(raw: &str, fallback: &str) -> String {
    // Strip NUL and non-whitespace C0 control bytes that cause Venice Zod 400 validation errors
    // (e.g. accidental binary/zip output or raw terminal control codes).
    let cleaned: String = raw
        .chars()
        .filter(|&c| c == '\n' || c == '\r' || c == '\t' || (c >= ' ' && c != '\u{007f}'))
        .collect();
    if cleaned.trim().is_empty() {
        fallback.to_string()
    } else if cleaned.len() > VENICE_MAX_SINGLE_MSG_BYTES {
        let keep = VENICE_MAX_SINGLE_MSG_BYTES.saturating_sub(240);
        format!(
            "{}\n... [truncated from {} B to fit Venice 72 KiB turn budget — use read_file(start_line, end_line) or grep_files for narrower slices]",
            truncate_utf8_safe(&cleaned, keep),
            cleaned.len()
        )
    } else {
        cleaned
    }
}

pub fn prepare_messages_for_venice(messages: &[Value]) -> Vec<Value> {
    let mut out: Vec<Value> = Vec::with_capacity(messages.len());
    let mut saw_system = false;

    for m in messages {
        let role = m.get("role").and_then(Value::as_str).unwrap_or("user");
        match role {
            "system" => {
                let text = sanitize_venice_message_text(
                    m.get("content").and_then(Value::as_str).unwrap_or("").trim(),
                    "",
                );
                if text.is_empty() {
                    continue;
                }
                if !saw_system {
                    saw_system = true;
                    out.push(json!({ "role": "system", "content": text }));
                } else {
                    let wrapped = format!("[Runtime State Update]\n{text}");
                    if let Some(last) = out.last_mut() {
                        if last.get("role").and_then(Value::as_str) == Some("user") {
                            let prev = last.get("content").and_then(Value::as_str).unwrap_or("");
                            last["content"] = Value::String(sanitize_venice_message_text(
                                &format!("{prev}\n\n{wrapped}"),
                                "[Runtime State Update]",
                            ));
                            continue;
                        }
                    }
                    out.push(json!({ "role": "user", "content": wrapped }));
                }
            }
            "assistant" => {
                let mut text = sanitize_venice_message_text(
                    m.get("content").and_then(Value::as_str).unwrap_or("").trim(),
                    "",
                );
                // If assistant had native tool_calls and empty text, synthesize readable <agy_call> tags
                if text.is_empty() {
                    if let Some(tcs) = m.get("tool_calls").and_then(Value::as_array) {
                        let mut parts = Vec::new();
                        for tc in tcs {
                            let fname = tc
                                .pointer("/function/name")
                                .and_then(Value::as_str)
                                .unwrap_or("tool");
                            let fargs = tc
                                .pointer("/function/arguments")
                                .and_then(Value::as_str)
                                .unwrap_or("{}");
                            parts.push(format!(
                                "<agy_call>{{\"name\": {}, \"arguments\": {}}}</agy_call>",
                                serde_json::to_string(fname).unwrap_or_else(|_| "\"tool\"".into()),
                                if serde_json::from_str::<Value>(fargs).is_ok() {
                                    fargs.to_string()
                                } else {
                                    "{}".to_string()
                                }
                            ));
                        }
                        if !parts.is_empty() {
                            text = parts.join("\n");
                        }
                    }
                }
                if text.trim().is_empty() {
                    text = "[Executing requested tool step]".to_string();
                }
                // Coalesce consecutive assistant messages (Venice Web Chat silently wipes history on double assistant!)
                if let Some(last) = out.last_mut() {
                    if last.get("role").and_then(Value::as_str) == Some("assistant") {
                        let prev = last.get("content").and_then(Value::as_str).unwrap_or("");
                        last["content"] = Value::String(sanitize_venice_message_text(
                            &format!("{prev}\n\n{text}"),
                            "[Executing requested tool step]",
                        ));
                        continue;
                    }
                }
                out.push(json!({ "role": "assistant", "content": text }));
            }
            "tool" => {
                let tname = m.get("name").and_then(Value::as_str).unwrap_or("tool");
                let call_id = m.get("tool_call_id").and_then(Value::as_str).unwrap_or("");
                let content = sanitize_venice_message_text(
                    m.get("content").and_then(Value::as_str).unwrap_or(""),
                    "(empty tool output)",
                );
                let block = if call_id.is_empty() {
                    format!("[Tool Result: {tname}]\n{content}")
                } else {
                    format!("[Tool Result: {tname} ({call_id})]\n{content}")
                };
                if let Some(last) = out.last_mut() {
                    if last.get("role").and_then(Value::as_str) == Some("user") {
                        let prev = last.get("content").and_then(Value::as_str).unwrap_or("");
                        last["content"] = Value::String(sanitize_venice_message_text(
                            &format!("{prev}\n\n{block}"),
                            "[Tool Result]",
                        ));
                        continue;
                    }
                }
                out.push(json!({ "role": "user", "content": block }));
            }
            _ => {
                let safe_text = sanitize_venice_message_text(
                    m.get("content").and_then(Value::as_str).unwrap_or(""),
                    "[continue]",
                );
                if let Some(last) = out.last_mut() {
                    if last.get("role").and_then(Value::as_str) == Some("user") {
                        let prev = last.get("content").and_then(Value::as_str).unwrap_or("");
                        last["content"] = Value::String(sanitize_venice_message_text(
                            &format!("{prev}\n\n{safe_text}"),
                            "[continue]",
                        ));
                        continue;
                    }
                }
                out.push(json!({ "role": "user", "content": safe_text }));
            }
        }
    }

    // Strict alternation boundary guards (prevent Venice Web Chat silent history wipe):
    // 1. First non-system message must be `user`
    let first_non_sys = if out
        .first()
        .and_then(|v| v.get("role"))
        .and_then(Value::as_str)
        == Some("system")
    {
        1
    } else {
        0
    };
    if out
        .get(first_non_sys)
        .and_then(|v| v.get("role"))
        .and_then(Value::as_str)
        == Some("assistant")
    {
        out.insert(
            first_non_sys,
            json!({ "role": "user", "content": "[Begin session]" }),
        );
    }
    // 2. Last message must ALWAYS be `user` (ending on `assistant` resets Venice web chat!)
    if out
        .last()
        .and_then(|v| v.get("role"))
        .and_then(Value::as_str)
        != Some("user")
    {
        out.push(json!({ "role": "user", "content": "[Continue]" }));
    }
    out
}

fn format_tool_trace_label(name: &str, args: &Value) -> String {
    let hint = match name {
        "run_command" => args.get("command").and_then(Value::as_str),
        "process_manage" => args.get("action").and_then(Value::as_str),
        "execute_code" => Some("python_rpc"),
        "read_file" | "write_file" | "edit_file" | "patch_file" | "list_dir" | "file_editor" | "code_to_md" => {
            args.get("path").and_then(Value::as_str)
        }
        "verify_project" => args.get("project_dir").and_then(Value::as_str),
        "md_to_code" => args.get("target_dir").and_then(Value::as_str),
        "grep_files" | "glob_files" | "web_search" | "memory_search" | "search_skills" => {
            args.get("pattern").or_else(|| args.get("query")).and_then(Value::as_str)
        }
        "fetch_url" => args.get("url").and_then(Value::as_str),
        "call_mcp_tool" => args.get("tool").and_then(Value::as_str),
        "discover_mcp_tools" => args.get("server").and_then(Value::as_str),
        "repo_map" => args.get("path").and_then(Value::as_str),
        "diff_files" => args.get("modified_path").and_then(Value::as_str),
        "assemble_slots" => args.get("slot").or_else(|| args.get("path")).and_then(Value::as_str),
        "load_skill" => args.get("skill_id").and_then(Value::as_str),
        "skillhub_search" => args.get("query").and_then(Value::as_str),
        "skillhub_catalog" => args.get("source").or_else(|| args.get("kind")).and_then(Value::as_str),
        "skillhub_get" => args.get("id").and_then(Value::as_str),
        _ => None,
    };
    match hint.filter(|s| !s.trim().is_empty()) {
        Some(h) => format!("{name}({})", clip_chars(h.trim(), 32)),
        None => name.to_string(),
    }
}

/// Kind of progress observed on a single OpenAI SSE delta chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SseDeltaKind {
    None,
    Content,
    Reasoning,
    ToolCall,
    Error,
}

/// Accumulator that reassembles OpenAI SSE `chat.completion.chunk` deltas into a standard
/// non-streaming `chat.completion` JSON object (handling text, reasoning, indexed/unindexed
/// `tool_calls`, `finish_reason`, `[DONE]`, keepalives, and in-stream errors).
#[derive(Default)]
struct SseChatAccumulator {
    content: String,
    reasoning: String,
    tool_calls: BTreeMap<usize, (String, String, String)>, // idx -> (id, name, args_buf)
    usage: Option<Value>,
    finish_reason: Option<String>,
    in_stream_error: Option<String>,
    saw_meaningful_delta: bool,
    saw_done: bool,
}

impl SseChatAccumulator {
    fn active_tool_name(&self) -> Option<&str> {
        self.tool_calls
            .values()
            .rev()
            .map(|(_, name, _)| name.as_str())
            .find(|n| !n.is_empty())
    }

    fn tool_args_bytes(&self) -> usize {
        self.tool_calls
            .values()
            .map(|(_, _, args)| args.len())
            .sum()
    }

    fn has_output(&self) -> bool {
        !self.content.trim().is_empty()
            || !self.reasoning.trim().is_empty()
            || !self.tool_calls.is_empty()
    }

    fn is_cleanly_terminated(&self) -> bool {
        self.saw_done || self.finish_reason.is_some()
    }

    fn ingest_data_line(&mut self, data: &str) -> SseDeltaKind {
        let trimmed = data.trim();
        if trimmed.is_empty() {
            return SseDeltaKind::None;
        }
        if trimmed == "[DONE]" {
            self.saw_done = true;
            return SseDeltaKind::None;
        }
        let Ok(chunk) = serde_json::from_str::<Value>(trimmed) else {
            return SseDeltaKind::None;
        };
        // Detect in-stream proxy/upstream error objects embedded inside 200 SSE streams!
        if let Some(err_obj) = chunk.get("error").filter(|v| !v.is_null()) {
            let msg = err_obj
                .get("message")
                .and_then(Value::as_str)
                .map(str::to_string)
                .unwrap_or_else(|| err_obj.to_string());
            self.in_stream_error = Some(redact_secrets_in_text(&msg));
            return SseDeltaKind::Error;
        }
        // Ignore OmniRoute/proxy synthetic keepalive heartbeats (`model: "keepalive"`, `choices: []`)
        if chunk.get("model").and_then(Value::as_str) == Some("keepalive")
            || chunk.get("id").and_then(Value::as_str) == Some("chatcmpl-keepalive")
        {
            return SseDeltaKind::None;
        }
        if let Some(u) = chunk.get("usage").filter(|v| v.is_object()) {
            self.usage = Some(u.clone());
        }
        let Some(choice0) = chunk.pointer("/choices/0") else {
            return SseDeltaKind::None;
        };
        if let Some(fr) = choice0
            .get("finish_reason")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
        {
            self.finish_reason = Some(fr.to_string());
        }
        // Support proxies that send `message` instead of `delta` inside an SSE frame
        let Some(delta) = choice0.get("delta").or_else(|| choice0.get("message")) else {
            return SseDeltaKind::None;
        };
        let mut kind = SseDeltaKind::None;
        if let Some(c) = delta.get("content").and_then(Value::as_str) {
            if !c.is_empty() {
                self.content.push_str(c);
                self.saw_meaningful_delta = true;
                kind = SseDeltaKind::Content;
            }
        }
        if let Some(r) = delta
            .get("reasoning_content")
            .or_else(|| delta.get("reasoning"))
            .and_then(Value::as_str)
        {
            if !r.is_empty() {
                self.reasoning.push_str(r);
                self.saw_meaningful_delta = true;
                if kind == SseDeltaKind::None {
                    kind = SseDeltaKind::Reasoning;
                }
            }
        }
        if let Some(tcs) = delta.get("tool_calls").and_then(Value::as_array) {
            for tc in tcs {
                let raw_idx = tc.get("index").and_then(Value::as_u64).map(|v| v as usize);
                let incoming_id = tc.get("id").and_then(Value::as_str).filter(|s| !s.is_empty());
                let idx = match raw_idx {
                    Some(i) => {
                        // Guard against proxies reusing index=0 for distinct tool_call ids
                        if let (Some(new_id), Some((existing_id, _, _))) =
                            (incoming_id, self.tool_calls.get(&i))
                        {
                            if !existing_id.is_empty() && existing_id != new_id {
                                self.tool_calls.len()
                            } else {
                                i
                            }
                        } else {
                            i
                        }
                    }
                    None => {
                        if incoming_id.is_some() {
                            self.tool_calls.len()
                        } else {
                            self.tool_calls.len().saturating_sub(1)
                        }
                    }
                };
                let entry = self
                    .tool_calls
                    .entry(idx)
                    .or_insert_with(|| (String::new(), String::new(), String::new()));
                if let Some(id) = incoming_id {
                    entry.0 = id.to_string();
                    self.saw_meaningful_delta = true;
                }
                if let Some(func) = tc.get("function") {
                    if let Some(name) = func.get("name").and_then(Value::as_str) {
                        if !name.is_empty() {
                            entry.1.push_str(name);
                            self.saw_meaningful_delta = true;
                            if kind == SseDeltaKind::None {
                                kind = SseDeltaKind::ToolCall;
                            }
                        }
                    }
                    match func.get("arguments") {
                        Some(Value::String(args)) if !args.is_empty() => {
                            entry.2.push_str(args);
                            self.saw_meaningful_delta = true;
                            if kind == SseDeltaKind::None {
                                kind = SseDeltaKind::ToolCall;
                            }
                        }
                        Some(obj @ Value::Object(_)) => {
                            entry.2 = obj.to_string();
                            self.saw_meaningful_delta = true;
                            if kind == SseDeltaKind::None {
                                kind = SseDeltaKind::ToolCall;
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
        kind
    }

    fn into_completion_json(self) -> Value {
        let mut msg = json!({
            "role": "assistant",
            "content": self.content,
        });
        if !self.reasoning.is_empty() {
            msg["reasoning_content"] = Value::String(self.reasoning);
        }
        if !self.tool_calls.is_empty() {
            let arr: Vec<Value> = self
                .tool_calls
                .into_iter()
                .map(|(idx, (id, name, args))| {
                    json!({
                        "id": if id.is_empty() { format!("call_{idx}") } else { id },
                        "type": "function",
                        "function": {
                            "name": name,
                            "arguments": args
                        }
                    })
                })
                .collect();
            msg["tool_calls"] = Value::Array(arr);
        }
        let mut choice = json!({
            "index": 0,
            "message": msg
        });
        if let Some(fr) = self.finish_reason {
            choice["finish_reason"] = Value::String(fr);
        }
        let mut out = json!({
            "choices": [choice]
        });
        if let Some(u) = self.usage {
            out["usage"] = u;
        }
        out
    }
}

fn parse_retry_after_secs(headers: &reqwest::header::HeaderMap) -> Option<u64> {
    if let Some(raw) = headers
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
    {
        if let Ok(s) = raw.parse::<u64>() {
            return Some(s.clamp(1, 45));
        }
    }
    // Venice API `x-ratelimit-reset-requests` (Unix ms or seconds)
    if let Some(raw) = headers
        .get("x-ratelimit-reset-requests")
        .or_else(|| headers.get("x-ratelimit-resets"))
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
    {
        if let Ok(val) = raw.parse::<u64>() {
            let now_ms = SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            if val > 1_000_000_000_000 {
                let delta_s = val.saturating_sub(now_ms).div_ceil(1000);
                return Some(delta_s.clamp(1, 45));
            } else if val > 1_000_000_000 {
                let delta_s = val.saturating_sub(now_ms / 1000);
                return Some(delta_s.clamp(1, 45));
            } else if val > 0 {
                return Some(val.clamp(1, 45));
            }
        }
    }
    None
}

fn parse_body_retry_after_secs(body: &str) -> Option<u64> {
    serde_json::from_str::<Value>(body)
        .ok()
        .and_then(|v| {
            v.pointer("/error/retry_after")
                .or_else(|| v.get("retry_after"))
                .and_then(Value::as_u64)
        })
        .map(|s| s.clamp(1, 30))
}

fn is_transient_http_status(status: u16, body: &str) -> bool {
    if matches!(status, 408 | 425 | 429 | 500..=599) {
        return true;
    }
    // Venice/OmniRoute Cloudflare challenge returns 403 with HTML `<!DOCTYPE html>` or retry_after
    if status == 403 {
        let low = body.to_ascii_lowercase();
        return low.contains("<!doctype html")
            || low.contains("cloudflare")
            || low.contains("retry_after")
            || low.contains("reset after");
    }
    // Reverse proxy (Traefik/Caddy/Nginx) brief reload returns plain-text "404 page not found" or HTML 404
    // (real API JSON 404s start with '{' and should not be retried blindly).
    if status == 404 {
        let trimmed = body.trim();
        let low = trimmed.to_ascii_lowercase();
        return !trimmed.starts_with('{')
            && (low.contains("404 page not found")
                || low.contains("<!doctype html")
                || low.contains("<html"));
    }
    false
}

fn retry_jitter_ms(attempt: usize) -> u64 {
    let sub = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_millis() as u64)
        .unwrap_or(0);
    ((sub ^ ((attempt as u64 + 1) * 313)) % 900) + 150
}

async fn sleep_cancellable(dur: Duration, cancel: &mut watch::Receiver<bool>) -> bool {
    if *cancel.borrow() {
        return true;
    }
    tokio::select! {
        biased;
        res = cancel.wait_for(|&v| v) => res.is_ok(),
        _ = tokio::time::sleep(dur) => false,
    }
}

/// Per-chunk idle timeout for SSE streaming responses (prevents indefinite hangs while allowing
/// arbitrarily long active generations).
const SSE_CHUNK_IDLE_TIMEOUT_SECS: u64 = 75;

/// Wait until cancellation flips `true`. If the watch sender is dropped while `false`,
/// pend forever instead of spinning a `tokio::select!` loop.
async fn wait_for_cancel(cancel: &mut tokio::sync::watch::Receiver<bool>) {
    if cancel.wait_for(|&v| v).await.is_err() {
        std::future::pending::<()>().await;
    }
}

async fn send_chat_completion(
    client: &reqwest::Client,
    provider: &dyn AuthHeaderProvider,
    payload: &Value,
    cancel: &mut watch::Receiver<bool>,
    live_progress: Option<(&mut Progress, &ProgressCallback)>,
    prefer_stream: bool,
) -> std::result::Result<Value, (u16, String)> {
    let mut force_auth = false;
    let mut force_ver = false;
    let mut disable_stream = false;
    let mut strip_venice_params = false;
    let mut live_progress = live_progress;
    const MAX_ATTEMPTS: usize = 4;

    for attempt in 0..MAX_ATTEMPTS {
        if *cancel.borrow() {
            return Err((0, "stopped".to_string()));
        }
        let (url, headers) = provider
            .resolve_request(force_auth, force_ver)
            .await
            .map_err(|e| (0u16, e.to_string()))?;

        let mut req_payload = payload.clone();
        if strip_venice_params {
            if let Some(obj) = req_payload.as_object_mut() {
                obj.remove("venice_parameters");
            }
        }
        if !disable_stream && (prefer_stream || live_progress.is_some()) {
            req_payload["stream"] = json!(true);
            req_payload["stream_options"] = json!({ "include_usage": true });
        } else if let Some(obj) = req_payload.as_object_mut() {
            obj.insert("stream".to_string(), json!(false));
            obj.remove("stream_options");
        }

        let mut req = client.post(&url).json(&req_payload);
        for (k, v) in &headers {
            req = req.header(k.as_str(), v.as_str());
        }

        let resp_res = tokio::select! {
            biased;
            _ = wait_for_cancel(cancel) => {
                return Err((0, "stopped".to_string()));
            }
            r = req.send() => r,
        };

        let resp = match resp_res {
            Ok(r) => r,
            Err(e) => {
                if attempt + 1 < MAX_ATTEMPTS {
                    if attempt >= 1 {
                        disable_stream = true;
                    }
                    let wait = Duration::from_millis(900 * (attempt as u64 + 1) + retry_jitter_ms(attempt));
                    warn!(attempt, error = %redact_secrets_in_text(&e.to_string()), "LLM HTTP transport error; retrying");
                    if sleep_cancellable(wait, cancel).await {
                        return Err((0, "stopped".to_string()));
                    }
                    continue;
                }
                return Err((0, format!("HTTP request failed: {}", redact_secrets_in_text(&e.to_string()))));
            }
        };

        let status = resp.status().as_u16();
        let retry_after_secs = parse_retry_after_secs(resp.headers());
        let is_sse = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|ct| ct.to_ascii_lowercase().contains("text/event-stream"));

        if !(200..300).contains(&status) {
            let body = tokio::select! {
                biased;
                _ = wait_for_cancel(cancel) => {
                    return Err((0, "stopped".to_string()));
                }
                b = resp.text() => b.unwrap_or_default(),
            };
            let body_low = body.to_ascii_lowercase();
            // Strip venice_parameters if a strict OpenAI proxy rejects unknown top-level fields
            if status == 400 && !strip_venice_params && body_low.contains("venice_parameters") {
                info!("received HTTP 400 for venice_parameters; retrying without venice_parameters");
                strip_venice_params = true;
                continue;
            }
            // Some strict OpenAI proxies reject `stream_options` with 400 -> retry without stream
            if status == 400 && !disable_stream && body_low.contains("stream") {
                disable_stream = true;
                continue;
            }
            if status == 401 && !force_auth {
                info!("received HTTP 401; retrying once with refreshed auth");
                force_auth = true;
                continue;
            }
            if status == 426 && !force_ver {
                info!("received HTTP 426; retrying once with refreshed CLI client version");
                force_ver = true;
                continue;
            }
            if is_transient_http_status(status, &body) && attempt + 1 < MAX_ATTEMPTS {
                let base_secs = retry_after_secs
                    .or_else(|| parse_body_retry_after_secs(&body))
                    .unwrap_or_else(|| (2u64 << attempt).min(16));
                let wait = Duration::from_secs(base_secs) + Duration::from_millis(retry_jitter_ms(attempt));
                info!(status, wait_ms = wait.as_millis() as u64, attempt, "backing off politely before retry");
                if attempt >= 1 {
                    disable_stream = true;
                }
                if sleep_cancellable(wait, cancel).await {
                    return Err((0, "stopped".to_string()));
                }
                continue;
            }
            return Err((status, provider.format_http_error(status, &body)));
        }

        if is_sse {
            let mut acc = SseChatAccumulator::default();
            let mut stream = resp.bytes_stream();
            let mut raw_buf: Vec<u8> = Vec::with_capacity(4096);
            let mut last_emit = Instant::now();
            let mut last_emitted_len = 0usize;
            let mut stream_transport_err: Option<String> = None;

            'sse_loop: loop {
                let next_chunk = tokio::select! {
                    biased;
                    _ = wait_for_cancel(cancel) => {
                        return Err((0, "stopped".to_string()));
                    }
                    c = tokio::time::timeout(Duration::from_secs(SSE_CHUNK_IDLE_TIMEOUT_SECS), stream.next()) => c,
                };
                match next_chunk {
                    Ok(Some(Ok(bytes))) => {
                        raw_buf.extend_from_slice(&bytes);
                        while let Some(nl) = raw_buf.iter().position(|&b| b == b'\n') {
                            let line_bytes: Vec<u8> = raw_buf.drain(..=nl).collect();
                            let line = String::from_utf8_lossy(&line_bytes)
                                .trim_end_matches(['\r', '\n'])
                                .to_string();
                            if let Some(data) = line.strip_prefix("data:") {
                                match acc.ingest_data_line(data) {
                                    SseDeltaKind::Error => {
                                        stream_transport_err = acc.in_stream_error.clone();
                                        raw_buf.clear();
                                        break 'sse_loop;
                                    }
                                    SseDeltaKind::Content => {
                                        if let Some((cut_idx, reason)) =
                                            detect_tool_stream_degeneration(&acc.content)
                                        {
                                            warn!(
                                                reason,
                                                orig_len = acc.content.len(),
                                                cut_len = cut_idx,
                                                "SSE tool repetition/runaway circuit breaker tripped; cleanly truncating turn"
                                            );
                                            if cut_idx < acc.content.len()
                                                && acc.content.is_char_boundary(cut_idx)
                                            {
                                                acc.content.truncate(cut_idx);
                                            }
                                            acc.finish_reason = Some("stop".to_string());
                                            acc.saw_done = true;
                                            raw_buf.clear();
                                            break 'sse_loop;
                                        }
                                        if let Some((ref mut prog, cb)) = live_progress {
                                            if text_has_tool_markup(&acc.content) {
                                                if last_emit.elapsed() >= Duration::from_millis(1500) {
                                                    let visible = strip_tool_call_markup(&acc.content);
                                                    if !visible.is_empty() {
                                                        prog.partial = visible;
                                                    }
                                                    prog.last_step = format!(
                                                        "preparing tool call… ({} B)",
                                                        acc.content.len()
                                                    );
                                                    cb(prog.clone()).await;
                                                    last_emit = Instant::now();
                                                }
                                            } else if last_emit.elapsed() >= Duration::from_millis(450)
                                                || acc.content.len().saturating_sub(last_emitted_len) >= 160
                                            {
                                                let visible = strip_tool_call_markup(&acc.content);
                                                if !visible.is_empty() {
                                                    prog.partial = visible;
                                                }
                                                cb(prog.clone()).await;
                                                last_emit = Instant::now();
                                                last_emitted_len = acc.content.len();
                                            }
                                        }
                                    }
                                    SseDeltaKind::Reasoning => {
                                        if let Some((ref mut prog, cb)) = live_progress {
                                            if last_emit.elapsed() >= Duration::from_millis(1500) {
                                                prog.last_step = format!(
                                                    "thinking… ({} chars)",
                                                    acc.reasoning.chars().count()
                                                );
                                                cb(prog.clone()).await;
                                                last_emit = Instant::now();
                                            }
                                        }
                                    }
                                    SseDeltaKind::ToolCall => {
                                        if let Some((ref mut prog, cb)) = live_progress {
                                            if last_emit.elapsed() >= Duration::from_millis(1500) {
                                                let tool_name =
                                                    acc.active_tool_name().unwrap_or("tool");
                                                prog.last_step = format!(
                                                    "writing {tool_name}… ({} B)",
                                                    acc.tool_args_bytes()
                                                );
                                                cb(prog.clone()).await;
                                                last_emit = Instant::now();
                                            }
                                        }
                                    }
                                    SseDeltaKind::None => {}
                                }
                            }
                        }
                        if stream_transport_err.is_some() {
                            break;
                        }
                    }
                    Ok(Some(Err(e))) => {
                        stream_transport_err = Some(format!(
                            "SSE stream read error: {}",
                            redact_secrets_in_text(&e.to_string())
                        ));
                        break;
                    }
                    Err(_) => {
                        stream_transport_err = Some(format!(
                            "SSE stream stalled (no chunk for {SSE_CHUNK_IDLE_TIMEOUT_SECS}s)"
                        ));
                        break;
                    }
                    Ok(None) => break,
                }
            }
            if !raw_buf.is_empty() {
                let tail_str = String::from_utf8_lossy(&raw_buf);
                let trimmed_tail = tail_str.trim();
                if let Some(data) = trimmed_tail.strip_prefix("data:") {
                    acc.ingest_data_line(data);
                } else if !acc.saw_meaningful_delta {
                    if let Ok(parsed) = serde_json::from_str::<Value>(trimmed_tail) {
                        if parsed.get("choices").is_some() {
                            return Ok(parsed);
                        }
                    }
                }
            }

            // Detect broken/truncated SSE streams (keepalive-only, in-stream error, transport cut without [DONE]/finish_reason)
            let incomplete_drop = stream_transport_err.is_some() && !acc.is_cleanly_terminated();
            let empty_after_keepalive = !acc.has_output();
            if incomplete_drop || empty_after_keepalive || acc.in_stream_error.is_some() {
                let reason = acc
                    .in_stream_error
                    .clone()
                    .or(stream_transport_err)
                    .unwrap_or_else(|| "empty SSE response from model endpoint (keepalive-only)".to_string());
                if attempt + 1 < MAX_ATTEMPTS {
                    warn!(attempt, reason = %reason, "SSE stream failed/truncated; retrying with non-stream fallback");
                    disable_stream = true;
                    let wait = Duration::from_millis(800 * (attempt as u64 + 1) + retry_jitter_ms(attempt));
                    if sleep_cancellable(wait, cancel).await {
                        return Err((0, "stopped".to_string()));
                    }
                    continue;
                }
                // On final attempt, preserve partial prose only if substantial & no hard in-stream error
                if acc.has_output() && acc.content.len() >= 120 {
                    return Ok(acc.into_completion_json());
                }
                return Err((status, reason));
            }

            return Ok(acc.into_completion_json());
        }

        let body_res = tokio::select! {
            biased;
            res = cancel.wait_for(|&v| v) => {
                if res.is_ok() {
                    return Err((0, "stopped".to_string()));
                }
                continue;
            }
            b = resp.text() => b,
        };
        let body = match body_res {
            Ok(b) => b,
            Err(e) => {
                if attempt + 1 < MAX_ATTEMPTS {
                    let wait = Duration::from_millis(900 * (attempt as u64 + 1) + retry_jitter_ms(attempt));
                    if sleep_cancellable(wait, cancel).await {
                        return Err((0, "stopped".to_string()));
                    }
                    continue;
                }
                return Err((status, format!("failed reading response body: {}", redact_secrets_in_text(&e.to_string()))));
            }
        };
        let mut parsed: Value = match serde_json::from_str(&body) {
            Ok(v) => v,
            Err(e) => {
                if attempt + 1 < MAX_ATTEMPTS {
                    warn!(attempt, error = %e, "invalid JSON from model endpoint; retrying");
                    let wait = Duration::from_millis(900 * (attempt as u64 + 1) + retry_jitter_ms(attempt));
                    if sleep_cancellable(wait, cancel).await {
                        return Err((0, "stopped".to_string()));
                    }
                    continue;
                }
                return Err((status, format!("invalid JSON from model endpoint: {e}")));
            }
        };
        if let Some(err_obj) = parsed.get("error").filter(|v| !v.is_null()) {
            let emsg = err_obj
                .get("message")
                .and_then(Value::as_str)
                .map(str::to_string)
                .unwrap_or_else(|| err_obj.to_string());
            if attempt + 1 < MAX_ATTEMPTS {
                warn!(attempt, error = %redact_secrets_in_text(&emsg), "JSON response contained error object; retrying");
                let wait = Duration::from_secs(2) + Duration::from_millis(retry_jitter_ms(attempt));
                if sleep_cancellable(wait, cancel).await {
                    return Err((0, "stopped".to_string()));
                }
                continue;
            }
            return Err((status, redact_secrets_in_text(&emsg)));
        }
        if let Some(c_str) = parsed.pointer("/choices/0/message/content").and_then(Value::as_str) {
            let clean = sanitize_degenerate_tool_response(c_str);
            if clean.len() != c_str.len() {
                warn!(orig_len = c_str.len(), clean_len = clean.len(), "sanitized degenerate tool tags in non-stream response");
                if let Some(slot) = parsed.pointer_mut("/choices/0/message/content") {
                    *slot = Value::String(clean);
                }
            }
        }
        return Ok(parsed);
    }

    Err((0, "exhausted retries contacting model endpoint".to_string()))
}

/// Extract the Telegram outbox directory path from the bridge prompt, if present.
fn extract_outbox_dir(user_prompt: &str) -> Option<PathBuf> {
    for line in user_prompt.lines() {
        let trimmed = line.trim();
        for prefix in [
            "Put any file you want delivered to the user in:",
            "outbox:",
        ] {
            if let Some(rest) = trimmed.strip_prefix(prefix) {
                let candidate = rest
                    .split(['·', '\t'])
                    .next()
                    .unwrap_or("")
                    .trim()
                    .trim_end_matches('/');
                if !candidate.is_empty() && candidate.contains("outbox") {
                    return Some(PathBuf::from(candidate));
                }
            }
        }
        // Fallback: inline `· outbox: /path/to/outbox/uid/req/`
        if let Some(pos) = trimmed.find("outbox:") {
            let candidate = trimmed[pos + "outbox:".len()..]
                .split(['·', '\t'])
                .next()
                .unwrap_or("")
                .trim()
                .trim_end_matches('/');
            if !candidate.is_empty() && candidate.contains("outbox") {
                return Some(PathBuf::from(candidate));
            }
        }
    }
    None
}

/// Returns `true` when the prompt indicates the user expects an output/improved/fixed file
/// delivered via the Telegram outbox directory.
fn prompt_expects_file_delivery(user_prompt: &str) -> bool {
    if extract_outbox_dir(user_prompt).is_none() {
        return false;
    }
    if user_prompt.contains("User attachments (local paths):") {
        return true;
    }
    let low = user_prompt.to_ascii_lowercase();
    [
        "outbox",
        "send the file",
        "deliver",
        "save to",
        "improved",
        "write the",
        "upload",
        "بفرست",
        "ارسال",
        "اپلود",
        "آپلود",
        "ذخیره",
        "فایل",
        "بهبود",
        "تغییر",
    ]
    .iter()
    .any(|kw| low.contains(kw) || user_prompt.contains(kw))
}

/// Recursively checks whether `dir` contains at least one non-hidden, non-empty file.
fn dir_has_non_empty_files(dir: &Path) -> bool {
    if !dir.is_dir() {
        return false;
    }
    let mut stack = vec![dir.to_path_buf()];
    while let Some(cur) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&cur) else {
            continue;
        };
        for ent in rd.flatten() {
            let name = ent.file_name();
            if name.to_string_lossy().starts_with('.') {
                continue;
            }
            let p = ent.path();
            if let Ok(meta) = std::fs::metadata(&p) {
                if meta.is_dir() {
                    stack.push(p);
                } else if meta.is_file() && meta.len() > 0 {
                    return true;
                }
            }
        }
    }
    false
}

/// Extract local attachment file paths referenced by the Telegram bridge prompt.
fn extract_attachment_paths(user_prompt: &str) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut in_attach_block = false;
    for line in user_prompt.lines() {
        let t = line.trim();
        if t.starts_with("User attachments (local paths):")
            || t.starts_with("=== VERIFIED ATTACHMENT MANIFEST ===")
        {
            in_attach_block = true;
            continue;
        }
        if in_attach_block {
            if let Some(rest) = t.strip_prefix("- ") {
                let raw = if let Some(bt) = rest.strip_prefix('`') {
                    bt.split('`').next().unwrap_or("")
                } else {
                    rest.split_whitespace().next().unwrap_or("")
                };
                if raw.starts_with('/') {
                    let p = PathBuf::from(raw);
                    if p.is_file() && !out.contains(&p) {
                        out.push(p);
                    }
                }
            } else if !t.starts_with("↳") && !t.is_empty() && !t.starts_with("```") {
                in_attach_block = false;
            }
        }
    }
    out
}

/// Strip block comments (`/* ... */`), line comments (`//`, `#`), and whitespace so we can compare
/// actual executable code lines rather than comment-only edits.
fn normalize_executable_code(text: &str) -> Vec<String> {
    // Strip /* ... */ block comments without regex backtracking limits
    let bytes = text.as_bytes();
    let mut no_block = String::with_capacity(text.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'*' {
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                if bytes[i] == b'\n' {
                    no_block.push('\n');
                }
                i += 1;
            }
            if i + 1 < bytes.len() {
                i += 2;
            }
        } else {
            let ch = text[i..].chars().next().unwrap_or('\0');
            no_block.push(ch);
            i += ch.len_utf8();
        }
    }

    let mut out = Vec::new();
    for line in no_block.lines() {
        let mut s = line.trim();
        if s.is_empty() || s.starts_with("//") || s.starts_with('#') {
            continue;
        }
        // Strip trailing `// ...` when not preceded by `:` (e.g. `https://`)
        if let Some(pos) = s.find("//") {
            let prev_is_colon = pos > 0 && s.as_bytes()[pos - 1] == b':';
            if !prev_is_colon {
                s = s[..pos].trim_end();
            }
        }
        if !s.is_empty() {
            out.push(s.to_string());
        }
    }
    out
}

fn is_checked_code_ext(ext: &str) -> bool {
    matches!(
        ext,
        "php" | "py" | "js" | "mjs" | "cjs" | "ts" | "rs" | "go" | "c" | "cpp" | "sh" | "bash" | "json"
    )
}

/// Inspect delivered code files inside `odir` before letting the agent finish:
/// 1. Syntax check (`php -l`, `python3`, `node --check`, `bash -n`, JSON)
/// 2. Lazy placeholder check (`// ... rest unchanged`, etc.)
/// 3. Anti-cosmetic check against matching-extension attachments (rejects rename + comment-only copies
///    with 0 executable code changes, and catches severe unexplained >40% executable line drops).
async fn inspect_outbox_code_quality(odir: &Path, attachments: &[PathBuf]) -> Option<String> {
    let rd = std::fs::read_dir(odir).ok()?;
    let mut out_files: Vec<PathBuf> = Vec::new();
    for ent in rd.flatten() {
        let name = ent.file_name();
        if name.to_string_lossy().starts_with('.') {
            continue;
        }
        let p = ent.path();
        if p.is_file() {
            out_files.push(p);
        }
    }
    out_files.sort();

    for out_path in out_files {
        let ext = out_path
            .extension()
            .and_then(|s| s.to_str())
            .map(|s| s.to_ascii_lowercase())
            .unwrap_or_default();
        if ext == "zip" {
            if let Some(zip_err) = crate::code_to_md::verify_zip_outbox_archive(&out_path).await {
                return Some(format!(
                    "Archive `{}` failed quality check: {zip_err}. Fix the archive contents via `<agy_exec>` and overwrite `{}` before finishing.",
                    out_path.display(),
                    out_path.display()
                ));
            }
            continue;
        }
        if !is_checked_code_ext(&ext) {
            continue;
        }
        let Ok(dst_text) = std::fs::read_to_string(&out_path) else {
            continue;
        };
        let leaked_slots = extract_slot_markers_from_text(&dst_text);
        if !leaked_slots.is_empty() {
            return Some(format!(
                "File `{}` still contains unfilled slot marker(s) [{}]. Fill every `<<<AGY_SLOT:...>>>` via `<agy_slot>` / `assemble_slots` before delivering.",
                out_path.display(),
                leaked_slots.join(", ")
            ));
        }
        if let Some(syn_err) = fast_syntax_check(&out_path, &dst_text).await {
            return Some(format!(
                "Syntax error in `{}`: {syn_err}. Fix the syntax error and re-verify before finishing.",
                out_path.display()
            ));
        }
        if let Some(marker) = detect_lazy_code_placeholders(&dst_text) {
            return Some(format!(
                "File `{}` contains lazy omission placeholder (`{marker}`). Replace every placeholder with complete working code.",
                out_path.display()
            ));
        }
        let dst_exec = normalize_executable_code(&dst_text);
        for att in attachments {
            let att_ext = att
                .extension()
                .and_then(|s| s.to_str())
                .map(|s| s.to_ascii_lowercase())
                .unwrap_or_default();
            if att_ext != ext {
                continue;
            }
            let Ok(src_text) = std::fs::read_to_string(att) else {
                continue;
            };
            let src_exec = normalize_executable_code(&src_text);
            if src_exec.is_empty() {
                continue;
            }
            if src_exec == dst_exec {
                return Some(format!(
                    "File `{}` has ZERO executable non-comment code changes compared to `{}` (rename/comment-only edit rejected!). Actually modify and improve the executable code logic, test it, and overwrite `{}`.",
                    out_path.display(),
                    att.display(),
                    out_path.display()
                ));
            }
            if src_exec.len() >= 100
                && dst_exec.len() < (src_exec.len() * 60) / 100
                && !dst_text.contains("__call")
                && !dst_text.contains("__getattr__")
            {
                return Some(format!(
                    "File `{}` shrank drastically from {} to {} executable lines (<60% of `{}`) without dynamic delegation — existing functions/methods appear to have been dropped! Preserve all existing functions/classes/methods while applying your fixes.",
                    out_path.display(),
                    src_exec.len(),
                    dst_exec.len(),
                    att.display()
                ));
            }
            // Check core named classes & non-numbered top-level functions weren't accidentally dropped
            let missing_syms = find_missing_core_symbols(&src_text, &dst_text);
            if missing_syms.len() >= 2 {
                return Some(format!(
                    "File `{}` dropped {} original class/function definition(s) from `{}`: {}. Preserve existing public classes/functions for backward compatibility.",
                    out_path.display(),
                    missing_syms.len(),
                    att.display(),
                    missing_syms.iter().take(6).cloned().collect::<Vec<_>>().join(", ")
                ));
            }
        }
    }
    None
}

/// Extract non-numbered top-level `class Name` / `function name` / `def name` symbols from source
/// and report those completely absent from `dst_text`.
fn find_missing_core_symbols(src_text: &str, dst_text: &str) -> Vec<String> {
    let mut syms: Vec<String> = Vec::new();
    for line in src_text.lines() {
        let trimmed = line.trim_start();
        // Only top-level (0 leading spaces) or simple `class ` declarations
        let indent = line.len().saturating_sub(trimmed.len());
        if indent > 0 {
            continue;
        }
        let rest = if let Some(r) = trimmed.strip_prefix("class ") {
            Some(r)
        } else if let Some(r) = trimmed.strip_prefix("function ") {
            Some(r)
        } else if let Some(r) = trimmed.strip_prefix("def ") {
            Some(r)
        } else {
            None
        };
        if let Some(r) = rest {
            let name: String = r
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            if name.len() >= 3
                && !name.starts_with('_')
                && !name.chars().last().is_some_and(|c| c.is_ascii_digit())
                && !syms.contains(&name)
            {
                syms.push(name);
            }
        }
    }
    syms.into_iter()
        .filter(|sym| !dst_text.contains(sym.as_str()))
        .collect()
}

/// Build a clean, bounded canonical assistant message for multi-turn history so degenerate
/// `</agy_call>` repeats or giant `<agy_write>` bodies never poison subsequent LLM steps.
fn build_canonical_assistant_history(
    msg: &Value,
    raw_content: &str,
    tool_calls: &[(String, String, Value)],
) -> Value {
    let mut assistant_msg = msg.clone();
    let visible = clip_chars(&strip_tool_call_markup(raw_content), 400);
    let has_native_tcs = msg
        .get("tool_calls")
        .and_then(Value::as_array)
        .is_some_and(|a| !a.is_empty());

    if !has_native_tcs {
        let mut canonical_calls = Vec::with_capacity(tool_calls.len());
        for (_, name, args) in tool_calls {
            if name == "write_file" || name == "assemble_slots" {
                let path = args.get("path").and_then(Value::as_str).unwrap_or("");
                let slot = args.get("slot").and_then(Value::as_str).unwrap_or("");
                let bytes = args
                    .get("content")
                    .or_else(|| args.get("code"))
                    .and_then(Value::as_str)
                    .map_or(0, str::len);
                if name == "write_file" {
                    canonical_calls.push(format!(
                        "<agy_call>{{\"name\": \"write_file\", \"arguments\": {{\"path\": {}, \"bytes\": {bytes}}}}}</agy_call>",
                        serde_json::to_string(path).unwrap_or_else(|_| "\"\"".into())
                    ));
                } else {
                    canonical_calls.push(format!(
                        "<agy_call>{{\"name\": \"assemble_slots\", \"arguments\": {{\"path\": {}, \"slot\": {}, \"bytes\": {bytes}}}}}</agy_call>",
                        serde_json::to_string(path).unwrap_or_else(|_| "\"\"".into()),
                        serde_json::to_string(slot).unwrap_or_else(|_| "\"\"".into())
                    ));
                }
            } else {
                let args_str = serde_json::to_string(args).unwrap_or_else(|_| "{}".into());
                let clipped_args = clip_chars(&args_str, 500);
                let name_json = serde_json::to_string(name).unwrap_or_else(|_| "\"tool\"".into());
                if clipped_args.len() == args_str.len() {
                    canonical_calls.push(format!(
                        "<agy_call>{{\"name\": {name_json}, \"arguments\": {args_str}}}</agy_call>"
                    ));
                } else {
                    // Always keep valid <agy_call> markup in assistant history so models never mimic plain-text "[Calling tool ...]" syntax!
                    let summary = format!("{} bytes omitted", args_str.len());
                    let summary_json = serde_json::to_string(&summary).unwrap_or_else(|_| "\"omitted\"".into());
                    canonical_calls.push(format!(
                        "<agy_call>{{\"name\": {name_json}, \"arguments\": {{\"_truncated\": {summary_json}}}}}</agy_call>"
                    ));
                }
            }
        }
        let body = if visible.is_empty() {
            canonical_calls.join("\n")
        } else if canonical_calls.is_empty() {
            visible
        } else {
            format!("{visible}\n{}", canonical_calls.join("\n"))
        };
        assistant_msg["content"] = Value::String(if body.trim().is_empty() {
            "[Calling tools]".to_string()
        } else {
            body
        });
    } else if assistant_msg
        .get("content")
        .and_then(Value::as_str)
        .is_none_or(|s| s.trim().is_empty())
    {
        let summary = tool_calls
            .iter()
            .map(|(_, n, _)| n.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        assistant_msg["content"] = Value::String(format!("[Calling tools: {summary}]"));
    }
    assistant_msg
}

/// Detect whether the model mistakenly refused or deferred tool usage on Step 1 when local files
/// or an outbox delivery path were provided in the prompt.
fn looks_like_premature_tool_deferral(user_prompt: &str, reply: &str) -> bool {
    let has_files_or_outbox = user_prompt.contains("User attachments (local paths):")
        || user_prompt.contains("/outbox/")
        || user_prompt.contains("outbox/");
    if !has_files_or_outbox {
        return false;
    }
    let low = reply.to_ascii_lowercase();
    let refusal_signals = [
        "paste the contents",
        "don't have a ",
        "do not have a ",
        "don't have file access",
        "do not have file access",
        "no file access",
        "no live tool",
        "plain text",
        "cannot access local",
        "can't access local",
        "cannot read local",
        "can't read local",
        "don't have access to your local",
        "not wired up",
        "unable to access the file",
        "please share the code",
        "please provide the contents",
    ];
    if refusal_signals.iter().any(|sig| low.contains(sig)) {
        return true;
    }
    // Very short "I'll analyze / read the file..." stub with no tool call emitted
    reply.chars().count() < 260
        && (low.contains("i'll read")
            || low.contains("i will read")
            || low.contains("i'll analyze")
            || low.contains("i will analyze")
            || low.contains("let me inspect")
            || low.contains("let me read")
            || reply.contains("ابتدا فایل را")
            || reply.contains("فایل را بررسی می‌کنم"))
}

#[derive(Default)]
struct ThreeStageRuntime {
    active: bool,
    stage: u8, // 0 = single-stage, 1 = memory pre-analysis, 2 = skills + plan, 3 = main prompt + chunked exec
    stage_dir: PathBuf,
    repo_map_md: String,
    detected_stack: Vec<String>,
    base_msg_count: usize,
    stage_steps_used: usize,
    stage1_cap: usize,
    stage2_cap: usize,
    memory_md: String,
    skills_brief: String,
    plan_md: String,
    slot_nudges: usize,
}

impl ThreeStageRuntime {
    fn in_final_stage(&self) -> bool {
        self.stage == 0 || self.stage == 3
    }

    fn phase_label(&self) -> &'static str {
        match self.stage {
            1 => "stage1_memory",
            2 => "stage2_skills_plan",
            3 => "stage3_execute",
            _ => "single",
        }
    }
}

fn has_3stage_prompt_cue(prompt: &str) -> bool {
    let low = prompt.to_ascii_lowercase();
    [
        "3-stage",
        "three-stage",
        "three stage",
        "3 stage",
        "chunked",
        "3 مرحله",
        "سه مرحله",
        "تیکه تیکه",
        "تکه تکه",
    ]
    .iter()
    .any(|kw| low.contains(kw) || prompt.contains(kw))
}

fn stack_tag_for_ext(ext: &str) -> Option<&'static str> {
    match ext {
        "py" | "pyi" => Some("python"),
        "php" => Some("php"),
        "js" | "mjs" | "cjs" => Some("javascript"),
        "ts" | "tsx" => Some("typescript"),
        "rs" => Some("rust"),
        "go" => Some("go"),
        "java" => Some("java"),
        "sql" => Some("sql"),
        "html" | "htm" => Some("html"),
        "css" => Some("css"),
        "sh" | "bash" => Some("bash"),
        _ => None,
    }
}

fn collect_workspace_files_bounded(root: &Path, max_entries: usize) -> Vec<(PathBuf, u64)> {
    const SKIP: &[&str] = &[
        ".git",
        ".agy_stage",
        "node_modules",
        "target",
        "__pycache__",
        ".venv",
        "venv",
        "dist",
        "build",
    ];
    let mut out = Vec::new();
    let mut queue = std::collections::VecDeque::from([(root.to_path_buf(), 0usize)]);
    while let Some((dir, depth)) = queue.pop_front() {
        if out.len() >= max_entries {
            break;
        }
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut ents: Vec<_> = rd.flatten().collect();
        ents.sort_by_key(|e| e.file_name());
        for ent in ents {
            if out.len() >= max_entries {
                break;
            }
            let name = ent.file_name();
            let nstr = name.to_string_lossy();
            if nstr.starts_with('.') || SKIP.iter().any(|s| *s == nstr.as_ref()) {
                continue;
            }
            let p = ent.path();
            let Ok(meta) = std::fs::metadata(&p) else {
                continue;
            };
            if meta.is_dir() {
                if depth < 3 {
                    queue.push_back((p, depth + 1));
                }
            } else if meta.is_file() {
                out.push((p, meta.len()));
            }
        }
    }
    out
}

async fn prepare_prestage_0(
    cfg: &AgentTurnConfig,
    user_prompt: &str,
    attachments: &[PathBuf],
    max_steps: usize,
) -> ThreeStageRuntime {
    let mut rt = ThreeStageRuntime::default();
    let venice_mode = is_venice_prompt_engine(cfg);
    if !cfg.agent_mode || !venice_mode {
        return rt;
    }
    let eligible = match cfg.three_stage_mode {
        ThreeStageMode::Off => false,
        ThreeStageMode::Always => max_steps >= 6,
        ThreeStageMode::Auto => max_steps >= 10,
    };
    if !eligible {
        return rt;
    }

    let mut stack: Vec<String> = Vec::new();
    let mut zip_overviews: Vec<String> = Vec::new();
    let mut zip_heavy = false;
    let mut total_attach_bytes = 0u64;

    for att in attachments {
        if let Ok(meta) = std::fs::metadata(att) {
            total_attach_bytes = total_attach_bytes.saturating_add(meta.len());
        }
        if crate::code_to_md::is_zip_archive(att) {
            if let Ok(rec) = crate::code_to_md::inspect_zip_recursive(att, 2).await {
                if rec.code_files >= 4 || !rec.nested_zips.is_empty() || rec.total_bytes >= 32 * 1024 {
                    zip_heavy = true;
                }
                for s in rec.detected_stack {
                    if !stack.contains(&s) {
                        stack.push(s);
                    }
                }
                zip_overviews.push(format!("### Archive `{}`\n{}", att.display(), rec.markdown_overview));
            }
        } else if let Some(ext) = att.extension().and_then(|s| s.to_str()) {
            let low_ext = ext.to_ascii_lowercase();
            if let Some(tag) = stack_tag_for_ext(&low_ext) {
                let t = tag.to_string();
                if !stack.contains(&t) {
                    stack.push(t);
                }
            }
        }
    }

    let should_activate = match cfg.three_stage_mode {
        ThreeStageMode::Off => false,
        ThreeStageMode::Always => true,
        ThreeStageMode::Auto => {
            has_3stage_prompt_cue(user_prompt)
                || attachments.len() >= 4
                || zip_heavy
                || total_attach_bytes >= 32 * 1024
        }
    };
    if !should_activate {
        return rt;
    }

    let stage_dir = cfg.cwd.join(".agy_stage");
    let _ = std::fs::create_dir_all(&stage_dir);

    let mut map_parts: Vec<String> = Vec::new();
    map_parts.push("# Pre-Stage 0 Structural Map (0 LLM tokens)".to_string());
    if !attachments.is_empty() {
        let mut att_lines = Vec::new();
        for p in attachments {
            let sz = std::fs::metadata(p).map(|m| m.len()).unwrap_or(0);
            att_lines.push(format!("- `{}` ({} B)", p.display(), sz));
        }
        map_parts.push(format!("## Attached Files\n{}", att_lines.join("\n")));
    }
    if !zip_overviews.is_empty() {
        map_parts.push(zip_overviews.join("\n\n"));
    } else {
        let ws_files = collect_workspace_files_bounded(&cfg.cwd, 40);
        if !ws_files.is_empty() {
            let mut ws_lines = Vec::new();
            for (p, sz) in ws_files {
                let rel = p.strip_prefix(&cfg.cwd).unwrap_or(&p);
                if let Some(ext) = p.extension().and_then(|s| s.to_str()) {
                    if let Some(tag) = stack_tag_for_ext(&ext.to_ascii_lowercase()) {
                        let t = tag.to_string();
                        if !stack.contains(&t) {
                            stack.push(t);
                        }
                    }
                }
                ws_lines.push(format!("- `{}` ({} B)", rel.display(), sz));
            }
            map_parts.push(format!("## Workspace Snapshot (`{}`)\n{}", cfg.cwd.display(), ws_lines.join("\n")));
        }
    }
    if !stack.is_empty() {
        map_parts.insert(1, format!("Detected stack: {}", stack.join(", ")));
    }

    let repo_map_md = clip_chars(&map_parts.join("\n\n"), 5_500);
    let _ = atomic_write_text(&stage_dir.join("00_repo_map.md"), &repo_map_md).await;

    rt.active = true;
    rt.stage = 1;
    rt.stage_dir = stage_dir;
    rt.repo_map_md = repo_map_md;
    rt.detected_stack = stack;
    rt.stage1_cap = (max_steps / 4).clamp(2, 5);
    rt.stage2_cap = 2;
    rt
}

async fn capture_stage_artifact(
    stage_dir: &Path,
    filename: &str,
    candidate: &str,
    fallback: &str,
    max_chars: usize,
) -> String {
    let path = stage_dir.join(filename);
    let disk_txt = tokio::fs::read_to_string(&path)
        .await
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| s.chars().count() >= 40);
    let cand_trimmed = candidate.trim();
    let chosen = match disk_txt {
        Some(disk) if cand_trimmed.chars().count() < 120 || disk.chars().count() >= cand_trimmed.chars().count() / 2 => disk,
        _ if cand_trimmed.chars().count() >= 40 => cand_trimmed.to_string(),
        Some(disk) => disk,
        None => fallback.to_string(),
    };
    let clipped = clip_chars(&chosen, max_chars);
    let _ = std::fs::create_dir_all(stage_dir);
    let _ = atomic_write_text(&path, &clipped).await;
    clipped
}

fn build_stage1_prompt(rt: &ThreeStageRuntime, user_prompt: &str) -> String {
    format!(
        "[STAGE 1 / 3 — PRE_ANALYSIS_AND_MEMORY]\n\
<stage_contract stage=\"1\" outbox_write=\"FORBIDDEN\">\n\
OBJ: fast read-only analysis + write concise verified memory (<=4KB) to `{}` via <agy_write path=\"{}\"> then call finish.\n\
TOOLS: batch_read | code_to_md | <agy_exec>(python zipfile into `{}` or targeted symbol inspection).\n\
EXTRACT: entrypoints, public symbols/contracts, verified bugs, deps, integration boundaries.\n\
</stage_contract>\n\
<goal_context>\n{}\n</goal_context>\n\
<repo_map>\n{}\n</repo_map>",
        rt.stage_dir.join("01_memory.md").display(),
        rt.stage_dir.join("01_memory.md").display(),
        rt.stage_dir.join("work").display(),
        clip_chars(user_prompt, 2_400),
        clip_chars(&rt.repo_map_md, 4_200),
    )
}

fn build_stage2_prompt(stage_dir: &Path, memory_md: &str, skills_brief: &str) -> String {
    let skills_block = if skills_brief.trim().is_empty() {
        "- Modular contracts, edge-case guards, syntax+functional verification after every edit.".to_string()
    } else {
        clip_chars(skills_brief, 4_500)
    };
    format!(
        "[STAGE 2 / 3 — CHUNK_INTEGRATION_PLAN]\n\
<stage_contract stage=\"2\" outbox_write=\"FORBIDDEN\">\n\
OBJ: combine Stage-1 Memory + SkillHub rules into ONE integrated plan (3..5 chunks; up to 10 for large multi-module).\n\
SLOT_RULE: Stage 3 creates unified skeleton(s) with `# <<<AGY_SLOT:id>>>` / `// <<<AGY_SLOT:id>>>` (<agy_write>) then fills slots (<5KB each via <agy_slot> or assemble_slots). NEVER emit standalone disconnected scripts.\n\
DELIVER: write plan to `{}` (<agy_write>) OR call finish with: (1) target files & preserved symbols, (2) ordered Slot IDs 1..N, (3) exact syntax/test verify commands.\n\
</stage_contract>\n\
<skills_brief>\n{}\n</skills_brief>\n\
<stage1_memory>\n{}\n</stage1_memory>",
        stage_dir.join("02_plan.md").display(),
        skills_block,
        clip_chars(memory_md, 3_200),
    )
}

fn build_stage3_prompt(
    stage_dir: &Path,
    memory_md: &str,
    skills_brief: &str,
    plan_md: &str,
    user_prompt: &str,
) -> String {
    format!(
        "[STAGE 3 / 3 — RE-SENT MAIN PROMPT & INTEGRATED CHUNKED EXECUTION]\n\
Stage-1 Chat Memory (`{}`), Targeted SkillHub Rules (`{}`), and your Locked Chunk Plan (`{}`) are active above.\n\n\
MANDATORY STAGE-3 EXECUTION PROTOCOL:\n\
1. NEVER emit standalone/toy files or partial code dumps. Implement ONE unified, integrated solution matching all contracts in Memory & Plan.\n\
2. Build in 3–5 chunks (up to 10 for large repos, <5 KB per chunk): write integrated skeleton(s) with `# <<<AGY_SLOT:id>>>` / `// <<<AGY_SLOT:id>>>` markers first, then fill EVERY slot via `<agy_slot name=\"id\" path=\"...\">...</agy_slot>` (or `assemble_slots`), checking syntax & imports cleanly.\n\
3. Verify the completed project with real syntax + runtime/unit tests (`<agy_exec>` / `run_command`), deliver clean verified output(s) to outbox if requested, ensure zero remaining `<<<AGY_SLOT:...>>>` markers, and only then call `finish`.\n\n\
### Quick Reference (distilled)\n\
- Memory: {}\n\
- Skills: {}\n\
- Plan: {}\n\n\
=== ORIGINAL USER PROMPT (RE-SENT FOR FULL EXECUTION) ===\n{}",
        stage_dir.join("01_memory.md").display(),
        stage_dir.join("02_skills_brief.md").display(),
        stage_dir.join("02_plan.md").display(),
        clip_chars(memory_md, 1_400),
        clip_chars(skills_brief, 1_200),
        clip_chars(plan_md, 1_600),
        user_prompt,
    )
}

fn compact_stage_messages(
    messages: &mut Vec<Value>,
    base_len: usize,
    user_summary: &str,
    assistant_commit: &str,
    next_user_prompt: &str,
) {
    messages.truncate(base_len);
    messages.push(json!({ "role": "user", "content": user_summary }));
    messages.push(json!({ "role": "assistant", "content": assistant_commit }));
    messages.push(json!({ "role": "user", "content": next_user_prompt }));
}

async fn advance_stage_1_to_2(
    cfg: &AgentTurnConfig,
    rt: &mut ThreeStageRuntime,
    user_prompt: &str,
    candidate_memory: &str,
    messages: &mut Vec<Value>,
    loop_guard: &mut LoopGuard,
    step1_nudged: &mut bool,
) {
    let mem = capture_stage_artifact(
        &rt.stage_dir,
        "01_memory.md",
        candidate_memory,
        &rt.repo_map_md,
        5_000,
    )
    .await;
    let skills = crate::uncensored::retrieve_targeted_skills_brief(
        &cfg.skills_dir,
        &cfg.state_dir,
        &rt.detected_stack,
        user_prompt,
        &mem,
    )
    .await;
    let skills_clipped = clip_chars(&skills, 4_500);
    let _ = atomic_write_text(&rt.stage_dir.join("02_skills_brief.md"), &skills_clipped).await;

    let stage2_prompt = build_stage2_prompt(&rt.stage_dir, &mem, &skills_clipped);
    let user_summary = format!(
        "[Stage 1 Background Analysis Complete — Strategic Compact applied]\nGoal: {}",
        clip_chars(user_prompt, 500)
    );
    let asst_commit = format!(
        "[VERIFIED CHAT MEMORY — `.agy_stage/01_memory.md`]\n{}",
        clip_chars(&mem, 4_500)
    );
    compact_stage_messages(messages, rt.base_msg_count, &user_summary, &asst_commit, &stage2_prompt);

    rt.memory_md = mem;
    rt.skills_brief = skills_clipped;
    rt.stage = 2;
    rt.stage_steps_used = 0;
    *step1_nudged = false;
    *loop_guard = LoopGuard::default();
}

async fn advance_stage_2_to_3(
    rt: &mut ThreeStageRuntime,
    user_prompt: &str,
    candidate_plan: &str,
    messages: &mut Vec<Value>,
    loop_guard: &mut LoopGuard,
    step1_nudged: &mut bool,
    outbox_nudges: &mut usize,
    quality_nudged: &mut bool,
    budget_outbox_nudged: &mut bool,
) {
    let plan = capture_stage_artifact(
        &rt.stage_dir,
        "02_plan.md",
        candidate_plan,
        "1. Write integrated skeleton with named `# <<<AGY_SLOT:...>>>` markers.\n2. Fill each slot in 3-5 clean chunks (<5 KB) via `<agy_slot>`.\n3. Verify syntax + run tests + write verified deliverable(s).",
        4_500,
    )
    .await;
    let stage3_prompt = build_stage3_prompt(
        &rt.stage_dir,
        &rt.memory_md,
        &rt.skills_brief,
        &plan,
        user_prompt,
    );
    let user_summary = format!(
        "[Stage 1 & 2 Complete — Active Memory + SkillHub + Locked Chunk Plan]\n{}",
        clip_chars(&rt.skills_brief, 1_500)
    );
    let asst_commit = format!(
        "[CHAT MEMORY & CHUNK PLAN COMMITTED]\n## Memory\n{}\n\n## Chunk Plan\n{}",
        clip_chars(&rt.memory_md, 2_500),
        clip_chars(&plan, 2_500)
    );
    compact_stage_messages(messages, rt.base_msg_count, &user_summary, &asst_commit, &stage3_prompt);

    rt.plan_md = plan;
    rt.stage = 3;
    rt.stage_steps_used = 0;
    rt.slot_nudges = 0;
    *step1_nudged = false;
    *outbox_nudges = 0;
    *quality_nudged = false;
    *budget_outbox_nudged = false;
    *loop_guard = LoopGuard::default();
}

fn build_wire_hud_suffix(
    rt: &ThreeStageRuntime,
    step: usize,
    max_steps: usize,
    turn_state: &TurnRuntimeState,
    expected_outbox: Option<&Path>,
) -> Option<String> {
    let slots = turn_state.open_slots_compact_label();
    if step == 1 && !rt.active && !turn_state.is_dirty() && slots.is_empty() {
        return None;
    }
    let outbox_lbl = match expected_outbox {
        Some(dir) if dir_has_non_empty_files(dir) => "ready",
        Some(_) => "empty",
        None => "n/a",
    };
    let slot_seg = if slots.is_empty() {
        String::new()
    } else {
        format!(" | open_slots={slots}")
    };
    Some(format!(
        "\n\n[HUD | phase={} | step={}/{} | dirty={} | outbox={}{slot_seg}]",
        rt.phase_label(),
        step,
        max_steps,
        turn_state.is_dirty(),
        outbox_lbl,
    ))
}

fn build_slot_guard_prompt(turn_state: &TurnRuntimeState) -> Option<String> {
    let items = turn_state.open_slots_snapshot();
    let (first_path, first_slots) = items.into_iter().next()?;
    let first_id = first_slots.first().cloned().unwrap_or_default();
    if first_id.is_empty() {
        return None;
    }
    Some(format!(
        "SLOT COMPLETENESS GUARD: `{}` STILL contains unfilled slot marker(s): [{}]. \
Do NOT finish with an incomplete skeleton! Emit the next chunk (<5 KB) now using:\n\
`<agy_slot name=\"{first_id}\" path=\"{}\">\n...complete integrated code for `{first_id}`...\n</agy_slot>`\n\
(or call `assemble_slots`), then verify syntax/tests before finishing.",
        first_path.display(),
        first_slots.join(", "),
        first_path.display()
    ))
}

fn has_modified_code_file(state: &TurnRuntimeState) -> bool {
    state.modified_files().iter().any(|p| {
        Path::new(p)
            .extension()
            .and_then(|s| s.to_str())
            .is_some_and(|e| is_checked_code_ext(&e.to_ascii_lowercase()))
    })
}

#[allow(clippy::too_many_arguments)]
fn maybe_dirty_verify_nudge(
    cfg: &AgentTurnConfig,
    venice_mode: bool,
    rt_stage: &ThreeStageRuntime,
    expects_outbox_delivery: bool,
    turn_state: &TurnRuntimeState,
    dirty_verify_nudged: &mut bool,
    step: usize,
    effective_max_steps: usize,
) -> Option<String> {
    if !cfg.can_exec()
        || !venice_mode
        || !rt_stage.in_final_stage()
        || !expects_outbox_delivery
        || *dirty_verify_nudged
        || !turn_state.is_dirty()
        || step >= effective_max_steps
        || !has_modified_code_file(turn_state)
    {
        return None;
    }
    *dirty_verify_nudged = true;
    Some(
        "VERIFICATION REQUIRED BEFORE FINISHING: Code file(s) were modified (`dirty=true`) without a passing verification command afterwards. \
Run a real runtime/functional check (putting any scratch test script inside `cwd`, NOT inside `outbox/`) via `<agy_exec>` or `run_command`, fix any error found, and only then call `finish`."
            .to_string(),
    )
}

/// Run a full multi-turn autonomous agent (or direct chat) turn against any OpenAI-compatible provider.
pub async fn run_openai_agent_turn(
    provider: &dyn AuthHeaderProvider,
    cfg: &AgentTurnConfig,
    user_prompt: &str,
    on_progress: Option<ProgressCallback>,
    mut cancel: watch::Receiver<bool>,
) -> Result<JobResult> {
    let client = if let Some(px) = cfg
        .proxy_url
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        let proxy = reqwest::Proxy::all(px).map_err(|e| {
            BridgeError::Network(format!(
                "invalid egress proxy {}: {e}",
                agy_core::redact_proxy_url(px)
            ))
        })?;
        reqwest::Client::builder()
            .use_rustls_tls()
            .tcp_keepalive(Duration::from_secs(30))
            .pool_max_idle_per_host(8)
            .connect_timeout(Duration::from_secs(20))
            .read_timeout(Duration::from_secs(90))
            .proxy(proxy)
            .build()
            .map_err(|e| BridgeError::Network(format!("agent HTTP client build failed: {e}")))?
    } else {
        shared_direct_http_client()?
    };

    let started = Instant::now();
    let deadline = started + Duration::from_secs(cfg.job_timeout_secs.max(30));
    let venice_mode = is_venice_prompt_engine(cfg);

    let mut session = cfg
        .session_key
        .as_deref()
        .map(|k| load_session(&cfg.state_dir, k))
        .unwrap_or_else(|| StoredAgentSession {
            session_id: uuid::Uuid::new_v4().to_string(),
            updated_at: 0,
            messages: Vec::new(),
        });

    let tools = if cfg.agent_mode {
        agent_tools_schema_for(cfg.allow_root, cfg.allow_sandbox)
    } else {
        Vec::new()
    };

    let mut messages: Vec<Value> = Vec::with_capacity(session.messages.len() + 4);
    let mut system_content = if cfg.agent_mode
        && !cfg.system_prompt.contains("Operating discipline:")
        && !cfg.system_prompt.contains("Execution & Code-Quality Discipline:")
        && !cfg.system_prompt.contains("Execution & Speed Discipline:")
    {
        format!("{}\n\n{AGENT_CORE_DISCIPLINE}", cfg.system_prompt)
    } else {
        cfg.system_prompt.clone()
    };
    if cfg.agent_mode {
        if let Some(microagents_ctx) = openhands::load_repo_microagents(&cfg.cwd, user_prompt) {
            system_content.push_str("\n\n");
            system_content.push_str(&microagents_ctx);
        }
        if venice_mode && !tools.is_empty() {
            system_content.push_str(&build_prompt_tool_protocol_spec(&tools));
        }
    }
    messages.push(json!({ "role": "system", "content": system_content }));
    messages.extend(session.messages.iter().cloned());

    let expected_outbox_dir = extract_outbox_dir(user_prompt);
    let attached_files = extract_attachment_paths(user_prompt);
    let expects_outbox_delivery = cfg.agent_mode
        && venice_mode
        && expected_outbox_dir.is_some()
        && prompt_expects_file_delivery(user_prompt);

    let max_steps = if cfg.agent_mode {
        cfg.max_steps.clamp(1, MAX_AGENT_STEPS_CAP)
    } else {
        3 // allows up to 2 auto-continuations on finish_reason="length" in chat mode
    };
    let mut rt_stage = prepare_prestage_0(cfg, user_prompt, &attached_files, max_steps).await;
    rt_stage.base_msg_count = messages.len();
    if rt_stage.active {
        let s1 = build_stage1_prompt(&rt_stage, user_prompt);
        messages.push(json!({ "role": "user", "content": s1 }));
    } else {
        messages.push(json!({ "role": "user", "content": user_prompt }));
    }

    let turn_state = Arc::new(TurnRuntimeState::new());
    let mut loop_guard = LoopGuard::default();

    let mut progress = Progress {
        started,
        ..Default::default()
    };
    let mut final_text = String::new();
    let mut total_usage = json!({ "input_tokens": 0u64, "output_tokens": 0u64 });
    let mut stopped = false;
    let mut timed_out = false;
    let mut api_error: Option<Value> = None;
    let mut hit_step_cap = false;
    let mut active_model = cfg.model.clone();
    let mut active_max_tokens = cfg.max_tokens;
    let mut failover_queue: Vec<String> = if is_venice_engine(cfg) {
        crate::uncensored::fallback_failover_chain(&active_model)
    } else {
        Vec::new()
    };
    let mut step1_nudged = false;
    let mut outbox_nudges = 0usize;
    let mut quality_nudged = false;
    let mut dirty_verify_nudged = false;
    let mut budget_outbox_nudged = false;
    let mut length_continuations = 0usize;

    let mut effective_max_steps = max_steps;
    let mut step = 0usize;

    'agent_loop: while step < effective_max_steps {
        step += 1;
        rt_stage.stage_steps_used += 1;
        if *cancel.borrow() {
            stopped = true;
            break;
        }
        if Instant::now() >= deadline {
            timed_out = true;
            break;
        }
        if cfg.agent_mode && step > 1 {
            progress.partial.clear();
        }

        // OpenHands Context Condenser: compact old tool outputs & preserve active task plan + modified files
        let compacted = compact_in_turn_messages(&mut messages, MAX_IN_TURN_CONTEXT_BYTES);
        if compacted > 0 {
            debug!(engine = %cfg.engine_id, compacted, "compacted older tool messages mid-turn");
            let mut state_lines = Vec::new();
            let mods = turn_state.modified_files();
            if !mods.is_empty() {
                state_lines.push(format!("Modified files so far: {}", mods.join(", ")));
            }
            if let Some(plan_summary) = turn_state.task_tracker().compact_summary() {
                state_lines.push(plan_summary);
            }
            if !state_lines.is_empty() {
                messages.retain(|m| {
                    !m.get("content")
                        .and_then(Value::as_str)
                        .is_some_and(|c| c.starts_with("[OpenHands Condenser State Snapshot]\n"))
                });
                messages.push(json!({
                    "role": "user",
                    "content": format!("[OpenHands Condenser State Snapshot]\n{}", state_lines.join("\n"))
                }));
            }
        }

        progress.steps = step;
        progress.last_step = if cfg.agent_mode {
            match rt_stage.stage {
                1 => format!("stage1_mem_step_{step}"),
                2 => format!("stage2_plan_step_{step}"),
                3 => format!("stage3_exec_step_{step}"),
                _ => format!("agent_step_{step}"),
            }
        } else if length_continuations > 0 {
            format!("chat_continue_{length_continuations}")
        } else {
            "chat_reply".to_string()
        };
        if let Some(ref cb) = on_progress {
            cb(progress.clone()).await;
        }

        let hud_suffix = if venice_mode && cfg.agent_mode {
            build_wire_hud_suffix(
                &rt_stage,
                step,
                effective_max_steps,
                &turn_state,
                expected_outbox_dir.as_deref(),
            )
        } else {
            None
        };

        let build_payload = |model_id: &str, max_toks: u32, msgs: &[Value]| -> Value {
            let mut wire_msgs = if venice_mode {
                prepare_messages_for_venice(msgs)
            } else {
                msgs.to_vec()
            };
            if let Some(ref hud) = hud_suffix {
                if let Some(last_u) = wire_msgs
                    .iter_mut()
                    .rev()
                    .find(|m| m.get("role").and_then(Value::as_str) == Some("user"))
                {
                    if let Some(txt) = last_u.get("content").and_then(Value::as_str) {
                        let base = if txt.len() + hud.len() > 71_000 {
                            clip_chars(txt, 70_000)
                        } else {
                            txt.to_string()
                        };
                        last_u["content"] = Value::String(format!("{base}{hud}"));
                    }
                }
            }
            let mut p = json!({
                "model": model_id,
                "messages": wire_msgs,
                "max_tokens": max_toks,
                "temperature": if cfg.agent_mode {
                    if venice_mode { 0.35 } else { 0.25 }
                } else {
                    0.45
                },
            });
            if venice_mode {
                // Disable Venice web-chat auto-search and default chatbot system prompt so our
                // agent/custom system prompt runs cleanly without interference.
                p["venice_parameters"] = json!({
                    "include_venice_system_prompt": false,
                    "enable_web_search": "off",
                    "enable_web_scraping": false
                });
            } else if cfg.agent_mode && !tools.is_empty() {
                p["tools"] = Value::Array(tools.clone());
                p["tool_choice"] = json!("auto");
            }
            p
        };

        let mut payload = build_payload(&active_model, active_max_tokens, &messages);
        let mut comp_retries = 0usize;

        let resp_json = loop {
            let live_hook = on_progress.as_ref().map(|cb| (&mut progress, cb));
            let attempt_res = send_chat_completion(
                &client,
                provider,
                &payload,
                &mut cancel,
                live_hook,
                venice_mode,
            )
            .await;
            match attempt_res {
                Ok(v) => break Some(v),
                Err((0, msg)) if msg == "stopped" => {
                    stopped = true;
                    break None;
                }
                Err((status, msg))
                    if comp_retries < 2
                        && (status == 413
                            || (status == 400
                                && {
                                    let low = msg.to_ascii_lowercase();
                                    low.contains("context")
                                        || low.contains("token")
                                        || low.contains("too large")
                                        || low.contains("too long")
                                        || low.contains("userprompttoolong")
                                        || low.contains("length")
                                })) =>
                {
                    if loop_guard.record_context_error() {
                        api_error = Some(json!({
                            "code": status,
                            "message": format!("[StuckDetector Pattern 5: repeated context window overflow] {msg}")
                        }));
                        break None;
                    }
                    comp_retries += 1;
                    let target_budget = if comp_retries == 1 { 48_000 } else { 16_000 };
                    compact_in_turn_messages(&mut messages, target_budget);
                    payload = build_payload(&active_model, active_max_tokens, &messages);
                    continue;
                }
                Err((status, msg)) => {
                    // Rescue Cascade: failover to the next healthy verified Venice Uncensored model!
                    if venice_mode && !failover_queue.is_empty() && !*cancel.borrow() {
                        let next_model = failover_queue.remove(0);
                        warn!(
                            from = %active_model,
                            to = %next_model,
                            status,
                            err = %clip_chars(&msg, 200),
                            "uncensored model failed; failing over to backup uncensored model"
                        );
                        active_model = next_model;
                        active_max_tokens = crate::uncensored::model_max_tokens(&active_model)
                            .min(cfg.max_tokens);
                        progress.last_step = format!("failover → {}", clip_chars(&active_model, 32));
                        if let Some(ref cb) = on_progress {
                            cb(progress.clone()).await;
                        }
                        if matches!(status, 0 | 404 | 429 | 500..=599) {
                            let pause = Duration::from_millis(1_800 + retry_jitter_ms(failover_queue.len()));
                            if sleep_cancellable(pause, &mut cancel).await {
                                stopped = true;
                                break None;
                            }
                        }
                        payload = build_payload(&active_model, active_max_tokens, &messages);
                        continue;
                    }
                    api_error = Some(json!({
                        "code": if status > 0 { Value::from(status) } else { Value::Null },
                        "message": msg
                    }));
                    break None;
                }
            }
        };
        let Some(resp_json) = resp_json else {
            break 'agent_loop;
        };

        // Accumulate usage telemetry
        if let Some(u) = resp_json.get("usage").and_then(Value::as_object) {
            let inp = u.get("prompt_tokens").and_then(Value::as_u64).unwrap_or(0);
            let out = u.get("completion_tokens").and_then(Value::as_u64).unwrap_or(0);
            total_usage["input_tokens"] =
                json!(total_usage["input_tokens"].as_u64().unwrap_or(0) + inp);
            total_usage["output_tokens"] =
                json!(total_usage["output_tokens"].as_u64().unwrap_or(0) + out);
        }

        let Some(choice) = resp_json
            .get("choices")
            .and_then(Value::as_array)
            .and_then(|c| c.first())
        else {
            api_error = Some(json!({ "message": "Model returned no choices." }));
            break 'agent_loop;
        };

        let finish_reason = choice
            .get("finish_reason")
            .and_then(Value::as_str)
            .unwrap_or("");

        let Some(msg) = choice.get("message") else {
            api_error = Some(json!({ "message": "Model response missing message object." }));
            break 'agent_loop;
        };

        let raw_content = msg
            .get("content")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_string();
        let reasoning_fallback = msg
            .get("reasoning_content")
            .or_else(|| msg.get("reasoning"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_string();
        let content_text = if !raw_content.is_empty() {
            raw_content.clone()
        } else {
            reasoning_fallback
        };

        let tool_calls = if cfg.agent_mode {
            extract_tool_calls(msg, &raw_content)
        } else {
            Vec::new()
        };

        if tool_calls.is_empty() {
            let is_stage_entry = rt_stage.stage_steps_used == 1 && (rt_stage.stage == 0 || rt_stage.stage == 1 || rt_stage.stage == 3);
            // Rescue: if model refused/deferred on stage entry when local files or outbox exist, nudge ONCE!
            if cfg.agent_mode
                && venice_mode
                && is_stage_entry
                && !step1_nudged
                && (content_text.is_empty() || looks_like_premature_tool_deferral(user_prompt, &content_text))
            {
                step1_nudged = true;
                let prev_asst = if content_text.is_empty() {
                    "[Empty initial response]".to_string()
                } else {
                    content_text.clone()
                };
                messages.push(json!({ "role": "assistant", "content": prev_asst }));
                messages.push(json!({
                    "role": "user",
                    "content": "IMPORTANT: You HAVE live tools right now! Do NOT stop or ask for files to be pasted. \
Immediately emit `<agy_call>{\"name\": \"read_file\", \"arguments\": {\"path\": \"...\"}}</agy_call>` (or `code_to_md` / `batch_read` / `<agy_exec>`), complete this stage's work cleanly, and call `finish`."
                }));
                continue 'agent_loop;
            }

            // Structural silent-truncation rescue for Venice Web Chat (where finish_reason is ALWAYS fake "stop")
            if venice_mode && length_continuations < 2 && step < effective_max_steps && !content_text.is_empty() {
                if let Some(trunc) = detect_silent_venice_truncation(&content_text) {
                    length_continuations += 1;
                    warn!(?trunc, step, "detected silent Venice web-chat truncation despite finish_reason=stop; rescuing");
                    match trunc {
                        SilentTruncation::UnclosedAgyWrite { path, partial_bytes } => {
                            let target_hint = if path.is_empty() { "the target file".to_string() } else { format!("`{path}`") };
                            messages.push(json!({
                                "role": "assistant",
                                "content": format!("[Truncated mid-<agy_write> for {target_hint} after {partial_bytes} B]")
                            }));
                            messages.push(json!({
                                "role": "user",
                                "content": format!(
                                    "SILENT TRUNCATION DETECTED: Venice Web Chat cut off your `<agy_write>` for {target_hint} before `</agy_write>`, so nothing was saved. \
Immediately write {target_hint} using `<agy_exec>` OR a compact skeleton with `<<<AGY_SLOT:id>>>` markers filled via `<agy_slot>` (<5 KiB per chunk), then verify syntax.",
                                )
                            }));
                            continue 'agent_loop;
                        }
                        SilentTruncation::UnclosedAgyExec { partial_bytes } => {
                            messages.push(json!({
                                "role": "assistant",
                                "content": format!("[Truncated mid-<agy_exec> after {partial_bytes} B]")
                            }));
                            messages.push(json!({
                                "role": "user",
                                "content": "SILENT TRUNCATION DETECTED: Your `<agy_exec>` script was cut off before `</agy_exec>`. Emit a shorter, focused `<agy_exec>...</agy_exec>` script (<4 KiB) to finish the edit and verify it."
                            }));
                            continue 'agent_loop;
                        }
                        SilentTruncation::UnclosedAgySlot { slot, partial_bytes } => {
                            let slot_hint = if slot.is_empty() {
                                "the current slot".to_string()
                            } else {
                                format!("slot `{slot}`")
                            };
                            messages.push(json!({
                                "role": "assistant",
                                "content": format!("[Truncated mid-<agy_slot> for {slot_hint} after {partial_bytes} B]")
                            }));
                            messages.push(json!({
                                "role": "user",
                                "content": format!(
                                    "SILENT TRUNCATION DETECTED: Venice Web Chat cut off your `<agy_slot>` for {slot_hint} before `</agy_slot>`, so nothing was spliced. \
Re-emit ONE smaller complete `<agy_slot name=\"{}\">...</agy_slot>` block (<5 KiB) with valid indentation, OR split that logic across two smaller slots/helper calls.",
                                    if slot.is_empty() { "<slot_id>" } else { &slot },
                                )
                            }));
                            continue 'agent_loop;
                        }
                        SilentTruncation::UnclosedAgyCall => {
                            messages.push(json!({
                                "role": "assistant",
                                "content": "[Truncated mid-<agy_call>]"
                            }));
                            messages.push(json!({
                                "role": "user",
                                "content": "SILENT TRUNCATION DETECTED: Your `<agy_call>` JSON was cut off before `</agy_call>`. Use `<agy_exec>...</agy_exec>` for Python code or `<agy_slot>`/`<agy_write path=\"...\">...</agy_write>` for files."
                            }));
                            continue 'agent_loop;
                        }
                        SilentTruncation::UnclosedCodeFence => {
                            let visible_chunk = strip_tool_call_markup(&content_text);
                            if !visible_chunk.is_empty() && rt_stage.in_final_stage() {
                                if !final_text.is_empty() {
                                    final_text.push('\n');
                                }
                                final_text.push_str(&visible_chunk);
                                progress.partial = final_text.clone();
                            }
                            messages.push(json!({ "role": "assistant", "content": content_text }));
                            messages.push(json!({
                                "role": "user",
                                "content": "Your previous reply was truncated mid-code-block. Continue seamlessly from the exact character where you stopped and close the fence, without repeating previous text."
                            }));
                            continue 'agent_loop;
                        }
                    }
                }
            }

            let visible_chunk = strip_tool_call_markup(&content_text);

            // Empty output with no tool calls -> try failover model once if available!
            if visible_chunk.trim().is_empty() && final_text.trim().is_empty() && venice_mode && !failover_queue.is_empty() && step < effective_max_steps {
                let next_model = failover_queue.remove(0);
                warn!(from = %active_model, to = %next_model, "uncensored model returned empty content; failing over");
                active_model = next_model;
                active_max_tokens = crate::uncensored::model_max_tokens(&active_model).min(cfg.max_tokens);
                continue 'agent_loop;
            }

            // Stage 1 / Stage 2 non-tool completion MUST transition to next stage rather than exiting early!
            if rt_stage.stage == 1 && step < effective_max_steps {
                advance_stage_1_to_2(
                    cfg,
                    &mut rt_stage,
                    user_prompt,
                    &visible_chunk,
                    &mut messages,
                    &mut loop_guard,
                    &mut step1_nudged,
                )
                .await;
                final_text.clear();
                progress.partial.clear();
                continue 'agent_loop;
            }
            if rt_stage.stage == 2 && step < effective_max_steps {
                advance_stage_2_to_3(
                    &mut rt_stage,
                    user_prompt,
                    &visible_chunk,
                    &mut messages,
                    &mut loop_guard,
                    &mut step1_nudged,
                    &mut outbox_nudges,
                    &mut quality_nudged,
                    &mut budget_outbox_nudged,
                )
                .await;
                final_text.clear();
                progress.partial.clear();
                continue 'agent_loop;
            }

            if !visible_chunk.is_empty() {
                if !final_text.is_empty() {
                    final_text.push('\n');
                }
                final_text.push_str(&visible_chunk);
                progress.partial = final_text.clone();
            }

            // Auto-continuation rescue when output hits max_tokens (`finish_reason == "length"`)
            if finish_reason == "length" && length_continuations < 2 && step < effective_max_steps && !content_text.is_empty() {
                length_continuations += 1;
                messages.push(json!({ "role": "assistant", "content": content_text }));
                messages.push(json!({
                    "role": "user",
                    "content": "Continue seamlessly from the exact character where you stopped, without repeating previous text."
                }));
                continue 'agent_loop;
            }

            // Slot Completeness Guard (Stage 0 / Stage 3): reject stopping while `<<<AGY_SLOT:...>>>` remains!
            if cfg.agent_mode
                && venice_mode
                && rt_stage.in_final_stage()
                && rt_stage.slot_nudges < 10
                && step < effective_max_steps
            {
                if let Some(slot_msg) = build_slot_guard_prompt(&turn_state) {
                    rt_stage.slot_nudges += 1;
                    let prev_asst = if visible_chunk.is_empty() {
                        "[Wrote skeleton with open slots]".to_string()
                    } else {
                        clip_chars(&visible_chunk, 800)
                    };
                    messages.push(json!({ "role": "assistant", "content": prev_asst }));
                    messages.push(json!({ "role": "user", "content": slot_msg }));
                    final_text.clear();
                    continue 'agent_loop;
                }
            }

            // Mandatory Outbox Delivery & Code-Quality Guard (ONLY in Stage 0 or Stage 3!)
            if expects_outbox_delivery && rt_stage.in_final_stage() && step < effective_max_steps {
                if let Some(ref odir) = expected_outbox_dir {
                    if outbox_nudges < 2 && !dir_has_non_empty_files(odir) {
                        outbox_nudges += 1;
                        let mods = turn_state.modified_files();
                        let mod_hint = if mods.is_empty() {
                            String::new()
                        } else {
                            format!(" Modified files in workspace: {}.", mods.join(", "))
                        };
                        let prev_asst = if visible_chunk.is_empty() {
                            "[Completed analysis]".to_string()
                        } else {
                            clip_chars(&visible_chunk, 800)
                        };
                        messages.push(json!({ "role": "assistant", "content": prev_asst }));
                        messages.push(json!({
                            "role": "user",
                            "content": format!(
                                "ACTION REQUIRED BEFORE FINISHING: The Telegram outbox directory `{}` is still EMPTY, so no file would be uploaded to the user!{mod_hint} \
Immediately write the complete, verified file(s) directly inside `{}/` using `<agy_write path=\"{}/<filename>\">...</agy_write>` (or `<agy_exec>`), verify syntax & tests, and only then give your final summary.",
                                odir.display(),
                                odir.display(),
                                odir.display()
                            )
                        }));
                        final_text.clear();
                        continue 'agent_loop;
                    } else if !quality_nudged && dir_has_non_empty_files(odir) {
                        if let Some(q_issue) = inspect_outbox_code_quality(odir, &attached_files).await {
                            quality_nudged = true;
                            let prev_asst = if visible_chunk.is_empty() {
                                "[Wrote output file]".to_string()
                            } else {
                                clip_chars(&visible_chunk, 800)
                            };
                            messages.push(json!({ "role": "assistant", "content": prev_asst }));
                            messages.push(json!({
                                "role": "user",
                                "content": format!(
                                    "QUALITY GUARD REJECTED OUTPUT BEFORE DELIVERY: {q_issue}\nFix this immediately using `execute_code`/`patch_file`/`<agy_write>`, re-verify syntax (`php -l`/`python3`/`node --check`), and then finish."
                                )
                            }));
                            final_text.clear();
                            continue 'agent_loop;
                        }
                    }
                }
            }

            if let Some(verify_nudge) = maybe_dirty_verify_nudge(
                cfg,
                venice_mode,
                &rt_stage,
                expects_outbox_delivery,
                &turn_state,
                &mut dirty_verify_nudged,
                step,
                effective_max_steps,
            ) {
                let prev_asst = if visible_chunk.is_empty() {
                    "[Wrote modified code file]".to_string()
                } else {
                    clip_chars(&visible_chunk, 800)
                };
                messages.push(json!({ "role": "assistant", "content": prev_asst }));
                messages.push(json!({ "role": "user", "content": verify_nudge }));
                final_text.clear();
                continue 'agent_loop;
            }

            break 'agent_loop;
        }

        let visible_preface = strip_tool_call_markup(&raw_content);
        if !visible_preface.is_empty() && rt_stage.in_final_stage() {
            progress.partial = visible_preface;
        }
        // Push clean canonical assistant message into history (never raw repeated </agy_call> spam!)
        messages.push(build_canonical_assistant_history(msg, &raw_content, &tool_calls));

        // Execute tool calls waves
        let mut idx = 0usize;
        let mut stage_transitioned = false;
        while idx < tool_calls.len() {
            if *cancel.borrow() {
                stopped = true;
                break;
            }
            if is_parallel_safe_call(&tool_calls[idx].1, &tool_calls[idx].2) {
                let mut end = idx + 1;
                while end < tool_calls.len()
                    && is_parallel_safe_call(&tool_calls[end].1, &tool_calls[end].2)
                {
                    end += 1;
                }
                if end - idx >= 2 {
                    let wave = &tool_calls[idx..end];
                    for (_, func_name, func_args) in wave {
                        let trace_lbl = format_tool_trace_label(func_name, func_args);
                        progress.tools.push(trace_lbl.clone());
                        progress
                            .trace
                            .push((started.elapsed().as_secs_f64(), trace_lbl));
                    }
                    progress.last_step = format!("tools_parallel({})", wave.len());
                    if let Some(ref cb) = on_progress {
                        cb(progress.clone()).await;
                    }

                    let sem = Arc::new(Semaphore::new(MAX_PARALLEL_READ_TOOLS));
                    let mut futs = Vec::with_capacity(wave.len());
                    for (call_id, func_name, func_args) in wave.iter().cloned() {
                        let blocked = loop_guard.check(&func_name, &func_args);
                        let sem_c = Arc::clone(&sem);
                        let st_c = Arc::clone(&turn_state);
                        futs.push(async move {
                            if let Some(msg) = blocked {
                                return (call_id, func_name, func_args, msg);
                            }
                            let _permit = sem_c.acquire_owned().await;
                            let out =
                                execute_agent_tool_with_state(&func_name, &func_args, cfg, &st_c)
                                    .await;
                            (call_id, func_name, func_args, out)
                        });
                    }

                    let results_opt = tokio::select! {
                        biased;
                        res = cancel.wait_for(|&v| v) => {
                            if res.is_ok() {
                                stopped = true;
                            }
                            None
                        }
                        res = futures_util::future::join_all(futs) => Some(res),
                    };
                    if let Some(results) = results_opt {
                        for (call_id, func_name, func_args, tool_out) in results {
                            let tool_out =
                                loop_guard.observe_with_args(&func_name, &func_args, tool_out);
                            messages.push(json!({
                                "role": "tool",
                                "tool_call_id": call_id,
                                "name": func_name,
                                "content": tool_out
                            }));
                        }
                    }
                    idx = end;
                    continue;
                }
            }

            let (call_id, func_name, func_args) = tool_calls[idx].clone();
            idx += 1;

            let trace_lbl = format_tool_trace_label(&func_name, &func_args);
            progress.tools.push(trace_lbl.clone());
            progress
                .trace
                .push((started.elapsed().as_secs_f64(), trace_lbl.clone()));
            progress.last_step = format!("tool:{func_name}");
            if let Some(ref cb) = on_progress {
                cb(progress.clone()).await;
            }

            debug!(engine = %cfg.engine_id, tool = %func_name, "agent invoking tool");
            let tool_out = if let Some(blocked) = loop_guard.check(&func_name, &func_args) {
                blocked
            } else {
                tokio::select! {
                    biased;
                    _ = wait_for_cancel(&mut cancel) => {
                        stopped = true;
                        break;
                    }
                    res = execute_agent_tool_with_state(&func_name, &func_args, cfg, &turn_state) => res,
                }
            };
            let tool_out = loop_guard.observe_with_args(&func_name, &func_args, tool_out);

            messages.push(json!({
                "role": "tool",
                "tool_call_id": call_id,
                "name": func_name,
                "content": tool_out
            }));

            if func_name == "finish" && !tool_out.trim().is_empty() {
                let push_skipped_remaining = |msgs: &mut Vec<Value>| {
                    for (rem_id, rem_name, _) in &tool_calls[idx..] {
                        msgs.push(json!({
                            "role": "tool",
                            "tool_call_id": rem_id,
                            "name": rem_name,
                            "content": "[skipped: verification/stage guard paused execution on `finish`]"
                        }));
                    }
                };
                if rt_stage.stage == 1 && step < effective_max_steps {
                    push_skipped_remaining(&mut messages);
                    advance_stage_1_to_2(
                        cfg,
                        &mut rt_stage,
                        user_prompt,
                        &strip_tool_call_markup(&tool_out),
                        &mut messages,
                        &mut loop_guard,
                        &mut step1_nudged,
                    )
                    .await;
                    stage_transitioned = true;
                    break;
                }
                if rt_stage.stage == 2 && step < effective_max_steps {
                    push_skipped_remaining(&mut messages);
                    advance_stage_2_to_3(
                        &mut rt_stage,
                        user_prompt,
                        &strip_tool_call_markup(&tool_out),
                        &mut messages,
                        &mut loop_guard,
                        &mut step1_nudged,
                        &mut outbox_nudges,
                        &mut quality_nudged,
                        &mut budget_outbox_nudged,
                    )
                    .await;
                    stage_transitioned = true;
                    break;
                }
                if venice_mode && rt_stage.in_final_stage() && rt_stage.slot_nudges < 10 && step < effective_max_steps {
                    if let Some(slot_msg) = build_slot_guard_prompt(&turn_state) {
                        push_skipped_remaining(&mut messages);
                        rt_stage.slot_nudges += 1;
                        messages.push(json!({
                            "role": "user",
                            "content": format!("WAIT — you called `finish`, but {slot_msg}")
                        }));
                        stage_transitioned = true;
                        break;
                    }
                }
                if expects_outbox_delivery && rt_stage.in_final_stage() && step < effective_max_steps {
                    if let Some(ref odir) = expected_outbox_dir {
                        if outbox_nudges < 2 && !dir_has_non_empty_files(odir) {
                            push_skipped_remaining(&mut messages);
                            outbox_nudges += 1;
                            messages.push(json!({
                                "role": "user",
                                "content": format!(
                                    "WAIT — you called `finish` but `{}` is still EMPTY! Write the improved/requested file(s) directly inside `{}/` via `<agy_write path=\"{}/<filename>\">...</agy_write>` and verify them before finishing.",
                                    odir.display(),
                                    odir.display(),
                                    odir.display()
                                )
                            }));
                            break;
                        } else if !quality_nudged && dir_has_non_empty_files(odir) {
                            if let Some(q_issue) = inspect_outbox_code_quality(odir, &attached_files).await {
                                push_skipped_remaining(&mut messages);
                                quality_nudged = true;
                                messages.push(json!({
                                    "role": "user",
                                    "content": format!(
                                        "WAIT — QUALITY GUARD REJECTED your output before `finish`: {q_issue}\nFix this immediately, verify syntax/tests, and then call `finish`."
                                    )
                                }));
                                break;
                            }
                        }
                    }
                }
                if let Some(verify_nudge) = maybe_dirty_verify_nudge(
                    cfg,
                    venice_mode,
                    &rt_stage,
                    expects_outbox_delivery,
                    &turn_state,
                    &mut dirty_verify_nudged,
                    step,
                    effective_max_steps,
                ) {
                    push_skipped_remaining(&mut messages);
                    messages.push(json!({
                        "role": "user",
                        "content": format!("WAIT — you called `finish`, but {verify_nudge}")
                    }));
                    stage_transitioned = true;
                    break;
                }
                push_skipped_remaining(&mut messages);
                final_text = strip_tool_call_markup(&tool_out);
                progress.partial = final_text.clone();
                stopped = false;
                hit_step_cap = false;
                break;
            }
        }

        if stage_transitioned {
            continue 'agent_loop;
        }
        if stopped || !final_text.is_empty() {
            break 'agent_loop;
        }

        if loop_guard.should_escape() {
            if rt_stage.stage == 1 && step < effective_max_steps {
                advance_stage_1_to_2(
                    cfg,
                    &mut rt_stage,
                    user_prompt,
                    &raw_content,
                    &mut messages,
                    &mut loop_guard,
                    &mut step1_nudged,
                )
                .await;
                continue 'agent_loop;
            }
            if rt_stage.stage == 2 && step < effective_max_steps {
                advance_stage_2_to_3(
                    &mut rt_stage,
                    user_prompt,
                    &raw_content,
                    &mut messages,
                    &mut loop_guard,
                    &mut step1_nudged,
                    &mut outbox_nudges,
                    &mut quality_nudged,
                    &mut budget_outbox_nudged,
                )
                .await;
                continue 'agent_loop;
            }
            hit_step_cap = true;
            break 'agent_loop;
        }

        // Enforce Stage 1 / Stage 2 budgets cleanly so Stage 3 always retains primary runway
        if rt_stage.stage == 1 && rt_stage.stage_steps_used >= rt_stage.stage1_cap && step < effective_max_steps {
            advance_stage_1_to_2(
                cfg,
                &mut rt_stage,
                user_prompt,
                &strip_tool_call_markup(&raw_content),
                &mut messages,
                &mut loop_guard,
                &mut step1_nudged,
            )
            .await;
            continue 'agent_loop;
        }
        if rt_stage.stage == 2 && rt_stage.stage_steps_used >= rt_stage.stage2_cap && step < effective_max_steps {
            advance_stage_2_to_3(
                &mut rt_stage,
                user_prompt,
                &strip_tool_call_markup(&raw_content),
                &mut messages,
                &mut loop_guard,
                &mut step1_nudged,
                &mut outbox_nudges,
                &mut quality_nudged,
                &mut budget_outbox_nudged,
            )
            .await;
            continue 'agent_loop;
        }

        if expects_outbox_delivery
            && rt_stage.in_final_stage()
            && !budget_outbox_nudged
            && effective_max_steps >= 4
            && step == effective_max_steps.saturating_sub(2)
        {
            if let Some(ref odir) = expected_outbox_dir {
                if !dir_has_non_empty_files(odir) {
                    budget_outbox_nudged = true;
                    messages.push(json!({
                        "role": "user",
                        "content": format!(
                            "BUDGET WARNING: Only 2 tool steps remain and `{}` is still EMPTY! Stop searching/reading now and IMMEDIATELY write the complete file into `{}/` via `<agy_write path=\"{}/<filename>\">...</agy_write>` or `execute_code`.",
                            odir.display(),
                            odir.display(),
                            odir.display()
                        )
                    }));
                }
            }
        }

        if step == effective_max_steps {
            if venice_mode
                && rt_stage.in_final_stage()
                && rt_stage.slot_nudges < 10
                && effective_max_steps + 2 <= MAX_AGENT_STEPS_CAP
            {
                if let Some(slot_msg) = build_slot_guard_prompt(&turn_state) {
                    rt_stage.slot_nudges += 1;
                    effective_max_steps += 2;
                    messages.push(json!({ "role": "user", "content": format!("EMERGENCY SLOT COMPLETION (+2 steps): {slot_msg}") }));
                    continue 'agent_loop;
                }
            }
            // Emergency +2 final steps if outbox is STILL empty OR a syntax/quality defect remains at the step cap!
            if expects_outbox_delivery && rt_stage.in_final_stage() && effective_max_steps + 2 <= MAX_AGENT_STEPS_CAP {
                if let Some(ref odir) = expected_outbox_dir {
                    if outbox_nudges < 2 && !dir_has_non_empty_files(odir) {
                        outbox_nudges += 1;
                        effective_max_steps += 2;
                        messages.push(json!({
                            "role": "user",
                            "content": format!(
                                "EMERGENCY DELIVERY (+2 final steps granted): `{}` is STILL EMPTY! Stop all other work and IMMEDIATELY write/package the final output file inside `{}/` via `<agy_write path=\"{}/<filename>\">...</agy_write>` or `execute_code` (Python zipfile/write), then finish.",
                                odir.display(),
                                odir.display(),
                                odir.display()
                            )
                        }));
                        continue 'agent_loop;
                    } else if !quality_nudged && dir_has_non_empty_files(odir) {
                        if let Some(q_issue) = inspect_outbox_code_quality(odir, &attached_files).await {
                            quality_nudged = true;
                            effective_max_steps += 2;
                            messages.push(json!({
                                "role": "user",
                                "content": format!(
                                    "EMERGENCY REPAIR (+2 final steps granted): {q_issue}\nFix ONLY this defect immediately, re-run syntax verification (`php -l`/`python3`/`node --check`), and finish."
                                )
                            }));
                            continue 'agent_loop;
                        }
                    }
                }
            }
            hit_step_cap = true;
        }
    }

    // Guaranteed final synthesis turn if we hit the step cap or escape-hatch while still invoking tools!
    if hit_step_cap && final_text.is_empty() && api_error.is_none() && !stopped && !timed_out {
        let capture = loop_guard.failure_capture();
        let synth_msg = if capture.is_empty() {
            "You reached the maximum tool-call step limit for this turn. Without calling any more tools or emitting any tool tags, provide a concise, complete final answer summarizing everything you found, fixed, verified, and wrote to outbox.".to_string()
        } else {
            format!(
                "Tool execution stopped (step limit or loop-guard escape). Without calling any more tools or emitting any tool tags, summarize verified findings, exact blockers, and next steps.\n\n{capture}"
            )
        };
        messages.push(json!({
            "role": "user",
            "content": synth_msg
        }));
        let wire_synth_msgs = if venice_mode {
            prepare_messages_for_venice(&messages)
        } else {
            messages.clone()
        };
        let mut synth_payload = json!({
            "model": active_model,
            "messages": wire_synth_msgs,
            "max_tokens": active_max_tokens,
            "temperature": 0.3,
        });
        if venice_mode {
            synth_payload["venice_parameters"] = json!({
                "include_venice_system_prompt": false,
                "enable_web_search": "off",
                "enable_web_scraping": false
            });
        }
        let live_hook = on_progress.as_ref().map(|cb| (&mut progress, cb));
        if let Ok(v) = send_chat_completion(
            &client,
            provider,
            &synth_payload,
            &mut cancel,
            live_hook,
            venice_mode,
        )
        .await
        {
            if let Some(txt) = v
                .pointer("/choices/0/message/content")
                .and_then(Value::as_str)
                .map(strip_tool_call_markup)
                .filter(|s| !s.is_empty())
            {
                final_text = txt;
            }
        }
    }

    if final_text.trim().is_empty() && !stopped && !timed_out {
        let mut delivered = Vec::new();
        if let Some(ref odir) = expected_outbox_dir {
            if let Ok(rd) = std::fs::read_dir(odir) {
                for ent in rd.flatten() {
                    let name = ent.file_name();
                    let name_str = name.to_string_lossy();
                    if name_str.starts_with('.') {
                        continue;
                    }
                    if let Ok(meta) = ent.metadata() {
                        if meta.is_file() && meta.len() > 0 {
                            delivered.push(format!("`{}` ({} B)", ent.path().display(), meta.len()));
                        }
                    }
                }
            }
        }
        delivered.sort();
        if !delivered.is_empty() {
            if let Some(ref err_val) = api_error {
                let err_msg = err_val
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("upstream error");
                final_text = format!(
                    "Completed {} tool call(s) and wrote verified output file(s): {}.\n\n⚠️ *Note: the final commentary step hit a transient upstream error (`{}`), so the completed file(s) are delivered directly.*",
                    progress.tools.len(),
                    delivered.join(", "),
                    clip_chars(err_msg, 120)
                );
                api_error = None;
            } else {
                final_text = format!(
                    "Completed {} tool call(s). Delivered file(s): {}.",
                    progress.tools.len(),
                    delivered.join(", ")
                );
            }
        } else if api_error.is_none() && !progress.tools.is_empty() {
            final_text = format!("Completed {} tool call(s).", progress.tools.len());
        }
    }

    if !stopped && !final_text.trim().is_empty() && cfg.agent_mode && turn_state.is_dirty() {
        final_text.push_str("\n\n⚠️ *Note: files were modified without a subsequent verification run.*");
    }

    // Persist clean multi-turn history only on non-escaped success (avoid polluting future turns)
    if !stopped && !loop_guard.should_escape() && api_error.is_none() && !final_text.trim().is_empty() {
        if let Some(ref skey) = cfg.session_key {
            session.messages.push(json!({
                "role": "user",
                "content": clip_chars(user_prompt, MAX_STORED_MSG_CHARS)
            }));
            session.messages.push(json!({
                "role": "assistant",
                "content": clip_chars(&final_text, MAX_STORED_MSG_CHARS)
            }));
            prune_session_messages(&mut session.messages);
            session.updated_at = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            save_session(&cfg.state_dir, skey, &session);
        }
    }

    if timed_out && api_error.is_none() && final_text.is_empty() {
        api_error = Some(json!({
            "message": format!("Agent turn timed out after {}s.", cfg.job_timeout_secs)
        }));
    }

    Ok(JobResult {
        text: final_text,
        conversation_id: Some(format!("{}-{}", cfg.engine_id, session.session_id)),
        finished_reason: Some(if stopped {
            "stopped".to_string()
        } else if timed_out {
            "timeout".to_string()
        } else if api_error.is_some() {
            "error".to_string()
        } else {
            "stop".to_string()
        }),
        error: api_error,
        exit_code: Some(0),
        denied_actions: Vec::new(),
        usage: Some(total_usage),
        steps: progress.steps,
        stopped,
        timed_out,
        guard_tripped: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_cfg(dir: &TempDir, allow_root: bool, allow_sandbox: bool) -> AgentTurnConfig {
        AgentTurnConfig {
            engine_id: "test".to_string(),
            model: "test-model".to_string(),
            system_prompt: "test".to_string(),
            cwd: dir.path().to_path_buf(),
            workspace_root: dir.path().to_path_buf(),
            allow_root,
            allow_sandbox,
            agent_mode: true,
            mcp_config_path: dir.path().join("mcp.json"),
            skills_dir: dir.path().join("skills"),
            state_dir: dir.path().join("state"),
            session_key: Some("test_1".to_string()),
            max_steps: 4,
            max_tokens: 1024,
            job_timeout_secs: 60,
            proxy_url: None,
            three_stage_mode: ThreeStageMode::Off,
        }
    }

    #[tokio::test]
    async fn read_file_inverted_bounds_does_not_panic_and_patch_file_safety_works() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("demo.txt");
        std::fs::write(&file, "line1\nline2\nline2\nline3\n").unwrap();
        let cfg = test_cfg(&dir, false, false);
        let state = Arc::new(TurnRuntimeState::new());

        // Inverted bounds must not panic
        let out = execute_agent_tool_with_state(
            "read_file",
            &json!({"path": "demo.txt", "start_line": 50, "end_line": 10}),
            &cfg,
            &state,
        )
        .await;
        assert!(out.contains("demo.txt"));

        // Ambiguous >1 match MUST be refused unless replace_all=true
        let ambig = execute_agent_tool_with_state(
            "patch_file",
            &json!({"path": "demo.txt", "target": "line2", "replacement": "LINE_TWO"}),
            &cfg,
            &state,
        )
        .await;
        assert!(ambig.contains("matched 2 locations"), "got: {ambig}");

        // Explicit replace_all=true succeeds atomically
        let ok_all = execute_agent_tool_with_state(
            "patch_file",
            &json!({"path": "demo.txt", "target": "line2", "replacement": "LINE_TWO", "replace_all": true}),
            &cfg,
            &state,
        )
        .await;
        assert!(ok_all.contains("Replaced 2 occurrence"), "got: {ok_all}");
        assert_eq!(
            std::fs::read_to_string(&file).unwrap(),
            "line1\nLINE_TWO\nLINE_TWO\nline3\n"
        );

        // Unified diff patch works
        let diff_out = execute_agent_tool_with_state(
            "patch_file",
            &json!({
                "path": "demo.txt",
                "diff": "@@ -1,3 +1,3 @@\n line1\n-LINE_TWO\n+SECOND_LINE\n LINE_TWO\n"
            }),
            &cfg,
            &state,
        )
        .await;
        assert!(diff_out.contains("Applied 1 unified diff"), "got: {diff_out}");
        assert!(std::fs::read_to_string(&file).unwrap().contains("SECOND_LINE"));

        // External modification breaks read-baseline guard!
        std::fs::write(&file, "externally_changed_by_human\n").unwrap();
        let stale = execute_agent_tool_with_state(
            "write_file",
            &json!({"path": "demo.txt", "content": "clobber"}),
            &cfg,
            &state,
        )
        .await;
        assert!(stale.contains("stale baseline"), "got: {stale}");

        // Fast differential JSON syntax diagnostic catches newly introduced invalid JSON
        let jfile = dir.path().join("cfg.json");
        std::fs::write(&jfile, "{\"ok\": true}\n").unwrap();
        let bad_json = execute_agent_tool_with_state(
            "patch_file",
            &json!({"path": "cfg.json", "target": "true", "replacement": "true,"}),
            &cfg,
            &state,
        )
        .await;
        assert!(bad_json.contains("new syntax error"), "got: {bad_json}");
    }

    #[tokio::test]
    async fn non_root_without_sandbox_blocks_shell_while_sandbox_exec_runs_isolated() {
        let dir = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        let secret = outside.path().join("secret.txt");
        std::fs::write(&secret, "top-secret").unwrap();

        // Standard user (no root, no sandbox_exec) -> shell denied
        let std_cfg = test_cfg(&dir, false, false);
        let shell = execute_agent_tool("run_command", &json!({"command": "id"}), &std_cfg).await;
        assert!(shell.contains("Permission denied"));

        let read_out = execute_agent_tool(
            "read_file",
            &json!({"path": secret.to_string_lossy()}),
            &std_cfg,
        )
        .await;
        assert!(read_out.contains("Permission denied"));
        assert!(!read_out.contains("top-secret"));

        // Dev user (no root, sandbox_exec = true) -> runs safely inside bwrap sandbox, blocks sudo/bot.env
        let dev_cfg = test_cfg(&dir, false, true);
        let sb_ok = execute_agent_tool("run_command", &json!({"command": "echo SANDBOX_DEV_OK"}), &dev_cfg).await;
        assert!(sb_ok.contains("SANDBOX_DEV_OK"), "got: {sb_ok}");
        assert!(sb_ok.contains("[sandbox:bwrap]"), "got: {sb_ok}");

        let sb_denied = execute_agent_tool("run_command", &json!({"command": "sudo id"}), &dev_cfg).await;
        assert!(sb_denied.contains("CommandGuard DENIED"), "got: {sb_denied}");

        // Dev user can run execute_code over RPC inside sandbox and cannot escape workspace via RPC!
        let rpc_code = format!(
            "import agy_tools as t\nprint(t.write_file('note.txt', 'hello_rpc'))\nprint(t.read_file({:?}))\n",
            secret.to_string_lossy()
        );
        let rpc_out = execute_agent_tool("execute_code", &json!({"code": rpc_code}), &dev_cfg).await;
        assert!(rpc_out.contains("Successfully wrote"), "got: {rpc_out}");
        assert!(rpc_out.contains("Permission denied"), "RPC must enforce workspace confinement: {rpc_out}");
        assert!(!rpc_out.contains("top-secret"));
    }

    #[test]
    fn sse_accumulator_reassembles_text_and_streamed_tool_calls() {
        let mut acc = SseChatAccumulator::default();
        acc.ingest_data_line(r#"{"choices":[{"delta":{"content":"Hello "}}]}"#);
        acc.ingest_data_line(r#"{"choices":[{"delta":{"content":"world"}}]}"#);
        acc.ingest_data_line(r#"{"choices":[{"delta":{"tool_calls":[{"index":0,"id":"tc_1","function":{"name":"read_","arguments":"{\"path\":"}}]}}]}"#);
        acc.ingest_data_line(r#"{"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"name":"file","arguments":"\"a.rs\"}"}}]}}],"usage":{"prompt_tokens":10,"completion_tokens":5}}"#);
        let merged = acc.into_completion_json();
        assert_eq!(merged["choices"][0]["message"]["content"], "Hello world");
        assert_eq!(merged["usage"]["prompt_tokens"], 10);
        let calls = extract_tool_calls(&merged["choices"][0]["message"], "");
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "tc_1");
        assert_eq!(calls[0].1, "read_file");
        assert_eq!(calls[0].2["path"], "a.rs");
    }

    #[test]
    fn mid_turn_compaction_shrinks_old_tool_outputs_preserving_recent_four() {
        let big = "Z".repeat(5000);
        let mut msgs = vec![
            json!({"role": "system", "content": "sys"}),
            json!({"role": "user", "content": "go"}),
        ];
        for i in 0..7 {
            msgs.push(json!({"role": "tool", "tool_call_id": format!("c{i}"), "content": format!("T{i}_{big}")}));
        }
        let n = compact_in_turn_messages(&mut msgs, 22_000);
        assert!(n >= 2, "expected old tool messages to compact, got {n}");
        assert!(msgs[2]["content"].as_str().unwrap().contains("compacted older tool output"));
        // Last 4 tool messages (indices 5..=8) remain verbatim
        for msg in &msgs[5..=8] {
            assert!(!msg["content"].as_str().unwrap().contains("compacted older tool output"));
        }

        // Hysteresis check: once compacted down to 65% low-watermark, adding another small step
        // must NOT immediately trigger another compaction pass (preserves KV-cache prefix).
        let after_first: usize = msgs.iter().map(|m| m.to_string().len()).sum();
        assert!(
            after_first <= 22_000,
            "post-compaction total should be within budget, got {after_first}"
        );
        msgs.push(json!({"role": "tool", "tool_call_id": "c_next", "content": "ok small"}));
        let n2 = compact_in_turn_messages(&mut msgs, 22_000);
        assert_eq!(n2, 0, "hysteresis must avoid thrashing compaction on the next step");
    }

    #[test]
    fn loop_guard_blocks_third_identical_call_resets_on_edit_and_nudges_fail_streak() {
        let mut g = LoopGuard::default();
        let args = json!({"command": "cargo test"});
        assert!(g.check("run_command", &args).is_none());
        assert!(g.check("run_command", &args).is_none());
        let blocked = g.check("run_command", &args).expect("third identical call blocked");
        assert!(blocked.starts_with("[loop-guard]"));

        // A successful file edit changes state -> the same check may run again
        let _ = g.observe("patch_file", "Replaced 1 occurrence in a.rs".to_string());
        assert!(g.check("run_command", &args).is_none());

        // Polling a live session is never blocked
        let poll = json!({"action": "poll", "session_id": "b1"});
        for _ in 0..5 {
            assert!(g.check("process_manage", &poll).is_none());
        }

        // Failure streak nudges on the 4th consecutive failure, success resets
        let fail = "[host] Exit code: 101 (2.10s)\nSTDERR:\nerror[E0308]".to_string();
        for i in 1..=4 {
            let out = g.observe("run_command", fail.clone());
            assert_eq!(out.contains("consecutive failed tool calls"), i == 4, "iteration {i}");
        }
        let ok = g.observe("run_command", "[host] Exit code: 0 (0.5s)\n(no output)\n".to_string());
        assert!(!ok.contains("loop-guard"));
        assert!(!LoopGuard::is_failure("[host] Exit code: 0 (1.00s)"));
        assert!(LoopGuard::is_failure("CommandGuard DENIED (x): y"));
        assert!(AGENT_CORE_DISCIPLINE.contains("loop-escape"));
    }

    #[test]
    fn loop_guard_family_escape_and_dirty_state() {
        let mut g = LoopGuard::default();
        for i in 1..=3 {
            let args = json!({"path": "/tmp/app.py", "flag": i});
            let _ = g.observe_with_args("verify_project", &args, "[status: error] syntax error".to_string());
        }
        assert!(g.should_escape());
        assert!(g.failure_capture().contains("verify_project:/tmp/app.py"));

        let st = TurnRuntimeState::new();
        assert!(!st.is_dirty());
        st.record_file_mutated();
        assert!(st.is_dirty());
        st.clear_dirty();
        assert!(!st.is_dirty());

        // OpenHands pattern: alternating ping-pong (A -> B -> A -> B)
        let mut pg = LoopGuard::default();
        let a = json!({"path": "a.rs"});
        let b = json!({"path": "b.rs"});
        assert!(pg.check("read_file", &a).is_none());
        assert!(pg.check("read_file", &b).is_none());
        assert!(pg.check("read_file", &a).is_none());
        let ping_pong = pg.check("read_file", &b).expect("A-B-A-B oscillation must trigger");
        assert!(ping_pong.contains("Alternating ping-pong"));
        assert!(pg.should_escape());
    }

    #[test]
    fn extract_tool_calls_handles_string_object_and_xml() {
        let msg_obj = json!({
            "tool_calls": [
                {"id": "c1", "function": {"name": "read_file", "arguments": {"path": "a.rs"}}},
                {"id": "c2", "function": {"name": "list_dir", "arguments": "{\"path\":\".\"}"}}
            ]
        });
        let calls = extract_tool_calls(&msg_obj, "");
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].1, "read_file");
        assert_eq!(calls[0].2["path"], "a.rs");
        assert_eq!(calls[1].1, "list_dir");
        assert_eq!(calls[1].2["path"], ".");

        let xml_calls = extract_tool_calls(
            &json!({}),
            "Checking now.\n<tool_call>{\"name\":\"grep_files\",\"arguments\":{\"pattern\":\"foo\"}}</tool_call>",
        );
        assert_eq!(xml_calls.len(), 1);
        assert_eq!(xml_calls[0].1, "grep_files");
        assert_eq!(xml_calls[0].2["pattern"], "foo");
    }

    #[test]
    fn session_persistence_and_clear() {
        let dir = TempDir::new().unwrap();
        let state_dir = dir.path().join("state");
        let mut s = load_session(&state_dir, "uncensored_42");
        assert!(!s.session_id.is_empty());
        s.messages.push(json!({"role": "user", "content": "hi"}));
        save_session(&state_dir, "uncensored_42", &s);
        assert_eq!(session_message_count(&state_dir, "uncensored_42"), 1);
        assert!(clear_session_history(&state_dir, "uncensored_42"));
        assert_eq!(session_message_count(&state_dir, "uncensored_42"), 0);
    }

    #[test]
    fn retry_after_header_parser_clamps_bounds() {
        let mut hdrs = reqwest::header::HeaderMap::new();
        assert_eq!(parse_retry_after_secs(&hdrs), None);
        hdrs.insert(reqwest::header::RETRY_AFTER, "7".parse().unwrap());
        assert_eq!(parse_retry_after_secs(&hdrs), Some(7));
        hdrs.insert(reqwest::header::RETRY_AFTER, "0".parse().unwrap());
        assert_eq!(parse_retry_after_secs(&hdrs), Some(1));
        hdrs.insert(reqwest::header::RETRY_AFTER, "999".parse().unwrap());
        assert_eq!(parse_retry_after_secs(&hdrs), Some(45));
        hdrs.insert(reqwest::header::RETRY_AFTER, "not-a-number".parse().unwrap());
        assert_eq!(parse_retry_after_secs(&hdrs), None);
    }

    #[test]
    fn early_head_tail_tool_compaction_preserves_head_tail_and_utf8() {
        let small = "hello world";
        assert_eq!(compact_tool_output(small, 1024), small);

        let mut big = String::from("HEADER_LINE\n");
        for _ in 0..300 {
            big.push_str("متن فارسی طولانی برای تست فشرده‌سازی زودهنگام خروجی ابزار\n");
        }
        big.push_str("FINAL_ERROR_SUMMARY_42");
        let compacted = compact_tool_output(&big, 2000);
        assert!(compacted.len() < big.len());
        assert!(compacted.starts_with("HEADER_LINE"));
        assert!(compacted.ends_with("FINAL_ERROR_SUMMARY_42"));
        assert!(compacted.contains("early-compacted"));
    }

    #[test]
    fn sse_accumulator_tracks_reasoning_and_tool_call_progress() {
        let mut acc = SseChatAccumulator::default();
        assert_eq!(
            acc.ingest_data_line(r#"{"choices":[{"delta":{"reasoning_content":"Analyzing"}}]}"#),
            SseDeltaKind::Reasoning
        );
        assert_eq!(
            acc.ingest_data_line(
                r#"{"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call_1","function":{"name":"write_file","arguments":"{\"path\":\"a.py\","}}]}}]}"#
            ),
            SseDeltaKind::ToolCall
        );
        assert_eq!(
            acc.ingest_data_line(
                r#"{"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\"content\":\"print(1)\"}"}}]}}]}"#
            ),
            SseDeltaKind::ToolCall
        );
        assert_eq!(acc.active_tool_name(), Some("write_file"));
        assert!(acc.tool_args_bytes() > 20);
        let done = acc.into_completion_json();
        assert_eq!(
            done["choices"][0]["message"]["tool_calls"][0]["function"]["name"],
            "write_file"
        );
    }

    #[tokio::test]
    async fn openhands_file_editor_insert_undo_task_tracker_glob_symbols_and_rpc() {
        let dir = TempDir::new().unwrap();
        let cfg = test_cfg(&dir, true, true);
        let state = Arc::new(TurnRuntimeState::new());

        // 1. file_editor create -> view -> insert -> undo_edit
        let created = execute_agent_tool_with_state(
            "file_editor",
            &json!({"command": "create", "path": "src/app.rs", "file_text": "pub fn alpha() -> i32 {\n    1\n}\n"}),
            &cfg,
            &state,
        )
        .await;
        assert!(created.contains("Successfully wrote"), "got: {created}");

        let inserted = execute_agent_tool_with_state(
            "file_editor",
            &json!({"command": "insert", "path": "src/app.rs", "insert_line": 1, "new_str": "    // inserted comment"}),
            &cfg,
            &state,
        )
        .await;
        assert!(inserted.contains("Inserted after line 1"), "got: {inserted}");
        let view = execute_agent_tool_with_state(
            "file_editor",
            &json!({"command": "view", "path": "src/app.rs", "view_range": [1, 4]}),
            &cfg,
            &state,
        )
        .await;
        assert!(view.contains("// inserted comment"), "got: {view}");

        let undone = execute_agent_tool_with_state(
            "file_editor",
            &json!({"command": "undo_edit", "path": "src/app.rs"}),
            &cfg,
            &state,
        )
        .await;
        assert!(undone.contains("Undid last edit"), "got: {undone}");
        assert!(!std::fs::read_to_string(dir.path().join("src/app.rs")).unwrap().contains("inserted comment"));

        // 2. glob_files + find_symbols + grep_files(glob + context_lines)
        let gl = execute_agent_tool_with_state("glob_files", &json!({"pattern": "**/*.rs"}), &cfg, &state).await;
        assert!(gl.contains("src/app.rs"), "got: {gl}");

        let syms = execute_agent_tool_with_state("find_symbols", &json!({"query": "alpha"}), &cfg, &state).await;
        assert!(syms.contains("src/app.rs:1: pub fn alpha"), "got: {syms}");

        let gr = execute_agent_tool_with_state(
            "grep_files",
            &json!({"pattern": "1", "glob": "*.rs", "context_lines": 1}),
            &cfg,
            &state,
        )
        .await;
        assert!(gr.contains(">2:     1"), "got: {gr}");

        // 3. task_tracker plan + update
        let plan = execute_agent_tool_with_state(
            "task_tracker",
            &json!({
                "command": "plan",
                "task_list": [
                    {"id": "t1", "title": "Write alpha", "status": "done"},
                    {"id": "t2", "title": "Run tests", "status": "todo"}
                ]
            }),
            &cfg,
            &state,
        )
        .await;
        assert!(plan.contains("1/2 done"), "got: {plan}");

        // 4. execute_code RPC calling new OpenHands tools (glob_files + find_symbols + task_tracker)
        let rpc_code = r#"
import agy_tools as t
g = t.glob_files("**/*.rs")
s = t.find_symbols("alpha")
tr = t.task_tracker("update", id="t2", status="done")
print("OH_RPC_OK", "src/app.rs" in g, "alpha" in s, "2/2 done" in tr)
"#;
        let rpc_out = execute_agent_tool_with_state("execute_code", &json!({"code": rpc_code}), &cfg, &state).await;
        assert!(rpc_out.contains("OH_RPC_OK True True True"), "got: {rpc_out}");

        // 5. LoopGuard Patterns 3 (monologue) & 5 (context window error) + mark_resumed()
        let mut lg = LoopGuard::default();
        for i in 1..=4 {
            let res = lg.check("think", &json!({"thought": format!("step {i}")}));
            assert_eq!(res.is_some(), i == 4, "think {i}");
        }
        assert!(lg.should_escape());
        lg.mark_resumed();
        assert!(!lg.should_escape());
        assert!(!lg.record_context_error());
        assert!(lg.record_context_error());
        assert!(lg.should_escape());
    }

    #[test]
    fn parallel_safe_call_handles_readonly_subcommands_and_venice_cred_fallback() {
        assert!(is_parallel_safe_call("file_editor", &json!({"command": "view", "path": "a.rs"})));
        assert!(!is_parallel_safe_call("file_editor", &json!({"command": "str_replace", "path": "a.rs"})));
        assert!(is_parallel_safe_call("git_ops", &json!({"action": "status"})));
        assert!(is_parallel_safe_call("git_ops", &json!({"action": "diff"})));
        assert!(!is_parallel_safe_call("git_ops", &json!({"action": "checkpoint"})));
        assert!(is_parallel_safe_call("task_tracker", &json!({"command": "view"})));
        assert!(!is_parallel_safe_call("task_tracker", &json!({"command": "update"})));
        assert!(is_parallel_safe_call("process_manage", &json!({"action": "poll"})));
        assert!(!is_parallel_safe_call("process_manage", &json!({"action": "kill"})));
        assert!(is_parallel_safe_call("code_to_md", &json!({"path": "."})));
        assert!(!is_parallel_safe_call("code_to_md", &json!({"path": ".", "output_path": "out.md"})));
        assert!(is_parallel_safe_call("skillhub_catalog", &json!({})));
        assert!(is_parallel_safe_call("think", &json!({"thought": "plan"})));
        assert!(is_parallel_safe_call("batch_read", &json!({"files": ["a.rs"]})));
    }

    #[tokio::test]
    async fn batch_read_and_multi_edit_work_with_undo_rollback() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("a.py"), "x = 1\ny = 2\n").unwrap();
        std::fs::write(dir.path().join("b.py"), "z = 3\n").unwrap();
        let cfg = test_cfg(&dir, true, true);
        let state = Arc::new(TurnRuntimeState::new());

        let br = execute_agent_tool_with_state(
            "batch_read",
            &json!({"files": ["a.py", {"path": "b.py", "start_line": 1, "end_line": 1}]}),
            &cfg,
            &state,
        )
        .await;
        assert!(br.contains("1: x = 1"), "got: {br}");
        assert!(br.contains("1: z = 3"), "got: {br}");

        let me = execute_agent_tool_with_state(
            "multi_edit",
            &json!({
                "edits": [
                    {"path": "a.py", "target": "x = 1", "replacement": "x = 10"},
                    {"path": "b.py", "target": "z = 3", "replacement": "z = 30"}
                ]
            }),
            &cfg,
            &state,
        )
        .await;
        assert!(me.contains("2 succeeded, 0 failed"), "got: {me}");
        assert!(std::fs::read_to_string(dir.path().join("a.py")).unwrap().contains("x = 10"));
        assert!(std::fs::read_to_string(dir.path().join("b.py")).unwrap().contains("z = 30"));

        let undone = execute_agent_tool_with_state(
            "file_editor",
            &json!({"command": "undo_edit", "path": "a.py"}),
            &cfg,
            &state,
        )
        .await;
        assert!(undone.contains("Undid"), "got: {undone}");
        assert!(std::fs::read_to_string(dir.path().join("a.py")).unwrap().contains("x = 1\n"));
    }

    #[test]
    fn venice_multi_protocol_tool_extraction_and_markup_stripping() {
        // 1. Neutral <agy_call> + escape-free <agy_write>
        let raw_agy = r#"Checking file now.
<agy_call>{"name": "read_file", "arguments": {"path": "/tmp/a.py"}}</agy_call>
<agy_write path="/tmp/out/a.py">
def greet(name: str) -> str:
    return f"Hello, \"quoted\" {name}\n"
</agy_write>"#;
        let calls = extract_tool_calls(&json!({}), raw_agy);
        assert_eq!(calls.len(), 2, "got: {calls:?}");
        assert_eq!(calls[0].1, "read_file");
        assert_eq!(calls[0].2["path"], "/tmp/a.py");
        assert_eq!(calls[1].1, "write_file");
        assert_eq!(calls[1].2["path"], "/tmp/out/a.py");
        assert!(calls[1].2["content"].as_str().unwrap().contains(r#"\"quoted\""#));
        assert_eq!(strip_tool_call_markup(raw_agy), "Checking file now.");

        // 2. DeepSeek DSML XML fallback (exact bytes observed from veniceai/deepseek-v4-1-flash-1017-uncensored)
        let raw_dsml = "I'll read it.\n\n<｜DSML｜ calls>\n<｜DSML｜ invoke name=\"read_file\">\n<｜DSML｜ parameter name=\"path\" string=\"true\">/tmp/brainauth.php</｜DSML｜ parameter>\n<｜DSML｜ parameter name=\"start_line\" string=\"false\">10</｜DSML｜ parameter>\n</｜DSML｜ invoke>\n</｜DSML｜ calls>";
        let dsml_calls = extract_tool_calls(&json!({}), raw_dsml);
        assert_eq!(dsml_calls.len(), 1, "got: {dsml_calls:?}");
        assert_eq!(dsml_calls[0].1, "read_file");
        assert_eq!(dsml_calls[0].2["path"], "/tmp/brainauth.php");
        assert_eq!(dsml_calls[0].2["start_line"], 10);
        assert_eq!(strip_tool_call_markup(raw_dsml), "I'll read it.");

        // 3. DeepSeek collided closing tag on <tool_call>
        let raw_collided = "Reading.\n<tool_call>{\"name\": \"read_file\", \"arguments\": {\"path\": \"/tmp/x.py\"}}</｜DSML｜ parameter>\n</｜DSML｜ invoke>\n</｜DSML｜ calls>";
        let col_calls = extract_tool_calls(&json!({}), raw_collided);
        assert_eq!(col_calls.len(), 1, "got: {col_calls:?}");
        assert_eq!(col_calls[0].1, "read_file");
        assert_eq!(col_calls[0].2["path"], "/tmp/x.py");
        assert_eq!(strip_tool_call_markup(raw_collided), "Reading.");

        // 4. Raw unescaped newline inside JSON string literal repaired automatically
        let raw_multiline = "<agy_call>{\"name\": \"write_file\", \"arguments\": {\"path\": \"x.txt\", \"content\": \"line1\nline2\",}}</agy_call>";
        let rep_calls = extract_tool_calls(&json!({}), raw_multiline);
        assert_eq!(rep_calls.len(), 1, "got: {rep_calls:?}");
        assert_eq!(rep_calls[0].2["content"], "line1\nline2");

        // 5. Half-streamed opening tag suppressed from user-visible partial draft
        assert_eq!(
            strip_tool_call_markup("Working on it...\n<agy_call>{\"name\":\"read_"),
            "Working on it..."
        );
    }

    #[test]
    fn venice_message_sanitizer_and_sse_keepalive_error_guards() {
        let msgs = vec![
            json!({"role": "system", "content": "MAIN_SYS"}),
            json!({"role": "user", "content": "Analyze a.py"}),
            json!({"role": "assistant", "content": "", "tool_calls": [{"id": "c1", "function": {"name": "read_file", "arguments": "{\"path\":\"a.py\"}"}}]}),
            json!({"role": "tool", "tool_call_id": "c1", "name": "read_file", "content": "x = 1"}),
            json!({"role": "tool", "tool_call_id": "c2", "name": "read_file", "content": "y = 2"}),
            json!({"role": "system", "content": "CONDENSER_STATE"}),
        ];
        let clean = prepare_messages_for_venice(&msgs);
        assert_eq!(clean[0]["role"], "system");
        assert_eq!(clean[0]["content"], "MAIN_SYS");
        // Every assistant message MUST have non-empty content (prevents Venice HTTP 400!)
        for m in &clean {
            if m["role"] == "assistant" {
                assert!(!m["content"].as_str().unwrap().trim().is_empty());
                assert!(m.get("tool_calls").is_none());
            }
            assert_ne!(m["role"], "tool");
        }
        // Only ONE system message at index 0
        assert_eq!(clean.iter().filter(|m| m["role"] == "system").count(), 1);
        // Tool results & condenser merged into user turn
        let last_user = clean.last().unwrap()["content"].as_str().unwrap();
        assert!(last_user.contains("[Tool Result: read_file (c1)]"));
        assert!(last_user.contains("CONDENSER_STATE"));

        // SSE keepalive must NOT mark stream as having meaningful content
        let mut acc = SseChatAccumulator::default();
        acc.ingest_data_line(r#"{"id":"chatcmpl-keepalive","object":"chat.completion.chunk","created":0,"model":"keepalive","choices":[]}"#);
        assert!(!acc.saw_meaningful_delta);
        assert!(!acc.has_output());

        // In-stream error must be detected and reported
        assert_eq!(
            acc.ingest_data_line(r#"{"error":{"message":"upstream reset"}}"#),
            SseDeltaKind::Error
        );
        assert!(acc.in_stream_error.as_deref().unwrap().contains("upstream reset"));

        // Finish reason and [DONE] tracked cleanly
        let mut acc2 = SseChatAccumulator::default();
        acc2.ingest_data_line(r#"{"choices":[{"delta":{"content":"سلام"},"finish_reason":null}]}"#);
        acc2.ingest_data_line(r#"{"choices":[{"delta":{},"finish_reason":"length"}]}"#);
        acc2.ingest_data_line("[DONE]");
        assert!(acc2.has_output());
        assert!(acc2.is_cleanly_terminated());
        let done = acc2.into_completion_json();
        assert_eq!(done["choices"][0]["finish_reason"], "length");
        assert_eq!(done["choices"][0]["message"]["content"], "سلام");
    }

    #[test]
    fn degeneration_breaker_and_orphan_tag_sanitization() {
        // 1. Exact reproduction of 90+ orphan </agy_call> + trailing '<' leak from Telegram screenshot
        let leaked = format!(
            "Analyzing...\n</agy_call> {} \n<\n</agy_c",
            "</agy_call> ".repeat(95)
        );
        assert_eq!(strip_tool_call_markup(&leaked), "Analyzing...");

        // 2. 976x closing tags after 2 valid <agy_call> blocks -> circuit breaker preserves valid prefix
        let mut flood_close = String::from(
            r#"Checking files.
<agy_call>{"name": "read_file", "arguments": {"path": "a.php"}}</agy_call>
<agy_call>{"name": "list_dir", "arguments": {"path": "."}}</agy_call>
"#,
        );
        flood_close.push_str(&"</agy_call> ".repeat(974));
        let (cut_idx, reason) =
            detect_tool_stream_degeneration(&flood_close).expect("must detect orphan close loop");
        assert!(reason.contains("orphan"), "unexpected reason: {reason}");
        let sanitized = sanitize_degenerate_tool_response(&flood_close);
        let parsed = extract_tool_calls(&json!({}), &sanitized);
        assert_eq!(parsed.len(), 2, "must preserve both valid calls");
        assert!(cut_idx < flood_close.len());
        assert!(!sanitized.ends_with("</agy_call> </agy_call>"));

        // 3. Runaway 20x <agy_call> flood capped at MAX_TOOL_CALLS_PER_TURN (8)
        let mut many_calls = String::new();
        for i in 0..20 {
            many_calls.push_str(&format!(
                "<agy_call>{{\"name\": \"web_search\", \"arguments\": {{\"query\": \"q{i}\"}}}}</agy_call>\n"
            ));
        }
        assert!(detect_tool_stream_degeneration(&many_calls).is_some());
        let cap_calls = extract_tool_calls(&json!({}), &many_calls);
        assert_eq!(cap_calls.len(), MAX_TOOL_CALLS_PER_TURN);

        // 4. Repeated tail token loop (>= 6 repetitions outside <agy_write>)
        let tail_loop = format!("{}wait_next\n", "Summary prefix padding text. ".repeat(6))
            + &"wait_next ".repeat(10);
        assert!(detect_tool_stream_degeneration(&tail_loop).is_some());

        // 5. Document order sorting (<agy_call> -> <agy_write> -> <agy_call>), attribute-swapped <agy_write>, and bare JSON fallback
        let mixed = r#"<agy_call>{"name": "read_file", "arguments": {"path": "a.txt"}}</agy_call>
<agy_write append='false' path='/tmp/mid.txt'>
hello world
</agy_write>
<agy_call>{"name": "list_dir", "arguments": {"path": "/tmp"}}</agy_call>"#;
        let ordered = extract_tool_calls(&json!({}), mixed);
        assert_eq!(ordered.len(), 3, "got: {ordered:?}");
        assert_eq!(ordered[0].1, "read_file");
        assert_eq!(ordered[1].1, "write_file");
        assert_eq!(ordered[1].2["path"], "/tmp/mid.txt");
        assert_eq!(ordered[1].2["append"], false);
        assert_eq!(ordered[2].1, "list_dir");

        let bare_json = r#"{"name": "read_file", "arguments": {"path": "bare.php"}}"#;
        let bare_calls = extract_tool_calls(&json!({}), bare_json);
        assert_eq!(bare_calls.len(), 1);
        assert_eq!(bare_calls[0].1, "read_file");
        assert_eq!(bare_calls[0].2["path"], "bare.php");
    }

    #[test]
    fn coercion_helpers_and_outbox_delivery_helpers() {
        let a_str = json!({"paths": "[\"a.php\", \"b.php\"]", "view_range": "[1, 20]"});
        assert_eq!(arg_array(&a_str, "paths").unwrap().len(), 2);
        assert_eq!(arg_array(&a_str, "view_range").unwrap(), vec![json!(1), json!(20)]);

        let o_str = json!({"arguments": "{\"path\": \"src/\"}"});
        let obj = arg_object(&o_str, "arguments").unwrap();
        assert_eq!(obj["path"], "src/");

        let prompt = "Put any file you want delivered to the user in: /root/agy-workspace/outbox/1000000001/588809940/\nPlease improve the file and upload it.";
        let outbox = extract_outbox_dir(prompt).expect("outbox extracted");
        assert_eq!(outbox.to_string_lossy(), "/root/agy-workspace/outbox/1000000001/588809940");
        assert!(prompt_expects_file_delivery(prompt));

        let td = TempDir::new().unwrap();
        assert!(!dir_has_non_empty_files(td.path()));
        std::fs::write(td.path().join(".hidden"), "x").unwrap();
        assert!(!dir_has_non_empty_files(td.path()));
        std::fs::write(td.path().join("empty.txt"), "").unwrap();
        assert!(!dir_has_non_empty_files(td.path()));
        std::fs::write(td.path().join("fixed.php"), "<?php echo 1;\n").unwrap();
        assert!(dir_has_non_empty_files(td.path()));
    }

    #[tokio::test]
    async fn mock_sse_stream_breaker_and_outbox_delivery_guard() {
        use std::sync::Mutex;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let dir = TempDir::new().unwrap();
        let src_file = dir.path().join("sample.php");
        std::fs::write(&src_file, "<?php\nfunction demo() { return 1; }\n").unwrap();
        let outbox = dir.path().join("outbox").join("u1").join("m1");
        std::fs::create_dir_all(&outbox).unwrap();
        let out_file = outbox.join("sample_fixed.php");

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let captured_requests: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let captured_clone = Arc::clone(&captured_requests);
        let out_file_str = out_file.to_string_lossy().to_string();
        let src_file_str = src_file.to_string_lossy().to_string();

        let server_task = tokio::spawn(async move {
            for step in 0..3 {
                let (mut sock, _) = listener.accept().await.unwrap();
                let mut buf = Vec::new();
                let mut tmp = [0u8; 4096];
                loop {
                    let n = sock.read(&mut tmp).await.unwrap();
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                    let s = String::from_utf8_lossy(&buf);
                    if let Some(hdr_end) = s.find("\r\n\r\n") {
                        let cl = s[..hdr_end]
                            .lines()
                            .find_map(|l| {
                                let low = l.to_ascii_lowercase();
                                low.strip_prefix("content-length:")
                                    .and_then(|v| v.trim().parse::<usize>().ok())
                            })
                            .unwrap_or(0);
                        if buf.len() >= hdr_end + 4 + cl {
                            break;
                        }
                    }
                }
                let req_str = String::from_utf8_lossy(&buf).to_string();
                let body_str = req_str
                    .split_once("\r\n\r\n")
                    .map(|(_, b)| b.to_string())
                    .unwrap_or_default();
                captured_clone.lock().unwrap().push(body_str);

                let sse_chunks: Vec<String> = match step {
                    // Step 1: emits read_file followed by 40x runaway </agy_call> spam + trailing '<'
                    0 => {
                        let first = format!(
                            "Checking file.\n<agy_call>{{\"name\": \"read_file\", \"arguments\": {{\"path\": \"{}\"}}}}</agy_call>",
                            src_file_str.replace('\\', "\\\\")
                        );
                        let mut chunks = vec![first];
                        for _ in 0..40 {
                            chunks.push("</agy_call> ".to_string());
                        }
                        chunks.push("<".to_string());
                        chunks
                    }
                    // Step 2: tries to finish WITHOUT writing any file into outbox -> triggers Outbox Delivery Guard
                    1 => vec!["I analyzed sample.php and explained improvements.".to_string()],
                    // Step 3: writes improved file into outbox via <agy_write> then reports done cleanly
                    _ => vec![format!(
                        "<agy_write path=\"{}\">\n<?php\nfunction demo(): int {{ return 2; }}\n</agy_write>\nDone! Saved improved file.",
                        out_file_str
                    )],
                };

                let mut resp = String::from(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n",
                );
                for delta in sse_chunks {
                    let line = json!({
                        "choices": [{"delta": {"content": delta}, "finish_reason": null}]
                    });
                    resp.push_str(&format!("data: {}\n\n", line));
                }
                let end_line = json!({"choices": [{"delta": {}, "finish_reason": "stop"}]});
                resp.push_str(&format!("data: {}\n\ndata: [DONE]\n\n", end_line));
                sock.write_all(resp.as_bytes()).await.unwrap();
                let _ = sock.shutdown().await;
            }
        });

        let seen_partials: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let seen_clone = Arc::clone(&seen_partials);
        let progress_cb: ProgressCallback = Arc::new(move |p| {
            let sc = Arc::clone(&seen_clone);
            Box::pin(async move {
                sc.lock().unwrap().push(p.partial);
            })
        });

        let mut cfg = test_cfg(&dir, true, false);
        cfg.engine_id = "venice".to_string();
        cfg.model = "veniceai/deepseek-v4-1-flash-1017-uncensored".to_string();
        cfg.max_steps = 6;

        let provider = StaticBearerProvider {
            api_base: format!("http://{}/v1", addr),
            api_key: "test-key".to_string(),
            extra_headers: vec![],
        };
        let prompt = format!(
            "Put any file you want delivered to the user in: {}/\nUser attachments (local paths):\n- {}\nAnalyze and write improved file to outbox.",
            outbox.display(),
            src_file.display()
        );
        let (_tx, rx) = watch::channel(false);
        let res = run_openai_agent_turn(&provider, &cfg, &prompt, Some(progress_cb), rx)
            .await
            .expect("agent turn should succeed");
        server_task.await.unwrap();

        // 1. Outbox file MUST have been written via Outbox Delivery Guard rescue step
        assert!(out_file.is_file(), "expected improved file in outbox");
        let saved = std::fs::read_to_string(&out_file).unwrap();
        assert!(saved.contains("return 2;"));

        // 2. Final answer & streamed partials MUST NOT leak any </agy_call> or stray '<'
        assert!(!res.text.contains("</agy_call>"));
        for p in seen_partials.lock().unwrap().iter() {
            assert!(!p.contains("</agy_call>"), "leaked closing tag in partial: {p}");
        }

        // 3. Step 2 request assistant message must NOT contain 40x </agy_call> spam (canonical history pushed)
        let reqs = captured_requests.lock().unwrap();
        assert!(reqs.len() >= 3, "expected >=3 steps, got {}", reqs.len());
        let step2_json: Value = serde_json::from_str(&reqs[1]).unwrap();
        let step2_asst: Vec<&str> = step2_json["messages"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|m| m["role"] == "assistant")
            .filter_map(|m| m["content"].as_str())
            .collect();
        assert!(!step2_asst.is_empty(), "expected assistant message in step 2");
        for msg_txt in &step2_asst {
            assert!(
                msg_txt.matches("</agy_call>").count() <= 2,
                "step 2 assistant history polluted with spam closing tags: {msg_txt}"
            );
        }
    }

    #[tokio::test]
    async fn write_file_rejects_empty_content_and_web_search_failures_do_not_abort_loop_guard() {
        let dir = TempDir::new().unwrap();
        let cfg = test_cfg(&dir, false, false);
        let state = Arc::new(TurnRuntimeState::new());

        // Missing or whitespace-only content must NOT write a 0-byte file
        let err_missing = execute_agent_tool_with_state(
            "write_file",
            &json!({"path": "zero.py"}),
            &cfg,
            &state,
        )
        .await;
        assert!(err_missing.starts_with("Error:"), "got: {err_missing}");
        assert!(!dir.path().join("zero.py").exists());

        let err_blank = execute_agent_tool_with_state(
            "write_file",
            &json!({"path": "blank.py", "content": "   \n"}),
            &cfg,
            &state,
        )
        .await;
        assert!(err_blank.starts_with("Error:"), "got: {err_blank}");
        assert!(!dir.path().join("blank.py").exists());

        // Explicit allow_empty=true still succeeds when intentionally creating marker file
        let ok_empty = execute_agent_tool_with_state(
            "write_file",
            &json!({"path": ".keep", "content": "", "allow_empty": true}),
            &cfg,
            &state,
        )
        .await;
        assert!(ok_empty.starts_with("Successfully wrote"), "got: {ok_empty}");
        assert!(dir.path().join(".keep").is_file());

        // 4 consecutive web_search/fetch_url failures must NEVER set force_escape in LoopGuard
        let mut lg = LoopGuard::default();
        for i in 1..=4 {
            let out = lg.observe_with_args(
                if i % 2 == 0 { "fetch_url" } else { "web_search" },
                &json!({"query": format!("q{i}")}),
                "Error: HTTP 404 Not Found".to_string(),
            );
            assert!(!lg.should_escape(), "web failure #{i} must not abort coding task");
            if i >= 2 {
                assert!(out.contains("stop calling web_search/fetch_url"));
            }
        }
    }

    #[tokio::test]
    async fn transient_proxy_404_php_syntax_check_and_outbox_quality_guard() {
        // 1. Reverse-proxy plain-text "404 page not found" & HTML 404 are transient; JSON 404 is not
        assert!(is_transient_http_status(404, "404 page not found\n"));
        assert!(is_transient_http_status(404, "<html><body>404 Not Found</body></html>"));
        assert!(!is_transient_http_status(
            404,
            r#"{"error":{"message":"Unknown API route","code":"unknown_route"}}"#
        ));

        let dir = TempDir::new().unwrap();
        let src_php = dir.path().join("gateway.php");
        let mut big_src = String::from("<?php\nfunction bt_calc($a, $b) {\n    return $a + $b;\n}\n");
        for i in 0..120 {
            big_src.push_str(&format!("function helper_{i}($x) {{ return $x + {i}; }}\n"));
        }
        std::fs::write(&src_php, &big_src).unwrap();

        let prompt = format!(
            "Put any file you want delivered to the user in: {}/out/\nUser attachments (local paths):\n- {}\nFix gateway.php.",
            dir.path().display(),
            src_php.display()
        );
        let atts = extract_attachment_paths(&prompt);
        assert_eq!(atts, vec![src_php.clone()]);

        let out_dir = dir.path().join("out");
        std::fs::create_dir_all(&out_dir).unwrap();
        let out_php = out_dir.join("gateway_improved.php");

        // 2. Rename + comment-only copy MUST be rejected
        std::fs::write(&out_php, format!("// Added header comment\n/* Cosmetic change */\n{big_src}")).unwrap();
        let q_cosmetic = inspect_outbox_code_quality(&out_dir, &atts)
            .await
            .expect("comment-only copy must be rejected");
        assert!(q_cosmetic.contains("ZERO executable non-comment code changes"), "got: {q_cosmetic}");

        // 3. Lazy placeholder MUST be rejected
        std::fs::write(
            &out_php,
            "<?php\nfunction bt_calc($a, $b) { return $a - $b; }\n// ... rest of code unchanged\n",
        )
        .unwrap();
        let q_lazy = inspect_outbox_code_quality(&out_dir, &atts)
            .await
            .expect("lazy placeholder must be rejected");
        assert!(q_lazy.contains("lazy omission placeholder"), "got: {q_lazy}");

        // 4. Severe unexplained shrinkage (<60% executable lines without __call) MUST be rejected
        std::fs::write(&out_php, "<?php\nfunction bt_calc($a, $b) { return $a * $b; }\n").unwrap();
        let q_shrink = inspect_outbox_code_quality(&out_dir, &atts)
            .await
            .expect("severe method-drop shrinkage must be rejected");
        assert!(q_shrink.contains("shrank drastically"), "got: {q_shrink}");

        // 5. Broken PHP syntax MUST be caught when `php` is installed
        let broken = big_src.replace("return $a + $b;", "return $a + ;");
        std::fs::write(&out_php, &broken).unwrap();
        if std::path::Path::new("/usr/bin/php").exists() {
            let q_syn = inspect_outbox_code_quality(&out_dir, &atts)
                .await
                .expect("PHP syntax error must be caught");
            assert!(q_syn.contains("Syntax error"), "got: {q_syn}");
        }

        // 6. Genuine substantive fix preserving all helpers passes cleanly!
        let fixed = big_src.replace("return $a + $b;", "return ($a > 0 ? $a : 0) + ($b > 0 ? $b : 0);");
        std::fs::write(&out_php, &fixed).unwrap();
        assert!(
            inspect_outbox_code_quality(&out_dir, &atts).await.is_none(),
            "valid improved PHP must pass quality guard"
        );

        // 7. Dropping >= 2 top-level classes/functions MUST be rejected even if byte size >= 60%
        let mut pad_src = String::from("<?php\nclass WC_Order_Mapper {}\nfunction bt_dispatch($a) { return $a; }\n");
        let mut pad_dst = String::from("<?php\nclass New_Class {}\n");
        for i in 0..120 {
            pad_src.push_str(&format!("function pad_fn_{i}() {{ return {i}; }}\n"));
            pad_dst.push_str(&format!("function pad_fn_{i}() {{ return {}; }}\n", i + 1));
        }
        let core_src = dir.path().join("core_src.php");
        std::fs::write(&core_src, &pad_src).unwrap();
        std::fs::write(&out_php, &pad_dst).unwrap();
        let q_drop = inspect_outbox_code_quality(&out_dir, &[core_src])
            .await
            .expect("dropping top-level class & function must be rejected");
        assert!(q_drop.contains("WC_Order_Mapper") && q_drop.contains("bt_dispatch"), "got: {q_drop}");

        // 8. build_canonical_assistant_history must NEVER emit plain-text "[Calling tool ...]"
        let huge_args = json!({"command": "echo ".to_string() + &"x".repeat(900)});
        let hist = build_canonical_assistant_history(
            &json!({"role": "assistant", "content": ""}),
            "",
            &[("c1".into(), "run_command".into(), huge_args)],
        );
        let htxt = hist["content"].as_str().unwrap();
        assert!(!htxt.contains("[Calling tool"), "must not emit plain-text tool mimicry: {htxt}");
        assert!(htxt.contains("<agy_call>") && htxt.contains("</agy_call>"), "got: {htxt}");
    }

    #[tokio::test]
    async fn repo_map_diff_files_and_direct_xml_tool_parsing() {
        let dir = TempDir::new().unwrap();
        let src_dir = dir.path().join("src");
        std::fs::create_dir_all(&src_dir).unwrap();
        let a = src_dir.join("app.py");
        let b = src_dir.join("app_v2.py");
        std::fs::write(&a, "class Gateway:\n    def charge(self, x):\n        return x + 1\n").unwrap();
        std::fs::write(&b, "class Gateway:\n    def charge(self, x):\n        return x * 2\n").unwrap();

        let cfg = test_cfg(&dir, false, false);
        let state = Arc::new(TurnRuntimeState::new());

        // 1. repo_map maps Python class/def cleanly
        let rmap = execute_agent_tool_with_state("repo_map", &json!({"path": "."}), &cfg, &state).await;
        assert!(rmap.contains("app.py") && rmap.contains("class Gateway"), "got: {rmap}");

        // 2. diff_files computes unified diff + non-comment stats
        let diff = execute_agent_tool_with_state(
            "diff_files",
            &json!({"original_path": "src/app.py", "modified_path": "src/app_v2.py"}),
            &cfg,
            &state,
        )
        .await;
        assert!(diff.contains("-        return x + 1") && diff.contains("+        return x * 2"), "got: {diff}");
        assert!(!diff.contains("ZERO executable code changes"), "got: {diff}");

        // 3. Direct XML tool call (GLM-4.7-Heretic style, including '>' inside quoted code) parsed & stripped cleanly
        let glm_xml = r#"Running check.
<execute_code allow_network="false" code="print(2 > 1)" />"#;
        let calls = extract_tool_calls(&json!({}), glm_xml);
        assert_eq!(calls.len(), 1, "got: {calls:?}");
        assert_eq!(calls[0].1, "execute_code");
        assert_eq!(calls[0].2["allow_network"], false);
        assert_eq!(calls[0].2["code"], "print(2 > 1)");
        assert_eq!(strip_tool_call_markup(glm_xml), "Running check.");

        // 4. <function=name><parameter=k>v</parameter></function> parsed cleanly
        let fn_xml = "Checking.\n<function=read_file><parameter=path>src/app.py</parameter><parameter=start_line>1</parameter></function>";
        let fcalls = extract_tool_calls(&json!({}), fn_xml);
        assert_eq!(fcalls.len(), 1, "got: {fcalls:?}");
        assert_eq!(fcalls[0].1, "read_file");
        assert_eq!(fcalls[0].2["path"], "src/app.py");
        assert_eq!(fcalls[0].2["start_line"], 1);
        assert_eq!(strip_tool_call_markup(fn_xml), "Checking.");

        // 5. Prose mentioning unclosed `<read_file>` MUST NOT be truncated by strip_tool_call_markup
        let prose = "Use <read_file> or <execute_code> to inspect code, then deliver the final file.";
        assert_eq!(strip_tool_call_markup(prose), prose);

        // 6. multi_edit accepts old_str/new_str + file_path aliases, and batch_read accepts paths alias
        let bread = execute_agent_tool_with_state(
            "batch_read",
            &json!({"paths": [{"file_path": "src/app.py"}]}),
            &cfg,
            &state,
        )
        .await;
        assert!(bread.contains("class Gateway"), "got: {bread}");
        let medit = execute_agent_tool_with_state(
            "multi_edit",
            &json!({"edits": [{"file_path": "src/app.py", "old_str": "return x + 1", "new_str": "return x + 99"}]}),
            &cfg,
            &state,
        )
        .await;
        assert!(medit.contains("1 succeeded, 0 failed"), "got: {medit}");

        // 7. Binary file guard in read_file + NUL sanitization in prepare_messages_for_venice
        let bin_p = src_dir.join("archive.zip");
        std::fs::write(&bin_p, b"PK\x03\x04\x00\x00binary_payload").unwrap();
        let rbin = execute_agent_tool_with_state("read_file", &json!({"path": "src/archive.zip"}), &cfg, &state).await;
        assert!(rbin.contains("binary file") && rbin.contains("zipfile"), "got: {rbin}");
        let vmsgs = prepare_messages_for_venice(&[
            json!({"role": "user", "content": "hi\0there\x07\nline2"}),
            json!({"role": "user", "content": "   "}),
        ]);
        let vc = vmsgs[0]["content"].as_str().unwrap();
        assert!(!vc.contains('\0') && !vc.contains('\x07') && vc.contains("hithere\nline2"), "got: {vc:?}");
    }

    #[test]
    fn v5_stage1_schemas_agy_exec_413_and_silent_truncation() {
        // 1. Lossless tiered tool schemas preserve enums, nested array keys, agy_tools list, and drop redundant edit_file
        let tools = agent_tools_schema(true);
        let spec = build_prompt_tool_protocol_spec(&tools);
        assert!(spec.contains("view|create|str_replace|insert|undo_edit"), "missing file_editor enum");
        assert!(spec.contains("list|poll|wait|log|write|kill"), "missing process_manage enum");
        assert!(spec.contains("status|diff|log|branch|checkpoint|restore"), "missing git_ops enum");
        assert!(spec.contains("edits:[{") && spec.contains("target") && spec.contains("replacement"), "missing multi_edit nested schema: {spec}");
        assert!(spec.contains("files:[string|{") && spec.contains("start_line?"), "missing batch_read nested schema");
        assert!(spec.contains("<agy_exec>") && spec.contains("OVERRIDES WEB-CHAT LIMITS"));
        assert!(!spec.contains("- `edit_file("), "redundant edit_file should be omitted from prompt spec");

        // 2. <agy_exec> parsing, document ordering, stripping, and orphan breaker
        let exec_msg = "Inspecting.\n<agy_exec timeout_secs=\"45\" allow_network=\"false\">\nimport json\nprint(json.dumps({'ok': True}))\n</agy_exec>";
        let calls = extract_tool_calls(&json!({}), exec_msg);
        assert_eq!(calls.len(), 1, "got: {calls:?}");
        assert_eq!(calls[0].1, "execute_code");
        assert_eq!(calls[0].2["timeout_secs"], 45);
        assert_eq!(calls[0].2["allow_network"], false);
        assert!(calls[0].2["code"].as_str().unwrap().contains("json.dumps"));
        assert_eq!(strip_tool_call_markup(exec_msg), "Inspecting.");
        let orphan_exec = "<agy_exec>print(1)</agy_exec></agy_exec></agy_exec>";
        assert!(detect_tool_stream_degeneration(orphan_exec).is_some());

        // 3. Silent truncation detector (for Venice fake finish_reason="stop")
        assert_eq!(
            detect_silent_venice_truncation("<agy_write path=\"/tmp/a.py\">\ndef f():\n    return 1"),
            Some(SilentTruncation::UnclosedAgyWrite {
                path: "/tmp/a.py".to_string(),
                partial_bytes: 22,
            })
        );
        assert!(matches!(
            detect_silent_venice_truncation("<agy_exec>\nimport zipfile"),
            Some(SilentTruncation::UnclosedAgyExec { .. })
        ));
        assert_eq!(
            detect_silent_venice_truncation("<agy_call>{\"name\":\"read_file\",\"arg"),
            Some(SilentTruncation::UnclosedAgyCall)
        );
        assert_eq!(
            detect_silent_venice_truncation("Here is the fix:\n```python\ndef x():\n    return 1"),
            Some(SilentTruncation::UnclosedCodeFence)
        );
        assert_eq!(
            detect_silent_venice_truncation("Done!\n```python\nprint(1)\n```"),
            None
        );

        // 4. Strict user<->assistant alternation + 72 KiB per-message cap
        let big = "A".repeat(100_000);
        let strict = prepare_messages_for_venice(&[
            json!({"role": "system", "content": "sys"}),
            json!({"role": "assistant", "content": "orphan_a1"}),
            json!({"role": "assistant", "content": "orphan_a2"}),
            json!({"role": "user", "content": big}),
            json!({"role": "assistant", "content": "a_end"}),
        ]);
        let roles: Vec<&str> = strict.iter().map(|v| v["role"].as_str().unwrap()).collect();
        assert_eq!(roles, vec!["system", "user", "assistant", "user", "assistant", "user"]);
        assert!(strict[2]["content"].as_str().unwrap().contains("orphan_a1"));
        assert!(strict[2]["content"].as_str().unwrap().contains("orphan_a2"));
        assert!(strict[3]["content"].as_str().unwrap().len() <= VENICE_MAX_SINGLE_MSG_BYTES + 256);

        // 5. Emergency 413 Pass-2 compaction shrinks Step-1 oversized user payload
        let mut msgs = vec![
            json!({"role": "system", "content": "sys"}),
            json!({"role": "user", "content": "U".repeat(90_000)}),
        ];
        let n = compact_in_turn_messages(&mut msgs, 20_000);
        assert_eq!(n, 1);
        assert!(msgs[1]["content"].as_str().unwrap().len() < 10_000);
    }

    #[tokio::test]
    async fn v5_phase_ab_slots_and_three_stage_compaction() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let dir = TempDir::new().unwrap();
        let cfg = test_cfg(&dir, false, false);
        let state = Arc::new(TurnRuntimeState::new());

        // 1. Contract-first <agy_slot> auto-indent + assemble_slots (status / replace / finalize)
        let app_py = dir.path().join("app.py");
        let skel = "class App:\n    # <<<AGY_SLOT:routes>>>\n    # <<<AGY_SLOT:helper>>>\n";
        let w_out = execute_agent_tool_with_state(
            "write_file",
            &json!({ "path": "app.py", "content": skel }),
            &cfg,
            &state,
        )
        .await;
        assert!(
            w_out.contains("[open slots (2): routes, helper]") && !w_out.contains("syntax warning"),
            "got: {w_out}"
        );
        assert!(state.has_open_slots());

        let msg_chunk1 = "<agy_slot name=\"routes\" path=\"app.py\">\ndef ping(self):\n    return 'pong'\n</agy_slot>";
        let calls1 = extract_tool_calls(&json!({}), msg_chunk1);
        assert_eq!(calls1.len(), 1);
        assert_eq!(calls1[0].1, "assemble_slots");
        let r1 = execute_agent_tool_with_state(&calls1[0].1, &calls1[0].2, &cfg, &state).await;
        assert!(
            r1.contains("[remaining slots (1): helper]") && !r1.contains("syntax warning"),
            "got: {r1}"
        );

        // Omit path on chunk 2 -> uses active_slot_target automatically!
        let msg_chunk2 = "<agy_slot name=\"helper\">\ndef calc(self, x):\n    return x * 2\n</agy_slot>";
        let calls2 = extract_tool_calls(&json!({}), msg_chunk2);
        let r2 = execute_agent_tool_with_state(&calls2[0].1, &calls2[0].2, &cfg, &state).await;
        assert!(r2.contains("[ALL SLOTS COMPLETE]") && !r2.contains("syntax warning"), "got: {r2}");
        assert!(!state.has_open_slots());

        let fin = execute_agent_tool_with_state(
            "assemble_slots",
            &json!({ "command": "finalize", "path": "app.py" }),
            &cfg,
            &state,
        )
        .await;
        assert!(fin.contains("[ALL SLOTS ASSEMBLED & SYNTAX PASS]"), "got: {fin}");
        let assembled = std::fs::read_to_string(&app_py).unwrap();
        assert!(assembled.contains("    def ping(self):\n        return 'pong'"), "auto-indent failed:\n{assembled}");
        assert!(assembled.contains("    def calc(self, x):\n        return x * 2"), "auto-indent failed:\n{assembled}");

        // 2. Smart nearest-line hints when patch_file misses target
        let miss = execute_agent_tool_with_state(
            "patch_file",
            &json!({
                "path": "app.py",
                "target": "def ping(self):\n    return 'WRONG_LINE'",
                "replacement": "pass"
            }),
            &cfg,
            &state,
        )
        .await;
        assert!(miss.contains("target block not found") && miss.contains("def ping(self):"), "got: {miss}");

        // 3. Outbox guard rejects unreplaced <<<AGY_SLOT:...>>> markers & corrupt .zip files
        let bad_out = dir.path().join("bad_outbox");
        std::fs::create_dir_all(&bad_out).unwrap();
        std::fs::write(bad_out.join("leaky.py"), "class X:\n    # <<<AGY_SLOT:body>>>\n").unwrap();
        let q_slot = inspect_outbox_code_quality(&bad_out, &[]).await.unwrap();
        assert!(q_slot.contains("unfilled slot marker"), "got: {q_slot}");

        // 4. End-to-end 3-Stage + strategic-compact + SkillHub + Slot Guard mock Venice server
        let skill_dir = dir.path().join("skills").join("systematic-debugging");
        std::fs::create_dir_all(&skill_dir).unwrap();
        std::fs::write(
            skill_dir.join("SKILL.md"),
            "---\nname: systematic-debugging\n---\nAlways reproduce bug and verify fix with runtime tests.",
        )
        .unwrap();

        let src_zip = dir.path().join("repo.zip");
        let zip_py = format!(
            "import zipfile\nwith zipfile.ZipFile({:?}, 'w') as z:\n    z.writestr('pkg/__init__.py', '')\n    z.writestr('pkg/core.py', 'def add(a, b): return a - b\\n')\n    z.writestr('pkg/val.py', 'def ok(x): return True\\n')\n    z.writestr('pkg/main.py', 'from .core import add\\n')\n",
            src_zip
        );
        let zst = std::process::Command::new("python3")
            .arg("-c")
            .arg(&zip_py)
            .status()
            .unwrap();
        assert!(zst.success());

        let out_dir = dir.path().join("outbox");
        std::fs::create_dir_all(&out_dir).unwrap();
        let stage_dir_str = dir.path().join(".agy_stage").to_string_lossy().to_string();
        let service_py_str = out_dir.join("service.py").to_string_lossy().to_string();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let captured: Arc<std::sync::Mutex<Vec<Value>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
        let cap_c = Arc::clone(&captured);

        let srv = tokio::spawn(async move {
            for step_idx in 0..5 {
                let (mut sock, _) = listener.accept().await.unwrap();
                let mut buf = Vec::new();
                let mut tmp = [0u8; 4096];
                loop {
                    let n = sock.read(&mut tmp).await.unwrap();
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                    let s = String::from_utf8_lossy(&buf);
                    if let Some(hdr_end) = s.find("\r\n\r\n") {
                        let cl = s[..hdr_end]
                            .lines()
                            .find_map(|l| {
                                l.to_ascii_lowercase()
                                    .strip_prefix("content-length:")
                                    .and_then(|v| v.trim().parse::<usize>().ok())
                            })
                            .unwrap_or(0);
                        if buf.len() >= hdr_end + 4 + cl {
                            break;
                        }
                    }
                }
                let body = String::from_utf8_lossy(&buf)
                    .split_once("\r\n\r\n")
                    .map(|(_, b)| b.to_string())
                    .unwrap_or_default();
                let parsed: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
                cap_c.lock().unwrap().push(parsed);

                let reply = match step_idx {
                    // Stage 1: save memory & finish Stage 1
                    0 => format!(
                        "<agy_write path=\"{stage_dir_str}/01_memory.md\">\n# Memory\npkg/core.py has subtraction bug in add(a,b).\n</agy_write>\n\
<agy_call>{{\"name\":\"finish\",\"arguments\":{{\"message\":\"Stage 1 memory distilled\"}}}}</agy_call>"
                    ),
                    // Stage 2: lock chunk plan & finish Stage 2
                    1 => format!(
                        "<agy_write path=\"{stage_dir_str}/02_plan.md\">\nChunk 1: core; Chunk 2: validator -> {service_py_str}\n</agy_write>\n\
<agy_call>{{\"name\":\"finish\",\"arguments\":{{\"message\":\"Chunk plan ready\"}}}}</agy_call>"
                    ),
                    // Stage 3 Step 1: write skeleton + try premature finish (MUST be blocked by Slot Guard!)
                    2 => format!(
                        "<agy_write path=\"{service_py_str}\">\nclass CalcService:\n    # <<<AGY_SLOT:core>>>\n    # <<<AGY_SLOT:validator>>>\n</agy_write>\n\
<agy_call>{{\"name\":\"finish\",\"arguments\":{{\"message\":\"PREMATURE\"}}}}</agy_call>"
                    ),
                    // Stage 3 Step 2: fill core slot
                    3 => format!(
                        "<agy_slot name=\"core\" path=\"{service_py_str}\">\ndef add(self, a, b):\n    return a + b\n</agy_slot>"
                    ),
                    // Stage 3 Step 3: fill remaining validator slot (auto target!) + finish cleanly
                    _ => "<agy_slot name=\"validator\">\ndef ok(self, x):\n    return isinstance(x, (int, float))\n</agy_slot>\n\
<agy_call>{\"name\":\"finish\",\"arguments\":{\"message\":\"ALL_SLOTS_INTEGRATED_OK\"}}</agy_call>".to_string(),
                };

                let mut resp = String::from(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n",
                );
                let line = json!({ "choices": [{ "delta": { "content": reply }, "finish_reason": null }] });
                resp.push_str(&format!("data: {line}\n\n"));
                let end_line = json!({ "choices": [{ "delta": {}, "finish_reason": "stop" }] });
                resp.push_str(&format!("data: {end_line}\n\ndata: [DONE]\n\n"));
                sock.write_all(resp.as_bytes()).await.unwrap();
                let _ = sock.shutdown().await;
            }
        });

        let provider = StaticBearerProvider {
            api_base: format!("http://{addr}"),
            api_key: "test-key".to_string(),
            extra_headers: Vec::new(),
        };
        let mut run_cfg = test_cfg(&dir, false, false);
        run_cfg.engine_id = "uncensored".to_string();
        run_cfg.max_steps = 15;
        run_cfg.three_stage_mode = ThreeStageMode::Auto; // auto-triggers on 4-file zip!

        let prompt = format!(
            "Fix the bug in repo.zip and save to outbox FIX_BUG_UNIQUE_TOKEN_3STAGE\n\
User attachments (local paths):\n\
- `{}`\n\
Put any file you want delivered to the user in: {}/",
            src_zip.display(),
            out_dir.display()
        );
        let (_tx, rx) = watch::channel(false);
        let res = run_openai_agent_turn(&provider, &run_cfg, &prompt, None, rx)
            .await
            .unwrap();
        srv.await.unwrap();

        assert!(
            res.text.contains("ALL_SLOTS_INTEGRATED_OK"),
            "unexpected result text: {}",
            res.text
        );

        let reqs = captured.lock().unwrap();
        assert_eq!(reqs.len(), 5, "expected 5 stage calls, got {}", reqs.len());

        // Req 0 = Stage 1
        let r0_msgs = reqs[0]["messages"].as_array().unwrap();
        let r0_last = r0_msgs.last().unwrap()["content"].as_str().unwrap();
        assert!(r0_last.contains("[STAGE 1 / 3") && r0_last.contains("phase=stage1_memory"), "r0={r0_last}");

        // Req 1 = Stage 2 after strategic-compact (must only have 4 messages, no Stage-1 tool clutter!)
        let r1_msgs = reqs[1]["messages"].as_array().unwrap();
        assert_eq!(r1_msgs.len(), 4, "strategic-compact failed before Stage 2: len={}", r1_msgs.len());
        let r1_last = r1_msgs.last().unwrap()["content"].as_str().unwrap();
        assert!(r1_last.contains("[STAGE 2 / 3") && r1_last.contains("systematic-debugging") && r1_last.contains("phase=stage2_skills_plan"), "r1={r1_last}");

        // Req 2 = Stage 3 after strategic-compact, containing ORIGINAL prompt + phase=stage3_execute
        let r2_msgs = reqs[2]["messages"].as_array().unwrap();
        assert_eq!(r2_msgs.len(), 4, "strategic-compact failed before Stage 3: len={}", r2_msgs.len());
        let r2_last = r2_msgs.last().unwrap()["content"].as_str().unwrap();
        assert!(r2_last.contains("[STAGE 3 / 3") && r2_last.contains("FIX_BUG_UNIQUE_TOKEN_3STAGE") && r2_last.contains("phase=stage3_execute"), "r2={r2_last}");

        // Req 3 = Premature finish blocked by Slot Guard + wire HUD shows both open slots
        let r3_last = reqs[3]["messages"].as_array().unwrap().last().unwrap()["content"].as_str().unwrap();
        assert!(r3_last.contains("SLOT COMPLETENESS GUARD") && r3_last.contains("open_slots=service.py:[core,validator]"), "r3={r3_last}");

        // Req 4 = Wire HUD updated to remaining slot [validator]
        let r4_last = reqs[4]["messages"].as_array().unwrap().last().unwrap()["content"].as_str().unwrap();
        assert!(r4_last.contains("open_slots=service.py:[validator]"), "r4={r4_last}");

        // Verify disk artifacts & final assembled integrated output
        for f in ["00_repo_map.md", "01_memory.md", "02_skills_brief.md", "02_plan.md"] {
            assert!(dir.path().join(".agy_stage").join(f).is_file(), "missing .agy_stage/{f}");
        }
        let final_service = std::fs::read_to_string(out_dir.join("service.py")).unwrap();
        assert!(extract_slot_markers_from_text(&final_service).is_empty(), "leftover slots:\n{final_service}");
        assert!(final_service.contains("    def add(self, a, b):\n        return a + b"));
        assert!(final_service.contains("    def ok(self, x):\n        return isinstance(x, (int, float))"));
    }
}
