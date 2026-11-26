//! Multi-engine CLI runner abstraction, `agy --output-format stream-json` streaming parser,
//! and process-group supervision (`SIGINT -> SIGTERM -> SIGKILL`).

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::future::Future;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use agy_core::error::{BridgeError, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use tokio::io::{AsyncReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::watch;
use tracing::{info, warn};

use crate::mcp_client::{
    configure_new_session, push_tail_bytes, read_bounded_line, redact_secrets_in_text,
    signal_process_group, ProcessGroupGuard,
};

/// Default Antigravity CLI binary path.
pub const DEFAULT_AGY_BIN: &str = "/root/.local/bin/agy";
/// Default workspace working directory for engine runs.
pub const DEFAULT_WORKSPACE: &str = "/root/agy-workspace";

/// Hard upper bound for a single NDJSON stdout line (16 MiB).
const MAX_STDOUT_LINE_BYTES: usize = 16 * 1024 * 1024;
/// Hard upper bound for accumulated response/delta text in memory (4 MiB).
const MAX_COLLECTED_TEXT_BYTES: usize = 4 * 1024 * 1024;
/// Maximum number of non-JSON fallback stdout lines retained in the ring buffer.
const MAX_RAW_LINES: usize = 2048;
/// Maximum stderr bytes retained in the tail ring buffer (64 KiB).
const MAX_STDERR_BYTES: usize = 64 * 1024;
/// Maximum tool trace entries recorded per job.
const MAX_TRACE_ENTRIES: usize = 512;
/// Default maximum bytes captured by [`run_cmd`] for stdout/stderr (4 MiB).
const MAX_RUN_CMD_BYTES: usize = 4 * 1024 * 1024;

const TEXT_KEYS: &[&str] = &[
    "result",
    "response",
    "text",
    "final_text",
    "output",
    "content",
    "message",
];

const RESPONSE_STEP_TEXT_KEYS: &[&str] = &["text", "response", "content", "message", "output"];

const RESULT_EXCLUDED_KEYS: &[&str] = &["usage", "tool_info", "subagent_info", "denied_actions"];

/// Boxed `Send` future alias used by [`EngineRunner`].
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Async callback invoked whenever a streaming step updates [`Progress`].
pub type ProgressCallback =
    Arc<dyn Fn(Progress) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync>;

/// Supported CLI agent backends.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EngineKind {
    Agy,
    Custom {
        command: String,
        extra_args: Vec<String>,
    },
}

impl EngineKind {
    /// Parse an engine specification string (e.g. `""` or `"agy"` -> [`EngineKind::Agy`],
    /// or `"/usr/local/bin/claude --output-format stream-json"` -> [`EngineKind::Custom`]).
    pub fn from_spec(spec: &str) -> Result<Self> {
        let trimmed = spec.trim();
        if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("agy") {
            return Ok(Self::Agy);
        }
        let parts = shell_words::split(trimmed)
            .map_err(|e| BridgeError::Config(format!("invalid engine command spec: {e}")))?;
        let Some((first, rest)) = parts.split_first() else {
            return Ok(Self::Agy);
        };
        if first.is_empty() {
            return Err(BridgeError::Config(
                "engine command must not be empty".to_string(),
            ));
        }
        Ok(Self::Custom {
            command: first.clone(),
            extra_args: rest.to_vec(),
        })
    }
}

/// Live anti-loop and anti-burst guard limits applied to streaming `agy` / custom CLI runs.
/// Any field set to `0` disables that individual check.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgyGuardConfig {
    /// Maximum distinct tool calls permitted in a single turn (e.g. `60`).
    #[serde(default)]
    pub max_tool_steps: usize,
    /// Maximum consecutive identical tool calls (`tool_name` + primary target, e.g. `4`).
    #[serde(default)]
    pub tool_repeat_limit: usize,
    /// Maximum distinct tool calls within any sliding 60-second window (e.g. `45`).
    #[serde(default)]
    pub max_tools_per_min: usize,
}

impl AgyGuardConfig {
    pub fn is_enabled(&self) -> bool {
        self.max_tool_steps > 0 || self.tool_repeat_limit > 0 || self.max_tools_per_min > 0
    }
}

/// Parameters for launching an agent engine run.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EngineRequest {
    pub prompt: String,
    pub bin: Option<String>,
    pub cwd: Option<PathBuf>,
    pub model: Option<String>,
    pub effort: Option<String>,
    pub mode: Option<String>,
    pub conversation_id: Option<String>,
    pub skip_permissions: bool,
    pub timeout_secs: u64,
    pub agent: Option<String>,
    pub add_dirs: Vec<String>,
    /// Extra child environment (e.g. per-account `HOME`); `BOT_TOKEN` is always stripped.
    #[serde(default)]
    pub env_overrides: BTreeMap<String, String>,
    /// Grace added to `--print-timeout` for the bridge hard timeout (default 120 s or
    /// `AGY_HARD_TIMEOUT_GRACE_SECS`). Per request so tests need no global state.
    #[serde(default)]
    pub hard_grace_secs: Option<u64>,
    /// Extra agy flags; only entries in [`ALLOWED_EXTRA_FLAGS`] (and `--settings <json>`) are passed.
    #[serde(default)]
    pub extra_flags: Vec<String>,
    /// Phase 3 live anti-loop / anti-burst guard configuration for streaming `agy` execution.
    #[serde(default)]
    pub guard: AgyGuardConfig,
}

/// Flags a caller may add through [`EngineRequest::extra_flags`].
pub const ALLOWED_EXTRA_FLAGS: &[&str] = &["--sandbox", "--disable-slash-commands"];

/// Final outcome of an engine execution.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct JobResult {
    pub text: String,
    pub conversation_id: Option<String>,
    pub finished_reason: Option<String>,
    pub error: Option<Value>,
    pub exit_code: Option<i32>,
    pub denied_actions: Vec<Value>,
    pub usage: Option<Value>,
    pub stopped: bool,
    pub timed_out: bool,
    pub steps: usize,
    /// Set when [`AgyGuardConfig`] tripped and stopped the child cleanly (never an account fault).
    #[serde(default)]
    pub guard_tripped: Option<String>,
}

/// Live streaming progress snapshot emitted during execution.
#[derive(Debug, Clone)]
pub struct Progress {
    pub started: Instant,
    pub steps: usize,
    pub last_step: String,
    pub tools: Vec<String>,
    pub trace: Vec<(f64, String)>,
    pub partial: String,
    pub conversation_id: Option<String>,
}

impl Default for Progress {
    fn default() -> Self {
        Self {
            started: Instant::now(),
            steps: 0,
            last_step: String::new(),
            tools: Vec::new(),
            trace: Vec::new(),
            partial: String::new(),
            conversation_id: None,
        }
    }
}

/// Row parsed from `agy mcp list`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct McpListRow {
    pub name: String,
    #[serde(rename = "type")]
    pub server_type: String,
    pub status: String,
    pub cmd: String,
}

/// Model descriptor parsed from `agy models`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ModelInfo {
    pub id: String,
    pub name: String,
}

/// Pluggable interface for spawning and supervising an agent CLI engine.
pub trait EngineRunner: Send + Sync {
    fn kind(&self) -> &EngineKind;
    fn build_args(&self, req: &EngineRequest) -> Vec<String>;
    fn create_job(
        &self,
        req: &EngineRequest,
        on_progress: Option<ProgressCallback>,
    ) -> Arc<AgyProcessJob>;
    fn run(
        &self,
        req: EngineRequest,
        on_progress: Option<ProgressCallback>,
    ) -> BoxFuture<'static, Result<JobResult>>;
}

/// Standard Antigravity CLI runner (`agy --output-format stream-json`).
#[derive(Debug, Clone)]
pub struct AgyEngine {
    pub kind: EngineKind,
    pub default_bin: String,
    pub default_cwd: PathBuf,
}

impl AgyEngine {
    pub fn new(default_bin: Option<String>, default_cwd: Option<PathBuf>) -> Self {
        Self {
            kind: EngineKind::Agy,
            default_bin: default_bin
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(|| DEFAULT_AGY_BIN.to_string()),
            default_cwd: default_cwd.unwrap_or_else(|| PathBuf::from(DEFAULT_WORKSPACE)),
        }
    }
}

impl Default for AgyEngine {
    fn default() -> Self {
        Self::new(None, None)
    }
}

impl EngineRunner for AgyEngine {
    fn kind(&self) -> &EngineKind {
        &self.kind
    }

    fn build_args(&self, req: &EngineRequest) -> Vec<String> {
        let bin = req
            .bin
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or(&self.default_bin);
        build_agy_args(bin, req)
    }

    fn create_job(
        &self,
        req: &EngineRequest,
        on_progress: Option<ProgressCallback>,
    ) -> Arc<AgyProcessJob> {
        let args = self.build_args(req);
        let cwd = req.cwd.clone().unwrap_or_else(|| self.default_cwd.clone());
        Arc::new(
            AgyProcessJob::new(args, Some(cwd), on_progress)
                .with_env_overrides(req.env_overrides.clone().into_iter().collect())
                .with_hard_grace(req.hard_grace_secs)
                .with_guard(req.guard),
        )
    }

    fn run(
        &self,
        req: EngineRequest,
        on_progress: Option<ProgressCallback>,
    ) -> BoxFuture<'static, Result<JobResult>> {
        let job = self.create_job(&req, on_progress);
        Box::pin(async move { job.run().await })
    }
}

/// Pluggable custom CLI engine runner configured via `EngineKind::Custom`.
#[derive(Debug, Clone)]
pub struct CustomCliEngine {
    pub kind: EngineKind,
    pub default_cwd: PathBuf,
    pub pass_agy_flags: bool,
}

impl CustomCliEngine {
    pub fn new(command: String, extra_args: Vec<String>, default_cwd: Option<PathBuf>) -> Self {
        Self {
            kind: EngineKind::Custom {
                command,
                extra_args,
            },
            default_cwd: default_cwd.unwrap_or_else(|| PathBuf::from(DEFAULT_WORKSPACE)),
            pass_agy_flags: false,
        }
    }

    pub fn with_agy_flags(mut self, pass_agy_flags: bool) -> Self {
        self.pass_agy_flags = pass_agy_flags;
        self
    }
}

impl EngineRunner for CustomCliEngine {
    fn kind(&self) -> &EngineKind {
        &self.kind
    }

    fn build_args(&self, req: &EngineRequest) -> Vec<String> {
        match &self.kind {
            EngineKind::Agy => build_agy_args(
                req.bin.as_deref().unwrap_or(DEFAULT_AGY_BIN),
                req,
            ),
            EngineKind::Custom {
                command,
                extra_args,
            } => {
                let mut args = Vec::with_capacity(extra_args.len() + 16);
                let cmd = req
                    .bin
                    .as_deref()
                    .filter(|s| !s.trim().is_empty())
                    .unwrap_or(command);
                args.push(cmd.to_string());
                args.extend(extra_args.iter().cloned());
                if self.pass_agy_flags {
                    append_agy_option_flags(&mut args, req);
                }
                args.push("-p".to_string());
                args.push(req.prompt.clone());
                args
            }
        }
    }

    fn create_job(
        &self,
        req: &EngineRequest,
        on_progress: Option<ProgressCallback>,
    ) -> Arc<AgyProcessJob> {
        let args = self.build_args(req);
        let cwd = req.cwd.clone().unwrap_or_else(|| self.default_cwd.clone());
        Arc::new(
            AgyProcessJob::new(args, Some(cwd), on_progress)
                .with_env_overrides(req.env_overrides.clone().into_iter().collect())
                .with_hard_grace(req.hard_grace_secs)
                .with_guard(req.guard),
        )
    }

    fn run(
        &self,
        req: EngineRequest,
        on_progress: Option<ProgressCallback>,
    ) -> BoxFuture<'static, Result<JobResult>> {
        let job = self.create_job(&req, on_progress);
        Box::pin(async move { job.run().await })
    }
}

/// Construct an [`EngineRunner`] trait object for any [`EngineKind`].
pub fn build_runner(
    kind: EngineKind,
    default_bin: Option<String>,
    default_cwd: Option<PathBuf>,
) -> Arc<dyn EngineRunner> {
    match kind {
        EngineKind::Agy => Arc::new(AgyEngine::new(default_bin, default_cwd)),
        EngineKind::Custom {
            command,
            extra_args,
        } => Arc::new(CustomCliEngine::new(command, extra_args, default_cwd)),
    }
}

/// Build sanitized child environment for `agy` / custom engines (never leaks `BOT_TOKEN`).
/// `--print-timeout <N>s` plus 120 s of grace, if present.
fn hard_timeout_from_args(args: &[String], grace: Option<u64>) -> Option<Duration> {
    let i = args.iter().position(|a| a == "--print-timeout")?;
    let v = args.get(i + 1)?.trim_end_matches('s');
    let secs: u64 = v.parse().ok()?;
    let grace: u64 = grace
        .or_else(|| std::env::var("AGY_HARD_TIMEOUT_GRACE_SECS").ok().and_then(|v| v.parse().ok()))
        .unwrap_or(120);
    (secs > 0).then(|| Duration::from_secs(secs + grace))
}

/// True when an agy model id encodes its own effort level.
pub fn model_id_has_effort(id: &str) -> bool {
    let l = id.to_ascii_lowercase();
    ["-xhigh", "-high", "-medium", "-low", "-minimal", "-thinking", "-max"].iter().any(|s| l.ends_with(s))
}

pub fn agy_env() -> HashMap<String, String> {
    agy_env_from(std::env::vars().collect())
}

/// [`agy_env`] over an explicit variable map (pure; used by tests).
pub fn agy_env_from(vars: HashMap<String, String>) -> HashMap<String, String> {
    let mut env = vars;
    // Strip bridge secrets, dynamic-linker hooks, and systemd notify/watchdog sockets
    env.retain(|k, _| !crate::exec_backend::is_sensitive_env_key(k));
    let home = env
        .get("AGY_HOME")
        .filter(|s| !s.is_empty())
        .cloned()
        .unwrap_or_else(|| "/root".to_string());
    env.insert("HOME".to_string(), home);

    let existing_path = env.get("PATH").cloned().unwrap_or_default();
    let prefix = "/root/.local/bin:/usr/local/bin:/usr/bin:/bin";
    let new_path = if existing_path.is_empty() {
        prefix.to_string()
    } else {
        format!("{prefix}:{existing_path}")
    };
    env.insert("PATH".to_string(), new_path);
    env.entry("TERM".to_string())
        .or_insert_with(|| "dumb".to_string());
    env.insert("NO_COLOR".to_string(), "1".to_string());
    env
}

fn append_agy_option_flags(args: &mut Vec<String>, req: &EngineRequest) {
    if let Some(agent) = req.agent.as_deref().filter(|s| !s.is_empty()) {
        args.push("--agent".to_string());
        args.push(agent.to_string());
    }
    for d in &req.add_dirs {
        args.push("--add-dir".to_string());
        args.push(d.clone());
    }
    if let Some(model) = req.model.as_deref().filter(|s| !s.is_empty()) {
        args.push("--model".to_string());
        args.push(model.to_string());
    }
    // Model ids that already carry an effort (`…-high`, `…-medium`, `…-low`, `…-thinking`) must
    // not get a second, possibly conflicting `--effort`.
    let model_has_effort = req.model.as_deref().is_some_and(model_id_has_effort);
    if let Some(effort) = req.effort.as_deref().filter(|s| !s.is_empty() && !model_has_effort) {
        args.push("--effort".to_string());
        args.push(effort.to_string());
    }
    if let Some(mode) = req.mode.as_deref().filter(|s| !s.is_empty()) {
        args.push("--mode".to_string());
        args.push(mode.to_string());
    }
    if let Some(cid) = req.conversation_id.as_deref().filter(|s| !s.is_empty()) {
        args.push("--conversation".to_string());
        args.push(cid.to_string());
    }
    if req.skip_permissions {
        args.push("--dangerously-skip-permissions".to_string());
    }
    let mut it = req.extra_flags.iter();
    while let Some(f) = it.next() {
        if ALLOWED_EXTRA_FLAGS.contains(&f.as_str()) {
            args.push(f.clone());
        } else if f == "--settings" {
            if let Some(v) = it.next().filter(|v| v.trim_start().starts_with('{')) {
                args.push("--settings".to_string());
                args.push(v.clone());
            }
        }
    }
    if req.timeout_secs > 0 {
        args.push("--print-timeout".to_string());
        args.push(format!("{}s", req.timeout_secs));
    }
}

/// Build CLI arguments for `agy` matching Python `agy.build_args`.
pub fn build_agy_args(bin: &str, req: &EngineRequest) -> Vec<String> {
    let resolved_bin = req
        .bin
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or(bin);
    let mut args = vec![
        resolved_bin.to_string(),
        "--output-format".to_string(),
        "stream-json".to_string(),
    ];
    append_agy_option_flags(&mut args, req);
    args.push("-p".to_string());
    args.push(req.prompt.clone());
    args
}

/// Parse trailing `AGY_ERROR: {...}` line from stderr into structured JSON.
pub fn parse_agy_error(stderr_text: &str) -> Option<Value> {
    for line in stderr_text.lines().rev() {
        if let Some((_, rhs)) = line.split_once("AGY_ERROR:") {
            let raw = rhs.trim();
            if let Ok(parsed) = serde_json::from_str::<Value>(raw) {
                return Some(parsed);
            }
            let excerpt: String = raw.chars().take(2000).collect();
            return Some(json!({ "message": excerpt }));
        }
    }
    None
}

fn ansi_regex() -> Option<&'static Regex> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\x1b\[[0-9;]*[A-Za-z]").ok())
        .as_ref()
}

fn clean_tail(s: &str, max_chars: usize) -> String {
    let stripped = match ansi_regex() {
        Some(re) => re.replace_all(s, "").into_owned(),
        None => s.to_string(),
    };
    let trimmed = stripped.trim();
    let total = trimmed.chars().count();
    if total <= max_chars {
        return trimmed.to_string();
    }
    trimmed.chars().skip(total - max_chars).collect()
}

fn first_str(obj: &Value, keys: &[&str]) -> Option<String> {
    match obj {
        Value::String(s) => Some(s.clone()),
        Value::Object(map) => {
            for k in keys {
                if let Some(Value::String(s)) = map.get(*k) {
                    if !s.trim().is_empty() {
                        return Some(s.clone());
                    }
                }
            }
            for k in keys {
                if let Some(v) = map.get(*k) {
                    if v.is_object() || v.is_array() {
                        if let Some(s) = first_str(v, keys) {
                            if !s.is_empty() {
                                return Some(s);
                            }
                        }
                    }
                }
            }
            None
        }
        Value::Array(arr) => {
            let parts: Vec<String> = arr
                .iter()
                .filter_map(|x| first_str(x, keys).filter(|s| !s.is_empty()))
                .collect();
            if parts.is_empty() {
                None
            } else {
                Some(parts.join("\n"))
            }
        }
        _ => None,
    }
}

fn find_key<'a>(obj: &'a Value, key: &str, depth: usize) -> Option<&'a Value> {
    if depth > 4 {
        return None;
    }
    if let Value::Object(map) = obj {
        if let Some(v) = map.get(key) {
            if !v.is_null()
                && v != &Value::String(String::new())
                && v != &Value::Bool(false)
            {
                return Some(v);
            }
        }
        for v in map.values() {
            if let Some(found) = find_key(v, key, depth + 1) {
                return Some(found);
            }
        }
    }
    None
}

fn non_empty_str_val(v: Option<&Value>) -> Option<String> {
    match v {
        Some(Value::String(s)) if !s.is_empty() => Some(s.clone()),
        _ => None,
    }
}

fn value_as_label(v: Option<&Value>) -> Option<String> {
    match v {
        Some(Value::String(s)) if !s.is_empty() => Some(s.clone()),
        Some(Value::Number(n)) => Some(n.to_string()),
        Some(Value::Bool(true)) => Some("true".to_string()),
        _ => None,
    }
}

const TOOL_TARGET_KEYS: &[&str] = &[
    "CommandLine",
    "command",
    "cmd",
    "Path",
    "path",
    "file_path",
    "url",
    "Url",
    "query",
    "Query",
    "Target",
];

fn is_polling_tool(norm_tool: &str) -> bool {
    matches!(
        norm_tool,
        "manage_task" | "process_manage" | "schedule" | "wait" | "sleep"
    )
}

/// Read/edit coding tools commonly invoked in parallel batches across distinct files.
/// When `agy` omits arguments from `step_update` (empty target), these get 3x repeat headroom
/// so normal multi-file batch reads/edits never falsely trip the identical-loop guard.
fn is_batchable_file_tool(norm_tool: &str) -> bool {
    matches!(
        norm_tool,
        "read_file"
            | "edit_file"
            | "write_file"
            | "patch_file"
            | "view_file"
            | "list_dir"
            | "find_by_name"
            | "grep_search"
    )
}

fn extract_tool_target(ev_map: &Map<String, Value>) -> String {
    let containers: [Option<&Value>; 5] = [
        ev_map.get("tool_info"),
        ev_map.get("arguments"),
        ev_map.get("input"),
        ev_map.get("args"),
        None,
    ];
    for c in containers.into_iter().flatten() {
        if let Some(s) = first_str(c, TOOL_TARGET_KEYS) {
            return s.trim().chars().take(120).collect();
        }
    }
    for k in TOOL_TARGET_KEYS {
        if let Some(Value::String(s)) = ev_map.get(*k) {
            let t = s.trim();
            if !t.is_empty() {
                return t.chars().take(120).collect();
            }
        }
    }
    String::new()
}

#[derive(Default)]
struct AgyStreamGuard {
    cfg: AgyGuardConfig,
    seen_tool_steps: HashSet<String>,
    raw_events: usize,
    tool_calls: usize,
    last_tool_sig: Option<String>,
    last_tool_phase: Option<u8>,
    consecutive_repeats: usize,
    recent_tool_ts: VecDeque<Instant>,
    tripped_reason: Option<String>,
}

fn tool_status_phase(ev_map: &Map<String, Value>) -> Option<u8> {
    let raw = ev_map.get("status").and_then(Value::as_str)?;
    match raw.trim().to_ascii_uppercase().as_str() {
        "PENDING" | "QUEUED" => Some(1),
        "RUNNING" | "IN_PROGRESS" => Some(2),
        "DONE" | "COMPLETED" | "SUCCEEDED" | "SUCCESS" | "FAILED" | "ERROR" | "CANCELLED" => Some(3),
        _ => None,
    }
}

impl AgyStreamGuard {
    fn new(cfg: AgyGuardConfig) -> Self {
        Self {
            cfg,
            ..Default::default()
        }
    }

    fn observe_step(
        &mut self,
        ev_map: &Map<String, Value>,
        ev_val: &Value,
        tool: Option<&str>,
        has_delta: bool,
        now: Instant,
    ) -> Option<String> {
        if !self.cfg.is_enabled() {
            return None;
        }
        if self.tripped_reason.is_some() {
            return self.tripped_reason.clone();
        }

        self.raw_events = self.raw_events.saturating_add(1);
        if self.cfg.max_tool_steps > 0 {
            let max_raw = self.cfg.max_tool_steps.saturating_mul(60).max(1200);
            if self.raw_events > max_raw {
                let reason = format!(
                    "stream event flood guard triggered ({} events > {})",
                    self.raw_events, max_raw
                );
                self.tripped_reason = Some(reason.clone());
                return Some(reason);
            }
        }

        let tool_name = tool.map(str::trim).filter(|s| !s.is_empty())?;

        // Deduplicate repeated status emissions (PENDING -> RUNNING -> DONE) for the same step/call ID.
        let step_key = value_as_label(
            ev_map
                .get("tool_call_id")
                .or_else(|| ev_map.get("call_id"))
                .or_else(|| ev_map.get("step_index"))
                .or_else(|| find_key(ev_val, "tool_call_id", 0)),
        );
        let norm_name = tool_name.to_ascii_lowercase();
        let target = extract_tool_target(ev_map);
        let sig = if target.is_empty() {
            norm_name.clone()
        } else {
            format!("{norm_name}|{target}")
        };
        let phase = tool_status_phase(ev_map);
        if let Some(sk) = step_key {
            if !self.seen_tool_steps.insert(sk) {
                return None;
            }
            if self.seen_tool_steps.len() > 4096 {
                self.seen_tool_steps.clear();
            }
        } else if has_delta {
            return None;
        } else if self.last_tool_sig.as_deref() == Some(sig.as_str()) {
            // Even when `step_index`/`tool_call_id` is absent, a monotonic status progression
            // (PENDING -> RUNNING -> DONE) for the same tool+target is the same invocation.
            if let (Some(prev_p), Some(cur_p)) = (self.last_tool_phase, phase) {
                if cur_p > prev_p && prev_p < 3 {
                    self.last_tool_phase = Some(cur_p);
                    return None;
                }
            }
        }
        self.last_tool_phase = phase;

        self.tool_calls = self.tool_calls.saturating_add(1);
        while let Some(&front) = self.recent_tool_ts.front() {
            if now.saturating_duration_since(front) >= Duration::from_secs(60) {
                self.recent_tool_ts.pop_front();
            } else {
                break;
            }
        }
        self.recent_tool_ts.push_back(now);

        if self.last_tool_sig.as_deref() == Some(sig.as_str()) {
            self.consecutive_repeats = self.consecutive_repeats.saturating_add(1);
        } else {
            self.last_tool_sig = Some(sig);
            self.consecutive_repeats = 1;
        }

        if self.cfg.max_tool_steps > 0 && self.tool_calls > self.cfg.max_tool_steps {
            let reason = format!(
                "tool step limit reached ({} > {} calls/turn)",
                self.tool_calls, self.cfg.max_tool_steps
            );
            self.tripped_reason = Some(reason.clone());
            return Some(reason);
        }
        let effective_repeat_limit = if self.cfg.tool_repeat_limit == 0 {
            0
        } else if !target.is_empty() {
            // Exact target argument known (e.g. identical command/path): enforce strict repeat limit.
            self.cfg.tool_repeat_limit
        } else if is_batchable_file_tool(&norm_name) {
            // `agy` NDJSON omits arguments on batch read/edit tool steps: give 3x headroom (min 12)
            // so normal multi-file parallel reads/edits never falsely trip the identical-loop guard.
            self.cfg.tool_repeat_limit.saturating_mul(3).max(12)
        } else {
            self.cfg.tool_repeat_limit.saturating_mul(2).max(6)
        };
        if effective_repeat_limit > 0
            && !is_polling_tool(&norm_name)
            && self.consecutive_repeats > effective_repeat_limit
        {
            let reason = format!(
                "tool loop detected: `{tool_name}` repeated {}x consecutively (limit {effective_repeat_limit})",
                self.consecutive_repeats
            );
            self.tripped_reason = Some(reason.clone());
            return Some(reason);
        }
        if self.cfg.max_tools_per_min > 0 && self.recent_tool_ts.len() > self.cfg.max_tools_per_min {
            let reason = format!(
                "tool burst rate exceeded ({} calls/60s > limit {})",
                self.recent_tool_ts.len(),
                self.cfg.max_tools_per_min
            );
            self.tripped_reason = Some(reason.clone());
            return Some(reason);
        }

        None
    }
}

#[derive(Default)]
struct StreamAccumulator {
    raw_lines: VecDeque<String>,
    raw_lines_bytes: usize,
    deltas: String,
    responses: BTreeMap<String, String>,
    result: JobResult,
    guard: AgyStreamGuard,
}

impl StreamAccumulator {
    fn push_raw_line(&mut self, line: &str) {
        if line.len() > MAX_COLLECTED_TEXT_BYTES {
            return;
        }
        while self.raw_lines.len() >= MAX_RAW_LINES
            || self.raw_lines_bytes + line.len() > MAX_COLLECTED_TEXT_BYTES
        {
            if let Some(old) = self.raw_lines.pop_front() {
                self.raw_lines_bytes = self.raw_lines_bytes.saturating_sub(old.len());
            } else {
                break;
            }
        }
        self.raw_lines_bytes += line.len();
        self.raw_lines.push_back(line.to_string());
    }

    fn push_delta(&mut self, delta: &str) {
        let remaining = MAX_COLLECTED_TEXT_BYTES.saturating_sub(self.deltas.len());
        if remaining == 0 {
            return;
        }
        if delta.len() <= remaining {
            self.deltas.push_str(delta);
        } else {
            let mut end = remaining;
            while end > 0 && !delta.is_char_boundary(end) {
                end -= 1;
            }
            self.deltas.push_str(&delta[..end]);
        }
    }

    fn rebuild_responses_partial(&self) -> String {
        let mut out = String::new();
        for (idx, txt) in self.responses.values().enumerate() {
            let sep = if idx == 0 { "" } else { "\n\n" };
            let needed = sep.len() + txt.len();
            if out.len() + needed <= MAX_COLLECTED_TEXT_BYTES {
                out.push_str(sep);
                out.push_str(txt);
            } else {
                break;
            }
        }
        out
    }
}

/// Clonable handle for cancelling an in-flight [`AgyProcessJob`] from another task.
#[derive(Clone)]
pub struct JobStopHandle {
    inner: Arc<JobControl>,
}

impl JobStopHandle {
    /// Interrupt -> terminate -> kill the entire child process group (`-pgid`).
    pub async fn stop(&self) {
        self.inner.stop().await;
    }
}

struct JobControl {
    pgid: Mutex<Option<libc::pid_t>>,
    stopping: AtomicBool,
    exited_tx: watch::Sender<bool>,
    exited_rx: watch::Receiver<bool>,
    sigint_wait: Duration,
    sigterm_wait: Duration,
    sigkill_wait: Duration,
}

impl JobControl {
    fn new(sigint_wait: Duration, sigterm_wait: Duration, sigkill_wait: Duration) -> Self {
        let (exited_tx, exited_rx) = watch::channel(false);
        Self {
            pgid: Mutex::new(None),
            stopping: AtomicBool::new(false),
            exited_tx,
            exited_rx,
            sigint_wait,
            sigterm_wait,
            sigkill_wait,
        }
    }

    async fn stop(&self) {
        self.stopping.store(true, Ordering::SeqCst);
        let mut rx = self.exited_rx.clone();
        if *rx.borrow() {
            return;
        }

        let signals = [
            (libc::SIGINT, self.sigint_wait),
            (libc::SIGTERM, self.sigterm_wait),
            (libc::SIGKILL, self.sigkill_wait),
        ];

        for (sig, wait_dur) in signals {
            if *rx.borrow() {
                return;
            }
            let pid = {
                let guard = self.pgid.lock().unwrap_or_else(|e| e.into_inner());
                *guard
            };
            let Some(pgid) = pid else {
                return;
            };
            if !signal_process_group(pgid, sig) {
                return;
            }
            if tokio::time::timeout(wait_dur, rx.wait_for(|&done| done))
                .await
                .is_ok()
            {
                return;
            }
        }
    }
}

/// Supervised streaming process job for `agy` or custom NDJSON engines.
pub struct AgyProcessJob {
    args: Vec<String>,
    cwd: PathBuf,
    on_progress: Option<ProgressCallback>,
    env_overrides: HashMap<String, String>,
    hard_grace_secs: Option<u64>,
    guard: AgyGuardConfig,
    progress: Mutex<Progress>,
    control: Arc<JobControl>,
}

impl AgyProcessJob {
    /// Create a new streaming job for `args` running in `cwd` (defaults to [`DEFAULT_WORKSPACE`]).
    pub fn new(
        args: Vec<String>,
        cwd: Option<PathBuf>,
        on_progress: Option<ProgressCallback>,
    ) -> Self {
        Self {
            args,
            cwd: cwd.unwrap_or_else(|| PathBuf::from(DEFAULT_WORKSPACE)),
            on_progress,
            env_overrides: HashMap::new(),
            hard_grace_secs: None,
            guard: AgyGuardConfig::default(),
            progress: Mutex::new(Progress::default()),
            control: Arc::new(JobControl::new(
                Duration::from_secs(6),
                Duration::from_secs(5),
                Duration::from_secs(3),
            )),
        }
    }

    /// Supply extra environment overrides (note: `BOT_TOKEN` is always stripped).
    pub fn with_env_overrides(mut self, overrides: HashMap<String, String>) -> Self {
        self.env_overrides = overrides;
        self
    }

    /// Override the grace period of the bridge hard timeout.
    pub fn with_hard_grace(mut self, secs: Option<u64>) -> Self {
        self.hard_grace_secs = secs;
        self
    }

    /// Attach Phase 3 live anti-loop and anti-burst guard limits to this streaming job.
    pub fn with_guard(mut self, guard: AgyGuardConfig) -> Self {
        self.guard = guard;
        self
    }

    /// Customize `SIGINT -> SIGTERM -> SIGKILL` escalation wait windows (primarily for testing).
    pub fn with_stop_timeouts(
        mut self,
        sigint_wait: Duration,
        sigterm_wait: Duration,
        sigkill_wait: Duration,
    ) -> Self {
        self.control = Arc::new(JobControl::new(sigint_wait, sigterm_wait, sigkill_wait));
        self
    }

    /// Return a clonable cancellation handle that can stop the running process group.
    pub fn stop_handle(&self) -> JobStopHandle {
        JobStopHandle {
            inner: Arc::clone(&self.control),
        }
    }

    /// Return a thread-safe snapshot of current streaming progress.
    pub fn progress_snapshot(&self) -> Progress {
        self.progress
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Interrupt -> terminate -> kill the entire child process group (`-pgid`).
    pub async fn stop(&self) {
        self.control.stop().await;
    }

    /// Spawn the subprocess in its own session (`setsid`), stream NDJSON stdout, capture bounded
    /// stderr, and return the parsed [`JobResult`].
    pub async fn run(&self) -> Result<JobResult> {
        let Some((program, rest_args)) = self.args.split_first() else {
            return Err(BridgeError::Validation(
                "Engine command args must not be empty".to_string(),
            ));
        };

        if self.control.stopping.load(Ordering::SeqCst) {
            let _ = self.control.exited_tx.send(true);
            return Ok(JobResult {
                stopped: true,
                ..Default::default()
            });
        }

        let flags_summary: Vec<&str> = rest_args
            .iter()
            .map(String::as_str)
            .filter(|a| a.starts_with("--"))
            .collect();
        info!(flags = %flags_summary.join(" "), "agy job start");

        let mut env = agy_env();
        for (k, v) in &self.env_overrides {
            if k != "BOT_TOKEN" {
                env.insert(k.clone(), v.clone());
            }
        }

        let mut cmd = Command::new(program);
        cmd.args(rest_args)
            .current_dir(&self.cwd)
            .env_clear()
            .envs(env)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        configure_new_session(&mut cmd);

        let mut child = cmd
            .spawn()
            .map_err(|e| BridgeError::Process(program.clone(), format!("failed to spawn: {e}")))?;

        let mut pg_guard = ProcessGroupGuard::new(child.id());
        {
            let mut lock = self.control.pgid.lock().unwrap_or_else(|e| e.into_inner());
            *lock = pg_guard.pgid();
        }

        // Handle stop() racing during spawn() with full SIGINT -> SIGTERM -> SIGKILL escalation.
        if self.control.stopping.load(Ordering::SeqCst) {
            let ctrl = Arc::clone(&self.control);
            tokio::spawn(async move {
                ctrl.stop().await;
            });
        }

        let stdout = child.stdout.take().ok_or_else(|| {
            BridgeError::Process(program.clone(), "stdout pipe unavailable".to_string())
        })?;
        let stderr = child.stderr.take().ok_or_else(|| {
            BridgeError::Process(program.clone(), "stderr pipe unavailable".to_string())
        })?;

        let stderr_task = tokio::spawn(async move {
            let mut reader = stderr;
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                match reader.read(&mut chunk).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => push_tail_bytes(&mut buf, &chunk[..n], MAX_STDERR_BYTES),
                }
            }
            buf
        });

        let mut acc = StreamAccumulator {
            guard: AgyStreamGuard::new(self.guard),
            ..Default::default()
        };
        let mut reader = BufReader::new(stdout);
        let mut line_buf = Vec::new();

        // Bridge-side hard limit: agy's own --print-timeout plus a grace period. Protects the
        // queue when agy (or a grandchild holding stdout) never closes the pipe.
        let hard_limit = hard_timeout_from_args(rest_args, self.hard_grace_secs);
        let read_all = async {
        loop {
            let read_res =
                read_bounded_line(&mut reader, &mut line_buf, MAX_STDOUT_LINE_BYTES).await;
            match read_res {
                Ok((0, _)) => break,
                Ok((_, truncated)) => {
                    if truncated {
                        warn!("truncated oversized NDJSON stdout line (>16 MiB)");
                        continue;
                    }
                    let raw = String::from_utf8_lossy(&line_buf);
                    let line = raw.trim_end_matches(&['\r', '\n'][..]);
                    if line.trim().is_empty() {
                        continue;
                    }
                    if self.handle_line(line, &mut acc).await {
                        break;
                    }
                }
                Err(e) => {
                    warn!(error = %e, "error reading engine stdout");
                    break;
                }
            }
        }
        };
        let mut hard_timed_out = false;
        match hard_limit {
            Some(d) => {
                if tokio::time::timeout(d, read_all).await.is_err() {
                    hard_timed_out = true;
                    warn!(secs = d.as_secs(), "agy exceeded the bridge hard timeout; killing its process group");
                    if let Some(pgid) = pg_guard.pgid() {
                        signal_process_group(pgid, libc::SIGKILL);
                    }
                }
            }
            None => read_all.await,
        }

        if let Some(ref reason) = acc.guard.tripped_reason {
            warn!(reason = %reason, "agy live stream guard tripped; stopping process group cleanly");
            self.control.stop().await;
        }

        let status = match tokio::time::timeout(Duration::from_secs(30), child.wait()).await {
            Ok(r) => r,
            Err(_) => {
                warn!("agy closed stdout but did not exit; killing its process group");
                if let Some(pgid) = pg_guard.pgid() {
                    signal_process_group(pgid, libc::SIGKILL);
                }
                child.wait().await
            }
        }
        .map_err(|e| BridgeError::Process(program.clone(), format!("wait failed: {e}")))?;
        pg_guard.disarm();
        {
            let mut lock = self.control.pgid.lock().unwrap_or_else(|e| e.into_inner());
            *lock = None;
        }
        let _ = self.control.exited_tx.send(true);

        let stderr_bytes = stderr_task.await.unwrap_or_default();
        let stderr_text = String::from_utf8_lossy(&stderr_bytes);

        let rc = status
            .code()
            .or_else(|| status.signal().map(|sig| -sig));
        let stopped = self.control.stopping.load(Ordering::SeqCst);
        let guard_reason = acc.guard.tripped_reason.clone();

        let prog_snapshot = self.progress_snapshot();
        let mut r = acc.result;
        r.exit_code = rc;
        r.stopped = stopped && guard_reason.is_none();
        r.guard_tripped = guard_reason.clone();
        if guard_reason.is_some() {
            r.finished_reason = Some("guard_tripped".to_string());
        }
        r.steps = prog_snapshot.steps;
        if r.conversation_id.is_none() {
            r.conversation_id = prog_snapshot.conversation_id;
        }
        if r.text.is_empty() {
            let delta_trim = acc.deltas.trim();
            if !delta_trim.is_empty() {
                r.text = delta_trim.to_string();
            } else {
                let partial_trim = prog_snapshot.partial.trim();
                if !partial_trim.is_empty() {
                    r.text = partial_trim.to_string();
                } else if rc == Some(0) {
                    // Raw non-JSON stdout is an answer only for a clean exit; on a crash it is
                    // diagnostic noise and goes into the error instead.
                    let joined: Vec<&str> = acc.raw_lines.iter().map(String::as_str).collect();
                    r.text = joined.join("\n").trim().to_string();
                }
            }
        }

        if hard_timed_out && !stopped {
            r.timed_out = true;
            if r.error.is_none() {
                r.error = Some(json!({ "message": "agy did not finish within the bridge hard timeout and was stopped" }));
            }
        }
        if rc != Some(0) && !stopped {
            if r.error.is_none() {
                let raw_out: String = if r.text.is_empty() { acc.raw_lines.iter().map(String::as_str).collect::<Vec<_>>().join("\n") } else { String::new() };
                let combined = format!("{stderr_text}\n{raw_out}");
                let stderr_text = combined.as_str();
                r.error = parse_agy_error(stderr_text).or_else(|| {
                    let tail = redact_secrets_in_text(&clean_tail(stderr_text, 1500));
                    let msg = if tail.is_empty() {
                        format!("agy exited with code {}", rc.unwrap_or(-1))
                    } else {
                        tail
                    };
                    Some(json!({ "message": msg }))
                });
            }
        } else if rc == Some(0) && r.text.is_empty() && !stopped {
            // A clean exit with no answer at all is a failure, not an empty success.
            r.error = parse_agy_error(&stderr_text).or_else(|| {
                let tail = redact_secrets_in_text(&clean_tail(&stderr_text, 600));
                Some(json!({ "message": if tail.is_empty() { "agy exited without an answer (empty output)".to_string() } else { format!("agy exited without an answer: {tail}") } }))
            });
        }

        if r.finished_reason.as_deref() == Some("print_timeout") {
            r.timed_out = true;
        }

        info!(
            rc = ?r.exit_code,
            steps = r.steps,
            reason = ?r.finished_reason,
            err = r.error.is_some(),
            "agy job end"
        );
        Ok(r)
    }

    async fn handle_line(&self, line: &str, acc: &mut StreamAccumulator) -> bool {
        let Ok(parsed) = serde_json::from_str::<Value>(line) else {
            acc.push_raw_line(line);
            return false;
        };
        let Some(orig_map) = parsed.as_object() else {
            return false;
        };

        let et = orig_map
            .get("type")
            .or_else(|| orig_map.get("event"))
            .and_then(|v| match v {
                Value::String(s) => Some(s.clone()),
                Value::Number(n) => Some(n.to_string()),
                _ => None,
            })
            .unwrap_or_default();

        // Unwrap nested event shape: {"event": "step_update", "step_update": {...}}
        let ev_map: Map<String, Value> = if !et.is_empty() {
            if let Some(Value::Object(inner)) = orig_map.get(&et) {
                let mut merged = inner.clone();
                for (k, v) in orig_map {
                    if k != &et {
                        merged.insert(k.clone(), v.clone());
                    }
                }
                merged
            } else {
                orig_map.clone()
            }
        } else {
            orig_map.clone()
        };
        let ev_val = Value::Object(ev_map.clone());

        let cid = non_empty_str_val(ev_map.get("conversation_id"))
            .or_else(|| non_empty_str_val(find_key(&ev_val, "conversation_id", 0)));
        if let Some(ref c) = cid {
            if matches!(et.as_str(), "init" | "result" | "") {
                let mut prog = self.progress.lock().unwrap_or_else(|e| e.into_inner());
                prog.conversation_id = Some(c.clone());
            }
        }

        if et == "result" {
            let r = &mut acc.result;
            let text = match ev_map.get("result") {
                Some(Value::String(s)) => Some(s.clone()),
                _ => {
                    let filtered: Map<String, Value> = ev_map
                        .iter()
                        .filter(|(k, _)| !RESULT_EXCLUDED_KEYS.contains(&k.as_str()))
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect();
                    first_str(&Value::Object(filtered), TEXT_KEYS)
                }
            };
            r.text = text.unwrap_or_default().trim().to_string();
            r.conversation_id = cid.or_else(|| {
                self.progress
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .conversation_id
                    .clone()
            });
            r.finished_reason = ev_map
                .get("finished_reason")
                .and_then(Value::as_str)
                .map(str::to_string);
            r.denied_actions = ev_map
                .get("denied_actions")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            r.usage = ev_map.get("usage").filter(|v| !v.is_null()).cloned();

            let err_val = ev_map.get("error");
            let is_error = ev_map
                .get("is_error")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let has_err = err_val.is_some_and(|v| match v {
                Value::Null => false,
                Value::Bool(b) => *b,
                Value::String(s) => !s.is_empty(),
                Value::Array(a) => !a.is_empty(),
                Value::Object(o) => !o.is_empty(),
                _ => true,
            });
            if has_err || is_error {
                r.error = match err_val {
                    Some(Value::Object(_)) => err_val.cloned(),
                    Some(other) if !other.is_null() => {
                        let msg = match other {
                            Value::String(s) => s.clone(),
                            _ => other.to_string(),
                        };
                        Some(json!({ "message": msg }))
                    }
                    _ => Some(json!({ "message": "error" })),
                };
            }
            info!(text_len = r.text.len(), "agy result event");
            return false;
        }

        if et == "init" {
            info!("agy init event");
            return false;
        }

        // step_update and any other event
        let step_type = value_as_label(ev_map.get("step_type"))
            .or_else(|| value_as_label(find_key(&ev_val, "step_type", 0)))
            .unwrap_or_else(|| et.clone());

        let mut tool = value_as_label(ev_map.get("tool_name"))
            .or_else(|| value_as_label(find_key(&ev_val, "tool_name", 0)));
        if tool.is_none() {
            if let Some(Value::Object(ti)) = ev_map.get("tool_info") {
                tool = value_as_label(ti.get("name"))
                    .or_else(|| value_as_label(ti.get("tool_name")));
            }
        }

        let mut delta = ev_map
            .get("delta")
            .and_then(Value::as_str)
            .map(str::to_string);
        if delta.is_none() {
            if let Some(d_obj @ Value::Object(_)) = ev_map.get("delta") {
                delta = first_str(d_obj, &["text", "content"]);
            }
        }
        if delta.is_none() {
            delta = ev_map
                .get("text_delta")
                .and_then(Value::as_str)
                .map(str::to_string);
        }

        let delta_non_empty = delta.filter(|s| !s.is_empty());

        let snapshot = {
            let mut prog = self.progress.lock().unwrap_or_else(|e| e.into_inner());
            prog.steps += 1;

            if let Some(ref label) = tool {
                if prog.tools.last() != Some(label) && prog.tools.len() < MAX_TRACE_ENTRIES {
                    prog.tools.push(label.clone());
                    let elapsed = prog.started.elapsed().as_secs_f64();
                    prog.trace.push((elapsed, label.clone()));
                }
            }

            if let Some(ref d) = delta_non_empty {
                if tool.is_none() {
                    acc.push_delta(d);
                    prog.partial = acc.deltas.clone();
                }
            } else if tool.is_none()
                && matches!(
                    step_type.as_str(),
                    "agent_response"
                        | "response"
                        | "text"
                        | "message"
                        | "assistant"
                        | "model_response"
                        | "PLANNER_RESPONSE"
                        | "CORTEX_STEP_TYPE_PLANNER_RESPONSE"
                )
            {
                let subset: Map<String, Value> = ev_map
                    .iter()
                    .filter(|(k, _)| RESPONSE_STEP_TEXT_KEYS.contains(&k.as_str()))
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                if let Some(txt) = first_str(&Value::Object(subset), RESPONSE_STEP_TEXT_KEYS) {
                    let step_key = match ev_map.get("step_index") {
                        Some(Value::String(s)) => s.clone(),
                        Some(Value::Number(n)) => n.to_string(),
                        _ => acc.responses.len().to_string(),
                    };
                    acc.responses.insert(step_key, txt);
                    prog.partial = acc.rebuild_responses_partial();
                }
            }

            prog.last_step = step_type.chars().take(60).collect();
            prog.clone()
        };

        if let Some(ref cb) = self.on_progress {
            cb(snapshot).await;
        }

        acc.guard
            .observe_step(
                &ev_map,
                &ev_val,
                tool.as_deref(),
                delta_non_empty.is_some(),
                Instant::now(),
            )
            .is_some()
    }
}

/// Execute an external CLI command asynchronously with `setsid` process-group timeout cleanup
/// and sanitized environment (`BOT_TOKEN` stripped).
pub async fn run_cmd(
    args: &[String],
    cwd: Option<&Path>,
    timeout_secs: f64,
) -> Result<(i32, String, String)> {
    run_cmd_env(args, cwd, timeout_secs, &[]).await
}

/// [`run_cmd`] with extra environment overrides applied after the sanitized agy env
/// (e.g. a per-account `HOME`).
pub async fn run_cmd_env(
    args: &[String],
    cwd: Option<&Path>,
    timeout_secs: f64,
    env_overrides: &[(String, String)],
) -> Result<(i32, String, String)> {
    let Some((program, rest)) = args.split_first() else {
        return Err(BridgeError::Validation(
            "run_cmd args must not be empty".to_string(),
        ));
    };
    if !timeout_secs.is_finite() || timeout_secs <= 0.0 {
        return Err(BridgeError::Validation(
            "run_cmd timeout_secs must be positive and finite".to_string(),
        ));
    }

    let work_dir = cwd.unwrap_or_else(|| Path::new(DEFAULT_WORKSPACE));
    let mut cmd = Command::new(program);
    cmd.args(rest)
        .current_dir(work_dir)
        .env_clear()
        .envs(agy_env())
        .envs(env_overrides.iter().map(|(k, v)| (k.as_str(), v.as_str())))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    configure_new_session(&mut cmd);

    let mut child = cmd
        .spawn()
        .map_err(|e| BridgeError::Process(program.clone(), format!("failed to spawn: {e}")))?;
    let mut pg_guard = ProcessGroupGuard::new(child.id());

    let stdout_pipe = child.stdout.take();
    let stderr_pipe = child.stderr.take();

    let out_task = tokio::spawn(async move {
        let mut buf = Vec::new();
        if let Some(mut r) = stdout_pipe {
            let mut chunk = [0u8; 4096];
            loop {
                match r.read(&mut chunk).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let rem = MAX_RUN_CMD_BYTES.saturating_sub(buf.len());
                        if rem == 0 {
                            break;
                        }
                        buf.extend_from_slice(&chunk[..n.min(rem)]);
                    }
                }
            }
        }
        buf
    });
    let err_task = tokio::spawn(async move {
        let mut buf = Vec::new();
        if let Some(mut r) = stderr_pipe {
            let mut chunk = [0u8; 4096];
            loop {
                match r.read(&mut chunk).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => push_tail_bytes(&mut buf, &chunk[..n], MAX_RUN_CMD_BYTES),
                }
            }
        }
        buf
    });

    let wait_res = tokio::time::timeout(Duration::from_secs_f64(timeout_secs), child.wait()).await;
    match wait_res {
        Ok(Ok(status)) => {
            pg_guard.disarm();
            let out_bytes = out_task.await.unwrap_or_default();
            let err_bytes = err_task.await.unwrap_or_default();
            let code = status
                .code()
                .or_else(|| status.signal().map(|s| -s))
                .unwrap_or(-1);
            Ok((
                code,
                String::from_utf8_lossy(&out_bytes).into_owned(),
                String::from_utf8_lossy(&err_bytes).into_owned(),
            ))
        }
        Ok(Err(e)) => {
            if let Some(pgid) = pg_guard.pgid() {
                signal_process_group(pgid, libc::SIGKILL);
            }
            let _ = child.wait().await;
            pg_guard.disarm();
            out_task.abort();
            err_task.abort();
            Err(BridgeError::Process(
                program.clone(),
                format!("process wait failed: {e}"),
            ))
        }
        Err(_) => {
            if let Some(pgid) = pg_guard.pgid() {
                signal_process_group(pgid, libc::SIGTERM);
                if tokio::time::timeout(Duration::from_millis(500), child.wait())
                    .await
                    .is_err()
                {
                    signal_process_group(pgid, libc::SIGKILL);
                    let _ = tokio::time::timeout(Duration::from_secs(1), child.wait()).await;
                }
            }
            if let Ok(Some(_)) = child.try_wait() {
                pg_guard.disarm();
            }
            out_task.abort();
            err_task.abort();
            Ok((-1, String::new(), "timeout".to_string()))
        }
    }
}

fn split_whitespace_max(line: &str, max_parts: usize) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut rest = line.trim_start();
    while !rest.is_empty() {
        if parts.len() + 1 == max_parts {
            parts.push(rest);
            break;
        }
        match rest.find(char::is_whitespace) {
            Some(idx) => {
                parts.push(&rest[..idx]);
                rest = rest[idx..].trim_start();
            }
            None => {
                parts.push(rest);
                break;
            }
        }
    }
    parts
}

/// Parse table output from `agy mcp list`.
pub fn parse_mcp_list(out: &str) -> Vec<McpListRow> {
    let mut rows = Vec::new();
    for line in out.lines() {
        if line.trim().is_empty() || line.starts_with("NAME") {
            continue;
        }
        let parts = split_whitespace_max(line, 4);
        if parts.len() >= 3 {
            rows.push(McpListRow {
                name: parts[0].to_string(),
                server_type: parts[1].to_string(),
                status: parts[2].to_string(),
                cmd: parts.get(3).copied().unwrap_or("").trim_end().to_string(),
            });
        }
    }
    rows
}

/// Parse model list from JSON array/object (`{"models": [...]}`) or TSV (`id\tDisplay Name`).
pub fn parse_models(out: &str) -> Vec<ModelInfo> {
    let trimmed = out.trim();
    if trimmed.starts_with('[') || trimmed.starts_with('{') {
        if let Ok(data) = serde_json::from_str::<Value>(trimmed) {
            let items_opt = match &data {
                Value::Array(arr) => Some(arr.as_slice()),
                Value::Object(obj) => obj.get("models").and_then(Value::as_array).map(Vec::as_slice),
                _ => None,
            };
            if let Some(items) = items_opt {
                let mut res = Vec::new();
                for it in items {
                    let Some(obj) = it.as_object() else {
                        continue;
                    };
                    let mid = non_empty_str_val(obj.get("id"))
                        .or_else(|| non_empty_str_val(obj.get("name")))
                        .or_else(|| non_empty_str_val(obj.get("model")));
                    if let Some(id) = mid {
                        let name = non_empty_str_val(obj.get("display_name"))
                            .or_else(|| non_empty_str_val(obj.get("label")))
                            .or_else(|| non_empty_str_val(obj.get("name")))
                            .unwrap_or_else(|| id.clone());
                        res.push(ModelInfo { id, name });
                    }
                }
                if !res.is_empty() {
                    return res;
                }
            }
        }
    }

    let mut res = Vec::new();
    for line in trimmed.lines() {
        if let Some((mid, name)) = line.split_once('\t') {
            let mid_clean = mid.trim();
            if !mid_clean.is_empty() && !mid_clean.contains(' ') {
                res.push(ModelInfo {
                    id: mid_clean.to_string(),
                    name: name.trim().to_string(),
                });
            }
        }
    }
    res
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Mutex as StdMutex;
    use tempfile::TempDir;

    fn write_script(dir: &TempDir, name: &str, body: &str) -> String {
        let path = dir.path().join(name);
        fs::write(&path, body).unwrap();
        let mut perms = fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&path, perms).unwrap();
        path.to_string_lossy().into_owned()
    }

    #[test]
    fn test_build_args_and_engine_kind() {
        let req = EngineRequest {
            prompt: "[telegram-bridge] hi".to_string(),
            model: Some("m1".to_string()),
            effort: Some("high".to_string()),
            mode: Some("plan".to_string()),
            conversation_id: Some("c1".to_string()),
            skip_permissions: false,
            timeout_secs: 60,
            agent: Some("coder".to_string()),
            add_dirs: vec!["/tmp/a".to_string()],
            ..Default::default()
        };
        let args = build_agy_args("/usr/bin/agy", &req);
        assert_eq!(args[0], "/usr/bin/agy");
        assert_eq!(&args[1..3], &["--output-format", "stream-json"]);
        assert!(args.contains(&"--agent".to_string()));
        assert!(args.contains(&"--add-dir".to_string()));
        assert!(args.contains(&"--conversation".to_string()));
        assert!(!args.contains(&"--dangerously-skip-permissions".to_string()));
        assert_eq!(&args[args.len() - 2..], &["-p", "[telegram-bridge] hi"]);

        assert_eq!(EngineKind::from_spec("").unwrap(), EngineKind::Agy);
        assert_eq!(EngineKind::from_spec("agy").unwrap(), EngineKind::Agy);
        let custom = EngineKind::from_spec("/opt/bin/claude --verbose --model opus").unwrap();
        assert_eq!(
            custom,
            EngineKind::Custom {
                command: "/opt/bin/claude".to_string(),
                extra_args: vec![
                    "--verbose".to_string(),
                    "--model".to_string(),
                    "opus".to_string()
                ]
            }
        );
        let runner = build_runner(custom, None, None);
        let c_args = runner.build_args(&EngineRequest {
            prompt: "hello".to_string(),
            ..Default::default()
        });
        assert_eq!(
            c_args,
            vec![
                "/opt/bin/claude",
                "--verbose",
                "--model",
                "opus",
                "-p",
                "hello"
            ]
        );
    }

    #[test]
    fn test_parse_error_models_and_mcp_list() {
        let e = parse_agy_error(
            "x\nAGY_ERROR: {\"status\":\"PERMISSION_DENIED\",\"code\":403,\"message\":\"disabled\"}\n",
        )
        .unwrap();
        assert_eq!(e["code"], 403);

        let e_plain = parse_agy_error("AGY_ERROR: plain failure text").unwrap();
        assert_eq!(e_plain["message"], "plain failure text");

        let m_tsv = parse_models(
            "gemini-4-carbon-high\tGemini 4 Carbon (High)\nclaude-opus-4-6-thinking\tClaude Opus 4.6 (Thinking)\n",
        );
        assert_eq!(m_tsv.len(), 2);
        assert_eq!(m_tsv[1].id, "claude-opus-4-6-thinking");

        let m_json = parse_models(
            r#"{"models":[{"id":"m1","display_name":"Model One"},{"model":"m2","label":"Model Two"}]}"#,
        );
        assert_eq!(m_json.len(), 2);
        assert_eq!(m_json[0].name, "Model One");
        assert_eq!(m_json[1].id, "m2");

        let rows = parse_mcp_list(
            "NAME TYPE STATUS COMMAND/URL\ngortex stdio enabled /root/.local/bin/gortex mcp\n",
        );
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].name, "gortex");
        assert!(rows[0].cmd.ends_with("mcp"));
    }

    #[tokio::test]
    async fn test_streaming_ndjson_progress_and_env_redaction() {
        let dir = TempDir::new().unwrap();
        let lines = [
            json!({"type": "init", "conversation_id": "conv-1"}),
            json!({"type": "step_update", "step_type": "tool_call", "tool_name": "read_file"}),
            json!({"type": "step_update", "step_type": "text", "delta": "Hel"}),
            json!({"type": "step_update", "step_type": "text", "delta": "lo"}),
            json!({
                "type": "result",
                "result": "Hello **world**",
                "conversation_id": "conv-1",
                "denied_actions": [{"tool": "rm"}],
                "usage": {"output_tokens": 5}
            }),
        ];
        let payload: String = lines
            .iter()
            .map(|v| serde_json::to_string(v).unwrap())
            .collect::<Vec<_>>()
            .join("\n");
        let script = write_script(
            &dir,
            "fakeagy",
            &format!(
                "#!/bin/sh\nif [ -n \"$BOT_TOKEN\" ]; then echo 'LEAKED_TOKEN' >&2; fi\ncat <<'X'\n{payload}\nX\n"
            ),
        );

        let seen = Arc::new(StdMutex::new(Vec::new()));
        let seen_cb = Arc::clone(&seen);
        let cb: ProgressCallback = Arc::new(move |p| {
            let s = Arc::clone(&seen_cb);
            Box::pin(async move {
                s.lock().unwrap().push(p.steps);
            })
        });

        let mut env_over = HashMap::new();
        env_over.insert("BOT_TOKEN".to_string(), "123456:SECRET_SHOULD_NOT_PASS".to_string());
        let job = AgyProcessJob::new(
            vec![script, "-p".to_string(), "x".to_string()],
            Some(dir.path().to_path_buf()),
            Some(cb),
        )
        .with_env_overrides(env_over);

        let r = job.run().await.unwrap();
        assert_eq!(r.text, "Hello **world**");
        assert_eq!(r.conversation_id.as_deref(), Some("conv-1"));
        assert_eq!(r.exit_code, Some(0));
        assert_eq!(r.denied_actions.len(), 1);
        assert_eq!(r.usage, Some(json!({"output_tokens": 5})));
        assert!(r.error.is_none());
        assert_eq!(*seen.lock().unwrap(), vec![1, 2, 3]);
    }

    #[tokio::test]
    async fn test_nested_event_shape_and_full_response_fallback() {
        let dir = TempDir::new().unwrap();
        let lines = [
            json!({"event": "init", "init": {"model": "x"}, "conversation_id": "c9"}),
            json!({"event": "step_update", "step_update": {"step_type": "tool_call", "tool_name": "grep"}}),
            json!({"event": "step_update", "step_update": {"step_type": "text", "delta": "Hi "}}),
            json!({"event": "step_update", "step_update": {"step_type": "agent_response", "step_index": 0, "text": "Full response"}}),
            json!({"event": "result", "result": {"response": "Hi there", "usage": {"output_tokens": 3}}, "conversation_id": "c9"}),
        ];
        let payload: String = lines
            .iter()
            .map(|v| serde_json::to_string(v).unwrap())
            .collect::<Vec<_>>()
            .join("\n");
        let script = write_script(
            &dir,
            "fakeagy_nested",
            &format!("#!/bin/sh\ncat <<'X'\n{payload}\nX\n"),
        );

        let job = AgyProcessJob::new(vec![script], Some(dir.path().to_path_buf()), None);
        let r = job.run().await.unwrap();
        assert_eq!(r.text, "Hi there");
        assert_eq!(r.conversation_id.as_deref(), Some("c9"));
        assert_eq!(r.steps, 3);
        assert_eq!(r.usage, Some(json!({"output_tokens": 3})));
    }

    #[tokio::test]
    async fn test_fake_agy_error_and_bounded_stdout() {
        let dir = TempDir::new().unwrap();
        let script = write_script(
            &dir,
            "fakeagy_err",
            "#!/bin/sh\necho 'AGY_ERROR: {\"code\":403,\"message\":\"This service has been disabled\"}' >&2\nexit 3\n",
        );
        let job = AgyProcessJob::new(vec![script], Some(dir.path().to_path_buf()), None);
        let r = job.run().await.unwrap();
        assert_eq!(r.exit_code, Some(3));
        assert_eq!(r.error.unwrap()["code"], 403);

        // Bounded raw_lines ring test: emit 3000 plain lines and ensure capped without OOM
        let flood_script = write_script(
            &dir,
            "flood.py",
            "#!/usr/bin/env python3\nfor i in range(3000):\n    print(f'line-{i}')\n",
        );
        let flood_job = AgyProcessJob::new(vec![flood_script], Some(dir.path().to_path_buf()), None);
        let flood_res = flood_job.run().await.unwrap();
        assert_eq!(flood_res.exit_code, Some(0));
        assert_eq!(flood_res.text.lines().count(), MAX_RAW_LINES);
        assert!(flood_res.text.ends_with("line-2999"));
    }

    #[tokio::test]
    async fn test_stop_process_group_kill_and_escalation() {
        let dir = TempDir::new().unwrap();
        // 1) Normal SIGINT termination
        let script = write_script(&dir, "sleep_agy", "#!/bin/sh\nsleep 60\n");
        let job = Arc::new(AgyProcessJob::new(
            vec![script],
            Some(dir.path().to_path_buf()),
            None,
        ));
        let job_run = Arc::clone(&job);
        let handle = tokio::spawn(async move { job_run.run().await });
        tokio::time::sleep(Duration::from_millis(150)).await;
        job.stop().await;
        let r = handle.await.unwrap().unwrap();
        assert!(r.stopped);
        assert!(r.error.is_none());

        // 2) Full SIGINT -> SIGTERM -> SIGKILL escalation when process traps INT and TERM
        let pid_file = dir.path().join("trapped.pid");
        let stub_script = write_script(
            &dir,
            "trap_all.py",
            &format!(
                r#"#!/usr/bin/env python3
import os, signal, subprocess, time
signal.signal(signal.SIGINT, signal.SIG_IGN)
signal.signal(signal.SIGTERM, signal.SIG_IGN)
sub = subprocess.Popen(["sleep", "60"])
open({pid:?}, "w").write(str(sub.pid))
time.sleep(60)
"#,
                pid = pid_file.to_string_lossy()
            ),
        );
        let escal_job = Arc::new(
            AgyProcessJob::new(vec![stub_script], Some(dir.path().to_path_buf()), None)
                .with_stop_timeouts(
                    Duration::from_millis(60),
                    Duration::from_millis(60),
                    Duration::from_secs(2),
                ),
        );
        let ej2 = Arc::clone(&escal_job);
        let h2 = tokio::spawn(async move { ej2.run().await });
        tokio::time::sleep(Duration::from_millis(200)).await;
        escal_job.stop().await;
        let r2 = h2.await.unwrap().unwrap();
        assert!(r2.stopped);
        if pid_file.exists() {
            let sub_pid: libc::pid_t = fs::read_to_string(&pid_file).unwrap().trim().parse().unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;
            let alive = unsafe { libc::kill(sub_pid, 0) } == 0;
            assert!(!alive, "descendant {sub_pid} survived SIGKILL to -pgid");
        }
    }

    #[tokio::test]
    async fn test_run_cmd_and_timeout() {
        let dir = TempDir::new().unwrap();
        let (rc, out, err) = run_cmd(
            &["sh".to_string(), "-c".to_string(), "echo hello".to_string()],
            Some(dir.path()),
            5.0,
        )
        .await
        .unwrap();
        assert_eq!(rc, 0);
        assert_eq!(out.trim(), "hello");
        assert!(err.is_empty());

        let (rc_to, _, err_to) = run_cmd(
            &["sh".to_string(), "-c".to_string(), "sleep 10".to_string()],
            Some(dir.path()),
            0.2,
        )
        .await
        .unwrap();
        assert_eq!(rc_to, -1);
        assert_eq!(err_to, "timeout");
    }

    #[tokio::test]
    async fn hard_timeout_kills_hung_group_and_empty_exit_is_an_error() {
        let dir = TempDir::new().unwrap();
        let pid_file = dir.path().join("gc.pid");
        // child exits at once, but a grandchild keeps stdout open forever (no EOF)
        let hung = write_script(
            &dir,
            "hung_eng",
            &format!("#!/bin/sh\necho '{{\"type\":\"init\",\"conversation_id\":\"c\"}}'\n(sleep 60; echo late) &\necho $! > {}\nexit 0\n", pid_file.display()),
        );
        let runner = build_runner(
            EngineKind::Custom { command: hung, extra_args: vec!["--print-timeout".into(), "1s".into()] },
            None,
            Some(dir.path().to_path_buf()),
        );
        let t0 = std::time::Instant::now();
        let res = runner
            .run(EngineRequest { prompt: "x".into(), hard_grace_secs: Some(1), ..Default::default() }, None)
            .await
            .unwrap();
        assert!(t0.elapsed() < Duration::from_secs(15), "bridge hard timeout must fire");
        assert!(res.timed_out);
        assert!(res.error.is_some());
        tokio::time::sleep(Duration::from_millis(300)).await;
        let gpid: i32 = fs::read_to_string(&pid_file).unwrap().trim().parse().unwrap();
        assert!(unsafe { libc::kill(gpid, 0) } != 0, "grandchild killed with the process group");

        // rc=0 with no output at all is a failure, not an empty success
        let empty = write_script(&dir, "empty_eng", "#!/bin/sh\nexit 0\n");
        let runner = build_runner(EngineKind::Custom { command: empty, extra_args: vec![] }, None, Some(dir.path().to_path_buf()));
        let res = runner.run(EngineRequest { prompt: "x".into(), ..Default::default() }, None).await.unwrap();
        assert!(res.text.is_empty());
        let msg = res.error.as_ref().map(|e| e.to_string()).unwrap_or_default();
        assert!(msg.contains("without an answer"), "{msg}");

        // rc!=0: raw stdout lines are not delivered as the answer
        let crash = write_script(&dir, "crash_eng", "#!/bin/sh\necho 'some raw crash line'\nexit 2\n");
        let runner = build_runner(EngineKind::Custom { command: crash, extra_args: vec![] }, None, Some(dir.path().to_path_buf()));
        let res = runner.run(EngineRequest { prompt: "x".into(), ..Default::default() }, None).await.unwrap();
        assert!(res.text.is_empty());
        assert!(res.error.as_ref().map(|e| e.to_string()).unwrap_or_default().contains("some raw crash line"));
    }

    #[test]
    fn env_strips_systemd_sockets_and_effort_suffix() {
        let vars: HashMap<String, String> = [
            ("NOTIFY_SOCKET", "/run/x"),
            ("WATCHDOG_USEC", "1"),
            ("BOT_TOKEN", "t"),
            ("VENICE_API_KEY", "sk-secret"),
            ("WEBHOOK_SECRET", "wh"),
            ("WEBAPP_SECRET", "wa"),
            ("PROXY_URLS", "socks5://p"),
            ("LD_PRELOAD", "/tmp/evil.so"),
            ("KEEP", "1"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        let e = agy_env_from(vars);
        assert!(!e.contains_key("BOT_TOKEN") && e.contains_key("KEEP"));
        assert!(!e.contains_key("VENICE_API_KEY"));
        assert!(!e.contains_key("WEBHOOK_SECRET"));
        assert!(!e.contains_key("WEBAPP_SECRET"));
        assert!(!e.contains_key("PROXY_URLS"));
        assert!(!e.contains_key("LD_PRELOAD"));
        assert!(!e.contains_key("NOTIFY_SOCKET") && !e.contains_key("WATCHDOG_USEC"));
        assert!(model_id_has_effort("gemini-3.8-flash-high"));
        assert!(!model_id_has_effort("claude-sonnet-4-6"));
        assert!(crate::mcp_client::looks_like_secret("token ya29.a0AfH6SMBxxxxxxxxxxxxxxxxxxxxxxx"));
        assert!(crate::mcp_client::looks_like_secret("code 4/0AfJohXxxxxxxxxxxxxxxxxxxxxxxxx"));
    }

    #[tokio::test]
    async fn test_custom_engine_runner_print_timeout_and_abort_cleanup() {
        let dir = TempDir::new().unwrap();
        let line = json!({
            "type": "result",
            "result": "timed out response",
            "finished_reason": "print_timeout",
            "is_error": true
        });
        let custom_script = write_script(
            &dir,
            "custom_eng",
            &format!("#!/bin/sh\necho '{}'\n", serde_json::to_string(&line).unwrap()),
        );
        let runner = build_runner(
            EngineKind::Custom {
                command: custom_script,
                extra_args: vec!["--flag".to_string()],
            },
            None,
            Some(dir.path().to_path_buf()),
        );
        let res = runner
            .run(
                EngineRequest {
                    prompt: "hello".to_string(),
                    ..Default::default()
                },
                None,
            )
            .await
            .unwrap();
        assert_eq!(res.text, "timed out response");
        assert!(res.timed_out);
        assert!(res.error.is_some());

        // Task abort (Drop) kills process group
        let pid_file = dir.path().join("drop_child.pid");
        let drop_script = write_script(
            &dir,
            "drop_agy.py",
            &format!(
                "#!/usr/bin/env python3\nimport subprocess, time\np = subprocess.Popen(['sleep', '60'])\nopen({:?}, 'w').write(str(p.pid))\ntime.sleep(60)\n",
                pid_file.to_string_lossy()
            ),
        );
        let job = Arc::new(AgyProcessJob::new(
            vec![drop_script],
            Some(dir.path().to_path_buf()),
            None,
        ));
        let j2 = Arc::clone(&job);
        let h = tokio::spawn(async move { j2.run().await });
        tokio::time::sleep(Duration::from_millis(150)).await;
        h.abort();
        let _ = h.await;
        if pid_file.exists() {
            let sub_pid: libc::pid_t = fs::read_to_string(&pid_file).unwrap().trim().parse().unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;
            let alive = unsafe { libc::kill(sub_pid, 0) } == 0;
            assert!(!alive, "descendant {sub_pid} survived task drop");
        }
    }

    #[tokio::test]
    async fn test_agy_live_stream_guard_loop_step_burst_and_dedup() {
        let dir = TempDir::new().unwrap();

        // 1. Legitimate diverse tools with multiple status updates per step_index must NOT trip.
        let ok_script = write_script(
            &dir,
            "ok_diverse.py",
            r#"#!/usr/bin/env python3
import json
for i in range(1, 6):
    for st in ("PENDING", "RUNNING", "DONE"):
        print(json.dumps({
            "type": "step_update",
            "step_index": i,
            "step_type": "tool_use",
            "tool_name": "read_file",
            "tool_info": {"name": "read_file", "Path": f"/src/file_{i}.rs"},
            "status": st
        }), flush=True)
print(json.dumps({"type": "result", "result": "all 5 files read cleanly"}), flush=True)
"#,
        );
        let ok_job = AgyProcessJob::new(vec![ok_script], Some(dir.path().to_path_buf()), None)
            .with_guard(AgyGuardConfig {
                max_tool_steps: 10,
                tool_repeat_limit: 2,
                max_tools_per_min: 20,
            });
        let ok_res = ok_job.run().await.unwrap();
        assert!(ok_res.guard_tripped.is_none(), "diverse tools tripped: {:?}", ok_res.guard_tripped);
        assert_eq!(ok_res.text, "all 5 files read cleanly");

        // 2. Identical tool repeat loop with intervening thinking steps trips cleanly and stops child.
        let loop_script = write_script(
            &dir,
            "loop_tool.py",
            r#"#!/usr/bin/env python3
import json, time
print(json.dumps({"type": "step_update", "step_type": "agent_response", "delta": "partial before loop"}), flush=True)
for i in range(1, 20):
    print(json.dumps({"type": "step_update", "step_index": i * 2 - 1, "step_type": "thinking"}), flush=True)
    print(json.dumps({
        "type": "step_update",
        "step_index": i * 2,
        "step_type": "tool_use",
        "tool_name": "run_command",
        "tool_info": {"name": "run_command", "CommandLine": "curl https://broken.invalid"}
    }), flush=True)
    time.sleep(0.05)
time.sleep(30)
"#,
        );
        let loop_job = AgyProcessJob::new(vec![loop_script], Some(dir.path().to_path_buf()), None)
            .with_stop_timeouts(
                Duration::from_millis(200),
                Duration::from_millis(200),
                Duration::from_millis(200),
            )
            .with_guard(AgyGuardConfig {
                max_tool_steps: 50,
                tool_repeat_limit: 2,
                max_tools_per_min: 50,
            });
        let loop_res = loop_job.run().await.unwrap();
        assert!(
            loop_res
                .guard_tripped
                .as_deref()
                .is_some_and(|s| s.contains("tool loop detected")),
            "expected loop guard trip, got {loop_res:?}"
        );
        assert_eq!(loop_res.finished_reason.as_deref(), Some("guard_tripped"));
        assert!(!loop_res.stopped, "guard trip must be distinct from user /stop");
        assert!(loop_res.error.is_none(), "guard trip must not look like account crash");
        assert!(loop_res.text.contains("partial before loop"));

        // 3. Max tool steps cap stops runaway diverse tools cleanly.
        let steps_script = write_script(
            &dir,
            "many_tools.py",
            r#"#!/usr/bin/env python3
import json, time
for i in range(1, 20):
    print(json.dumps({
        "type": "step_update",
        "step_index": i,
        "step_type": "tool_use",
        "tool_name": "read_file",
        "tool_info": {"name": "read_file", "Path": f"/tmp/f{i}"}
    }), flush=True)
time.sleep(10)
"#,
        );
        let steps_job = AgyProcessJob::new(vec![steps_script.clone()], Some(dir.path().to_path_buf()), None)
            .with_stop_timeouts(
                Duration::from_millis(200),
                Duration::from_millis(200),
                Duration::from_millis(200),
            )
            .with_guard(AgyGuardConfig {
                max_tool_steps: 3,
                tool_repeat_limit: 10,
                max_tools_per_min: 100,
            });
        let steps_res = steps_job.run().await.unwrap();
        assert!(
            steps_res
                .guard_tripped
                .as_deref()
                .is_some_and(|s| s.contains("tool step limit reached")),
            "expected max step guard trip, got {steps_res:?}"
        );

        // 4. Burst rate cap stops rapid tool calls cleanly.
        let burst_job = AgyProcessJob::new(vec![steps_script], Some(dir.path().to_path_buf()), None)
            .with_stop_timeouts(
                Duration::from_millis(200),
                Duration::from_millis(200),
                Duration::from_millis(200),
            )
            .with_guard(AgyGuardConfig {
                max_tool_steps: 100,
                tool_repeat_limit: 10,
                max_tools_per_min: 3,
            });
        let burst_res = burst_job.run().await.unwrap();
        assert!(
            burst_res
                .guard_tripped
                .as_deref()
                .is_some_and(|s| s.contains("tool burst rate exceeded")),
            "expected burst guard trip, got {burst_res:?}"
        );

        // 5. Targetless batch `read_file` calls (real agy stream omits Path) allow 6+ consecutive
        //    calls without false-positive tripping, while 14 consecutive still trip cleanly.
        let batch_read_script = write_script(
            &dir,
            "batch_read_targetless.py",
            r#"#!/usr/bin/env python3
import json
for i in range(1, 7):
    print(json.dumps({
        "type": "step_update",
        "step_index": i,
        "step_type": "tool_use",
        "tool_name": "read_file"
    }), flush=True)
print(json.dumps({"type": "result", "result": "batch 6 targetless reads ok"}), flush=True)
"#,
        );
        let batch_res = AgyProcessJob::new(vec![batch_read_script], Some(dir.path().to_path_buf()), None)
            .with_guard(AgyGuardConfig {
                max_tool_steps: 60,
                tool_repeat_limit: 4,
                max_tools_per_min: 45,
            })
            .run()
            .await
            .unwrap();
        assert!(batch_res.guard_tripped.is_none(), "6 targetless read_file calls must not trip: {batch_res:?}");
        assert_eq!(batch_res.text, "batch 6 targetless reads ok");

        let runaway_read_script = write_script(
            &dir,
            "runaway_read_targetless.py",
            r#"#!/usr/bin/env python3
import json, time
for i in range(1, 20):
    print(json.dumps({
        "type": "step_update",
        "step_index": i,
        "step_type": "tool_use",
        "tool_name": "read_file"
    }), flush=True)
    time.sleep(0.01)
time.sleep(5)
"#,
        );
        let runaway_res = AgyProcessJob::new(vec![runaway_read_script], Some(dir.path().to_path_buf()), None)
            .with_stop_timeouts(
                Duration::from_millis(200),
                Duration::from_millis(200),
                Duration::from_millis(200),
            )
            .with_guard(AgyGuardConfig {
                max_tool_steps: 60,
                tool_repeat_limit: 4,
                max_tools_per_min: 45,
            })
            .run()
            .await
            .unwrap();
        assert!(
            runaway_res
                .guard_tripped
                .as_deref()
                .is_some_and(|s| s.contains("tool loop detected")),
            "14+ consecutive targetless read_file calls must still trip loop guard: {runaway_res:?}"
        );
    }

    #[test]
    fn test_agy_stream_guard_dedups_targetless_status_transitions() {
        let mut g = AgyStreamGuard::new(AgyGuardConfig {
            max_tool_steps: 10,
            tool_repeat_limit: 2,
            max_tools_per_min: 50,
        });
        let now = Instant::now();
        // Same tool call emitting PENDING -> RUNNING -> DONE without step_index must count as 1 call, not 3!
        for st in ["PENDING", "RUNNING", "DONE"] {
            let v = json!({
                "type": "step_update",
                "step_type": "tool_use",
                "tool_name": "run_command",
                "tool_info": {"CommandLine": "cargo test"},
                "status": st
            });
            let res = g.observe_step(v.as_object().unwrap(), &v, Some("run_command"), false, now);
            assert!(res.is_none(), "status transition {st} must not trip: {res:?}");
        }
        assert_eq!(g.tool_calls, 1);
        assert_eq!(g.consecutive_repeats, 1);
    }
}
