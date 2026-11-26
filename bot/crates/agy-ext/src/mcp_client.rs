//! Async Tokio stdio JSON-RPC 2.0 MCP client and secret redaction helpers.

use std::collections::HashMap;
use std::process::Stdio;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use agy_core::error::{BridgeError, Result};
use regex::{Regex, RegexBuilder};
use serde_json::{json, Value};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::sync::Mutex as AsyncMutex;
use tracing::{debug, warn};

/// Default timeout for stdio MCP tool invocations (seconds).
pub const DEFAULT_MCP_TIMEOUT_SECS: f64 = 12.0;

/// Maximum single JSON-RPC stdout line size (64 MiB — safely supports > 4 MiB payloads without OOM).
pub const MAX_STDIO_JSONRPC_LINE_BYTES: usize = 64 * 1024 * 1024;

/// Maximum stderr bytes retained for diagnostic error messages.
const MAX_STDERR_CAPTURE_BYTES: usize = 16 * 1024;

const SECRET_VALUE_PATTERN: &str = concat!(
    r"(?:",
    r"\bsk-[A-Za-z0-9_-]{8,}",
    r"|\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{10,}",
    r"|\bgithub_pat_[A-Za-z0-9_]{16,}",
    r"|\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
    r"|\bxox[baprs]-[A-Za-z0-9-]{10,}",
    r"|\bAIza[0-9A-Za-z_-]{20,}",
    r"|\b4/0A[0-9A-Za-z_-]{20,}",
    r"|\bya29\.[0-9A-Za-z._-]{20,}",
    r"|\b1//0[0-9A-Za-z_-]{20,}",
    r"|\bGOCSPX-[0-9A-Za-z_-]{10,}",
    r"|\b\d{6,12}:[A-Za-z0-9_-]{25,}\b",
    r"|-----BEGIN [A-Z ]*PRIVATE KEY-----",
    r"|\b(?:BOT_TOKEN|API_KEY|SECRET_KEY|ACCESS_TOKEN|AUTH_TOKEN|PASSWORD|PASSWD|PRIVATE_KEY|DATABASE_URL|MEMORY_DB_URL)\s*[:=]\s*\S+",
    r"|\b(?:postgres(?:ql)?|mysql|redis|mongodb(?:\+srv)?|amqp)://[^:\s]+:[^@\s]+@",
    r"|\bBearer\s+[A-Za-z0-9._-]{16,}",
    r")"
);

fn secret_regex() -> Option<&'static Regex> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    RE.get_or_init(|| {
        RegexBuilder::new(SECRET_VALUE_PATTERN)
            .case_insensitive(true)
            .build()
            .ok()
    })
    .as_ref()
}

/// Replace recognized API keys, tokens, PEM headers, and credentialed URLs with `[REDACTED]`.
pub fn redact_secrets_in_text(text: &str) -> String {
    match secret_regex() {
        Some(re) => re.replace_all(text, "[REDACTED]").into_owned(),
        None => "[REDACTED]".to_string(),
    }
}

/// Return `true` if `text` contains any recognized secret or credential pattern.
pub fn looks_like_secret(text: &str) -> bool {
    match secret_regex() {
        Some(re) => re.is_match(text),
        None => true,
    }
}

/// Configure a [`Command`] to spawn in a fresh POSIX session/process group via `setsid()`.
pub(crate) fn configure_new_session(cmd: &mut Command) {
    // SAFETY: `libc::setsid()` and reading `errno` via `last_os_error()` are async-signal-safe
    // and safe to invoke between `fork()` and `exec()`.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

/// Send a signal to an entire process group (`-pgid`). Returns `false` if no such process group exists.
pub(crate) fn signal_process_group(pgid: libc::pid_t, sig: libc::c_int) -> bool {
    if pgid <= 0 {
        return false;
    }
    // SAFETY: Negative `pgid` targets the child's process group created via `setsid()`.
    let rc = unsafe { libc::kill(-pgid, sig) };
    if rc == 0 {
        return true;
    }
    let err = std::io::Error::last_os_error();
    if err.raw_os_error() == Some(libc::ESRCH) {
        return false;
    }
    warn!(pgid, sig, error = %err, "failed to signal process group");
    false
}

/// RAII guard that ensures an un-reaped child's process group is `SIGKILL`ed on drop/cancellation.
pub(crate) struct ProcessGroupGuard {
    pgid: Option<libc::pid_t>,
}

impl ProcessGroupGuard {
    pub(crate) fn new(child_id: Option<u32>) -> Self {
        let pgid = child_id.and_then(|id| libc::pid_t::try_from(id).ok().filter(|&p| p > 0));
        Self { pgid }
    }

    pub(crate) fn pgid(&self) -> Option<libc::pid_t> {
        self.pgid
    }

    /// Disarm once the direct child has been reaped (preventing signaling a reused PID).
    pub(crate) fn disarm(&mut self) {
        self.pgid = None;
    }
}

impl Drop for ProcessGroupGuard {
    fn drop(&mut self) {
        if let Some(pgid) = self.pgid.take() {
            signal_process_group(pgid, libc::SIGKILL);
        }
    }
}

/// Read a single `\n`-delimited line from `reader` into `buf`, enforcing `max_bytes` during reading
/// so an oversized unterminated line cannot exhaust memory.
///
/// Returns `(total_bytes_consumed, was_truncated)`.
pub(crate) async fn read_bounded_line<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    buf: &mut Vec<u8>,
    max_bytes: usize,
) -> std::io::Result<(usize, bool)> {
    buf.clear();
    let mut total = 0usize;
    let mut truncated = false;
    loop {
        let chunk = reader.fill_buf().await?;
        if chunk.is_empty() {
            return Ok((total, truncated));
        }
        if let Some(pos) = chunk.iter().position(|&b| b == b'\n') {
            let take = pos + 1;
            if !truncated {
                let allowed = max_bytes.saturating_sub(buf.len());
                let copy_len = take.min(allowed);
                buf.extend_from_slice(&chunk[..copy_len]);
                if copy_len < take {
                    truncated = true;
                }
            }
            total += take;
            reader.consume(take);
            return Ok((total, truncated));
        } else {
            let len = chunk.len();
            if !truncated {
                let allowed = max_bytes.saturating_sub(buf.len());
                let copy_len = len.min(allowed);
                buf.extend_from_slice(&chunk[..copy_len]);
                if copy_len < len {
                    truncated = true;
                }
            }
            total += len;
            reader.consume(len);
        }
    }
}

/// Append incoming bytes into a bounded ring-tail buffer retaining the newest `cap` bytes.
pub(crate) fn push_tail_bytes(buf: &mut Vec<u8>, incoming: &[u8], cap: usize) {
    if cap == 0 || incoming.is_empty() {
        return;
    }
    if incoming.len() >= cap {
        buf.clear();
        buf.extend_from_slice(&incoming[incoming.len() - cap..]);
        return;
    }
    let overflow = (buf.len() + incoming.len()).saturating_sub(cap);
    if overflow > 0 {
        buf.drain(..overflow);
    }
    buf.extend_from_slice(incoming);
}

async fn drain_stderr(
    mut stderr: tokio::process::ChildStderr,
    captured: Arc<Mutex<Vec<u8>>>,
) {
    let mut chunk = [0u8; 4096];
    loop {
        match stderr.read(&mut chunk).await {
            Ok(0) => break,
            Ok(n) => {
                let mut guard = captured.lock().unwrap_or_else(|e| e.into_inner());
                push_tail_bytes(&mut guard, &chunk[..n], MAX_STDERR_CAPTURE_BYTES);
            }
            Err(_) => break,
        }
    }
}

fn format_redacted_stderr(captured: &Arc<Mutex<Vec<u8>>>) -> String {
    let bytes = {
        let guard = captured.lock().unwrap_or_else(|e| e.into_inner());
        guard.clone()
    };
    let text = String::from_utf8_lossy(&bytes);
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let redacted = redact_secrets_in_text(trimmed);
    let excerpt: String = redacted.chars().take(300).collect();
    excerpt
}

async fn send_jsonrpc(stdin: &mut tokio::process::ChildStdin, payload: &Value) -> Result<()> {
    let mut encoded = serde_json::to_vec(payload)
        .map_err(|e| BridgeError::json("serializing MCP JSON-RPC request", e))?;
    encoded.push(b'\n');
    stdin
        .write_all(&encoded)
        .await
        .map_err(|e| BridgeError::io("writing MCP JSON-RPC request to stdin", e))?;
    stdin
        .flush()
        .await
        .map_err(|e| BridgeError::io("flushing MCP stdin", e))?;
    Ok(())
}

async fn read_jsonrpc_response<R: AsyncBufRead + Unpin>(
    stdout: &mut R,
    expected_id: u64,
    server: &str,
    tool: &str,
    stderr_buf: &Arc<Mutex<Vec<u8>>>,
) -> Result<Value> {
    let mut line_buf = Vec::new();
    loop {
        let (bytes_read, truncated) =
            read_bounded_line(stdout, &mut line_buf, MAX_STDIO_JSONRPC_LINE_BYTES)
                .await
                .map_err(|e| BridgeError::Mcp {
                    server: server.to_string(),
                    tool: tool.to_string(),
                    message: redact_secrets_in_text(&format!("failed reading MCP stdout: {e}")),
                })?;

        if truncated {
            return Err(BridgeError::PayloadTooLarge {
                actual: bytes_read,
                limit: MAX_STDIO_JSONRPC_LINE_BYTES,
            });
        }

        if bytes_read == 0 {
            // Brief yield so stderr drain task can catch final flush before formatting error.
            tokio::time::sleep(Duration::from_millis(20)).await;
            let detail = format_redacted_stderr(stderr_buf);
            let suffix = if detail.is_empty() {
                String::new()
            } else {
                format!(" ({detail})")
            };
            return Err(BridgeError::Mcp {
                server: server.to_string(),
                tool: tool.to_string(),
                message: format!("MCP server closed stdout unexpectedly{suffix}"),
            });
        }

        let line = String::from_utf8_lossy(&line_buf);
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let msg: Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(e) => {
                // Tolerate stray non-JSON startup banners/warnings printed to stdout
                debug!(server, tool, error = %e, "ignoring non-JSON line on MCP stdout");
                continue;
            }
        };

        let Some(obj) = msg.as_object() else {
            debug!(server, tool, "ignoring non-object JSON line on MCP stdout");
            continue;
        };

        // Only match actual JSON-RPC responses (no `method` field, carries `result` or `error`),
        // skipping server-initiated notifications or requests (e.g. ping/roots/list) that reuse ids.
        if obj.get("method").is_none()
            && (obj.contains_key("result") || obj.contains_key("error"))
            && obj.get("id").and_then(Value::as_u64) == Some(expected_id)
        {
            return Ok(msg);
        }
    }
}

fn extract_rpc_error_message(err: &Value) -> String {
    let raw = err
        .as_object()
        .and_then(|o| o.get("message"))
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| err.to_string());
    redact_secrets_in_text(&raw)
}

fn parse_mcp_tool_result(call_resp: &Value, server: &str, tool: &str) -> Result<Value> {
    if let Some(err) = call_resp.get("error").filter(|v| !v.is_null()) {
        return Err(BridgeError::Mcp {
            server: server.to_string(),
            tool: tool.to_string(),
            message: format!("MCP tool '{tool}' error: {}", extract_rpc_error_message(err)),
        });
    }

    let result = call_resp.get("result").cloned().unwrap_or(Value::Null);
    let Some(res_obj) = result.as_object() else {
        return Ok(result);
    };

    let content = res_obj.get("content").and_then(Value::as_array);
    if res_obj.get("isError").and_then(Value::as_bool) == Some(true) {
        let err_parts: Vec<&str> = content
            .into_iter()
            .flatten()
            .filter_map(|item| item.as_object()?.get("text")?.as_str())
            .filter(|s| !s.is_empty())
            .collect();
        let joined = err_parts.join("\n");
        let trimmed = joined.trim();
        let msg = if trimmed.is_empty() {
            format!("MCP tool '{tool}' reported isError=true")
        } else {
            redact_secrets_in_text(trimmed)
        };
        return Err(BridgeError::Mcp {
            server: server.to_string(),
            tool: tool.to_string(),
            message: msg,
        });
    }

    if let Some(items) = content.filter(|arr| !arr.is_empty()) {
        if let Some(text) = items[0]
            .as_object()
            .and_then(|o| o.get("text"))
            .and_then(Value::as_str)
        {
            let stripped = text.trim_start();
            if items.len() == 1 {
                if stripped.starts_with('{') || stripped.starts_with('[') {
                    if let Ok(parsed) = serde_json::from_str::<Value>(stripped) {
                        return Ok(parsed);
                    }
                }
                return Ok(Value::String(text.to_string()));
            }
            let texts: Vec<&str> = items
                .iter()
                .filter_map(|c| c.as_object()?.get("text")?.as_str())
                .collect();
            if !texts.is_empty() {
                return Ok(Value::String(texts.join("\n")));
            }
            return Ok(result);
        }
    }

    Ok(res_obj
        .get("structuredContent")
        .cloned()
        .unwrap_or(result))
}

async fn cleanup_mcp_child(
    child: &mut Child,
    pg_guard: &mut ProcessGroupGuard,
    graceful_eof_wait: bool,
) {
    if let Ok(Some(_)) = child.try_wait() {
        pg_guard.disarm();
        return;
    }

    if graceful_eof_wait
        && matches!(
            tokio::time::timeout(Duration::from_millis(250), child.wait()).await,
            Ok(Ok(_))
        )
    {
        pg_guard.disarm();
        return;
    }

    if let Some(pgid) = pg_guard.pgid() {
        signal_process_group(pgid, libc::SIGTERM);
    }
    if matches!(
        tokio::time::timeout(Duration::from_secs(1), child.wait()).await,
        Ok(Ok(_))
    ) {
        pg_guard.disarm();
        return;
    }

    if let Some(pgid) = pg_guard.pgid() {
        signal_process_group(pgid, libc::SIGKILL);
    }
    let _ = tokio::time::timeout(Duration::from_secs(1), child.wait()).await;
    if let Ok(Some(_)) = child.try_wait() {
        pg_guard.disarm();
    }
}

/// Invoke a tool on a stdio MCP server binary using JSON-RPC 2.0 (`initialize`,
/// `notifications/initialized`, `tools/call`).
///
/// Spawns the server in a dedicated POSIX session (`setsid`), removes `BOT_TOKEN` from child env,
/// supports arbitrarily large JSON-RPC response lines (`> 4 MiB`), captures and redacts stderr,
/// and kills the entire child process group on timeout or cancellation/drop.
pub async fn call_stdio_mcp_tool(
    bin: &str,
    tool_name: &str,
    arguments: Value,
    env_overrides: Option<&HashMap<String, String>>,
    timeout_secs: f64,
) -> Result<Value> {
    call_stdio_mcp_cmd(&[bin], tool_name, arguments, env_overrides, timeout_secs).await
}

/// Invoke a tool on a stdio MCP server specified as a command slice `[program, arg1, ...]`.
pub async fn call_stdio_mcp_cmd<S: AsRef<str>>(
    cmd: &[S],
    tool_name: &str,
    arguments: Value,
    env_overrides: Option<&HashMap<String, String>>,
    timeout_secs: f64,
) -> Result<Value> {
    if cmd.is_empty() || cmd.iter().any(|part| part.as_ref().is_empty()) {
        return Err(BridgeError::Validation(
            "MCP command must be a non-empty list of non-empty strings".to_string(),
        ));
    }
    if tool_name.trim().is_empty() {
        return Err(BridgeError::Validation(
            "MCP tool_name must not be empty".to_string(),
        ));
    }
    if !timeout_secs.is_finite() || timeout_secs <= 0.0 {
        return Err(BridgeError::Validation(
            "MCP timeout_secs must be a positive finite number".to_string(),
        ));
    }

    let server_name = cmd[0].as_ref();
    let mut command = Command::new(server_name);
    for arg in &cmd[1..] {
        command.arg(arg.as_ref());
    }
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    // Strip bridge/systemd/linker secrets so third-party MCP subprocesses cannot read them.
    for key in crate::exec_backend::STRIPPED_ENV_KEYS {
        command.env_remove(key);
    }

    if let Some(overrides) = env_overrides {
        for (k, v) in overrides {
            if k != "BOT_TOKEN" {
                command.env(k, v);
            }
        }
    }
    configure_new_session(&mut command);

    let mut child = command.spawn().map_err(|e| BridgeError::Mcp {
        server: server_name.to_string(),
        tool: tool_name.to_string(),
        message: redact_secrets_in_text(&format!(
            "Failed to start MCP server {server_name}: {e}"
        )),
    })?;

    let mut pg_guard = ProcessGroupGuard::new(child.id());

    let Some(mut stdin) = child.stdin.take() else {
        cleanup_mcp_child(&mut child, &mut pg_guard, false).await;
        return Err(BridgeError::Mcp {
            server: server_name.to_string(),
            tool: tool_name.to_string(),
            message: "MCP subprocess stdin unavailable".to_string(),
        });
    };
    let Some(stdout) = child.stdout.take() else {
        drop(stdin);
        cleanup_mcp_child(&mut child, &mut pg_guard, false).await;
        return Err(BridgeError::Mcp {
            server: server_name.to_string(),
            tool: tool_name.to_string(),
            message: "MCP subprocess stdout unavailable".to_string(),
        });
    };
    let stderr_buf = Arc::new(Mutex::new(Vec::new()));
    let stderr_task = child
        .stderr
        .take()
        .map(|stderr| tokio::spawn(drain_stderr(stderr, Arc::clone(&stderr_buf))));

    let args_val = if arguments.is_null() {
        json!({})
    } else {
        arguments
    };

    let timeout_dur = Duration::from_secs_f64(timeout_secs);
    let mut stdout_reader = BufReader::new(stdout);

    let handshake_res: Result<Value> = match tokio::time::timeout(timeout_dur, async {
        send_jsonrpc(
            &mut stdin,
            &json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "agy-telegram", "version": "1.0"}
                }
            }),
        )
        .await?;

        let init_resp =
            read_jsonrpc_response(&mut stdout_reader, 1, server_name, tool_name, &stderr_buf)
                .await?;
        if let Some(err) = init_resp.get("error").filter(|v| !v.is_null()) {
            return Err(BridgeError::Mcp {
                server: server_name.to_string(),
                tool: tool_name.to_string(),
                message: format!(
                    "MCP initialize failed: {}",
                    extract_rpc_error_message(err)
                ),
            });
        }

        send_jsonrpc(
            &mut stdin,
            &json!({
                "jsonrpc": "2.0",
                "method": "notifications/initialized",
                "params": {}
            }),
        )
        .await?;

        send_jsonrpc(
            &mut stdin,
            &json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": tool_name,
                    "arguments": args_val
                }
            }),
        )
        .await?;

        let call_resp =
            read_jsonrpc_response(&mut stdout_reader, 2, server_name, tool_name, &stderr_buf)
                .await?;

        parse_mcp_tool_result(&call_resp, server_name, tool_name)
    })
    .await
    {
        Ok(inner) => inner,
        Err(_elapsed) => {
            let detail = format_redacted_stderr(&stderr_buf);
            let suffix = if detail.is_empty() {
                String::new()
            } else {
                format!(" ({detail})")
            };
            Err(BridgeError::Mcp {
                server: server_name.to_string(),
                tool: tool_name.to_string(),
                message: format!(
                    "MCP tool '{tool_name}' timed out after {timeout_secs:.2}s{suffix}"
                ),
            })
        }
    };

    let succeeded = handshake_res.is_ok();
    debug!(
        server = server_name,
        tool = tool_name,
        ok = succeeded,
        "finished stdio MCP call"
    );

    drop(stdin);
    drop(stdout_reader);
    cleanup_mcp_child(&mut child, &mut pg_guard, succeeded).await;

    if let Some(mut task) = stderr_task {
        if tokio::time::timeout(Duration::from_millis(150), &mut task)
            .await
            .is_err()
        {
            task.abort();
        }
    }

    handshake_res
}

/// Query a stdio MCP server's live `tools/list` catalog via JSON-RPC 2.0 (`initialize`,
/// `notifications/initialized`, `tools/list`) with strict secret scrubbing & process-group cleanup.
pub async fn list_stdio_mcp_tools<S: AsRef<str>>(
    cmd: &[S],
    env_overrides: Option<&HashMap<String, String>>,
    timeout_secs: f64,
) -> Result<Vec<Value>> {
    if cmd.is_empty() || cmd.iter().any(|part| part.as_ref().is_empty()) {
        return Err(BridgeError::Validation(
            "MCP command must be a non-empty list of non-empty strings".to_string(),
        ));
    }
    let server_name = cmd[0].as_ref();
    let mut command = Command::new(server_name);
    for arg in &cmd[1..] {
        command.arg(arg.as_ref());
    }
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    for key in crate::exec_backend::STRIPPED_ENV_KEYS {
        command.env_remove(key);
    }
    if let Some(overrides) = env_overrides {
        for (k, v) in overrides {
            if k != "BOT_TOKEN" {
                command.env(k, v);
            }
        }
    }
    configure_new_session(&mut command);

    let mut child = command.spawn().map_err(|e| BridgeError::Mcp {
        server: server_name.to_string(),
        tool: "tools/list".to_string(),
        message: redact_secrets_in_text(&format!("Failed to start MCP server {server_name}: {e}")),
    })?;
    let mut pg_guard = ProcessGroupGuard::new(child.id());

    let Some(mut stdin) = child.stdin.take() else {
        cleanup_mcp_child(&mut child, &mut pg_guard, false).await;
        return Err(BridgeError::Mcp {
            server: server_name.to_string(),
            tool: "tools/list".to_string(),
            message: "MCP subprocess stdin unavailable".to_string(),
        });
    };
    let Some(stdout) = child.stdout.take() else {
        drop(stdin);
        cleanup_mcp_child(&mut child, &mut pg_guard, false).await;
        return Err(BridgeError::Mcp {
            server: server_name.to_string(),
            tool: "tools/list".to_string(),
            message: "MCP subprocess stdout unavailable".to_string(),
        });
    };
    let stderr_buf = Arc::new(Mutex::new(Vec::new()));
    let stderr_task = child
        .stderr
        .take()
        .map(|stderr| tokio::spawn(drain_stderr(stderr, Arc::clone(&stderr_buf))));
    let timeout_dur = Duration::from_secs_f64(if timeout_secs.is_finite() {
        timeout_secs.clamp(2.0, 45.0)
    } else {
        15.0
    });
    let mut stdout_reader = BufReader::new(stdout);

    let res: Result<Vec<Value>> = match tokio::time::timeout(timeout_dur, async {
        send_jsonrpc(
            &mut stdin,
            &json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "agy-telegram", "version": "1.0"}
                }
            }),
        )
        .await?;
        let init_resp =
            read_jsonrpc_response(&mut stdout_reader, 1, server_name, "tools/list", &stderr_buf)
                .await?;
        if let Some(err) = init_resp.get("error").filter(|v| !v.is_null()) {
            return Err(BridgeError::Mcp {
                server: server_name.to_string(),
                tool: "tools/list".to_string(),
                message: format!("MCP initialize failed: {}", extract_rpc_error_message(err)),
            });
        }
        send_jsonrpc(
            &mut stdin,
            &json!({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}),
        )
        .await?;
        send_jsonrpc(
            &mut stdin,
            &json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
        )
        .await?;
        let list_resp =
            read_jsonrpc_response(&mut stdout_reader, 2, server_name, "tools/list", &stderr_buf)
                .await?;
        if let Some(err) = list_resp.get("error").filter(|v| !v.is_null()) {
            return Err(BridgeError::Mcp {
                server: server_name.to_string(),
                tool: "tools/list".to_string(),
                message: extract_rpc_error_message(err),
            });
        }
        let tools = list_resp
            .pointer("/result/tools")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        Ok(tools)
    })
    .await
    {
        Ok(inner) => inner,
        Err(_) => Err(BridgeError::Mcp {
            server: server_name.to_string(),
            tool: "tools/list".to_string(),
            message: format!("MCP tools/list timed out after {timeout_secs:.1}s"),
        }),
    };

    let succeeded = res.is_ok();
    drop(stdin);
    drop(stdout_reader);
    cleanup_mcp_child(&mut child, &mut pg_guard, succeeded).await;
    if let Some(mut task) = stderr_task {
        if tokio::time::timeout(Duration::from_millis(150), &mut task)
            .await
            .is_err()
        {
            task.abort();
        }
    }
    res
}

/// Idle eviction TTL for pooled persistent stdio MCP servers (5 minutes).
const MCP_POOL_IDLE_TTL: Duration = Duration::from_secs(300);

type McpPoolKey = (Vec<String>, Vec<(String, String)>);

struct PooledMcpConn {
    server_name: String,
    child: Child,
    pg_guard: ProcessGroupGuard,
    stdin: ChildStdin,
    stdout_reader: BufReader<ChildStdout>,
    stderr_buf: Arc<Mutex<Vec<u8>>>,
    stderr_task: Option<tokio::task::JoinHandle<()>>,
    next_id: u64,
    last_used: Instant,
}

impl PooledMcpConn {
    async fn spawn_and_init(
        cmd: &[String],
        env_overrides: Option<&HashMap<String, String>>,
        init_timeout: Duration,
    ) -> Result<Self> {
        let server_name = cmd[0].clone();
        let mut command = Command::new(&server_name);
        for arg in &cmd[1..] {
            command.arg(arg);
        }
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        for key in crate::exec_backend::STRIPPED_ENV_KEYS {
            command.env_remove(key);
        }
        if let Some(overrides) = env_overrides {
            for (k, v) in overrides {
                if k != "BOT_TOKEN" {
                    command.env(k, v);
                }
            }
        }
        configure_new_session(&mut command);

        let mut child = command.spawn().map_err(|e| BridgeError::Mcp {
            server: server_name.clone(),
            tool: "initialize".to_string(),
            message: redact_secrets_in_text(&format!(
                "Failed to start pooled MCP server {server_name}: {e}"
            )),
        })?;
        let mut pg_guard = ProcessGroupGuard::new(child.id());
        let Some(mut stdin) = child.stdin.take() else {
            cleanup_mcp_child(&mut child, &mut pg_guard, false).await;
            return Err(BridgeError::Mcp {
                server: server_name,
                tool: "initialize".to_string(),
                message: "Pooled MCP stdin unavailable".to_string(),
            });
        };
        let Some(stdout) = child.stdout.take() else {
            drop(stdin);
            cleanup_mcp_child(&mut child, &mut pg_guard, false).await;
            return Err(BridgeError::Mcp {
                server: server_name,
                tool: "initialize".to_string(),
                message: "Pooled MCP stdout unavailable".to_string(),
            });
        };
        let stderr_buf = Arc::new(Mutex::new(Vec::new()));
        let stderr_task = child
            .stderr
            .take()
            .map(|stderr| tokio::spawn(drain_stderr(stderr, Arc::clone(&stderr_buf))));
        let mut stdout_reader = BufReader::new(stdout);

        let init_res: Result<()> = match tokio::time::timeout(init_timeout, async {
            send_jsonrpc(
                &mut stdin,
                &json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {},
                        "clientInfo": {"name": "agy-telegram", "version": "2.0"}
                    }
                }),
            )
            .await?;
            let init_resp = read_jsonrpc_response(
                &mut stdout_reader,
                1,
                &server_name,
                "initialize",
                &stderr_buf,
            )
            .await?;
            if let Some(err) = init_resp.get("error").filter(|v| !v.is_null()) {
                return Err(BridgeError::Mcp {
                    server: server_name.clone(),
                    tool: "initialize".to_string(),
                    message: format!(
                        "MCP initialize failed: {}",
                        extract_rpc_error_message(err)
                    ),
                });
            }
            send_jsonrpc(
                &mut stdin,
                &json!({
                    "jsonrpc": "2.0",
                    "method": "notifications/initialized",
                    "params": {}
                }),
            )
            .await?;
            Ok(())
        })
        .await
        {
            Ok(r) => r,
            Err(_) => Err(BridgeError::Mcp {
                server: server_name.clone(),
                tool: "initialize".to_string(),
                message: "Pooled MCP initialize timed out".to_string(),
            }),
        };

        if let Err(e) = init_res {
            drop(stdin);
            drop(stdout_reader);
            cleanup_mcp_child(&mut child, &mut pg_guard, false).await;
            if let Some(t) = stderr_task {
                t.abort();
            }
            return Err(e);
        }

        Ok(Self {
            server_name,
            child,
            pg_guard,
            stdin,
            stdout_reader,
            stderr_buf,
            stderr_task,
            next_id: 2,
            last_used: Instant::now(),
        })
    }

    fn is_alive(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    async fn call_tool(
        &mut self,
        tool_name: &str,
        arguments: Value,
        timeout_dur: Duration,
    ) -> Result<Value> {
        let req_id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        let args_val = if arguments.is_null() {
            json!({})
        } else {
            arguments
        };
        let srv = self.server_name.clone();

        let call_res = tokio::time::timeout(timeout_dur, async {
            send_jsonrpc(
                &mut self.stdin,
                &json!({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "method": "tools/call",
                    "params": {
                        "name": tool_name,
                        "arguments": args_val
                    }
                }),
            )
            .await?;
            let resp = read_jsonrpc_response(
                &mut self.stdout_reader,
                req_id,
                &srv,
                tool_name,
                &self.stderr_buf,
            )
            .await?;
            parse_mcp_tool_result(&resp, &srv, tool_name)
        })
        .await;

        self.last_used = Instant::now();
        match call_res {
            Ok(inner) => inner,
            Err(_) => {
                let detail = format_redacted_stderr(&self.stderr_buf);
                let suffix = if detail.is_empty() {
                    String::new()
                } else {
                    format!(" ({detail})")
                };
                Err(BridgeError::Mcp {
                    server: srv,
                    tool: tool_name.to_string(),
                    message: format!(
                        "Pooled MCP tool '{tool_name}' timed out after {:.2}s{suffix}",
                        timeout_dur.as_secs_f64()
                    ),
                })
            }
        }
    }

    async fn shutdown(mut self) {
        drop(self.stdin);
        drop(self.stdout_reader);
        cleanup_mcp_child(&mut self.child, &mut self.pg_guard, false).await;
        if let Some(mut task) = self.stderr_task.take() {
            if tokio::time::timeout(Duration::from_millis(100), &mut task)
                .await
                .is_err()
            {
                task.abort();
            }
        }
    }
}

/// Default TTL (seconds) for caching verified read-only MCP tool responses inside [`McpClientPool`].
pub const DEFAULT_MCP_RO_CACHE_TTL_SECS: u64 = 45;
const MAX_MCP_RO_CACHE_ENTRIES: usize = 128;

/// Verified idempotent read-only MCP tools eligible for short-TTL in-memory caching.
/// Any tool NOT on this explicit allowlist bypasses the cache AND invalidates all cached
/// entries for the same MCP server so writes are never followed by stale reads.
pub fn is_readonly_mcp_tool(tool_name: &str) -> bool {
    matches!(
        tool_name.trim(),
        "memory_search"
            | "memory_list"
            | "memory_stats"
            | "memory_get_relations"
            | "memory_graph_search"
            | "memory_traverse"
            | "memory_decay_status"
            | "memory_graph_analysis"
            | "skillhub_search"
            | "skillhub_get"
            | "skillhub_catalog"
            | "skillhub_sources"
            | "skillhub_stats"
            | "search_skills"
            | "load_skill"
            | "get_skill"
            | "list_domains"
            | "list_repos"
            | "recommend_skills"
            | "catalog_stats"
            | "query_graph"
            | "get_node"
            | "get_section"
            | "get_neighbors"
            | "get_community"
            | "god_nodes"
            | "graph_stats"
            | "shortest_path"
            | "list_prs"
            | "get_pr_impact"
            | "resolve-library-id"
            | "query-docs"
            | "search_status"
            | "parse_dork_ast"
            | "uncensored_models"
    )
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RoCacheKey {
    pool_key: McpPoolKey,
    tool_name: String,
    args_json: String,
}

struct RoCacheEntry {
    value: Value,
    stored_at: Instant,
}

#[derive(Default)]
struct RoCache {
    map: HashMap<RoCacheKey, RoCacheEntry>,
    hits: u64,
    misses: u64,
}

/// Persistent warm pool of stdio MCP servers (eliminates repeated process spawn + handshake overhead)
/// with bounded short-TTL caching for verified read-only MCP tool calls and instant write invalidation.
pub struct McpClientPool {
    entries: AsyncMutex<HashMap<McpPoolKey, Arc<AsyncMutex<Option<PooledMcpConn>>>>>,
    ro_cache_ttl_secs: std::sync::atomic::AtomicU64,
    ro_cache: std::sync::Mutex<RoCache>,
    seen_config_epoch: std::sync::atomic::AtomicU64,
}

impl Default for McpClientPool {
    fn default() -> Self {
        Self::new()
    }
}

impl McpClientPool {
    pub fn new() -> Self {
        Self {
            entries: AsyncMutex::new(HashMap::new()),
            ro_cache_ttl_secs: std::sync::atomic::AtomicU64::new(DEFAULT_MCP_RO_CACHE_TTL_SECS),
            ro_cache: std::sync::Mutex::new(RoCache::default()),
            seen_config_epoch: std::sync::atomic::AtomicU64::new(
                crate::mcp_config::mcp_config_epoch(),
            ),
        }
    }

    fn ro_cache_epoch_stale(&self, cur_epoch: u64) -> bool {
        let prev = self
            .seen_config_epoch
            .swap(cur_epoch, std::sync::atomic::Ordering::SeqCst);
        if prev != cur_epoch {
            self.clear_ro_cache();
            true
        } else {
            false
        }
    }

    /// Clear all cached read-only MCP responses (e.g. after out-of-band mutations).
    pub fn clear_ro_cache(&self) {
        if let Ok(mut c) = self.ro_cache.lock() {
            c.map.clear();
        }
    }

    /// Configure the read-only MCP tool response TTL (`0` disables caching).
    pub fn set_ro_cache_ttl(&self, ttl: Duration) {
        let secs = ttl.as_secs().min(600);
        self.ro_cache_ttl_secs
            .store(secs, std::sync::atomic::Ordering::Relaxed);
        if secs == 0 {
            if let Ok(mut c) = self.ro_cache.lock() {
                c.map.clear();
            }
        }
    }

    /// Return `(hits, misses)` counters for the read-only MCP TTL cache.
    pub fn ro_cache_stats(&self) -> (u64, u64) {
        self.ro_cache
            .lock()
            .map(|c| (c.hits, c.misses))
            .unwrap_or((0, 0))
    }

    fn ro_cache_get(&self, key: &RoCacheKey, ttl: Duration) -> Option<Value> {
        let mut c = self.ro_cache.lock().ok()?;
        let now = Instant::now();
        if let Some(entry) = c.map.get(key) {
            if now.saturating_duration_since(entry.stored_at) < ttl {
                let val = entry.value.clone();
                c.hits = c.hits.saturating_add(1);
                return Some(val);
            }
        }
        c.map.remove(key);
        c.misses = c.misses.saturating_add(1);
        None
    }

    fn ro_cache_put(&self, key: RoCacheKey, value: Value, ttl: Duration) {
        if let Ok(mut c) = self.ro_cache.lock() {
            let now = Instant::now();
            if c.map.len() >= MAX_MCP_RO_CACHE_ENTRIES {
                c.map
                    .retain(|_, v| now.saturating_duration_since(v.stored_at) < ttl);
                if c.map.len() >= MAX_MCP_RO_CACHE_ENTRIES {
                    if let Some(oldest) = c
                        .map
                        .iter()
                        .min_by_key(|(_, v)| v.stored_at)
                        .map(|(k, _)| k.clone())
                    {
                        c.map.remove(&oldest);
                    }
                }
            }
            c.map.insert(
                key,
                RoCacheEntry {
                    value,
                    stored_at: now,
                },
            );
        }
    }

    fn ro_cache_invalidate_server(&self, pool_key: &McpPoolKey) {
        if let Ok(mut c) = self.ro_cache.lock() {
            c.map.retain(|k, _| &k.pool_key != pool_key);
        }
    }

    fn make_key<S: AsRef<str>>(
        cmd: &[S],
        env_overrides: Option<&HashMap<String, String>>,
    ) -> McpPoolKey {
        let cmd_vec: Vec<String> = cmd.iter().map(|s| s.as_ref().to_string()).collect();
        let mut env_vec: Vec<(String, String)> = env_overrides
            .map(|m| {
                m.iter()
                    .filter(|(k, _)| k.as_str() != "BOT_TOKEN")
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect()
            })
            .unwrap_or_default();
        env_vec.sort();
        (cmd_vec, env_vec)
    }

    /// Invoke a tool via a warm pooled stdio MCP process, automatically respawning once if the
    /// cached process exited or broke its pipe between calls.
    pub async fn call_pooled_stdio_mcp_cmd<S: AsRef<str>>(
        &self,
        cmd: &[S],
        tool_name: &str,
        arguments: Value,
        env_overrides: Option<&HashMap<String, String>>,
        timeout_secs: f64,
    ) -> Result<Value> {
        if cmd.is_empty() || cmd.iter().any(|part| part.as_ref().is_empty()) {
            return Err(BridgeError::Validation(
                "MCP command must be a non-empty list of non-empty strings".to_string(),
            ));
        }
        if tool_name.trim().is_empty() {
            return Err(BridgeError::Validation(
                "MCP tool_name must not be empty".to_string(),
            ));
        }
        if !timeout_secs.is_finite() || timeout_secs <= 0.0 {
            return Err(BridgeError::Validation(
                "MCP timeout_secs must be a positive finite number".to_string(),
            ));
        }

        let key = Self::make_key(cmd, env_overrides);
        let ttl_secs = self
            .ro_cache_ttl_secs
            .load(std::sync::atomic::Ordering::Relaxed);
        let cache_ttl = Duration::from_secs(ttl_secs);
        let cacheable = ttl_secs > 0 && is_readonly_mcp_tool(tool_name);
        let cache_key = if cacheable {
            let ck = RoCacheKey {
                pool_key: key.clone(),
                tool_name: tool_name.trim().to_string(),
                args_json: serde_json::to_string(&arguments).unwrap_or_default(),
            };
            if let Some(hit) = self.ro_cache_get(&ck, cache_ttl) {
                return Ok(hit);
            }
            Some(ck)
        } else {
            // Mutating or non-allowlisted tool: purge cached read-only entries for this server.
            self.ro_cache_invalidate_server(&key);
            None
        };

        let cmd_owned = key.0.clone();

        let cur_epoch = crate::mcp_config::mcp_config_epoch();
        let slot = {
            let mut map = self.entries.lock().await;
            Arc::clone(
                map.entry(key.clone())
                    .or_insert_with(|| Arc::new(AsyncMutex::new(None))),
            )
        };

        let timeout_dur = Duration::from_secs_f64(timeout_secs);
        let init_timeout = timeout_dur.min(Duration::from_secs(20));

        let mut guard = slot.lock().await;

        // Evict stale or dead connection (or one spawned before an mcp_config mutation)
        let need_evict = match guard.as_mut() {
            Some(conn) => {
                conn.last_used.elapsed() > MCP_POOL_IDLE_TTL
                    || !conn.is_alive()
                    || self.ro_cache_epoch_stale(cur_epoch)
            }
            None => false,
        };
        if need_evict {
            if let Some(old) = guard.take() {
                old.shutdown().await;
            }
        }

        let mut was_warm = guard.is_some();
        let mut conn = match guard.take() {
            Some(c) => c,
            None => PooledMcpConn::spawn_and_init(&cmd_owned, env_overrides, init_timeout).await?,
        };

        // Hold `conn` outside `guard` across the await so dropping a cancelled future
        // drops `conn` (killing the child) instead of leaving a desynced stream in the pool.
        let first_res = conn
            .call_tool(tool_name, arguments.clone(), timeout_dur)
            .await;

        let (final_res, maybe_reusable) = match first_res {
            Ok(val) => (Ok(val), Some(conn)),
            Err(err) => {
                let err_msg = err.to_string();
                let transport_broken = err_msg.contains("closed stdout unexpectedly")
                    || err_msg.contains("Broken pipe")
                    || err_msg.contains("timed out")
                    || err_msg.contains("failed reading MCP stdout")
                    || err_msg.contains("writing MCP JSON-RPC");

                if transport_broken {
                    conn.shutdown().await;
                    // Retry once transparently if we hit a dead warm connection (not a timeout)
                    if was_warm && !err_msg.contains("timed out") {
                        was_warm = false;
                        let _ = was_warm;
                        let mut fresh =
                            PooledMcpConn::spawn_and_init(&cmd_owned, env_overrides, init_timeout)
                                .await?;
                        let retry_res = fresh
                            .call_tool(tool_name, arguments, timeout_dur)
                            .await;
                        match retry_res {
                            Ok(val) => (Ok(val), Some(fresh)),
                            Err(retry_err) => {
                                fresh.shutdown().await;
                                (Err(retry_err), None)
                            }
                        }
                    } else {
                        (Err(err), None)
                    }
                } else {
                    (Err(err), Some(conn))
                }
            }
        };

        if let Some(reusable) = maybe_reusable {
            if crate::mcp_config::mcp_config_epoch() == cur_epoch {
                *guard = Some(reusable);
            } else {
                reusable.shutdown().await;
            }
        }

        if let (Ok(ref val), Some(ck)) = (&final_res, cache_key) {
            self.ro_cache_put(ck, val.clone(), cache_ttl);
        }
        final_res
    }

    /// Gracefully shut down and clear all warm pooled MCP servers.
    pub async fn clear(&self) {
        if let Ok(mut c) = self.ro_cache.lock() {
            c.map.clear();
        }
        let slots: Vec<Arc<AsyncMutex<Option<PooledMcpConn>>>> = {
            let mut map = self.entries.lock().await;
            map.drain().map(|(_, v)| v).collect()
        };
        for slot in slots {
            let mut g = slot.lock().await;
            if let Some(conn) = g.take() {
                conn.shutdown().await;
            }
        }
    }
}

/// Process-wide persistent stdio MCP connection pool.
pub fn global_mcp_pool() -> &'static McpClientPool {
    static POOL: OnceLock<McpClientPool> = OnceLock::new();
    POOL.get_or_init(McpClientPool::new)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    fn write_mock_mcp(dir: &TempDir, name: &str, body: &str) -> String {
        let path = dir.path().join(name);
        let script = format!("#!/usr/bin/env python3\nimport json, os, sys, time\n{body}\n");
        fs::write(&path, script).unwrap();
        let mut perms = fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&path, perms).unwrap();
        path.to_string_lossy().into_owned()
    }

    #[test]
    fn test_secret_redaction_and_benign_text() {
        let samples = [
            "sk-proj-1234567890abcdef",
            "ghp_abcdefghij1234567890",
            "github_pat_1234567890abcdef_xyz",
            "AKIA1234567890ABCDEF",
            "ASIA1234567890ABCDEF",
            "xoxb-1234567890-abcdef",
            "AIzaSyD-1234567890abcdefghij",
            "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZ_1234",
            "-----BEGIN RSA PRIVATE KEY-----",
            "BOT_TOKEN=999999:secret_value",
            "DATABASE_URL: postgres://u:p@db/app",
            "postgres://user:pass@localhost:5432/db",
            "Bearer abcdefghijklmnopqrstuvwxyz",
        ];
        for s in samples {
            assert!(looks_like_secret(s), "expected secret match for {s}");
            let red = redact_secrets_in_text(&format!("prefix {s} suffix"));
            assert!(!red.contains(s), "secret leaked in {red}");
            assert!(red.contains("[REDACTED]"));
        }

        // Benign phrases containing `sk-` inside words must NOT match
        assert!(!looks_like_secret("task-123 note"));
        assert!(!looks_like_secret("Ask user before purge"));
        assert_eq!(redact_secrets_in_text("task-123 note"), "task-123 note");
    }

    #[tokio::test]
    async fn test_stdio_mcp_handshake_notifications_env_and_json_parse() {
        let dir = TempDir::new().unwrap();
        let srv = write_mock_mcp(
            &dir,
            "mock_mcp.py",
            r#"
for raw in sys.stdin:
    msg = json.loads(raw)
    method = msg.get("method")
    if method == "initialize":
        print(json.dumps({"jsonrpc": "2.0", "method": "notifications/message", "params": {"ok": True}}), flush=True)
        print(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": {"protocolVersion": "2024-11-05"}}), flush=True)
    elif method == "notifications/initialized":
        continue
    elif method == "tools/call":
        args = msg["params"]["arguments"]
        payload = {
            "tool": msg["params"]["name"],
            "args": args,
            "has_bot_token": "BOT_TOKEN" in os.environ,
            "override": os.environ.get("TEST_CUSTOM_ENV"),
        }
        print(json.dumps({
            "jsonrpc": "2.0",
            "id": msg["id"],
            "result": {"content": [{"type": "text", "text": "  " + json.dumps(payload)}]}
        }), flush=True)
        break
"#,
        );

        let mut overrides = HashMap::new();
        overrides.insert("TEST_CUSTOM_ENV".to_string(), "ok-val".to_string());
        overrides.insert("BOT_TOKEN".to_string(), "999999:TOP_SECRET_BOT_TOKEN_123456".to_string());

        let res = call_stdio_mcp_tool(
            &srv,
            "echo_tool",
            json!({"x": 42}),
            Some(&overrides),
            5.0,
        )
        .await
        .unwrap();

        assert_eq!(
            res,
            json!({
                "tool": "echo_tool",
                "args": {"x": 42},
                "has_bot_token": false,
                "override": "ok-val"
            })
        );
    }

    #[tokio::test]
    async fn test_stdio_mcp_large_over_4mb_payload_and_markdown_bracket() {
        let dir = TempDir::new().unwrap();
        let srv = write_mock_mcp(
            &dir,
            "mock_big.py",
            r#"
for raw in sys.stdin:
    msg = json.loads(raw)
    if msg.get("method") == "initialize":
        print(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": {}}), flush=True)
    elif msg.get("method") == "tools/call":
        kind = msg["params"]["arguments"].get("kind")
        if kind == "big_json":
            txt = json.dumps({"blob": "B" * (5 * 1024 * 1024)})
        else:
            txt = "[Note]: large markdown\n" + ("A" * 120_000)
        print(json.dumps({
            "jsonrpc": "2.0",
            "id": msg["id"],
            "result": {"content": [{"type": "text", "text": txt}]}
        }), flush=True)
        break
"#,
        );

        let res_big = call_stdio_mcp_tool(&srv, "get_big", json!({"kind": "big_json"}), None, 10.0)
            .await
            .unwrap();
        assert_eq!(res_big["blob"].as_str().unwrap().len(), 5 * 1024 * 1024);

        let res_md = call_stdio_mcp_tool(&srv, "get_big", json!({"kind": "md"}), None, 5.0)
            .await
            .unwrap();
        let md_str = res_md.as_str().unwrap();
        assert!(md_str.starts_with("[Note]: large markdown\n"));
        assert_eq!(md_str.len(), "[Note]: large markdown\n".len() + 120_000);
    }

    #[tokio::test]
    async fn test_stdio_mcp_errors_redaction_timeout_and_pgid_cleanup() {
        let dir = TempDir::new().unwrap();
        let srv_err = write_mock_mcp(
            &dir,
            "mock_err.py",
            r#"
for raw in sys.stdin:
    msg = json.loads(raw)
    if msg.get("method") == "initialize":
        print(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": {}}), flush=True)
    elif msg.get("method") == "tools/call":
        print(json.dumps({
            "jsonrpc": "2.0",
            "id": msg["id"],
            "result": {"isError": True, "content": [{"type": "text", "text": "boom sk-secret1234567890"}]}
        }), flush=True)
        break
"#,
        );
        let err = call_stdio_mcp_tool(&srv_err, "fail_tool", json!({}), None, 5.0)
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("boom"));
        assert!(!msg.contains("sk-secret1234567890"));
        assert!(msg.contains("[REDACTED]"));

        let srv_crash = write_mock_mcp(
            &dir,
            "mock_crash.py",
            r#"
sys.stderr.write("fatal: BOT_TOKEN=123456:SECRET_VALUE_TOKEN_ABCDEFGHIJK\n")
sys.stderr.flush()
sys.exit(1)
"#,
        );
        let crash_err = call_stdio_mcp_tool(&srv_crash, "x", json!({}), None, 5.0)
            .await
            .unwrap_err()
            .to_string();
        assert!(!crash_err.contains("SECRET_VALUE_TOKEN_ABCDEFGHIJK"));
        assert!(crash_err.contains("[REDACTED]"));

        // Timeout kills entire process group including spawned child sleep process
        let pid_file = dir.path().join("child.pid");
        let srv_hang = write_mock_mcp(
            &dir,
            "mock_hang.py",
            &format!(
                r#"
import subprocess
p = subprocess.Popen(["sleep", "60"])
open({pid_path:?}, "w").write(str(p.pid))
time.sleep(60)
"#,
                pid_path = pid_file.to_string_lossy().to_string()
            ),
        );
        let timeout_err = call_stdio_mcp_tool(&srv_hang, "slow", json!({}), None, 0.35)
            .await
            .unwrap_err()
            .to_string();
        assert!(timeout_err.contains("timed out"));

        if pid_file.exists() {
            let child_pid: libc::pid_t = fs::read_to_string(&pid_file).unwrap().trim().parse().unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;
            // Verify descendant process was killed by process-group cleanup
            let alive = unsafe { libc::kill(child_pid, 0) } == 0;
            assert!(!alive, "orphan child {child_pid} survived process-group cleanup");
        }

        // Missing binary returns Mcp error
        let missing = call_stdio_mcp_tool(
            &dir.path().join("missing-bin").to_string_lossy(),
            "x",
            json!({}),
            None,
            2.0,
        )
        .await;
        assert!(matches!(missing, Err(BridgeError::Mcp { .. })));
    }

    #[tokio::test]
    async fn test_stdio_mcp_drop_cleanup_rpc_error_and_multicontent() {
        let dir = TempDir::new().unwrap();
        let srv_rpc_err = write_mock_mcp(
            &dir,
            "mock_rpc_err.py",
            r#"
for raw in sys.stdin:
    msg = json.loads(raw)
    if msg.get("method") == "initialize":
        print(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": {}}), flush=True)
    elif msg.get("method") == "tools/call":
        print(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "error": {"code": -32601, "message": "not found"}}), flush=True)
        break
"#,
        );
        let rpc_err = call_stdio_mcp_tool(&srv_rpc_err, "missing_tool", json!({}), None, 5.0)
            .await
            .unwrap_err()
            .to_string();
        assert!(rpc_err.contains("not found"));

        let srv_multi = write_mock_mcp(
            &dir,
            "mock_multi.py",
            r#"
for raw in sys.stdin:
    msg = json.loads(raw)
    if msg.get("method") == "initialize":
        print(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": {}}), flush=True)
    elif msg.get("method") == "tools/call":
        print(json.dumps({
            "jsonrpc": "2.0",
            "id": msg["id"],
            "result": {"content": [{"type": "text", "text": "part1"}, {"type": "text", "text": "part2"}]}
        }), flush=True)
        break
"#,
        );
        let multi = call_stdio_mcp_tool(&srv_multi, "multi", json!({}), None, 5.0)
            .await
            .unwrap();
        assert_eq!(multi, json!("part1\npart2"));

        // Aborting future drops ProcessGroupGuard and kills child process group
        let pid_file = dir.path().join("abort_child.pid");
        let srv_abort = write_mock_mcp(
            &dir,
            "mock_abort.py",
            &format!(
                r#"
import subprocess
p = subprocess.Popen(["sleep", "60"])
open({pid_path:?}, "w").write(str(p.pid))
time.sleep(60)
"#,
                pid_path = pid_file.to_string_lossy().to_string()
            ),
        );
        let handle = tokio::spawn(async move {
            call_stdio_mcp_tool(&srv_abort, "hang", json!({}), None, 30.0).await
        });
        tokio::time::sleep(Duration::from_millis(150)).await;
        handle.abort();
        let _ = handle.await;
        if pid_file.exists() {
            let child_pid: libc::pid_t = fs::read_to_string(&pid_file).unwrap().trim().parse().unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;
            let alive = unsafe { libc::kill(child_pid, 0) } == 0;
            assert!(!alive, "orphan child {child_pid} survived future abort");
        }
    }

    #[tokio::test]
    async fn test_mcp_client_pool_reuses_warm_process_and_recovers_on_crash() {
        let dir = TempDir::new().unwrap();
        let srv = write_mock_mcp(
            &dir,
            "mock_pooled.py",
            r#"
call_n = 0
for raw in sys.stdin:
    msg = json.loads(raw)
    m = msg.get("method")
    if m == "initialize":
        print(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": {}}), flush=True)
    elif m == "tools/call":
        call_n += 1
        if msg["params"]["arguments"].get("crash"):
            sys.exit(1)
        out = {"pid": os.getpid(), "call_n": call_n}
        print(json.dumps({
            "jsonrpc": "2.0",
            "id": msg["id"],
            "result": {"content": [{"type": "text", "text": json.dumps(out)}]}
        }), flush=True)
"#,
        );

        let pool = McpClientPool::new();
        let r1 = pool
            .call_pooled_stdio_mcp_cmd(&[&srv], "ping", json!({}), None, 5.0)
            .await
            .unwrap();
        let r2 = pool
            .call_pooled_stdio_mcp_cmd(&[&srv], "ping", json!({}), None, 5.0)
            .await
            .unwrap();
        assert_eq!(r1["pid"], r2["pid"], "expected warm process reuse");
        assert_eq!(r1["call_n"], 1);
        assert_eq!(r2["call_n"], 2);

        // Trigger crash on cached server -> subsequent call recovers cleanly with a new PID
        let _ = pool
            .call_pooled_stdio_mcp_cmd(&[&srv], "ping", json!({"crash": true}), None, 5.0)
            .await;
        let r3 = pool
            .call_pooled_stdio_mcp_cmd(&[&srv], "ping", json!({}), None, 5.0)
            .await
            .unwrap();
        assert_ne!(r3["pid"], r1["pid"], "expected respawned server after crash");
        assert_eq!(r3["call_n"], 1);

        pool.clear().await;
    }

    #[tokio::test]
    async fn test_mcp_pool_readonly_ttl_cache_and_write_invalidation() {
        let dir = TempDir::new().unwrap();
        let srv = write_mock_mcp(
            &dir,
            "mock_ro_cache.py",
            r#"
call_n = 0
for raw in sys.stdin:
    msg = json.loads(raw)
    m = msg.get("method")
    if m == "initialize":
        print(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": {}}), flush=True)
    elif m == "tools/call":
        call_n += 1
        out = {"tool": msg["params"]["name"], "call_n": call_n}
        print(json.dumps({
            "jsonrpc": "2.0",
            "id": msg["id"],
            "result": {"content": [{"type": "text", "text": json.dumps(out)}]}
        }), flush=True)
"#,
        );

        let pool = McpClientPool::new();
        pool.set_ro_cache_ttl(Duration::from_secs(60));

        // 1. First read-only memory_search hits server (call_n = 1)
        let r1 = pool
            .call_pooled_stdio_mcp_cmd(&[&srv], "memory_search", json!({"query": "a"}), None, 5.0)
            .await
            .unwrap();
        assert_eq!(r1["call_n"], 1);

        // 2. Second identical read-only call hits cache (still call_n = 1!)
        let r2 = pool
            .call_pooled_stdio_mcp_cmd(&[&srv], "memory_search", json!({"query": "a"}), None, 5.0)
            .await
            .unwrap();
        assert_eq!(r2["call_n"], 1);
        assert_eq!(pool.ro_cache_stats(), (1, 1));

        // 3. Mutating memory_store executes on server (call_n = 2) AND invalidates server cache
        let w = pool
            .call_pooled_stdio_mcp_cmd(&[&srv], "memory_store", json!({"content": {}}), None, 5.0)
            .await
            .unwrap();
        assert_eq!(w["call_n"], 2);

        // 4. Subsequent memory_search must NOT return stale cached value (call_n = 3)
        let r3 = pool
            .call_pooled_stdio_mcp_cmd(&[&srv], "memory_search", json!({"query": "a"}), None, 5.0)
            .await
            .unwrap();
        assert_eq!(r3["call_n"], 3);

        pool.clear().await;
    }
}
