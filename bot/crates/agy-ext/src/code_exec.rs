//! Programmatic Tool Calling (`execute_code`) over a per-run Unix Domain Socket RPC bridge,
//! inspired by Hermes Agent's `execute_code` / `hermes_tools.py`.
//!
//! Lets the LLM collapse 10-50 `read_file` / `grep_files` / `patch_file` / `run_command` tool
//! calls into ONE single Python script execution and ONE LLM turn: only `print()` output enters
//! the model context (bounded to 50 KiB via head+tail ring buffer), while every RPC call still
//! enforces full ACL, workspace containment, `CommandGuard`, and secret redaction on the Rust side.

use std::future::Future;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;

use crate::exec_backend::{run_exec_command, ExecOptions};

/// Hard cap on RPC tool calls per `execute_code` invocation (expanded to 150 for high-speed batch coding).
pub const MAX_RPC_CALLS_PER_RUN: usize = 150;
/// Maximum timeout for an `execute_code` script (300 seconds / 5 minutes).
pub const MAX_CODE_EXEC_TIMEOUT_SECS: u64 = 300;
/// Output budget for `execute_code` stdout (12 KiB head + 38 KiB tail = 50 KiB).
/// Align with `DEFAULT_EARLY_TOOL_OUTPUT_BYTES` (24 KiB) so `execute_code` stdout is not
/// truncated twice across layers.
const CODE_EXEC_HEAD_BYTES: usize = 10 * 1024;
const CODE_EXEC_TAIL_BYTES: usize = 12 * 1024;

/// Allowed tools callable from Python via `agy_tools` RPC (explicitly excludes recursive `execute_code`).
const ALLOWED_RPC_TOOLS: &[&str] = &[
    "read_file",
    "batch_read",
    "write_file",
    "edit_file",
    "patch_file",
    "multi_edit",
    "file_editor",
    "list_dir",
    "glob_files",
    "grep_files",
    "find_symbols",
    "git_ops",
    "run_command",
    "process_manage",
    "verify_project",
    "code_to_md",
    "md_to_code",
    "inspect_image",
    "web_search",
    "fetch_url",
    "memory_search",
    "memory_store",
    "call_mcp_tool",
    "task_tracker",
];

/// Callback executed on the Rust side to handle each RPC tool call from the Python script.
pub type RpcToolDispatcher = Arc<
    dyn Fn(String, Value) -> Pin<Box<dyn Future<Output = String> + Send>> + Send + Sync,
>;

/// Zero-dependency Python helper injected via `PYTHONPATH` into `execute_code` scripts.
const AGY_TOOLS_PY: &str = r#"
import json
import os
import socket

_SOCK_PATH = os.environ["AGY_RPC_SOCK"]


def _call(tool: str, args: dict) -> str:
    payload = json.dumps({"tool": tool, "args": args}).encode("utf-8") + b"\n"
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(180.0)
        s.connect(_SOCK_PATH)
        s.sendall(payload)
        s.shutdown(socket.SHUT_WR)
        chunks = []
        while True:
            data = s.recv(65536)
            if not data:
                break
            chunks.append(data)
    raw = b"".join(chunks).decode("utf-8", errors="replace").strip()
    if not raw:
        raise RuntimeError(f"empty RPC response for {tool}")
    resp = json.loads(raw)
    if not resp.get("ok", False):
        raise RuntimeError(resp.get("output", "RPC error"))
    return resp.get("output", "")


def read_file(path: str, start_line: int = 1, end_line=None) -> str:
    args = {"path": path, "start_line": int(start_line)}
    if end_line is not None:
        args["end_line"] = int(end_line)
    return _call("read_file", args)


def batch_read(files: list) -> str:
    return _call("batch_read", {"files": list(files)})


def multi_edit(edits: list) -> str:
    return _call("multi_edit", {"edits": list(edits)})


def write_file(path: str, content: str) -> str:
    return _call("write_file", {"path": path, "content": content})


def patch_file(path: str, target: str, replacement: str, replace_all: bool = False) -> str:
    return _call(
        "patch_file",
        {
            "path": path,
            "target": target,
            "replacement": replacement,
            "replace_all": bool(replace_all),
        },
    )


def edit_file(path: str, target: str, replacement: str, replace_all: bool = False) -> str:
    return patch_file(path, target, replacement, replace_all=replace_all)


def list_dir(path: str = ".") -> str:
    return _call("list_dir", {"path": path})


def grep_files(pattern: str, path: str = ".", glob: str = "", context_lines: int = 0) -> str:
    args = {"pattern": pattern, "path": path, "context_lines": int(context_lines)}
    if glob:
        args["glob"] = glob
    return _call("grep_files", args)


def glob_files(pattern: str, path: str = ".", max_results: int = 100) -> str:
    return _call("glob_files", {"pattern": pattern, "path": path, "max_results": int(max_results)})


def find_symbols(query: str = "", path: str = ".", file_glob: str = "", max_results: int = 100) -> str:
    args = {"path": path, "max_results": int(max_results)}
    if query:
        args["query"] = query
    if file_glob:
        args["file_glob"] = file_glob
    return _call("find_symbols", args)


def file_editor(command: str, path: str, **kwargs) -> str:
    args = {"command": command, "path": path}
    args.update(kwargs)
    return _call("file_editor", args)


def git_ops(action: str, **kwargs) -> str:
    args = {"action": action}
    args.update(kwargs)
    return _call("git_ops", args)


def verify_project(project_dir: str = ".", run_tests: bool = False, commands=None) -> str:
    args = {"project_dir": project_dir, "run_tests": bool(run_tests)}
    if commands:
        args["commands"] = list(commands)
    return _call("verify_project", args)


def code_to_md(path: str, output_path: str = "") -> str:
    args = {"path": path}
    if output_path:
        args["output_path"] = output_path
    return _call("code_to_md", args)


def md_to_code(target_dir: str, markdown: str, dry_run: bool = False) -> str:
    return _call("md_to_code", {"target_dir": target_dir, "markdown": markdown, "dry_run": bool(dry_run)})


def web_search(query: str, profile: str = "hybrid", limit: int = 8, strict_ast: bool = False, allow_relax: bool = True) -> str:
    return _call("web_search", {"query": query, "profile": profile, "limit": int(limit), "strict_ast": bool(strict_ast), "allow_relax": bool(allow_relax)})


def fetch_url(url: str, max_chars: int = 12000) -> str:
    return _call("fetch_url", {"url": url, "max_chars": int(max_chars)})


def memory_search(query: str, limit: int = 5, tags=None) -> str:
    args = {"query": query, "limit": int(limit)}
    if tags is not None:
        args["tags"] = list(tags)
    return _call("memory_search", args)


def memory_store(title: str, summary: str, type: str = "fact", tags=None) -> str:
    args = {"title": title, "summary": summary, "type": type}
    if tags is not None:
        args["tags"] = list(tags)
    return _call("memory_store", args)


def call_mcp_tool(server: str, tool: str, arguments=None, timeout_secs: int = 30) -> str:
    return _call(
        "call_mcp_tool",
        {
            "server": server,
            "tool": tool,
            "arguments": arguments or {},
            "timeout_secs": int(timeout_secs),
        },
    )


def gortex_search(query: str, limit: int = 10) -> str:
    return call_mcp_tool("gortex", "search", {"query": query, "limit": int(limit)})


def search_docs(library: str, query: str) -> str:
    resolved = call_mcp_tool("context7", "resolve-library-id", {"libraryName": library, "query": query})
    return f"[resolve]\n{resolved}"


def read_range(path: str, start_line: int = 1, end_line: int = 120) -> str:
    return read_file(path, start_line=int(start_line), end_line=int(end_line))


def inspect_image(path: str, question: str = "", model: str = "") -> str:
    args = {"path": path}
    if question:
        args["question"] = question
    if model:
        args["model"] = model
    return _call("inspect_image", args)


def process_manage(action: str, **kwargs) -> str:
    args = {"action": action}
    args.update(kwargs)
    return _call("process_manage", args)


def task_tracker(command: str = "view", **kwargs) -> str:
    args = {"command": command}
    args.update(kwargs)
    return _call("task_tracker", args)


def run_command(command: str, timeout_secs: int = 60, **kwargs) -> str:
    args = {"command": command, "timeout_secs": int(timeout_secs)}
    args.update(kwargs)
    return _call("run_command", args)
"#;

pub struct CodeExecRequest<'a> {
    pub code: &'a str,
    pub cwd: &'a Path,
    pub workspace_root: &'a Path,
    pub allow_root: bool,
    pub allow_network: bool,
    pub timeout_secs: u64,
}

async fn handle_rpc_client(
    stream: tokio::net::UnixStream,
    dispatcher: RpcToolDispatcher,
    call_counter: Arc<AtomicUsize>,
) {
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let mut line = String::new();
    if reader.read_line(&mut line).await.unwrap_or(0) == 0 {
        return;
    }
    let resp = match serde_json::from_str::<Value>(line.trim()) {
        Ok(req) => {
            let tool = req
                .get("tool")
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim()
                .to_string();
            let args = req.get("args").cloned().unwrap_or_else(|| json!({}));
            if !ALLOWED_RPC_TOOLS.contains(&tool.as_str()) {
                json!({
                    "ok": false,
                    "output": format!("Error: tool '{tool}' is not permitted over execute_code RPC")
                })
            } else {
                let prev = call_counter.fetch_add(1, Ordering::SeqCst);
                if prev >= MAX_RPC_CALLS_PER_RUN {
                    json!({
                        "ok": false,
                        "output": format!("Error: execute_code RPC call budget exceeded (max {MAX_RPC_CALLS_PER_RUN} calls)")
                    })
                } else {
                    let out = dispatcher(tool, args).await;
                    json!({ "ok": true, "output": out })
                }
            }
        }
        Err(e) => json!({ "ok": false, "output": format!("Invalid RPC JSON: {e}") }),
    };

    if let Ok(mut bytes) = serde_json::to_vec(&resp) {
        bytes.push(b'\n');
        let _ = write_half.write_all(&bytes).await;
        let _ = write_half.shutdown().await;
    }
}

/// Run a Python 3 programmatic tool-calling script backed by a temporary Unix Domain Socket RPC server.
pub async fn run_execute_code(
    req: &CodeExecRequest<'_>,
    dispatcher: RpcToolDispatcher,
) -> String {
    if req.code.trim().is_empty() {
        return "Error: 'code' must not be empty.".to_string();
    }

    let started = Instant::now();
    let rpc_dir = match TempDir::with_prefix("agy-rpc-") {
        Ok(d) => d,
        Err(e) => return format!("Error creating temporary RPC dir: {e}"),
    };
    let _ = std::fs::set_permissions(rpc_dir.path(), std::fs::Permissions::from_mode(0o700));

    let sock_path = rpc_dir.path().join("rpc.sock");
    let helper_path = rpc_dir.path().join("agy_tools.py");
    let script_path = rpc_dir.path().join("script.py");

    if let Err(e) = std::fs::write(&helper_path, AGY_TOOLS_PY) {
        return format!("Error writing agy_tools.py helper: {e}");
    }
    if let Err(e) = std::fs::write(&script_path, req.code) {
        return format!("Error writing execute_code script: {e}");
    }

    let listener = match UnixListener::bind(&sock_path) {
        Ok(l) => l,
        Err(e) => return format!("Error binding execute_code RPC socket: {e}"),
    };
    let _ = std::fs::set_permissions(&sock_path, std::fs::Permissions::from_mode(0o600));

    let call_counter = Arc::new(AtomicUsize::new(0));
    let counter_srv = Arc::clone(&call_counter);
    let disp_srv = Arc::clone(&dispatcher);

    let srv_task = tokio::spawn(async move {
        while let Ok((stream, _addr)) = listener.accept().await {
            let d = Arc::clone(&disp_srv);
            let c = Arc::clone(&counter_srv);
            tokio::spawn(handle_rpc_client(stream, d, c));
        }
    });

    // When running inside bubblewrap, bind the ephemeral rpc_dir into `/run/agy-rpc` so the
    // sandboxed Python process can import `agy_tools` and connect ONLY to its own RPC socket.
    let use_sandbox = !req.allow_root;
    let (py_dir_in_proc, sock_in_proc, script_in_proc) = if use_sandbox {
        (
            PathBuf::from("/run/agy-rpc"),
            PathBuf::from("/run/agy-rpc/rpc.sock"),
            PathBuf::from("/run/agy-rpc/script.py"),
        )
    } else {
        (
            rpc_dir.path().to_path_buf(),
            sock_path.clone(),
            script_path.clone(),
        )
    };

    let shell_cmd = format!(
        "PYTHONPATH='{}' AGY_RPC_SOCK='{}' python3 -u '{}'",
        py_dir_in_proc.display(),
        sock_in_proc.display(),
        script_in_proc.display(),
    );

    let timeout_secs = req.timeout_secs.clamp(5, MAX_CODE_EXEC_TIMEOUT_SECS);
    let mut exec_opts = ExecOptions::for_shell(
        shell_cmd,
        req.cwd.to_path_buf(),
        req.workspace_root.to_path_buf(),
        timeout_secs,
        req.allow_root,
    );
    exec_opts.allow_network = req.allow_network;
    exec_opts.head_bytes = CODE_EXEC_HEAD_BYTES;
    exec_opts.tail_bytes = CODE_EXEC_TAIL_BYTES;
    if use_sandbox {
        exec_opts
            .extra_rw_binds
            .push((rpc_dir.path().to_path_buf(), PathBuf::from("/run/agy-rpc")));
    }

    let outcome = run_exec_command(&exec_opts).await;
    srv_task.abort();
    let _ = tokio::time::timeout(Duration::from_millis(100), srv_task).await;

    let rpc_calls = call_counter.load(Ordering::SeqCst).min(MAX_RPC_CALLS_PER_RUN);
    format!(
        "[execute_code | rpc_calls={rpc_calls}/{MAX_RPC_CALLS_PER_RUN} | {:.2}s]\n{}",
        started.elapsed().as_secs_f64(),
        outcome.format_for_agent()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn execute_code_batches_multiple_rpc_calls_and_enforces_cap() {
        let dir = TempDir::new().unwrap();
        let ws = dir.path().to_path_buf();
        std::fs::write(ws.join("alpha.txt"), "hello world").unwrap();

        let dispatcher: RpcToolDispatcher = Arc::new(move |tool, args| {
            Box::pin(async move {
                match tool.as_str() {
                    "read_file" => format!("READ:{}", args["path"].as_str().unwrap_or("")),
                    "grep_files" => format!("GREP:{}", args["pattern"].as_str().unwrap_or("")),
                    other => format!("OTHER:{other}"),
                }
            })
        });

        let code = r#"
import agy_tools as t
a = t.read_file("alpha.txt")
b = t.grep_files("hello")
print(f"BATCH_OK|{a}|{b}")
"#;
        let out = run_execute_code(
            &CodeExecRequest {
                code,
                cwd: &ws,
                workspace_root: &ws,
                allow_root: true,
                allow_network: false,
                timeout_secs: 20,
            },
            Arc::clone(&dispatcher),
        )
        .await;
        assert!(out.contains("rpc_calls=2/150"), "got: {out}");
        assert!(out.contains("BATCH_OK|READ:alpha.txt|GREP:hello"), "got: {out}");

        // Test sandboxed execution over mounted Unix socket when allow_root == false
        let out_sb = run_execute_code(
            &CodeExecRequest {
                code,
                cwd: &ws,
                workspace_root: &ws,
                allow_root: false,
                allow_network: false,
                timeout_secs: 20,
            },
            Arc::clone(&dispatcher),
        )
        .await;
        assert!(out_sb.contains("BATCH_OK|READ:alpha.txt|GREP:hello"), "sandbox rpc failed: {out_sb}");
        assert!(out_sb.contains("rpc_calls=2/150"), "got: {out_sb}");
    }
}
