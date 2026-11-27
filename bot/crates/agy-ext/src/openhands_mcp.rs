//! Model-agnostic OpenHands V1 / Venice unified toolkit MCP server (`agy-telegram --mcp-openhands`).
//!
//! Exposes ALL 17 OpenHands/Venice pro-coding modules natively over stdio JSON-RPC 2.0 so
//! Gemini (Antigravity CLI), Grok, Venice Uncensored, and any other MCP client share the exact
//! same high-speed coding primitives:
//! - Stateful `oh_file_editor` (`view`/`create`/`str_replace`/`insert`/`undo_edit` rollback stack)
//! - `oh_patch_file` (unique/fuzzy/unified diff + fast differential syntax diagnostics)
//! - `oh_glob_files`, `oh_find_symbols`, `oh_grep_files`, `oh_git_ops`, `oh_microagents`
//! - `oh_execute_code` (Python 3 Unix-socket RPC with 24 `agy_tools` & up to 150 calls in 1 turn!)
//! - `oh_pty_start` + `oh_process_manage` (persistent `tmux` PTY sessions across turns)
//! - `oh_task_tracker` (persistent checklist), `oh_pack_md`, `oh_apply_md`, `oh_verify`, `oh_inspect_image`
//! - `oh_delegate_agent` & `oh_dev_loop` (cross-engine delegation to `uncensored` OR `grok`)

use std::path::{Path, PathBuf};
use std::sync::Arc;

use agy_core::error::{BridgeError, Result};
use agy_core::proxies::{ProxyFallbackPolicy, ProxyRegistry, ResolvedProxy};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::watch;
use tracing::info;

use crate::agent_runtime::{
    execute_agent_tool_with_state, resolve_venice_credentials, AgentTurnConfig, TurnRuntimeState,
    DEFAULT_JOB_TIMEOUT_SECS, DEFAULT_MAX_AGENT_STEPS,
};
use crate::grok_oauth::{run_grok_agent_with_options, DEFAULT_GROK_MODEL};
use crate::mcp_client::redact_secrets_in_text;
use crate::uncensored::{
    prepend_packed_attachments, run_uncensored_agent, run_uncensored_dev_loop,
    DEFAULT_UNCENSORED_MODEL,
};

/// Persistent runtime context for one `openhands` stdio MCP session.
pub struct OpenHandsMcpContext {
    pub workspace: PathBuf,
    pub state_dir: PathBuf,
    pub mcp_config: PathBuf,
    pub skills_dir: PathBuf,
    pub turn_state: Arc<TurnRuntimeState>,
}

impl OpenHandsMcpContext {
    pub fn from_env() -> Self {
        let workspace = std::env::var("AGY_WORKSPACE")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/root/agy-workspace"));
        let state_dir = std::env::var("STATE_DIR")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/var/lib/agy-telegram"));
        let mcp_config = std::env::var("MCP_CONFIG_PATH")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(crate::mcp_config::DEFAULT_MCP_CONFIG_PATH));
        let skills_dir = std::env::var("AGY_SKILLS_DIR")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/root/.gemini/config/skills"));
        Self {
            workspace,
            state_dir,
            mcp_config,
            skills_dir,
            turn_state: Arc::new(TurnRuntimeState::new()),
        }
    }

    fn resolve_cwd(&self, args: &Value) -> PathBuf {
        match args
            .get("cwd")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            Some(p) if Path::new(p).is_absolute() => PathBuf::from(p),
            Some(p) => self.workspace.join(p),
            None => self.workspace.clone(),
        }
    }

    fn resolve_path(&self, raw: Option<&str>) -> PathBuf {
        match raw.map(str::trim).filter(|s| !s.is_empty()) {
            Some(p) if Path::new(p).is_absolute() => PathBuf::from(p),
            Some(p) => self.workspace.join(p),
            None => self.workspace.clone(),
        }
    }

    fn tool_cfg(&self, cwd: PathBuf) -> AgentTurnConfig {
        AgentTurnConfig {
            engine_id: "openhands".to_string(),
            model: "openhands-mcp".to_string(),
            system_prompt: String::new(),
            cwd,
            workspace_root: self.workspace.clone(),
            allow_root: true,
            allow_sandbox: true,
            agent_mode: true,
            mcp_config_path: self.mcp_config.clone(),
            skills_dir: self.skills_dir.clone(),
            state_dir: self.state_dir.clone(),
            session_key: None,
            max_steps: DEFAULT_MAX_AGENT_STEPS,
            max_tokens: 32_768,
            job_timeout_secs: DEFAULT_JOB_TIMEOUT_SECS,
            proxy_url: None,
            three_stage_mode: crate::agent_runtime::ThreeStageMode::Off,
        }
    }
}

/// JSON Schema catalog of all 19 unified OpenHands MCP tools.
pub fn openhands_mcp_tools_schema() -> Value {
    json!([
        {
            "name": "oh_file_editor",
            "description": "OpenHands str_replace_editor with stateful per-file rollback: view (line range), create, str_replace (unique/fuzzy), insert (at 0-based line), or undo_edit (revert last edit).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "command": { "type": "string", "enum": ["view", "create", "str_replace", "insert", "undo_edit"] },
                    "path": { "type": "string", "description": "Target file path (relative to cwd/workspace or absolute)" },
                    "cwd": { "type": "string", "description": "Optional working directory" },
                    "view_range": { "type": "array", "items": { "type": "integer" }, "description": "[start_line, end_line] for view" },
                    "file_text": { "type": "string", "description": "Full text for create" },
                    "old_str": { "type": "string", "description": "Existing text for str_replace" },
                    "new_str": { "type": "string", "description": "Replacement text for str_replace or inserted text for insert" },
                    "insert_line": { "type": "integer", "description": "Line number after which to insert (0 = top)" },
                    "replace_all": { "type": "boolean", "description": "Replace all occurrences (default false)" }
                },
                "required": ["command", "path"]
            }
        },
        {
            "name": "oh_patch_file",
            "description": "Surgical file patcher supporting unique/fuzzy target replacement OR unified diff hunks, atomic write, and fast differential syntax check.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": { "type": "string" },
                    "cwd": { "type": "string" },
                    "target": { "type": "string" },
                    "replacement": { "type": "string" },
                    "replace_all": { "type": "boolean" },
                    "diff": { "type": "string", "description": "Unified diff (@@ -old +new @@) alternative to target/replacement" }
                },
                "required": ["path"]
            }
        },
        {
            "name": "oh_batch_read",
            "description": "Read up to 20 files or line ranges concurrently in ONE single MCP call (records read baselines for safe edits; eliminates sequential read round-trips).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "cwd": { "type": "string", "description": "Optional working directory" },
                    "files": {
                        "type": "array",
                        "description": "List of file paths or {path, start_line?, end_line?} objects",
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
        },
        {
            "name": "oh_multi_edit",
            "description": "Apply up to 25 surgical text edits across one or more files in ONE single MCP call (records EditHistory snapshots for oh_file_editor undo_edit, writes atomically, runs syntax checks).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "cwd": { "type": "string", "description": "Optional working directory" },
                    "edits": {
                        "type": "array",
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
        },
        {
            "name": "oh_glob_files",
            "description": "Fast native Rust recursive glob file discovery (e.g. '**/*.rs', 'src/*.{ts,tsx}'), skipping .git/target/node_modules/.venv.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "pattern": { "type": "string" },
                    "path": { "type": "string", "description": "Root directory (default workspace)" },
                    "max_results": { "type": "integer", "description": "Max files (default 100, max 300)" }
                },
                "required": ["pattern"]
            }
        },
        {
            "name": "oh_find_symbols",
            "description": "Fast multi-language symbol indexer (Rust, Python, TS/JS, Go, PHP, Java, C/C++, Ruby, Shell) returning file:line declarations.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": { "type": "string", "description": "Optional substring filter" },
                    "path": { "type": "string", "description": "Directory or file (default workspace)" },
                    "file_glob": { "type": "string", "description": "Optional file glob filter (e.g. '*.rs')" },
                    "max_results": { "type": "integer", "description": "Max symbols (default 100, max 200)" }
                }
            }
        },
        {
            "name": "oh_grep_files",
            "description": "Fast recursive regex/text search with glob filter, context_lines (0..5), and case_sensitive toggle.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "pattern": { "type": "string" },
                    "path": { "type": "string" },
                    "glob": { "type": "string" },
                    "context_lines": { "type": "integer" },
                    "case_sensitive": { "type": "boolean" }
                },
                "required": ["pattern"]
            }
        },
        {
            "name": "oh_git_ops",
            "description": "First-class Git workflow tool: status, diff (staged/stat/path), log, branch, checkpoint (safe stash snapshot), or restore.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "action": { "type": "string", "enum": ["status", "diff", "log", "branch", "checkpoint", "restore"] },
                    "cwd": { "type": "string", "description": "Repository directory (default workspace)" },
                    "path": { "type": "string" },
                    "staged": { "type": "boolean" },
                    "stat": { "type": "boolean" },
                    "limit": { "type": "integer" },
                    "message": { "type": "string" }
                },
                "required": ["action"]
            }
        },
        {
            "name": "oh_execute_code",
            "description": "SPEED MULTIPLIER (CodeAct Python RPC): execute ONE Python 3 script importing `agy_tools` (24 RPC tools: read_file, batch_read, write_file, patch_file, multi_edit, file_editor, list_dir, glob_files, grep_files, find_symbols, git_ops, run_command, process_manage, verify_project, code_to_md, md_to_code, inspect_image, web_search, fetch_url, memory_search, memory_store, call_mcp_tool, task_tracker) — up to 150 tool calls in ONE turn (300s timeout). Only print() enters model context!",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "code": { "type": "string", "description": "Python 3 script importing agy_tools and printing concise output" },
                    "cwd": { "type": "string", "description": "Working directory (default workspace)" },
                    "timeout_secs": { "type": "integer", "description": "Timeout in seconds (default 60, max 300)" },
                    "allow_network": { "type": "boolean", "description": "Allow outbound network (default true)" }
                },
                "required": ["code"]
            }
        },
        {
            "name": "oh_pty_start",
            "description": "Start a persistent detached/interactive tmux PTY session (for dev servers, long builds, or interactive REPLs) managed via oh_process_manage.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "command": { "type": "string", "description": "Shell command to launch in persistent tmux PTY" },
                    "cwd": { "type": "string" },
                    "session_name": { "type": "string", "description": "Optional short session name" },
                    "sandbox": { "type": "boolean", "description": "Force Linux bubblewrap sandbox isolation (default false)" }
                },
                "required": ["command"]
            }
        },
        {
            "name": "oh_process_manage",
            "description": "Control persistent tmux PTY sessions started with oh_pty_start: list, poll, wait, log, write (send keys/Ctrl-C), or kill.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "action": { "type": "string", "enum": ["list", "poll", "wait", "log", "write", "kill"] },
                    "session_id": { "type": "string" },
                    "input": { "type": "string" },
                    "send_enter": { "type": "boolean" },
                    "ctrl_c": { "type": "boolean" },
                    "lines": { "type": "integer" },
                    "timeout_secs": { "type": "integer" }
                },
                "required": ["action"]
            }
        },
        {
            "name": "oh_task_tracker",
            "description": "Stateful OpenHands multi-step task checklist (view, plan, update) persisted across MCP calls.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "command": { "type": "string", "enum": ["view", "plan", "update"] },
                    "task_list": {
                        "type": "array",
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
                    "id": { "type": "string" },
                    "status": { "type": "string", "enum": ["todo", "in_progress", "done", "blocked"] },
                    "notes": { "type": "string" }
                },
                "required": ["command"]
            }
        },
        {
            "name": "oh_pack_md",
            "description": "Pack a code file, directory, or .zip archive into a structured .md bundle with directory tree, folder map, symbol map, and code blocks.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": { "type": "string" },
                    "output_path": { "type": "string" },
                    "include_extensions": { "type": "array", "items": { "type": "string" } },
                    "exclude_patterns": { "type": "array", "items": { "type": "string" } },
                    "include_line_numbers": { "type": "boolean" },
                    "include_symbols": { "type": "boolean" }
                },
                "required": ["path"]
            }
        },
        {
            "name": "oh_apply_md",
            "description": "Unpack ### `rel/path` fenced code blocks from a .md bundle safely onto disk without touching unrelated files.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target_dir": { "type": "string" },
                    "markdown": { "type": "string" },
                    "markdown_path": { "type": "string" },
                    "dry_run": { "type": "boolean" }
                },
                "required": ["target_dir"]
            }
        },
        {
            "name": "oh_verify",
            "description": "Auto-detect project toolchain (Rust/Python/TS/Go/PHP/Bash) or run custom checks, returning PASS or structured errors.md with source context.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "project_dir": { "type": "string" },
                    "commands": { "type": "array", "items": { "type": "string" } },
                    "run_tests": { "type": "boolean" },
                    "timeout_secs": { "type": "integer" },
                    "errors_md_path": { "type": "string" }
                },
                "required": ["project_dir"]
            }
        },
        {
            "name": "oh_inspect_image",
            "description": "Inspect a local image (.png/.jpg/.webp/.gif) using Venice multimodal vision (auto-resolves credentials for any caller model).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": { "type": "string" },
                    "question": { "type": "string" },
                    "model": { "type": "string" }
                },
                "required": ["path"]
            }
        },
        {
            "name": "oh_microagents",
            "description": "Discover and load OpenHands repo microagents (.openhands/microagents/*.md with YAML triggers) plus AGENTS.md/CLAUDE.md/GEMINI.md/.cursorrules for a directory.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Repository directory (default workspace)" },
                    "prompt": { "type": "string", "description": "Optional task text for YAML keyword trigger matching" }
                }
            }
        },
        {
            "name": "oh_delegate_agent",
            "description": "Delegate an autonomous OpenHands sub-agent task to Venice Uncensored (`engine='uncensored'`) OR xAI Grok OAuth (`engine='grok'`) with all 29 server/coding tools (up to 100 steps).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "engine": { "type": "string", "enum": ["uncensored", "grok"], "description": "Target engine (default 'uncensored')" },
                    "task": { "type": "string", "description": "Self-contained autonomous task" },
                    "model": { "type": "string", "description": "Optional model override for the chosen engine" },
                    "cwd": { "type": "string", "description": "Working directory (default workspace)" },
                    "max_steps": { "type": "integer", "description": "Max steps (default 40, max 100)" },
                    "session_key": { "type": "string", "description": "Optional persistent session key" },
                    "system_prompt": { "type": "string", "description": "Optional custom system prompt" },
                    "attach_paths": { "type": "array", "items": { "type": "string" }, "description": "Optional files/dirs/.zip to pack and prepend" }
                },
                "required": ["task"]
            }
        },
        {
            "name": "oh_dev_loop",
            "description": "Run an autonomous OpenHands coding + verify_project fix loop on Venice Uncensored (`engine='uncensored'`) OR Grok (`engine='grok'`). Supports fast .md round-trip or full `agentic=true` multi-tool loop.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "project_dir": { "type": "string" },
                    "task": { "type": "string" },
                    "engine": { "type": "string", "enum": ["uncensored", "grok"], "description": "Engine to drive the loop (default 'uncensored')" },
                    "model": { "type": "string" },
                    "commands": { "type": "array", "items": { "type": "string" } },
                    "run_tests": { "type": "boolean" },
                    "max_iters": { "type": "integer", "description": "Max fix iterations (default 4, max 10)" },
                    "agentic": { "type": "boolean", "description": "Use full 29-tool autonomous agent per iteration (default true for grok, false for fast .md uncensored)" },
                    "search_on_error": { "type": "boolean" }
                },
                "required": ["project_dir", "task"]
            }
        }
    ])
}

/// Handle a single JSON-RPC 2.0 request for the `openhands` MCP server.
/// Returns `None` for notifications (requests without `id`).
pub async fn handle_mcp_request(req: &Value, ctx: &OpenHandsMcpContext) -> Option<Value> {
    let id = req.get("id")?.clone();
    let method = req.get("method").and_then(Value::as_str).unwrap_or("");
    let params = req.get("params").cloned().unwrap_or_else(|| json!({}));

    let response = match method {
        "initialize" => {
            let req_ver = params
                .get("protocolVersion")
                .and_then(Value::as_str)
                .unwrap_or("2024-11-05");
            let negotiated = match req_ver {
                "2025-06-18" | "2025-03-26" | "2024-11-05" => req_ver,
                _ => "2024-11-05",
            };
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "protocolVersion": negotiated,
                    "capabilities": { "tools": { "listChanged": false } },
                    "serverInfo": { "name": "openhands", "version": "1.0.0" }
                }
            })
        }
        "ping" => json!({ "jsonrpc": "2.0", "id": id, "result": {} }),
        "resources/list" => json!({ "jsonrpc": "2.0", "id": id, "result": { "resources": [] } }),
        "prompts/list" => json!({ "jsonrpc": "2.0", "id": id, "result": { "prompts": [] } }),
        "tools/list" => json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": { "tools": openhands_mcp_tools_schema() }
        }),
        "tools/call" => {
            let tname = params.get("name").and_then(Value::as_str).unwrap_or("");
            let targs = params.get("arguments").cloned().unwrap_or_else(|| json!({}));
            dispatch_tool_call(id, tname, &targs, ctx).await
        }
        other => json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": { "code": -32601, "message": format!("Method not found: {other}") }
        }),
    };
    Some(response)
}

fn ok_text(id: Value, text: String) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": { "content": [{ "type": "text", "text": text }] }
    })
}

fn err_text(id: Value, text: String) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "isError": true,
            "content": [{ "type": "text", "text": redact_secrets_in_text(&text) }]
        }
    })
}

fn tool_reply(id: Value, text: String) -> Value {
    let trimmed = text.trim_start();
    if trimmed.starts_with("Error:") || trimmed.starts_with("Error ") {
        err_text(id, text)
    } else {
        ok_text(id, text)
    }
}

fn resolve_grok_sticky_proxy(state_dir: &Path) -> std::result::Result<Option<String>, String> {
    let proxies_path = state_dir.join("proxies.json");
    if !proxies_path.exists() {
        return Ok(None);
    }
    let reg = ProxyRegistry::open_readonly(proxies_path, ProxyFallbackPolicy::FailClosed);
    match reg.resolve_grok() {
        ResolvedProxy::Blocked { reason, .. } => Err(format!(
            "Grok sticky proxy blocked (fail-closed): {reason}. Check /proxies."
        )),
        ResolvedProxy::Use { url, .. } => Ok(Some(url)),
        ResolvedProxy::Direct | ResolvedProxy::DirectFallback { .. } => Ok(None),
    }
}

async fn dispatch_tool_call(
    id: Value,
    tname: &str,
    targs: &Value,
    ctx: &OpenHandsMcpContext,
) -> Value {
    let cwd = ctx.resolve_cwd(targs);
    let cfg = ctx.tool_cfg(cwd.clone());

    match tname {
        "oh_file_editor" => {
            let out = execute_agent_tool_with_state("file_editor", targs, &cfg, &ctx.turn_state).await;
            tool_reply(id, out)
        }
        "oh_patch_file" => {
            let out = execute_agent_tool_with_state("patch_file", targs, &cfg, &ctx.turn_state).await;
            tool_reply(id, out)
        }
        "oh_batch_read" => {
            let out = execute_agent_tool_with_state("batch_read", targs, &cfg, &ctx.turn_state).await;
            tool_reply(id, out)
        }
        "oh_multi_edit" => {
            let out = execute_agent_tool_with_state("multi_edit", targs, &cfg, &ctx.turn_state).await;
            tool_reply(id, out)
        }
        "oh_glob_files" => {
            let out = execute_agent_tool_with_state("glob_files", targs, &cfg, &ctx.turn_state).await;
            tool_reply(id, out)
        }
        "oh_find_symbols" => {
            let out = execute_agent_tool_with_state("find_symbols", targs, &cfg, &ctx.turn_state).await;
            tool_reply(id, out)
        }
        "oh_grep_files" => {
            let out = execute_agent_tool_with_state("grep_files", targs, &cfg, &ctx.turn_state).await;
            tool_reply(id, out)
        }
        "oh_git_ops" => {
            let out = execute_agent_tool_with_state("git_ops", targs, &cfg, &ctx.turn_state).await;
            tool_reply(id, out)
        }
        "oh_execute_code" => {
            ctx.turn_state.reset_mcp_calls();
            let out = execute_agent_tool_with_state("execute_code", targs, &cfg, &ctx.turn_state).await;
            tool_reply(id, out)
        }
        "oh_pty_start" => {
            let command = targs.get("command").and_then(Value::as_str).unwrap_or("");
            if command.trim().is_empty() {
                return err_text(id, "Error: 'command' must not be empty.".to_string());
            }
            let mut run_args = json!({
                "command": command,
                "pty": true,
                "background": true,
            });
            if let Some(name) = targs.get("session_name").and_then(Value::as_str) {
                run_args["session_name"] = json!(name);
            }
            if let Some(sb) = targs.get("sandbox").and_then(Value::as_bool) {
                run_args["sandbox"] = json!(sb);
            }
            let out = execute_agent_tool_with_state("run_command", &run_args, &cfg, &ctx.turn_state).await;
            tool_reply(id, out)
        }
        "oh_process_manage" => {
            let out = execute_agent_tool_with_state("process_manage", targs, &cfg, &ctx.turn_state).await;
            tool_reply(id, out)
        }
        "oh_task_tracker" => {
            let out = execute_agent_tool_with_state("task_tracker", targs, &cfg, &ctx.turn_state).await;
            tool_reply(id, out)
        }
        "oh_pack_md" => {
            let out = execute_agent_tool_with_state("code_to_md", targs, &cfg, &ctx.turn_state).await;
            tool_reply(id, out)
        }
        "oh_apply_md" => {
            let out = execute_agent_tool_with_state("md_to_code", targs, &cfg, &ctx.turn_state).await;
            tool_reply(id, out)
        }
        "oh_verify" => {
            let out = execute_agent_tool_with_state("verify_project", targs, &cfg, &ctx.turn_state).await;
            tool_reply(id, out)
        }
        "oh_inspect_image" => {
            let out = execute_agent_tool_with_state("inspect_image", targs, &cfg, &ctx.turn_state).await;
            tool_reply(id, out)
        }
        "oh_microagents" => {
            let root = ctx.resolve_path(targs.get("path").and_then(Value::as_str));
            let prompt = targs.get("prompt").and_then(Value::as_str).unwrap_or("").to_string();
            let out = tokio::task::spawn_blocking(move || {
                crate::openhands::load_repo_microagents(&root, &prompt)
                    .unwrap_or_else(|| format!("No microagents or project rules found in {}", root.display()))
            })
            .await
            .unwrap_or_else(|e| format!("Error loading microagents: {e}"));
            ok_text(id, out)
        }
        "oh_delegate_agent" => {
            let engine = targs
                .get("engine")
                .and_then(Value::as_str)
                .unwrap_or("uncensored")
                .trim()
                .to_ascii_lowercase();
            let raw_task = targs
                .get("task")
                .or_else(|| targs.get("prompt"))
                .and_then(Value::as_str)
                .unwrap_or("");
            if raw_task.trim().is_empty() {
                return err_text(id, "Error: 'task' must not be empty.".to_string());
            }
            let task = prepend_packed_attachments(raw_task, targs, &cwd).await;
            let max_steps = targs.get("max_steps").and_then(Value::as_u64).map(|n| n as usize);
            let session_key = targs
                .get("session_key")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string);
            let sys = targs.get("system_prompt").and_then(Value::as_str);
            let timeout_secs = targs
                .get("timeout_secs")
                .and_then(Value::as_u64)
                .unwrap_or(145)
                .clamp(15, 165);
            let (cancel_tx, rx) = watch::channel(false);

            let fut = async {
                match engine.as_str() {
                    "grok" => {
                        let proxy_url = match resolve_grok_sticky_proxy(&ctx.state_dir) {
                            Ok(px) => px,
                            Err(e) => return Err(agy_core::BridgeError::Network(e)),
                        };
                        let model = targs
                            .get("model")
                            .and_then(Value::as_str)
                            .filter(|s| !s.trim().is_empty())
                            .unwrap_or(DEFAULT_GROK_MODEL);
                        info!(engine = "grok", model = %model, timeout_secs, "mcp-openhands delegating task");
                        run_grok_agent_with_options(
                            &ctx.state_dir,
                            model,
                            &task,
                            &cwd,
                            &ctx.workspace,
                            &ctx.mcp_config,
                            &ctx.skills_dir,
                            session_key,
                            true,
                            true,
                            true,
                            max_steps,
                            sys,
                            proxy_url,
                            None,
                            rx,
                        )
                        .await
                    }
                    "uncensored" | "venice" => {
                        let (api_base, api_key) = resolve_venice_credentials(&ctx.mcp_config);
                        let model = targs
                            .get("model")
                            .and_then(Value::as_str)
                            .filter(|s| !s.trim().is_empty())
                            .unwrap_or(DEFAULT_UNCENSORED_MODEL);
                        info!(engine = "uncensored", model = %model, timeout_secs, "mcp-openhands delegating task");
                        run_uncensored_agent(
                            &api_base,
                            &api_key,
                            model,
                            &task,
                            &cwd,
                            &ctx.workspace,
                            &ctx.mcp_config,
                            &ctx.skills_dir,
                            &ctx.state_dir,
                            session_key,
                            true,
                            true,
                            true,
                            max_steps,
                            sys,
                            None,
                            rx,
                        )
                        .await
                    }
                    other => Err(agy_core::BridgeError::Validation(format!(
                        "Error: unsupported engine '{other}' (use 'uncensored' or 'grok')."
                    ))),
                }
            };

            let res = match tokio::time::timeout(std::time::Duration::from_secs(timeout_secs), fut).await {
                Ok(inner) => inner,
                Err(_) => {
                    let _ = cancel_tx.send(true);
                    return err_text(
                        id,
                        format!(
                            "Error: oh_delegate_agent({engine}) timed out after {timeout_secs}s (capped below MCP client deadline). Try smaller max_steps or focused scope."
                        ),
                    );
                }
            };

            match res {
                Ok(r) if r.error.is_none() => ok_text(id, r.text),
                Ok(r) => err_text(
                    id,
                    r.error
                        .map(|e| e.to_string())
                        .unwrap_or_else(|| "delegated agent returned empty output".to_string()),
                ),
                Err(e) => err_text(id, e.to_string()),
            }
        }
        "oh_dev_loop" => {
            let project_dir = ctx.resolve_path(targs.get("project_dir").and_then(Value::as_str));
            let task = targs.get("task").and_then(Value::as_str).unwrap_or("");
            if task.trim().is_empty() {
                return err_text(id, "Error: 'task' must not be empty.".to_string());
            }
            let engine = targs
                .get("engine")
                .and_then(Value::as_str)
                .unwrap_or("uncensored")
                .trim()
                .to_ascii_lowercase();
            let max_iters = targs
                .get("max_iters")
                .and_then(Value::as_u64)
                .unwrap_or(4)
                .clamp(1, 10) as usize;
            let run_tests = targs.get("run_tests").and_then(Value::as_bool).unwrap_or(false);
            let search_on_error = targs.get("search_on_error").and_then(Value::as_bool).unwrap_or(true);
            let commands: Vec<String> = targs
                .get("commands")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect())
                .unwrap_or_default();
            let (_tx, rx) = watch::channel(false);

            let agentic = targs
                .get("agentic")
                .and_then(Value::as_bool)
                .unwrap_or(engine == "grok");

            let dev_res = if agentic {
                let mut agent_prompt = format!(
                    "Project directory: {}\nTask: {task}\nUse file_editor/patch_file/glob_files/find_symbols/git_ops/execute_code to complete the task cleanly, then run verify_project(project_dir=\"{}\", run_tests={run_tests}) and fix any errors before finishing.",
                    project_dir.display(),
                    project_dir.display()
                );
                if !commands.is_empty() {
                    agent_prompt.push_str(&format!("\nCustom verification commands: {commands:?}"));
                }
                let step_budget = Some((max_iters * 12).min(100));
                let run = match engine.as_str() {
                    "grok" => {
                        let proxy_url = match resolve_grok_sticky_proxy(&ctx.state_dir) {
                            Ok(px) => px,
                            Err(e) => return err_text(id, e),
                        };
                        let model = targs
                            .get("model")
                            .and_then(Value::as_str)
                            .filter(|s| !s.trim().is_empty())
                            .unwrap_or(DEFAULT_GROK_MODEL);
                        run_grok_agent_with_options(
                            &ctx.state_dir,
                            model,
                            &agent_prompt,
                            &project_dir,
                            &ctx.workspace,
                            &ctx.mcp_config,
                            &ctx.skills_dir,
                            None,
                            true,
                            true,
                            true,
                            step_budget,
                            None,
                            proxy_url,
                            None,
                            rx,
                        )
                        .await
                    }
                    "uncensored" | "venice" => {
                        let (api_base, api_key) = resolve_venice_credentials(&ctx.mcp_config);
                        let model = targs
                            .get("model")
                            .and_then(Value::as_str)
                            .filter(|s| !s.trim().is_empty())
                            .unwrap_or(DEFAULT_UNCENSORED_MODEL);
                        run_uncensored_agent(
                            &api_base,
                            &api_key,
                            model,
                            &agent_prompt,
                            &project_dir,
                            &ctx.workspace,
                            &ctx.mcp_config,
                            &ctx.skills_dir,
                            &ctx.state_dir,
                            None,
                            true,
                            true,
                            true,
                            step_budget,
                            None,
                            None,
                            rx,
                        )
                        .await
                    }
                    other => Err(BridgeError::Validation(format!(
                        "unsupported engine '{other}' (use 'uncensored' or 'grok')"
                    ))),
                };
                match run {
                    Ok(r) if r.error.is_none() => Ok(r.text),
                    Ok(r) => Err(r
                        .error
                        .map(|e| e.to_string())
                        .unwrap_or_else(|| "agentic dev loop failed".to_string())),
                    Err(e) => Err(e.to_string()),
                }
            } else {
                let (api_base, api_key) = resolve_venice_credentials(&ctx.mcp_config);
                let model = targs
                    .get("model")
                    .and_then(Value::as_str)
                    .filter(|s| !s.trim().is_empty())
                    .unwrap_or(DEFAULT_UNCENSORED_MODEL);
                run_uncensored_dev_loop(
                    &api_base,
                    &api_key,
                    model,
                    &project_dir,
                    task,
                    commands,
                    run_tests,
                    max_iters,
                    search_on_error,
                    &ctx.workspace,
                    &ctx.mcp_config,
                    &ctx.skills_dir,
                    &ctx.state_dir,
                    rx,
                )
                .await
            };

            match dev_res {
                Ok(report) => ok_text(id, report),
                Err(e) => err_text(id, e),
            }
        }
        other => json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": { "code": -32601, "message": format!("Unknown tool: {other}") }
        }),
    }
}

/// Standalone stdio JSON-RPC 2.0 MCP server (`agy-telegram --mcp-openhands`).
pub async fn run_mcp_openhands_server() -> Result<()> {
    let ctx = Arc::new(OpenHandsMcpContext::from_env());
    let stdin = tokio::io::stdin();
    let stdout = Arc::new(tokio::sync::Mutex::new(tokio::io::stdout()));
    let mut reader = BufReader::new(stdin);
    let mut line = String::new();
    let mut tasks = tokio::task::JoinSet::new();

    loop {
        line.clear();
        let n = reader
            .read_line(&mut line)
            .await
            .map_err(|e| BridgeError::io("reading mcp-openhands stdin", e))?;
        if n == 0 {
            break;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let req = match serde_json::from_str::<Value>(trimmed) {
            Ok(v) => v,
            Err(e) => {
                let err_resp = json!({
                    "jsonrpc": "2.0",
                    "id": Value::Null,
                    "error": { "code": -32700, "message": format!("Parse error: {e}") }
                });
                if let Ok(mut encoded) = serde_json::to_vec(&err_resp) {
                    encoded.push(b'\n');
                    let mut out = stdout.lock().await;
                    let _ = out.write_all(&encoded).await;
                    let _ = out.flush().await;
                }
                continue;
            }
        };

        let ctx_c = Arc::clone(&ctx);
        let out_c = Arc::clone(&stdout);
        tasks.spawn(async move {
            let Some(response) = handle_mcp_request(&req, &ctx_c).await else {
                return;
            };
            if let Ok(mut encoded) = serde_json::to_vec(&response) {
                encoded.push(b'\n');
                let mut out = out_c.lock().await;
                let _ = out.write_all(&encoded).await;
                let _ = out.flush().await;
            }
        });
        while tasks.try_join_next().is_some() {}
    }

    while tasks.join_next().await.is_some() {}
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_ctx(dir: &TempDir) -> OpenHandsMcpContext {
        OpenHandsMcpContext {
            workspace: dir.path().to_path_buf(),
            state_dir: dir.path().join("state"),
            mcp_config: dir.path().join("mcp_config.json"),
            skills_dir: dir.path().join("skills"),
            turn_state: Arc::new(TurnRuntimeState::new()),
        }
    }

    #[tokio::test]
    async fn openhands_mcp_exposes_all_17_tools_and_executes_statefully() {
        let dir = TempDir::new().unwrap();
        let ctx = test_ctx(&dir);

        // 1. Initialize & list tools
        let init = handle_mcp_request(
            &json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05"}}),
            &ctx,
        )
        .await
        .unwrap();
        assert_eq!(init["result"]["serverInfo"]["name"], "openhands");

        let list = handle_mcp_request(
            &json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
            &ctx,
        )
        .await
        .unwrap();
        let tools = list["result"]["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 19);

        // 2. Stateful oh_file_editor: create -> insert -> undo_edit
        let create = handle_mcp_request(
            &json!({
                "jsonrpc": "2.0", "id": 3, "method": "tools/call",
                "params": {
                    "name": "oh_file_editor",
                    "arguments": {
                        "command": "create",
                        "path": "app.py",
                        "file_text": "def greet(name):\n    return f'hi {name}'\n"
                    }
                }
            }),
            &ctx,
        )
        .await
        .unwrap();
        let create_txt = create["result"]["content"][0]["text"].as_str().unwrap();
        assert!(create_txt.contains("Successfully wrote"), "got: {create_txt}");

        let ins = handle_mcp_request(
            &json!({
                "jsonrpc": "2.0", "id": 4, "method": "tools/call",
                "params": {
                    "name": "oh_file_editor",
                    "arguments": {
                        "command": "insert",
                        "path": "app.py",
                        "insert_line": 0,
                        "new_str": "# header"
                    }
                }
            }),
            &ctx,
        )
        .await
        .unwrap();
        assert!(ins["result"]["content"][0]["text"].as_str().unwrap().contains("Inserted"));
        assert!(std::fs::read_to_string(dir.path().join("app.py")).unwrap().starts_with("# header"));

        let undo = handle_mcp_request(
            &json!({
                "jsonrpc": "2.0", "id": 5, "method": "tools/call",
                "params": {
                    "name": "oh_file_editor",
                    "arguments": { "command": "undo_edit", "path": "app.py" }
                }
            }),
            &ctx,
        )
        .await
        .unwrap();
        assert!(undo["result"]["content"][0]["text"].as_str().unwrap().contains("Undid"));
        assert!(std::fs::read_to_string(dir.path().join("app.py")).unwrap().starts_with("def greet"));

        // 3. oh_find_symbols & oh_execute_code Python RPC batching
        let syms = handle_mcp_request(
            &json!({
                "jsonrpc": "2.0", "id": 6, "method": "tools/call",
                "params": { "name": "oh_find_symbols", "arguments": { "query": "greet" } }
            }),
            &ctx,
        )
        .await
        .unwrap();
        assert!(syms["result"]["content"][0]["text"].as_str().unwrap().contains("app.py:1: def greet"));

        let rpc = handle_mcp_request(
            &json!({
                "jsonrpc": "2.0", "id": 7, "method": "tools/call",
                "params": {
                    "name": "oh_execute_code",
                    "arguments": {
                        "code": "import agy_tools as t\nf = t.glob_files('*.py')\ns = t.find_symbols('greet')\nprint('RPC_OK|' + ('app.py' in f).__str__() + '|' + ('def greet' in s).__str__())\n"
                    }
                }
            }),
            &ctx,
        )
        .await
        .unwrap();
        let rpc_txt = rpc["result"]["content"][0]["text"].as_str().unwrap();
        assert!(rpc_txt.contains("RPC_OK|True|True"), "got: {rpc_txt}");

        // 4. oh_task_tracker persists across calls
        let _ = handle_mcp_request(
            &json!({
                "jsonrpc": "2.0", "id": 8, "method": "tools/call",
                "params": {
                    "name": "oh_task_tracker",
                    "arguments": {
                        "command": "plan",
                        "task_list": [{ "id": "T1", "title": "Ship unified OpenHands", "status": "done" }]
                    }
                }
            }),
            &ctx,
        )
        .await
        .unwrap();
        let view = handle_mcp_request(
            &json!({
                "jsonrpc": "2.0", "id": 9, "method": "tools/call",
                "params": { "name": "oh_task_tracker", "arguments": { "command": "view" } }
            }),
            &ctx,
        )
        .await
        .unwrap();
        assert!(view["result"]["content"][0]["text"].as_str().unwrap().contains("Ship unified OpenHands"));

        // 5. oh_batch_read & oh_multi_edit
        std::fs::write(dir.path().join("extra.py"), "VAL = 1\n").unwrap();
        let br = handle_mcp_request(
            &json!({
                "jsonrpc": "2.0", "id": 10, "method": "tools/call",
                "params": { "name": "oh_batch_read", "arguments": { "files": ["app.py", "extra.py"] } }
            }),
            &ctx,
        )
        .await
        .unwrap();
        let br_txt = br["result"]["content"][0]["text"].as_str().unwrap();
        assert!(br_txt.contains("def greet") && br_txt.contains("VAL = 1"), "got: {br_txt}");

        let me = handle_mcp_request(
            &json!({
                "jsonrpc": "2.0", "id": 11, "method": "tools/call",
                "params": {
                    "name": "oh_multi_edit",
                    "arguments": {
                        "edits": [
                            { "path": "extra.py", "target": "VAL = 1", "replacement": "VAL = 42" }
                        ]
                    }
                }
            }),
            &ctx,
        )
        .await
        .unwrap();
        assert!(me["result"]["content"][0]["text"].as_str().unwrap().contains("1 succeeded, 0 failed"));
        assert!(std::fs::read_to_string(dir.path().join("extra.py")).unwrap().contains("VAL = 42"));
    }
}
