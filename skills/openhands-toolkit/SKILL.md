---
name: openhands-toolkit
description: >-
  Use the unified OpenHands V1 / Venice pro-coding toolkit across Gemini (via `openhands` MCP, 19 tools),
  Grok, and Venice Uncensored (31 native tools): Python programmatic RPC batching (`oh_execute_code`,
  24 `agy_tools`, 150 calls/turn), `oh_batch_read` (20 files), `oh_multi_edit` (25 edits w/ rollback),
  stateful `oh_file_editor` (`insert`/`undo_edit`), persistent tmux PTYs (16 sessions), `.zip`/dir
  Markdown round-trip, auto-verification (`oh_verify`), and cross-engine delegation (`oh_delegate_agent`,
  `oh_dev_loop` for `uncensored` and `grok`).
metadata:
  skillport:
    category: coding
    tags: [openhands, venice, grok, gemini, mcp, codeact, rpc, speed]
---
# Unified OpenHands V1 Toolkit (Gemini · Grok · Uncensored)

All three engines share the same Rust OpenHands V1 modules (`openhands.rs`, `code_exec.rs`, `pty_manager.rs`, `code_to_md.rs`, `agent_runtime.rs`):

- **Gemini (Antigravity CLI):** invokes the **19 tools** natively via the `openhands` stdio MCP server (`agy-telegram --mcp-openhands`), with 120 default max steps & 90 tools/min ceiling.
- **Grok (xAI OAuth) & Venice Uncensored:** execute all **31 tools** natively inside `agent_runtime.rs` with 12-wide contiguous parallel wave batching, pooled keep-alive HTTP, 40/100 step budgets, 220 KiB condenser window, 32 KiB tool output cap, 300s MCP delegation timeout, and 32K output tokens.

## Speed Playbook
1. **Collapse 10–150 tool calls into ONE turn:** Use `oh_execute_code` / `execute_code` with `import agy_tools as t` (24 helpers) to read, grep, index symbols, apply multi-file edits, inspect git, query MCPs, and run `verify_project` in a single Python script — printing only a concise summary.
2. **One-shot multi-file reads & edits:** Use `oh_batch_read` / `batch_read` (up to 20 files concurrently) and `oh_multi_edit` / `multi_edit` (up to 25 surgical edits with automatic `undo_edit` snapshots and differential syntax checks).
3. **Parallel read waves:** Emit independent read/search/git-status/view calls together; they run concurrently (up to 12 in parallel) even when mixed with edits in the same turn.
4. **Stateful editing & instant rollback:** Use `oh_file_editor` / `file_editor` (`view`, `create`, `str_replace`, `insert`, `undo_edit`).
5. **Persistent builds & dev servers:** Launch via `oh_pty_start` / `run_command(pty=true, background=true)` and manage with `oh_process_manage` / `process_manage` (up to 16 concurrent tmux PTY sessions).
6. **Cross-engine fan-out:** From Gemini, call `oh_delegate_agent(engine="grok" | "uncensored", task=...)` or `oh_dev_loop(engine="grok" | "uncensored", project_dir=..., task=..., agentic=true)` (respects Grok's fail-closed sticky proxy automatically).

## 19 `openhands` MCP Tools
`oh_file_editor`, `oh_patch_file`, `oh_batch_read`, `oh_multi_edit`, `oh_glob_files`, `oh_find_symbols`, `oh_grep_files`, `oh_git_ops`, `oh_execute_code`, `oh_pty_start`, `oh_process_manage`, `oh_task_tracker`, `oh_pack_md`, `oh_apply_md`, `oh_verify`, `oh_inspect_image`, `oh_microagents`, `oh_delegate_agent`, `oh_dev_loop`.
