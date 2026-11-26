---
name: venice-uncensored
description: >-
  Invoke Venice uncensored models as a specialized OpenHands-grade autonomous sub-agent or MCP tool.
  Provides access to models with uncensored filtering (e.g. DeepSeek V4 1 Flash Uncensored,
  GLM 5.3 Flash Uncensored, Gemma 4 Uncensored) with full OpenHands coding & server execution capabilities.
metadata:
  skillport:
    category: multi-agent
    tags: [venice, uncensored, openhands, subagent, mcp, coding]
---
# Venice Uncensored Autonomous Agent & OpenHands MCP Tool (v4.0 Unified)

Use this skill when you need an uncensored OpenAI-compatible model from Venice to act as a multi-step OpenHands-grade autonomous coding & engineering agent with maximum authorized server access.
For model-agnostic OpenHands tools usable directly by **Gemini, Grok, and Uncensored**, also see the `openhands` MCP server (`openhands-toolkit` skill).

## Available Models
- `veniceai/deepseek-v4-1-flash-1017-uncensored` (Default, fast, strong reasoning, 1M ctx, tool calling)
- `veniceai/glm-5-3-flash-uncensored` (GLM 5.3 Flash uncensored, 1M ctx, reasoning)
- `veniceai/gemma-4-uncensored` (Gemma 4 uncensored, 256K ctx)
- `veniceai/venice-uncensored-1-2` (Venice 1.2 uncensored)
- `veniceai/venice-uncensored-role-play` (Role play uncensored)

## Autonomous OpenHands Agent Capabilities (31 Live Tools — Shared by Venice & Grok)
- **OpenHands File Editor, Batch & Rollback:** `batch_read` (up to 20 files concurrently in 1 call), `multi_edit` (up to 25 surgical edits across files in 1 call w/ `undo_edit` rollback), `file_editor` (`view`, `create`, `str_replace`, `insert` at line, `undo_edit` per-file rollback stack), `read_file`, `write_file` (`append=true`), `patch_file` / `edit_file` (unique/fuzzy/unified diff + differential syntax diagnostics)
- **Codebase Discovery & Git:** `glob_files` (`**/*.rs`, `*.py`), `find_symbols` (multi-language fn/struct/class/trait indexer), `grep_files` (regex + glob + context_lines + case_sensitive), `list_dir`, `git_ops` (`status`, `diff`, `log`, `branch`, `checkpoint`, `restore`)
- **OpenHands Planning, Condenser & Microagents:** `task_tracker` (`view`, `plan`, `update` — preserved across 220 KiB Context Condenser compaction), `think`, `finish`, auto-loaded repo microagents (`.openhands/microagents/*.md` with YAML triggers + `AGENTS.md`/`CLAUDE.md`/`GEMINI.md`/`.cursorrules`), full 5-pattern `StuckDetector`, 12-wide contiguous parallel read waves
- **Shell, PTY & Programmatic RPC:** `run_command` (timeout up to 600s, zero-SIGPIPE head+tail capture, tmux PTY up to 16 sessions, bubblewrap sandbox), `process_manage`, `execute_code` (Python 3 Unix-socket RPC, **24 `agy_tools`**, up to **150 calls/turn**, 300s timeout, network enabled by default for `root_access`)
- **Project Round-Trip & Vision:** `code_to_md`, `md_to_code`, `verify_project`, `inspect_image`
- **Live Web Research, Memory & MCPs:** `web_search`, `fetch_url` (`search-v3`), `memory_search`, `memory_store` (`ai-memory`), `search_skills`, `load_skill`, `skillhub_search`, `skillhub_catalog`, `skillhub_get`, `list_mcp_servers`, `call_mcp_tool` (up to 50 calls/turn, timeout up to 300s)
- **Step Budget:** Default 40 steps, up to 100 steps per turn; 32,768 max output tokens.

## Invocation as MCP Tool (`venice-uncensored` — 9 Tools, plus `openhands` — 19 Tools)
1. `uncensored_models`: Live list of verified uncensored models.
2. `uncensored_chat`: Direct single-turn uncensored chat completion (`prompt`, `model`, `system_prompt`, `attach_paths`).
3. `uncensored_agent`: Autonomous OpenHands agent (`task`, `model`, `cwd`, `max_steps` up to 100, `session_key`, `system_prompt`, `attach_paths`).
4. `uncensored_pack_md`: Pack file/dir/`.zip` into structured `.md`.
5. `uncensored_apply_md`: Apply `### \`rel/path\`` blocks from `.md` to disk.
6. `uncensored_verify`: Auto-detected toolchain checks returning PASS or `errors.md`.
7. `uncensored_dev_loop`: Autonomous `.md` or `agentic=true` multi-tool fix loop (`max_iters` up to 10).
8. `uncensored_glob`: Fast recursive glob file search.
9. `uncensored_find_symbols`: Fast multi-language symbol indexer.

## CLI & Sub-Agent Execution
```bash
/opt/agy-telegram/bin/agy-telegram --mcp-uncensored
/opt/agy-telegram/bin/agy-telegram --mcp-openhands
```
