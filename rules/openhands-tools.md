---
trigger: always_on
description: Route multi-file reads, edits, verification and batch scripting through OpenHands MCP to cut round-trips and tokens
---

# OpenHands Unified Toolkit (`openhands` MCP — 19 Tools)

Use OpenHands by default to collapse 5–30 sequential tool turns into 1 compact call and keep raw payloads out of context.

## Token-saving routing rules
- **2+ files to read** → MUST use `oh_batch_read` with `start_line`/`end_line` (never sequential `read_file` calls).
- **2+ edits (one or many files)** → MUST use `oh_multi_edit` (atomic w/ `undo_edit` snapshots & syntax checks) or `oh_file_editor` (`view`/`create`/`str_replace`/`insert`/`undo_edit`), or `oh_patch_file` (unified diff).
- **3+ read/grep/edit/verify steps, `.zip` inspection, or log filtering** → MUST use `oh_execute_code` (Python 3 importing `agy_tools` — unprefixed helpers: `read_file`, `batch_read`, `write_file`, `patch_file`, `multi_edit`, `file_editor`, `glob_files`, `grep_files`, `find_symbols`, `git_ops`, `run_command`, `process_manage`, `verify_project`, `code_to_md`, `md_to_code`, `web_search`, `fetch_url`, `memory_search`, `memory_store`, `call_mcp_tool`, `inspect_image`, `task_tracker`, up to 150 calls/turn). **Only `print()` enters context**, cutting token burn drastically.
- **Discovery & git** → `oh_glob_files`, `oh_find_symbols`, `oh_grep_files`, `oh_git_ops` (`status`/`diff`/`log`/`branch`/`checkpoint`/`restore`), `oh_microagents`.
- **Verification** → Prefer `oh_verify` (auto-detects Rust/Python/TS/Go/PHP/Bash → `PASS` or `errors.md`) over dumping raw build/test stdout.
- **Long builds / servers / REPLs** → `oh_pty_start` + `oh_process_manage` (`list`/`poll`/`wait`/`log`/`write`/`kill`, up to 16 tmux PTYs).
- **Bundles & offload** → For `oh_pack_md`, ALWAYS pass `output_path` + `include_extensions`/`exclude_patterns` so files write to disk instead of flooding context. Offload heavy multi-file sweeps via `oh_delegate_agent` / `oh_dev_loop` (`uncensored` | `grok`) and `oh_inspect_image`.
