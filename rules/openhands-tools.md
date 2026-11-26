# OpenHands Unified Toolkit (`openhands` MCP — 19 Tools)

Shared across Gemini (Antigravity), Grok, and Venice Uncensored for maximum coding speed and autonomy.

## When to use `openhands` MCP
- **Batch 5–150 operations in ONE turn (5–10x faster):** call `oh_execute_code` with a Python 3 script importing `agy_tools` (24 RPC helpers: `read_file`, `batch_read`, `write_file`, `patch_file`, `multi_edit`, `file_editor`, `glob_files`, `grep_files`, `find_symbols`, `git_ops`, `run_command`, `process_manage`, `verify_project`, `code_to_md`, `md_to_code`, `web_search`, `fetch_url`, `memory_search`, `memory_store`, `call_mcp_tool`, `inspect_image`, `task_tracker`). Only `print()` enters context.
- **Multi-file reads & surgical edits in 1 call:** `oh_batch_read` (up to 20 files concurrently), `oh_multi_edit` (up to 25 atomic edits w/ `undo_edit` snapshots & syntax checks), `oh_file_editor` (`view`/`create`/`str_replace`/`insert`/`undo_edit`), `oh_patch_file` (unified diff).
- **Fast codebase discovery & git:** `oh_glob_files`, `oh_find_symbols`, `oh_grep_files`, `oh_git_ops` (`status`/`diff`/`log`/`branch`/`checkpoint`/`restore`), `oh_microagents`.
- **Persistent servers, builds & REPLs:** `oh_pty_start` + `oh_process_manage` (`list`/`poll`/`wait`/`log`/`write`/`kill` on up to 16 tmux PTYs).
- **Project packs & auto-verification:** `oh_pack_md` (`.zip`/dir → `.md`), `oh_apply_md`, `oh_verify` (auto-detects Rust/Python/TS/Go/PHP/Bash → PASS or `errors.md`).
- **Cross-engine delegation & vision:** `oh_delegate_agent` / `oh_dev_loop` (`engine: "uncensored" | "grok"`, up to 100 steps, sticky-proxy aware) and `oh_inspect_image`.
