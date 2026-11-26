---
trigger: always_on
description: Route multi-file reads, edits, verification and batch scripting through OpenHands MCP to cut round-trips and tokens
---

# OpenHands Unified Toolkit (`openhands` MCP — 19 Tools)

Collapse 5–30 sequential tool turns into 1 compact call and keep raw payloads out of context.

## Token-saving routing rules
- **2+ workspace files to read** → `oh_batch_read` with `start_line`/`end_line` (exception: `CommandGuard` blocks `/var/lib/agy-telegram/accounts/` including `.system_generated/steps/*/output.txt` — use native `read_file` for those paths).
- **2+ edits** → `oh_multi_edit` / `oh_file_editor` (`view`/`create`/`str_replace`/`insert`/`undo_edit`) / `oh_patch_file` (or parallel native `edit_file` if MCP array serialization fails).
- **3+ read/grep/edit/verify steps, `.zip` inspection, or log filtering** → `oh_execute_code` (Python 3 importing `agy_tools` — up to 150 RPC calls/turn; **only `print()` enters context** — keep printed summaries ≤4 KB to avoid disk spill).
- **Discovery & git** → `oh_glob_files`, `oh_find_symbols`, `oh_grep_files`, `oh_git_ops` (`status`/`diff`/`log`/`branch`/`checkpoint`/`restore`), `oh_microagents`.
- **Verification** → `oh_verify` (auto-detects Rust/Python/TS/Go/PHP/Bash → `PASS` or `errors.md`) over dumping raw stdout.
- **Long builds / servers / REPLs** → `oh_pty_start` + `oh_process_manage` (`list`/`poll`/`wait`/`log`/`write`/`kill`).
- **Bundles & offload** → For `oh_pack_md`, always pass `output_path` + `include_extensions`/`exclude_patterns`. Offload heavy sweeps via `oh_delegate_agent` / `oh_dev_loop` (`uncensored` | `grok`) and `oh_inspect_image`.
