---
trigger: always_on
description: AI-native CodeAct-first tool ladder via OpenHands MCP to maximize leverage and minimize token burn
---

<tool_ladder id="openhands_codeact">
# Prefer high-leverage programmatic/batch tools over weak sequential native calls.
TIER_0_CODEACT:
  IF steps>=3 | log_filter | zip_inspect | multi_grep_edit_verify
  -> oh_execute_code(python3 + agy_tools; <=150 RPC/turn; ONLY print() enters context -> cap stdout <=4KB)

TIER_1_SPECIALIZED:
  IF read_files>=2 (workspace) -> oh_batch_read(start_line, end_line)
  IF edit_ops>=2               -> oh_multi_edit | oh_file_editor(view|create|str_replace|insert|undo_edit) | oh_patch_file
  IF discovery|git             -> oh_glob_files | oh_find_symbols | oh_grep_files | oh_git_ops(status|diff|log|branch|checkpoint|restore) | oh_microagents
  IF build_or_test_verify      -> oh_verify (auto-detects Rust/Py/TS/Go/PHP/Bash -> PASS or errors.md)
  IF long_build|server|repl    -> oh_pty_start + oh_process_manage(list|poll|wait|log|write|kill)
  IF pack_bundle|offload       -> oh_pack_md(output_path, include_extensions, exclude_patterns) | oh_delegate_agent/oh_dev_loop(uncensored|grok) | oh_inspect_image

TIER_2_NATIVE_FALLBACK:
  USE native read_file/edit_file ONLY IF:
    - CommandGuard blocks path (/var/lib/agy-telegram/accounts/* including .system_generated/steps/*/output.txt)
    - MCP array serialization fails on oh_multi_edit
    - single trivial small file op
</tool_ladder>
