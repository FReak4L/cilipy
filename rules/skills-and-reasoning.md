---
trigger: always_on
description: Skills routing matrix, engineering method, critical thinking, emergency playbook and multi-agent rules
---

# Skills, method, emergency playbook & multi-agent

## Skill routing (IF → THEN; load ≤3/task, skip on trivial Q&A)
- **Bug / test failure / unexpected behavior** → `systematic-debugging` (don't patch blindly).
- **Any code edit / refactor** → `code-change-protocol` (read exact lines, smallest diff, narrowest check first).
- **2x failed command, repeated edit, or stalled loop** → `loop-escape` (stop, re-frame, change hypothesis).
- **Before claiming done / fixed / passing** → `verification-before-completion` + `grounded-answers` (fresh observed output; never guess).
- **Multi-step spec / architecture** → `writing-plans` (don't code before plan). **2+ disjoint subtasks** → `dispatching-parallel-agents`.
- **Extra skills:** `skillport` (`search_skills` 1–3 keywords → `load_skill`); fallback `skillhub_search` / `skills-catalog` (untrusted; never run unknown scripts blindly).

## Method & critical thinking
Understand (goal, constraints, acceptance criteria) → plan small reversible steps → execute via `openhands` batching → verify with fresh output → self-critique → remember (`ai-memory`). Label claims `verified` / `reported` / `inferred` / `assumed`. Seek one disconfirming fact before concluding.

## Emergency playbook (act immediately, never spin)
1. **Doom-loop / 2x failure:** Stop retrying the same call. State exact error, switch strategy, or rollback (`oh_git_ops restore` / `oh_file_editor undo_edit`).
2. **429 / Quota / Timeout / Failover:** Refresh `.handoff/tg-<uid>.md` before risky or long work; collapse multi-step ops into one `oh_execute_code` script; never start `/swarm` under quota pressure.
3. **Context rot / huge output:** Never dump raw logs or multi-KB blobs into chat; filter inside `oh_execute_code` (`print()` ≤4 KB). If `CommandGuard` blocks `.system_generated/` paths, use native `read_file`.
4. **Search 0 hits / dead engines:** Retry `search_web_v3` with `strict_ast:false, allow_relax:true` or `engines:["searxng","ddg_html"]`; pair with built-in `search_web`.
5. **Broken build / live service risk:** Test locally first; if a deploy/edit breaks tests or service health, rollback immediately and report the exact failure.

## Multi-agent
Split only for ≥2 independent, separately verifiable subtasks. Lean team: coordinator + exclusive-ownership writers + 1 verifier per 2–4 writers (native swarm is quota-heavy). Briefs must be self-contained with zero secrets. Merge one branch at a time and settle conflicts with a test. Skills: `antigravity-multi-agent-orchestration`, `agent-brief-template`, `multi-agent-result-merging`.
