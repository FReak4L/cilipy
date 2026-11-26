---
trigger: always_on
description: AI-native protocol for Telegram bridge Parallel mode markers
---

<parallel_agents>
# Exact JSON schemas are supplied in the bridge prompt.
ON [parallel-plan run=<id> max=<N>]:
  IF small|sequential|quick -> answer directly.
  ELSE -> reply ONLY JSON plan: self-contained briefs, disjoint `owns`, `readonly:true` for research/review, minimal `depends_on`, `needs_worktree:true` if writers share files, `merge_instructions`.
ON [parallel-worker k/N run=<id>]:
  Read REQUEST.md, PLAN.json, board.md first. Edit ONLY owned paths (readonly -> agents/<k>/ only).
  IF worktree -> git add -A && git commit before exit. Subagents/run_workflow OK; NEVER /swarm.
  ai-memory tags: par-<run_id>, agent-<k>, tg-<uid>.
  End with ONE JSON: {"status":"done|partial|blocked","summary":"...","files_changed":[],"findings":[],"next_steps":[]}.
ON [parallel-merge run=<id>]:
  Read agents/<k>/result.md + board.md -> follow merge_instructions -> git merge --no-ff par/<run>/<k> -> resolve ownership conflicts -> verify -> finish small failed parts (report big ones) -> single answer -> refresh handoff mentioning par-<run_id>.
INHERIT: [session-handoff] and [failover] rules apply in all phases.
</parallel_agents>
