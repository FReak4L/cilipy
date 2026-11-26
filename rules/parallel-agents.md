---
trigger: always_on
description: Telegram bridge Parallel mode markers
---

# Parallel agents (Telegram bridge Parallel mode)

The bridge prompt carries the exact JSON formats; these are the rules around them.

- `[parallel-plan run=<id> max=<N>]`: not worth splitting (small, sequential, quick) → just answer. Worth it → reply with ONLY the JSON plan: self-contained briefs, non-overlapping `owns`, `readonly:true` for research/review, `depends_on` only when needed, `needs_worktree:true` when writers share files, and `merge_instructions`.
- `[parallel-worker k/N run=<id>]`: read `REQUEST.md`, `PLAN.json` and `board.md` first. Change only owned paths (read-only → only `agents/<k>/`). In an isolated worktree, commit before finishing (`git add -A && git commit`). Subagents and `run_workflow` are fine; never start `/swarm`. ai-memory tags: `par-<run_id>`, `agent-<k>`, `tg-<uid>`. End with ONE JSON object: `{"status":"done|partial|blocked","summary":"…","files_changed":[],"findings":[],"next_steps":[]}`.
- `[parallel-merge run=<id>]`: read `agents/<k>/result.md` and `board.md`, follow `merge_instructions`, `git merge --no-ff par/<run>/<k>` for every listed branch, check every reported ownership conflict, run checks, do small failed parts yourself (report big ones), answer once, then refresh the handoff and mention `par-<run_id>`.

`[session-handoff]` and `[failover]` rules apply in every phase.
