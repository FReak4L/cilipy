---
name: antigravity-multi-agent-orchestration
description: >-
  Decide whether and how to split work across multiple agents in Antigravity (subagents or the
  native swarm), then run the full loop: frame, decompose, assign roles, brief, run parallel or
  sequential, merge, verify, critique. Use for any large or multi-part task, when 2+ independent
  subtasks exist, or when the user asks for multi-agent / parallel work.
metadata:
  skillport:
    category: multi-agent
    tags: [multi-agent, antigravity, swarm, subagents, orchestration, parallel]
---
# Multi-agent orchestration in Antigravity

## 1. Should I split?
Split when **all** hold: ≥2 subtasks that can proceed independently; each is big enough to be worth
a fresh context (>~10 min of work or a large read); outputs can be verified separately.
Do **not** split: small tasks, tightly coupled edits behind one interface, one-file changes,
or when the plan itself is still unclear (frame and plan first). Swarm is preview and quota-heavy:
use it only when parallelism clearly pays off; otherwise a single agent or a couple of subagents.

## 2. Parallel vs sequential
- **Parallel:** read-only research/review/debug angles; implementation with disjoint file ownership
  or isolated workspaces (swarm `branch` workspace / git worktrees).
- **Sequential:** dependent steps (schema → API → UI), shared interfaces, migrations, anything on
  shared infra (DB, firewall, services) — one writer at a time.
- Mixed pipeline (typical): plan → parallel coders → parallel verifiers → integrator → final review.

## 3. Loop
1. Frame (`problem-framing`), plan (`writing-plans` / `task-coordination-strategies`).
2. Choose roles (`agent-team-roles`), size the team lean (+1 verifier per 2–4 writers).
3. Brief each worker (`agent-brief-template`) — self-contained, ownership, done-checks, evidence.
4. Run: swarm (`swarm` add/post_message/read_board/swarm_wait) or subagents; coordinator does not do
   the technical work, it watches, unblocks, reassigns.
5. Merge + cross-verify (`multi-agent-result-merging`); share state per `multi-agent-shared-state`.
6. Final `self-critique` and `verification-before-completion`, then report.

Related skills: dispatching-parallel-agents, subagent-driven-development, parallel-debugging,
parallel-feature-development, multi-reviewer-patterns, review-swarm, bug-hunt-swarm.
