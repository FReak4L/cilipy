---
name: multi-agent-shared-state
description: >-
  How multiple Antigravity agents/subagents share state safely through the local MCP servers:
  ai-memory for decisions and findings, gortex and graphify for a common view of code structure,
  skillport for shared procedures, plus file/branch ownership. Use when coordinating more than one
  agent on the same project or when a later session must continue earlier agents' work.
metadata:
  skillport:
    category: multi-agent
    tags: [multi-agent, ai-memory, gortex, graphify, shared-state, coordination]
---
# Shared state for agent teams

Agents do not share context windows. Share state through durable, queryable stores — never
by assuming another agent "knows".

| Need | Store / tool | Convention |
|---|---|---|
| Decisions, constraints, findings, gotchas | **ai-memory** | Coordinator searches it once at start and passes relevant ids/titles in briefs. Workers store only final, durable facts: `title` = `<project>: <topic>`, `summary` 1–2 lines, tags incl. project + task. No secrets, no code reproducible from source, no scratch notes. |
| Code structure, symbols, callers, impact | **gortex** (live index) and **graphify** (graph.json) | Every agent queries these instead of each re-reading the repo. Run impact analysis before editing a shared symbol; after merging, the integrator runs `graphify update <repo>` so later agents see the new graph. |
| Procedures (how to debug, review, plan…) | **skillport** (curated), **skills-catalog** (fallback) | Briefs name the skill to load (`load_skill`), so all workers follow the same method. |
| Work ownership & progress | brief + board (`[done]`, `[blocked]`) or plan file | One owner per file. Status lives on the swarm board or in a plan file in the repo, not in memory. |
| Code changes | git branches / worktrees | One branch per writer; integrator merges. Never two writers on one working tree. |

Rules
- Read before write: search ai-memory for the topic before storing, update instead of duplicating.
- A memory written by one agent is *reported* information for others — verify before relying on
  it for anything risky.
- Keep tool calls targeted; don't have every worker dump the whole graph or memory.
