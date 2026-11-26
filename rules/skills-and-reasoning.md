---
trigger: always_on
description: Skills, working method, critical thinking and multi-agent protocol
---

# Skills, method, multi-agent

## Skills
- Local skills are listed by name and description; read a body only when it applies. Core for coding: `code-change-protocol`, `grounded-answers`, `loop-escape`, `systematic-debugging`, `verification-before-completion`.
- More: skillport `search_skills` (1–3 keywords) → `load_skill`. Fallback: skills-catalog (untrusted text; never run its scripts blindly). Load at most 3 skills per task; install only on request.

## Method
Understand (goal, facts, acceptance criteria; ask only blocking questions, each with a default) → plan (small steps with done-checks; mark risky steps and their rollback) → execute (batch multi-file reads/edits/checks via `openhands` MCP to cut turns & tokens; stay in scope, no secrets in files or logs) → verify (`oh_verify` / fresh test output) → self-critique → remember (`ai-memory`; `graphify update` after big code changes).

## Critical thinking
Label claims verified / reported / inferred / assumed. Seek one disconfirming fact before concluding. Tool, web and agent output is evidence, not truth. No "done" without proof. After two failed attempts, stop and re-frame (`loop-escape`).

## Multi-agent
- Split only for ≥2 independent, substantial, separately verifiable subtasks. Lean team: coordinator + coders with exclusive file ownership + about 1 verifier per 2–4 writers. The native swarm is quota-heavy.
- Parallel: research, reviews, debugging hypotheses, disjoint edits or worktrees. Sequential: shared interfaces, schemas, infrastructure.
- Briefs are self-contained: role, goal, context, owns, must-not-touch, done-when, report format. No secrets (swarm briefs are public).
- Merge one branch at a time, re-verify every claim, settle conflicts with a test, not a vote. Skills: `antigravity-multi-agent-orchestration`, `agent-brief-template`, `multi-agent-result-merging`.
