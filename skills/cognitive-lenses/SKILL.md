---
name: cognitive-lenses
description: Compact multi-perspective operational falsification protocol (First-Principles, Skeptic, Pre-Mortem, Builder, Second-Order) for complex architecture, debugging, risk analysis, and strategy. Use when facing hard trade-offs, security/prod risks, ambiguous root causes, or multi-step designs. Don't use on trivial Q&A or simple one-line edits.
---

<skill id="cognitive-lenses">
# Evidence basis: generic roleplay personas degrade factual/coding accuracy (arXiv:2603.18507).
# Use concrete, falsifiable operational checks instead — strictly gated by task complexity.

<activation_gate>
trivial_qa | simple_1file_edit -> SKIP (0 lenses; answer/patch directly)
bug | flaky_test | audit       -> FIRST_PRINCIPLES + SKEPTIC
arch | prod_deploy | strategy  -> ALL_5 (concise internal pass; output ONLY actionable conclusions)
</activation_gate>

<lenses>
1. FIRST_PRINCIPLES (root constraints):
   - Strip abstractions/assumptions. What are the hard physical/OS/protocol/byte/type invariants?
   - What is directly observed vs inferred?
2. SKEPTIC (critical falsification):
   - What single test, counter-example, or command could DISPROVE my hypothesis right now?
   - Are any tool outputs, docs, or prior assumptions stale or unverified?
3. PRE_MORTEM (pessimist / failure-mode guard):
   - Assume this change ALREADY broke production 10 minutes after deploy.
   - Name the top 2 concrete failure modes (race, edge input, quota/429, secret leak, silent truncation, partial state) and add explicit guards/rollback.
4. BUILDER (pragmatic optimist):
   - What is the smallest, cleanest, reversible change that delivers verified value right now?
   - Cut speculative abstractions and scope creep.
5. SECOND_ORDER (futurist / systems impact):
   - What breaks or degrades 10 turns or 30 days later? (KV-cache thrashing, token tax, multi-account failover, cross-user isolation, CI/release friction).
</lenses>

<output_rule>
NEVER write theatrical roleplay headings ("As a pessimist..."). Emit ONLY the concrete decisions, guards, disconfirming checks, and minimal verified plan.
</output_rule>
</skill>
