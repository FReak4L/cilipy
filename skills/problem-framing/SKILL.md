---
name: problem-framing
description: >-
  Turn a vague or ambiguous request into a precise problem statement with goals, constraints,
  acceptance criteria and open questions before any planning or coding. Use at the start of any
  non-trivial task, when requirements are unclear, when the request mixes problem and solution,
  or when previous attempts solved the wrong thing.
metadata:
  skillport:
    category: problem-understanding
    tags: [requirements, problem-statement, acceptance-criteria, clarification]
---
# Problem framing

Produce this short block before planning (keep it under ~15 lines):

```
Goal (outcome, not solution):
Context / current state (verified facts, with source):
Constraints (must / must not; environment, versions, budget, time):
Non-goals (explicitly out of scope):
Acceptance criteria (observable, testable checks that mean "done"):
Assumptions (unverified — mark how each will be checked):
Open questions (blocking vs non-blocking):
Risks / irreversible steps:
```

Method
1. Restate the request in your own words; separate the *problem* from any *solution* the user named.
   Ask "what would be true if this were solved?"
2. Gather context cheaply first: read the relevant code/config (use gortex/graphify for code
   structure), search ai-memory for prior decisions, check logs. Facts beat guesses.
3. Ask *why* until you reach the real need (usually 2–3 levels); stop when the goal is concrete.
4. Make acceptance criteria executable where possible (a command, a test, a URL, a metric).
5. Ask the user only blocking questions, batched in one message, each with your proposed default.
   For non-blocking ones, choose the default, state it, proceed.
6. Re-read the original request once more at the end and confirm nothing was dropped.
