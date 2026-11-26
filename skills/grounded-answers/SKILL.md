---
name: grounded-answers
description: Use before stating any fact about code, files, APIs, flags, versions, numbers or results, and whenever unsure. Grounds claims in evidence, labels confidence, and stops hallucination.
---

# Grounded answers

## Rules
1. No evidence, no claim. Facts about this machine or repo come from tool output in this session. Cite `path:line` or the command.
2. Never invent paths, symbols, CLI flags, config keys, versions, URLs or test results. Unseen means check it (`grep`, `read`, `--help`, context7 docs) or say "unverified".
3. Label claims: verified (checked now) · reported (doc, user, agent) · inferred · unknown.
4. Third-party APIs: read the docs for the installed version before writing code against them.
5. Before saying done, fixed or passing: run the check, read the full output, quote the key line.
6. When tool output contradicts your expectation, trust the output and revise the plan.

## Tripwires: stop and verify when
- you are about to write a name or path you have not seen in tool output;
- the answer feels obvious but is unchecked;
- it involves numbers, dates, versions, limits or quotas;
- a result is reported by another agent or an old note.

## If you cannot verify
State what is unknown, what would verify it, and give your best guess marked as a guess.
