---
name: self-critique
description: >-
  Structured self-review pass on your own plan, code, answer or report before handing it over:
  red-team it against the requirements, edge cases, failure modes and overclaims, then fix what
  you find. Use right before finishing any substantive task, before merging multi-agent results,
  and after any long autonomous run.
metadata:
  skillport:
    category: critical-thinking
    tags: [self-review, red-team, quality-gate, verification]
---
# Self-critique pass

Do this as a deliberate second pass, in the role of a skeptical senior reviewer who did not write it.

1. **Requirement trace:** list every requirement/acceptance criterion; mark each met (with the
   evidence), partially met, or not met. Missing items are blockers.
2. **Does it actually run?** Re-run the verification command now; read its full output (exit code,
   warnings, counts). Old output does not count.
3. **Edge cases & failure modes:** empty/huge input, concurrency, permissions, network failure,
   restart/reboot, idempotency (run twice), rollback path.
4. **Simplicity:** anything unnecessary, duplicated, or speculative? Remove it.
5. **Safety:** secrets in code/logs/output? destructive commands? scope creep beyond the request?
6. **Claims audit:** every "works/fixed/done/all" in the report — is there evidence? Downgrade
   or remove unsupported claims; list known limits explicitly.
7. **Pre-mortem:** "It's a week later and this failed — what's the most likely reason?" Mitigate
   or disclose it.

Fix the issues found, then re-verify. Report remaining limitations honestly rather than hiding them.
