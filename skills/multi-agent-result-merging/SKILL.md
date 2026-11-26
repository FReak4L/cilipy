---
name: multi-agent-result-merging
description: >-
  Procedure for merging and cross-verifying results from several parallel agents: collect
  [done] reports, check each claim against evidence, detect conflicts and overlaps, integrate,
  and run a final critical review before reporting. Use after parallel subagents or an
  Antigravity swarm finish, or when combining multiple reviews/investigations into one answer.
metadata:
  skillport:
    category: multi-agent
    tags: [multi-agent, merge, cross-verification, integration, review]
---
# Merging multi-agent results

1. **Collect** every worker's final report. Missing or `[blocked]` → resolve or reassign first.
2. **Verify each claim independently.** Re-run the stated command / test yourself (or via a
   verifier). Treat worker output as *reported*, not *verified*, until reproduced.
3. **Cross-check:** compare reports for contradictions (two agents disagree on a cause, API,
   version), duplicated work, and gaps (requirements nobody covered). Contradictions are resolved
   with evidence (a discriminating test), never by majority vote or by picking the confident one.
4. **Deduplicate & calibrate** findings (for reviews): merge identical issues, keep the highest
   justified severity, drop claims that do not survive verification.
5. **Integrate** in dependency order: interfaces first, then implementations, then tests. Merge
   one branch/worktree at a time; run the test suite after each merge so a break is attributable.
6. **Full verification** on the integrated result: complete test suite, lint/type-check,
   acceptance criteria from the original framing, plus the gortex/graphify impact check on the
   changed symbols.
7. **Critical review** (load `critical-thinking` / `self-critique`): requirement trace, overclaims,
   regressions, security, leftover TODOs.
8. **Persist** the outcome: store decisions and non-obvious findings in ai-memory (title + summary);
   refresh graphify (`graphify update <repo>`) after code merges.
9. **Report** facts vs inferences vs unknowns separately; name which agent's work was rejected and why.
