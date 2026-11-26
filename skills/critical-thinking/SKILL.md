---
name: critical-thinking
description: >-
  Rigorously evaluate claims, plans, designs, code changes, sources and your own conclusions:
  separate evidence from assumption, look for counter-evidence, steelman alternatives, and
  calibrate confidence. Use before committing to a decision, when reviewing someone's (or an
  agent's) output, when information conflicts, or before reporting a result as fact.
metadata:
  skillport:
    category: critical-thinking
    tags: [critical-thinking, evidence, bias, review, calibration]
---
# Critical thinking checklist

For each important claim (yours or another agent's):
1. **What exactly is claimed?** Restate it so it is falsifiable.
2. **Evidence:** what supports it — observed output, test, source, doc version, or only inference?
   Label each: *verified* (I ran/read it now) · *reported* (someone said) · *inferred* · *assumed*.
3. **Counter-evidence:** actively look for one fact that would disprove it. Run that check.
4. **Alternatives:** what else explains the same observations? Steelman the best alternative.
5. **Source quality:** primary > secondary; current version > old blog post; reproducible > anecdote.
6. **Scope:** does it hold in *this* environment (OS, versions, config, data size)?
7. **Confidence:** state high/medium/low and the single thing that would change your mind.

Common traps to check yourself for: confirmation bias (only testing what you expect to pass),
anchoring on the first hypothesis, sunk cost, survivorship ("it worked once"), mistaking absence
of an error for success, trusting tool/agent output without checking it, and overclaiming
("fixed", "all", "never") beyond what was tested.

Output rule: in reports, keep facts, inferences and unknowns visibly separate; never upgrade
an inference to a fact in the summary.
