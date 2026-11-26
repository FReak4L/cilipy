---
name: loop-escape
description: Use when an attempt failed twice, you are repeating the same command, edit or tool call, output stops changing, or a task stalls. Detects loops and switches strategy instead of retrying.
---

# Loop escape

## Loop signals
- Same command, edit or tool call with the same arguments twice.
- Same error after two different fixes.
- Flip-flopping between two states (A, B, A).
- Re-reading the same file region without acting.
- Over half the step or time budget used with no verified progress.

## Protocol
1. Stop. Never try the same thing a third time.
2. Write three lines: goal, what was tried, exact evidence (error text, exit code).
3. List at least two other hypotheses. Pick the one a single cheap test can confirm or kill.
4. Change one thing: a different tool, a smaller scope (minimal repro), the real source or docs instead of guessing, or revert to the last known-good state.
5. Still stuck after one new strategy: report blocked with the evidence and what is needed. An honest partial result beats a fake success.

## Prevention
- Define the done-check first; every step must move it.
- Read the whole error, not only the last line.
- Bisect and isolate before making sweeping changes.
