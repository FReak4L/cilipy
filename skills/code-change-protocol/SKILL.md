---
name: code-change-protocol
description: Use for any code edit, feature, refactor or bugfix. Locate, read, make the smallest change, run the narrowest check, then widen. Keeps diffs small, correct and verified.
---

# Code change protocol

1. Locate: search symbols and usages first (gortex, grep). Read only the relevant lines plus callers.
2. Understand the contract: types, callers, tests, error paths. Check impact before touching shared symbols.
3. Plan the smallest change that meets the done-check. No unrelated refactors.
4. Edit: unique-target patches, match existing style, handle errors, no placeholder or TODO code.
5. Verify narrow to wide: build or typecheck, targeted test, full suite, linter. For bugs, add a test that fails before the fix and passes after.
6. Review the diff hunk by hunk: off-by-one, empty or null input, concurrency, leaked secrets, removed behavior.
7. Report: changed paths, verification command with result, remaining risks.

For failing tests or unexpected behavior, load `systematic-debugging`. After two failed fixes, load `loop-escape`.
