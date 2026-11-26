# 08 · Multiple accounts, models and session handoff

The bridge (Rust, `/opt/agy-telegram-rs`, service `agy-telegram.service`) runs agy through
a **pool of Antigravity accounts**. The owner manages the pool from the **Accounts** button
(or `/accounts`): add (Google sign-in link → paste code), enable/disable, rename, priority,
reset health, remove. Each extra account gets its own shadow `HOME`
(`/var/lib/agy-telegram/accounts/accN/home`, mode 0700): only the credentials and per-install
files are private, while conversations, brain, MCP config, rules and skills are shared.

- Accounts are shown as `accN · ma…ei@domain` (masked e-mail). Only the owner sees them.
- Two accounts signed in with the **same e-mail** are reported to the owner once as duplicates.
  The bridge never deletes an account on its own.
- An account that is running a job cannot be removed or re-logged in until the job ends.
- `/mcp`, the agents list and `/changelog` run **as the user's current account** (its shadow
  `HOME`), not always as the primary.

## Models are per account
Each account has its own model list (`agy models`, list-only, no quota used), cached in
`/var/lib/agy-telegram/accounts/<id>/models.json` (primary: `/var/lib/agy-telegram/models.json`)
and refreshed every 6 hours. The **Models** picker shows the list of the user's current account.

- Every run passes an explicit `--model`. Without a saved choice the bridge uses the shared
  default from `settings.json` only if this account offers it, else the account's first model.
- **No silent substitution.** If the user's model is not on the account the job lands on (or
  agy rejects it), the job **pauses** and the user gets that account's models as buttons. After
  the pick the **same prompt continues in the same conversation**. Cancel or no answer
  (timeout) drops the task. The user's own saved model stays unchanged.
- Saved models that no account offers anymore are marked invalid; the user is asked to pick on
  their next message.

## What happens when an account fails
| agy error (examples) | Class | Bridge action |
|---|---|---|
| `violation of Terms of Service`, `submit an appeal` | banned | disable account, alert owner, switch |
| `not eligible`, `not available in your location` | ineligible | disable, alert, switch |
| `not logged into Antigravity`, `invalid_grant`, 401, auth timeout | auth | disable, alert, switch |
| `Individual quota reached`, 5-hour/weekly/daily limit | quota | cooldown until the reset hint (default 5h, 24h or 6h), switch |
| `Out of credits`, spend cap, subscription/billing | subscription | 24h cooldown, switch |
| model not found / not available for this account | model unavailable | **no cooldown**; pause and ask the user to pick a model (see above) |
| 429 / rate limit | rate limit | short cooldown (≥30s), switch |
| capacity / 5xx / overloaded | capacity | 2 min cooldown (escalates if repeated), switch |
| network / timeout / DNS | network | retry the same account once |
| crash, or exit without an answer | crash | retry once, then switch (3 in a row → cooldown) |
| prompt too long / bad request | context | downgrade continuity (Resume → Replay → Recall) |

Users see one short line ("🔁 Switching account…"). If no account is available, users are told
when the next one frees up. A run that hangs past the print timeout plus a grace period
(default 120 s) is killed with its whole process group.

**Telegram flood control:** when Telegram answers 429, the bridge waits at most 30 s per retry
and 60 s per call (`TG_MAX_RETRY_AFTER_SECS`, `TG_MAX_RETRY_AFTER_TOTAL_SECS`). Past that,
answers go to the persistent outbox and are delivered later; progress edits are dropped.

## Continuity: one primary method, two fallbacks
1. **Resume**: shared `conversations/` lets any account run `--conversation <id>`.
2. **Replay**: new conversation and a `[session-handoff]` context pack built from
   `/root/agy-workspace/.handoff/tg-<uid>.md` plus the last exchanges from the bridge transcript
   (`/var/lib/agy-telegram/transcripts/<uid>.jsonl`, 0600, secrets redacted, 12k-char budget).
3. **Recall**: a `[session-handoff]` directive tells you to rebuild context from the note and
   ai-memory (`handoff tg-<uid>`), and from graphify/gortex if code context is needed.

**Your part:** follow `~/.gemini/config/rules/session-handoff.md`.

- **Session start:** `memory_search` for `handoff tg-<uid>` (and `conv <id>` if known), read the
  note if present, and resume without re-asking.
- **Milestones and before long operations:** overwrite the note in the session-handoff / handoff
  skill's five-section format (**Goal of next session**, **State of play**, **Open decisions**,
  **Skills to use**, **Artifacts**). Then refresh the ai-memory record: `memory_update` cannot
  change `content`, so `memory_delete` the previous handoff id and `memory_store` a new one
  (`type: context`, `title` + `summary` each ≤200 chars, tags `handoff`, `tg-<uid>`).
- **Prompt markers:** official `[session-handoff]` (Replay pack or Recall directive; alias
  `[handoff-resume]`); mid-turn switch `[failover]`. Continue without re-asking or redoing
  finished work.

With good notes, fallbacks 1 and 2 are nearly lossless. Parallel mode is in
[09-parallel.md](09-parallel.md).

## Safety policy, 1% weekly reserve & sticky proxies
- **Policy (`/accounts` → `🛡 Policy & Reserve`)**: defaults to `strict_safe` (1 concurrent run/account, 8 s pacing gap + jitter, 3 s failover switch delay, max 4 attempts, Pool Safety Breaker after 2 severe ToS/validation/ineligible hits in 15 min).
- **1% weekly reserve**: rolling 5-hour and 7-day usage ledgers are tracked separately; accounts soft-park at ≥99% weekly usage (owner cap or auto-calibrated on weekly quota hit). 5-hour usage never triggers the weekly reserve.
- **Sticky proxies (`/proxies`, also in `/menu` Pages 0/1/2)**: owner manages dedicated HTTP/HTTPS/SOCKS5/SOCKS5H proxies with live TLS/HTTP 204 health probing, EWMA latency + quality scoring (`0..=100`), credential redaction, immediate deletion of pasted proxy messages, 1:1 per-account & Grok OAuth binding, and `FailClosed` default (never silently falls back to direct server IP).
- **Phase 3 security & live AI guards**: live `agy` NDJSON stream guard stops repeated tool loops (`AGY_TOOL_REPEAT_LIMIT=4`, targetless batch file-tool headroom `3x`), runaway step counts (`AGY_MAX_STEPS_PER_TURN=80`), and tool bursts (`AGY_MAX_TOOLS_PER_MIN=45`) via clean `SIGINT` without penalizing accounts; Axum `:8787` enforces per-IP & per-UID rate limiting (`HTTP_RL_PER_MIN=120`), concurrency cap (`64`), request timeout (`30s`), and full security headers; Telegram enforces per-UID anti-flood (`TG_USER_RL_PER_MIN=30`, `/stop` exempt), `/start` pending cap (`ACL_MAX_PENDING=100`) with 60s disk debounce, global AI job semaphore (`MAX_GLOBAL_AI_JOBS=4`), and outbox secret-leak scanning (`OUTBOX_SECRET_SCAN=1`).
- **Phase 4 token hygiene & local autonomy**: resumed turns use a compact 1-line `[telegram-bridge]` header (`PROMPT_COMPACT_RESUME=1`, auto-expanding to full header on first turn or failover); dynamic turn profiling (`AGY_DYNAMIC_PROFILE=1`) optimizes `lite` chat turns without touching MCPs, skills, or `.md` rules; `LOCAL_FAST_PATH=1` answers unambiguous ping/time/status/math queries locally in Rust (0 AI tokens, strict RBAC); verified read-only MCP calls use a 45s TTL cache with instant write invalidation (`MCP_RO_CACHE_TTL_SECS=45`) alongside early 16 KiB head+tail tool-output compaction (`AGENT_TOOL_OUTPUT_MAX_BYTES=16384`).
