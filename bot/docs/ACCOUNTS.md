# Antigravity account pool and session continuity

## Components
| File | Role |
|---|---|
| `crates/agy-core/src/accounts.rs` | `AccountStore` (`$STATE_DIR/accounts.json`, 0600), shadow homes, `AccountPolicy`, 5h vs 7d usage ledger & 1% weekly reserve, `PoolBreakerState`, `classify_failure`, reset-hint parser, selection |
| `crates/agy-core/src/proxies.rs` | `ProxyRegistry` (`$STATE_DIR/proxies.json`, 0600), 1:1 sticky proxy bindings for AGY accounts & Grok OAuth, quality scoring (`0..=100`), credential redaction, `FailClosed` vs `FallbackDirect` |
| `crates/agy-net/src/proxy.rs` | Bot transport proxy pool + `probe_proxy_route` (TLS/HTTP 204 health prober) & `Retry-After` parser |
| `crates/agy-ext/src/login.rs` | `LoginSession`: runs `agy` under `script(1)` PTY with `HOME=<shadow>` and bound sticky proxy env, extracts OAuth URL, submits code, kills process group + strays |
| `crates/agy-ext/src/engines.rs` | `EngineRequest.env_overrides` (per-run `HOME` + sticky `HTTPS_PROXY`/`HTTP_PROXY`/`ALL_PROXY`/`NO_PROXY`) |
| `crates/agy-bot/src/jobs.rs` | attempt loop in `run_job_inner`: breaker check → pick (respecting weekly reserve, concurrency cap, fail-closed proxy) → gentle pacing → run → usage accounting → classify → soft switch delay → continuity |
| `crates/agy-bot/src/handoff.rs` | transcripts (`$STATE_DIR/transcripts/<uid>.jsonl`), Replay context pack, Recall directive |
| `crates/agy-bot/src/handlers_accounts.rs` | owner-only `/accounts` panel, `acct:*` callbacks, `🛡 Policy` (`acct:pol`), per-account `🌐 Proxy` binding (`acct:px:*`), weekly token caps (`acct:cap:*`), Telegram OAuth relay |
| `crates/agy-bot/src/handlers_proxies.rs` | `/proxies` panel (`px:*`), bot transport + AI sticky proxy CRUD, live probing, Grok binding, `FailClosed`/`FallbackDirect` toggle, auto-delete of credential messages |

## Shadow HOME layout
`$STATE_DIR/accounts/accN/home` (0700) mirrors `/root` with symlinks. Inside `.gemini/antigravity-cli`, only
these entries are private: the token, `cache`, `log`, `cli.log`, `crashes`, `updater`, `last_check.timestamp`,
`installation_id`, `jetski_state.pbtxt`, `presence`, `conversation_summaries.db*`, `jetbox_summaries_proto.pb`,
`history.jsonl`, `implicit`. `conversations/` and `brain/` are shared, so `--conversation <id>` works on
any account. The summary DB is rebuilt per account from `conversations/` (agy's "reconcile" step, as seen in its logs).
The primary account (`primary`) is the real `/root` HOME and cannot be removed.

## Failover
See `/root/agy-workspace/telegram-docs/08-accounts-and-handoff.md` for the error → action table.
There are at most 8 engine attempts per turn. Network errors retry the same account once and never switch
(another account would fail the same way). After a mid-turn failure, the next account resumes the
conversation the failed attempt created, with a `[failover]` prefix.

## Continuity
Resume (primary) → Replay (`[session-handoff]` pack: handoff note plus the last exchanges, 12k chars) → Recall
(directive to use the note, ai-memory `handoff tg-<uid>`, and graphify/gortex). Replay is used when the
conversation file is missing. A context-class error downgrades continuity one step on the same account.

## Security
- Tokens are never read into logs or messages. `inspect_token` returns only Missing, Invalid, or Present{email}.
- The OAuth code message is deleted from the chat right after it is received. Codes are validated (8–512 safe chars).
- One login at a time, owner only, expires after 10 minutes. On failure the previous token (`.prev`) is restored.
- `remove` refuses the primary account, refuses paths outside `$STATE_DIR/accounts`, and never follows symlinks.

## Tests
`cargo test --workspace` covers:
- `accounts::tests::*`: classification, reset hints, persistence, shadow home isolation, selection.
- `login::tests::*`: the fake TUI relay.
- `handoff::tests::*`.
- `jobs::tests::multi_account_failover_and_session_continuity_with_fake_agy`: quota → switch and resume;
  ban → disable, owner alert, and resume; lost conversation → Replay; pool exhausted → clear message.

## Research-driven hardening (2026-11-18)
- agy's own log lines (glog `W1118 …`, `level=warn`, the transient `Singleflight refresh failed … not logged into Antigravity` WARN) are removed before classification. They can never disable an account.
- `Verify your account` / `VALIDATION_REQUIRED` → disable plus an owner alert that includes the verification URL from the error detail.
- Also recognised: `Authentication expired`, `OAuth session expired or revoked`, `invalid_client`, `unauthorized_client`, `exhausted your capacity`, `QUOTA_EXHAUSTED`/`QuotaFailure`, `credits balance is too low`, `Unable to verify account eligibility` (cooldown), `trajectory not found` (→ downgrade continuity), `inference connection failed` (network).
- A print timeout (`finished_reason=print_timeout`) and 400/INVALID_ARGUMENT never rotate accounts.
- Resume check: if agy returns a different `conversation_id` than requested and the run had ≤1 step (no side effects), the turn is redone once with Replay. Otherwise the answer is kept and a warning line is shown.

## Phase 1 & 2 Hardening (2026-11-24)
- **Strict Safe defaults** (`ACCT_POLICY_PRESET=strict_safe`): max 1 concurrent run/account, 8s minimum gap (+ jitter, scaled 1.5x at 75% and 2x at 90% weekly), 3s soft switch delay, max 4 failover attempts, and Pool Safety Breaker pausing automatic failover after 2 severe ToS/validation/ineligible incidents in 15m.
- **1% Weekly Reserve (`ACCT_WEEKLY_RESERVE_PCT=1.0`)**: persistent per-account rolling 5-hour vs 7-day ledgers. Accounts soft-park at `>= 99%` weekly usage (explicit cap or auto-calibrated on weekly quota hit). **5-hour usage never triggers the weekly reserve.**
- **1:1 Sticky Clean Proxies (`/proxies`, `$STATE_DIR/proxies.json`, `0600`)**: dedicated HTTP/HTTPS/SOCKS5/SOCKS5H proxy per Antigravity account and for Grok OAuth, with periodic 15m TLS/HTTP 204 health probing, quality scoring (`0..=100`), credential redaction, immediate chat message deletion on paste, and `FailClosed` default (never silently leaks direct server IP when a bound proxy goes down).
- **Grok/OpenAI `Retry-After` compliance**: honors upstream `Retry-After` headers with exponential backoff and jitter on HTTP 429/5xx.
- **3-page tabbed `/menu`**: Page 0 (AI & Chat), Page 1 (Tools, Proxies & Settings), Page 2 (Owner Accounting, Proxies & Safety Policy).

## Phase 3 Hardening (2026-11-24)
- **Live `agy` stream guard (`AgyGuardConfig`)**: tracks distinct tool calls deduplicated by `step_index`/`tool_call_id` (`AGY_MAX_STEPS_PER_TURN=60`, `AGY_TOOL_REPEAT_LIMIT=4`, `AGY_MAX_TOOLS_PER_MIN=45`), issuing a clean `SIGINT -> SIGTERM -> SIGKILL` stop on runaway loops without penalizing or rotating accounts.
- **Anti-DDoS & security headers**: `http_guard` protects `:8787` (`HTTP_RL_PER_MIN=120`, `HTTP_MAX_CONCURRENCY=64`, `HTTP_REQ_TIMEOUT_SECS=30`, loopback `/healthz` exempt, proxy headers trusted only from loopback, full security headers + Telegram `frame-ancestors`); `WebAppState` enforces per-UID `/api/w/*` limits; Telegram applies per-UID anti-flood (`TG_USER_RL_PER_MIN=30`, owner 3x headroom, `/stop` exempt); `AclStore` caps pending strangers (`ACL_MAX_PENDING=100`) with 60s disk debounce; `JobManager` enforces `MAX_GLOBAL_AI_JOBS=4`.
- **Outbox secret scanner (`OUTBOX_SECRET_SCAN=1`)**: scans text/config outbox files for leaked tokens, private keys, proxy credentials, and live runtime secrets before Telegram upload, blocking compromised files with a secret-free chat alert.

## Phase 4 Efficiency & Local Autonomy (2026-11-24)
- **Compact resume prompt (`PROMPT_COMPACT_RESUME=1`)**: strips repeated bridge/handoff boilerplate on resumed turns while auto-restoring the full header on first turns, isolated runs, and failovers.
- **Dynamic turn profiles (`AGY_DYNAMIC_PROFILE=1`)**: optimizes `lite` conversational turns (`--effort low` if unset + `--disable-slash-commands`) while leaving MCPs, skills, and `.md` rules untouched.
- **Local fast-path (`LOCAL_FAST_PATH=1`) & read-only MCP TTL cache (`MCP_RO_CACHE_TTL_SECS=45`)**: serves zero-token ping/time/status/math replies in Rust (RBAC-enforced), caches verified read-only MCP queries with instant write invalidation, and applies 16 KiB head+tail early tool compaction in Grok/Venice sessions.
