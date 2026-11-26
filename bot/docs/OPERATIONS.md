# `agy-telegram-rs` Operations, Cutover & Update Runbook

## CLI Modes (`agy-telegram`)
- `agy-telegram` (default): Start dual HTTP/WebApp/Webhook server (`127.0.0.1:8787`), Poller/Webhook/Auto transport, Cron/Sync scheduler, OutQueue worker, and `sd_notify` Watchdog.
- `agy-telegram --check`: Validate env config (`BOT_TOKEN`, `OWNER_ID`, paths), verify RW access on `STATE_DIR`, lint all 4 built-in widgets (`<= 4096 B` zlib-9), verify MCP config schema without starting polling.
- `agy-telegram --health`: Probe local WebApp `/healthz`, `$STATE_DIR/health.json` freshness (`<= 120s`), and `stall_s` threshold; exit non-zero if unhealthy.
- `agy-telegram --bench-ab`: Execute in-memory deterministic A/B benchmark harness (render, ACL, widget build+zlib, RSS KB) and emit JSON on stdout.
- `agy-telegram --self-update <staged-binary>` / `/update`: Atomically verify staged ELF (`--check`), back up active `/opt/agy-telegram/bin/agy-telegram` to `/opt/agy-telegram/backups/bin/`, atomically replace binary, and provide rollback restore (`--rollback`).

## Transport & Proxy Modes
- `TG_TRANSPORT`: `polling` (default), `webhook` (`https://example.sslip.io/tg/webhook` with `WEBHOOK_SECRET`), or `auto` (tries webhook registration when `WEBHOOK_URL` + `WEBHOOK_SECRET` are set, automatically falling back to long-polling if unreachable).
- `PROXY_URLS`: Comma/semicolon-separated list of `direct`, `http://...`, `https://...`, `socks5://...`, `socks5h://...`.
- `PROXY_MODE`: `failover` (default priority order with circuit breaker), `round_robin`, or `race` (health/EWMA-latency adaptive selection).
- **AI Account Safety & Sticky Proxies (`/accounts`, `/proxies`)**:
  - `ACCT_POLICY_PRESET`: `strict_safe` (default) or `balanced`.
  - `ACCT_WEEKLY_RESERVE_PCT`: Weekly reserve percentage (`1.0` default → parks at 99% weekly; never triggered by 5-hour usage).
  - `ACCT_WEEKLY_TOKEN_BUDGET`: Optional default 7-day token ceiling (`0` = auto-calibrate on weekly hit or per-account UI cap).
  - `ACCT_MAX_CONCURRENCY`: Max concurrent runs per account (`1` in `strict_safe`, `2` in `balanced`).
  - `ACCT_MIN_GAP_SECS`, `ACCT_SWITCH_DELAY_SECS`, `ACCT_MAX_ATTEMPTS`: Gentle pacing gap (`8s`), failover delay (`3s`), max failover attempts (`4`).
  - `POOL_SEVERE_BREAKER_N`, `POOL_SEVERE_BREAKER_WINDOW_SECS`: Pool Safety Breaker threshold (`2` severe hits in `900s`).
  - `ACCT_PROXY_FALLBACK`: `fail_closed` (default — blocks account instead of leaking server IP) or `fallback_direct`.
- **Phase 3 Anti-DDoS, Security & Live AI Guard**:
  - `AGY_MAX_STEPS_PER_TURN`: Live `agy` stream max distinct tool calls per turn (`60` default, `0` disables).
  - `AGY_TOOL_REPEAT_LIMIT`: Consecutive identical tool calls before clean `SIGINT` loop-guard stop (`4` default, `0` disables).
  - `AGY_MAX_TOOLS_PER_MIN`: Sliding 60s tool-call burst cap (`45` default, `0` disables).
  - `HTTP_RL_PER_MIN`, `HTTP_MAX_CONCURRENCY`, `HTTP_REQ_TIMEOUT_SECS`: Axum `:8787` anti-DDoS limits (`120/min` per IP + per UID on `/api/w/*`, `64` concurrent, `30s` timeout; loopback `/healthz` exempt).
  - `TG_USER_RL_PER_MIN`: Per-UID Telegram anti-flood limit (`30/min`, owner 3x headroom, `/stop` always exempt).
  - `MAX_GLOBAL_AI_JOBS`: Server-wide concurrent AI execution semaphore (`4` default, anti-OOM).
  - `ACL_MAX_PENDING`: Maximum persisted unapproved `/start` strangers (`100` default) with 60s disk-flush debounce.
  - `OUTBOX_SECRET_SCAN`: Scan text/config outbox files for leaked tokens/keys/proxy credentials before Telegram upload (`true` default).
- **Phase 4 Token Hygiene, Dynamic Profiles & Local Autonomy**:
  - `PROMPT_COMPACT_RESUME`: Compact 1-line `[telegram-bridge]` header on resumed turns (`true` default; full header on first turn, isolated runs, or failover/Replay/Recall).
  - `AGY_DYNAMIC_PROFILE`: Classify incoming prompts locally into `lite`/`standard`/`full` (`true` default; trims unused slash expansion & default effort on `lite` chat while keeping all MCPs, skills, and `.md` rules intact).
  - `LOCAL_FAST_PATH`: Answer unambiguous ping/time/status/math queries locally in Rust with strict RBAC (`true` default; 0 AI tokens).
  - `MCP_RO_CACHE_TTL_SECS`: Short-TTL in-memory cache for verified read-only MCP tool responses with instant server-wide invalidation on any mutating call (`45` default, `0` disables).
  - `AGENT_TOOL_OUTPUT_MAX_BYTES`: Early head+tail (70%/25%) compaction cap for heavy Grok/Venice tool outputs (`16384` default; clamped `4096..=65536`).

## Built-in Cron & Sync Scheduler (`CRON_ENABLED=1`)
- `models_sync` (`0 */6 * * *`): Refreshes `$STATE_DIR/models.json` via configured AI engine.
- `mcp_health_sync` (`*/15 * * * *`): Audits configured MCP server definitions & redacted state.
- `memory_cache_sync` (`*/10 * * * *`): Updates lightweight memory overview metrics cache without LLM prompts.
- `inbox_gc` (`15 4 * * *`): Removes temporary downloaded inbox/staged files older than 7 days.
- Manageable interactively via `/cron` (owner/admin view, manual trigger, enable/disable) backed by `$STATE_DIR/cron_jobs.json`.
