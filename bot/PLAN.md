# `agy-telegram-rs` — Full Rust Architecture & Rebuild Plan

**Goal:** Replace the monolithic Python `@your_agy_bot` bridge (`/opt/agy-telegram/app`, 11,768 LOC) with a compiled, modular, zero-panic Rust workspace (`/opt/agy-telegram-rs`) that preserves 100% behavioral & on-disk JSON compatibility while upgrading networking, proxies, webhooks, cron/sync jobs, multi-engine process supervision, modern typed error handling, performance, and atomic self-update/rollback.

## Workspace Crates & Ownership Boundaries

1. **`agy-core` (`crates/agy-core`)**
   - `error.rs`: `BridgeError` (`thiserror`) with structured variants (`Io`, `Json`, `Config`, `Auth`, `PermissionDenied`, `Network`, `BotApi`, `RateLimited`, `Process`, `Validation`, `Cron`, `Updater`).
   - `config.rs`: `Config::from_env()` reading all env keys (`STATE_DIR`, `AGY_BIN`, `AGY_WORKSPACE`, `BOT_TOKEN`, `OWNER_ID`, `ALLOWED_USER_IDS`, `ALLOW_INLINE_WIDGETS`, `WEBAPP_BASE_URL`, `WIDGET_PORT`, `FORCE_IPV4`, `POLL_TIMEOUT`, `WD_SOFT`, `WD_HARD`, `STREAM_INTERVAL`, `AGY_JOB_TIMEOUT`, `AGY_SKILLS_DIR`, `SKILLPORT_SKILLS_DIR`, `SKILLS_CATALOG_JSON`, `MCP_CONFIG_PATH`, `AI_MEMORY_MCP_BIN`, `SKILLS_CATALOG_MCP_BIN`, `PREMIUM_UI`, plus new `TG_TRANSPORT`, `WEBHOOK_URL`, `WEBHOOK_SECRET`, `PROXY_URLS`, `PROXY_MODE`, `AGY_ENGINE`, `CRON_ENABLED`, `SYNC_INTERVAL_S`) with secret-safe `Debug` impl (`[REDACTED]`).
   - `atomic.rs`: Atomic temp-file write + `0600` chmod + rename helper; directory sync safety.
   - `store.rs`: Thread-safe `StateStore` preserving `/var/lib/agy-telegram/state.json` schema (`users`, `meta`, defaults: `conversation_id`, `model`, `effort`, `mode`, `skip_permissions`, `stream`, `stream_mode`, `render`, `trace`, `cwd`, `agent`, `history`).
   - `acl.rs`: `AclStore` preserving `/var/lib/agy-telegram/acl.json` schema (`users`, `selected`, `suppressed_seeds`, `mcp_requests`) with full parity: owner protection invariants, `record_start_attempt` (300s cooldown), individual/bulk/preset mutations (`skills_manage`, `mcp_manage`, `root_access`), 100-capped idempotent `mcp_requests`.
   - `outbox.rs`: `OutQueue` preserving `outqueue.json` schema with SHA-256 dedupe key, 6h TTL, AWS full-jitter backoff.
   - `health.rs`: `Health` metrics + `health.json` atomic writer compatible with `/opt/agy-telegram/healthcheck.sh` plus transport/proxy/cron telemetry.

2. **`agy-render` (`crates/agy-render`)**
   - `render.rs`: Pure-Rust Markdown -> Telegram HTML (`esc`, `esc_attr`, `utf16_len`, `cut_utf16`, `escape_markdown_v2`, GFM tables -> aligned monospace `<pre>` with Unicode display width, `<details><summary>...</summary>` -> `<blockquote expandable>`, fenced code, spoilers `||...||`, underline `==...==`, bold/italic/strike, safe links), `split_html` (UTF-16 limit keeping open tags balanced), `split_markdown` (block/fence aware for 32,768 UTF-16 / 500 blocks), `md_cell`, `strip_md`.
   - `premium.rs`: `Premium` (`DEFAULT_IDS` 17 vetted `RestrictedEmoji` IDs + runtime overlay from `$STATE_DIR/emoji.json` + single-emoji `_fallback_by_id`), `EFFECTS`, `e()`, `md()`, `button()`, `strip_custom_emoji()`, `strip_md_custom_emoji()`, `strip_icons()`, `looks_premium_error()`.

3. **`agy-net` (`crates/agy-net`)**
   - `proxy.rs`: `ProxyPool` supporting direct + `http://` + `https://` + `socks5://` / `socks5h://` endpoints, round-robin / failover / latency health-scoring, automatic quarantining of failing routes with cooldown recovery, secret-redacted proxy display labels.
   - `client.rs`: Typed **Telegram Bot API 10.4** client built on `reqwest` (`rustls-tls`, `socks`, TCP keepalive, configurable IPv4-only / dual-stack, AWS full-jitter retry, circuit breaker, 429 `retry_after` honoring). Supports all methods: `getMe`, `getUpdates`, `setWebhook`, `deleteWebhook`, `getWebhookInfo`, `sendMessage`, `editMessageText` (HTML & `InputRichMessage`), `sendRichMessage`, `sendRichMessageDraft`, `sendWidget`, `sendSharedWidget`, `editMessageWidgetData`, `editSharedWidgetData`, `answerWidgetQuery`, `answerCallbackQuery`, `deleteMessage`, `sendChatAction`, `setMyCommands`, `setChatMenuButton`, `sendDocument`/`Photo`/`Video`/`Audio`/`Voice`/`Animation`, `getFile`, streaming download with size guard (`20 MB`). Empty strings in `public_data`/`chat_data`/`data` are preserved natively via JSON.
   - `poller.rs`: Safe `Poller` with persistent `offset` file, 2000-entry seen-id dedupe, watchdog `Notify` kick cancellation, conflict & flood backoff.
   - `watchdog.rs`: Linux `NOTIFY_SOCKET` `sd_notify` (`READY=1`, `WATCHDOG=1`, `STATUS=...`, `STOPPING=1`) + watchdog task probing `getMe`, rotating proxy/client on soft stall, controlled exit (`75`) on hard stall only when no active agent jobs are running, writing `health.json` every 10s.

4. **`agy-widgets` (`crates/agy-widgets`)**
   - `spec.rs`: `WidgetSpec`, `encode_widget_data`, `count_widget_size` (`zlib` level 9 via pure-Rust `flate2`), `minify_widget_html`, `lint_widget_profile` (Bot API 10.4 Profile-1 CSS/JS/HTML validator).
   - `parser.rs`: `<tg-widget ...>` extractor (ignoring fenced/inline code), `.widget.html` parser (`<!-- widget: {...} -->`), `.widget.json` parser (`send`, `send_shared`, `edit_message_data`, `edit_shared_data`, `builtin`).
   - `store.rs`: `WidgetStore` preserving `widgets.json` schema + `purge_legacy_widgets()` (`status`, `poll`, `control`, `wallet`) + shared rate-limit tracking.
   - `builtins.rs`: Exact 4 Apple-HIG built-in HTML/JS widgets (`skills`, `mcp`, `models`, `memory`), each Profile-1 clean and `<= 4096 B` zlib-9.
   - `webapp.rs`: `verify_webapp_init_data` (HMAC-SHA256 `WebAppData` + duplicate param check + expiry + `allowed_uids`), `render_in_bubble_widget` (`premium_active` + plain fallback + `<= 64 B` callbacks), `Axum` WebApp & API router (`/healthz`, `/w/{wid}`, `/api/w/{wid}/{init,query,action,state}`) + WebApp shell HTML (`CSP`, `nosniff`, `16 KB` action cap).

5. **`agy-ext` (`crates/agy-ext`)**
   - `mcp_client.rs`: Async Tokio stdio JSON-RPC 2.0 MCP client (process-group cleanup, timeout, secret redaction in errors/logs, large payload line buffering).
   - `skills.rs`: Installed skills YAML frontmatter CRUD + path traversal guard, local `SkillPort` (namespaces + atomic install), community `skills-catalog` (`catalog.json` mtime-cached + search + stdio fetch).
   - `mcp_config.rs`: `mcp_config.json` CRUD (`list`, `get`, `toggle`, `update`, `replace_json`, `remove`) preserving secrets against `MASKED_SECRET = "••••••••"`, sensitive key detection, atomic `0600` writes.
   - `memory.rs`: Async `ai-memory` overview/search/add/remove over stdio MCP.
   - `engines.rs`: Extensible `EngineRunner` trait + `AgyEngine` (`agy --output-format stream-json`, NDJSON streaming parser, tool trace, `SIGINT -> SIGTERM -> SIGKILL` process-group termination, timeouts) + `CustomCliEngine` pluggable runner (`AGY_ENGINE`).

6. **`agy-bot` (`crates/agy-bot`)**
   - `cron.rs`: Persistent Cron & Sync scheduler (`cron_jobs.json`, 5/6-field cron expressions): automated `models` refresh, MCP config sync, stale inbox cleanup, disk/health telemetry without running ad-hoc LLM prompts.
   - `updater.rs`: Safe binary updater & pre-flight `--check` / `--health` CLI modes, artifact verification, atomic swap with rollback backup retention.
   - `auth.rs`: Silent AuthMiddleware parity (drop non-private/unapproved, trigger `on_unapproved_start` only on private `/start` with cooldown).
   - `jobs.rs`, `handlers_system.rs`, `handlers_users.rs`, `handlers_mcp.rs`, `handlers_skills.rs`, `handlers_widgets.rs`, `webapp_bridge.rs`, `webhook.rs`, `main.rs`: Complete Telegram update router (Long-Polling + Webhook + Auto fallback), all commands (`/start`, `/menu`, `/users`, `/skills`, `/mcp`, `/widget`, `/model`, `/settings`, `/effort`, `/mode`, `/resume`, `/cwd`, `/agent`, `/trace`, `/changelog`, `/net`, `/status`, `/cron`, `/help`, `/cancel`, `/new`, `/stop`), media download (`20 MB`) & upload (`50 MB`), outbox auto-delivery, `notice_once.html` + `widget_once.json` consumption, graceful shutdown.

## Global Constraints & Review Focus
- **Zero `.unwrap()`/`.expect()`/`panic!()`** in runtime production code; all fallible paths return typed `BridgeError` / `Result`.
- **Zero secret leaks** in logs, responses, WebApp init/action payloads, MCP diffs, or backup archives (`MASKED_SECRET = "••••••••"`).
- **Review Focus (5 adversarial failure classes pinned by tests):**
  1. Unapproved / blocked user sending `/start`, text, callback, widget query, or forging `X-Telegram-Bot-Api-Secret-Token` / `initData` (must fail closed + silent).
  2. Secret preservation when editing or replacing `mcp_config.json` with `••••••••` or invalid JSON/command/URL.
  3. Empty-string (`""`) clear semantics on `editMessageWidgetData` / `editSharedWidgetData` / `answerWidgetQuery`.
  4. Premium custom emoji / message effect rejection gracefully falling back to plain Rich -> balanced HTML -> plain text without breaking HTML tags or exceeding UTF-16 limits.
  5. Process-group cancellation on `/stop` or timeout, proxy failover when primary proxy/endpoint fails, and health-checked cutover rollback.
