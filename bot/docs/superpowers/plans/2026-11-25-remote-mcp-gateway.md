# AGY Remote MCP Gateway (`agy-mcp-gateway`) — Architecture Spec & Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a production-grade, standards-compliant, modular Remote MCP Gateway embedded in `agy-telegram` (`ch-base` Rust workspace) so any MCP-capable client (VS Code, Claude.ai/Desktop/Code, Gemini CLI/Antigravity, xAI Grok API/CLI, ChatGPT Connectors, Cursor, Windsurf) can securely access all bot capabilities section-by-section with progressive tool discovery, model switching, session continuity, token optimization, anti-DDoS/anti-ban protection, and full Owner management inside Telegram (`/mcpgw`).

**Architecture:** Add a dedicated crate `crates/agy-mcp-gateway` inside `/root/agy-stack/src/ch-base/` served on an isolated loopback Axum listener (`127.0.0.1:8788`, separate from `:8787` WebApp/Webhook) behind Caddy TLS on dual domains: `mcp.example.com` (CDN OFF — direct low-latency/long-running Streamable HTTP) and `gateway.example.com` (CDN ON — Cloudflare DDoS/WAF edge + OAuth UI + heartbeat-protected fallback). The gateway implements Streamable HTTP (both 2025 stateful & 2026 stateless specs) + legacy SSE fallback, dual auth (OAuth 2.1 with PKCE S256 + RFC 9728/8414/7591/8707 + Telegram 2FA consent, AND SHA-256 scoped Bearer API keys), 9 modular section endpoints + a progressive-discovery Smart Hub (`/mcp`), OWASP MCP Top 10 defenses (SHA-256 manifest pinning against rug-pulls, indirect prompt-injection sanitization, secret redaction, HITL Telegram approval gates), upstream account anti-ban protection (`AccountStore` 1% weekly reserve + sticky proxies + MCP concurrency cap + loop circuit breaker), and an Owner-only `/mcpgw` Telegram panel.

**Tech Stack:** Rust 2021 (`axum 0.8`, `tokio 1.44`, `tower-http 0.6`, `dashmap 6.1`, `sha2`, `hmac`, `subtle`, `serde_json`, `regex`, `uuid`, `chrono`), Caddy 2 (auto Let's Encrypt TLS + Cloudflare real-IP trust + zero-buffer streaming), existing `agy-core` / `agy-ext` / `agy-bot` runtime primitives.

**Research Grounding (2026-11-25):**
- **SkillHub consultations (8 docs):** `anthropic-skills:skills/mcp-builder/SKILL.md`, `anthropic-skills:skills/mcp-builder/reference/mcp_best_practices.md`, `ecc:skills/mcp-server-patterns/SKILL.md`, `ecc:docs/token-optimization.md`, `ecc:skills/strategic-compact/SKILL.md`, `ecc:skills/prompt-optimizer/SKILL.md`, `ecc:skills/security-review/SKILL.md`, `ecc:the-security-guide.md`, `wshobson-agents:plugins/developer-essentials/skills/auth-implementation-patterns/SKILL.md`.
- **Global Specs & Community Research:** MCP Streamable HTTP (`2025-03-26`, `2025-06-18`, `2025-11-25` stateful `Mcp-Session-Id`/`Last-Event-ID` + `2026-07-28` stateless `MCP-Protocol-Version`/`Mcp-Method`/`Mcp-Name`), OAuth 2.1 + PKCE `S256` + RFC 9728 + RFC 8414 + RFC 7591 DCR + RFC 8707 audience binding, xAI Grok Remote MCP (`type: "mcp"`, `server_url`, `authorization`), Claude.ai Custom Connector CORS & Content-Type pitfalls, Cloudflare 100s timeout (Error 524) & WAF JSON-RPC false-positive mitigations, OWASP MCP Top 10 (tool poisoning, rug pulls, confused deputy, multi-tenant isolation), Reddit/GitHub MCP Gateway progressive disclosure consensus.

---

## Global Constraints

1. **Workspace Policy:** All Rust code compiles with zero warnings under `#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used, clippy::panic))]`.
2. **Network Isolation:** Gateway MUST bind strictly to `127.0.0.1:8788` (configurable via `MCP_GW_PORT`, default `8788`), NEVER `0.0.0.0`. Existing `:8787` (`example-gateway.sslip.io`) WebApp/Webhook router MUST remain unaffected.
3. **Secret Hygiene & Hard Deny List:**
   - NEVER read, expose, or modify `/var/lib/agy-telegram/accounts/`, `antigravity-oauth-token`, `bot.env`, `grok_oauth.json`, `grok_bot_oauth.json`, raw `mcp_config.json` secrets, `~/.ssh`, or `/etc/shadow` via any MCP tool.
   - All API keys and OAuth tokens are stored on disk as salted SHA-256 hashes only (`0600` atomic writes via `agy_core::atomic::atomic_write_json`); raw secrets are returned ONCE at creation.
   - Every outgoing MCP tool result MUST pass through `agy_ext::mcp_client::redact_secrets_in_text()`.
4. **Dual-Domain TLS & Real-IP Safety:**
   - `mcp.example.com` (CDN OFF -> `203.0.113.10`): Caddy automatic Let's Encrypt TLS; origin trusts `X-Real-IP` only from loopback peer; `flush_interval -1` for zero-buffering streaming.
   - `gateway.example.com` (CDN ON -> Cloudflare proxy): Caddy trusts `CF-Connecting-IP` ONLY when peer matches official Cloudflare CIDR ranges; SSE heartbeats `: ping\n\n` every 15s; `Cache-Control: no-store` on all `/mcp*` and `/oauth/*` routes.
5. **Account Anti-Ban Invariants:**
   - External MCP AI calls MUST go through `AccountStore` (respecting 5h/7d ledger, 1% weekly reserve, sticky proxy 1:1 binding, cooldowns, and `AccountPolicy`) and `JobManager` global slot semaphore.
   - Dedicated MCP AI concurrency cap (`max_mcp_ai_concurrency`, default `2`, configurable `0..=8`) ensures external clients can never starve Telegram or trigger multi-burst upstream bans.
   - Never expose raw account emails or OAuth tokens in any MCP tool/resource (use opaque slot IDs like `acc-1`, health state, and percentage remaining).
6. **Backward Compatibility:** Existing `--mcp-openhands`, `--mcp-skillhub`, and `--mcp-uncensored` stdio modes remain 100% functional.
7. **Owner-Only Control:** All `/mcpgw` Telegram panel actions and OAuth consent approvals are strictly restricted to `ctx.is_owner(uid)`.

---

## Complete System & Tool Mapping (9 Modular Sections + Smart Hub)

| # | Route | Section Scope | Underlying Runtime / MCPs | Tool Count & Key Capabilities |
|---|-------|---------------|---------------------------|-------------------------------|
| **0** | `/mcp` (Smart Hub) | `mcp:hub` (default) | All allowed sections via Progressive Discovery | **~12 core tools (~2.5k tok)**: `hub_status`, `hub_list_sections`, `hub_discover_tools` (BM25F + intent ranking across 120+ tools), `hub_tool_schema`, `hub_call_tool` (RBAC-checked universal dispatcher), `hub_task_status` / `hub_task_cancel` (async handles for >60s Cloudflare-safe ops), plus pinned essentials (`model_status`, `model_switch`, `session_list`, `optimize_prompt`, `token_budget`) |
| **1** | `/mcp/s/openhands` | `mcp:openhands:read`, `mcp:openhands:write`, `mcp:openhands:exec` | In-process `openhands_mcp` + `agent_runtime` + `pty_manager` | **19 tools**: `oh_file_editor`, `oh_patch_file`, `oh_batch_read`, `oh_multi_edit`, `oh_glob_files`, `oh_find_symbols`, `oh_grep_files`, `oh_git_ops`, `oh_execute_code` (Python RPC), `oh_pty_start`, `oh_process_manage`, `oh_task_tracker`, `oh_pack_md`, `oh_apply_md`, `oh_verify`, `oh_inspect_image`, `oh_microagents`, `oh_delegate_agent`, `oh_dev_loop` (subject to workspace jail + `command_guard` + optional HITL!) |
| **2** | `/mcp/s/search` | `mcp:search` | Pooled `search-v3` MCP (`McpClientPool`) | **8 tools**: `search_web_v3`, `search_all_engines`, `batch_search`, `fetch_url`, `parse_dork_ast`, `crawl_urls`, `search_status`, `export_links_txt` (with indirect prompt-injection sanitization & size compaction) |
| **3** | `/mcp/s/skillhub` | `mcp:skillhub` | In-process Rust `skill_hub` index + pooled `skillport` & `skills-catalog` | **13 tools**: `skillhub_catalog`, `skillhub_search`, `skillhub_get`, `skillhub_sources`, `skillhub_stats`, `skillport_search`, `skillport_load`, `catalog_search`, `catalog_get`, `catalog_domains`, `catalog_recommend`, `catalog_stats` (admin `sync`/`install` locked to owner scope only!) |
| **4** | `/mcp/s/memory` | `mcp:memory` | Pooled `ai-memory` (PostgreSQL 16 + pgvector) | **17 tools**: `memory_store`, `memory_search`, `memory_list`, `memory_update`, `memory_delete`, `memory_batch`, `memory_graph_search`, `memory_consolidate`, `memory_stats`, `memory_relate`, `memory_unrelate`, `memory_get_relations`, `memory_traverse`, `memory_decay_status`, `memory_preserve`, `memory_graph_analysis` (namespace-tagged per key/tenant to prevent memory poisoning!) |
| **5** | `/mcp/s/codeintel` | `mcp:codeintel` | Pooled `gortex` + `graphify` + `context7` | **31 tools**: Gortex (`search`, `relations`, `change`, `trace`, `analyze`, `explore`, `read`, `review`, `refactor`, etc.), Graphify (`query_graph`, `get_node`, `get_neighbors`, `god_nodes`, `shortest_path`, `graph_stats`, etc.), Context7 (`resolve-library-id`, `query-docs`) |
| **6** | `/mcp/s/models` | `mcp:models:read`, `mcp:models:switch`, `mcp:models:run` | `models_pool`, `AccountStore`, `AgyEngine`, `grok_oauth`/`grok_bot`, `uncensored` (Venice v5 3-Stage + `<agy_slot>`) | **9 tools**: `models_list` (all engines: Antigravity/Gemini/Claude, Grok, Venice Uncensored), `models_switch` (switch active engine/model/effort/3-stage per MCP session or linked user state), `models_current`, `models_run` (execute a prompt on chosen engine/model with quota guard & async task option), `models_compare` (cross-model second opinion), `uncensored_chat`, `uncensored_agent`, `grok_chat`, `models_pool_health` (sanitized health/remaining % — zero credentials!) |
| **7** | `/mcp/s/sessions` | `mcp:sessions` | `StateStore`, transcripts, `.handoff/`, outbox, `AgentSessions` | **9 tools**: `session_list`, `session_get`, `session_create`, `session_resume`, `session_switch`, `session_search_transcript`, `session_handoff_read`, `session_handoff_write`, `session_export_summary` |
| **8** | `/mcp/s/optimizer` | `mcp:optimizer` | `turn_profile`, `local_fast`, `agent_runtime` compaction + `<agy_slot>`, `McpClientPool` RO cache, ECC `prompt-optimizer` & `strategic-compact` heuristics | **8 tools (0 AI tokens!)**: `opt_classify_turn` (`lite`/`standard`/`full` + effort advice), `opt_local_eval` (zero-token fast path for status/math/time), `opt_compact_text` (head+tail / code-preserving UTF-8 compaction with configurable token budget), `opt_strategic_compact_check` (context window & tool-call pressure advisor), `opt_prompt_analyze` (intent/scope/missing-context & SkillHub skill matcher), `opt_token_estimate` (fast BPE-approx token counter & cost/quota estimator), `opt_cache_stats` (`McpClientPool` RO cache hits/misses & TTL), `opt_slot_assemble` (deterministic `<agy_slot>` chunked file assembly + syntax check) |
| **9** | `/mcp/s/federation` | `mcp:federation` | Dynamic `mcp_config.json` + `McpClientPool` + `ManifestPinStore` | **4 tools**: `fed_list_servers`, `fed_list_tools`, `fed_call_tool` (auto-routes any newly added enabled MCP server with SHA-256 manifest pin verification!), `fed_manifest_status` |
| **★** | `/mcp/all` | Explicit per-key allowed sections | Union of allowed sections (capped cleanly per client) | Direct expanded tool list for power-users/clients wanting zero-hop direct tool visibility on a small selected subset of sections |

**MCP Resources (`resources/list`, `resources/read`):**
- `agy://gateway/status` — live health, enabled sections, protocol versions, rate-limit budget
- `agy://models/catalog` — available Antigravity, Grok, and Venice Uncensored models + active selection
- `agy://sessions/recent` — recent sessions & active conversation ID
- `agy://sessions/handoff` — current `.handoff` continuity summary
- `agy://skillhub/roster` — Superpowers + Anthropic Official Skills + Source×Kind matrix
- `agy://optimizer/telemetry` — RO cache hit ratio, active concurrency, remaining quota %

**MCP Prompts (`prompts/list`, `prompts/get`):**
- `skillhub_workflow` — injects curated workflow from SkillHub by topic/name
- `strategic_compact_handoff` — builds a lossless phase-transition compaction brief
- `optimize_prompt` — runs the 6-phase prompt optimization framework
- `three_stage_codegen` — structures complex multi-file tasks with `<agy_slot>` verification

---

## Security, Anti-DDoS & Anti-Ban Architecture Matrix

| Threat / Requirement | Defense Mechanism | Enforcement Point |
|---------------------|-------------------|-------------------|
| **L3/L4/L7 Volumetric DDoS** | Cloudflare Proxy on `gateway.example.com` + Caddy header/body/idle limits + Rust `McpGuard` bounded concurrency semaphore + per-IP & per-key `KeyedTokenBucket` + automatic temporary IP ban after N consecutive 401/403/429s | Edge (CF) + Caddy + `agy-mcp-gateway/src/guard.rs` |
| **Cloudflare 100s Timeout (Error 524)** | Primary direct domain `mcp.example.com` (no CF timeout); on `gateway.example.com`, SSE streams emit `: ping\n\n` every 15s + long tools (`>45s`) support `async: true` returning `task_id` polled via `hub_task_status` | `transport.rs` + `Caddyfile` (`flush_interval -1`) |
| **Cloudflare WAF JSON-RPC False Positives** | Documented Cloudflare Custom WAF Rule to skip OWASP body inspection ONLY on authenticated `gateway.example.com/mcp*` while keeping DDoS/Rate-Limit rules active; direct `mcp.example.com` unaffected | Cloudflare Dashboard + Docs |
| **OAuth 2.1 / Claude.ai Compatibility** | Full RFC 9728 (`/.well-known/oauth-protected-resource`), RFC 8414 (`/.well-known/oauth-authorization-server`), RFC 7591 DCR (`/oauth/register`), PKCE `S256`, RFC 8707 `resource`/`aud` binding, defensive JSON + form-urlencoded parsers, strict CORS on `.well-known/*` & `/oauth/*`, Telegram Owner 2FA approval | `oauth.rs` |
| **DNS Rebinding / CSRF** | Validate `Host` against allowlisted domains (`mcp.example.com`, `gateway.example.com`, `127.0.0.1`), validate `Origin` on browser requests, reject cross-origin POST without valid OAuth/Bearer token | `guard.rs` |
| **Account Ban & Quota Exhaustion** | Shared `AccountStore` (5h/7d ledger + 1% weekly reserve + 1:1 sticky proxy per account) + dedicated `max_mcp_ai_concurrency` cap + per-key hourly/daily AI call limits + runaway loop circuit breaker (identical tool+args > 6x in 30s -> circuit open) + process-group `SIGKILL` kill switch | `policy.rs` + `sections/models.rs` + `JobManager` |
| **Tool Poisoning & Rug Pulls (OWASP MCP)** | SHA-256 hash pinning of every upstream MCP's `tools/list` schema in `mcp_manifest_lock.json`; any silent schema/description mutation quarantines that tool and notifies Owner in Telegram for explicit re-approval | `manifest_pin.rs` |
| **Indirect Prompt Injection** | Unicode bidi/zero-width stripping (`\u{200B}..\u{202E}`), provenance fencing (`[untrusted external output]`), early head+tail compaction (`AGENT_TOOL_OUTPUT_MAX_BYTES`) on web/search/external tool outputs | `sanitize.rs` |
| **Secret Leakage / Path Traversal** | Hard deny-list on credential paths (`accounts/`, `bot.env`, `*.oauth*`, `.ssh`), `resolve_safe_cwd` workspace jail, `command_guard`, mandatory `redact_secrets_in_text()` on every tool output & audit log entry | `policy.rs` + `sanitize.rs` |
| **High-Risk Tool Abuse** | Per-key/per-tool policy (`allow` / `ask_telegram` / `deny`); `ask_telegram` sends inline `[✅ Once] [✅ Session] [❌ Deny]` buttons to Owner in Telegram while holding the request open with SSE heartbeats | `hitl.rs` + `handlers_mcpgw.rs` |

---

## Review Focus (Top 5 Failure Modes to Pin with Tests)

1. **Claude.ai / OAuth 2.1 pre-auth silent failure:** Unauthenticated `POST /mcp` MUST return HTTP `401` with exact `WWW-Authenticate: Bearer resource_metadata="https://<host>/.well-known/oauth-protected-resource"`, CORS headers on `.well-known/*`, and `/oauth/token` + `/oauth/register` MUST accept both `application/json` and `application/x-www-form-urlencoded` (including missing `Content-Type`).
2. **Header spoofing on `CF-Connecting-IP` / `X-Forwarded-For`:** Direct attackers sending spoofed `CF-Connecting-IP` to `mcp.example.com` (or bypassing Caddy) MUST NOT evade IP rate limits or IP allowlists; only loopback Caddy peer + verified Cloudflare CIDR source may supply `CF-Connecting-IP`.
3. **Runaway external agent loop burning upstream quotas:** An external client calling `models_run` or `oh_execute_code` in a tight loop MUST trip the per-key loop circuit breaker and `max_mcp_ai_concurrency` semaphore BEFORE touching `AccountStore`'s weekly reserve or starving Telegram.
4. **Silent upstream MCP rug-pull / schema drift:** If a downstream stdio MCP alters a tool description or inputSchema after pinning, `manifest_pin.rs` MUST quarantine that tool (returning structured JSON-RPC error + Owner Telegram alert) instead of executing or forwarding poisoned metadata.
5. **Credential exfiltration through OpenHands / Federation tools:** Attempting to read `/var/lib/agy-telegram/accounts/*`, `/etc/agy-telegram/bot.env`, or echoing a secret pattern (`sk-...`, `Bearer ...`, bot token) MUST be blocked on input AND redacted on output even for `Developer` or `Owner` remote keys.

---

## File Structure & Crate Decomposition

```text
/root/agy-stack/src/ch-base/
├── Cargo.toml                                    # Add "crates/agy-mcp-gateway" to workspace members
├── crates/agy-mcp-gateway/
│   ├── Cargo.toml                                # Deps: agy-core, agy-ext, axum, tokio, dashmap, sha2, hmac, subtle, regex, uuid, chrono
│   └── src/
│       ├── lib.rs                                # Public GatewayState, build_gateway_router, spawn_gateway_server
│       ├── config.rs                             # GatewayConfig persisted at $STATE_DIR/mcp_gateway.json (0600 atomic)
│       ├── auth.rs                               # Scoped API Keys (SHA-256 salted), KeyStore, presets (ReadOnly/Research/Dev/Owner), client config snippet generator
│       ├── oauth.rs                              # OAuth 2.1 AS + PKCE S256 + RFC 9728/8414/7591/8707 + Telegram 2FA consent bridge
│       ├── guard.rs                              # McpGuard middleware: per-IP/per-key token buckets, concurrency sem, Host/Origin validation, auto-ban, CF-IP verification, body cap
│       ├── protocol.rs                           # JSON-RPC 2.0 + MCP 2025 stateful & 2026 stateless Streamable HTTP + legacy SSE (/sse + /messages) + heartbeat frames
│       ├── registry.rs                           # Section enum (9 sections + hub + all), tool catalog, BM25F progressive discovery index (hub_discover_tools)
│       ├── policy.rs                             # Scope enforcement, hard secret path deny-list, loop circuit breaker, MCP AI concurrency & daily quota guard
│       ├── manifest_pin.rs                       # SHA-256 manifest lockfile ($STATE_DIR/mcp_manifest_lock.json) + rug-pull quarantine
│       ├── sanitize.rs                           # Secret redaction, bidi/zero-width stripping, provenance fencing, head+tail output compaction
│       ├── hitl.rs                               # Telegram Owner inline approval broker (Once / Session / Deny) with timeout & cleanup
│       ├── audit.rs                              # Bounded async JSONL audit writer ($STATE_DIR/mcp_gateway_audit.jsonl) + ring buffer for /mcpgw live view
│       ├── tasks.rs                              # Async task handle manager (task_id, progress, cancel via pgid) for long-running ops behind Cloudflare
│       └── sections/
│           ├── mod.rs                            # Unified SectionDispatcher trait + routing
│           ├── hub.rs                            # Smart Hub progressive discovery + meta-tools
│           ├── openhands.rs                      # Bridge to agy-ext openhands_mcp (19 tools) with jail/guard/HITL
│           ├── search.rs                         # Bridge to pooled search-v3 MCP (8 tools) + sanitization
│           ├── skillhub.rs                       # In-process SkillHub + pooled SkillPort/Catalog (13 tools)
│           ├── memory.rs                         # Pooled ai-memory with tenant tag isolation (17 tools)
│           ├── codeintel.rs                      # Pooled gortex + graphify + context7 (31 tools)
│           ├── models.rs                         # Multi-engine model catalog, switching, guarded run (Antigravity/Grok/Venice v5)
│           ├── sessions.rs                       # StateStore sessions, transcripts, .handoff continuity
│           ├── optimizer.rs                      # Zero-token turn_profile, local_fast, compaction, prompt analyzer, token estimator, RO cache stats, <agy_slot>
│           └── federation.rs                     # Dynamic mcp_config.json proxy with manifest pinning
├── crates/agy-bot/src/
│   ├── main.rs                                   # Wire GatewayServer on 127.0.0.1:8788 + graceful shutdown + /mcpgw command dispatch
│   ├── ctx.rs                                    # Hold Arc<McpGatewayHandle> in BotCtx
│   ├── handlers_mcp.rs                           # Add "🌐 MCP Gateway" entry button in /mcp
│   └── handlers_mcpgw.rs                         # Full Owner-only /mcpgw Telegram management panel (Dashboard, Kill Switch, Keys, Config Snippets, Sections, Limits, HITL, Audit)
└── /etc/caddy/Caddyfile                          # Add mcp.example.com (direct) & gateway.example.com (Cloudflare) blocks
```

---

## Phased Implementation Tasks (TDD-First, Independently Verifiable)

### Phase 1 — Core Crate, Config, Auth, Guard & Protocol Layer

#### Task 1: Scaffold `agy-mcp-gateway` crate & Persistent Config Store
**Files:**
- Modify: `/root/agy-stack/src/ch-base/Cargo.toml`
- Create: `crates/agy-mcp-gateway/Cargo.toml`, `crates/agy-mcp-gateway/src/lib.rs`, `crates/agy-mcp-gateway/src/config.rs`
**Interfaces:**
- Produces: `GatewayConfig`, `GatewayMode` (`Active | ReadOnly | Disabled`), `SectionConfig`, `RateLimitConfig`, `GatewayConfigStore::open(path) -> Result<Self>`
- [ ] **Step 1:** Write unit tests in `config.rs` verifying default safe bounds (`bind_port = 8788`, `max_mcp_ai_concurrency = 2`, `default_ip_rpm = 120`, `auto_ban_401_threshold = 10`, atomic `0600` save/reload).
- [ ] **Step 2:** Run `cargo test -p agy-mcp-gateway` (verify compile/fail before impl).
- [ ] **Step 3:** Implement `GatewayConfig` & `GatewayConfigStore` using `agy_core::atomic::atomic_write_json`.
- [ ] **Step 4:** Verify `cargo test -p agy-mcp-gateway` passes.

#### Task 2: Scoped API Key Store & Client Config Generator
**Files:**
- Create: `crates/agy-mcp-gateway/src/auth.rs`
**Interfaces:**
- Produces: `KeyRecord`, `KeyPreset` (`ReadOnly | Research | Developer | Owner`), `KeyScope`, `KeyStore::create_key(...) -> Result<(KeyRecord, String)>`, `KeyStore::verify_bearer(raw: &str) -> Option<AuthenticatedPrincipal>`, `render_client_configs(host, section, raw_key) -> ClientSnippets` (VS Code `mcp.json`, Claude Desktop/Code, Gemini CLI, Grok API/CLI, Cursor).
- [ ] **Step 1:** Write unit tests covering key creation (prefix `agymcp_`), constant-time SHA-256 verification (`subtle::ConstantTimeEq`), revocation, expiry, scope enforcement, and ensuring plaintext keys never appear in serialized JSON or `Debug` output.
- [ ] **Step 2:** Implement `auth.rs` + multi-client snippet generator.
- [ ] **Step 3:** Verify `cargo test -p agy-mcp-gateway auth::` passes.

#### Task 3: Anti-DDoS `McpGuard` Middleware (Dual-Domain Real-IP, Auto-Ban, Host/Origin)
**Files:**
- Create: `crates/agy-mcp-gateway/src/guard.rs`
**Interfaces:**
- Produces: `McpGuardLayer`, `extract_verified_client_ip(peer, headers, trust_cf_cidrs) -> (String, IpSource)`, `AutoBanTable`.
- [ ] **Step 1:** Write tests pinning Review Focus #2: spoofed `CF-Connecting-IP` from non-CF/non-loopback rejected; per-IP 429; 10 consecutive 401s trigger temporary IP ban (`403`); disallowed `Host`/`Origin` rejected (`403`); body > limit returns `413`.
- [ ] **Step 2:** Implement `guard.rs` reusing `agy_core::security::KeyedTokenBucket`.
- [ ] **Step 3:** Verify `cargo test -p agy-mcp-gateway guard::` passes.

#### Task 4: Universal MCP Transport (`protocol.rs` — Streamable HTTP 2025 + 2026 + Legacy SSE)
**Files:**
- Create: `crates/agy-mcp-gateway/src/protocol.rs`
**Interfaces:**
- Produces: Axum handlers for `POST /mcp`, `GET /mcp`, `DELETE /mcp`, `POST /mcp/all`, `POST /mcp/s/{section}`, `GET /mcp/s/{section}`, `GET /sse`, `POST /messages`; protocol version negotiation (`2025-03-26`, `2025-06-18`, `2025-11-25`, `2026-07-28`); `Mcp-Session-Id` & `Mcp-Method`/`Mcp-Name` support; 15s SSE keep-alive `: ping\n\n`; `tools/list`, `tools/call`, `resources/list`, `resources/read`, `prompts/list`, `prompts/get`, `ping`.
- [ ] **Step 1:** Write integration tests (via `tower::ServiceExt::oneshot`) verifying:
  - 2025 stateful handshake (`initialize` -> `Mcp-Session-Id` -> `tools/list` -> `DELETE /mcp`)
  - 2026 stateless `POST /mcp` with `MCP-Protocol-Version: 2026-07-28` without prior `initialize`
  - Unauthenticated `POST /mcp` returns `401` + RFC 9728 `WWW-Authenticate` header (Review Focus #1)
  - Legacy `GET /sse` emits endpoint event and accepts `POST /messages`
- [ ] **Step 2:** Implement `protocol.rs`.
- [ ] **Step 3:** Verify `cargo test -p agy-mcp-gateway protocol::` passes.

---

### Phase 2 — OAuth 2.1 Server (Claude.ai / ChatGPT / VS Code / Gemini Universal Auth)

#### Task 5: OAuth 2.1 + PKCE `S256` + RFC 9728/8414/7591/8707 + Telegram 2FA Consent
**Files:**
- Create: `crates/agy-mcp-gateway/src/oauth.rs`
**Interfaces:**
- Produces: Routes:
  - `GET /.well-known/oauth-protected-resource` (and `/.well-known/oauth-protected-resource/mcp*`)
  - `GET /.well-known/oauth-authorization-server`
  - `POST /oauth/register` (RFC 7591 DCR with rate-limit & client cap)
  - `GET /oauth/authorize` + `POST /oauth/authorize` (PKCE `S256` mandatory, RFC 8707 `resource` binding, triggers Telegram Owner inline approval or one-time code!)
  - `POST /oauth/token` (accepts BOTH `application/x-www-form-urlencoded` and `application/json`, authorization_code + refresh_token rotation, short-lived access tokens 30m)
  - `POST /oauth/revoke`
- [ ] **Step 1:** Write tests pinning Review Focus #1: metadata JSON fields, CORS `OPTIONS` preflight, DCR registration, PKCE `S256` challenge verification (rejecting `plain` or mismatched verifier), RFC 8707 `resource`/`aud` mismatch rejection, dual Content-Type parsing on `/oauth/token`.
- [ ] **Step 2:** Implement `oauth.rs` with clean minimal HTML consent page + Telegram approval channel.
- [ ] **Step 3:** Verify `cargo test -p agy-mcp-gateway oauth::` passes.

---

### Phase 3 — Security Engine (Policy, Manifest Pinning, Sanitization, HITL, Audit, Async Tasks)

#### Task 6: Policy Engine, Anti-Ban Quota Guard, Loop Circuit Breaker & Hard Secret Path Deny-List
**Files:**
- Create: `crates/agy-mcp-gateway/src/policy.rs`, `crates/agy-mcp-gateway/src/sanitize.rs`
**Interfaces:**
- Produces: `PolicyEngine::check_call(principal, section, tool, args) -> PolicyDecision` (`Allow | RequireHitl | Deny(reason)`), `LoopCircuitBreaker`, `sanitize_untrusted_output(text, max_bytes) -> String`, `is_forbidden_path(path) -> bool`.
- [ ] **Step 1:** Write tests pinning Review Focus #3 & #5: forbidden paths (`/var/lib/agy-telegram/accounts/acc1/...`, `/etc/agy-telegram/bot.env`, `~/.ssh/id_rsa`, `../` traversal) denied; secret patterns redacted from output; invisible Unicode `\u{202E}`/`\u{200B}` stripped from untrusted output; 7 identical calls in 30s trip circuit breaker; `max_mcp_ai_concurrency` blocks excess concurrent AI runs.
- [ ] **Step 2:** Implement `policy.rs` and `sanitize.rs`.
- [ ] **Step 3:** Verify `cargo test -p agy-mcp-gateway policy:: sanitize::` passes.

#### Task 7: Manifest Pinning (Anti-Rug-Pull), HITL Telegram Broker, Audit Log & Async Task Handles
**Files:**
- Create: `crates/agy-mcp-gateway/src/manifest_pin.rs`, `crates/agy-mcp-gateway/src/hitl.rs`, `crates/agy-mcp-gateway/src/audit.rs`, `crates/agy-mcp-gateway/src/tasks.rs`
**Interfaces:**
- Produces: `ManifestPinStore::verify_or_pin(server, tools) -> PinVerdict`, `HitlBroker::request_approval(...) -> HitlOutcome`, `AuditLogger::record(...)`, `TaskManager::spawn_tracked(...)`.
- [ ] **Step 1:** Write tests pinning Review Focus #4: first pin succeeds; identical schema passes; mutated description triggers `PinVerdict::Drifted` quarantine; HITL approval resolves on owner decision or times out cleanly; `TaskManager` cancels via cancellation watch channel.
- [ ] **Step 2:** Implement all 4 modules.
- [ ] **Step 3:** Verify `cargo test -p agy-mcp-gateway` passes.

---

### Phase 4 — All 9 Modular Tool Sections + Progressive Discovery Smart Hub + Resources & Prompts

#### Task 8: Smart Hub Progressive Discovery (`registry.rs` + `sections/hub.rs`)
**Files:**
- Create: `crates/agy-mcp-gateway/src/registry.rs`, `crates/agy-mcp-gateway/src/sections/mod.rs`, `crates/agy-mcp-gateway/src/sections/hub.rs`
- [ ] **Step 1:** Implement BM25-weighted tool discovery index over all 9 sections (respecting caller's scopes — **Discovery != Authorization**: unauthorized tools are hidden OR marked locked, never executable).
- [ ] **Step 2:** Write unit tests proving `/mcp` returns <= 15 compact tools (<3,000 tokens), `hub_discover_tools("find python symbols")` ranks `oh_find_symbols` / `gortex_search` top-3, and `hub_call_tool` enforces full RBAC + policy.

#### Task 9: Sections 1–5 (OpenHands, Search-v3, SkillHub/SkillPort/Catalog, AI-Memory, CodeIntel)
**Files:**
- Create: `crates/agy-mcp-gateway/src/sections/{openhands,search,skillhub,memory,codeintel}.rs`
- [ ] **Step 1:** Wire OpenHands directly to `agy_ext::openhands_mcp` / `agent_runtime` with per-key workspace jail + `command_guard` + HITL for `exec`/`write`.
- [ ] **Step 2:** Wire Search-v3, SkillPort, Skills-Catalog, AI-Memory, Gortex, Graphify, Context7 through `agy_ext::mcp_client::global_mcp_pool()` (inheriting 45s RO cache + write invalidation + secret redaction) and SkillHub directly in-process (`agy_ext::skill_hub` sub-ms Rust index).
- [ ] **Step 3:** Enforce tenant tag prefix (`mcp-key:<id>`) on `memory_store` writes for non-owner keys to prevent cross-tenant memory poisoning.
- [ ] **Step 4:** Write mock/unit tests for each section dispatcher + output sanitization.

#### Task 10: Sections 6–9 (Multi-Model & Switching, Sessions & Handoff, Token Optimizers, Dynamic Federation) + Resources & Prompts
**Files:**
- Create: `crates/agy-mcp-gateway/src/sections/{models,sessions,optimizer,federation}.rs`
- [ ] **Step 1:** Implement `models.rs` exposing Antigravity (`models_pool` + `AccountStore` guarded), Grok (`grok_oauth`/`grok_bot`), and Venice Uncensored (v5 3-Stage + `<agy_slot>`) catalog, session-scoped & state-synced model/effort switching, guarded `models_run`, and sanitized `models_pool_health`.
- [ ] **Step 2:** Implement `sessions.rs` exposing `StateStore` session list/create/resume/switch, transcript search, `.handoff` read/write.
- [ ] **Step 3:** Implement `optimizer.rs` exposing all 8 zero-token optimization tools (`turn_profile`, `local_fast`, head+tail compaction, strategic-compact check, prompt analyzer, token estimator, RO cache stats, `<agy_slot>` assembler).
- [ ] **Step 4:** Implement `federation.rs` dynamically proxying enabled entries from `mcp_config.json` with `ManifestPinStore` rug-pull checks.
- [ ] **Step 5:** Implement MCP `resources/*` and `prompts/*` handlers + tests.

---

### Phase 5 — Telegram Owner Management Panel (`/mcpgw`), Bot Wiring & Dual-Domain Caddy Deployment

#### Task 11: Owner-Only Telegram Panel (`handlers_mcpgw.rs`) & Bot Wiring (`main.rs`, `ctx.rs`, `handlers_mcp.rs`)
**Files:**
- Create: `crates/agy-bot/src/handlers_mcpgw.rs`
- Modify: `crates/agy-bot/src/main.rs`, `crates/agy-bot/src/ctx.rs`, `crates/agy-bot/src/handlers_mcp.rs`
- [ ] **Step 1:** Implement `/mcpgw` Owner-only panel (plus button inside `/mcp`):
  - **Dashboard**: live status, dual-domain endpoints, active sessions, call/cache/block metrics, account pool health
  - **Kill Switch**: `🟢 Active` / `🟡 Read-Only` / `🔴 Kill`
  - **API Keys**: Create (preset or custom sections), View/Revoke/Rotate, 1-tap Copy-Ready Config Snippets for VS Code, Claude, Gemini, Grok, Cursor
  - **OAuth Clients**: View active DCR/OAuth clients, Revoke tokens, inline Telegram 2FA Approve/Deny callback handler (`mcpgw:oauth:ok:<id>` / `no:<id>`)
  - **Sections & HITL Policy**: Toggle each of the 9 sections globally, toggle `ask_telegram` HITL mode, inline HITL approve/deny callback (`mcpgw:hitl:once:<id>` / `sess:<id>` / `no:<id>`), approve/reject drifted manifest pins
  - **Limits & Security**: Edit IP RPM, Key RPM, `max_mcp_ai_concurrency`, daily AI cap, IP ban list, view live audit log
- [ ] **Step 2:** Wire `agy-mcp-gateway` startup on `127.0.0.1:8788` in `main.rs` with graceful `shutdown_rx`.
- [ ] **Step 3:** Write unit tests verifying non-owner `/mcpgw` is strictly denied (`is_owner` check) and callback flows work cleanly.

#### Task 12: Dual-Domain Caddy TLS Configuration, End-to-End Verification & Atomic Cutover
**Files:**
- Modify: `/etc/caddy/Caddyfile` (keeping `example-gateway.sslip.io` untouched!)
- [ ] **Step 1:** Add `mcp.example.com` (direct Let's Encrypt TLS, `flush_interval -1`, strict security headers, `X-Real-IP {remote_host}`) and `gateway.example.com` (Cloudflare proxied TLS, trusted Cloudflare IP ranges for `CF-Connecting-IP`, `flush_interval -1`, `Cache-Control: no-store`).
- [ ] **Step 2:** Validate `caddy validate --config /etc/caddy/Caddyfile` and `systemctl reload caddy`.
- [ ] **Step 3:** Run full workspace verification: `cargo test --workspace`, `cargo clippy --workspace --all-targets`, `cargo build --release`.
- [ ] **Step 4:** Atomic deploy to `/root/agy-stack/app/bin/agy-telegram` + delayed `systemctl restart agy-telegram`.
- [ ] **Step 5:** Live E2E verification suite against BOTH `https://mcp.example.com/mcp` and `https://gateway.example.com/mcp`:
  - TLS certificate & HTTP/2 verification
  - Unauthenticated `401` + RFC 9728 `/.well-known/oauth-protected-resource` + RFC 8414 `/.well-known/oauth-authorization-server`
  - OAuth 2.1 DCR + PKCE flow test
  - Streamable HTTP 2025 stateful + 2026 stateless + Legacy `/sse` checks
  - Section-by-section tool calls (`hub_discover_tools`, `skillhub_search`, `search_status`, `opt_classify_turn`, `models_list`, `session_list`, `oh_glob_files`)
  - Security probes (blocked path read, secret redaction, rate-limit `429`, spoofed `CF-Connecting-IP`)
  - Zero regression on existing `:8787/healthz` and Telegram bot commands.
