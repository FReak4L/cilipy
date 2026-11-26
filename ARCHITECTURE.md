# Architecture Overview

`cilipy` combines a high-throughput Rust Telegram bridge (`agy-telegram`), an isolated Remote MCP Gateway (`agy-mcp-gateway`), modular AI agent rules & skills, external stdio MCP servers, and a GitOps release/update pipeline.

## System Topology

```mermaid
flowchart LR
    TG["Telegram Bot API / Mini App"] <-->|"Polling / Webhook + Axum :8787"| BOT["agy-telegram (Rust)"]
    CLI["Remote MCP Clients (OAuth 2.1 / Bearer)"] <-->|"Streamable HTTP :8788"| GW["agy-mcp-gateway"]
    BOT --> EXT["agy-ext Runtime & Guardrails"]
    GW --> EXT
    EXT -->|"stdio JSON-RPC"| MCP["11 MCP Servers (search-v3, skills-catalog, ai-memory, browser, graphify, gortex, skillport, context7, skillhub, openhands, venice-uncensored)"]
    BOT -.->|"reads 0600 outside repo"| ENV["/etc/agy-telegram/bot.env"]
    GH["GitHub FReak4L/cilipy"] -->|"SHA256 verified Release + --self-update"| UPD["scripts/agy-updater.sh"]
    STACK["Live Server Stack"] -->|"sanitize + gitleaks + PR"| SYNC["scripts/sync-to-github.sh"]
    SYNC --> GH
```

## Crate Breakdown (`bot/crates/`)

| Crate | Purpose |
|---|---|
| `agy-core` | Config validation, 3-tier ACL, account rotation & 1% weekly reserve, proxy pool, secret scanner, atomic file store |
| `agy-render` | GFM-to-Telegram HTML/Rich renderer, UTF-16 entity splitting, premium emoji overlay |
| `agy-net` | Resilient Telegram HTTP client, FloodWait queue, proxy circuit breaker, `sd_notify` watchdog |
| `agy-ext` | Multi-engine runtime, OpenHands tools, SkillHub & skill indexer, fleet updater, update seal guard |
| `agy-widgets` | Compressed interactive Telegram widgets (`<= 4096 B` zlib-9), HMAC `initData` WebApp bridge |
| `agy-mcp-gateway` | Loopback `:8788` Streamable HTTP MCP gateway with OAuth 2.1 PKCE, manifest pinning, and HITL gates |
| `agy-bot` | Main binary (`agy-telegram`), Telegram handlers, webhook/poller router, cron scheduler, CLI self-updater |
