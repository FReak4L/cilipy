# cilipy — AGY Telegram Bot & Modular AI Stack

[![CI](https://github.com/FReak4L/cilipy/actions/workflows/ci.yml/badge.svg)](https://github.com/FReak4L/cilipy/actions/workflows/ci.yml)
[![Security](https://github.com/FReak4L/cilipy/actions/workflows/security.yml/badge.svg)](https://github.com/FReak4L/cilipy/actions/workflows/security.yml)
[![Release](https://img.shields.io/github/v/release/FReak4L/cilipy?sort=semver)](https://github.com/FReak4L/cilipy/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A modular, security-hardened Telegram bridge and AI tooling stack built around a 7-crate Rust runtime (`agy-telegram` + MCP Gateway), Markdown agent rules & 24 skills, 11 MCP servers (`search-v3`, `skills-catalog`, `ai-memory`, `skillhub`, `openhands`, `venice-uncensored`, `browser`, `graphify`, `gortex`, `skillport`, `context7`), and GitOps CI/CD self-update automation.

---

## Repository Structure

| Component | Path | Description |
|---|---|---|
| Core Rust Bot & MCP Gateway | `bot/` | 7-crate workspace (`agy-core`, `agy-render`, `agy-net`, `agy-ext`, `agy-widgets`, `agy-mcp-gateway`, `agy-bot`) |
| Agent Rules (`.md`) | `rules/` | Global behavioral & operational Markdown rules including mandatory `github-sync.md` |
| Agent Skills | `skills/` | 24 modular skills (`skillhub`, `telegram-premium-emoji`, `browser-automation`, `openhands-toolkit`, `venice-uncensored`, etc.) |
| Federated Search v3 MCP | `mcp/search-v3/` | Async federated search engine & stdio MCP server (`search-v3-mcp`) |
| SkillHub Catalog MCP | `mcp/skills-catalog/` | TypeScript skill index & discovery MCP (`skills-catalog-mcp`) |
| AI Memory Guard | `mcp/ai-memory/` | Stdout JSON-RPC guard wrapper for `mcp-ai-memory` |
| Launcher Wrappers | `bin-wrappers/` | Sanitized wrappers (`ai-memory-mcp`, `search-v3-mcp`, `skills-catalog-mcp`, `uncensored-mcp`) |
| Documentation | `docs/` | Telegram Rich Message / Widget / Parallel docs (`docs/telegram-docs/`) & runbooks (`bot/docs/`) |
| Deployment & Config Templates | `deploy/` | `systemd` units, `bot.env.example`, `mcp_config.example.json`, `agent-browser.json`, `Caddyfile.example`, `install.sh` |
| GitOps Updater & Utility Tools | `scripts/` | `agy-updater.sh`, `sync-to-github.sh`, and `scripts/tools/` verification/extraction scripts |
| CI/CD & Security | `.github/` | Rust/Python/Node CI, `gitleaks` secret scan, `release-please`, tagged release builds, Dependabot, templates |

---

## Included 11-MCP Stack (`deploy/mcp_config.example.json`)

| MCP Server | Runtime / Binary | Purpose |
|---|---|---|
| `ai-memory` | Node + `mcp/ai-memory/stdout-guard.mjs` | Persistent vector/graph memory (`mcp-ai-memory`) |
| `search-v3` | Python (`mcp/search-v3`) | Federated multi-engine search & strict Boolean AST dork filter |
| `skills-catalog` | Node/TS (`mcp/skills-catalog`) | 9,000+ community skills catalog search & install |
| `skillhub` | Built-in (`agy-telegram --mcp-skillhub`) | Local 4,700+ curated ecosystem docs & skill lookup |
| `openhands` | Built-in (`agy-telegram --mcp-openhands`) | Batch reads, multi-edit with rollback, PTY, Python RPC batching |
| `venice-uncensored` | Built-in (`agy-telegram --mcp-uncensored`) | Uncensored OpenAI-compatible agent execution |
| `browser` | `agent-browser` + `deploy/agent-browser.json` | Headless Chrome accessibility-tree automation |
| `graphify` | `uv tool` (`graphify-mcp`) | Whole-repo knowledge graph queries & PR impact |
| `gortex` | `gortex mcp` | Live symbol/call-graph index & change impact |
| `skillport` | `uv tool` (`skillport-mcp`) | Local skill search & loading |
| `context7` | `context7-mcp` | Up-to-date third-party library documentation |

---

## Security & GitOps Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) and [SECURITY.md](SECURITY.md) for details:
- **Zero secrets in Git:** Runtime `.env` lives strictly outside the repo at `/etc/agy-telegram/bot.env` (`0600`) and CI/CD secrets live in GitHub `Environment: production`.
- **Protected `main` branch:** All changes land via Pull Requests passing `Rust Bot & Gateway Tests`, `Search v3 Unit Tests`, `Skills Catalog MCP Build`, and `Secret Scan (gitleaks)`.
- **Atomic Self-Updates (`scripts/agy-updater.sh`):** Downloads verified GitHub Releases + `SHA256SUMS.txt`, runs `agy-telegram --check`, swaps atomically via `--self-update`, and auto-rolls back if `--health` fails.
- **Post-Update Sync (`scripts/sync-to-github.sh`):** Sanitizes local server metadata, verifies `gitleaks` + `cargo test`, and opens a PR on `FReak4L/cilipy`.

---

## Quick Start

```bash
# 1. Run full bootstrap (edits /etc/agy-telegram/bot.env outside the repo)
./deploy/install.sh

# 2. Populate tokens in /etc/agy-telegram/bot.env (chmod 0600) and run pre-flight diagnostics
/root/agy-stack/app/bin/agy-telegram --check

# 3. Run test suites locally
cargo test --manifest-path bot/Cargo.toml
```
