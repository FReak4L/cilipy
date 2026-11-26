# cilipy — AGY Telegram Bot & Modular AI Stack

A modular, security-hardened Telegram bridge and AI tooling stack built around a 7-crate Rust runtime (`agy-telegram` + MCP Gateway), Markdown agent rules & skills, federated Search v3, SkillHub catalog MCP, and GitOps self-update/CI-CD automation.

## Architecture

| Component | Path | Description |
|---|---|---|
| Core Rust Bot & MCP Gateway | `bot/` | 7-crate workspace (`agy-core`, `agy-render`, `agy-net`, `agy-ext`, `agy-widgets`, `agy-mcp-gateway`, `agy-bot`) |
| Agent Rules (`.md`) | `rules/` | Global behavioral & operational Markdown rules including `github-sync.md` |
| Agent Skills | `skills/` | 24 modular skills (`skillhub`, `telegram-premium-emoji`, `browser-automation`, `openhands-toolkit`, etc.) |
| Federated Search v3 MCP | `mcp/search-v3/` | Async federated search engine & stdio MCP server (`search-v3-mcp`) |
| SkillHub Catalog MCP | `mcp/skills-catalog/` | TypeScript skill index & discovery MCP (`skills-catalog-mcp`) |
| AI Memory Guard | `mcp/ai-memory/` | Stdout JSON-RPC guard wrapper for `mcp-ai-memory` |
| Documentation | `docs/` | Telegram rich output guides (`docs/telegram-docs/`) & bot runbooks (`bot/docs/`) |
| Deployment & Templates | `deploy/` | Hardened `systemd` units, `bot.env.example`, `Caddyfile.example`, `install.sh` |
| Self-Updater & GitHub Sync | `scripts/` | Atomic release updater (`agy-updater.sh`) & PR-based publisher (`sync-to-github.sh`) |
| CI/CD & Security | `.github/` | Rust/Python/Node CI, `gitleaks` scanning, `release-please`, release asset builder |

## Security Model

1. **Secrets are never stored in Git.** Runtime `.env` lives at `/etc/agy-telegram/bot.env` (`0600`) and CI/CD secrets live in GitHub `Environment: production`.
2. **PR-only `main` branch** enforced with CI + `gitleaks` checks and GitHub Push Protection.
3. **Atomic Self-Updates (`agy-updater.sh`):** Downloads verified GitHub Release assets + `SHA256SUMS.txt`, runs `agy-telegram --check`, atomically replaces the binary via `--self-update`, and rolls back automatically on failure without touching `/etc/agy-telegram/bot.env`.
4. **Automated Post-Update GitHub Sync (`rules/github-sync.md` + `scripts/sync-to-github.sh`):** Any live stack update is sanitized, secret-scanned with `gitleaks`, tested, and submitted as a clean feature-branch Pull Request so the public repo and release history stay current.

## Quick Start

```bash
# 1. Inspect and populate environment template outside the git tree
sudo mkdir -p /etc/agy-telegram /var/lib/agy-telegram
sudo cp deploy/bot.env.example /etc/agy-telegram/bot.env
sudo chmod 600 /etc/agy-telegram/bot.env

# 2. Build Rust workspace
cd bot && cargo build --release

# 3. Run pre-flight check & tests
cargo test
```
