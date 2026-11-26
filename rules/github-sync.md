---
trigger: always_on
description: Mandatory post-update GitHub sync to FReak4L/cilipy after bot, rule, skill, doc, or MCP changes
---

# Post-update GitHub sync (`FReak4L/cilipy`)

**Mandatory rule:** After ANY update to the `agy-telegram` bot source (`/root/agy-stack/src/ch-base/`), rules (`/root/agy-stack/config/gemini/rules/`), skills (`/root/agy-stack/config/gemini/skills/`), MCP servers (`search-v3`, `skills-catalog`, `ai-memory`), or docs (`/root/agy-stack/data/workspace/telegram-docs/`), you MUST sync the changes to the public GitHub repository `FReak4L/cilipy` (`https://github.com/FReak4L/cilipy`) before considering the update complete.

## Security invariants (NEVER violate)
1. **Never commit directly inside `/root/agy-stack` or `config/bot/`.** Always sync through `/root/agy-stack/cilipy/` using `/root/agy-stack/scripts/sync-to-github.sh` (with `GH_CONFIG_DIR=/root/.config/gh`).
2. **Never leak secrets or live infrastructure:** `.env` files, `bot.env`, `mcp-ai-memory.env`, OAuth tokens, `.session` files, private proxies, real server IPs, and personal UIDs MUST never enter Git history. `gitleaks` must pass with 0 findings.
3. **Always preserve GitHub Activity & CI checks:**
   - Use Conventional Commits (`feat:`, `fix:`, `docs:`, `chore:`, `ci:`) authored as `Freak 4L <freakxray@proton.me>`.
   - Push to a feature branch and open a Pull Request to `main` (never force-push to `main`).
   - Wait for CI (`rust-bot`, `python-search-v3`, `node-skills-catalog`, `gitleaks`, `CodeQL & Dependency Audit`) before merging; `release-please` handles version bumps, `CHANGELOG.md`, and tagged GitHub Releases.

## Standard sync command after any update
```bash
GH_CONFIG_DIR=/root/.config/gh /root/agy-stack/scripts/sync-to-github.sh "feat/update-$(date -u +%Y%m%d)" "feat: <concise summary of update>"
```
