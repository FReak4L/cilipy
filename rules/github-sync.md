---
trigger: always_on
description: Mandatory post-update GitHub sync invariants for FReak4L/cilipy
---

<github_sync repo="FReak4L/cilipy">
TRIGGER: ANY edit to /root/agy-stack/src/ch-base/, config/gemini/rules/, config/gemini/skills/, mcp/(search-v3|skills-catalog|ai-memory), or data/workspace/telegram-docs/.
INVARIANTS:
  1. NEVER commit inside /root/agy-stack or config/bot/. Sync ONLY via /root/agy-stack/cilipy/ using /root/agy-stack/scripts/sync-to-github.sh (GH_CONFIG_DIR=/root/.config/gh).
  2. ZERO_LEAKS: no .env, bot.env, mcp-ai-memory.env, OAuth tokens, .session, private proxies, server IPs, personal UIDs. gitleaks MUST pass (0 findings).
  3. ACTIVITY_AND_CI: Conventional Commits (feat:|fix:|docs:|chore:|ci:) authored as `Freak 4L <freakxray@proton.me>`; feature branch -> PR to main (never force-push main); wait for CI green before merge; release-please handles version/CHANGELOG/Release.
CMD:
  GH_CONFIG_DIR=/root/.config/gh /root/agy-stack/scripts/sync-to-github.sh "feat/update-$(date -u +%Y%m%d)" "feat: <summary>"
</github_sync>
