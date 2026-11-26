# Contributing to cilipy

Thank you for contributing! All changes land through Pull Requests against `main` with passing CI and secret-scan checks.

## Workflow
1. Fork or branch from `main` (`feat/...`, `fix/...`, `docs/...`, `ci/...`).
2. Follow [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `docs:`, `chore:`, `ci:`) so `release-please` generates accurate changelogs and semantic releases.
3. Run local verification before pushing:
   ```bash
   gitleaks detect --no-git -s . -c .gitleaks.toml --redact
   cargo test --manifest-path bot/Cargo.toml
   ```
4. Never commit real `.env` files, bot tokens, OAuth tokens, `.session` files, private proxies, or live server IPs. Keep runtime secrets in `/etc/agy-telegram/bot.env` (`chmod 600`) and GitHub `Environment: production`.
