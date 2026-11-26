## Summary
<!-- Describe what changed and why. Reference any issue with `Fixes #123`. -->

## Changes
- [ ] Rust bot / MCP Gateway (`bot/`)
- [ ] Rules / Docs (`rules/`, `docs/`)
- [ ] Skills (`skills/`)
- [ ] MCP Servers / Wrappers (`mcp/`, `bin-wrappers/`)
- [ ] Deploy / Updater / CI (`deploy/`, `scripts/`, `.github/`)

## Security & Verification Checklist
- [ ] No real tokens, `.env` files, `.session` files, private server IPs, or personal UIDs included
- [ ] `gitleaks detect --no-git -s . -c .gitleaks.toml` passes with 0 findings
- [ ] Relevant test suite passes (`cargo test`, `pytest`, `npm run build`)
- [ ] Conventional Commit title used (`feat:`, `fix:`, `docs:`, `ci:`, `chore:`)
