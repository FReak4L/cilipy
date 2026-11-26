# Security Policy

## Secret Hygiene
- **Zero secrets in Git:** All runtime tokens (`BOT_TOKEN`, API keys, proxy credentials, OAuth tokens, and `.session` files) MUST live outside the Git repository under `/etc/agy-telegram/bot.env` (`chmod 0600`) and GitHub `Environment: production` secrets.
- **Automated Secret Scanning:** Every pull request and push is scanned by `gitleaks` in GitHub Actions and via pre-commit / sync guards. GitHub Secret Scanning & Push Protection are enabled on the repository.
- **Branch Protection:** Direct pushes to `main` are disabled. All updates land via reviewed Pull Requests passing CI checks.
- **Least-Privilege Deployment:**
  - Server update pulls use a read-only deploy key or public GitHub Release artifact verification (`SHA256SUMS.txt`).
  - The live bot process does **not** hold repository write credentials.

## Reporting a Vulnerability
Please report security issues privately via GitHub Security Advisories rather than opening a public issue.
