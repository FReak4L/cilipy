#!/usr/bin/env bash
set -euo pipefail

# Post-Update GitHub Publisher:
# Syncs live stack changes from /root/agy-stack into the clean public repo,
# applies local sanitization rules from /etc/agy-telegram/sanitize-map.json,
# runs gitleaks + cargo test, opens a PR, and enables auto-merge on CI.

STACK_ROOT="${STACK_ROOT:-/root/agy-stack}"
REPO_DIR="${CILIPY_DIR:-${STACK_ROOT}/cilipy}"
SANITIZE_MAP="${SANITIZE_MAP:-/etc/agy-telegram/sanitize-map.json}"
BRANCH="${1:-chore/sync-$(date -u +%Y%m%d-%H%M%S)}"
COMMIT_MSG="${2:-chore: sync verified stack updates}"

export PATH="/root/.cargo/bin:/usr/local/bin:${PATH}"
export GH_CONFIG_DIR="${GH_CONFIG_DIR:-/root/.config/gh}"

cd "$REPO_DIR"
git checkout main
git pull --ff-only origin main

echo "[1/5] Syncing source, rules, skills, docs, MCPs, and utility tools into ${REPO_DIR}..."
rsync -a --delete --exclude='target/' --exclude='.git/' --exclude='*.bak' \
  "${STACK_ROOT}/src/ch-base/" "${REPO_DIR}/bot/"
rsync -a --delete --exclude='*.bak' \
  "${STACK_ROOT}/config/gemini/rules/" "${REPO_DIR}/rules/"
rsync -a --delete --exclude='__pycache__/' --exclude='*.pyc' --exclude='.git/' --exclude='*.bak' \
  "${STACK_ROOT}/config/gemini/skills/" "${REPO_DIR}/skills/"
rsync -a --delete --exclude='*.bak' \
  "${STACK_ROOT}/data/workspace/telegram-docs/" "${REPO_DIR}/docs/telegram-docs/"
rsync -a --delete --exclude='__pycache__/' --exclude='*.pyc' --exclude='.git/' --exclude='*.db' \
  --exclude='*.log' --exclude='*.zip' --exclude='.venv/' --exclude='*.egg-info/' \
  --exclude='benchmark_100_out/' --exclude='per_engine_runs/' --exclude='results_*.json' \
  --exclude='workspace/cache/' --exclude='workspace/logs/' --exclude='workspace/proxies/' \
  --exclude='workspace/configs/' --exclude='workspace/exports/' \
  "${STACK_ROOT}/mcp/search-v3/v3/" "${REPO_DIR}/mcp/search-v3/"
rsync -a --delete --exclude='node_modules/' --exclude='dist/' --exclude='data/' --exclude='.git/' \
  "${STACK_ROOT}/mcp/skills-catalog/" "${REPO_DIR}/mcp/skills-catalog/"
mkdir -p "${REPO_DIR}/mcp/ai-memory" "${REPO_DIR}/scripts/tools"
for f in package.json package-lock.json stdout-guard.mjs; do
  [ -f "${STACK_ROOT}/mcp/ai-memory/${f}" ] && cp "${STACK_ROOT}/mcp/ai-memory/${f}" "${REPO_DIR}/mcp/ai-memory/${f}"
done
[ -f "${STACK_ROOT}/config/mcp/agent-browser.json" ] && cp "${STACK_ROOT}/config/mcp/agent-browser.json" "${REPO_DIR}/deploy/agent-browser.json"
[ -f "${STACK_ROOT}/app/healthcheck.sh" ] && cp "${STACK_ROOT}/app/healthcheck.sh" "${REPO_DIR}/deploy/healthcheck.sh"
[ -d "${STACK_ROOT}/scripts/tools" ] && rsync -a --delete --exclude='__pycache__/' "${STACK_ROOT}/scripts/tools/" "${REPO_DIR}/scripts/tools/"

if [ -r "$SANITIZE_MAP" ]; then
  echo "[2/5] Applying local sanitization rules from ${SANITIZE_MAP}..."
  python3 - "$REPO_DIR" "$SANITIZE_MAP" <<'PY'
import json, os, sys
root_dir, map_path = sys.argv[1], sys.argv[2]
replacements = json.load(open(map_path, encoding="utf-8"))
exts = {".rs", ".md", ".py", ".ts", ".js", ".mjs", ".toml", ".json", ".yml", ".yaml", ".sh", ".txt", ".html", ".css"}
for root, _, files in os.walk(root_dir):
    if "/.git/" in root or root.endswith("/.git") or "/target/" in root:
        continue
    for fn in files:
        if os.path.splitext(fn)[1].lower() not in exts and fn != "Cargo.lock":
            continue
        p = os.path.join(root, fn)
        try:
            raw = open(p, "r", encoding="utf-8").read()
        except Exception:
            continue
        new = raw
        for old, rep in replacements:
            new = new.replace(old, rep)
        if new != raw:
            open(p, "w", encoding="utf-8").write(new)
PY
else
  echo "[2/5] Skipping external sanitize-map (not present)."
fi

if [ -z "$(git status --porcelain)" ]; then
  echo "No changes to publish."
  exit 0
fi

echo "[3/5] Running gitleaks secret scan & Rust tests..."
gitleaks detect --no-git -s "$REPO_DIR" -c "${REPO_DIR}/.gitleaks.toml" --redact
cargo test --manifest-path "${REPO_DIR}/bot/Cargo.toml"

echo "[4/5] Creating branch ${BRANCH} and committing..."
git checkout -b "$BRANCH"
git add -A
git commit -m "$COMMIT_MSG"
git push -u origin "$BRANCH"

echo "[5/5] Opening Pull Request..."
PR_URL="$(gh pr create --base main --head "$BRANCH" --title "$COMMIT_MSG" --body "Automated post-update sync verified with gitleaks and cargo test.")"
echo "Opened PR: ${PR_URL}"
gh pr merge "$PR_URL" --merge --delete-branch --auto || true
git checkout main
