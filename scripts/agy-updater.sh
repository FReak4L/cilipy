#!/usr/bin/env bash
set -euo pipefail

# Secure GitOps Updater for agy-telegram & rules/skills from FReak4L/cilipy.
# Never touches /etc/agy-telegram/bot.env, config/bot/bot.env, or /var/lib/agy-telegram state.

REPO="${CILIPY_REPO:-FReak4L/cilipy}"
STACK_ROOT="${STACK_ROOT:-/root/agy-stack}"
BIN_PATH="${STACK_ROOT}/app/bin/agy-telegram"
STAGE_DIR="$(mktemp -d /tmp/cilipy-update.XXXXXX)"
trap 'rm -rf "$STAGE_DIR"' EXIT

export GH_CONFIG_DIR="${GH_CONFIG_DIR:-/root/.config/gh}"

resolve_env_file() {
  if [ -n "${ENV_FILE:-}" ] && [ -r "$ENV_FILE" ]; then
    echo "$ENV_FILE"
    return 0
  fi
  for cand in "/etc/agy-telegram/bot.env" "${STACK_ROOT}/config/bot/bot.env"; do
    if [ -r "$cand" ]; then
      echo "$cand"
      return 0
    fi
  done
  echo "ERROR: readable bot.env not found under /etc/agy-telegram/bot.env or ${STACK_ROOT}/config/bot/bot.env" >&2
  return 1
}

echo "[1/5] Checking GitHub release for ${REPO}..."
TAG="${1:-}"
if [ -z "$TAG" ]; then
  TAG="$(gh release view -R "$REPO" --json tagName -q .tagName)"
fi
echo "Target release: ${TAG}"

echo "[2/5] Downloading release artifacts & SHA256SUMS.txt..."
gh release download "$TAG" -R "$REPO" -D "$STAGE_DIR" \
  -p "agy-telegram-linux-x86_64.tar.gz" \
  -p "cilipy-rules-skills.tar.gz" \
  -p "SHA256SUMS.txt"

echo "[3/5] Verifying SHA256 checksums..."
(cd "$STAGE_DIR" && sha256sum -c SHA256SUMS.txt)

echo "[4/5] Staging binary and running --self-update (with --check + rollback)..."
tar -xzf "${STAGE_DIR}/agy-telegram-linux-x86_64.tar.gz" -C "$STAGE_DIR"
chmod +x "${STAGE_DIR}/agy-telegram"

BOT_ENV_PATH="$(resolve_env_file)"
set -a
# shellcheck disable=SC1090
. "$BOT_ENV_PATH"
set +a
export STATE_DIR="${STATE_DIR:-/var/lib/agy-telegram}"
export AGY_WORKSPACE="${AGY_WORKSPACE:-/root/agy-workspace}"
export HOME="${HOME:-/root}"

"${STAGE_DIR}/agy-telegram" --check >/dev/null
"$BIN_PATH" --self-update "${STAGE_DIR}/agy-telegram"

echo "[5/5] Syncing rules, skills & docs..."
tar -xzf "${STAGE_DIR}/cilipy-rules-skills.tar.gz" -C "$STAGE_DIR"
rsync -a --delete "${STAGE_DIR}/rules/" "${STACK_ROOT}/config/gemini/rules/"
rsync -a "${STAGE_DIR}/skills/" "${STACK_ROOT}/config/gemini/skills/"
if [ -d "${STAGE_DIR}/docs/telegram-docs" ] && [ -d "${STACK_ROOT}/data/workspace/telegram-docs" ]; then
  rsync -a --delete "${STAGE_DIR}/docs/telegram-docs/" "${STACK_ROOT}/data/workspace/telegram-docs/"
fi

if grep -q "agy-telegram.service" /proc/self/cgroup 2>/dev/null; then
  UNIT="agy-updater-restart-$(date +%s)"
  echo "Detected inside agy-telegram.service cgroup; scheduling detached restart (${UNIT}) with auto-rollback..."
  systemd-run --on-active=4s --unit="$UNIT" --collect \
    /bin/bash -c "systemctl restart agy-telegram && sleep 4 && (systemctl is-active --quiet agy-telegram && '$BIN_PATH' --health >/dev/null && curl -fsS --max-time 5 http://127.0.0.1:8787/healthz >/dev/null) || ('$BIN_PATH' --rollback && systemctl restart agy-telegram)"
  echo "Staged ${TAG} and scheduled detached activation (${UNIT})."
else
  echo "Restarting agy-telegram and verifying health..."
  systemctl restart agy-telegram
  sleep 4
  if ! "$BIN_PATH" --health || ! curl -fsS --max-time 5 http://127.0.0.1:8787/healthz >/dev/null; then
    echo "Healthcheck failed! Rolling back binary..."
    "$BIN_PATH" --rollback
    systemctl restart agy-telegram
    exit 1
  fi
  echo "Successfully updated to ${TAG}."
fi
