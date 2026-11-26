#!/usr/bin/env bash
set -euo pipefail

# Secure GitOps Updater for agy-telegram & rules/skills from FReak4L/cilipy.
# Never touches /etc/agy-telegram/bot.env or /var/lib/agy-telegram state.

REPO="${CILIPY_REPO:-FReak4L/cilipy}"
STACK_ROOT="${STACK_ROOT:-/root/agy-stack}"
BIN_PATH="${STACK_ROOT}/app/bin/agy-telegram"
STAGE_DIR="$(mktemp -d /tmp/cilipy-update.XXXXXX)"
trap 'rm -rf "$STAGE_DIR"' EXIT

export GH_CONFIG_DIR="${GH_CONFIG_DIR:-/root/.config/gh}"

echo "[1/5] Checking latest GitHub release for ${REPO}..."
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

set -a
# shellcheck disable=SC1091
. /etc/agy-telegram/bot.env
set +a
STATE_DIR=/var/lib/agy-telegram "${STAGE_DIR}/agy-telegram" --check
"$BIN_PATH" --self-update "${STAGE_DIR}/agy-telegram"

echo "[5/5] Syncing rules, skills & docs..."
tar -xzf "${STAGE_DIR}/cilipy-rules-skills.tar.gz" -C "$STAGE_DIR"
rsync -a --delete "${STAGE_DIR}/rules/" "${STACK_ROOT}/config/gemini/rules/"
rsync -a "${STAGE_DIR}/skills/" "${STACK_ROOT}/config/gemini/skills/"

echo "Restarting agy-telegram and verifying health..."
systemctl restart agy-telegram
sleep 3
if ! "$BIN_PATH" --health; then
  echo "Healthcheck failed! Rolling back binary..."
  "$BIN_PATH" --rollback
  systemctl restart agy-telegram
  exit 1
fi
echo "Successfully updated to ${TAG}."
