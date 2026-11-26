#!/usr/bin/env bash
set -euo pipefail

# Bootstrap full cilipy stack on a clean Linux host without storing secrets in Git.
STACK_ROOT="${STACK_ROOT:-/root/agy-stack}"

mkdir -p /etc/agy-telegram /var/lib/agy-telegram \
  "${STACK_ROOT}/app/bin" "${STACK_ROOT}/app/backups" \
  "${STACK_ROOT}/bin" "${STACK_ROOT}/config/mcp" "${STACK_ROOT}/config/gemini"
chmod 700 /etc/agy-telegram

if [ ! -f /etc/agy-telegram/bot.env ]; then
  cp deploy/bot.env.example /etc/agy-telegram/bot.env
  chmod 600 /etc/agy-telegram/bot.env
  echo "Created /etc/agy-telegram/bot.env (edit with real tokens before starting service)."
fi

if [ ! -f /etc/agy-telegram/mcp-ai-memory.env ]; then
  cp deploy/mcp-ai-memory.env.example /etc/agy-telegram/mcp-ai-memory.env
  chmod 600 /etc/agy-telegram/mcp-ai-memory.env
fi

cp deploy/agent-browser.json "${STACK_ROOT}/config/mcp/agent-browser.json"
if [ ! -f "${STACK_ROOT}/config/gemini/mcp_config.json" ]; then
  cp deploy/mcp_config.example.json "${STACK_ROOT}/config/gemini/mcp_config.json"
  chmod 600 "${STACK_ROOT}/config/gemini/mcp_config.json"
fi

echo "[1/5] Building Rust bot & MCP gateway..."
cargo build --release --manifest-path bot/Cargo.toml
install -m 0755 bot/target/release/agy-telegram "${STACK_ROOT}/app/bin/agy-telegram"

echo "[2/5] Installing Node MCPs (skills-catalog, ai-memory)..."
if command -v npm >/dev/null 2>&1; then
  (cd mcp/skills-catalog && npm ci && npm run build)
  (cd mcp/ai-memory && npm ci --omit=dev)
fi

echo "[3/5] Installing Python Search v3 MCP..."
if command -v python3 >/dev/null 2>&1; then
  python3 -m venv /opt/search-v3/venv
  /opt/search-v3/venv/bin/pip install --upgrade pip
  /opt/search-v3/venv/bin/pip install -e ./mcp/search-v3
fi

echo "[4/5] Installing optional uv CLI tools (graphify, skillport)..."
if command -v uv >/dev/null 2>&1; then
  uv tool install graphifyy || true
  uv tool install skillport || true
  uv tool install skillport-mcp || true
fi

echo "[5/5] Installing wrappers, rules, skills, and healthcheck..."
install -m 0755 deploy/healthcheck.sh "${STACK_ROOT}/app/healthcheck.sh"
install -m 0755 bin-wrappers/*-mcp "${STACK_ROOT}/bin/"
rsync -a rules/ "${STACK_ROOT}/config/gemini/rules/"
rsync -a skills/ "${STACK_ROOT}/config/gemini/skills/"

echo "Done. Verify pre-flight with: ${STACK_ROOT}/app/bin/agy-telegram --check"
