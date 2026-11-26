#!/usr/bin/env bash
set -euo pipefail

# Bootstrap cilipy stack on a clean Linux host without storing secrets in Git.
STACK_ROOT="${STACK_ROOT:-/root/agy-stack}"

mkdir -p /etc/agy-telegram /var/lib/agy-telegram "${STACK_ROOT}/app/bin" "${STACK_ROOT}/app/backups" "${STACK_ROOT}/bin"
chmod 700 /etc/agy-telegram

if [ ! -f /etc/agy-telegram/bot.env ]; then
  cp deploy/bot.env.example /etc/agy-telegram/bot.env
  chmod 600 /etc/agy-telegram/bot.env
  echo "Created /etc/agy-telegram/bot.env (edit with real tokens before starting service)."
fi

echo "Building Rust workspace..."
cargo build --release --manifest-path bot/Cargo.toml
install -m 0755 bot/target/release/agy-telegram "${STACK_ROOT}/app/bin/agy-telegram"

echo "Installing MCP dependencies..."
if command -v npm >/dev/null 2>&1; then
  (cd mcp/skills-catalog && npm ci && npm run build)
  (cd mcp/ai-memory && npm ci --omit=dev)
fi

install -m 0755 deploy/healthcheck.sh "${STACK_ROOT}/app/healthcheck.sh"
echo "Done. Run: ${STACK_ROOT}/app/bin/agy-telegram --check"
