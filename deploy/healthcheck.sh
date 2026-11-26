#!/bin/sh
# agy-telegram external health check (run by agy-telegram-health.timer every 2 min).
H=/var/lib/agy-telegram/health.json
if ! systemctl is-active --quiet agy-telegram; then
  logger -t agy-telegram-health "service not active -> start"; systemctl start agy-telegram; exit 0
fi
[ -f "$H" ] || exit 0
python3 - "$H" <<'PY' || { logger -t agy-telegram-health "unhealthy -> restart"; systemctl restart agy-telegram; }
import json, sys, time, subprocess
h = json.load(open(sys.argv[1]))
age = time.time() - h.get("ts", 0)
stall = h.get("stall_s", 0)
busy = subprocess.run(["pgrep", "-P", str(h.get("pid", 0)), "-x", "agy"], capture_output=True).returncode == 0
if age > 120:
    print("health file stale", age); sys.exit(1)
if stall > 900 and not busy:
    print("polling stalled", stall); sys.exit(1)
PY
