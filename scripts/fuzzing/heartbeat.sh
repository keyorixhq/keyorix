#!/usr/bin/env bash
# Sends one daily ntfy.sh ping so the box's silence itself is informative: if
# the heartbeat stops arriving, keyorix-fuzz.service died (or the box did)
# without you having to check in manually. Run via keyorix-fuzz-heartbeat.timer.
set -euo pipefail

: "${NTFY_TOPIC:?}"

if systemctl is-active --quiet keyorix-fuzz.service; then
  status="running"
  tags="heartbeat"
else
  status="NOT RUNNING"
  tags="warning,heartbeat"
fi

curl -fsS \
  -H "Title: keyorix fuzz heartbeat: $status" \
  -H "Tags: $tags" \
  -d "keyorix-fuzz.service: $status
$(date -u +%FT%TZ)" \
  "$NTFY_TOPIC" >/dev/null
