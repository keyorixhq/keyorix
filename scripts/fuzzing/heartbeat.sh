#!/usr/bin/env bash
# Sends one daily ntfy.sh ping so the box's silence itself is informative: if
# the heartbeat stops arriving, keyorix-fuzz.service died (or the box did)
# without you having to check in manually. Run via keyorix-fuzz-heartbeat.timer.
set -euo pipefail

: "${NTFY_TOPIC:?}"

# Scratch file for curl's --config (-K) file, used below to keep the
# NTFY_TOPIC URL — the bearer secret protecting the ntfy.sh channel; see
# config.env.example — out of curl's argv, where `ps auxww`/
# `/proc/<pid>/cmdline` would expose it to any other local account for the
# life of the curl call.
ntfy_curl_cfg=""
cleanup_ntfy_curl_cfg() {
  [[ -n "$ntfy_curl_cfg" ]] && rm -f "$ntfy_curl_cfg"
}
trap cleanup_ntfy_curl_cfg EXIT

if systemctl is-active --quiet keyorix-fuzz.service; then
  status="running"
  tags="heartbeat"
else
  status="NOT RUNNING"
  tags="warning,heartbeat"
fi

ntfy_curl_cfg="$(mktemp)"
chmod 600 "$ntfy_curl_cfg"
printf 'url = "%s"\n' "$NTFY_TOPIC" >"$ntfy_curl_cfg"

curl -fsS \
  -K "$ntfy_curl_cfg" \
  -H "Title: keyorix fuzz heartbeat: $status" \
  -H "Tags: $tags" \
  -d "keyorix-fuzz.service: $status
$(date -u +%FT%TZ)" \
  >/dev/null
