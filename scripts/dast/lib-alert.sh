#!/usr/bin/env bash
# lib-alert.sh — shared DAST-ALERT emission. Source this, then call:
#   dast_alert "message"
#
# Always prints "DAST-ALERT: message" to stdout — the caller's own cron
# redirection (>> results/cron.log 2>&1) is what makes this land in
# cron.log; this function does not write the log file itself.
#
# Additionally pushes to ntfy when NTFY_TOPIC is set (in .env) — until a
# topic exists this is a silent no-op. Once NTFY_TOPIC is set, every
# DAST-ALERT (token failure, stale checkout, heartbeat gap) starts pushing
# with no further script changes needed. Mirrors
# scripts/mutation-testing/notify-summary.sh's pattern: the topic URL (which
# doubles as the ntfy auth secret) goes into a curl -K config file, never
# into argv, so it never shows up in `ps`.
dast_alert() {
    local msg="$1"
    echo "DAST-ALERT: $msg"
    if [ -n "${NTFY_TOPIC:-}" ]; then
        local cfg
        cfg="$(mktemp)"
        chmod 600 "$cfg"
        printf 'url = "%s"\n' "$NTFY_TOPIC" > "$cfg"
        curl -fsS -K "$cfg" -H "Title: Keyorix DAST alert" -H "Priority: high" -H "Tags: rotating_light" \
            -d "$msg" >/dev/null 2>&1 || echo "DAST-ALERT: (also) failed to push to ntfy"
        rm -f "$cfg"
    fi
}
