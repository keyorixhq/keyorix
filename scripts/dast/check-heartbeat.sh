#!/usr/bin/env bash
# check-heartbeat.sh — daily check: DAST-ALERT if no successful scan run
# landed in results/heartbeat.log within the last 48h. Run once a day from
# cron; this is what would have caught the 2026-08-08 -> 09-11 CT-down
# outage the moment CT 221 came back up, instead of it being found by
# accident five weeks later.
#
# Note the limit this implies: this check itself only runs if cron on CT 221
# is running, i.e. if the CT is up. It cannot notice a fully-stopped CT in
# real time — it fires the alert on the FIRST run after the CT (and its own
# cron) comes back, not during the outage. Real-time detection of "the whole
# CT went away" needs an external dead-man's-switch on a different host
# (e.g. pve01 itself, or ntfy's own dead-man's-switch feature) — out of
# scope here, flagged for follow-up once NTFY_TOPIC exists.
set -euo pipefail
WORKDIR="$(cd "$(dirname "$0")" && pwd)"
HB_LOG="$WORKDIR/results/heartbeat.log"

if [ -f "$WORKDIR/.env" ]; then
    # shellcheck source=/dev/null
    set -a; . "$WORKDIR/.env"; set +a
fi
# shellcheck source=/dev/null
. "$WORKDIR/lib-alert.sh"

if [ ! -f "$HB_LOG" ]; then
    dast_alert "heartbeat.log does not exist — no scan has ever recorded a run"
    exit 1
fi

LAST_SUCCESS_LINE=$(grep ' exit=0 ' "$HB_LOG" | tail -1 || true)
if [ -z "$LAST_SUCCESS_LINE" ]; then
    dast_alert "no successful DAST run found anywhere in heartbeat.log"
    exit 1
fi

LAST_SUCCESS_END=$(echo "$LAST_SUCCESS_LINE" | grep -oE 'end=[^ ]+' | cut -d= -f2)
LAST_SUCCESS_EPOCH=$(date -u -d "$LAST_SUCCESS_END" +%s 2>/dev/null || echo 0)
NOW=$(date -u +%s)
AGE=$(( NOW - LAST_SUCCESS_EPOCH ))

if [ "$AGE" -gt 172800 ]; then
    dast_alert "no successful DAST run in $((AGE/3600))h (last success: $LAST_SUCCESS_END) — $LAST_SUCCESS_LINE"
    exit 1
fi

echo "OK: last successful run $LAST_SUCCESS_END ($((AGE/3600))h ago)"
