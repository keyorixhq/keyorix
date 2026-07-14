#!/usr/bin/env bash
# Sends one ntfy.sh push notification for a fuzz target's failure, deduped so
# a target that keeps re-failing against an already-saved crasher on every
# subsequent rotation cycle (expected Go fuzz behaviour — the failing input is
# replayed as part of the seed corpus on every future run until it's fixed)
# does not re-alert every cycle.
set -euo pipefail

FUNC="${1:?fuzz func name}"
PKG="${2:?package path}"
LOGFILE="${3:?path to the log file for this run}"

: "${NTFY_TOPIC:?set NTFY_TOPIC to your ntfy.sh topic URL, e.g. https://ntfy.sh/some-long-random-topic-name}"
: "${NOTIFIED_STATE_DIR:?}"

fail_line="$(grep -m1 -E 'FAIL|panic:' "$LOGFILE" || true)"
fail_hash="$(printf '%s' "${fail_line:-unknown}" | sha256sum | cut -c1-16)"
marker="$NOTIFIED_STATE_DIR/notified-$FUNC-$fail_hash"

if [[ -f "$marker" ]]; then
  exit 0 # already alerted for this exact failure
fi

summary="$(grep -m8 -E 'FAIL|panic:|--- FAIL|Fatalf|\.go:[0-9]+' "$LOGFILE" | head -c 1500 || true)"

curl -fsS \
  -H "Title: keyorix fuzz: $FUNC crashed" \
  -H "Priority: high" \
  -H "Tags: rotating_light" \
  -d "$PKG :: $FUNC

${summary:-see log on the fuzz box}

Failing input pushed to the fuzz-corpus branch." \
  "$NTFY_TOPIC" >/dev/null

touch "$marker"
