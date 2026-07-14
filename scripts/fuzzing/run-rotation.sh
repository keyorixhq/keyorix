#!/usr/bin/env bash
# Continuous fuzz-rotation runner. Intended to run as a long-lived systemd
# service (see systemd/keyorix-fuzz.service) on a dedicated box (e.g. a
# Proxmox LXC) separate from CI, since deep fuzzing wants hours of continuous
# runtime that a CI job's budget can't afford.
#
# Cycles through every target in targets.conf, each for its configured
# `go test -fuzz -fuzztime`, forever. Pulls the repo's main branch before EACH
# target (not just once per full cycle) so fuzzing stays close to the current
# codebase — this repo merges dozens of commits a day, so a once-per-cycle
# pull (the original design) could leave a target fuzzing code that was
# already half a rotation cycle stale by the time it ran. Per-target pulls
# cost a few seconds of git overhead against hours of fuzzing time, in
# exchange for freshness bounded by the PRECEDING target's own duration
# instead of the whole cycle's. After each target run, pushes any new corpus
# files (crashers or coverage-expanding "interesting" inputs) to the
# fuzz-corpus branch via sync-corpus.sh, and — on a crash — sends exactly one
# notification per unique failure via notify-on-crash.sh (a target that keeps
# re-failing against an already-saved crasher on every subsequent cycle does
# not re-alert).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

: "${KEYORIX_REPO:?set KEYORIX_REPO to the path of the main keyorix git clone}"
: "${NOTIFIED_STATE_DIR:=$SCRIPT_DIR/.state}"
mkdir -p "$NOTIFIED_STATE_DIR"

cd "$KEYORIX_REPO"

while true; do
  while IFS='|' read -r pkg func duration; do
    [[ -z "$pkg" ]] && continue
    case "$pkg" in \#*) continue ;; esac

    echo "=== $(date -u +%FT%TZ) pulling latest main ==="
    git fetch origin main --quiet
    git checkout main --quiet
    git reset --hard origin/main --quiet

    echo "=== $(date -u +%FT%TZ) fuzzing $func in ./$pkg for $duration ==="
    logfile="$NOTIFIED_STATE_DIR/last-$func.log"

    set +e
    go test "./$pkg" -run="^${func}\$" -fuzz="^${func}\$" -fuzztime="$duration" \
      >"$logfile" 2>&1
    status=$?
    set -e

    "$SCRIPT_DIR/sync-corpus.sh" "$func" "$status"

    if [[ "$status" -ne 0 ]]; then
      echo "=== $(date -u +%FT%TZ) $func FAILED (exit $status) ==="
      "$SCRIPT_DIR/notify-on-crash.sh" "$func" "$pkg" "$logfile"
    fi
  done <"$SCRIPT_DIR/targets.conf"

  echo "=== $(date -u +%FT%TZ) rotation cycle complete, looping ==="
done
