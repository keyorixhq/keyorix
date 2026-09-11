#!/usr/bin/env bash
# Continuous fuzz-rotation runner. Intended to run as a long-lived systemd
# service (see systemd/keyorix-fuzz.service) on a dedicated box (e.g. a
# Proxmox LXC) separate from CI, since deep fuzzing wants hours of continuous
# runtime that a CI job's budget can't afford.
#
# Cycles through every target in targets.conf, each for its configured
# `go test -fuzz -fuzztime`, forever. Refreshes the repo's main branch before
# EACH target (not just once per full cycle) so fuzzing stays close to the
# current codebase. After each target run, pushes any new corpus files
# (crashers) to the fuzz-corpus branch via sync-corpus.sh, and — on a crash —
# sends exactly one notification per unique failure via notify-on-crash.sh.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

: "${KEYORIX_REPO:?set KEYORIX_REPO to the path of the main keyorix git clone}"
: "${NOTIFIED_STATE_DIR:=$SCRIPT_DIR/.state}"
: "${REMOTE:=origin}"
# How many times to retry a failed fetch, and the base backoff between tries.
: "${FETCH_RETRIES:=5}"
: "${FETCH_BACKOFF:=10}"
mkdir -p "$NOTIFIED_STATE_DIR"

cd "$KEYORIX_REPO"

# Per-run logs under $FUZZ_LOG_DIR (default $NOTIFIED_STATE_DIR/logs), gzipped
# and never overwritten, and a GitHub tracking-issue copy of every failing
# run's log — see the header of runlog.sh for why. Sourced once, at startup.
# shellcheck source=scripts/fuzzing/runlog.sh
source "$SCRIPT_DIR/runlog.sh"

log() { echo "=== $(date -u +%FT%TZ) $* ==="; }

# sync_main refreshes the fuzzing checkout to the latest origin/main, but a
# failed fetch must NEVER take the service down. Under the old code a single
# `git fetch` failure (a DNS blip, a brief network drop — routine on the vCD
# tenant) exited the script under `set -e`; systemd's Restart=always then
# restarted it from the TOP of targets.conf. With per-target fetches that meant
# a flaky network pinned the rig on target #1 forever: confirmed live, only
# FuzzCombineKEK (the first target) was fuzzed for two weeks while every other
# target went untouched. So: retry with backoff, and if the fetch still fails,
# log it and fuzz the checkout we already have (stale main is far better than no
# fuzzing) rather than exiting.
sync_main() {
  local i
  for ((i = 1; i <= FETCH_RETRIES; i++)); do
    if git fetch "$REMOTE" main --quiet 2>/dev/null; then
      git checkout main --quiet 2>/dev/null || true
      git reset --hard "$REMOTE/main" --quiet
      return 0
    fi
    log "fetch of $REMOTE/main failed (attempt $i/$FETCH_RETRIES) — retrying in $((FETCH_BACKOFF * i))s"
    sleep "$((FETCH_BACKOFF * i))"
  done
  log "fetch still failing after $FETCH_RETRIES attempts — fuzzing the existing checkout ($(git rev-parse --short HEAD 2>/dev/null || echo unknown)) instead of exiting"
  return 0
}

# Load the target list once into an array so a restart can resume where it left
# off. targets.conf lines are pkg|func|duration; blanks and #-comments skipped.
targets=()
while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  case "$line" in \#*) continue ;; esac
  targets+=("$line")
done <"$SCRIPT_DIR/targets.conf"
if [[ ${#targets[@]} -eq 0 ]]; then
  echo "run-rotation: no targets in $SCRIPT_DIR/targets.conf" >&2
  exit 1
fi

# Resume from the next target after the last one we started, so a restart
# (reboot, OOM, deploy) does not always redo target #1 — the failure mode that,
# combined with the fetch-fatal bug above, starved every target but the first.
pos_file="$NOTIFIED_STATE_DIR/rotation-pos"
start=0
if [[ -r "$pos_file" ]]; then
  saved=$(cat "$pos_file" 2>/dev/null || echo 0)
  [[ "$saved" =~ ^[0-9]+$ ]] && start=$((saved % ${#targets[@]}))
fi

# Flush failing-run logs a previous process queued but could not post.
runlog_post_pending

i=$start
while true; do
  entry="${targets[$i]}"
  IFS='|' read -r pkg func duration <<<"$entry"
  # Persist the NEXT index before running, so a mid-run restart resumes on the
  # following target rather than repeating this one forever if it is the crasher.
  echo "$(((i + 1) % ${#targets[@]}))" >"$pos_file"

  log "refreshing main"
  sync_main

  log "fuzzing $func in ./$pkg for $duration"
  runlog_start "$func" "./$pkg" "$duration"

  set +e
  go test "./$pkg" -run="^${func}\$" -fuzz="^${func}\$" -fuzztime="$duration" \
    >>"$RUNLOG" 2>&1
  status=$?
  set -e

  # Seal and queue the log BEFORE sync-corpus.sh and notify-on-crash.sh, which
  # talk to GitHub under `set -e`: if either takes the loop down, the log must
  # already be safe (and queued).
  runlog_finish "$status"

  # sync-corpus.sh pushes to GitHub and notify-on-crash.sh calls the gh API;
  # either can fail transiently (network, auth, a racing push). Never let that
  # take the rotation down — the whole point of this runner is to keep fuzzing.
  # Both are also invoked with `|| true`-style guards so a non-zero exit is
  # logged, not fatal under `set -e`.
  "$SCRIPT_DIR/sync-corpus.sh" "$func" "$status" || log "sync-corpus failed for $func (non-fatal) — reproducer, if any, stays in the checkout for the next run"

  if [[ "$status" -ne 0 ]]; then
    log "$func exited $status — log: $RUNLOG_FINAL"
    # notify-on-crash.sh opens a PR + alerts ONLY when a real reproducer landed
    # on the fuzz-corpus branch; a setup/build/network failure or an
    # end-of-fuzztime timeout produces none and is left as a quiet logged entry
    # on the tracking issue, not a crash alert.
    "$SCRIPT_DIR/notify-on-crash.sh" "$func" "$pkg" "$RUNLOG_FINAL" || log "notify-on-crash failed for $func (non-fatal)"
  fi
  runlog_post_pending

  i=$(((i + 1) % ${#targets[@]}))
  [[ "$i" -eq 0 ]] && log "rotation cycle complete, looping"
done
