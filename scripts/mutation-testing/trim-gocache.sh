#!/usr/bin/env bash
# Threshold-triggered GOCACHE trim, run periodically (see
# systemd/keyorix-mutation-cache-trim.timer) independent of
# run-mutation.sh's own lifecycle.
#
# Mutation testing is inherently cache-hostile: gremlins recompiles a new,
# distinct source variant per mutant, and Go's build cache is content-
# addressed, so nearly every mutant produces a brand-new cache entry with
# little reuse. Go's own automatic cache GC is age-based (days), not
# size-based, so it doesn't kick in fast enough for a workload that can
# generate double-digit GiB within hours -- this filled the container's
# disk to 100% once already.
#
# Deliberately NOT `go clean -cache` (a full wipe): that needs an exclusive
# lock on the whole cache, so running it unconditionally on a fixed
# interval would frequently collide with gremlins' own in-flight compiles
# over a run lasting hours, stalling them for no reason on cycles where
# there was nothing worth reclaiming anyway. Deleting the OLDEST files
# individually is much less likely to touch anything actively in use (a
# live compile's own cache writes are, by definition, the newest files),
# and this script only touches disk at all when actually over threshold --
# most invocations of this timer should be a no-op.
set -euo pipefail

# `find` below tries to restore its starting cwd when it's done traversing;
# if that cwd isn't readable by this script's caller (e.g. invoked via
# `sudo -u mutation` from a root shell sitting in /root), find exits
# non-zero purely over that, which -- combined with `set -e` -- aborts the
# whole script before it ever reaches the deletion loop. systemd's own
# invocation already defaults WorkingDirectory to `/` (always accessible),
# but cd there explicitly so this script is robust to any caller, not just
# the one it's currently wired to.
cd /

: "${GOCACHE:?set GOCACHE to the mutation-testing build cache dir}"
: "${TRIM_DISK_THRESHOLD_PCT:=85}" # trigger trimming at this usage%
: "${TRIM_DISK_TARGET_PCT:=65}"    # trim until usage drops back to this%
: "${TRIM_CHECK_EVERY_N_FILES:=200}" # how often to re-check usage while trimming

usage_pct() {
  df --output=pcent "$GOCACHE" | tail -1 | tr -dc '0-9'
}

current="$(usage_pct)"
if [ "$current" -lt "$TRIM_DISK_THRESHOLD_PCT" ]; then
  echo "$(date -u +%FT%TZ) disk usage ${current}% below threshold ${TRIM_DISK_THRESHOLD_PCT}%, nothing to do"
  exit 0
fi

echo "$(date -u +%FT%TZ) disk usage ${current}% >= threshold ${TRIM_DISK_THRESHOLD_PCT}%, trimming oldest GOCACHE entries toward ${TRIM_DISK_TARGET_PCT}%..."

# Sorted-oldest-first file list goes to a real temp file, not a `| while
# read` pipe -- a pipe's right-hand side runs in a subshell in bash, so
# `exit 0` inside the loop below would only end that subshell, silently
# falling through to the "exhausted" message afterward instead of actually
# stopping the script once the target is reached.
file_list="$(mktemp)"
trap 'rm -f "$file_list"' EXIT
find "$GOCACHE" -type f -printf '%T@ %p\n' | sort -n | cut -d' ' -f2- > "$file_list"

deleted=0
checked=0
while IFS= read -r path; do
  rm -f -- "$path"
  deleted=$((deleted + 1))
  checked=$((checked + 1))
  if [ "$checked" -ge "$TRIM_CHECK_EVERY_N_FILES" ]; then
    checked=0
    current="$(usage_pct)"
    if [ "$current" -lt "$TRIM_DISK_TARGET_PCT" ]; then
      echo "$(date -u +%FT%TZ) usage back to ${current}% after deleting $deleted files, target reached"
      exit 0
    fi
  fi
done < "$file_list"

echo "$(date -u +%FT%TZ) exhausted all cache files (deleted $deleted), usage still $(usage_pct)%"
