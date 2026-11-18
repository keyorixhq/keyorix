#!/usr/bin/env bash
# scripts/demo/native-down.sh [--wipe] — stop the server started by native-up.sh.
# --wipe also deletes .demo-native/ (config, keys, SQLite file, state, logs).
#
# A server that cannot be stopped is never reported as stopped: one line names its pid,
# the pid file and the state dir are KEPT (an orphan still holds keyorix.db.server.lock,
# and wiping the files under it would hide it), and the exit status is 1. Stop the pid by
# hand, then run this again. KEYORIX_DEMO_STOP_WAIT (default 15) is how many seconds a
# server gets to exit after SIGTERM.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
WORK="${KEYORIX_DEMO_DIR:-$REPO_ROOT/.demo-native}"
STOP_WAIT="${KEYORIX_DEMO_STOP_WAIT:-15}"
failed=0

# alive PID: the process exists, even when we may not signal it (kill -0 says "not
# permitted" for a process of another user; ps still sees it).
alive() { kill -0 "$1" 2>/dev/null || ps -p "$1" >/dev/null 2>&1; }

if [ -f "$WORK/server.pid" ]; then
  pid="$(cat "$WORK/server.pid")"
  if ! [[ "$pid" =~ ^[0-9]+$ ]]; then
    echo "could not stop the server: $WORK/server.pid does not hold a pid (\"$pid\"); find the server process by hand, then remove that file" >&2
    failed=1
  elif ! alive "$pid"; then
    echo "server pid $pid was not running (stale pid file removed)"
    rm -f "$WORK/server.pid"
  elif ! kill "$pid" 2>/dev/null; then
    echo "could not stop server pid $pid: kill was refused (another user's process?); stop it by hand: kill $pid" >&2
    failed=1
  else
    waited=0
    while alive "$pid" && [ "$waited" -lt "$STOP_WAIT" ]; do
      sleep 1
      waited=$((waited + 1))
    done
    if alive "$pid"; then
      echo "could not stop server pid $pid: still running ${STOP_WAIT}s after SIGTERM; it keeps keyorix.db.server.lock, stop it by hand: kill -9 $pid" >&2
      failed=1
    else
      echo "stopped server pid $pid"
      rm -f "$WORK/server.pid"
    fi
  fi
fi

if [ "$failed" -ne 0 ]; then
  echo "native-down: server still running; $WORK left untouched (no wipe). Stop it, then re-run scripts/demo/native-down.sh" >&2
  exit 1
fi
if [ "${1:-}" = "--wipe" ]; then
  rm -rf "$WORK"
  echo "wiped $WORK"
fi
