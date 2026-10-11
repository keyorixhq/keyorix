#!/usr/bin/env bash
# scripts/demo/down.sh — stop the one-command Keyorix demo (scripts/demo/up.sh).
#
# By default, stops and removes the container but KEEPS the data volume and
# local state file, so a later up.sh resumes the same seeded demo instantly.
# Pass --wipe to also delete the data volume and state file for a genuinely
# fresh next run.
#
# Usage: scripts/demo/down.sh [--wipe]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

CONTAINER_NAME="${KEYORIX_DEMO_CONTAINER:-keyorix-demo}"
VOLUME_NAME="${KEYORIX_DEMO_VOLUME:-keyorix-demo-data}"
STATE_FILE="$REPO_ROOT/.demo-2-state"

WIPE=false
for arg in "$@"; do
  case "$arg" in
    --wipe) WIPE=true ;;
    *) echo "unknown argument: $arg" >&2; exit 1 ;;
  esac
done

command -v docker >/dev/null 2>&1 || { echo "docker is required" >&2; exit 1; }

if docker ps -a --format '{{.Names}}' | grep -qx "$CONTAINER_NAME"; then
  docker rm -f "$CONTAINER_NAME" >/dev/null
  echo "Stopped and removed container $CONTAINER_NAME"
else
  echo "Container $CONTAINER_NAME is not present"
fi

if [ "$WIPE" = true ]; then
  docker volume rm "$VOLUME_NAME" >/dev/null 2>&1 || true
  rm -f "$STATE_FILE"
  rm -rf "$REPO_ROOT/.demo-2-cli-home"
  echo "Wiped data volume $VOLUME_NAME and local state"
else
  echo "Data volume $VOLUME_NAME kept — scripts/demo/up.sh will resume this demo. Pass --wipe to delete it."
fi
