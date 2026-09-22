#!/usr/bin/env bash
# ZAP full scan — spider-based active scan covering the entire app surface
# (web UI, static assets, routes not in the OpenAPI spec).
# Run weekly to complement the OpenAPI-driven API scan.
# HTML + JSON report saved to results/zap-full-$(date)-$(sha).*
set -euo pipefail
WORKDIR="$(cd "$(dirname "$0")" && pwd)"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
LOCKFILE="$WORKDIR/dast.lock"
HB_LOG="$WORKDIR/results/heartbeat.log"
START_TS="$(date -u +%FT%TZ)"
SCAN_SHA=""

record_heartbeat() {
    local rc=$?
    echo "$(date -u +%FT%TZ) scan=zap-full start=$START_TS end=$(date -u +%FT%TZ) exit=$rc sha=${SCAN_SHA:-unknown}" >> "$HB_LOG"
}
trap record_heartbeat EXIT

mkdir -p "$WORKDIR/results"
chmod 777 "$WORKDIR/results"  # zap user (UID 1000) must be able to write here

# Exclusive lock — waits for any running Nuclei or API scan to finish first,
# and guards the src refresh/rebuild below from racing another scan's rebuild.
exec 9>"$LOCKFILE"
flock -x 9

SCAN_SHA="$("$WORKDIR/refresh-src.sh")"
REPORT="$WORKDIR/results/zap-full-$TIMESTAMP-$SCAN_SHA.html"

echo "[$(date -u +%FT%TZ)] Starting ZAP full scan (spider, sha=$SCAN_SHA) → $REPORT"
# zap-full-scan.py spiders the entire app, not just OpenAPI-declared endpoints.
# -I  treat informational findings as pass (don't fail the script).
docker run --rm \
  --pull never \
  --network keyorix-dast_default \
  -v "$WORKDIR/results:/zap/wrk" \
  keyorix-scanner:latest \
  zap-full-scan.py \
  -t http://keyorix:8080 \
  -r "$(basename "$REPORT")" \
  -J "zap-full-$TIMESTAMP-$SCAN_SHA.json" \
  -I || true

echo "[$(date -u +%FT%TZ)] ZAP full scan done (sha=$SCAN_SHA) — $REPORT"
if [ -x "$WORKDIR/create-issues.sh" ]; then
    "$WORKDIR/create-issues.sh" "-" "$WORKDIR/results/zap-full-$TIMESTAMP-$SCAN_SHA.json"
fi
