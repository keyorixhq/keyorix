#!/usr/bin/env bash
# ZAP API scan — OpenAPI-driven active scan against all keyorix endpoints,
# unauthenticated (anonymous baseline). See scan-zap-auth.sh for the
# regular-user and admin authenticated passes.
# HTML + JSON report saved to results/zap-$(date)-$(sha).*
set -euo pipefail
WORKDIR="$(cd "$(dirname "$0")" && pwd)"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
LOCKFILE="$WORKDIR/dast.lock"
HB_LOG="$WORKDIR/results/heartbeat.log"
START_TS="$(date -u +%FT%TZ)"
SCAN_SHA=""

record_heartbeat() {
    local rc=$?
    echo "$(date -u +%FT%TZ) scan=zap-api start=$START_TS end=$(date -u +%FT%TZ) exit=$rc sha=${SCAN_SHA:-unknown}" >> "$HB_LOG"
}
trap record_heartbeat EXIT

mkdir -p "$WORKDIR/results"
chmod 777 "$WORKDIR/results"  # zap user (UID 1000) must be able to write here

# Exclusive lock — waits for any running Nuclei scan to finish first, and
# guards the src refresh/rebuild below from racing another scan's rebuild.
exec 9>"$LOCKFILE"
flock -x 9

SCAN_SHA="$("$WORKDIR/refresh-src.sh")"
REPORT="$WORKDIR/results/zap-$TIMESTAMP-$SCAN_SHA.html"

echo "[$(date -u +%FT%TZ)] Starting ZAP API scan (OpenAPI-driven, anonymous, sha=$SCAN_SHA) → $REPORT"
# zap-api-scan.py reads the live OpenAPI spec and tests every declared endpoint.
# -f openapi  tells ZAP the spec format.
# -I          treat informational findings as pass (don't fail the script).
#
# No --hook: the stock "Unexpected Content Types" rule (100001) used to be
# scoped away from the SPA shell via a ZAP-native alertFilter in
# zap-api-scope-hook.py (#1245, #1249). That's retired -- the same
# suppression now lives in accepted-exceptions.yaml (plugin_id 100001),
# applied post-scan by create-issues.sh, so there is one suppression
# mechanism instead of two. The raw alert now reaches the JSON report
# unsuppressed; create-issues.sh is what decides not to file it.
docker run --rm \
  --pull never \
  --network keyorix-dast_default \
  -v "$WORKDIR/results:/zap/wrk" \
  keyorix-scanner:latest \
  zap-api-scan.py \
  -t http://keyorix:8080/openapi.yaml \
  -f openapi \
  -r "$(basename "$REPORT")" \
  -J "zap-$TIMESTAMP-$SCAN_SHA.json" \
  -I || true

echo "[$(date -u +%FT%TZ)] ZAP done (sha=$SCAN_SHA) — $REPORT"
if [ -x "$WORKDIR/create-issues.sh" ]; then
    "$WORKDIR/create-issues.sh" "-" "$WORKDIR/results/zap-$TIMESTAMP-$SCAN_SHA.json"
fi
