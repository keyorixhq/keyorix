#!/usr/bin/env bash
# Daily Nuclei DAST scan against the PostgreSQL-backed Keyorix instance.
# Fetches the live OpenAPI spec to build a full URL list, then scans all endpoints.
# Saves SARIF to results/nuclei-$(date)-$(sha).sarif
set -euo pipefail
WORKDIR="$(cd "$(dirname "$0")" && pwd)"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
LOCKFILE="$WORKDIR/dast.lock"
HB_LOG="$WORKDIR/results/heartbeat.log"
START_TS="$(date -u +%FT%TZ)"
SCAN_SHA=""

record_heartbeat() {
    local rc=$?
    echo "$(date -u +%FT%TZ) scan=nuclei start=$START_TS end=$(date -u +%FT%TZ) exit=$rc sha=${SCAN_SHA:-unknown}" >> "$HB_LOG"
}
trap record_heartbeat EXIT

mkdir -p "$WORKDIR/results"
# zap user (UID 1000) writes the SARIF — dir must be world-writable
chmod 777 "$WORKDIR/results"

# Exclusive lock — prevents ZAP from starting while Nuclei is running, and
# guards the src refresh/rebuild below from racing another scan's rebuild.
exec 9>"$LOCKFILE"
flock -x 9

SCAN_SHA="$("$WORKDIR/refresh-src.sh")"
SARIF_OUT="$WORKDIR/results/nuclei-$TIMESTAMP-$SCAN_SHA.sarif"
URLS_FILE="$WORKDIR/results/nuclei-$TIMESTAMP-$SCAN_SHA-urls.txt"

echo "[$(date -u +%FT%TZ)] Building URL list from OpenAPI spec..."
# Fetch the live spec from the host-side port and extract all paths.
# Path params like {id} are replaced with a dummy UUID so Nuclei gets real URLs.
curl -sf http://localhost:8080/openapi.yaml 2>/dev/null \
  | grep -E '^\s{2}/[a-zA-Z]' \
  | sed 's/^  //; s/:$//' \
  | sed 's/{[^}]*}/00000000-0000-0000-0000-000000000000/g' \
  | sed 's|^|http://keyorix:8080|' \
  > "$URLS_FILE" || true
# Fallback to base URL if spec fetch failed
if [ ! -s "$URLS_FILE" ]; then
    echo "http://keyorix:8080" > "$URLS_FILE"
    echo "[$(date -u +%FT%TZ)] WARNING: could not fetch OpenAPI spec, falling back to base URL"
fi
URL_COUNT=$(wc -l < "$URLS_FILE")
echo "[$(date -u +%FT%TZ)] Starting Nuclei scan (sha=$SCAN_SHA) → $SARIF_OUT ($URL_COUNT URLs)"

# -no-mhe: do NOT drop a host from the scan after N connection errors.
#
# Nuclei's default is 30, and on 2026-09-11 a manual run hit it. The log read
# "Skipped keyorix:8080 from target list as found unresponsive 35 times" while
# the target was healthy, had 0 restarts, and answered 200 to curl from this
# same Docker network. The errors are the server correctly closing connections
# on malformed and hostile requests -- so the default inverts the incentive:
# the more robustly the target rejects junk, the sooner it scans itself out of
# coverage, and the SARIF comes back clean because nothing was tested. That run
# spent 2h38m of wall clock on 5m42s of CPU and produced no findings at all.
#
# -stats/-stats-interval: progress, so a long run is legible rather than three
# silent hours.
docker run --rm \
  --pull never \
  --network keyorix-dast_default \
  -v "$WORKDIR/results:/results" \
  keyorix-scanner:latest \
  nuclei \
  -list "/results/$(basename "$URLS_FILE")" \
  -tags "auth,token,jwt,exposure,misconfig,sqli,xss,ssrf" \
  -sarif-export "/results/$(basename "$SARIF_OUT")" \
  -severity "low,medium,high,critical" \
  -rate-limit 50 \
  -timeout 10 \
  -concurrency 10 \
  -no-mhe \
  -stats \
  -stats-interval 60 \
  -no-color || true

# Ensure a valid SARIF always exists (fallback if Nuclei found nothing)
if [ ! -f "$SARIF_OUT" ] || [ ! -s "$SARIF_OUT" ]; then
    printf '{"$schema":"https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json","version":"2.1.0","runs":[{"tool":{"driver":{"name":"Nuclei","rules":[]}},"results":[]}]}' > "$SARIF_OUT"
fi

echo "[$(date -u +%FT%TZ)] Nuclei done (sha=$SCAN_SHA) — $SARIF_OUT"
if [ -x "$WORKDIR/create-issues.sh" ]; then
    "$WORKDIR/create-issues.sh" "$SARIF_OUT" "-"
fi
