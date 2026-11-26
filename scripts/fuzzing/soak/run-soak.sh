#!/usr/bin/env bash
# run-soak.sh: run the server/soak resource-growth harness (SOAK-1) and keep its outputs.
#
#   scripts/fuzzing/soak/run-soak.sh smoke                      # about a minute, SQLite
#   scripts/fuzzing/soak/run-soak.sh long                       # 30 minutes, SQLite
#   scripts/fuzzing/soak/run-soak.sh long 2h 4                  # duration, workers
#   KEYORIX_TEST_PG_DSN=postgres://... scripts/fuzzing/soak/run-soak.sh long   # PostgreSQL
#
# Environment: KEYORIX_SOAK_SEED (default 1), SOAK_OUT (output directory, default
# .scratch/soak/<UTC timestamp>-<mode>-<backend>), KEYORIX_SOAK_HEAPPROFILE is set
# to <out>/heap so the baseline and final heap profiles are kept next to the series.
#
# Writes <out>/series.tsv (every sample), <out>/run.log (the go test -v output with
# the SOAK verdict lines) and <out>/verdicts.txt (only the verdict lines). Exits with
# go test's status: non-zero when a hard oracle failed or a mix kind never ran.
set -eu

mode="${1:-}"
case "$mode" in
  smoke|long) ;;
  *) echo "usage: $0 smoke|long [duration] [workers]" >&2; exit 2 ;;
esac
duration="${2:-30m}"
workers="${3:-4}"

if [ ! -d server/soak ]; then
  echo "run-soak.sh: run from the repository root (server/soak not found)" >&2
  exit 2
fi

backend="sqlite"
if [ -n "${KEYORIX_TEST_PG_DSN:-}" ]; then backend="postgres"; fi
out="${SOAK_OUT:-.scratch/soak/$(date -u +%Y%m%dT%H%M%SZ)-${mode}-${backend}}"
mkdir -p "$out"
out="$(cd "$out" && pwd)" # go test runs in server/soak, so the paths must be absolute

log() { echo "$(date -u +%FT%TZ) run-soak: $*" >&2; }
log "mode=$mode backend=$backend duration=$duration workers=$workers out=$out"
log "KEYORIX_TEST_PG_DSN is $([ -n "${KEYORIX_TEST_PG_DSN:-}" ] && echo set || echo unset)"

export KEYORIX_SOAK="$mode"
export KEYORIX_SOAK_SERIES="$out/series.tsv"
export KEYORIX_SOAK_HEAPPROFILE="$out/heap"
if [ "$mode" = "long" ]; then
  export KEYORIX_SOAK_DURATION="$duration"
  export KEYORIX_SOAK_WORKERS="$workers"
fi

# Smoke: 15 minutes is generous. Long: no go test deadline (-timeout 0), because
# every phase of the run is time-bounded by the harness itself (the load by
# KEYORIX_SOAK_DURATION, the drain by its own deadline, each client request by a
# 30 s timeout), so a hang cannot outlive them by more than a few minutes.
timeout="15m"
if [ "$mode" = "long" ]; then timeout="0"; fi
log "go test timeout=$timeout"

keepawake=""
if command -v caffeinate >/dev/null 2>&1; then keepawake="caffeinate -i"; fi
rc=0
$keepawake go test ./server/soak -run 'TestSoak$' -count=1 -v -timeout "$timeout" >"$out/run.log" 2>&1 || rc=$?
grep -E "SOAK (PASS|FAIL|WARN|SKIP|INFO) |SOAK done|SOAK mix|SOAK baseline" "$out/run.log" >"$out/verdicts.txt" || true
log "go test exit=$rc; series: $out/series.tsv; verdicts: $out/verdicts.txt"
cat "$out/verdicts.txt"
if [ "$rc" -ne 0 ]; then
  log "FAIL: see $out/run.log (a hard oracle failed, a mix kind never ran, or the run did not finish)"
fi
exit "$rc"
