#!/usr/bin/env bash
# Run the SQLite-vs-PostgreSQL differential campaign inside the CT that
# pg-differential-ct.sh provisions. Chunked so a crasher is saved and the campaign
# continues; stops at BUDGET_WORKER_HOURS of fuzz-worker time or the DEADLINE_UTC,
# whichever comes first. Results land in $OUT (default /root/pgdiff-campaign).
#
#   DEADLINE_UTC=2026-11-20T00:00:00Z nohup scripts/fuzzing/pg-differential-campaign.sh > /root/campaign.log 2>&1 &
#
# Requires KEYORIX_TEST_PG_DSN and go on PATH (see pg-differential-ct.sh's last line).
#
# No `set -e`: a chunk that finds a divergence exits non-zero, and that is the case the
# loop records and continues from. Every step whose failure must stop the run checks
# its own status.
set -uo pipefail

REPO="${REPO:-/root/keyorix}"
OUT="${OUT:-/root/pgdiff-campaign}"
WORKERS="${WORKERS:-2}"
CHUNK_MIN="${CHUNK_MIN:-10}"                # fuzztime per chunk, minutes (the doc's campaign 1 used 10)
BUDGET_WORKER_HOURS="${BUDGET_WORKER_HOURS:-20}" # wall time x WORKERS, summed over chunks
DEADLINE_UTC="${DEADLINE_UTC:-}"            # hard wall stop, required: no campaign runs open-ended

if [ -z "$DEADLINE_UTC" ]; then
  echo "DEADLINE_UTC is required (for example DEADLINE_UTC=2026-11-20T00:00:00Z)" >&2
  exit 2
fi
if [ -z "${KEYORIX_TEST_PG_DSN:-}" ]; then
  echo "KEYORIX_TEST_PG_DSN is not set; without it every differential test skips" >&2
  exit 2
fi
deadline_epoch=$(date -u -d "$DEADLINE_UTC" +%s) || { echo "DEADLINE_UTC=$DEADLINE_UTC is not a date" >&2; exit 2; }
CHUNK="${CHUNK_MIN}m"
CHUNK_SECS=$((CHUNK_MIN * 60))
if [ $(($(date -u +%s) + CHUNK_SECS + 120)) -ge "$deadline_epoch" ]; then
  echo "DEADLINE_UTC=$DEADLINE_UTC leaves no room for one ${CHUNK} chunk; nothing to do" >&2
  exit 2
fi

cd "$REPO" || { echo "REPO=$REPO not found" >&2; exit 2; }
mkdir -p "$OUT/crashers" || exit 2
spent_worker_secs=0
chunk=0
echo "campaign start $(date -u +%FT%TZ): chunks of $CHUNK, $WORKERS workers, budget ${BUDGET_WORKER_HOURS} worker-hours, deadline $DEADLINE_UTC, results in $OUT"

# Deterministic tests first (ordering strict, 200 concurrency rounds); recorded, not gating.
echo "deterministic tests -> $OUT/deterministic.log"
{
  echo "== deterministic tests $(date -u +%FT%TZ)"
  DIFF_ORDER_STRICT=1 go test ./internal/storage/store -run 'TestBackendDifferential' -count=1 -v 2>&1 | grep -v -E 'audit index|storage:'
  DIFF_CONC_ROUNDS=200 go test ./internal/storage/store -run 'TestBackendDifferentialConcurrentUnique' -count=1 -v 2>&1 | grep -v -E 'audit index|storage:'
} > "$OUT/deterministic.log" 2>&1

while :; do
  now=$(date -u +%s)
  if [ $((now + CHUNK_SECS + 120)) -ge "$deadline_epoch" ]; then echo "deadline reached"; break; fi
  if [ $((spent_worker_secs / 3600)) -ge "$BUDGET_WORKER_HOURS" ]; then echo "budget reached"; break; fi
  chunk=$((chunk + 1))
  log="$OUT/chunk-$(printf %03d $chunk).log"
  start=$(date -u +%s)
  go test ./internal/storage/store -run '^$' -fuzz '^FuzzStorageBackendDifferentialV2$' \
    -fuzztime "$CHUNK" -parallel "$WORKERS" > "$log" 2>&1
  rc=$?
  end=$(date -u +%s)
  spent_worker_secs=$((spent_worker_secs + (end - start) * WORKERS))
  cpu_usec=$(awk '/^usage_usec/{print $2}' /sys/fs/cgroup/cpu.stat 2>/dev/null || echo 0) # whole CT incl. postgres
  echo "ct_cgroup_cpu_seconds=$((cpu_usec / 1000000))"
  echo "chunk $chunk rc=$rc wall=$((end - start))s total_worker_hours=$(awk "BEGIN{printf \"%.2f\", $spent_worker_secs/3600}") $(grep -E 'execs:' "$log" | tail -1)"
  if [ $rc -ne 0 ]; then
    dest="$OUT/crashers/chunk-$chunk-$(date -u +%H%M%S)"
    mkdir -p "$dest"
    cp "$log" "$dest/"
    if [ -d internal/storage/store/testdata/fuzz/FuzzStorageBackendDifferentialV2 ]; then
      mv internal/storage/store/testdata/fuzz/FuzzStorageBackendDifferentialV2 "$dest/corpus-crashers"
    fi
    echo "CRASHER saved in $dest"
  fi
done
echo "campaign done: chunks=$chunk worker_hours=$(awk "BEGIN{printf \"%.2f\", $spent_worker_secs/3600}")"
