#!/usr/bin/env bash
# Run the SQLite-vs-PostgreSQL differential campaign inside the CT that
# pg-differential-ct.sh provisions. Chunked so a crasher is saved and the campaign
# continues; stops at BUDGET_CPU_HOURS of fuzz-worker time or the DEADLINE_UTC,
# whichever comes first. Results land in $OUT (default /root/pgdiff-campaign).
#
#   nohup scripts/fuzzing/pg-differential-campaign.sh > /root/campaign.log 2>&1 &
#
# Requires KEYORIX_TEST_PG_DSN and go on PATH (see pg-differential-ct.sh's last line).
set -uo pipefail

REPO="${REPO:-/root/keyorix}"
OUT="${OUT:-/root/pgdiff-campaign}"
WORKERS="${WORKERS:-2}"
CHUNK="${CHUNK:-30m}"                       # fuzztime per chunk
CHUNK_SECS="${CHUNK_SECS:-1800}"
BUDGET_CPU_HOURS="${BUDGET_CPU_HOURS:-20}"
DEADLINE_UTC="${DEADLINE_UTC:-2026-11-10T00:00:00Z}"

mkdir -p "$OUT/crashers"
cd "$REPO"
deadline_epoch=$(date -u -d "$DEADLINE_UTC" +%s)
spent_worker_secs=0
chunk=0

# Deterministic tests first (ordering strict, 200 concurrency rounds); recorded, not gating.
{
  echo "== deterministic tests $(date -u +%FT%TZ)"
  DIFF_ORDER_STRICT=1 go test ./internal/storage/store -run 'TestBackendDifferential' -count=1 -v 2>&1 | grep -v -E 'audit index|storage:'
  DIFF_CONC_ROUNDS=200 go test ./internal/storage/store -run 'TestBackendDifferentialConcurrentUnique' -count=1 -v 2>&1 | grep -v -E 'audit index|storage:'
} > "$OUT/deterministic.log" 2>&1

while :; do
  now=$(date -u +%s)
  if [ $((now + CHUNK_SECS + 120)) -ge "$deadline_epoch" ]; then echo "deadline reached"; break; fi
  if [ $((spent_worker_secs / 3600)) -ge "$BUDGET_CPU_HOURS" ]; then echo "budget reached"; break; fi
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
