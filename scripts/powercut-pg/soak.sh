#!/usr/bin/env bash
# Soak driver for scripts/powercut-pg/run-dmflakey-pg.sh: run cut-and-recover
# cycles across every cut-timing shape for a wall-clock budget, accumulating
# total time actually spent in power-cut cycles and flagging any strict-mode
# failure (a lost acknowledged commit, a torn write, or a recovery failure) as a
# candidate durability FINDING.
#
#   sudo scripts/powercut-pg/soak.sh --minutes 20 [--bin ./powercut-pg] [--log FILE]
#
# Rotation per round (one round ~ a minute of cut cycles):
#   - wal        strict  : in-flight cut mid WAL stream           (oracle, must pass)
#   - checkpoint strict  : CHECKPOINT fired at the cut instant    (oracle, must pass)
#   - clean      strict  : drain + CHECKPOINT then cut            (sanity, must pass)
#   - wal        standard : relaxed-durability differential CONTROL. synchronous_commit
#                           is off, so acknowledged commits may be lost on the cut; a
#                           RESULT=FAIL here is EXPECTED (ADR-112), proving the oracle
#                           can go red — it is NOT a finding.
#
# The "real fault-injection run time" the task counts is the sum of each
# run-dmflakey-pg.sh invocation's wall time, logged per round and totalled at the
# end. Append-only to --log so repeated invocations accumulate across batches.
set -euo pipefail

MINUTES=20
BIN=""
LOG=/var/tmp/powercut-pg/soak-results.tsv
N_INFLIGHT=200000
N_CLEAN=2000
RUN_SECS=4

while [ $# -gt 0 ]; do
  case "$1" in
    --minutes) MINUTES=$2; shift 2 ;;
    --bin) BIN=$2; shift 2 ;;
    --log) LOG=$2; shift 2 ;;
    --n-inflight) N_INFLIGHT=$2; shift 2 ;;
    --n-clean) N_CLEAN=$2; shift 2 ;;
    --run-secs) RUN_SECS=$2; shift 2 ;;
    *) echo "unknown arg $1" >&2; exit 2 ;;
  esac
done

HERE=$(cd "$(dirname "$0")" && pwd)
RUNNER=$HERE/run-dmflakey-pg.sh
mkdir -p "$(dirname "$LOG")"

if [ -z "$BIN" ]; then
  REPO=$(cd "$HERE/../.." && pwd)
  BIN=/var/tmp/powercut-pg/powercut-pg.bin
  echo "building powercut-pg -> $BIN"
  ( cd "$REPO" && go build -o "$BIN" ./scripts/powercut-pg )
fi

# round-robin of (cut-mode durability n run-secs expect) tuples. expect=pass means
# RC 0 required; expect=maydrop means a nonzero RC is a legitimate control, not a finding.
rounds=(
  "wal strict $N_INFLIGHT $RUN_SECS pass"
  "checkpoint strict $N_INFLIGHT $RUN_SECS pass"
  "clean strict $N_CLEAN 0 pass"
  "wal standard $N_INFLIGHT $RUN_SECS maydrop"
)

[ -f "$LOG" ] || printf 'ts_ns\tcut_mode\tdurability\texpect\trc\tsecs\tsummary\n' >"$LOG"

START=$(date +%s)
DEADLINE=$(( START + MINUTES * 60 ))
i=0
cycle_secs=0
findings=0
pass=0
control_red=0
while [ "$(date +%s)" -lt "$DEADLINE" ]; do
  tuple=${rounds[$(( i % ${#rounds[@]} ))]}
  i=$(( i + 1 ))
  set -- $tuple
  mode=$1; dur=$2; n=$3; rs=$4; expect=$5
  t0=$(date +%s)
  set +e
  out=$(timeout 300 bash "$RUNNER" --bin "$BIN" --cut-mode "$mode" --durability "$dur" --n "$n" --run-secs "$rs" --workers 4 2>&1)
  rc=$?
  set -e
  t1=$(date +%s)
  secs=$(( t1 - t0 ))
  cycle_secs=$(( cycle_secs + secs ))
  summary=$(echo "$out" | grep -E 'acknowledged_before_cut=|postgres_recovery=|RESULT_RC=' | tr '\n' ' ' | sed 's/\t/ /g')
  printf '%s\t%s\t%s\t%s\t%d\t%d\t%s\n' "$(date +%s%N)" "$mode" "$dur" "$expect" "$rc" "$secs" "$summary" >>"$LOG"
  if [ "$expect" = pass ]; then
    if [ "$rc" = 0 ]; then
      pass=$(( pass + 1 ))
      echo "[ok]   $mode/$dur rc=$rc ${secs}s :: $summary"
    else
      findings=$(( findings + 1 ))
      echo "[FIND] $mode/$dur rc=$rc ${secs}s :: $summary" >&2
      echo "$out" >"/var/tmp/powercut-pg/FINDING-$(date +%s%N)-$mode-$dur.txt"
    fi
  else
    control_red=$(( control_red + 1 ))
    echo "[ctl]  $mode/$dur rc=$rc ${secs}s (relaxed-durability control) :: $summary"
  fi
done

echo "----"
echo "soak batch done: cut_cycle_seconds=$cycle_secs iterations=$i strict_pass=$pass strict_findings=$findings controls=$control_red"
echo "cumulative (this log): $(awk -F'\t' 'NR>1{s+=$6; n++} END{printf "cut_cycle_seconds=%d iterations=%d", s, n}' "$LOG")"
echo "log: $LOG"
exit 0
