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
#                           can go red — it is NOT a finding. Only the lost tail is
#                           by design: recovery, audit_chain_valid=true, pg_amcheck
#                           and e2fsck must still be clean, otherwise it IS a finding.
#
# Exit status: 0 when no finding, 1 when any run was a finding.
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
LOGDIR=$(dirname "$LOG")
mkdir -p "$LOGDIR"

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
control_green=0
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
  summary=$(echo "$out" | grep -E 'acknowledged_before_cut=|missing_acknowledged=|postgres_recovery=|audit_chain_valid=|audit_chain_verify_error=|pg_amcheck=|e2fsck=|FAILED|RESULT_RC=' | tr '\n' ' ' | sed 's/\t/ /g')
  printf '%s\t%s\t%s\t%s\t%d\t%d\t%s\n' "$(date +%s%N)" "$mode" "$dur" "$expect" "$rc" "$secs" "$summary" >>"$LOG"
  if [ "$expect" = pass ]; then
    if [ "$rc" = 0 ]; then
      pass=$(( pass + 1 ))
      echo "[ok]   $mode/$dur rc=$rc ${secs}s :: $summary"
    else
      findings=$(( findings + 1 ))
      echo "[FIND] $mode/$dur rc=$rc ${secs}s :: $summary" >&2
      echo "$out" >"$LOGDIR/FINDING-$(date +%s%N)-$mode-$dur.txt"
    fi
  else
    # maydrop (standard durability): losing the acknowledged tail is by design, but
    # recovery, the audit hash chain, heap/btree pages and the filesystem must
    # still be intact. Only a run that shows all four clean AND rc 0, or rc 1 with
    # missing_acknowledged above 0 (and nothing else wrong), is a legitimate control.
    if { [ "$rc" = 0 ] || { [ "$rc" = 1 ] && grep -qE 'missing_acknowledged=[1-9]' <<<"$out"; }; } \
      && grep -q 'postgres_recovery=yes' <<<"$out" \
      && grep -q 'audit_chain_valid=true' <<<"$out" \
      && grep -q 'pg_amcheck=clean' <<<"$out" \
      && grep -q 'e2fsck=clean' <<<"$out" \
      && ! grep -qE 'RECOVERY FAILED|PG_AMCHECK FAILED|FSCK FAILED|audit_chain_valid=false|audit_chain_verify_error' <<<"$out"; then
      if [ "$rc" = 0 ]; then
        control_green=$(( control_green + 1 ))
        echo "[ctl]  $mode/$dur rc=$rc ${secs}s (relaxed durability, nothing lost) :: $summary"
      else
        control_red=$(( control_red + 1 ))
        echo "[ctl]  $mode/$dur rc=$rc ${secs}s (relaxed-durability control, tail lost by design) :: $summary"
      fi
    else
      findings=$(( findings + 1 ))
      echo "[FIND] $mode/$dur rc=$rc ${secs}s (relaxed durability, but recovery/chain/amcheck/fsck not clean) :: $summary" >&2
      echo "$out" >"$LOGDIR/FINDING-$(date +%s%N)-$mode-$dur.txt"
    fi
  fi
done

echo "----"
echo "soak batch done: cut_cycle_seconds=$cycle_secs iterations=$i strict_pass=$pass findings=$findings controls_lost_tail=$control_red controls_nothing_lost=$control_green"
echo "cumulative (this log): $(awk -F'\t' 'NR>1{s+=$6; n++} END{printf "cut_cycle_seconds=%d iterations=%d", s, n}' "$LOG")"
echo "log: $LOG"
[ "$findings" -eq 0 ] || exit 1
