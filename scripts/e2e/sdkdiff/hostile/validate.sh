#!/bin/bash
# Planted-defect and control validation of the hostile-server mode (hostile/RULES.md section 5).
# Usage: validate.sh <sdkdiff binary> <keyorix-sdks checkout> <plants dir from make-plants.sh> <build dir of the checkout> <work dir>
# For each plant it runs the plant's mutation subset on the planted SDK copy and on the unpatched checkout, then prints the
# violations that exist only with the plant.  PH0 (no-op patch) must show none, on all four SDKs.
# A run that fails or writes no results is reported as HARNESS-FAIL (with the tail of its log), never as MISSED.
set -u
BIN=$1; SDKS=$2; PLANTS=$3; BUILD=$4; W=$5
ROOT=$(cd "$(dirname "$0")/.." && pwd)
mkdir -p "$W"
FAILS=0
run() { # name sdkdir builddir kinds muts scens; returns non-zero when the run failed or wrote no results
  local rc=0
  "$BIN" hostile run -sdks "$4" -sdks-dir "$2" -build "$3" -root "$ROOT" -out "$W/$1" -mut "$5" -scen "$6" -par 4 -label "$1" >"$W/$1.log" 2>&1 || rc=$?
  if [ "$rc" -ne 0 ] || [ ! -s "$W/$1/results.jsonl" ]; then
    echo "$1: HARNESS-FAIL (exit $rc, log $W/$1.log)"
    tail -5 "$W/$1.log" | sed 's/^/    /'
    return 1
  fi
}
declare -a SPEC=(
  "PH1|go|O3|R05b,R02,B07,R05d|S07,S08,S09"
  "PH2|python|O3|S01m,S02m|S02,S03,S06,S07,S08,S10"
  "PH3|node|O1|N02,N03,N05,N06|S03,S06,S07"
  "PH4|java|O4|S01m,S03m|S03,S06,S07"
  "PH5|python|O6|I01,I02,I20|S03,S05,S06"
  "PH6|python|O2|T02,T03,T04|S03,S06,S07"
  "PH0|go,node,python,java|none|R05b,S01m,N02,I01,U15|S03,S06,S07"
)
for spec in "${SPEC[@]}"; do
  IFS='|' read -r P KINDS ORACLE MUTS SCENS <<<"$spec"
  OK=1
  run "base-$P" "$SDKS" "$BUILD" "$KINDS" "$MUTS" "$SCENS" || OK=0
  run "plant-$P" "$PLANTS/$P" "$PLANTS/build-$P" "$KINDS" "$MUTS" "$SCENS" || OK=0
  if [ "$OK" -eq 0 ]; then
    echo "$P sdk=$KINDS registered=$ORACLE verdict=HARNESS-FAIL (no verdict: a run failed)"
    FAILS=$((FAILS + 1))
    continue
  fi
  for K in ${KINDS//,/ }; do
    if ! OUT=$("$BIN" hostile diff -base "$W/base-$P" -run "$W/plant-$P" -sdk "$K"); then
      echo "$P sdk=$K registered=$ORACLE verdict=HARNESS-FAIL (hostile diff failed)"
      FAILS=$((FAILS + 1))
      continue
    fi
    NEW=$(echo "$OUT" | grep -c "^NEW .* $ORACLE:" || true)
    TOT=$(echo "$OUT" | tail -1)
    if [ "$ORACLE" = none ]; then
      [ "$TOT" = "new=0 gone=0" ] && V=SILENT || V="NOT-SILENT"
    else
      [ "$NEW" -ge 1 ] && V=DETECTED || V=MISSED
    fi
    echo "$P sdk=$K registered=$ORACLE verdict=$V ($TOT, registered-oracle new violations: $NEW)"
    echo "$OUT" | grep "^NEW" | head -3 | cut -c1-220 | sed 's/^/    /'
  done
done
exit $((FAILS > 0))
