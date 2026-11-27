#!/usr/bin/env bash
# run.sh: red-proof of the soak oracles. For each plant it copies the plant into
# server/soak/zz_plant_test.go (never committed), runs the smoke, and checks
# that the RIGHT oracle failed and named its subject. It also runs the control
# (no plant), which must be green. The plant is removed on every exit.
#
# Usage, from the repository root:
#   server/soak/testdata/redproof/run.sh              # control + all plants
#   server/soak/testdata/redproof/run.sh goroutine    # control + one plant
#
# Output: one TSV line per run on stdout (run, must_fail, result, seconds, verdict,
# evidence); progress on stderr; per-run logs in .scratch/soak-redproof/<run>.log.
# Exit status 1 when any run did not behave as expected.
set -eu

here="server/soak/testdata/redproof"
dest="server/soak/zz_plant_test.go"
logdir=".scratch/soak-redproof"

if [ ! -d "$here" ]; then
  echo "run.sh: run from the repository root ($here not found)" >&2
  exit 2
fi
mkdir -p "$logdir"
rm -f "$logdir/.bad"

log() { echo "$(date -u +%FT%TZ) soak-redproof: $*" >&2; }
trap 'rm -f "$dest"; log "removed $dest"' EXIT

# run | go test must fail | ";;"-separated regexes, ALL of which must match a SOAK line
runs="control|no|
goroutine|yes|SOAK FAIL +hard +baseline +goroutines .*grew: .*plantGoroutineLeak
one_goroutine|yes|SOAK PASS +hard +baseline +goroutines;;SOAK FAIL +hard +stacks +.*plantOneGoroutineLeak
rows|yes|SOAK FAIL +hard +baseline +db_in_use
tempfile|yes|SOAK FAIL +hard +baseline +temp_files .*soak-plant-
fd|yes|SOAK FAIL +hard +baseline +fds"

only="${1:-}"
printf 'run\tmust_fail\tresult\tseconds\tverdict\tevidence\n'
echo "$runs" | while IFS='|' read -r name mustfail patterns; do
  if [ -n "$only" ] && [ "$name" != "control" ] && [ "$name" != "$only" ]; then
    log "$name: skipped (only=$only)"
    continue
  fi
  if [ "$name" = "control" ] && [ -n "${SOAK_REDPROOF_SKIP_CONTROL:-}" ]; then
    log "control: skipped (SOAK_REDPROOF_SKIP_CONTROL set)"
    continue
  fi
  rm -f "$dest"
  if [ "$name" = "control" ]; then
    log "control: no plant"
  else
    src="$here/plant_${name}.go.txt"
    if [ ! -f "$src" ]; then
      echo "run.sh: missing $src" >&2
      exit 2
    fi
    log "$name: installing $src as $dest"
    cp "$src" "$dest"
  fi
  start=$(date +%s)
  rc=0
  KEYORIX_SOAK=smoke go test ./server/soak -run 'TestSoak$' -count=1 -v -timeout 10m >"$logdir/$name.log" 2>&1 || rc=$?
  secs=$(( $(date +%s) - start ))
  evidence=$(grep -E "SOAK FAIL" "$logdir/$name.log" | head -2 | cut -c1-160 | tr '\n' ' ' || true)
  result="green"
  [ "$rc" -ne 0 ] && result="red"
  verdict="OK"
  if [ "$mustfail" = "no" ]; then
    [ "$rc" -eq 0 ] || verdict="UNEXPECTED-RED"
    if grep -q "SOAK FAIL" "$logdir/$name.log"; then verdict="UNEXPECTED-RED"; fi
  else
    [ "$rc" -ne 0 ] || verdict="UNEXPECTED-GREEN"
    rest="$patterns"
    while [ -n "$rest" ]; do
      pat="${rest%%;;*}"
      if [ "$pat" = "$rest" ]; then rest=""; else rest="${rest#*;;}"; fi
      grep -Eq "$pat" "$logdir/$name.log" || verdict="WRONG-ORACLE($pat)"
    done
  fi
  log "$name: go test exit=$rc ${secs}s verdict=$verdict"
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$name" "$mustfail" "$result" "$secs" "$verdict" "$evidence"
  [ "$verdict" = "OK" ] || echo 1 >"$logdir/.bad"
done
if [ -f "$logdir/.bad" ]; then
  rm -f "$logdir/.bad"
  log "FAIL: at least one run did not behave as expected"
  exit 1
fi
log "all runs behaved as expected"
