#!/usr/bin/env bash
# Oracle self-test for the config-space fuzzer.
#
#   planted/selftest.sh <template-dir> <control-server-binary> [planted-id ...]
#
# For every planted defect in expect.tsv this checks out HEAD into a scratch worktree,
# applies the patch, runs the campaign there, and requires that the oracle reports the
# defect. It then runs the unpatched tree (the control) and requires silence for all of
# them. <template-dir> is the baseline made by TestMatrix / BuildTemplate;
# <control-server-binary> is a keyorix-server built from the unpatched tree.
#
# Runs at low priority and caps Go at two procs: it is meant to share a busy machine.
set -euo pipefail

tpl=${1:?template dir}
ctl=${2:?control server binary}
shift 2
root=$(git rev-parse --show-toplevel)
here=scripts/fuzzing/configspace
export GOMAXPROCS=2
run() { nice -n 15 "$@"; }

cd "$root"
ids=("$@")
if [ ${#ids[@]} -eq 0 ]; then
  while IFS=$'\t' read -r id _; do
    case "$id" in \#*|"") continue ;; esac
    ids+=("$id")
  done <"$here/planted/expect.tsv"
fi

status=0
for id in "${ids[@]}"; do
  line=$(awk -F'\t' -v id="$id" '$1==id' "$here/planted/expect.tsv")
  patch=$(echo "$line" | cut -f2)
  needs=$(echo "$line" | cut -f3)
  wt=$(mktemp -d "${TMPDIR:-/tmp}/cs-planted-XXXXXX")
  git worktree add --detach "$wt" HEAD >/dev/null
  echo "== $id: applying $patch"
  ok=1
  (
    cd "$wt"
    git apply "$here/planted/$patch"
    bin=""
    if [ "$needs" = 1 ]; then
      run go build -o "$wt/server.bin" ./server
      bin="$wt/server.bin"
    fi
    CONFIGSPACE_PLANTED="$id" CONFIGSPACE_TEMPLATE="$tpl" CONFIGSPACE_BIN="$bin" \
      run go test "./$here" -run 'TestPlanted$' -count=1 -parallel 2 -timeout 40m
  ) || ok=0
  git worktree remove --force "$wt" >/dev/null 2>&1 || true
  if [ "$ok" = 1 ]; then echo "PASS $id (detected)"; else echo "FAIL $id (not detected)"; status=1; fi
done

echo "== control (unpatched)"
if CONFIGSPACE_PLANTED=control CONFIGSPACE_TEMPLATE="$tpl" CONFIGSPACE_BIN="$ctl" \
  run go test "./$here" -run 'TestPlanted$' -count=1 -parallel 2 -timeout 40m; then
  echo "PASS control (silent)"
else
  echo "FAIL control (reported a planted defect)"
  status=1
fi
exit $status
