#!/usr/bin/env bash
# THROWAWAY (CI-CACHE-SPIKE-1). measure.sh <label> <leg|all>
# Compiles and links the test binaries of one test-suite leg (or of every leg)
# with the test-suite step's exact build flags, runs nothing (-exec true), and
# prints one SPIKE| line. Must run from the root of the tree being compiled.
set -euo pipefail
label=$1
want=$2
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

# shellcheck source=/dev/null
source scripts/ci-test-legs.sh

# Same package choice as ci.yml's test-suite "go test" step.
leg_pkgs() {
  case "$1" in
    handlers-*) echo ./server/http/handlers/... ;;
    http-*) echo ./server/http ;;
    encryption-*) echo ./internal/encryption ;;
    faultops-*) echo ./server/faultops ;;
    storage-store-*) echo ./internal/storage/store ;;
    *) pkgs_for_leg "$1" | tr '\n' ' ' ;;
  esac
}

if [ "$want" = all ]; then
  pkgs=$(for l in $(all_leg_names); do leg_pkgs "$l" | tr ' ' '\n'; done | sed '/^$/d' | sort -u | tr '\n' ' ')
else
  pkgs=$(leg_pkgs "$want")
fi
echo "label=$label leg=$want nproc=$(nproc) go=$(go version)"
echo "packages: $(echo "$pkgs" | wc -w)"
gocache=$(go env GOCACHE)
echo "GOCACHE=$gocache before: $(du -sh "$gocache" 2>/dev/null | cut -f1 || echo 0) files=$(find "$gocache" -type f 2>/dev/null | wc -l)"

ag="${RUNNER_TEMP:-/tmp}/ag-$label.json"
start=$(date +%s.%N)
# shellcheck disable=SC2086
go test -race -run '^$' -exec /usr/bin/true -coverprofile="${RUNNER_TEMP:-/tmp}/cov.out" -covermode=atomic \
  -debug-actiongraph="$ag" $pkgs > /dev/null
end=$(date +%s.%N)
wall=$(echo "$end - $start" | bc)
after=$(du -sm "$gocache" | cut -f1)
python3 "$here/actiongraph_summary.py" "$ag" "$label" "$want" "$wall" "$after"
