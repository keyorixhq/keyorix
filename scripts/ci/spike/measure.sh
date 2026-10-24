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

gocache=$(go env GOCACHE)
echo "label=$label leg=$want nproc=$(nproc) go=$(go version)"
echo "GOCACHE=$gocache before: $(du -sh "$gocache" 2>/dev/null | cut -f1 || echo 0) files=$(find "$gocache" -type f 2>/dev/null | wc -l)"

# One go test invocation exactly like one leg's (the package list decides
# which packages get coverage instrumentation, so a union of several legs is
# NOT the same build: it fails to link, run 40138061823).
run_leg() { # <tag> <pkgs...>
  local tag=$1 ag start end wall after
  shift
  ag="${RUNNER_TEMP:-/tmp}/ag-$label-$tag.json"
  start=$(date +%s.%N)
  go test -race -run '^$' -exec /usr/bin/true -coverprofile="${RUNNER_TEMP:-/tmp}/cov.out" -covermode=atomic \
    -debug-actiongraph="$ag" "$@" > /dev/null
  end=$(date +%s.%N)
  wall=$(echo "$end - $start" | bc)
  after=$(du -sm "$gocache" | cut -f1)
  python3 "$here/actiongraph_summary.py" "$ag" "$label" "$tag" "$wall" "$after"
}

t0=$(date +%s.%N)
case "$want" in
  all)
    # Every distinct leg command once (core-1..4 share one package, etc.).
    seen=""
    for l in $(all_leg_names); do
      p=$(leg_pkgs "$l")
      case "$seen" in *"|$p|"*) continue ;; esac
      seen="$seen|$p|"
      # shellcheck disable=SC2086
      run_leg "$l" $p
    done
    ;;
  deps)
    # Third-party + std only, -race, never a package of this module: what a
    # cache keyed on go.sum + Go version alone may hold.
    all_pkgs=$(for l in $(all_leg_names); do leg_pkgs "$l" | tr ' ' '\n'; done | sed '/^$/d' | sort -u)
    # shellcheck disable=SC2086
    go list -race -deps -test $all_pkgs | grep -v '^github.com/keyorixhq/keyorix' | grep -v '\.test$' | grep -v ' \[' | sort -u > "${RUNNER_TEMP:-/tmp}/deps.txt"
    echo "deps packages: $(wc -l < "${RUNNER_TEMP:-/tmp}/deps.txt")"
    # shellcheck disable=SC2046
    go build -race $(cat "${RUNNER_TEMP:-/tmp}/deps.txt")
    ;;
  *)
    # shellcheck disable=SC2046
    run_leg "$want" $(leg_pkgs "$want")
    ;;
esac
t1=$(date +%s.%N)
echo "SPIKE-TOTAL|label=$label|leg=$want|wall_s=$(echo "$t1 - $t0" | bc)|gocache_mb=$(du -sm "$gocache" | cut -f1)|files=$(find "$gocache" -type f | wc -l)"
