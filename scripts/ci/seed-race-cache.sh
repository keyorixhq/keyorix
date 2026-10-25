#!/usr/bin/env bash
# seed-race-cache.sh: fill GOCACHE with what ci.yml's test-suite legs compile,
# so a leg that restores it (go-race-cache.yml saves it) links instead of
# rebuilding ~1,000 packages with -race -cover.
#
# For every distinct leg command it runs the leg's own `go test` build flags
# (-race -coverprofile -covermode=atomic, the leg's package list) with
# `-run '^$' -exec /usr/bin/true`: everything is compiled, vetted and linked,
# no test runs and no service is needed.
#
# Why per leg and not one `go test` over every package: the package list
# decides which packages get coverage instrumentation, so a union is a
# different build (it does not even link: "fingerprint mismatch" on
# internal/config, CI-CACHE-SPIKE-1 run 40138061823). Only a leg's exact
# package list produces the action IDs that leg looks up.
#
# Correctness never depends on this cache: GOCACHE is content-addressed (an
# action ID hashes the Go version, flags and every input file), so an entry
# from an older tree is simply not found, and -coverprofile disables test
# result caching. What the seed can get wrong is only speed: if leg_pkgs
# below drifts from the test-suite step's package choice, that leg misses.
set -euo pipefail

# shellcheck source=/dev/null # sourced from the repo root, as ci.yml does
source scripts/ci-test-legs.sh

# The test-suite "go test" step's package choice (its case statement): these
# prefixes override pkgs_for_leg there; every other leg uses pkgs_for_leg.
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
cov="${RUNNER_TEMP:-${TMPDIR:-/tmp}}/seed-race-cache.cover.out"
echo "Seeding $gocache with every test-suite leg's -race -cover build ($(go version))."
start=$SECONDS
seen="|"
n=0
for leg in $(all_leg_names); do
  pkgs=$(leg_pkgs "$leg")
  case "$seen" in *"|$pkgs|"*) echo "  $leg: same packages as an earlier leg, skipped"; continue ;; esac
  seen="$seen$pkgs|"
  n=$((n + 1))
  t=$SECONDS
  # shellcheck disable=SC2086 # $pkgs is a word-split package list, as in ci.yml
  go test -race -run '^$' -exec /usr/bin/true -coverprofile="$cov" -covermode=atomic $pkgs > /dev/null
  echo "  $leg: compiled in $((SECONDS - t)) s"
done
rm -f "$cov"
echo "Done: $n leg commands in $((SECONDS - start)) s; GOCACHE now $(du -sh "$gocache" | cut -f1)."
