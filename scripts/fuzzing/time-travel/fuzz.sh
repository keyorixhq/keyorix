#!/bin/bash
# fuzz.sh — drive FuzzPKCS7TimeTravelOracle (the TT1 mutation layer) with the
# old-version oracle wired in and the shared-host resource caps applied.
#
#   fuzz.sh smoke           # run seeds only (compile + oracle round-trip check)
#   fuzz.sh run <seconds>   # coverage-guided fuzz for <seconds> of real time
#
# The old-version oracle binary must already be built (run.sh build pkcs7); its
# path is passed through TT1_PKCS7_OLD_DRIVER. GOMAXPROCS=2 / -parallel 2 / nice
# keep this within the shared pve01 budget.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../.." && pwd)"
BUILD="$REPO_ROOT/.scratch/tt1/build"
PKG="./internal/libconformance"
FUZZ="FuzzPKCS7TimeTravelOracle"

# Oldest cached version is the oracle by default (the pre-fix v2023 pkcs7).
OLD_TAG="${TT1_OLD_TAG:-v0.0.0-20230713084857-e76b763bdc49}"
export TT1_PKCS7_OLD_DRIVER="${TT1_PKCS7_OLD_DRIVER:-$BUILD/pkcs7-$OLD_TAG/driver}"
export GOMAXPROCS=2
export GOTRACEBACK=none   # a deliberately-crashed old oracle must not spew

if [ ! -x "$TT1_PKCS7_OLD_DRIVER" ]; then
  echo "oracle driver not built: $TT1_PKCS7_OLD_DRIVER (run: run.sh build pkcs7)" >&2
  exit 2
fi
echo "oracle = $TT1_PKCS7_OLD_DRIVER" >&2

cmd="${1:-smoke}"
mkdir -p "$HERE/out"
case "$cmd" in
  smoke)
    nice -n 10 go test -run="$FUZZ" -count=1 "$PKG"
    ;;
  run)
    secs="${2:?usage: fuzz.sh run <seconds>}"
    nice -n 10 go test -run='^$' -fuzz="^$FUZZ\$" -parallel=2 \
      -fuzztime="${secs}s" "$PKG"
    ;;
  *)
    echo "usage: fuzz.sh {smoke|run <seconds>}" >&2; exit 2 ;;
esac
