#!/usr/bin/env bash
# tz-sweep.sh — run the time-sensitive Go packages under non-UTC host zones.
#
# Why: tests that write a host-zone time.Now() into a TIMESTAMP column (SQLite
# stores the zone-suffixed string and compares lexicographically) pass on a UTC
# CI runner and fail for a developer or customer in another zone. CI is UTC, so
# nothing else catches this class (TZ-SWEEP-1).
#
# Usage:
#   scripts/ci/tz-sweep.sh                       # default zones x default packages
#   TZ_SWEEP_ZONES="Asia/Kolkata" scripts/ci/tz-sweep.sh
#   TZ_SWEEP_PKGS="./internal/audit/..." scripts/ci/tz-sweep.sh
#   scripts/ci/tz-sweep.sh -run 'TestStats'      # extra args go to go test
#
# Zones: +05:30 (half-hour offset, ahead of UTC) and UTC-7/-8 (behind UTC, where the
# host date trails the UTC date). Add Pacific/Auckland via TZ_SWEEP_ZONES (far ahead).
# Packages run one at a time (they are heavy; see the RAM-disk note in
# the sandbox README). Exit status is non-zero if any zone/package fails; every
# failure is listed in the summary at the end.
set -u

zones=${TZ_SWEEP_ZONES:-"Asia/Kolkata America/Los_Angeles"}
pkgs=${TZ_SWEEP_PKGS:-"./internal/core ./internal/storage/... ./internal/audit/... ./server/admin"}
timeout=${TZ_SWEEP_TIMEOUT:-20m}

root=$(git rev-parse --show-toplevel 2>/dev/null) || { echo "tz-sweep: run inside the repo" >&2; exit 2; }
cd "$root" || exit 2

# The machine-wide GOFLAGS may carry -trimpath, which breaks source-locating tests.
flags=""
for f in ${GOFLAGS:-}; do [ "$f" = "-trimpath" ] || flags="$flags $f"; done
export GOFLAGS="${flags# }"

mkdir -p .scratch

# Fail closed on a zone Go cannot load: Go silently falls back to UTC for an
# unknown or unloadable TZ (a typo, or a host without /usr/share/zoneinfo), which
# would make every pair below run under UTC and report a false all-pass. The probe
# uses Go's own loader, the same one the test binaries use, and does not import
# time/tzdata, so a host without zoneinfo is caught too.
probe=.scratch/tz-sweep-probe.go
cat >"$probe" <<'EOF'
package main

import (
	"fmt"
	"os"
	"time"
)

func main() {
	z := os.Getenv("TZ")
	if _, err := time.LoadLocation(z); err != nil {
		fmt.Fprintf(os.Stderr, "cannot load zone %q: %v\n", z, err)
		os.Exit(1)
	}
	if got := time.Local.String(); got != z {
		fmt.Fprintf(os.Stderr, "zone %q resolved to %q (Go fell back to UTC)\n", z, got)
		os.Exit(1)
	}
}
EOF
for z in $zones; do
  if ! TZ="$z" go run "$probe"; then
    echo "tz-sweep: invalid or unloadable zone '$z' in TZ_SWEEP_ZONES; refusing to run (it would silently use UTC)" >&2
    exit 2
  fi
done

failed=()
for z in $zones; do
  for p in $pkgs; do
    log=".scratch/tz-sweep-$(echo "${z}${p}" | tr '/.' '__').log"
    echo "tz-sweep: TZ=$z $p ..." >&2
    if TZ="$z" go test "$p" -count=1 -timeout "$timeout" "$@" >"$log" 2>&1; then
      echo "tz-sweep: ok   TZ=$z $p" >&2
    else
      echo "tz-sweep: FAIL TZ=$z $p (log $log)" >&2
      failed+=("TZ=$z $p")
      grep -E '^(--- FAIL|FAIL|panic)' "$log" | head -20 >&2
    fi
  done
done

if [ ${#failed[@]} -gt 0 ]; then
  echo "tz-sweep: ${#failed[@]} failing zone/package pair(s):" >&2
  printf '  %s\n' "${failed[@]}" >&2
  exit 1
fi
echo "tz-sweep: all zone/package pairs passed (zones: $zones)" >&2
