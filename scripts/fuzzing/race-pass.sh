#!/usr/bin/env bash
# Race-detector pass over keyorix's CONCURRENT fuzz targets.
#
# The production rigs fuzz with CGO_ENABLED=0 (static, air-gap-friendly binaries),
# but the race detector needs cgo + a C toolchain — so this is a dev/CI check, NOT
# a rig job. It runs each concurrent target under -race to surface data races the
# native rig cannot. Single-threaded parser targets have no races to find, so only
# targets that spin up goroutines/servers are listed here.
#
# fuzzutil.Guard auto-scales its wall-clock budget under -race (see
# internal/fuzzutil/guard_race.go), so the detector's ~10-20x slowdown does not
# false-trip the hang guard.
#
# Usage: scripts/fuzzing/race-pass.sh [fuzztime]   # default 2m per target
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

FUZZTIME="${1:-2m}"

# "<package> <FuzzTarget>" per concurrent target.
CONCURRENT_TARGETS=(
	"./internal/notary FuzzRFC3161Anchor"
)

rc=0
for entry in "${CONCURRENT_TARGETS[@]}"; do
	pkg="${entry% *}"
	target="${entry##* }"
	echo "== -race fuzz: ${target} (${pkg}) for ${FUZZTIME} =="
	if ! CGO_ENABLED=1 go test -race -run='^$' -fuzz="^${target}\$" -parallel=2 -fuzztime="${FUZZTIME}" "${pkg}"; then
		echo "!! race pass FAILED for ${target}"
		rc=1
	fi
done

[ "${rc}" -eq 0 ] && echo "OK - no data races found"
exit "${rc}"
