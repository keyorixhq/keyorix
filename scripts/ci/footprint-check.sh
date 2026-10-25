#!/usr/bin/env bash
# footprint-check.sh -- EDGE-LOWMEM-1: a cheap footprint tripwire so the edge
# advantage (small, light) cannot regress silently. Compares, against the
# committed scripts/ci/footprint-budget.json:
#
#   1. size of the release server binary and of the CLI binary
#      (CGO_ENABLED=0 -trimpath -ldflags "-s -w"; budget = measured + 10%);
#   2. peak RSS of the server idle: secure-baseline SQLite install (admin init
#      without --dev: TLS and rate limit on), healthy, 30 s idle, run 3 times,
#      the MAX is compared (budget = measured + 25%; the headroom absorbs noise).
#
# Exits 1 and prints "current vs budget" for every metric that is over. It
# complements scripts/edge/footprint.sh (EDGE-1: server-only, per-profile size
# for four platforms, one short RSS run); this one adds the CLI, the secure
# baseline, the 3 x 30 s RSS protocol and a self-test.
#
# Usage:
#   scripts/ci/footprint-check.sh                    # host platform, sizes + RSS
#   scripts/ci/footprint-check.sh --platform linux/amd64 --skip-rss
#                                                    # cross-build sizes only
#   scripts/ci/footprint-check.sh --print            # current values + suggested limits (no check)
#   scripts/ci/footprint-check.sh --self-test        # red/green proof the check fires
# Options: --budget FILE  --runs N (3)  --idle SECONDS (30)  --skip-size
#          --skip-rss  --require-rss (a null RSS budget FAILS instead of skipping)
#
# Budget file: platform -> {server_bytes, cli_bytes, idle_rss_kib}; null = no
# budget yet. A missing size budget FAILS (fail closed). A null RSS budget SKIPS
# with a message unless --require-rss. RSS is only measured for the host platform.
# If growth is intended, raise the limit in the PR that causes it and say why.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

budget="scripts/ci/footprint-budget.json"
platform=""
runs=3
idle=30
skip_size="" skip_rss="" require_rss="" print="" self_test=""
while [ $# -gt 0 ]; do
  case "$1" in
    --budget) budget="$2"; shift 2 ;;
    --platform) platform="$2"; shift 2 ;;
    --runs) runs="$2"; shift 2 ;;
    --idle) idle="$2"; shift 2 ;;
    --skip-size) skip_size=1; shift ;;
    --skip-rss) skip_rss=1; shift ;;
    --require-rss) require_rss=1; shift ;;
    --print) print=1; shift ;;
    --self-test) self_test=1; shift ;;
    -h|--help) sed -n '2,28p' "$0"; exit 0 ;;
    *) echo "footprint-check: unknown argument: $1" >&2; exit 2 ;;
  esac
done

say() { echo "footprint-check: $*" >&2; }

host="$(go env GOOS)/$(go env GOARCH)"
[ -n "$platform" ] || platform="$host"

work="$(mktemp -d "${TMPDIR:-/tmp}/fpcheck.XXXXXX")"
trap 'rm -rf "$work"' EXIT

# budget_get <file> <platform> <metric> -> integer, or "-" for null; exit 3 = no such platform row.
budget_get() {
  python3 -I - "$1" "$2" "$3" <<'PY'
import json, sys
path, plat, metric = sys.argv[1:4]
with open(path, encoding="utf-8") as f:
    rows = json.load(f)["platforms"]
if plat not in rows:
    sys.exit(3)
v = rows[plat].get(metric)
print("-" if v is None else int(v))
PY
}

build_binaries() { # build_binaries <platform> <outdir>: server + cli, release flags
  local goos="${1%/*}" goarch="${1#*/}" out="$2"
  local arm=""
  [ "$goarch" = "arm" ] && arm=7 # linux/arm means armv7
  say "building keyorix-server and the CLI for $1 (release flags)"
  env CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" GOARM="$arm" \
    go build -trimpath -ldflags "-s -w" -o "$out/keyorix-server" ./server
  env CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" GOARM="$arm" GOWORK=off \
    go -C cli build -trimpath -ldflags "-s -w" -o "$out/keyorix" .
}

fsize() { wc -c <"$1" | tr -d ' '; }

failed=0
# check <label> <unit> <current> <limit> : prints one line, sets failed on breach.
check() {
  local label="$1" unit="$2" cur="$3" limit="$4" verdict=OK
  if [ "$cur" -gt "$limit" ]; then verdict=FAIL; failed=1; fi
  printf 'footprint-check: %-24s current %12s %s  budget %12s %s  %s\n' "$label" "$cur" "$unit" "$limit" "$unit" "$verdict"
}

# size_metric <label> <metric> <current>
size_metric() {
  local limit="-" rc=0
  if [ -z "$print" ]; then limit="$(budget_get "$budget" "$platform" "$2")" || rc=$?; fi
  [ "$rc" -eq 0 ] || [ "$rc" -eq 3 ] || { say "cannot read $budget"; exit 2; }
  if [ -n "$print" ]; then
    printf 'footprint-check: PRINT %s %s current=%s suggested_limit=%s (+10%%)\n' "$platform" "$2" "$3" "$(( ($3 * 110 + 99) / 100 ))"
    return
  fi
  if [ "$rc" -ne 0 ] || [ "$limit" = "-" ]; then
    say "FAIL: no $2 budget for $platform in $budget (measured $3 bytes); add a limit about 10% above the measured value"
    failed=1
    return
  fi
  check "$1" bytes "$3" "$limit"
}

measure_sizes() {
  build_binaries "$platform" "$work"
  size_metric "server binary" server_bytes "$(fsize "$work/keyorix-server")"
  size_metric "CLI binary" cli_bytes "$(fsize "$work/keyorix")"
}

measure_rss() {
  if [ "$platform" != "$host" ]; then
    say "SKIP idle RSS for $platform: it needs a run and this host is $host"
    return
  fi
  local limit="-" rc=0
  if [ -z "$print" ]; then limit="$(budget_get "$budget" "$platform" idle_rss_kib)" || rc=$?; fi
  [ "$rc" -eq 0 ] || [ "$rc" -eq 3 ] || { say "cannot read $budget"; exit 2; }
  if [ -z "$print" ] && { [ "$rc" -ne 0 ] || [ "$limit" = "-" ]; }; then
    if [ -n "$require_rss" ]; then
      say "FAIL: no idle_rss_kib budget for $platform in $budget (--require-rss); measure on that platform with --print and add the row"
      failed=1
    else
      say "SKIP idle RSS for $platform: no budget yet (measure on that platform with --print and add idle_rss_kib)"
    fi
    return
  fi
  if [ ! -x "$work/keyorix-server" ]; then # --skip-size path: still need the host binary
    say "building keyorix-server for $platform (release flags)"
    env CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o "$work/keyorix-server" ./server
  fi
  local max=0 i out rss
  for i in $(seq 1 "$runs"); do
    mkdir "$work/run$i"
    say "idle RSS run $i/$runs (healthy, then ${idle}s idle)"
    out="$(python3 -I scripts/ci/footprint_rss.py "$work/keyorix-server" "$work/run$i" "$idle")" || { say "FAIL: RSS run $i did not complete"; failed=1; return; }
    rss="${out##*RSS_KIB=}"
    say "run $i peak RSS ${rss} KiB"
    [ "$rss" -gt "$max" ] && max="$rss"
  done
  if [ -n "$print" ]; then
    printf 'footprint-check: PRINT %s idle_rss_kib current=%s (max of %s) suggested_limit=%s (+25%%)\n' "$platform" "$max" "$runs" "$(( (max * 125 + 99) / 100 ))"
    return
  fi
  check "idle RSS (max of $runs)" KiB "$max" "$limit"
}

if [ -n "$self_test" ]; then
  exec "$repo_root/scripts/ci/footprint-check-selftest.sh"
fi

[ -n "$print" ] || [ -f "$budget" ] || { say "budget file $budget not found"; exit 2; }
say "platform $platform, budget $budget"
[ -n "$skip_size" ] || measure_sizes
[ -n "$skip_rss" ] || measure_rss

if [ -n "$print" ]; then exit 0; fi
if [ "$failed" -ne 0 ]; then
  say "FAILED: over budget (or no budget). If the growth is intended, raise the limit in $budget in the same PR and say why; otherwise find what linked in or allocates at start-up."
  exit 1
fi
say "OK: within budget"
