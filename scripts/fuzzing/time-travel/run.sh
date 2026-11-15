#!/bin/bash
# run.sh — time-travel differential runner (task TT1).
#
# Builds the per-version driver for a library against each historical version
# that Keyorix has ever pinned AND that is present in the offline module cache,
# then runs every version on one shared corpus and writes canonical JSON-lines
# output per version. A separate comparer (compare.go) diffs consecutive
# versions.
#
# Why a scratch module per version: two versions of the same import path cannot
# coexist in one Go binary, so each version is built in its own throwaway module
# (require <version>) under .scratch/tt1/build/, and the differential crosses a
# process boundary. The repo's own go.mod / go.sum are NEVER touched (the task
# forbids it and it would defeat the point).
#
# Offline: GOPROXY=off, everything resolved from GOMODCACHE. A version missing
# from the cache is skipped with a logged note (never a silent omission).
#
# Resource discipline (shared host): GOMAXPROCS=2, nice, a wall-clock timeout and
# a hard virtual-memory rlimit on every driver run so a historical
# memory-amplification bug (e.g. GHSA-3xqc-rpq8-wgp9 in old digitorus/pkcs7) dies
# cleanly as an "oom" record instead of eating the host's RAM.
#
# Usage:
#   run.sh build   <lib>                 # build all cached-version drivers
#   run.sh corpus  <lib> <corpus.tsv>    # run every built driver on a corpus
#   run.sh all     <lib> <corpus.tsv>    # build + corpus
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../.." && pwd)"
BUILD="$REPO_ROOT/.scratch/tt1/build"
OUT="$HERE/out"

export GOWORK=off          # scratch modules are not part of the repo workspace
export GOPROXY=off         # offline: cache only
export GOFLAGS=-mod=mod    # let go compute go.sum from the cache for the scratch module
export GOMAXPROCS=2
export CGO_ENABLED=0

# Per-driver-run safety caps (overridable from the environment).
TT1_TIMEOUT="${TT1_TIMEOUT:-120}"        # seconds of wall clock per corpus run
TT1_VMEM_KB="${TT1_VMEM_KB:-3500000}"    # ~3.3 GiB virtual-memory ceiling per run

# Module path + the historical versions this harness knows how to drive.
lib_module() {
  case "$1" in
    pkcs7) echo "github.com/digitorus/pkcs7" ;;
    *) echo "" ;;
  esac
}
# Versions in chronological (pin) order, oldest first. Only those present in the
# cache are actually built; the rest are reported skipped.
lib_versions() {
  case "$1" in
    pkcs7)
      echo "v0.0.0-20230713084857-e76b763bdc49"
      echo "v0.0.0-20260914070511-d678ea5ea03f"
      echo "v0.0.0-20261104113855-bd33e0b11a3d"
      ;;
  esac
}

# A filesystem-safe tag for a version (pseudo-versions contain no slashes but we
# keep the short hash suffix to stay readable).
ver_tag() { echo "$1" | sed 's/[^A-Za-z0-9._-]/_/g'; }

in_cache() {
  # zip present in the download cache => buildable offline.
  local mod="$1" ver="$2"
  local z="$(go env GOMODCACHE)/cache/download/${mod}/@v/${ver}.zip"
  [ -f "$z" ]
}

build_one() {
  local lib="$1" ver="$2" mod tag dir
  mod="$(lib_module "$lib")"
  tag="$(ver_tag "$ver")"
  dir="$BUILD/${lib}-${tag}"
  if ! in_cache "$mod" "$ver"; then
    echo "SKIP  $lib $ver (not in module cache)" >&2
    return 2
  fi
  mkdir -p "$dir"
  cp "$HERE/drivers/$lib/main.go" "$dir/main.go"
  cat > "$dir/go.mod" <<EOF
module tt1driver

go 1.27

require $mod $ver
EOF
  ( cd "$dir" && nice -n 10 go build -o driver . ) 2>"$dir/build.log"
  if [ ! -x "$dir/driver" ]; then
    echo "FAIL  $lib $ver — build failed, see $dir/build.log" >&2
    sed 's/^/      /' "$dir/build.log" >&2
    return 1
  fi
  echo "BUILT $lib $ver -> $dir/driver" >&2
  return 0
}

build_all() {
  local lib="$1" ver rc=0
  while read -r ver; do
    [ -z "$ver" ] && continue
    build_one "$lib" "$ver" || { [ $? -eq 1 ] && rc=1; }
  done < <(lib_versions "$lib")
  return $rc
}

run_corpus() {
  local lib="$1" corpus="$2" ver tag dir
  mkdir -p "$OUT/$lib"
  while read -r ver; do
    [ -z "$ver" ] && continue
    tag="$(ver_tag "$ver")"
    dir="$BUILD/${lib}-${tag}"
    [ -x "$dir/driver" ] || { echo "SKIP  $lib $ver (no driver built)" >&2; continue; }
    echo "RUN   $lib $ver on $(wc -l < "$corpus") items" >&2
    ( ulimit -v "$TT1_VMEM_KB" 2>/dev/null
      timeout "$TT1_TIMEOUT" nice -n 10 "$dir/driver" < "$corpus" > "$OUT/$lib/${tag}.jsonl" )
    local rc=$?
    if [ $rc -ne 0 ]; then
      echo "WARN  $lib $ver driver exited $rc (timeout/oom) — partial output kept" >&2
      echo "{\"id\":\"__DRIVER_EXIT__\",\"verdict\":\"driver_exit\",\"errclass\":\"exit${rc}\"}" >> "$OUT/$lib/${tag}.jsonl"
    fi
  done < <(lib_versions "$lib")
}

cmd="${1:-}"; shift || true
case "$cmd" in
  build)  build_all "$1" ;;
  corpus) run_corpus "$1" "$2" ;;
  all)    build_all "$1"; run_corpus "$1" "$2" ;;
  *) echo "usage: run.sh {build|corpus|all} <lib> [corpus.tsv]" >&2; exit 2 ;;
esac
