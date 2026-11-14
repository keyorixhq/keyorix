#!/usr/bin/env bash
# crossbuild-check.sh -- static-binary and cross-build guard for the edge targets
# (EDGE-ARM64). keyorix-server (./server) and the keyorix CLI (cli/, its own
# module) must build for linux/arm64 and linux/arm (GOARM=7) with CGO_ENABLED=0,
# and the result must be a pure-Go, statically linked binary. Per component and
# target it checks:
#
#   1. no dependency outside the standard library imports "C": `go list -deps`
#      is run with cgo ENABLED so cgo files are visible (with CGO_ENABLED=0 the
#      toolchain hides them, which is exactly how a cgo dependency would slip by);
#   2. `go build` with CGO_ENABLED=0 exits 0;
#   3. `go version -m` on the result records CGO_ENABLED=0 and no external link
#      mode, i.e. the binary has no libc/dynamic-loader dependency.
#
# The standard library's own cgo files (net, os/user) are excluded from check 1:
# with CGO_ENABLED=0 they fall back to their pure-Go implementations.
#
# This is cross-COMPILE only. It does not run anything on ARM: a run on a
# Raspberry Pi is pending device. Complements scripts/edge/cross-build.sh, which
# builds every shipped component but does not look for cgo or inspect the result.
#
# Usage:
#   scripts/edge/crossbuild-check.sh [--out DIR] [--targets linux/arm64,linux/arm]
#                                    [--component name:dir:pkg]...
#   scripts/edge/crossbuild-check.sh --self-test
# --component replaces the default list (keyorix-server:.:./server and
# keyorix:cli:.); dir is relative to the repo root, or absolute for a fixture.
# --self-test proves the guard is red on a package that imports "C" and green on
# a pure-Go one. Exit status is non-zero if any check failed; all are attempted.
set -uo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# check_one NAME DIR PKG GOOS GOARCH OUTDIR: prints one result line, returns 1 on failure.
check_one() {
  local name="$1" dir="$2" pkg="$3" goos="$4" goarch="$5" out="$6"
  local bin="$out/${name}_${goos}_${goarch}" target="$goos/$goarch" cgo info
  [ "$goarch" = arm ] && export GOARM=7
  (
    cd "$dir" || exit 1
    [ "$dir" != "$repo_root" ] && export GOWORK=off
    export GOOS="$goos" GOARCH="$goarch"

    cgo="$(CGO_ENABLED=1 go list -deps -f '{{if and (not .Standard) .CgoFiles}}{{.ImportPath}}{{end}}' "$pkg" 2>"$bin.list.log")" || {
      printf '%-16s %-12s FAIL     go list failed\n' "$name" "$target"
      sed 's/^/    /' "$bin.list.log" | head -10
      exit 1
    }
    if [ -n "$cgo" ]; then
      printf '%-16s %-12s FAIL     imports "C": %s\n' "$name" "$target" "$(echo "$cgo" | tr '\n' ' ')"
      exit 1
    fi

    if ! CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o "$bin" "$pkg" >"$bin.log" 2>&1; then
      printf '%-16s %-12s FAIL     go build with CGO_ENABLED=0\n' "$name" "$target"
      sed 's/^/    /' "$bin.log" | head -10
      exit 1
    fi

    info="$(go version -m "$bin" 2>&1)"
    if ! grep -q 'CGO_ENABLED=0' <<<"$info" || grep -qE 'linkmode=external|-extld' <<<"$info"; then
      printf '%-16s %-12s FAIL     not a static pure-Go build (go version -m)\n' "$name" "$target"
      exit 1
    fi
    printf '%-16s %-12s ok       static, no cgo\n' "$name" "$target"
  )
}

# run_checks OUTDIR TARGETS COMPONENT...: returns 1 if any check failed.
run_checks() {
  local out="$1" targets="$2"
  shift 2
  local failed=0 target c name dir pkg
  local -a target_list
  IFS=',' read -r -a target_list <<<"$targets"
  for target in "${target_list[@]}"; do
    for c in "$@"; do
      IFS=':' read -r name dir pkg <<<"$c"
      case "$dir" in /*) ;; *) dir="$repo_root/$dir" ;; esac
      dir="${dir%/.}"
      check_one "$name" "$dir" "$pkg" "${target%%/*}" "${target##*/}" "$out" || failed=1
    done
  done
  return "$failed"
}

self_test() {
  local work fixtures rc=0
  work="$(mktemp -d)"
  fixtures="$work/fixtures"
  mkdir -p "$fixtures/purego" "$fixtures/cgo"
  printf 'module fixture\n\ngo 1.21\n' | tee "$fixtures/purego/go.mod" >"$fixtures/cgo/go.mod"
  printf 'package main\n\nfunc main() {}\n' >"$fixtures/purego/main.go"
  cat >"$fixtures/cgo/main.go" <<'EOF'
package main

// int answer(void) { return 42; }
import "C"

func main() { _ = C.answer() }
EOF
  local targets=linux/arm64,linux/arm
  echo "self-test: pure-Go fixture must pass"
  if ! run_checks "$work" "$targets" "purego:$fixtures/purego:."; then
    echo "self-test FAILED: the guard rejected a pure-Go package" >&2
    rc=1
  fi
  echo "self-test: fixture importing \"C\" must be rejected"
  if run_checks "$work" "$targets" "cgo:$fixtures/cgo:."; then
    echo "self-test FAILED: the guard accepted a package that imports \"C\"" >&2
    rc=1
  fi
  [ "$rc" -eq 0 ] && echo "self-test ok: green on pure Go, red on import \"C\""
  return "$rc"
}

out=""
targets="linux/arm64,linux/arm"
components=()
while [ $# -gt 0 ]; do
  case "$1" in
    --out) out="$2"; shift 2 ;;
    --targets) targets="$2"; shift 2 ;;
    --component) components+=("$2"); shift 2 ;;
    --self-test) self_test; exit $? ;;
    -h|--help) sed -n '2,32p' "$0"; exit 0 ;;
    *) echo "crossbuild-check.sh: unknown argument: $1" >&2; exit 2 ;;
  esac
done
[ "${#components[@]}" -gt 0 ] || components=("keyorix-server:.:./server" "keyorix:cli:.")
[ -n "$out" ] || out="$(mktemp -d)"
mkdir -p "$out"
out="$(cd "$out" && pwd)"

printf '%-16s %-12s %-8s %s\n' component target result detail
if run_checks "$out" "$targets" "${components[@]}"; then
  echo "crossbuild-check: all builds static and cgo-free (cross-compile only; running on ARM hardware is pending device)"
else
  echo "crossbuild-check: FAILED (logs in $out)" >&2
  exit 1
fi
