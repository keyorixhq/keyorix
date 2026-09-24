#!/usr/bin/env bash
# mapsize_of_bin.sh — measure a Go native fuzz target's coverage-map size.
#
# ADR-109 (docs/adr-109-core-depends-on-interfaces.md) tracks each
# decoupling step by how much this shrinks for a core fuzz target. The
# authoritative rig runner (keyorixhq/fuzz-harness) has its own copy of this
# measurement used for the leaf-package A/B results the ADR cites; this
# script is a local, repo-side reproduction so the number can be measured
# from a plain checkout without that private repo. It was cross-checked
# against the ADR's own baseline figure (core's map "about 480 KB") before
# being trusted: FuzzCoreOperationSequence measures 486847 bytes (~475 KiB)
# here, which matches.
#
# Method: `go test -c -fuzz=<pattern>` is the only go test invocation that
# turns on fuzz coverage instrumentation (cmd/go only appends
# -d=libfuzzer to the compiler flags when the -fuzz flag is present at
# build time — see cmd/go/internal/test/test.go's testFuzz-gated loop and
# cmd/go/internal/work/gc.go's FuzzInstrument check). That instrumentation
# brackets the 8-bit coverage-counter array with two zero-size marker
# symbols, internal/fuzz._counters and internal/fuzz._ecounters, whose
# addresses cmd/link assigns specially (src/internal/fuzz/coverage.go).
# The byte distance between them IS the coverage map: every package pulled
# into the fuzz target's build graph contributes counters to this one
# shared array, which is exactly why decoupling internal/core from its
# integration packages shrinks it.
#
# Usage: mapsize_of_bin.sh <package-import-path> <FuzzFuncName>
# <package-import-path> is a Go import path relative to this module (e.g.
# ./internal/core), resolved against the repo root regardless of the
# caller's own working directory. Prints the coverage map size in bytes to
# stdout. Exit 0 on success.

set -euo pipefail

if [ "$#" -ne 2 ]; then
	echo "usage: $0 <package-import-path> <FuzzFuncName>" >&2
	exit 2
fi

pkg="$1"
fuzz_name="$2"

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

bin="$workdir/instrumented.bin"
nm_out="$workdir/nm.txt"

GOWORK=off go -C "$repo_root" test -c -fuzz="${fuzz_name}" -o "$bin" "$pkg"
go tool nm "$bin" > "$nm_out"

counters_line="$(grep -F 'internal/fuzz._counters' "$nm_out" || true)"
ecounters_line="$(grep -F 'internal/fuzz._ecounters' "$nm_out" || true)"

if [ -z "$counters_line" ] || [ -z "$ecounters_line" ]; then
	echo "mapsize_of_bin: internal/fuzz._counters/_ecounters not found — was $fuzz_name actually instrumented? (unsupported GOOS/GOARCH for fuzz instrumentation returns nil flags; see platform.FuzzInstrumented)" >&2
	exit 1
fi

counters_addr="0x$(echo "$counters_line" | awk '{print $1}')"
ecounters_addr="0x$(echo "$ecounters_line" | awk '{print $1}')"

python3 -c "print(${ecounters_addr} - ${counters_addr})"
