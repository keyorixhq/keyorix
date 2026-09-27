#!/bin/bash
# gen-security-closures-tsv.sh — regenerates docs/security-closures.tsv from
# the per-claim files in docs/security-closures.d/.
#
# docs/security-closures.tsv itself is GENERATED, not hand-maintained: adding
# a closure used to mean appending a line to one shared file, so any two
# closure PRs open at once were a guaranteed merge conflict (the same problem
# scripts/fuzzing/targets.d/ fixes for fuzz targets, C1 in this session).
# Adding a closure now means adding one new docs/security-closures.d/<id>.tsv
# file, which cannot conflict with anyone else's new file.
#
# scripts/check-closures.sh and scripts/check-adr-conformance.sh keep reading
# the flat generated docs/security-closures.tsv unchanged -- this script is
# the only thing that needs to know about the split.
#
# Usage:
#   scripts/gen-security-closures-tsv.sh          # regenerate in place
#   scripts/gen-security-closures-tsv.sh --check  # exit 1 if stale
set -euo pipefail
# Byte-order glob expansion: the output must be identical on macOS and the
# Linux CI runner regardless of either machine's locale collation.
export LC_ALL=C

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLOSURES_D="$REPO_ROOT/docs/security-closures.d"
OUT="$REPO_ROOT/docs/security-closures.tsv"
HEADER="$CLOSURES_D/HEADER.txt"

tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT

cat "$HEADER" > "$tmp"
echo >> "$tmp"

for f in "$CLOSURES_D"/*.tsv; do
    cat "$f" >> "$tmp"
done

if [ "${1:-}" = "--check" ]; then
    if ! diff -u "$OUT" "$tmp" >&2; then
        echo "FAIL: $OUT is stale -- run scripts/gen-security-closures-tsv.sh and commit the result" >&2
        exit 1
    fi
    echo "ok: $OUT matches docs/security-closures.d/*.tsv"
    exit 0
fi

cp "$tmp" "$OUT"
echo "wrote $OUT from $(ls "$CLOSURES_D"/*.tsv | wc -l | tr -d ' ') claim file(s)"
