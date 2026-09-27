#!/bin/bash
# gen-targets-conf.sh — regenerates scripts/fuzzing/targets.conf from the
# per-target source files in scripts/fuzzing/targets.d/.
#
# targets.conf itself is GENERATED, not hand-maintained: the external
# fuzz-harness rig repo still reads the flat file (see targets.d/README.md
# for the handoff to point it at targets.d directly instead), so this script
# keeps producing it from the real source of truth. Adding a fuzz target no
# longer means editing a single shared file that every other target's PR also
# touches (the recurring merge-conflict problem this replaces) — it means
# adding one new file under targets.d/, which cannot conflict with anyone
# else's new file.
#
# Usage:
#   scripts/fuzzing/gen-targets-conf.sh          # regenerate targets.conf in place
#   scripts/fuzzing/gen-targets-conf.sh --check  # exit 1 if targets.conf is stale
set -euo pipefail
# Byte-order glob expansion: the output must be identical on macOS and the
# Linux CI runner regardless of either machine's locale collation.
export LC_ALL=C

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TARGETS_D="$REPO_ROOT/scripts/fuzzing/targets.d"
OUT="$REPO_ROOT/scripts/fuzzing/targets.conf"
HEADER="$REPO_ROOT/scripts/fuzzing/targets.d/HEADER.txt"

tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT

cat "$HEADER" > "$tmp"
echo >> "$tmp"

first=1
for f in "$TARGETS_D"/*.conf; do
    if [ "$first" -eq 0 ]; then
        echo >> "$tmp"
    fi
    first=0
    cat "$f" >> "$tmp"
done

if [ "${1:-}" = "--check" ]; then
    if ! diff -u "$OUT" "$tmp" >&2; then
        echo "FAIL: $OUT is stale — run scripts/fuzzing/gen-targets-conf.sh and commit the result" >&2
        exit 1
    fi
    echo "ok: $OUT matches scripts/fuzzing/targets.d/*.conf"
    exit 0
fi

cp "$tmp" "$OUT"
echo "wrote $OUT from $(ls "$TARGETS_D"/*.conf | wc -l | tr -d ' ') target file(s)"
