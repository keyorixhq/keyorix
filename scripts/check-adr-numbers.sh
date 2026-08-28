#!/bin/bash
# check-adr-numbers.sh — fails if two docs/adr-NNN-*.md files share a number.
#
# Caught missing: ADR-087 was used for both adr-087-remote-storage-deletion-pass.md
# and adr-087-system-proxy-layer-design.md (the latter renumbered to 088). An
# identifier that does not identify is a defect in a decision log, not a nit.
set -euo pipefail

dupes=$(find docs -maxdepth 1 -type f -name 'adr-[0-9]*.md' -print \
    | sed -E 's#.*/adr-([0-9]+)-.*#\1#' \
    | sort -n \
    | uniq -d)

if [ -n "$dupes" ]; then
    echo "FAIL: duplicate ADR number(s) found:"
    for n in $dupes; do
        find docs -maxdepth 1 -type f -name "adr-${n}-*.md"
    done
    exit 1
fi

echo "ok: every docs/adr-NNN-*.md number is unique"
