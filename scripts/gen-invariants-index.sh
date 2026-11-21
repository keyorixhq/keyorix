#!/bin/bash
# gen-invariants-index.sh — regenerates the package table of docs/INVARIANTS.md
# (between the BEGIN/END GENERATED markers) from the real per-package
# INVARIANTS.md files and their INVARIANTS.d/ fragments.
#
# The table is GENERATED, not hand-maintained. Adding or changing an invariant
# means editing only the package's own INVARIANTS.md / INVARIANTS.d/ file; the
# shared index is refreshed by running this script. A PR that touches one
# package's invariants therefore no longer edits the most-conflicted file in the
# merge queue, and a new package's first INVARIANTS.md gets its row by itself.
#
# CONFLICT RESOLUTION (one line): if two PRs both regenerated the block, take
# main's docs/INVARIANTS.md and rerun scripts/gen-invariants-index.sh.
#
# Usage:
#   scripts/gen-invariants-index.sh          # regenerate the block in place
#   scripts/gen-invariants-index.sh --check  # exit 1 if the block is stale
#   scripts/gen-invariants-index.sh --root DIR ...  # operate on another tree
#                                                   # (test fixtures)
# Exit codes: 0 ok, 1 stale (--check only), 2 usage or a broken marker pair.
#
# Counting rules (the ones docs/INVARIANTS.md "Maintaining this index" states):
#   - a package is every <dir>/INVARIANTS.md (docs/INVARIANTS.md itself and
#     everything under the top-level fuzzkit/ module are excluded: fuzzkit/ is a
#     separate module whose invariants are deliberately not in this table);
#   - Invariants = the column-0 "- **INV-<PKG>-<id>**" bullets of that file
#     (a bullet runs to the next column-0 line) plus one per
#     <dir>/INVARIANTS.d/INV-*.md fragment;
#   - UNGUARDED = the bullets / fragments whose OWN text contains the word. It
#     is never a raw grep -c over the file: each file's intro "Format:" line
#     contains the literal word and is not inside any bullet;
#   - Guarded = Invariants - UNGUARDED.
# Rows are sorted by package directory in byte order (LC_ALL=C), so the output
# is identical on macOS and Linux.
set -euo pipefail
# Byte-order sort and glob: must not depend on either machine's locale.
export LC_ALL=C

BEGIN_MARK='<!-- BEGIN GENERATED: package table -->'
END_MARK='<!-- END GENERATED: package table -->'

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHECK=0
while [ $# -gt 0 ]; do
    case "$1" in
        --check) CHECK=1 ;;
        --root)
            if [ $# -lt 2 ]; then echo "usage: --root needs a directory" >&2; exit 2; fi
            ROOT="$(cd "$2" && pwd)"
            shift
            ;;
        *) echo "usage: $0 [--check] [--root DIR]" >&2; exit 2 ;;
    esac
    shift
done

DOC="$ROOT/docs/INVARIANTS.md"
if [ ! -f "$DOC" ]; then
    echo "FAIL: $DOC not found" >&2
    exit 2
fi

# The marker pair must be present exactly once each, BEGIN before END. Anything
# else would make the replacement ambiguous, so refuse without touching the file.
n_begin=$(grep -c -x -F "$BEGIN_MARK" "$DOC" || true)
n_end=$(grep -c -x -F "$END_MARK" "$DOC" || true)
if [ "$n_begin" -ne 1 ] || [ "$n_end" -ne 1 ]; then
    echo "FAIL: $DOC must contain exactly one '$BEGIN_MARK' and one '$END_MARK' line (found $n_begin / $n_end)" >&2
    exit 2
fi
line_begin=$(grep -n -x -F "$BEGIN_MARK" "$DOC" | cut -d: -f1)
line_end=$(grep -n -x -F "$END_MARK" "$DOC" | cut -d: -f1)
if [ "$line_begin" -ge "$line_end" ]; then
    echo "FAIL: $DOC has the END GENERATED marker (line $line_end) before the BEGIN marker (line $line_begin)" >&2
    exit 2
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# Every package file and fragment, sorted. find, not git ls-files: the same code
# path serves a fixture tree and a checkout, and a brand-new INVARIANTS.md gets
# its row before it is `git add`ed.
(
    cd "$ROOT"
    find . \( -name .git -o -name .claude -o -name .scratch -o -name node_modules -o -path ./fuzzkit \) -prune -o \
        -type f \( -name INVARIANTS.md -o -path '*/INVARIANTS.d/INV-*.md' \) \
        ! -path ./docs/INVARIANTS.md -print
) | sort > "$tmp/files"

files=()
while IFS= read -r f; do
    files+=("$ROOT/${f#./}")
done < "$tmp/files"

: > "$tmp/counts"
if [ "${#files[@]}" -gt 0 ]; then
    awk -v root="$ROOT/" '
        function flush() {
            if (inb) { inv[pkg]++; if (ung) un[pkg]++; inb = 0; ung = 0 }
        }
        FNR == 1 {
            flush()
            f = FILENAME
            if (index(f, root) == 1) f = substr(f, length(root) + 1)
            frag = (f ~ /\/INVARIANTS\.d\/[^\/]+\.md$/)
            pkg = f
            if (frag) sub(/\/INVARIANTS\.d\/[^\/]+$/, "", pkg)
            else if (pkg ~ /\//) sub(/\/INVARIANTS\.md$/, "", pkg)
            else pkg = "."
            seen[pkg] = 1; inv[pkg] += 0; un[pkg] += 0
            if (frag) { inb = 1; ung = 0 }   # a fragment is one invariant: the whole file
        }
        {
            if (frag) { if (index($0, "UNGUARDED")) ung = 1; next }
            if ($0 ~ /^- \*\*INV-[^* \t]+\*\*/) { flush(); inb = 1; ung = 0 }
            else if ($0 ~ /^[^ \t]/) flush()   # a column-0 line ends the bullet
            if (inb && index($0, "UNGUARDED")) ung = 1
        }
        END {
            flush()
            for (p in seen) printf "%s\t%d\t%d\n", p, inv[p], un[p]
        }
    ' "${files[@]}" | sort > "$tmp/counts"
fi

# Presentation-only decoration of a few row labels (kept from the hand-written
# table). Everything else is the bare package directory.
# The backticks are literal markdown, not command substitution.
# shellcheck disable=SC2016
label_suffix() {
    case "$1" in
        server/http) printf ' (+ `handlers`)' ;;
        server/grpc) printf ' (+ `interceptors`)' ;;
        server/pgfault) printf ' (test-only)' ;;
    esac
}

{
    echo "$BEGIN_MARK"
    echo '<!-- Generated by scripts/gen-invariants-index.sh from every <pkg>/INVARIANTS.md and <pkg>/INVARIANTS.d/. Do not edit by hand: on a conflict take main'"'"'s file and rerun the script. -->'
    echo '| Package | File | Invariants | Guarded | UNGUARDED |'
    echo '|---|---|---|---|---|'
    while IFS=$'\t' read -r pkg inv un; do
        [ -n "$pkg" ] || continue
        if [ "$pkg" = "." ]; then file="INVARIANTS.md"; else file="$pkg/INVARIANTS.md"; fi
        # shellcheck disable=SC2016
        printf '| `%s`%s | [%s](../%s) | %d | %d | %d |\n' \
            "$pkg" "$(label_suffix "$pkg")" "$file" "$file" "$inv" "$((inv - un))" "$un"
    done < "$tmp/counts"
    echo "$END_MARK"
} > "$tmp/block"

# Replace the marker pair (and everything between) with the new block; every
# other line is copied through unchanged.
awk -v blockfile="$tmp/block" -v b="$BEGIN_MARK" -v e="$END_MARK" '
    $0 == b { while ((getline l < blockfile) > 0) print l; skip = 1; next }
    $0 == e { skip = 0; next }
    !skip { print }
' "$DOC" > "$tmp/new"

if [ "$CHECK" -eq 1 ]; then
    if ! diff -u "$DOC" "$tmp/new" >&2; then
        echo "FAIL: the generated package table in $DOC is stale: run scripts/gen-invariants-index.sh and commit the result (on a merge conflict take main's file, then rerun it)" >&2
        exit 1
    fi
    echo "ok: $DOC package table matches the INVARIANTS.md files and INVARIANTS.d/ fragments"
    exit 0
fi

pkgs=$(grep -c . "$tmp/counts" || true)
totals=$(awk -F'\t' '{ i += $2; u += $3 } END { printf "%d invariants, %d guarded, %d UNGUARDED", i, i - u, u }' "$tmp/counts")
if cmp -s "$DOC" "$tmp/new"; then
    echo "$DOC already up to date ($pkgs packages: $totals)"
else
    cp "$tmp/new" "$DOC"
    echo "wrote $DOC ($pkgs packages: $totals)"
fi
