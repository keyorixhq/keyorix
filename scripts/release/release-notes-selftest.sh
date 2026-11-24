#!/usr/bin/env bash
# scripts/release/release-notes-selftest.sh -- self-test of release-notes.sh (REL-NOTES-LIMIT-1).
#
# No network, no gh: the generated body comes from RELNOTES_GENERATED_FILE, the notes file from a
# fixture RELNOTES_DOCS_DIR. Red AND green:
#   1. a 300000-character generated body (multi-byte text included) is cut below the limit, ends with
#      the "Full list:" compare link and is cut at a line boundary;
#   2. a short generated body passes unchanged;
#   3. an rc tag gets the fixed body plus the compare link, and ignores a notes file;
#   4. a notes file wins over the generated body; one of 125000+ characters fails;
#   5. an empty generated body fails; no previous tag falls back to a commits link;
#   6. --previous-tag picks the newest final tag below the version, for final and rc tags.
#
# Usage: scripts/release/release-notes-selftest.sh   (exit 0 = all cases green)
# No `set -e`: a failing assertion must be counted by check(), not abort the run.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NOTES="$HERE/release-notes.sh"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
FAILS=0
check() { # <name> <exit-status-of-the-case> (0 = pass)
    if [ "$2" -eq 0 ]; then echo "PASS: $1"; else echo "FAIL: $1"; FAILS=$((FAILS + 1)); fi
}
assert() { # <name> <command...>
    local name="$1" st=0
    shift
    "$@" || st=$?
    check "$name" "$st"
}
nchars() { perl -CSD -0777 -ne 'print length($_)' <"$1"; }

REPO=acme/widgets
PREV=v0.96.3
TAG=v0.97.0
LINK="https://github.com/$REPO/compare/$PREV...$TAG"
mkdir -p "$WORK/docs"
export RELNOTES_DOCS_DIR="$WORK/docs"

# --- 1. oversized generated body ---------------------------------------------------------------------
perl -CSD -e 'use utf8; for my $i (1..6000) { printf "* PR %05d: tighten the café handling by \@someone in #%d\n", $i, $i }' >"$WORK/big.md"
[ "$(nchars "$WORK/big.md")" -gt 300000 ] || { echo "FAIL: fixture is not over 300000 characters"; exit 1; }
export RELNOTES_GENERATED_FILE="$WORK/big.md"
rc=0
"$NOTES" "$TAG" "$PREV" "$REPO" >"$WORK/out1.md" || rc=$?
check "oversized body: exit 0" "$rc"
assert "oversized body: under 100000 characters" [ "$(nchars "$WORK/out1.md")" -lt 100000 ]
assert "oversized body: ends with the compare link" [ "$(tail -n 1 "$WORK/out1.md")" = "Full list: $LINK" ]
# every line before the footer is a whole generated line (cut at a line boundary)
perl -CSD -ne 'use utf8; push @l, $_; END { exit 1 if @l < 10; splice @l, -2; for (@l) { exit 1 unless /^\* PR \d{5}: tighten the café handling by \@someone in #\d+$/ } }' "$WORK/out1.md"
check "oversized body: cut at a line boundary" $?

# --- 2. short generated body unchanged ---------------------------------------------------------------
printf '## What'"'"'s Changed\n* one by @a in #1\n' >"$WORK/short.md"
export RELNOTES_GENERATED_FILE="$WORK/short.md"
"$NOTES" "$TAG" "$PREV" "$REPO" >"$WORK/out2.md"
cmp -s "$WORK/short.md" "$WORK/out2.md"; check "short body passes unchanged" $?

# --- 3. rc tag ---------------------------------------------------------------------------------------
printf 'notes file that an rc must ignore\n' >"$WORK/docs/v0.97.0-rc.1.md"
"$NOTES" v0.97.0-rc.1 "$PREV" "$REPO" >"$WORK/out3.md"
grep -qF "Release candidate for v0.97.0. Not for production use. Release notes are published with the final tag." "$WORK/out3.md"
check "rc tag: fixed body" $?
grep -qF "https://github.com/$REPO/compare/$PREV...v0.97.0-rc.1" "$WORK/out3.md"; check "rc tag: compare link" $?
! grep -q "must ignore" "$WORK/out3.md"; check "rc tag: ignores a notes file" $?
assert "rc tag: short" [ "$(nchars "$WORK/out3.md")" -lt 1000 ]

# --- 4. notes file wins ------------------------------------------------------------------------------
printf '# v0.97.0\nhand-written\n' >"$WORK/docs/$TAG.md"
export RELNOTES_GENERATED_FILE="$WORK/big.md"
"$NOTES" "$TAG" "$PREV" "$REPO" >"$WORK/out4.md"
cmp -s "$WORK/docs/$TAG.md" "$WORK/out4.md"; check "notes file wins over a generated body" $?
perl -e 'print "x" x 125000, "\n"' >"$WORK/docs/$TAG.md"
rc=0
"$NOTES" "$TAG" "$PREV" "$REPO" >/dev/null 2>"$WORK/err4.txt" || rc=$?
assert "notes file of 125000+ characters fails" [ "$rc" -ne 0 ]
rm "$WORK/docs/$TAG.md"

# --- 5. failure and fallback -------------------------------------------------------------------------
: >"$WORK/empty.md"
export RELNOTES_GENERATED_FILE="$WORK/empty.md"
rc=0
"$NOTES" "$TAG" "$PREV" "$REPO" >/dev/null 2>&1 || rc=$?
assert "empty generated body fails" [ "$rc" -ne 0 ]
export RELNOTES_GENERATED_FILE="$WORK/big.md"
"$NOTES" "$TAG" "" "$REPO" >"$WORK/out5.md"
assert "no previous tag: commits link" [ "$(tail -n 1 "$WORK/out5.md")" = "Full list: https://github.com/$REPO/commits/$TAG" ]

# --- 6. --previous-tag -------------------------------------------------------------------------------
printf '%s\n' v0.9.9 v0.96.3 v0.96.10 v0.97.0-rc.1 v0.97.0 v0.96.4-rc.1 v1.0.0 >"$WORK/tags.txt"
assert "previous tag of a final (numeric order)" [ "$("$NOTES" --previous-tag v0.97.0 <"$WORK/tags.txt")" = v0.96.10 ]
assert "previous tag of an rc skips rc tags and its own final" [ "$("$NOTES" --previous-tag v0.97.0-rc.1 <"$WORK/tags.txt")" = v0.96.10 ]
assert "previous tag of the oldest is empty" [ -z "$("$NOTES" --previous-tag v0.9.9 <"$WORK/tags.txt")" ]

if [ "$FAILS" -ne 0 ]; then echo "release-notes-selftest: $FAILS case(s) FAILED"; exit 1; fi
echo "release-notes-selftest: all cases PASS"
