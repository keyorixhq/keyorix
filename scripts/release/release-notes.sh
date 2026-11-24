#!/usr/bin/env bash
# scripts/release/release-notes.sh -- the GitHub Release body for a tag (REL-NOTES-LIMIT-1).
#
# GitHub rejects a release body over 125000 characters (HTTP 422 "body is too long"). v0.97.0-rc.1
# failed that way: --generate-notes over ~1000 merged PRs. release.yml calls this script and passes
# the result to `gh release create --notes-file`, so the body is decided and bounded in one place.
#
# Usage:
#   release-notes.sh <tag> <previous-tag> <owner/repo>   body on stdout; non-zero if it cannot be bounded
#   release-notes.sh --previous-tag <tag>                reads tag names on stdin, prints the newest
#                                                        FINAL tag below <tag> (an rc compares against
#                                                        the final before its own version)
#
# Body rules:
#   *-rc.*   fixed short text plus a compare link (the workflow also marks the release a pre-release);
#   final    docs/releases/<tag>.md if it exists (fails if it is 125000+ characters: never cut an
#            author-written file silently), else the GitHub-generated notes, cut at a line boundary
#            so the body, including the trailing "Full list: <compare URL>" line, stays under
#            RELNOTES_TARGET characters (default 100000).
# Characters, not bytes. Test hooks: RELNOTES_GENERATED_FILE replaces the `gh api` call,
# RELNOTES_DOCS_DIR replaces docs/releases.
set -euo pipefail

HARD_LIMIT=125000
TARGET="${RELNOTES_TARGET:-100000}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOCS_DIR="${RELNOTES_DOCS_DIR:-$HERE/../../docs/releases}"

die() { echo "release-notes.sh: $*" >&2; exit 1; }

if [ "${1:-}" = "--previous-tag" ]; then
    [ $# -eq 2 ] || die "usage: release-notes.sh --previous-tag <tag> < tag-list"
    base="${2%%-rc.*}"
    { cat; echo "$base"; } | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | sort -uV |
        awk -v b="$base" '$0 == b { print prev; exit } { prev = $0 }'
    exit 0
fi

[ $# -eq 3 ] || die "usage: release-notes.sh <tag> <previous-tag> <owner/repo>"
TAG="$1"
PREV="$2"
REPO="$3"
command -v perl >/dev/null || die "perl is required (character-accurate counting)"

if [ -n "$PREV" ]; then
    COMPARE="https://github.com/$REPO/compare/$PREV...$TAG"
else
    COMPARE="https://github.com/$REPO/commits/$TAG"
fi

chars() { perl -CSD -0777 -ne 'print length($_)' <"$1"; }

case "$TAG" in
*-rc.*)
    base="${TAG%%-rc.*}"
    printf 'Release candidate for %s. Not for production use. Release notes are published with the final tag.\n' "$base"
    if [ -n "$PREV" ]; then printf '\nChanges since %s: %s\n' "$PREV" "$COMPARE"; fi
    exit 0
    ;;
esac

OUT="$(mktemp)"
trap 'rm -f "$OUT" "$OUT.cut"' EXIT

if [ -f "$DOCS_DIR/$TAG.md" ]; then
    cp "$DOCS_DIR/$TAG.md" "$OUT"
    n="$(chars "$OUT")"
    [ "$n" -lt "$HARD_LIMIT" ] || die "$DOCS_DIR/$TAG.md is $n characters; GitHub allows at most $HARD_LIMIT"
    cat "$OUT"
    exit 0
fi

if [ -n "${RELNOTES_GENERATED_FILE:-}" ]; then
    cp "$RELNOTES_GENERATED_FILE" "$OUT"
else
    args=(-f "tag_name=$TAG")
    if [ -n "$PREV" ]; then args+=(-f "previous_tag_name=$PREV"); fi
    gh api "repos/$REPO/releases/generate-notes" "${args[@]}" --jq .body >"$OUT" ||
        die "gh api generate-notes failed for $TAG"
fi
[ -s "$OUT" ] || die "generated notes for $TAG are empty"

FOOTER="Full list: $COMPARE"
n="$(chars "$OUT")"
if [ "$n" -lt "$TARGET" ]; then
    cat "$OUT"
    exit 0
fi

# Too long: keep whole lines while body + blank line + footer fits under the target.
perl -CSD -e '
    my ($target, $footer) = @ARGV;
    my $budget = $target - length($footer) - 2;    # "\n\n" before the footer
    local $/ = "\n";
    my ($out, $len) = ("", 0);
    while (my $line = <STDIN>) {
        last if $len + length($line) > $budget;
        $out .= $line; $len += length($line);
    }
    $out =~ s/\s+\z//;
    print "$out\n\n$footer\n";
' "$TARGET" "$FOOTER" <"$OUT" >"$OUT.cut"
mv "$OUT.cut" "$OUT"
n="$(chars "$OUT")"
[ "$n" -lt "$HARD_LIMIT" ] || die "body is still $n characters after cutting"
cat "$OUT"
