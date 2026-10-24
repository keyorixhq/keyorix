#!/usr/bin/env bash
# measure-core.sh — the before/after numbers an ADR-116 extraction PR pastes:
#   1. the build-cache archive sizes of CORE-SPLIT-DESIGN-1 section 3.2
#      (go list -test -export; compiles the listed packages' tests first);
#   2. the test-side counts of section 3.7 (scripts/refactor/coretestclass):
#      in-package test files, black-box files, wave files, each also with
#      c.storage/c.now treated as reachable, plus their 30-day edit counts.
#
# Usage: scripts/refactor/measure-core.sh [--importers] [--since 30.days] [--ref origin/main]
#   --importers  also sum the archives of every package importing internal/core
#                directly (prod + test variants; compiles all their tests, minutes).
#
# Run from the repository root. Progress goes to stderr, tables to stdout.
# Not measured here: test time per set (needs a full `go test -json` run of
# internal/core) and GOCACHE growth (the cache is shared; see the design's
# section 11). Edit counts are first-parent commits on --ref touching each file.
set -euo pipefail

importers=0
since="30.days"
ref="origin/main"
while [ $# -gt 0 ]; do
	case "$1" in
	--importers) importers=1 ;;
	--since) since="$2"; shift ;;
	--ref) ref="$2"; shift ;;
	-h | --help) sed -n '2,17p' "$0"; exit 0 ;;
	*) echo "measure-core.sh: unknown argument $1 (try --help)" >&2; exit 2 ;;
	esac
	shift
done

mod=github.com/keyorixhq/keyorix
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

mb() { awk -v b="$1" 'BEGIN { printf "%.1f", b / 1048576 }'; }

# archive_rows <pkgs...>: "<label>\t<bytes>" for every compiled archive go list
# reports for the packages and their test variants.
archive_rows() {
	go list -test -export -f '{{.ImportPath}}	{{.Export}}' "$@" | while IFS='	' read -r path export; do
		[ -n "$export" ] || continue
		[ -f "$export" ] || continue
		printf '%s\t%s\n' "${path//$mod\//}" "$(wc -c <"$export" | tr -d ' ')"
	done
}

echo "measure-core: compiling test archives of core, handlers, http, grpc/services, server (cached runs are fast)..." >&2
archive_rows ./internal/core ./server/http/handlers ./server/http ./server/grpc/services ./server >"$work/archives.tsv"

echo "## Archives in the build cache (section 3.2)"
echo
echo "| Archive | MB |"
echo "|---|---|"
sort -t '	' -k2,2nr "$work/archives.tsv" | head -12 | while IFS='	' read -r label bytes; do
	echo "| \`$label\` | $(mb "$bytes") |"
done

if [ "$importers" = 1 ]; then
	echo "measure-core: listing direct importers of internal/core and compiling their tests (slow)..." >&2
	go list -f '{{.ImportPath}} {{join .Imports " "}}' ./... | awk -v core="$mod/internal/core" '{ for (i = 2; i <= NF; i++) if ($i == core) { print $1; break } }' >"$work/importers.txt"
	n=$(wc -l <"$work/importers.txt" | tr -d ' ')
	# shellcheck disable=SC2046 # one package path per line, no spaces
	archive_rows ./internal/core $(cat "$work/importers.txt") >"$work/all.tsv"
	total=$(awk -F '	' '{ s += $2 } END { print s + 0 }' "$work/all.tsv")
	echo "| all archives of core + its $n direct importers, prod and test variants | $(mb "$total") ($(wc -l <"$work/all.tsv" | tr -d ' ') archives) |"
fi
echo

echo "measure-core: counting $since of edits on $ref under internal/core..." >&2
git log --first-parent --since="$since" --name-only --format= "$ref" -- internal/core |
	awk -F/ 'NF == 3 && $1 == "internal" && $2 == "core" { n[$3]++ } END { for (f in n) print f "\t" n[f] }' >"$work/edits.tsv"

echo "## Test side (section 3.7)"
echo
for relax in "" "storage,now"; do
	out="$work/sets${relax:+-relaxed}"
	mkdir -p "$out"
	echo "measure-core: classifying internal/core test files${relax:+ with $relax reachable}..." >&2
	go run ./scripts/refactor/coretestclass -relax "$relax" -out "$out" >"$out/table.txt"
	if [ -n "$relax" ]; then echo "### if $relax were reachable"; else echo "### today"; fi
	echo
	echo '```'
	cat "$out/table.txt"
	echo '```'
	echo
	echo "| Set | edits since $since (in-package = all current in-package test files) |"
	echo "|---|---|"
	for set in in-package blackbox wave; do
		edits=$(awk -F '	' 'NR == FNR { e[$1] = $2; next } { s += e[$1] } END { print s + 0 }' "$work/edits.tsv" "$out/$set.txt")
		echo "| $set | $edits |"
	done
	echo
done
echo "measure-core: done." >&2
