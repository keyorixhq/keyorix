#!/usr/bin/env bash
# cgo-dependency-guard.sh — fails if a shipped Keyorix binary can pick up cgo.
#
# Keyorix ships static, cgo-free binaries (every release build and Docker build
# sets CGO_ENABLED=0). That is a product property for air-gapped and on-premise
# installs: no libc, no C toolchain, plain cross-compiles. A transitive
# dependency can change it silently, so this guard checks:
#
#  1. DEPENDENCIES. For every shipped main package (TARGETS below) and each
#     GOOS it is built for, `go list -deps` with CGO_ENABLED=1 lists every
#     non-stdlib package that has cgo files (`import "C"`) ACTIVE for that
#     GOOS and tag set. cgo is switched on here on purpose: with
#     CGO_ENABLED=0 Go hides those files and nothing would show. A hit that
#     is not in ALLOWLIST (with a reason) fails. Build constraints are
#     evaluated, so a file gated by `//go:build darwin && cgo` counts for
#     darwin only, and a test-only import (go-sqlite3 behind
#     internal/testutil/sqlitetest) is outside the shipped graph and is not
#     reported.
#  2. BUILD COMMANDS. Every `go build` in the Makefile `release` recipe, in the
#     shipped Dockerfiles and in the release/docker-publish workflows must set
#     CGO_ENABLED=0 (on the line, or by an `ENV CGO_ENABLED=0` in the
#     Dockerfile).
#  3. BINARIES (only with --binaries DIR, run after `make release`). Each Go
#     binary in DIR must report `build CGO_ENABLED=0` in `go version -m` and
#     must not be built with the netcgo tag.
#  4. --self-test plants cgo packages in a throw-away module and proves the
#     checks above fire, and stay quiet on clean input.
#
# ALLOWLIST entries are "import/path|reason". An entry that no longer matches
# anything is reported as stale, so the list cannot rot unread.
#
# Usage: scripts/cgo-dependency-guard.sh [--binaries DIR] [--self-test]
# Exit 0: clean. Exit 1: a violation (stderr). Exit 2: usage or tool error.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# "import/path|reason". Add an entry only for a dependency that is unavoidable,
# with a reason a reviewer can check.
ALLOWLIST=(
	"github.com/prometheus/client_golang/prometheus|process_collector_mem_cgo_darwin.go is an optional darwin+cgo file for the process-memory collector; release builds set CGO_ENABLED=0, so it is inactive in every shipped binary (checks 2 and 3 enforce that)"
)

# "module dir|package|tags|GOOS list" — one row per shipped main package. Keep in
# step with the Makefile `release` recipe and the Dockerfiles.
TARGETS=(
	".|./server||linux darwin"
	".|./server|noaws,noazure,nogcp|linux"
	".|./cmd/keyorix-mcp||linux"
	".|./cmd/keyorix-k8s-sync||linux"
	"cli|.||linux darwin"
	"migrate|.||linux darwin"
	"operator|./cmd||linux"
)

die() { echo "cgo-dependency-guard: $*" >&2; exit 2; }
command -v go >/dev/null 2>&1 || die "go not found in PATH"

# cgo_packages DIR GOOS TAGS PKG: non-stdlib packages with active cgo files.
cgo_packages() {
	local dir="$1" goos="$2" tags="$3" pkg="$4" out errf
	# stderr stays out of the package list: on a cold module cache go prints
	# "go: downloading ..." lines there, which are not packages.
	errf="$(mktemp)"
	if ! out="$(cd "$dir" && GOWORK=off GOOS="$goos" CGO_ENABLED=1 go list ${tags:+-tags "$tags"} -deps \
		-f '{{if and .CgoFiles (not .Standard)}}{{.ImportPath}}{{end}}' "$pkg" 2>"$errf")"; then
		echo "cgo-dependency-guard: go list failed in $dir for $pkg ($goos):" >&2
		echo "$out" >&2
		cat "$errf" >&2
		rm -f "$errf"
		return 2
	fi
	rm -f "$errf"
	printf '%s\n' "$out" | sed '/^$/d' | sort -u
}

USED_ALLOW=""
in_allowlist() {
	local pkg="$1" entry prefix
	for entry in "${ALLOWLIST[@]+"${ALLOWLIST[@]}"}"; do
		prefix="${entry%%|*}"
		if [ "$pkg" = "$prefix" ]; then
			USED_ALLOW="$USED_ALLOW $prefix"
			return 0
		fi
	done
	return 1
}

VIOLATIONS=0
check_dependencies() {
	local row dir pkg tags goses goos found p
	for row in "$@"; do
		IFS='|' read -r dir pkg tags goses <<<"$row"
		for goos in $goses; do
			found="$(cgo_packages "$dir" "$goos" "$tags" "$pkg")" || exit 2
			while IFS= read -r p; do
				[ -z "$p" ] && continue
				if in_allowlist "$p"; then continue; fi
				echo "cgo-dependency-guard: $dir $pkg [$goos${tags:+ tags=$tags}] links a package with cgo files:" >&2
				echo "  $p" >&2
				VIOLATIONS=$((VIOLATIONS + 1))
			done <<<"$found"
		done
	done
}

stale_allowlist() {
	local entry prefix n=0
	for entry in "${ALLOWLIST[@]+"${ALLOWLIST[@]}"}"; do
		prefix="${entry%%|*}"
		case " $USED_ALLOW " in
		*" $prefix "*) ;;
		*)
			echo "cgo-dependency-guard: stale ALLOWLIST entry (no shipped binary links it any more): $prefix" >&2
			n=$((n + 1))
			;;
		esac
	done
	return $n
}

# lint_stream LABEL ENV_OK: stdin = lines; every non-comment line with
# `go build` must carry CGO_ENABLED=0 unless ENV_OK=1 (an ENV CGO_ENABLED=0 was
# seen in the file). Returns the number of offending lines.
lint_stream() {
	local label="$1" env_ok="$2" n=0 line trimmed
	while IFS= read -r line; do
		case "$line" in
		*"go build"*)
			trimmed="${line#"${line%%[![:space:]]*}"}"
			case "$trimmed" in
			\#*) continue ;;
			esac
			[ "$env_ok" = 1 ] && continue
			case "$line" in
			*"CGO_ENABLED=0"*) ;;
			*)
				echo "cgo-dependency-guard: $label: go build without CGO_ENABLED=0: $line" >&2
				n=$((n + 1))
				;;
			esac
			;;
		esac
	done
	return $n
}

# release_recipe FILE: the lines of the Makefile `release:` recipe.
release_recipe() {
	awk '/^release:/ {on=1; next} on && /^[^\t#[:space:]]/ {on=0} on {print}' "$1"
}

check_build_commands() {
	local f n=0 env_ok list recipe
	recipe="$(release_recipe "$repo_root/Makefile")"
	if [ -z "$recipe" ]; then
		echo "cgo-dependency-guard: Makefile has no 'release:' recipe to lint (renamed? update this guard)" >&2
		n=$((n + 1))
	else
		printf '%s\n' "$recipe" | lint_stream "Makefile (release recipe)" 0 || n=$((n + $?))
	fi
	list="$(cd "$repo_root" && git ls-files | grep -E '(^|/)Dockerfile[^/]*$' | grep -vE '^(web/|scripts/dast/)' || true)"
	while IFS= read -r f; do
		[ -z "$f" ] && continue
		env_ok=0
		grep -qE '^[[:space:]]*(ENV|ARG)[[:space:]]+CGO_ENABLED=0' "$repo_root/$f" && env_ok=1
		lint_stream "$f" "$env_ok" <"$repo_root/$f" || n=$((n + $?))
	done <<<"$list"
	for f in .github/workflows/release.yml .github/workflows/docker-publish.yml; do
		[ -f "$repo_root/$f" ] || continue
		lint_stream "$f" 0 <"$repo_root/$f" || n=$((n + $?))
	done
	VIOLATIONS=$((VIOLATIONS + n))
}

check_binaries() {
	local dir="$1" f info n=0 checked=0
	[ -d "$dir" ] || die "--binaries: $dir is not a directory"
	for f in "$dir"/*; do
		[ -f "$f" ] || continue
		info="$(go version -m "$f" 2>/dev/null)" || continue
		[ -n "$info" ] || continue
		checked=$((checked + 1))
		if ! printf '%s\n' "$info" | grep -qE '^[[:space:]]*build[[:space:]]+CGO_ENABLED=0[[:space:]]*$'; then
			echo "cgo-dependency-guard: $(basename "$f"): build info does not say CGO_ENABLED=0" >&2
			n=$((n + 1))
		fi
		if printf '%s\n' "$info" | grep -E '^[[:space:]]*build[[:space:]]+-tags=' | grep -qE '(=|,)netcgo(,|[[:space:]]*$)'; then
			echo "cgo-dependency-guard: $(basename "$f"): built with the netcgo tag" >&2
			n=$((n + 1))
		fi
	done
	if [ "$checked" -eq 0 ]; then
		echo "cgo-dependency-guard: --binaries $dir: no Go binary found to check (did 'make release' run?)" >&2
		n=$((n + 1))
	else
		echo "cgo-dependency-guard: inspected $checked binaries in $dir"
	fi
	VIOLATIONS=$((VIOLATIONS + n))
}

self_test() {
	local tmp rc=0 got
	tmp="$(mktemp -d)"
	trap 'rm -rf "$tmp"' RETURN
	mkdir -p "$tmp/dirty" "$tmp/gated" "$tmp/clean" "$tmp/usesdirty" "$tmp/usesgated" "$tmp/usesclean" "$tmp/bin"
	printf 'module example.test/cgoguard\n\ngo 1.21\n' >"$tmp/go.mod"
	printf 'package dirty\n\nimport "C"\n' >"$tmp/dirty/d.go"
	printf '//go:build darwin && cgo\n\npackage gated\n\nimport "C"\n' >"$tmp/gated/g_cgo.go"
	printf '//go:build !(darwin && cgo)\n\npackage gated\n' >"$tmp/gated/g_nocgo.go"
	printf 'package clean\n' >"$tmp/clean/c.go"
	printf 'package main\n\nimport _ "example.test/cgoguard/dirty"\n\nfunc main() {}\n' >"$tmp/usesdirty/m.go"
	printf 'package main\n\nimport _ "example.test/cgoguard/gated"\n\nfunc main() {}\n' >"$tmp/usesgated/m.go"
	printf 'package main\n\nimport _ "example.test/cgoguard/clean"\n\nfunc main() {}\n' >"$tmp/usesclean/m.go"

	count() { printf '%s\n' "$1" | sed '/^$/d' | wc -l | tr -d ' '; }
	expect() { # DESC WANT GOT
		if [ "$2" != "$3" ]; then
			echo "self-test FAIL: $1 (wanted $2, got $3)" >&2
			rc=1
		else
			echo "self-test ok: $1"
		fi
	}

	expect 'package with import "C" is found on linux' 1 "$(count "$(cgo_packages "$tmp" linux "" ./usesdirty)")"
	expect "darwin+cgo gated file is quiet on linux" 0 "$(count "$(cgo_packages "$tmp" linux "" ./usesgated)")"
	expect "darwin+cgo gated file is found on darwin" 1 "$(count "$(cgo_packages "$tmp" darwin "" ./usesgated)")"
	expect "clean package has no finding" 0 "$(count "$(cgo_packages "$tmp" linux "" ./usesclean)")"

	got="$(printf '\tGOOS=linux go build -o x ./server\n\tCGO_ENABLED=0 go build -o y ./server\n    # go build in an indented comment\n' | lint_stream t 0 2>&1 >/dev/null || true)"
	expect "lint flags only the go build without CGO_ENABLED=0" 1 "$(count "$got")"
	got="$(printf 'RUN go build ./...\n' | lint_stream t 1 2>&1 >/dev/null || true)"
	expect "lint accepts a Dockerfile with ENV CGO_ENABLED=0" 0 "$(count "$got")"

	(cd "$tmp" && GOWORK=off CGO_ENABLED=0 go build -o bin/nocgo ./usesclean)
	if (cd "$tmp" && GOWORK=off CGO_ENABLED=1 go build -o bin/withcgo ./usesclean) 2>/dev/null; then
		VIOLATIONS=0
		check_binaries "$tmp/bin" >/dev/null 2>&1 || true
		expect "binaries mode flags exactly the CGO_ENABLED=1 binary" 1 "$VIOLATIONS"
	else
		echo "self-test skipped: no C toolchain to build a CGO_ENABLED=1 binary"
	fi
	VIOLATIONS=0
	return $rc
}

mode_binaries=""
mode_selftest=0
while [ $# -gt 0 ]; do
	case "$1" in
	--binaries)
		[ $# -ge 2 ] || die "--binaries needs a directory"
		mode_binaries="$2"
		shift 2
		;;
	--self-test)
		mode_selftest=1
		shift
		;;
	-h | --help)
		sed -n '2,37p' "${BASH_SOURCE[0]}"
		exit 0
		;;
	*) die "unknown argument: $1" ;;
	esac
done

if [ "$mode_selftest" = 1 ]; then
	self_test
	exit $?
fi

if [ -n "$mode_binaries" ]; then
	check_binaries "$mode_binaries"
else
	check_dependencies "${TARGETS[@]}"
	stale_allowlist || VIOLATIONS=$((VIOLATIONS + $?))
	check_build_commands
fi

if [ "$VIOLATIONS" -gt 0 ]; then
	echo "" >&2
	echo "cgo-dependency-guard: $VIOLATIONS violation(s). Keyorix ships cgo-free static binaries (CGO_ENABLED=0)." >&2
	echo "  Remove the dependency, or add it to ALLOWLIST in scripts/cgo-dependency-guard.sh with a reason a reviewer can check." >&2
	exit 1
fi
echo "cgo-dependency-guard: ok (no shipped binary links a cgo package; release builds set CGO_ENABLED=0)"
