#!/usr/bin/env bash
# scripts/release-qa/restore_compat_matrix.sh -- the cross-version restore
# matrix (UPGRADE-RESTORE-COMPAT-1): for each release tag, build that
# release's keyorix-server + keyorix natively from the tag (git archive into
# the work dir: the checkout is not touched, no Docker), build HEAD the same
# way, then run scenario_restore_compat.sh OLD -> HEAD on SQLite and, when a
# DSN is given for that version, on PostgreSQL. Prints one result line per
# version at the end; exits non-zero if any leg failed.
#
# Usage: restore_compat_matrix.sh <work-dir> [--tags N] [<tag>[=<empty-postgres-dsn>] ...]
#   e.g. restore_compat_matrix.sh .scratch/rcm v0.95.3 v0.96.1="$(kpg dsn x_0961)"
#        restore_compat_matrix.sh .scratch/rcm --tags 3   # the newest 3 vX.Y.Z tags, SQLite only
#
# --tags N adds the newest N release tags (vX.Y.Z, no pre-releases; needs the tags
# fetched: git fetch --tags) to any tags given explicitly. It is meant for a nightly job.
# Each PostgreSQL DSN must name its own EMPTY database (restore refuses a
# populated target). Container and Helm legs are not covered here.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TAGS_N=""
ARGS=()
while [ $# -gt 0 ]; do
    case "$1" in
        --tags) TAGS_N="${2:-}"; [ $# -ge 2 ] && shift; shift ;;
        --tags=*) TAGS_N="${1#--tags=}"; shift ;;
        -h|--help) sed -n '2,16p' "$0"; exit 0 ;;
        *) ARGS+=("$1"); shift ;;
    esac
done
set -- "${ARGS[@]+"${ARGS[@]}"}"
if [ -n "$TAGS_N" ] && ! [[ "$TAGS_N" =~ ^[1-9][0-9]*$ ]]; then
    echo "--tags needs a positive number, got '$TAGS_N'" >&2
    exit 2
fi
if [ $# -lt 1 ] || { [ -z "$TAGS_N" ] && [ $# -lt 2 ]; }; then sed -n '2,16p' "$0" >&2; exit 2; fi
WORK="$1"
shift
if [ -n "$TAGS_N" ]; then
    declare -a LATEST=()
    while IFS= read -r t; do LATEST+=("$t"); done < <(git -C "$REPO_ROOT" tag --list 'v[0-9]*.[0-9]*.[0-9]*' --sort=-v:refname | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | head -n "$TAGS_N")
    if [ "${#LATEST[@]}" -eq 0 ]; then
        echo "--tags $TAGS_N: no vX.Y.Z tags in this checkout (git fetch --tags)" >&2
        exit 2
    fi
    echo "==> --tags $TAGS_N: ${LATEST[*]}" >&2
    for t in "${LATEST[@]}"; do
        dup=0
        for given in "$@"; do [ "${given%%=*}" = "$t" ] && dup=1; done
        [ "$dup" -eq 0 ] && set -- "$@" "$t"
    done
fi
mkdir -p "$WORK/bin"
WORK="$(cd "$WORK" && pwd)"

build() { # <label> <source-dir>
    echo "==> building $1" >&2
    (cd "$2" && go build -o "$WORK/bin/server-$1" ./server) || return 1
    (cd "$2/cli" && GOWORK=off go build -o "$WORK/bin/cli-$1" .) || return 1
}

build head "$REPO_ROOT" || { echo "build of HEAD failed" >&2; exit 1; }

declare -a RESULTS=()
status=0
for spec in "$@"; do
    tag="${spec%%=*}"
    dsn="-"
    [ "$spec" != "$tag" ] && dsn="${spec#*=}"
    src="$WORK/src-$tag"
    if [ ! -x "$WORK/bin/server-$tag" ]; then
        rm -rf "$src" && mkdir -p "$src"
        if ! git -C "$REPO_ROOT" archive "$tag" | tar -x --exclude='.claude' -C "$src" || ! build "$tag" "$src"; then
            RESULTS+=("$tag: BUILD FAILED")
            status=1
            continue
        fi
    fi
    log="$WORK/$tag.log"
    rm -rf "${WORK:?}/run-$tag"
    echo "==> $tag -> HEAD (log: $log)" >&2
    if "$REPO_ROOT/scripts/release-qa/scenario_restore_compat.sh" \
        "$WORK/bin/server-$tag" "$WORK/bin/cli-$tag" "$WORK/bin/server-head" "$WORK/bin/cli-head" \
        "$dsn" "$WORK/run-$tag" > "$log" 2>&1; then
        legs="$(grep -oE 'LEG PASSED: [a-z]+' "$log" | awk '{print $3}' | paste -sd, -)"
        RESULTS+=("$tag: PASS ($legs)")
    else
        RESULTS+=("$tag: FAIL -- $(grep -m1 'RESTORE-COMPAT FAILED' "$log" || tail -1 "$log")")
        status=1
    fi
done

echo ""
echo "restore-compat matrix (OLD backup -> HEAD restore):"
printf '  %s\n' "${RESULTS[@]}"
exit "$status"
