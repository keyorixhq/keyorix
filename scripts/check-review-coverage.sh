#!/bin/bash
# check-review-coverage.sh — fails if a Go package has no adversarial-review
# coverage row, or if a row cites a package that no longer exists.
#
# Built because "is anything neglected?" had no mechanical answer: answering
# it by hand on 2026-09-08 meant text-matching package paths across 47 review
# documents, and that reconstruction got things wrong in both directions —
# internal/keyfiles and internal/envflag looked uncovered because they
# postdate the docs that would name them, and migrations/ was recorded as
# "known-dead, never invoked" when it is actually uninvoked-but-specified
# (migrations_test.go and factory_sqlite_pragma_test.go both assert schema
# properties against those SQL files as a spec). Scope must be DERIVED from
# `go list ./...` at run time, never hand-enumerated — a hand-maintained
# package list is the exact failure mode this exists to prevent.
#
# Design rules (same reasoning as check-closures.sh, applied to coverage
# instead of closure claims):
#
#   1. Both directions must fail. A package go list finds with no ledger row
#      is a silent gap. A ledger row for a package that no longer exists is
#      the ledger rotting into a list of things that used to be true — ONLY
#      catching the first direction lets deleted/renamed packages accumulate
#      as false coverage claims forever.
#
#   2. depth=none requires an evidenced status_note from a closed set
#      (example / test-helper / main-wiring / generated /
#      uninvoked-but-specified / pending). An unqualified "none" is
#      indistinguishable from "nobody checked" — the closed set forces
#      whoever adds the row to say which one it is. uninvoked-but-specified
#      exists specifically because migrations/ needed a state the original
#      four-state guess ("example/test-helper/main-wiring/generated") could
#      not express — if a future package needs a state this set cannot
#      express, extend the set; don't misuse the nearest existing one.
#
#   3. Any real pass (depth != none) requires a non-empty last_pass AND
#      evidence citation — a claimed pass with no citation is exactly the
#      inherited-assumption failure this ledger exists to replace.
#
# Usage:
#   ./scripts/check-review-coverage.sh              # verify the real repo
#   ./scripts/check-review-coverage.sh --self-test   # prove the check can go
#                                                     # red (both directions)
#                                                     # and can go green
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LEDGER="${REVIEW_LEDGER:-$REPO_ROOT/docs/review-coverage.tsv}"
MODULE_PREFIX="github.com/keyorixhq/keyorix"
VALID_DEPTHS="full-adversarial targeted structural-only none"
VALID_STATUS_NOTES="example test-helper main-wiring generated uninvoked-but-specified pending"

fail=0
die()  { echo "FAIL: $*" >&2; fail=1; }
note() { echo "  $*"; }

in_set() {
    # $1=needle  $2=space-separated haystack
    local n="$1" h="$2" w
    for w in $h; do [ "$w" = "$n" ] && return 0; done
    return 1
}

if [ ! -f "$LEDGER" ]; then
    echo "FAIL: coverage ledger not found at $LEDGER" >&2; exit 1
fi

# Package list: derived from go list at run time unless overridden (self-test
# only — REVIEW_PKGLIST lets the self-test inject a synthetic list without
# creating throwaway .go files on disk). Relative to the module root, with
# the root package itself represented as "." (matching `go list ./...`'s own
# convention for the package at the module root).
if [ -n "${REVIEW_PKGLIST:-}" ]; then
    pkglist="$(cat "$REVIEW_PKGLIST")"
else
    raw="$(cd "$REPO_ROOT" && go list ./... 2>&1)" || {
        echo "FAIL: go list ./... failed:" >&2; echo "$raw" >&2; exit 1
    }
    pkglist="$(sed -e "s|^${MODULE_PREFIX}/||" -e "s|^${MODULE_PREFIX}\$|.|" <<<"$raw")"
fi

rows="$(grep -vE '^[[:space:]]*(#|$)' "$LEDGER" || true)"
if [ -z "$rows" ]; then
    echo "FAIL: coverage ledger is empty — a ledger with no rows cannot fail, and" >&2
    echo "      a check that cannot fail is not a check." >&2
    exit 1
fi

ledger_pkgs="$(cut -f1 <<<"$rows")"
dupes="$(sort <<<"$ledger_pkgs" | uniq -d || true)"
if [ -n "$dupes" ]; then
    die "duplicate package rows in ledger:"; for d in $dupes; do note "$d"; done
fi

# Direction 1: every package go list finds must have a row.
missing="$(comm -23 <(sort -u <<<"$pkglist") <(sort -u <<<"$ledger_pkgs") || true)"
if [ -n "$missing" ]; then
    die "package(s) reported by go list have no coverage row:"
    while IFS= read -r p; do [ -n "$p" ] && note "$p"; done <<<"$missing"
fi

# Direction 2: every row must name a package go list still reports — a stale
# row is coverage claimed for something that no longer exists.
stale="$(comm -13 <(sort -u <<<"$pkglist") <(sort -u <<<"$ledger_pkgs") || true)"
if [ -n "$stale" ]; then
    die "coverage row(s) name a package go list no longer reports (renamed/deleted — remove or update the row):"
    while IFS= read -r p; do [ -n "$p" ] && note "$p"; done <<<"$stale"
fi

# Column order: package  depth  last_pass  evidence  status_note
checked=0
while IFS=$'\t' read -r pkg depth last_pass evidence status_note; do
    [ -z "${pkg:-}" ] && continue
    checked=$((checked + 1))
    if ! in_set "${depth:-}" "$VALID_DEPTHS"; then
        die "$pkg: depth must be one of [$VALID_DEPTHS] (got '${depth:-<empty>}')"
        continue
    fi
    if [ "$depth" = "none" ]; then
        if ! in_set "${status_note:-}" "$VALID_STATUS_NOTES"; then
            die "$pkg: depth=none requires status_note in [$VALID_STATUS_NOTES] (got '${status_note:-<empty>}')"
        fi
    else
        if [ -z "${last_pass:-}" ] || [ "$last_pass" = "-" ]; then
            die "$pkg: depth=$depth requires a non-empty last_pass — a claimed pass with no citation is not a pass"
        fi
        if [ -z "${evidence:-}" ] || [ "$evidence" = "-" ]; then
            die "$pkg: depth=$depth requires a non-empty evidence citation — a claimed pass with no citation is not a pass"
        fi
    fi
done <<<"$rows"

if [ "${1:-}" = "--self-test" ]; then
    echo; echo "==> self-test: the check must reject every bad fixture below, and accept the good one"
    selffail=0

    run_case() {
        # $1=description  $2=expected(reject|accept)  $3=pkglist  $4=ledger rows
        local desc="$1" expect="$2" pkglist_body="$3" ledger_body="$4" out rc
        local tmp_pkgs tmp_ledger
        tmp_pkgs=$(mktemp); tmp_ledger=$(mktemp)
        printf '%s\n' "$pkglist_body" > "$tmp_pkgs"
        printf '%s\n' "$ledger_body" > "$tmp_ledger"
        set +e
        out=$(REVIEW_PKGLIST="$tmp_pkgs" REVIEW_LEDGER="$tmp_ledger" "$0" 2>&1); rc=$?
        set -e
        rm -f "$tmp_pkgs" "$tmp_ledger"
        if [ "$expect" = "reject" ] && [ "$rc" -eq 0 ]; then
            echo "FAIL: self-test case '$desc' PASSED when it must be REJECTED." >&2
            sed -n '1,40p' <<<"$out" | sed 's/^/      /' >&2
            selffail=1
        elif [ "$expect" = "accept" ] && [ "$rc" -ne 0 ]; then
            echo "FAIL: self-test case '$desc' was REJECTED when it must be ACCEPTED." >&2
            sed -n '1,40p' <<<"$out" | sed 's/^/      /' >&2
            selffail=1
        else
            echo "  ok: '$desc' correctly ${expect}ed (exit $rc)"
        fi
    }

    run_case "package with no ledger row" "reject" \
        $'pkg/a\npkg/b' \
        $'pkg/a\tnone\t-\t-\tpending'

    run_case "ledger row for a package that no longer exists" "reject" \
        $'pkg/a' \
        $'pkg/a\tnone\t-\t-\tpending\npkg/deleted\tnone\t-\t-\tpending'

    run_case "depth=none with no status_note" "reject" \
        $'pkg/a' \
        $'pkg/a\tnone\t-\t-\t'

    run_case "depth=none with an invalid status_note" "reject" \
        $'pkg/a' \
        $'pkg/a\tnone\t-\t-\tprobably-fine'

    run_case "depth=full-adversarial with no evidence" "reject" \
        $'pkg/a' \
        $'pkg/a\tfull-adversarial\tSOME-DOC.md\t-\t-'

    run_case "depth=full-adversarial with no last_pass" "reject" \
        $'pkg/a' \
        $'pkg/a\tfull-adversarial\t-\tSOME-DOC.md:L1\t-'

    run_case "duplicate package rows" "reject" \
        $'pkg/a' \
        $'pkg/a\tnone\t-\t-\tpending\npkg/a\tnone\t-\t-\tpending'

    run_case "well-formed matching pkglist and ledger" "accept" \
        $'pkg/a\npkg/b' \
        $'pkg/a\tfull-adversarial\tSOME-DOC.md (2026-09-09)\tSOME-DOC.md:L1, finding F1\t-\npkg/b\tnone\t-\t-\tpending'

    if [ "$selffail" -ne 0 ]; then
        exit 1
    fi
fi

echo
if [ "$fail" -eq 0 ]; then
    echo "ok: $checked package(s) covered by the ledger, $(sort -u <<<"$pkglist" | grep -c .) reported by go list"
else
    echo "COVERAGE VERIFICATION FAILED — ledger does not match the real package set or has malformed rows" >&2
    exit 1
fi
