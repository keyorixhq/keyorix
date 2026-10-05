#!/bin/bash
# check-adr-conformance.sh — verifies docs/adr-conformance-enforced.tsv the
# same way scripts/check-closures.sh verifies docs/security-closures.tsv: a
# named test must produce a literal `--- PASS:` line, not just a nonzero
# go-test exit code, or the claim doesn't count. This is a thin wrapper, not
# a fork — the actual verification logic (duplicate-claim detection, SKIP/
# no-match/unrecognised-output handling, the --self-test mode) lives in
# check-closures.sh and is reused unchanged via CLOSURE_LEDGER, so a fix to
# that logic benefits both ledgers automatically instead of drifting apart.
#
# Usage:
#   ./scripts/check-adr-conformance.sh              # verify every row
#   ./scripts/check-adr-conformance.sh --self-test   # prove the check can go red
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# New rows go in docs/adr-conformance-enforced.d/<claim_id>.tsv (one row per
# file, same columns), read IN ADDITION to the flat ledger — see that
# directory's README.md. The flat ledger's existing rows stay where they are
# until scripts/ledgers/migrate-to-fragments.sh is run in a quiet window.
exec env CLOSURE_LEDGER="$REPO_ROOT/docs/adr-conformance-enforced.tsv" \
    CLOSURE_LEDGER_D="$REPO_ROOT/docs/adr-conformance-enforced.d" \
    "$REPO_ROOT/scripts/check-closures.sh" "$@"
