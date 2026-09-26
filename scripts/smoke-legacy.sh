#!/usr/bin/env bash
# scripts/smoke-legacy.sh -- the OLD, thick CLI's (internal/cli) embedded-mode flow
# (system init, no --server -- opens the local database directly, no server ever
# started), moved out of scripts/smoke.sh by the Phase 5 switch (ADR-108): the new
# CLI is REST-only and has no embedded mode to test this way at all.
#
# Dev/CI-only -- NEVER the release gate (scripts/smoke.sh is). Runs against
# bin/keyorix-legacy (built by `make keyorix-legacy`), which is never a release
# asset (see the Makefile's check-release-assets target). Kept until Phase 6
# deletes internal/cli entirely; delete this file in the same PR.
#
# This is the executing counterpart to scripts/cli-parity-check.sh's own coverage
# of the old CLI, and to internal/cli/quickstart_commands_test.go before it was
# deleted alongside QUICK_START.md's rewrite -- QUICK_START.md no longer documents
# this flow (the shipped binary can't run it), so this script's own header is now
# the flow's only documentation.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$REPO_ROOT/bin/keyorix-legacy"

fail() {
    echo "" >&2
    echo "SMOKE-LEGACY TEST FAILED: $1" >&2
    exit 1
}

if [ ! -x "$BIN" ]; then
    echo "==> bin/keyorix-legacy not found, building it"
    (cd "$REPO_ROOT" && go build -o "$BIN" .) || fail "go build did not produce $BIN"
fi

SMOKE_DIR="$(mktemp -d)"
cleanup() { rm -rf "$SMOKE_DIR"; }
trap cleanup EXIT

echo "==> Isolated smoke-legacy test dir: $SMOKE_DIR"

# HOME isolation: a real ~/.keyorix/ (client-mode config or otherwise) must
# never be visible to this run.
export HOME="$SMOKE_DIR"
export KEYORIX_MASTER_PASSWORD="smoke-legacy-test-password-$$-${RANDOM}"

cd "$SMOKE_DIR"

echo "==> keyorix-legacy system init"
"$BIN" system init --config ./keyorix.yaml || fail "system init exited non-zero"
[ -f "$SMOKE_DIR/keyorix.yaml" ] || fail "system init did not create keyorix.yaml"

export KEYORIX_CONFIG_PATH="$SMOKE_DIR/keyorix.yaml"

echo "==> keyorix-legacy connect status (assert embedded mode -- no server involved)"
STATUS_OUT="$("$BIN" connect status)" || fail "connect status exited non-zero"
echo "$STATUS_OUT" | grep -qi "Embedded Mode" || fail \
    "connect status did not report Embedded Mode -- got:
$STATUS_OUT
If this is genuinely ClientMode, that's a real finding (the CLI silently
needs a server on a clean checkout), not something to fix by starting one."

# secret create requires a project + environment to exist first (project
# create seeds default environments 1/2/3) -- system init only writes config
# and initializes encryption/database/logging, it does not seed a default
# project in embedded mode (only --server remote bootstrap does that, via
# POST /system/init).
echo "==> keyorix-legacy project create"
"$BIN" project create --name smoke-project || fail "project create exited non-zero"

echo "==> keyorix-legacy secret create"
SECRET_VALUE="smoke-value-$$-${RANDOM}"
"$BIN" secret create --name smoke-secret --value "$SECRET_VALUE" || fail "secret create exited non-zero"

echo "==> keyorix-legacy secret list"
LIST_OUT="$("$BIN" secret list)" || fail "secret list exited non-zero"
echo "$LIST_OUT" | grep -q "smoke-secret" || fail \
    "secret list did not show the secret just created -- got:
$LIST_OUT"

echo "==> keyorix-legacy secret get (value round-trip)"
GET_OUT="$("$BIN" secret get --id 1 --show-value)" || fail "secret get exited non-zero"
echo "$GET_OUT" | grep -qF "$SECRET_VALUE" || fail \
    "secret get did not return the value that was stored -- got:
$GET_OUT"

echo ""
echo "SMOKE-LEGACY TEST PASSED"
