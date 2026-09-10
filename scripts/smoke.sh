#!/usr/bin/env bash
# scripts/smoke.sh -- executes the QUICK_START.md "CLI only" flow end to end
# against a real built binary, in an isolated HOME and working directory.
#
# This is the executing counterpart to
# internal/cli/quickstart_commands_test.go, which only proves every command in
# QUICK_START.md resolves to a real cobra command with real flags -- its own
# header says it "does not run them." That gap is exactly what let a broken
# `system init` (reading its config template from the wrong path) ship into
# the documented first-run path undetected. This script runs the flow for
# real. Neither mechanism is sufficient alone: one proves the commands exist,
# the other proves they work.
#
# Two isolation requirements, both learned from a real dress rehearsal:
#   - HOME is pinned to a throwaway temp dir. A developer's real ~/.keyorix/
#     can carry a leftover client-mode config that silently switches the CLI
#     into ClientMode, pointing every command at http://localhost:18712 --
#     a smoke test that inherits a developer's $HOME tests their machine, not
#     the product.
#   - KEYORIX_MASTER_PASSWORD is set to a throwaway value. Without it the
#     default passphrase provider hard-fails in crypto.ResolvePassphrase.
#
# The run must stay in embedded mode throughout -- no keyorix-server is ever
# started here. That's the documented default (internal/cli/modes.go,
# detectMode) and the single-machine / air-gapped story the product is
# positioned on. If this script silently needed a server, that would be a
# finding, not something to work around by starting one -- so the script
# asserts it via `keyorix connect status` rather than just never starting one.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$REPO_ROOT/bin/keyorix"

fail() {
    echo "" >&2
    echo "SMOKE TEST FAILED: $1" >&2
    exit 1
}

if [ ! -x "$BIN" ]; then
    echo "==> bin/keyorix not found, building it"
    (cd "$REPO_ROOT" && go build -o "$BIN" .) || fail "go build did not produce $BIN"
fi

SMOKE_DIR="$(mktemp -d)"
cleanup() { rm -rf "$SMOKE_DIR"; }
trap cleanup EXIT

echo "==> Isolated smoke test dir: $SMOKE_DIR"

# HOME isolation: a real ~/.keyorix/ (client-mode config or otherwise) must
# never be visible to this run.
export HOME="$SMOKE_DIR"
export KEYORIX_MASTER_PASSWORD="smoke-test-password-$$-${RANDOM}"

cd "$SMOKE_DIR"

echo "==> keyorix system init"
"$BIN" system init --config ./keyorix.yaml || fail "system init exited non-zero"
[ -f "$SMOKE_DIR/keyorix.yaml" ] || fail "system init did not create keyorix.yaml"

export KEYORIX_CONFIG_PATH="$SMOKE_DIR/keyorix.yaml"

echo "==> keyorix connect status (assert embedded mode -- no server involved)"
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
# POST /system/init). See QUICK_START.md's "Use it -- CLI only" section.
echo "==> keyorix project create"
"$BIN" project create --name smoke-project || fail "project create exited non-zero"

echo "==> keyorix secret create"
SECRET_VALUE="smoke-value-$$-${RANDOM}"
"$BIN" secret create --name smoke-secret --value "$SECRET_VALUE" || fail "secret create exited non-zero"

echo "==> keyorix secret list"
LIST_OUT="$("$BIN" secret list)" || fail "secret list exited non-zero"
echo "$LIST_OUT" | grep -q "smoke-secret" || fail \
    "secret list did not show the secret just created -- got:
$LIST_OUT"

echo "==> keyorix secret get (value round-trip)"
GET_OUT="$("$BIN" secret get --id 1 --show-value)" || fail "secret get exited non-zero"
echo "$GET_OUT" | grep -qF "$SECRET_VALUE" || fail \
    "secret get did not return the value that was stored -- got:
$GET_OUT"

echo ""
echo "SMOKE TEST PASSED"
