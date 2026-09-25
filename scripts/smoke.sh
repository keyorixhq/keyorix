#!/usr/bin/env bash
# scripts/smoke.sh -- the CI + release gate for the SHIPPED $(BINARY_CLI) binary
# (Phase 5, ADR-108). Executes QUICK_START.md's flow, step for step, against real
# built binaries, in an isolated HOME/cwd. Keep this file's steps in exact
# correspondence with QUICK_START.md -- if you change one, change the other.
#
# This is the executing counterpart to cli/cmd/quickstart_commands_test.go and
# server/admin/quickstart_commands_test.go, which only prove every command QUICK_START.md
# documents resolves to a real command with real flags -- their own header says they
# "do not run them." This script runs the flow for real, including the exact
# `secret export --project --env --format json` call
# integrations/github-action/entrypoint.sh makes, so a break in that contract is
# caught here too. Neither mechanism is sufficient alone: one proves the commands
# exist, this one proves they work.
#
# The new CLI is REST-only -- there is no embedded/local mode to smoke test here.
# scripts/smoke-legacy.sh covers the OLD CLI's embedded-mode flow, kept separately
# until Phase 6 deletes internal/cli; it is never the release gate.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLI_BIN="$REPO_ROOT/bin/keyorix"
SERVER_BIN="$REPO_ROOT/bin/keyorix-server"
SERVER_PORT=18089
SERVER_URL="http://127.0.0.1:$SERVER_PORT"

fail() {
    echo "" >&2
    echo "SMOKE TEST FAILED: $1" >&2
    exit 1
}

if [ ! -x "$CLI_BIN" ]; then
    echo "==> bin/keyorix not found, building it"
    (cd "$REPO_ROOT/cli" && GOWORK=off go build -o "$CLI_BIN" .) || fail "go build did not produce $CLI_BIN"
fi
if [ ! -x "$SERVER_BIN" ]; then
    echo "==> bin/keyorix-server not found, building it"
    (cd "$REPO_ROOT" && go build -o "$SERVER_BIN" ./server) || fail "go build did not produce $SERVER_BIN"
fi

SMOKE_DIR="$(mktemp -d)"
SERVER_PID=""
cleanup() {
    [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null || true
    rm -rf "$SMOKE_DIR"
}
trap cleanup EXIT

echo "==> Isolated smoke test dir: $SMOKE_DIR"

# HOME isolation: a real ~/.keyorix/ credential file must never be visible to this
# run, and must never be overwritten by it.
export HOME="$SMOKE_DIR"
export KEYORIX_MASTER_PASSWORD="smoke-test-master-password-$$-${RANDOM}"
BOOTSTRAP_TOKEN="smoke-test-bootstrap-token-$$-${RANDOM}"
# Must satisfy internal/core/rules.DefaultPasswordPolicy: >=16 chars, upper,
# lower, digit, and special, and must not contain the account's username/
# email/display name -- the plain lowercase/digit/hyphen form this used to be
# failed "password must contain an uppercase letter" against a real bootstrap
# call (only exercised once this script became the actual release gate; a
# mocked/unit test never validates a real password against the policy), and
# "Admin" in the password collided with --admin-username admin below.
ADMIN_PASSWORD="Smoke-Test-Op3rator-Passw0rd!-$$-${RANDOM}"

cd "$SMOKE_DIR"
# admin init refuses an absolute --config path (securefiles.SecureWriteFileSync
# requires a path relative to its base dir) -- relative, from this cwd, like the
# old smoke.sh's equivalent step.
CONFIG_PATH="./keyorix.yaml"

echo "==> keyorix-server admin init"
"$SERVER_BIN" admin init --config "$CONFIG_PATH" || fail "admin init exited non-zero"
[ -f "$CONFIG_PATH" ] || fail "admin init did not create $CONFIG_PATH"
# admin init's generated config always listens on the default port -- point this
# run's server at an isolated one so it never collides with a real dev server or
# scripts/cli-parity-check.sh's own instance.
sed -i.bak -E "s/port: \"8080\"/port: \"$SERVER_PORT\"/" "$CONFIG_PATH"
rm -f "$CONFIG_PATH.bak"

echo "==> keyorix-server admin encryption init"
"$SERVER_BIN" admin encryption init --config "$CONFIG_PATH" || fail "admin encryption init exited non-zero"

echo "==> keyorix-server admin migrate"
"$SERVER_BIN" admin migrate --config "$CONFIG_PATH" || fail "admin migrate exited non-zero"

echo "==> starting keyorix-server"
KEYORIX_CONFIG_PATH="$CONFIG_PATH" KEYORIX_BOOTSTRAP_TOKEN="$BOOTSTRAP_TOKEN" "$SERVER_BIN" \
    > "$SMOKE_DIR/server.log" 2>&1 &
SERVER_PID=$!

for _ in $(seq 1 30); do
    if curl -fs "$SERVER_URL/health" >/dev/null 2>&1; then break; fi
    sleep 0.5
done
if ! curl -fs "$SERVER_URL/health" >/dev/null 2>&1; then
    echo "server never became healthy -- see $SMOKE_DIR/server.log" >&2
    cat "$SMOKE_DIR/server.log" >&2
    fail "keyorix-server did not start"
fi

echo "==> keyorix system init --server (bootstrap admin + default workspace)"
"$CLI_BIN" system init --server "$SERVER_URL" --admin-username admin \
    --admin-password "$ADMIN_PASSWORD" --admin-email admin@smoke-test.local \
    --bootstrap-token "$BOOTSTRAP_TOKEN" || fail "system init --server exited non-zero"

echo "==> keyorix login"
"$CLI_BIN" login --server "$SERVER_URL" --username admin --password "$ADMIN_PASSWORD" \
    || fail "login exited non-zero"

echo "==> keyorix project create"
"$CLI_BIN" project create --name smoke-project || fail "project create exited non-zero"

echo "==> keyorix secret create"
SECRET_VALUE="smoke-value-$$-${RANDOM}"
"$CLI_BIN" secret create --name smoke-secret --value "$SECRET_VALUE" \
    --project 1 --environment 1 || fail "secret create exited non-zero"

echo "==> keyorix secret get (value round-trip)"
GET_OUT="$("$CLI_BIN" secret get --id 1 --show-value)" || fail "secret get exited non-zero"
echo "$GET_OUT" | grep -qF "$SECRET_VALUE" || fail \
    "secret get did not return the value that was stored -- got:
$GET_OUT"

echo "==> keyorix secret export (the exact call integrations/github-action/entrypoint.sh makes)"
EXPORT_OUT="$("$CLI_BIN" secret export --project 1 --env 1 --format json)" || fail "secret export exited non-zero"
echo "$EXPORT_OUT" | grep -qF "$SECRET_VALUE" || fail \
    "secret export did not include the value that was stored -- got:
$EXPORT_OUT"

echo ""
echo "SMOKE TEST PASSED"
