#!/usr/bin/env bash
# scripts/e2e/web-real-smoke.sh -- I4 (SESSION-I): drives the real web UI
# against a REAL keyorix-server backend (not web/e2e's existing mocked
# specs, which intercept every API call with canned responses -- see
# web/e2e/mocks.ts). Boots a real server the exact same way
# scripts/smoke.sh already proves works (admin init -> admin encryption
# init -> admin migrate -> start -> POST /system/init), points the Vite dev
# server at it via VITE_API_BASE_URL, and runs the Playwright specs under
# web/e2e/real/ (a separate Playwright config, playwright.config.real.ts,
# so this never touches the existing mock-based suite or its config).
#
# Usage: scripts/e2e/web-real-smoke.sh
#   Requires: go, pnpm, a working `pnpm exec playwright install` (browsers
#   already cached locally is fine -- this script does not re-install them).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SERVER_BIN="$REPO_ROOT/bin/keyorix-server"
SERVER_PORT=18189
SERVER_URL="http://127.0.0.1:$SERVER_PORT"
WEB_PORT=18190

fail() {
    echo "" >&2
    echo "WEB E2E SMOKE FAILED: $1" >&2
    exit 1
}

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

# REAL_HOME is restored before the pnpm/Playwright section below -- Playwright's
# cached browser binaries live under the REAL $HOME (~/Library/Caches/ms-playwright
# on macOS), and this script's own HOME isolation (needed only for the backend
# provisioning steps, so a real ~/.keyorix/ is never touched or shadowed) would
# otherwise point Playwright at an empty, freshly-isolated HOME with no browsers
# installed -- "browserType.launch: Executable doesn't exist at
# $SMOKE_DIR/Library/Caches/ms-playwright/...", found live running this script.
REAL_HOME="$HOME"

# HOME isolation, exactly like scripts/smoke.sh -- a real ~/.keyorix/ must
# never be visible to (or overwritten by) this run. Restored to REAL_HOME
# before the pnpm/Playwright section (see above).
export HOME="$SMOKE_DIR"
export KEYORIX_MASTER_PASSWORD="web-e2e-master-password-$$-${RANDOM}"
BOOTSTRAP_TOKEN="web-e2e-bootstrap-token-$$-${RANDOM}"
# Deliberately unrelated to the username/email/display_name below --
# internal/core/rules.DefaultPasswordPolicy rejects a password containing
# any of those (see scripts/smoke.sh's own header comment on this exact trap).
ADMIN_USERNAME="webe2eadmin"
ADMIN_PASSWORD="Quartz-Falcon-77-Ridge!-$$-${RANDOM}"
ADMIN_EMAIL="webe2eadmin@example.invalid"

cd "$SMOKE_DIR"
CONFIG_PATH="./keyorix.yaml"

echo "==> keyorix-server admin init"
"$SERVER_BIN" admin init --config "$CONFIG_PATH" || fail "admin init exited non-zero"
[ -f "$CONFIG_PATH" ] || fail "admin init did not create $CONFIG_PATH"
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

echo "==> bootstrapping admin via POST /system/init"
INIT_CODE="$(curl -s -o "$SMOKE_DIR/init-response.json" -w '%{http_code}' -X POST "$SERVER_URL/system/init" \
    -H "Content-Type: application/json" \
    -H "X-Keyorix-Bootstrap-Token: $BOOTSTRAP_TOKEN" \
    -d "{\"username\":\"$ADMIN_USERNAME\",\"email\":\"$ADMIN_EMAIL\",\"password\":\"$ADMIN_PASSWORD\",\"display_name\":\"Web E2E Admin\"}")"
[ "$INIT_CODE" = "200" ] || fail "POST /system/init returned $INIT_CODE: $(cat "$SMOKE_DIR/init-response.json")"

echo "==> creating a project + secret so the real pages have something to show"
TOKEN="$(curl -s -X POST "$SERVER_URL/auth/login" -H "Content-Type: application/json" \
    -d "{\"username\":\"$ADMIN_USERNAME\",\"password\":\"$ADMIN_PASSWORD\"}" | python3 -c 'import sys,json; print(json.load(sys.stdin)["data"]["token"])')"
[ -n "$TOKEN" ] || fail "could not extract a login token"
curl -s -X POST "$SERVER_URL/api/v1/projects" -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
    -d '{"name":"web-e2e-project","description":"SESSION-I web real-backend smoke"}' >/dev/null

echo "==> running Playwright specs (web/e2e/real/) against the real backend"
# Restore the REAL HOME for this section -- see REAL_HOME's own comment
# above for why (Playwright's cached browsers live under the real one, not
# this script's isolated $SMOKE_DIR).
export HOME="$REAL_HOME"
cd "$REPO_ROOT/web"
if [ ! -d node_modules ]; then
    echo "==> pnpm install"
    pnpm install --frozen-lockfile
fi

export KEYORIX_E2E_BACKEND_URL="$SERVER_URL"
export KEYORIX_E2E_ADMIN_USERNAME="$ADMIN_USERNAME"
export KEYORIX_E2E_ADMIN_PASSWORD="$ADMIN_PASSWORD"
export KEYORIX_E2E_WEB_PORT="$WEB_PORT"

pnpm exec playwright test --config=playwright.config.real.ts || fail "Playwright real-backend specs failed"

echo ""
echo "WEB E2E SMOKE PASSED"
