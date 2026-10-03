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
# SESSION-WEB-E2E (2026-10-02/03): runs web/e2e/real/*.spec.ts in BUDGET
# GROUPS of at most MAX_SPECS_PER_GROUP files each, every group against its
# own freshly-booted server/DB, rather than one Playwright invocation
# covering every spec file against one shared backend.
# server/http/handlers/auth.go's reserveLoginAttempt enforces a shared
# per-IP budget of 10 login attempts (UI or API, success or fail) per 15
# minutes, backed by the DB -- fine for any one spec file alone, but the
# real-backend suite's total login volume across ALL files already exceeds
# it once summed (confirmed live: running every e2e/real/*.spec.ts file
# together in one invocation against one backend 429'd starting with the
# 11th login, mid-suite, with failures that look like broken tests but are
# actually an exhausted rate-limit budget -- nothing to do with any
# individual spec's correctness). A fresh SMOKE_DIR each group gets a fresh
# SQLite DB, which resets the counter (it's keyed in that DB, not wall-clock
# alone) -- so splitting into groups that each stay under budget, rather
# than trying to shave every file's login count down to fit one shared
# budget forever, is the fix that actually scales as more real-backend specs
# get added later instead of recreating this exact collision at some new
# file count.
#
# Groups are discovered dynamically (every e2e/real/*.spec.ts file that
# exists, chunked at MAX_SPECS_PER_GROUP) rather than a hardcoded file list,
# deliberately: a hardcoded list would be wrong -- and Playwright would error
# outright on a named file that doesn't exist -- on every individual PR
# branch that doesn't yet have every other in-flight real-backend spec file
# merged into it. Today's real per-file login counts run 2-5 each.
# MAX_SPECS_PER_GROUP=2 (not 3): confirmed live that 3 of today's 5 files
# (access-control + audit-and-session + mfa-login, alphabetically the first
# chunk) sum to EXACTLY 10 logins -- the hard ceiling, zero margin, one more
# login anywhere in any of those three files away from breaking again. At 2
# per group the worst real pairing today is 7 (mfa-login + pages), leaving
# real headroom.
#
# Usage: scripts/e2e/web-real-smoke.sh
#   Requires: go, pnpm, a working `pnpm exec playwright install` (browsers
#   already cached locally is fine -- this script does not re-install them).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SERVER_BIN="$REPO_ROOT/bin/keyorix-server"
WEB_DIR="$REPO_ROOT/web"
MAX_SPECS_PER_GROUP=2

mapfile -t ALL_SPECS < <(cd "$WEB_DIR" && find e2e/real -maxdepth 1 -name '*.spec.ts' | sort)
[ "${#ALL_SPECS[@]}" -gt 0 ] || { echo "no e2e/real/*.spec.ts files found under $WEB_DIR" >&2; exit 1; }

SPEC_GROUPS=()
current_group=""
current_count=0
for spec in "${ALL_SPECS[@]}"; do
    if [ "$current_count" -ge "$MAX_SPECS_PER_GROUP" ]; then
        SPEC_GROUPS+=("$current_group")
        current_group=""
        current_count=0
    fi
    current_group="${current_group:+$current_group }$spec"
    current_count=$((current_count + 1))
done
[ -n "$current_group" ] && SPEC_GROUPS+=("$current_group")

fail() {
    echo "" >&2
    echo "WEB E2E SMOKE FAILED: $1" >&2
    exit 1
}

if [ ! -x "$SERVER_BIN" ]; then
    echo "==> bin/keyorix-server not found, building it"
    (cd "$REPO_ROOT" && go build -o "$SERVER_BIN" ./server) || fail "go build did not produce $SERVER_BIN"
fi

REAL_HOME="$HOME"

if [ ! -d "$WEB_DIR/node_modules" ]; then
    echo "==> pnpm install"
    (cd "$WEB_DIR" && pnpm install --frozen-lockfile)
fi

# run_group boots one fresh server+DB, bootstraps an admin, seeds a project,
# runs the given spec files against it, and tears it all down -- isolating
# this group's login-attempt budget from every other group's.
run_group() {
    local group_label="$1"
    shift
    local specs=("$@")
    local server_port=$((18189 + group_label))
    local server_url="http://127.0.0.1:$server_port"
    local web_port=$((18190 + group_label))

    local smoke_dir
    smoke_dir="$(mktemp -d)"
    local server_pid=""
    group_cleanup() {
        [ -n "$server_pid" ] && kill "$server_pid" 2>/dev/null || true
        rm -rf "$smoke_dir"
    }
    trap group_cleanup RETURN

    echo "==> [group $group_label] isolated smoke test dir: $smoke_dir"

    # HOME isolation, exactly like scripts/smoke.sh -- a real ~/.keyorix/ must
    # never be visible to (or overwritten by) this run. Restored to REAL_HOME
    # before the pnpm/Playwright section below (Playwright's cached browsers
    # live under the real HOME, not this isolated one).
    export HOME="$smoke_dir"
    export KEYORIX_MASTER_PASSWORD="web-e2e-master-password-$$-${RANDOM}"
    local bootstrap_token="web-e2e-bootstrap-token-$$-${RANDOM}"
    # Deliberately unrelated to the username/email/display_name below --
    # internal/core/rules.DefaultPasswordPolicy rejects a password containing
    # any of those (see scripts/smoke.sh's own header comment on this exact trap).
    local admin_username="webe2eadmin"
    local admin_password="Quartz-Falcon-77-Ridge!-$$-${RANDOM}"
    local admin_email="webe2eadmin@example.invalid"

    # Relative to $smoke_dir (every admin subcommand below runs with cwd set
    # there) -- the CLI itself rejects an absolute --config path ("access
    # denied: path ... must be relative"), confirmed live.
    local config_rel="./keyorix.yaml"
    local config_path="$smoke_dir/keyorix.yaml"

    echo "==> [group $group_label] keyorix-server admin init"
    (cd "$smoke_dir" && "$SERVER_BIN" admin init --config "$config_rel") || fail "admin init exited non-zero"
    [ -f "$config_path" ] || fail "admin init did not create $config_path"
    sed -i.bak -E "s/port: \"8080\"/port: \"$server_port\"/" "$config_path"
    rm -f "$config_path.bak"

    echo "==> [group $group_label] keyorix-server admin encryption init"
    (cd "$smoke_dir" && "$SERVER_BIN" admin encryption init --config "$config_rel") ||
        fail "admin encryption init exited non-zero"

    echo "==> [group $group_label] keyorix-server admin migrate"
    (cd "$smoke_dir" && "$SERVER_BIN" admin migrate --config "$config_rel") || fail "admin migrate exited non-zero"

    echo "==> [group $group_label] starting keyorix-server"
    # `exec` replaces the subshell with the server binary itself, so $! below
    # is the server's own PID, not a wrapper subshell's -- without it, killing
    # $! on cleanup would only kill a `cd`-then-exited subshell, leaking the
    # actual server process as an orphan.
    (cd "$smoke_dir" && exec env KEYORIX_CONFIG_PATH="$config_rel" KEYORIX_BOOTSTRAP_TOKEN="$bootstrap_token" "$SERVER_BIN") \
        >"$smoke_dir/server.log" 2>&1 &
    server_pid=$!

    for _ in $(seq 1 30); do
        if curl -fs "$server_url/health" >/dev/null 2>&1; then break; fi
        sleep 0.5
    done
    if ! curl -fs "$server_url/health" >/dev/null 2>&1; then
        echo "server never became healthy -- see $smoke_dir/server.log" >&2
        cat "$smoke_dir/server.log" >&2
        fail "[group $group_label] keyorix-server did not start"
    fi

    echo "==> [group $group_label] bootstrapping admin via POST /system/init"
    local init_code
    init_code="$(curl -s -o "$smoke_dir/init-response.json" -w '%{http_code}' -X POST "$server_url/system/init" \
        -H "Content-Type: application/json" \
        -H "X-Keyorix-Bootstrap-Token: $bootstrap_token" \
        -d "{\"username\":\"$admin_username\",\"email\":\"$admin_email\",\"password\":\"$admin_password\",\"display_name\":\"Web E2E Admin\"}")"
    [ "$init_code" = "200" ] || fail "[group $group_label] POST /system/init returned $init_code: $(cat "$smoke_dir/init-response.json")"

    echo "==> [group $group_label] creating a project + secret so the real pages have something to show"
    local token
    token="$(curl -s -X POST "$server_url/auth/login" -H "Content-Type: application/json" \
        -d "{\"username\":\"$admin_username\",\"password\":\"$admin_password\"}" |
        python3 -c 'import sys,json; print(json.load(sys.stdin)["data"]["token"])')"
    [ -n "$token" ] || fail "[group $group_label] could not extract a login token"
    curl -s -X POST "$server_url/api/v1/projects" -H "Authorization: Bearer $token" -H "Content-Type: application/json" \
        -d '{"name":"web-e2e-project","description":"SESSION-I web real-backend smoke"}' >/dev/null

    echo "==> [group $group_label] running Playwright specs against the real backend: ${specs[*]}"
    export HOME="$REAL_HOME"
    export KEYORIX_E2E_BACKEND_URL="$server_url"
    export KEYORIX_E2E_ADMIN_USERNAME="$admin_username"
    export KEYORIX_E2E_ADMIN_PASSWORD="$admin_password"
    export KEYORIX_E2E_WEB_PORT="$web_port"

    (cd "$WEB_DIR" && pnpm exec playwright test --config=playwright.config.real.ts "${specs[@]}") ||
        fail "[group $group_label] Playwright real-backend specs failed"
}

group_num=0
for group_specs in "${SPEC_GROUPS[@]}"; do
    group_num=$((group_num + 1))
    # Intentional word-splitting: each SPEC_GROUPS element is a
    # space-separated list of relative paths.
    # shellcheck disable=SC2086
    run_group "$group_num" $group_specs
done

echo ""
echo "WEB E2E SMOKE PASSED"
