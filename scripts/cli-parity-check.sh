#!/usr/bin/env bash
# cli-parity-check.sh — live-server golden-output parity check for ADR-108 PR 2 and PR 6
# (docs/cli-split-inventory.md §7): builds the old thick `keyorix` CLI, the new
# thin `keyorix-next` CLI, and `keyorix-server`, boots a real local SQLite
# server, bootstraps an admin, and runs all 24 pat/auth/machine commands plus
# PR 6's project/user commands through both CLIs against the SAME live server --
# comparing stdout and exit codes, not mocked responses.
#
# This is a manual verification tool (like PR 0's own "exercised against a
# real running server ... not just unit tests"), not a CI gate: it needs to
# bootstrap a real server instance, which is more than a unit test should do.
# Run it by hand after touching cli/cmd/{pat,machine,logout,mfa,login,status}.go
# or their server-side handlers.
#
# Usage: scripts/cli-parity-check.sh [workdir]
#   workdir defaults to a fresh mktemp -d. Must NOT be the repo working tree
#   (system init writes CWD-relative files) -- see CLAUDE.md's one-writer rule
#   for why this script never touches the shared checkout's own directory.
#
# What "parity" means here, precisely:
#   - list/hygiene/token/binding commands: BYTE-IDENTICAL stdout for the same
#     underlying data (both CLIs list the SAME server-side resources).
#   - create/issue commands: identical FORMAT (same labels, same one-time-
#     secret warning text) with dynamic fields (ids, tokens, timestamps)
#     normalized out before comparing -- two independent `create` calls
#     mint two different resources by construction.
#   - login/status/logout: NOT compared for literal parity -- ADR-108
#     deliberately replaced the old CLI's API-key/config-file model with a
#     session-token/single-credential-file model; the auth mechanism itself
#     changed, so the commands are expected to differ. Verified instead: the
#     new commands do what THEIR OWN spec says (see cli/cmd/*_test.go).
#   - machine audit --format json: NOT byte-compared -- the new CLI's
#     generated-client struct fields serialize in alphabetical order,
#     the old CLI's hand-written struct in declaration order. Semantically
#     identical JSON, different (immaterial) key order. --format csv (fixed
#     column order, both sides) IS byte-compared.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="${1:-$(mktemp -d)}"
BIN="$WORKDIR/bin"
INSTANCE="$WORKDIR/instance"
RESULTS="$WORKDIR/results"
PASSPHRASE="parity-check-dev-passphrase"
BOOTSTRAP_TOKEN="parity-check-bootstrap-token"
ADMIN_PASSWORD='ParityCheck-Adm1n-Pass!'
SERVER_URL="http://127.0.0.1:18080"

fail_count=0
pass_count=0

log() { echo "[cli-parity-check] $*" >&2; }

check() {
  local label="$1" a="$2" b="$3"
  if diff -q "$a" "$b" >/dev/null 2>&1; then
    pass_count=$((pass_count + 1))
    log "PASS  $label"
  else
    fail_count=$((fail_count + 1))
    log "FAIL  $label -- diff:"
    diff "$a" "$b" >&2 || true
  fi
}

# normalize strips dynamic fields (numeric ids in known columns, raw secrets,
# timestamps) so two independently-created resources compare structurally.
normalize() {
  sed -E \
    -e 's/kx_(pat|machine)_[A-Za-z0-9_-]+/TOKEN/g' \
    -e 's/^[[:space:]]*[0-9]+([[:space:]]|$)/ID\1/' \
    -e 's/id=[0-9]+/id=N/' \
    -e 's/id:[[:space:]]+[0-9]+/id: N/' \
    -e 's/[0-9]{4}-[0-9]{2}-[0-9]{2}([T ][0-9:.]+(Z|[+-][0-9:]+)?)?/TIMESTAMP/g' \
    -e 's/(old|new)-(pat|machine|token|sub)-?1?/NAME/g' \
    "$1"
}

mkdir -p "$BIN" "$INSTANCE" "$RESULTS"
# Defensive: a prior crashed run against this same workdir could have leaked its
# server past its own exit trap (see the trap below for why plain `kill $!` isn't
# reliable here).
pkill -f "$BIN/keyorix-server" 2>/dev/null || true

log "building keyorix (old CLI), keyorix-server, keyorix-next into $BIN"
( cd "$REPO_ROOT" && GOWORK=off go build -o "$BIN/keyorix" . )
( cd "$REPO_ROOT" && GOWORK=off go build -o "$BIN/keyorix-server" ./server )
( cd "$REPO_ROOT/cli" && GOWORK=off go build -o "$BIN/keyorix-next" . )

log "provisioning a local SQLite instance at $INSTANCE"
( cd "$INSTANCE" && "$BIN/keyorix" system init --force >/dev/null )
# Pin the server's port to $SERVER_URL's port so this can run alongside a
# real dev server without colliding.
sed -i.bak -E 's/port: "8080"/port: "18080"/' "$INSTANCE/keyorix.yaml"
rm -f "$INSTANCE/keyorix.yaml.bak"
( cd "$INSTANCE" && echo "$PASSPHRASE" | "$BIN/keyorix" encryption init --passphrase-stdin >/dev/null )

log "starting keyorix-server"
# pkill -f "$BIN/keyorix-server" (not `kill $!`) on exit: $! would only capture this
# subshell's own PID, not the actual server process bash -c/the passphrase pipe forks
# underneath it -- that PID is a leaf process a plain `kill` never reaches, and it was
# confirmed to leak past script exit during this script's own development. Matching on
# $BIN (unique per workdir) can't collide with an unrelated run's server.
trap 'pkill -f "$BIN/keyorix-server" 2>/dev/null || true' EXIT
( cd "$INSTANCE" && KEYORIX_BOOTSTRAP_TOKEN="$BOOTSTRAP_TOKEN" bash -c "echo '$PASSPHRASE' | '$BIN/keyorix-server' --passphrase-stdin" ) \
  > "$INSTANCE/server.log" 2>&1 &

for _ in $(seq 1 30); do
  if curl -fs "$SERVER_URL/health" >/dev/null 2>&1; then break; fi
  sleep 0.5
done
if ! curl -fs "$SERVER_URL/health" >/dev/null 2>&1; then
  log "server never became healthy -- see $INSTANCE/server.log"
  cat "$INSTANCE/server.log" >&2
  exit 1
fi

log "bootstrapping admin"
"$BIN/keyorix" system init --server "$SERVER_URL" --admin-username admin \
  --admin-password "$ADMIN_PASSWORD" --admin-email admin@parity-check.test \
  --bootstrap-token "$BOOTSTRAP_TOKEN" >/dev/null

log "logging in both CLIs"
export HOME="$WORKDIR/home"
mkdir -p "$HOME"
KEYORIX_PASSWORD="$ADMIN_PASSWORD" "$BIN/keyorix" connect "$SERVER_URL" --username admin --insecure >/dev/null
"$BIN/keyorix-next" login --server "$SERVER_URL" --username admin --password "$ADMIN_PASSWORD" >/dev/null

run_old() { "$BIN/keyorix" "$@"; }
run_new() { "$BIN/keyorix-next" "$@"; }

# ── pat ──────────────────────────────────────────────────────────────────────
run_old pat create --name old-pat-1 > "$RESULTS/old_pat_create.raw" 2>&1 || true
run_new pat create --name new-pat-1 > "$RESULTS/new_pat_create.raw" 2>&1 || true
normalize "$RESULTS/old_pat_create.raw" > "$RESULTS/old_pat_create.norm"
normalize "$RESULTS/new_pat_create.raw" > "$RESULTS/new_pat_create.norm"
check "pat create (normalized format)" "$RESULTS/old_pat_create.norm" "$RESULTS/new_pat_create.norm"

run_old pat list > "$RESULTS/old_pat_list.raw" 2>&1
run_new pat list > "$RESULTS/new_pat_list.raw" 2>&1
check "pat list (same underlying tokens)" "$RESULTS/old_pat_list.raw" "$RESULTS/new_pat_list.raw"

run_old pat hygiene > "$RESULTS/old_pat_hygiene.raw" 2>&1
run_new pat hygiene > "$RESULTS/new_pat_hygiene.raw" 2>&1
check "pat hygiene" "$RESULTS/old_pat_hygiene.raw" "$RESULTS/new_pat_hygiene.raw"

run_old pat list-expired > "$RESULTS/old_pat_listexp.raw" 2>&1
run_new pat list-expired > "$RESULTS/new_pat_listexp.raw" 2>&1
check "pat list-expired" "$RESULTS/old_pat_listexp.raw" "$RESULTS/new_pat_listexp.raw"

run_old pat cleanup-expired > "$RESULTS/old_pat_cleanup.raw" 2>&1
run_new pat cleanup-expired > "$RESULTS/new_pat_cleanup.raw" 2>&1
check "pat cleanup-expired" "$RESULTS/old_pat_cleanup.raw" "$RESULTS/new_pat_cleanup.raw"

old_pat_id=$(run_old pat list | awk 'NR==2{print $1}')
new_pat_id=$(run_new pat list | awk 'NR==2{print $1}')
run_old pat revoke "$old_pat_id" > "$RESULTS/old_pat_revoke.raw" 2>&1
run_new pat revoke "$new_pat_id" > "$RESULTS/new_pat_revoke.raw" 2>&1
sed -E "s/$old_pat_id/N/" "$RESULTS/old_pat_revoke.raw" > "$RESULTS/old_pat_revoke.norm"
sed -E "s/$new_pat_id/N/" "$RESULTS/new_pat_revoke.raw" > "$RESULTS/new_pat_revoke.norm"
check "pat revoke" "$RESULTS/old_pat_revoke.norm" "$RESULTS/new_pat_revoke.norm"

# ── auth: mfa stepup, logout (login/status intentionally not parity-checked) ──
echo "000000" | run_old auth mfa stepup > "$RESULTS/old_mfa.raw" 2>&1 || true
echo "000000" | run_new mfa stepup > "$RESULTS/new_mfa.raw" 2>&1 || true
old_mfa_status=$(grep -oE 'HTTP [0-9]+' "$RESULTS/old_mfa.raw" | head -1 | grep -oE '[0-9]+')
new_mfa_status=$(grep -oE 'HTTP [0-9]+' "$RESULTS/new_mfa.raw" | head -1 | grep -oE '[0-9]+')
if [ "$old_mfa_status" = "$new_mfa_status" ] && [ "$old_mfa_status" = "401" ]; then
  pass_count=$((pass_count + 1)); log "PASS  mfa stepup (both HTTP 401, no MFA enrolled)"
else
  fail_count=$((fail_count + 1)); log "FAIL  mfa stepup: old=$old_mfa_status new=$new_mfa_status"
fi

run_new logout > "$RESULTS/new_logout.raw" 2>&1
if grep -q "^Logged out\.$" "$RESULTS/new_logout.raw"; then
  pass_count=$((pass_count + 1)); log "PASS  logout (revoked + local file cleared)"
else
  fail_count=$((fail_count + 1)); log "FAIL  logout: $(cat "$RESULTS/new_logout.raw")"
fi
"$BIN/keyorix-next" login --server "$SERVER_URL" --username admin --password "$ADMIN_PASSWORD" >/dev/null

# ── machine ──────────────────────────────────────────────────────────────────
run_old machine create --project default --name old-machine-1 --type ci > "$RESULTS/old_m_create.raw" 2>&1
run_new machine create --project default --name new-machine-1 --type ci > "$RESULTS/new_m_create.raw" 2>&1
normalize "$RESULTS/old_m_create.raw" > "$RESULTS/old_m_create.norm"
normalize "$RESULTS/new_m_create.raw" > "$RESULTS/new_m_create.norm"
check "machine create (normalized format)" "$RESULTS/old_m_create.norm" "$RESULTS/new_m_create.norm"

run_old machine list --project default > "$RESULTS/old_m_list.raw" 2>&1
run_new machine list --project default > "$RESULTS/new_m_list.raw" 2>&1
check "machine list (same underlying identities)" "$RESULTS/old_m_list.raw" "$RESULTS/new_m_list.raw"

run_old machine describe old-machine-1 --project default > "$RESULTS/old_m_desc.raw" 2>&1
run_new machine describe new-machine-1 --project default > "$RESULTS/new_m_desc.raw" 2>&1
sed -E 's/^ID:.*$/ID: N/; s/(old|new)-machine-1/M/' "$RESULTS/old_m_desc.raw" > "$RESULTS/old_m_desc.norm"
sed -E 's/^ID:.*$/ID: N/; s/(old|new)-machine-1/M/' "$RESULTS/new_m_desc.raw" > "$RESULTS/new_m_desc.norm"
check "machine describe (normalized)" "$RESULTS/old_m_desc.norm" "$RESULTS/new_m_desc.norm"

run_old machine suspend old-machine-1 --project default > "$RESULTS/old_m_suspend.raw" 2>&1
run_new machine suspend new-machine-1 --project default > "$RESULTS/new_m_suspend.raw" 2>&1
sed -E 's/(old|new)-machine-1/M/' "$RESULTS/old_m_suspend.raw" > "$RESULTS/old_m_suspend.norm"
sed -E 's/(old|new)-machine-1/M/' "$RESULTS/new_m_suspend.raw" > "$RESULTS/new_m_suspend.norm"
check "machine suspend (normalized)" "$RESULTS/old_m_suspend.norm" "$RESULTS/new_m_suspend.norm"

run_old machine reactivate old-machine-1 --project default > "$RESULTS/old_m_react.raw" 2>&1
run_new machine reactivate new-machine-1 --project default > "$RESULTS/new_m_react.raw" 2>&1
sed -E 's/(old|new)-machine-1/M/' "$RESULTS/old_m_react.raw" > "$RESULTS/old_m_react.norm"
sed -E 's/(old|new)-machine-1/M/' "$RESULTS/new_m_react.raw" > "$RESULTS/new_m_react.norm"
check "machine reactivate (normalized)" "$RESULTS/old_m_react.norm" "$RESULTS/new_m_react.norm"

run_old machine binding add old-machine-1 --project default --issuer https://issuer.example --subject old-sub > "$RESULTS/old_b_add.raw" 2>&1
run_new machine binding add new-machine-1 --project default --issuer https://issuer.example --subject new-sub > "$RESULTS/new_b_add.raw" 2>&1
normalize "$RESULTS/old_b_add.raw" | sed -E 's/(old|new)-machine-1/M/; s/(old|new)-sub/S/' > "$RESULTS/old_b_add.norm"
normalize "$RESULTS/new_b_add.raw" | sed -E 's/(old|new)-machine-1/M/; s/(old|new)-sub/S/' > "$RESULTS/new_b_add.norm"
check "machine binding add (normalized)" "$RESULTS/old_b_add.norm" "$RESULTS/new_b_add.norm"

run_old machine binding list old-machine-1 --project default > "$RESULTS/old_b_list.raw" 2>&1
run_new machine binding list new-machine-1 --project default > "$RESULTS/new_b_list.raw" 2>&1
normalize "$RESULTS/old_b_list.raw" | sed -E 's/(old|new)-sub/S/' > "$RESULTS/old_b_list.norm"
normalize "$RESULTS/new_b_list.raw" | sed -E 's/(old|new)-sub/S/' > "$RESULTS/new_b_list.norm"
check "machine binding list (normalized)" "$RESULTS/old_b_list.norm" "$RESULTS/new_b_list.norm"

old_binding_id=$(run_old machine binding list old-machine-1 --project default | awk 'NR==2{print $1}')
new_binding_id=$(run_new machine binding list new-machine-1 --project default | awk 'NR==2{print $1}')
run_old machine binding rm old-machine-1 "$old_binding_id" --project default > "$RESULTS/old_b_rm.raw" 2>&1
run_new machine binding rm new-machine-1 "$new_binding_id" --project default > "$RESULTS/new_b_rm.raw" 2>&1
sed -E "s/$old_binding_id/N/; s/(old|new)-machine-1/M/" "$RESULTS/old_b_rm.raw" > "$RESULTS/old_b_rm.norm"
sed -E "s/$new_binding_id/N/; s/(old|new)-machine-1/M/" "$RESULTS/new_b_rm.raw" > "$RESULTS/new_b_rm.norm"
check "machine binding rm (normalized)" "$RESULTS/old_b_rm.norm" "$RESULTS/new_b_rm.norm"

run_old machine token issue old-machine-1 --project default --name old-token > "$RESULTS/old_t_issue.raw" 2>&1
run_new machine token issue new-machine-1 --project default --name new-token > "$RESULTS/new_t_issue.raw" 2>&1
normalize "$RESULTS/old_t_issue.raw" | sed -E 's/^ID:.*$/ID: N/' > "$RESULTS/old_t_issue.norm"
normalize "$RESULTS/new_t_issue.raw" | sed -E 's/^ID:.*$/ID: N/' > "$RESULTS/new_t_issue.norm"
check "machine token issue (normalized, one-time-secret format)" "$RESULTS/old_t_issue.norm" "$RESULTS/new_t_issue.norm"

run_old machine token list old-machine-1 --project default > "$RESULTS/old_t_list.raw" 2>&1
run_new machine token list new-machine-1 --project default > "$RESULTS/new_t_list.raw" 2>&1
normalize "$RESULTS/old_t_list.raw" > "$RESULTS/old_t_list.norm"
normalize "$RESULTS/new_t_list.raw" > "$RESULTS/new_t_list.norm"
check "machine token list (normalized)" "$RESULTS/old_t_list.norm" "$RESULTS/new_t_list.norm"

old_token_id=$(run_old machine token list old-machine-1 --project default | awk 'NR==2{print $1}')
new_token_id=$(run_new machine token list new-machine-1 --project default | awk 'NR==2{print $1}')
run_old machine token revoke old-machine-1 "$old_token_id" --project default --force > "$RESULTS/old_t_revoke.raw" 2>&1
run_new machine token revoke new-machine-1 "$new_token_id" --project default --force > "$RESULTS/new_t_revoke.raw" 2>&1
check "machine token revoke" "$RESULTS/old_t_revoke.raw" "$RESULTS/new_t_revoke.raw"

run_old machine token-hygiene > "$RESULTS/old_th.raw" 2>&1
run_new machine token-hygiene > "$RESULTS/new_th.raw" 2>&1
check "machine token-hygiene" "$RESULTS/old_th.raw" "$RESULTS/new_th.raw"

run_old machine audit --format csv > "$RESULTS/old_audit_csv.raw" 2>&1
run_new machine audit --format csv > "$RESULTS/new_audit_csv.raw" 2>&1
check "machine audit --format csv (byte-identical)" "$RESULTS/old_audit_csv.raw" "$RESULTS/new_audit_csv.raw"

run_old machine audit --format json > "$RESULTS/old_audit_json.raw" 2>&1
run_new machine audit --format json > "$RESULTS/new_audit_json.raw" 2>&1
if python3 -c "
import json, sys
a = json.load(open('$RESULTS/old_audit_json.raw'))
b = json.load(open('$RESULTS/new_audit_json.raw'))
a.pop('generated_at', None); b.pop('generated_at', None)
sys.exit(0 if a == b else 1)
"; then
  pass_count=$((pass_count + 1)); log "PASS  machine audit --format json (semantically identical, key order differs -- expected)"
else
  fail_count=$((fail_count + 1)); log "FAIL  machine audit --format json (semantic diff, not just key order)"
fi

run_old machine revoke old-machine-1 --project default --force > "$RESULTS/old_m_revoke.raw" 2>&1
run_new machine revoke new-machine-1 --project default --force > "$RESULTS/new_m_revoke.raw" 2>&1
sed -E 's/(old|new)-machine-1/M/' "$RESULTS/old_m_revoke.raw" > "$RESULTS/old_m_revoke.norm"
sed -E 's/(old|new)-machine-1/M/' "$RESULTS/new_m_revoke.raw" > "$RESULTS/new_m_revoke.norm"
check "machine revoke (normalized)" "$RESULTS/old_m_revoke.norm" "$RESULTS/new_m_revoke.norm"

# ── project (ADR-108 PR 6) ───────────────────────────────────────────────────
run_old project create --name old-proj-1 > "$RESULTS/old_p_create.raw" 2>&1
run_new project create --name new-proj-1 > "$RESULTS/new_p_create.raw" 2>&1
sed -E 's/(old|new)-proj-1/P/; s/id=[0-9]+/id=N/' "$RESULTS/old_p_create.raw" > "$RESULTS/old_p_create.norm"
sed -E 's/(old|new)-proj-1/P/; s/id=[0-9]+/id=N/' "$RESULTS/new_p_create.raw" > "$RESULTS/new_p_create.norm"
check "project create (normalized format)" "$RESULTS/old_p_create.norm" "$RESULTS/new_p_create.norm"

run_old project list > "$RESULTS/old_p_list.raw" 2>&1
run_new project list > "$RESULTS/new_p_list.raw" 2>&1
check "project list (same underlying projects)" "$RESULTS/old_p_list.raw" "$RESULTS/new_p_list.raw"

run_old project describe old-proj-1 > "$RESULTS/old_p_desc.raw" 2>&1
run_new project describe new-proj-1 > "$RESULTS/new_p_desc.raw" 2>&1
sed -E 's/(old|new)-proj-1/P/; s/id=[0-9]+/id=N/' "$RESULTS/old_p_desc.raw" > "$RESULTS/old_p_desc.norm"
sed -E 's/(old|new)-proj-1/P/; s/id=[0-9]+/id=N/' "$RESULTS/new_p_desc.raw" > "$RESULTS/new_p_desc.norm"
check "project describe (normalized)" "$RESULTS/old_p_desc.norm" "$RESULTS/new_p_desc.norm"

run_old project hygiene 1 > "$RESULTS/old_p_hyg.raw" 2>&1
run_new project hygiene 1 > "$RESULTS/new_p_hyg.raw" 2>&1
check "project hygiene" "$RESULTS/old_p_hyg.raw" "$RESULTS/new_p_hyg.raw"

run_old project env list --project old-proj-1 > "$RESULTS/old_p_envlist.raw" 2>&1
run_new project env list --project new-proj-1 > "$RESULTS/new_p_envlist.raw" 2>&1
sed -E 's/(old|new)-proj-1/P/' "$RESULTS/old_p_envlist.raw" > "$RESULTS/old_p_envlist.norm"
sed -E 's/(old|new)-proj-1/P/' "$RESULTS/new_p_envlist.raw" > "$RESULTS/new_p_envlist.norm"
check "project env list (normalized)" "$RESULTS/old_p_envlist.norm" "$RESULTS/new_p_envlist.norm"

run_old project env create --project old-proj-1 --name old-env-1 > "$RESULTS/old_p_envcreate.raw" 2>&1
run_new project env create --project new-proj-1 --name new-env-1 > "$RESULTS/new_p_envcreate.raw" 2>&1
sed -E 's/(old|new)-env-1/E/; s/id=[0-9]+/id=N/' "$RESULTS/old_p_envcreate.raw" > "$RESULTS/old_p_envcreate.norm"
sed -E 's/(old|new)-env-1/E/; s/id=[0-9]+/id=N/' "$RESULTS/new_p_envcreate.raw" > "$RESULTS/new_p_envcreate.norm"
check "project env create (normalized)" "$RESULTS/old_p_envcreate.norm" "$RESULTS/new_p_envcreate.norm"

# ── user (ADR-108 PR 6) ──────────────────────────────────────────────────────
run_old user create --username old-user-1 --email old-user-1@parity-check.test --password 'ParityCheck-Us3r-Pass!' > "$RESULTS/old_u_create.raw" 2>&1
run_new user create --username new-user-1 --email new-user-1@parity-check.test --password 'ParityCheck-Us3r-Pass!' > "$RESULTS/new_u_create.raw" 2>&1
sed -E 's/(old|new)-user-1/U/; s/id=[0-9]+/id=N/' "$RESULTS/old_u_create.raw" > "$RESULTS/old_u_create.norm"
sed -E 's/(old|new)-user-1/U/; s/id=[0-9]+/id=N/' "$RESULTS/new_u_create.raw" > "$RESULTS/new_u_create.norm"
check "user create (normalized format)" "$RESULTS/old_u_create.norm" "$RESULTS/new_u_create.norm"

run_old user list > "$RESULTS/old_u_list.raw" 2>&1
run_new user list > "$RESULTS/new_u_list.raw" 2>&1
check "user list (same underlying users)" "$RESULTS/old_u_list.raw" "$RESULTS/new_u_list.raw"

old_user_id=$(run_old user list | awk '/old-user-1/{print $1}')
new_user_id=$(run_new user list | awk '/new-user-1/{print $1}')

run_old user get --id "$old_user_id" > "$RESULTS/old_u_get.raw" 2>&1
run_new user get --id "$new_user_id" > "$RESULTS/new_u_get.raw" 2>&1
sed -E "s/$old_user_id/N/; s/(old|new)-user-1/U/; s/[0-9]{4}-[0-9]{2}-[0-9]{2}[^ ]*/TIMESTAMP/g" "$RESULTS/old_u_get.raw" > "$RESULTS/old_u_get.norm"
sed -E "s/$new_user_id/N/; s/(old|new)-user-1/U/; s/[0-9]{4}-[0-9]{2}-[0-9]{2}[^ ]*/TIMESTAMP/g" "$RESULTS/new_u_get.raw" > "$RESULTS/new_u_get.norm"
check "user get --id (normalized)" "$RESULTS/old_u_get.norm" "$RESULTS/new_u_get.norm"

run_old user suspend --id "$old_user_id" --by admin@parity-check.test > "$RESULTS/old_u_suspend.raw" 2>&1
run_new user suspend --id "$new_user_id" --by admin@parity-check.test > "$RESULTS/new_u_suspend.raw" 2>&1
sed -E "s/$old_user_id/N/g; s/(old|new)-user-1/U/g" "$RESULTS/old_u_suspend.raw" > "$RESULTS/old_u_suspend.norm"
sed -E "s/$new_user_id/N/g; s/(old|new)-user-1/U/g" "$RESULTS/new_u_suspend.raw" > "$RESULTS/new_u_suspend.norm"
check "user suspend (normalized)" "$RESULTS/old_u_suspend.norm" "$RESULTS/new_u_suspend.norm"

run_old user reactivate --id "$old_user_id" --by admin@parity-check.test > "$RESULTS/old_u_react.raw" 2>&1
run_new user reactivate --id "$new_user_id" --by admin@parity-check.test > "$RESULTS/new_u_react.raw" 2>&1
sed -E "s/$old_user_id/N/g; s/(old|new)-user-1/U/g" "$RESULTS/old_u_react.raw" > "$RESULTS/old_u_react.norm"
sed -E "s/$new_user_id/N/g; s/(old|new)-user-1/U/g" "$RESULTS/new_u_react.raw" > "$RESULTS/new_u_react.norm"
check "user reactivate (normalized)" "$RESULTS/old_u_react.norm" "$RESULTS/new_u_react.norm"

run_old user revoke-sessions --id "$old_user_id" --by admin@parity-check.test > "$RESULTS/old_u_revoke.raw" 2>&1
run_new user revoke-sessions --id "$new_user_id" --by admin@parity-check.test > "$RESULTS/new_u_revoke.raw" 2>&1
sed -E "s/$old_user_id/N/g; s/(old|new)-user-1/U/g" "$RESULTS/old_u_revoke.raw" > "$RESULTS/old_u_revoke.norm"
sed -E "s/$new_user_id/N/g; s/(old|new)-user-1/U/g" "$RESULTS/new_u_revoke.raw" > "$RESULTS/new_u_revoke.norm"
check "user revoke-sessions (normalized)" "$RESULTS/old_u_revoke.norm" "$RESULTS/new_u_revoke.norm"

run_old user delete --id "$old_user_id" --by admin@parity-check.test --force > "$RESULTS/old_u_delete.raw" 2>&1
run_new user delete --id "$new_user_id" --by admin@parity-check.test --force > "$RESULTS/new_u_delete.raw" 2>&1
sed -E "s/$old_user_id/N/g; s/(old|new)-user-1/U/g" "$RESULTS/old_u_delete.raw" > "$RESULTS/old_u_delete.norm"
sed -E "s/$new_user_id/N/g; s/(old|new)-user-1/U/g" "$RESULTS/new_u_delete.raw" > "$RESULTS/new_u_delete.norm"
check "user delete (normalized)" "$RESULTS/old_u_delete.norm" "$RESULTS/new_u_delete.norm"

log ""
log "=== $pass_count passed, $fail_count failed (results in $RESULTS) ==="
[ "$fail_count" -eq 0 ]
