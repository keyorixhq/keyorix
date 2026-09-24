#!/usr/bin/env bash
# cli-parity-check.sh — live-server golden-output parity check for ADR-108
# PR 2 and PR 1 (docs/cli-split-inventory.md §7): builds the old thick
# `keyorix` CLI, the new thin `keyorix-next` CLI, and `keyorix-server`, boots
# a real local SQLite server, bootstraps an admin, and runs the pat/auth/
# machine commands (PR 2) plus the dynamic-secret/rotation/break-glass
# commands (PR 1) through both CLIs against the SAME live server -- comparing
# stdout and exit codes, not mocked responses.
#
# This is a manual verification tool (like PR 0's own "exercised against a
# real running server ... not just unit tests"), not a CI gate: it needs to
# bootstrap a real server instance, which is more than a unit test should do.
# Run it by hand after touching cli/cmd/{pat,machine,logout,mfa,login,status,
# dynamicsecret,rotation,breakglass}.go or their server-side handlers.
#
# Known gap (stated, not silent): dynamic-secret issue/renew/revoke need a
# real backend connection this SQLite-only instance can't provide. Those three
# are parity-checked as "both CLIs get the identical HTTP failure against the
# same unreachable admin DSN," not a successful credential mint -- see the
# dynamic-secret section below.
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
#   - rotation list/show/create: NOT compared for literal parity -- the OLD
#     CLI's policyView struct decodes the server's RotationPolicy response with
#     snake_case json tags against a model that actually marshals PascalCase
#     (models.RotationPolicy has no json tags at all), so every multi-word
#     field (interval, alert, active, created-by, target's project/env number)
#     silently decodes as its zero value in the OLD CLI today. The NEW CLI's
#     generated apiclient.RotationPolicy type was fixed (see cli/cmd/rotation.go's
#     rotScopeTarget doc comment, and openapi.yaml's RotationPolicy schema doc)
#     to actually match the real wire format, so these three commands now show
#     the CORRECT values in the new CLI while the old CLI keeps showing zeros --
#     a deliberate, verified bug fix, not a divergence to chase into parity.
#     Verified instead: TestRunRotList_MatchesOldCLIOutputShape and siblings in
#     cli/cmd/rotation_test.go assert the new CLI's OWN correct output.
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
    -e 's/keyorix-next/keyorix/g' \
    -e 's/kx_(pat|machine)_[A-Za-z0-9_-]+/TOKEN/g' \
    -e 's/^[[:space:]]*[0-9]+([[:space:]]|$)/ID\1/' \
    -e 's/id=[0-9]+/id=N/' \
    -e 's/id:[[:space:]]+[0-9]+/id: N/' \
    -e 's/#[0-9]+/#N/' \
    -e 's/(issue|revoke|renew|describe|show) [0-9]+$/\1 N/' \
    -e 's/[0-9]{4}-[0-9]{2}-[0-9]{2}([T ][0-9:.]+(Z|[+-][0-9:]+)?)?/TIMESTAMP/g' \
    -e 's/(old|new)-(pat|machine|token|sub|dyn|rot)-?1?/NAME/g' \
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
# The dynamic-secret section below deliberately registers a config against a
# loopback admin DSN (127.0.0.1) so `issue` fails deterministically without a
# real backend -- CreateDynamicSecretConfig's SSRF guard
# (enforceDynamicSecretSSRFGuard) refuses any private/loopback target unless
# this is explicitly opted into, so without this the very first
# `dynamic-secret create` call below would fail closed and abort the whole
# script under `set -e`.
cat >>"$INSTANCE/keyorix.yaml" <<'EOF'
dynamic_secrets:
  allow_private_network_targets: true
break_glass:
  enabled: true
  emergency_role: project_developer
  default_ttl: 4h
  max_ttl: 24h
EOF
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

# ── dynamic-secret, rotation, break-glass (ADR-108 PR 1) ──────────────────────
# These need a numeric project id (unlike machine's --project <name>).
PROJECT_ID=$(run_old project list | awk '$2=="default"{print $1; exit}')
# dynamic-secret create's --environment-id flag help says "0 = project-wide",
# but CreateDynamicSecretConfig (internal/core/dynamic_secrets.go) unconditionally
# calls GetEnvironment(ctx, req.EnvironmentID) even when it's 0, which always 404s
# ("environment 0 not found") -- the flag's own documented default doesn't work
# against a real server. A real, pre-existing server-side bug (0 isn't a valid
# environment ID and never will be), out of scope for this CLI-porting PR to fix
# there -- this script just avoids it by always passing a real environment id.
ENV_ID=$(run_old project environments "$PROJECT_ID" | awk '$1 ~ /^[0-9]+$/{print $1; exit}')

# dynamic-secret create/get-config/classify/leases/revoke-all don't need a live
# backend (the admin DSN is stored encrypted, never connected to, until issue).
# issue/renew/revoke DO need a real connection, which this script's SQLite-only
# instance can't provide -- for those three, parity is checked as "both CLIs get
# the identical HTTP failure against the same bogus DSN", not a successful mint.
# This is a real, stated gap (not a silent one): a genuinely successful
# issue/renew/revoke round-trip is NOT exercised here.
export KEYORIX_DYNAMIC_ADMIN_DSN="postgres://u:p@127.0.0.1:1/does-not-exist"

run_old dynamic-secret create --name old-dyn-1 --project-id "$PROJECT_ID" --environment-id "$ENV_ID" --backend postgres \
  --creation-template 'GRANT SELECT ON ALL TABLES IN SCHEMA public TO {{name}};' > "$RESULTS/old_dyn_create.raw" 2>&1
run_new dynamic-secret create --name new-dyn-1 --project-id "$PROJECT_ID" --environment-id "$ENV_ID" --backend postgres \
  --creation-template 'GRANT SELECT ON ALL TABLES IN SCHEMA public TO {{name}};' > "$RESULTS/new_dyn_create.raw" 2>&1
normalize "$RESULTS/old_dyn_create.raw" | sed -E 's/(old|new)-dyn-1/D/' > "$RESULTS/old_dyn_create.norm"
normalize "$RESULTS/new_dyn_create.raw" | sed -E 's/(old|new)-dyn-1/D/' > "$RESULTS/new_dyn_create.norm"
check "dynamic-secret create (normalized format)" "$RESULTS/old_dyn_create.norm" "$RESULTS/new_dyn_create.norm"

run_old dynamic-secret list --project-id "$PROJECT_ID" > "$RESULTS/old_dyn_list.raw" 2>&1
run_new dynamic-secret list --project-id "$PROJECT_ID" > "$RESULTS/new_dyn_list.raw" 2>&1
check "dynamic-secret list (same underlying configs)" "$RESULTS/old_dyn_list.raw" "$RESULTS/new_dyn_list.raw"

old_dyn_id=$(run_old dynamic-secret list --project-id "$PROJECT_ID" | awk '$2=="old-dyn-1"{print $1}')
new_dyn_id=$(run_new dynamic-secret list --project-id "$PROJECT_ID" | awk '$2=="new-dyn-1"{print $1}')

run_old dynamic-secret get-config "$old_dyn_id" > "$RESULTS/old_dyn_get.raw" 2>&1
run_new dynamic-secret get-config "$new_dyn_id" > "$RESULTS/new_dyn_get.raw" 2>&1
sed -E 's/^ID:.*$/ID: N/; s/(old|new)-dyn-1/D/' "$RESULTS/old_dyn_get.raw" > "$RESULTS/old_dyn_get.norm"
sed -E 's/^ID:.*$/ID: N/; s/(old|new)-dyn-1/D/' "$RESULTS/new_dyn_get.raw" > "$RESULTS/new_dyn_get.norm"
check "dynamic-secret get-config (normalized)" "$RESULTS/old_dyn_get.norm" "$RESULTS/new_dyn_get.norm"

run_old dynamic-secret leases "$old_dyn_id" > "$RESULTS/old_dyn_leases.raw" 2>&1
run_new dynamic-secret leases "$new_dyn_id" > "$RESULTS/new_dyn_leases.raw" 2>&1
check "dynamic-secret leases (both empty)" "$RESULTS/old_dyn_leases.raw" "$RESULTS/new_dyn_leases.raw"

run_old dynamic-secret classify "$old_dyn_id" --level confidential > "$RESULTS/old_dyn_classify.raw" 2>&1
run_new dynamic-secret classify "$new_dyn_id" --level confidential > "$RESULTS/new_dyn_classify.raw" 2>&1
sed -E "s/$old_dyn_id/N/" "$RESULTS/old_dyn_classify.raw" > "$RESULTS/old_dyn_classify.norm"
sed -E "s/$new_dyn_id/N/" "$RESULTS/new_dyn_classify.raw" > "$RESULTS/new_dyn_classify.norm"
check "dynamic-secret classify (normalized)" "$RESULTS/old_dyn_classify.norm" "$RESULTS/new_dyn_classify.norm"

run_old dynamic-secret issue "$old_dyn_id" > "$RESULTS/old_dyn_issue.raw" 2>&1 || true
run_new dynamic-secret issue "$new_dyn_id" > "$RESULTS/new_dyn_issue.raw" 2>&1 || true
old_issue_status=$(grep -oE 'HTTP [0-9]+' "$RESULTS/old_dyn_issue.raw" | head -1 | grep -oE '[0-9]+')
new_issue_status=$(grep -oE 'HTTP [0-9]+' "$RESULTS/new_dyn_issue.raw" | head -1 | grep -oE '[0-9]+')
if [ -n "$old_issue_status" ] && [ "$old_issue_status" = "$new_issue_status" ]; then
  pass_count=$((pass_count + 1)); log "PASS  dynamic-secret issue (both HTTP $old_issue_status against an unreachable DSN)"
else
  fail_count=$((fail_count + 1)); log "FAIL  dynamic-secret issue: old=$old_issue_status new=$new_issue_status"
fi

run_old dynamic-secret renew no-such-lease > "$RESULTS/old_dyn_renew.raw" 2>&1 || true
run_new dynamic-secret renew no-such-lease > "$RESULTS/new_dyn_renew.raw" 2>&1 || true
old_renew_status=$(grep -oE 'HTTP [0-9]+' "$RESULTS/old_dyn_renew.raw" | head -1 | grep -oE '[0-9]+')
new_renew_status=$(grep -oE 'HTTP [0-9]+' "$RESULTS/new_dyn_renew.raw" | head -1 | grep -oE '[0-9]+')
if [ "$old_renew_status" = "$new_renew_status" ] && [ "$old_renew_status" = "404" ]; then
  pass_count=$((pass_count + 1)); log "PASS  dynamic-secret renew (both HTTP 404, no such lease)"
else
  fail_count=$((fail_count + 1)); log "FAIL  dynamic-secret renew: old=$old_renew_status new=$new_renew_status"
fi

run_old dynamic-secret revoke no-such-lease > "$RESULTS/old_dyn_revoke.raw" 2>&1 || true
run_new dynamic-secret revoke no-such-lease > "$RESULTS/new_dyn_revoke.raw" 2>&1 || true
old_revoke_status=$(grep -oE 'HTTP [0-9]+' "$RESULTS/old_dyn_revoke.raw" | head -1 | grep -oE '[0-9]+')
new_revoke_status=$(grep -oE 'HTTP [0-9]+' "$RESULTS/new_dyn_revoke.raw" | head -1 | grep -oE '[0-9]+')
if [ "$old_revoke_status" = "$new_revoke_status" ] && [ "$old_revoke_status" = "404" ]; then
  pass_count=$((pass_count + 1)); log "PASS  dynamic-secret revoke (both HTTP 404, no such lease)"
else
  fail_count=$((fail_count + 1)); log "FAIL  dynamic-secret revoke: old=$old_revoke_status new=$new_revoke_status"
fi

run_old dynamic-secret revoke-all "$old_dyn_id" --yes > "$RESULTS/old_dyn_revokeall.raw" 2>&1
run_new dynamic-secret revoke-all "$new_dyn_id" --yes > "$RESULTS/new_dyn_revokeall.raw" 2>&1
sed -E "s/Config $old_dyn_id:/Config N:/" "$RESULTS/old_dyn_revokeall.raw" > "$RESULTS/old_dyn_revokeall.norm"
sed -E "s/Config $new_dyn_id:/Config N:/" "$RESULTS/new_dyn_revokeall.raw" > "$RESULTS/new_dyn_revokeall.norm"
check "dynamic-secret revoke-all (normalized, zero leases)" "$RESULTS/old_dyn_revokeall.norm" "$RESULTS/new_dyn_revokeall.norm"
unset KEYORIX_DYNAMIC_ADMIN_DSN

# ── rotation ─────────────────────────────────────────────────────────────────
# Both create calls are allowed to fail (set +e/-e around each): the grep-based
# check below inspects success/failure explicitly, so a real failure here should
# be reported as a FAIL by that check, not silently abort the whole script under
# this file's `set -e`.
set +e
run_old rotation create --name old-rot-1 --scope project --project-id "$PROJECT_ID" \
  --interval-days 30 > "$RESULTS/old_rot_create.raw" 2>&1
run_new rotation create --name new-rot-1 --scope project --project-id "$PROJECT_ID" \
  --interval-days 30 > "$RESULTS/new_rot_create.raw" 2>&1
set -e
# Not literal-parity-checked: see this script's header ("rotation list/show/create").
if grep -q "Created rotation policy #" "$RESULTS/old_rot_create.raw" && grep -q "Created rotation policy #" "$RESULTS/new_rot_create.raw"; then
  pass_count=$((pass_count + 1)); log "PASS  rotation create (both succeeded; NOT byte-compared, see header)"
else
  fail_count=$((fail_count + 1)); log "FAIL  rotation create: old=$(cat "$RESULTS/old_rot_create.raw") new=$(cat "$RESULTS/new_rot_create.raw")"
fi

run_old rotation list --project-id "$PROJECT_ID" > "$RESULTS/old_rot_list.raw" 2>&1
run_new rotation list --project-id "$PROJECT_ID" > "$RESULTS/new_rot_list.raw" 2>&1
# Not literal-parity-checked: see this script's header ("rotation list/show/create").
if grep -q "old-rot-1" "$RESULTS/old_rot_list.raw" && grep -q "new-rot-1" "$RESULTS/new_rot_list.raw"; then
  pass_count=$((pass_count + 1)); log "PASS  rotation list (both list their policy; NOT byte-compared, see header)"
else
  fail_count=$((fail_count + 1)); log "FAIL  rotation list: old=$(cat "$RESULTS/old_rot_list.raw") new=$(cat "$RESULTS/new_rot_list.raw")"
fi

old_rot_id=$(run_old rotation list --project-id "$PROJECT_ID" | awk '$2=="old-rot-1"{print $1}')
new_rot_id=$(run_new rotation list --project-id "$PROJECT_ID" | awk '$2=="new-rot-1"{print $1}')

run_old rotation show "$old_rot_id" > "$RESULTS/old_rot_show.raw" 2>&1
run_new rotation show "$new_rot_id" > "$RESULTS/new_rot_show.raw" 2>&1
# Not literal-parity-checked: see this script's header ("rotation list/show/create").
# The new CLI must show the CORRECT interval (30 days); the old CLI is expected
# to still show its pre-existing "0 days" decoding bug.
if grep -q "interval:         30 days" "$RESULTS/new_rot_show.raw"; then
  pass_count=$((pass_count + 1)); log "PASS  rotation show (new CLI decodes interval_days correctly; NOT byte-compared with old, see header)"
else
  fail_count=$((fail_count + 1)); log "FAIL  rotation show: new CLI did not show the correct interval: $(cat "$RESULTS/new_rot_show.raw")"
fi

run_old rotation status --project-id "$PROJECT_ID" > "$RESULTS/old_rot_status.raw" 2>&1
run_new rotation status --project-id "$PROJECT_ID" > "$RESULTS/new_rot_status.raw" 2>&1
check "rotation status (no covered secrets overdue)" "$RESULTS/old_rot_status.raw" "$RESULTS/new_rot_status.raw"

run_old rotation plan "$PROJECT_ID" > "$RESULTS/old_rot_plan.raw" 2>&1
run_new rotation plan "$PROJECT_ID" > "$RESULTS/new_rot_plan.raw" 2>&1
check "rotation plan (nothing to rotate)" "$RESULTS/old_rot_plan.raw" "$RESULTS/new_rot_plan.raw"

run_old rotation order "$PROJECT_ID" > "$RESULTS/old_rot_order.raw" 2>&1
run_new rotation order "$PROJECT_ID" > "$RESULTS/new_rot_order.raw" 2>&1
check "rotation order (no dependencies)" "$RESULTS/old_rot_order.raw" "$RESULTS/new_rot_order.raw"

run_old rotation delete "$old_rot_id" > "$RESULTS/old_rot_delete.raw" 2>&1
run_new rotation delete "$new_rot_id" > "$RESULTS/new_rot_delete.raw" 2>&1
sed -E "s/$old_rot_id/N/" "$RESULTS/old_rot_delete.raw" > "$RESULTS/old_rot_delete.norm"
sed -E "s/$new_rot_id/N/" "$RESULTS/new_rot_delete.raw" > "$RESULTS/new_rot_delete.norm"
check "rotation delete (normalized)" "$RESULTS/old_rot_delete.norm" "$RESULTS/new_rot_delete.norm"

# ── break-glass ──────────────────────────────────────────────────────────────
# ActivateBreakGlass is deliberately not RBAC-gated, but it does require the
# ACTIVATING user to be a project MEMBER (IsProjectMember) -- a global-only role
# grant (what "keyorix system init" bootstraps the admin with) does not count
# (internal/core/break_glass.go's own doc: "a user scoped only globally ... is
# refused"). Grant the admin a project-scoped role first so activation can
# succeed at all.
# rbac assign-role's --project takes a NAME, not a numeric id (unlike every
# other --project-id flag in this script). project_viewer (membership) must
# differ from project_developer (the configured break_glass.emergency_role
# above) -- ActivateBreakGlass's own grant step fails with "Role already
# assigned" if the activating user already holds the emergency role itself.
run_old rbac assign-role --user admin@parity-check.test --role project_viewer --project default >/dev/null

# ActivateBreakGlass refuses a second concurrent activation for the same
# (user, project) pair (prevents indefinite renewal), and both CLIs activate
# as the SAME admin user against the SAME project here -- so each activate is
# immediately paired with its own revoke (old activate+revoke, then new
# activate+revoke) rather than trying to hold both active at once.
#
# set +e for this whole pair: the admin session's token was observed going
# intermittently stale (HTTP 401) right around here in practice, root cause
# not pinned down (a real TTL/invalidation interaction with the old CLI's own
# concurrent auth activity against the same account, or something else). A
# failure here should surface as a FAIL from the check()s below, not silently
# abort the rest of this script under `set -e`.
set +e
run_old break-glass activate --project-id "$PROJECT_ID" --justification "old parity test" \
  > "$RESULTS/old_bg_activate.raw" 2>&1
old_bg_id=$(grep -oE 'id=[0-9]+' "$RESULTS/old_bg_activate.raw" | head -1 | grep -oE '[0-9]+')
run_old break-glass revoke --project-id "$PROJECT_ID" --activation-id "$old_bg_id" > "$RESULTS/old_bg_revoke.raw" 2>&1

"$BIN/keyorix-next" login --server "$SERVER_URL" --username admin --password "$ADMIN_PASSWORD" >/dev/null 2>&1
run_new break-glass activate --project-id "$PROJECT_ID" --justification "new parity test" \
  > "$RESULTS/new_bg_activate.raw" 2>&1
new_bg_id=$(grep -oE 'id=[0-9]+' "$RESULTS/new_bg_activate.raw" | head -1 | grep -oE '[0-9]+')
run_new break-glass revoke --project-id "$PROJECT_ID" --activation-id "$new_bg_id" > "$RESULTS/new_bg_revoke.raw" 2>&1
set -e

normalize "$RESULTS/old_bg_activate.raw" | sed -E 's/(old|new) parity test/J/' > "$RESULTS/old_bg_activate.norm"
normalize "$RESULTS/new_bg_activate.raw" | sed -E 's/(old|new) parity test/J/' > "$RESULTS/new_bg_activate.norm"
check "break-glass activate (normalized)" "$RESULTS/old_bg_activate.norm" "$RESULTS/new_bg_activate.norm"

sed -E "s/activation $old_bg_id /activation N /" "$RESULTS/old_bg_revoke.raw" > "$RESULTS/old_bg_revoke.norm"
sed -E "s/activation $new_bg_id /activation N /" "$RESULTS/new_bg_revoke.raw" > "$RESULTS/new_bg_revoke.norm"
check "break-glass revoke (normalized)" "$RESULTS/old_bg_revoke.norm" "$RESULTS/new_bg_revoke.norm"

# Both activations are revoked by now -- list shows the same 2 (revoked)
# entries regardless of which CLI is asking.
# Both CLIs' admin sessions were observed going stale intermittently around
# the rbac assign-role call earlier in this section (plausibly a "permissions
# changed, invalidate existing sessions for this principal" security measure,
# not root-caused further -- see the set +e block above's comment). Re-auth
# both immediately before this final check for the same reason.
KEYORIX_PASSWORD="$ADMIN_PASSWORD" "$BIN/keyorix" connect "$SERVER_URL" --username admin --insecure >/dev/null 2>&1
"$BIN/keyorix-next" login --server "$SERVER_URL" --username admin --password "$ADMIN_PASSWORD" >/dev/null 2>&1
set +e
run_old break-glass list --project-id "$PROJECT_ID" > "$RESULTS/old_bg_list.raw" 2>&1
run_new break-glass list --project-id "$PROJECT_ID" > "$RESULTS/new_bg_list.raw" 2>&1
set -e
check "break-glass list (same underlying activations)" "$RESULTS/old_bg_list.raw" "$RESULTS/new_bg_list.raw"

log ""
log "=== $pass_count passed, $fail_count failed (results in $RESULTS) ==="
[ "$fail_count" -eq 0 ]
