#!/usr/bin/env bash
# rotate-secrets.sh — one-shot rotation of every secret in .env that was
# exposed via an earlier `bash -x` mistake in this session. This box's
# target stack is disposable scan data, so the plan is: stop -> regenerate
# -> wipe the (confirmed stack-exclusive, nothing-else-uses-them) postgres
# and keys volumes -> start -> bootstrap -> provision the viewer test user
# again (its own record is gone with the wipe) -> one authenticated scan
# pass to prove it all actually works end-to-end.
#
# Never prints a secret value -- only "<NAME> rotated" confirmations.
set -euo pipefail
WORKDIR="/opt/keyorix-dast"
ENV_FILE="$WORKDIR/.env"

set -a; . "$ENV_FILE"; set +a
# shellcheck source=/dev/null
. "$WORKDIR/lib-alert.sh"
# shellcheck source=/dev/null
. "$WORKDIR/lib-passwords.sh"

echo "Stopping stack..."
( cd "$WORKDIR" && docker compose down )

NEW_DB_PASSWORD="$(openssl rand -hex 32)"
NEW_BOOTSTRAP_TOKEN="$(openssl rand -hex 32)"
NEW_KEK="$(openssl rand -hex 32)"
NEW_ADMIN_PASSWORD="$(generate_compliant_password "$KEYORIX_ADMIN_USERNAME" "dast" "DAST" "Admin")"

rewrite_env_var() {
    local name="$1" value="$2"
    if grep -q "^${name}=" "$ENV_FILE"; then
        awk -v n="$name" -v v="$value" -F= 'BEGIN{OFS="="} $1==n{print n,v; next} {print}' "$ENV_FILE" > "$ENV_FILE.tmp"
        mv "$ENV_FILE.tmp" "$ENV_FILE"
    else
        echo "${name}=${value}" >> "$ENV_FILE"
    fi
}

rewrite_env_var "KEYORIX_DB_PASSWORD" "$NEW_DB_PASSWORD"
echo "KEYORIX_DB_PASSWORD rotated"
rewrite_env_var "KEYORIX_BOOTSTRAP_TOKEN" "$NEW_BOOTSTRAP_TOKEN"
echo "KEYORIX_BOOTSTRAP_TOKEN rotated"
rewrite_env_var "KEYORIX_DAST_KEK" "$NEW_KEK"
echo "KEYORIX_DAST_KEK rotated"
rewrite_env_var "KEYORIX_ADMIN_PASSWORD" "$NEW_ADMIN_PASSWORD"
echo "KEYORIX_ADMIN_PASSWORD rotated"

# The dast-viewer test user record and its password live in the DB volume
# being wiped below -- remove the now-stale credential lines so
# provision-testuser.sh's own "already provisioned, nothing to do" check
# (which trusts .env without re-verifying against a wiped DB) doesn't
# short-circuit on a value that no longer exists anywhere.
sed -i '/^KEYORIX_TESTUSER_USERNAME=/d;/^KEYORIX_TESTUSER_EMAIL=/d;/^KEYORIX_TESTUSER_PASSWORD=/d' "$ENV_FILE"
chmod 600 "$ENV_FILE"

unset NEW_DB_PASSWORD NEW_BOOTSTRAP_TOKEN NEW_KEK NEW_ADMIN_PASSWORD

# Re-source the just-rewritten file: docker compose gives actual shell-
# exported environment variables PRECEDENCE over its own .env file, so the
# OLD values this script exported at the very top (via `set -a; . "$ENV_FILE"`,
# before rotation) would otherwise still win when `docker compose up` reads
# them below -- the container would bootstrap with the pre-rotation admin
# password while everything else on disk has already moved to the new one.
set -a; . "$ENV_FILE"; set +a

echo "Wiping scan-target DB + keys volumes (confirmed used only by this stack's own two containers)..."
( cd "$WORKDIR" && docker compose down -v )

echo "Starting stack with rotated secrets..."
( cd "$WORKDIR" && docker compose up -d )

for _ in $(seq 1 30); do
    curl -sf http://localhost:8080/openapi.yaml >/dev/null 2>&1 && break
    sleep 2
done
if ! curl -sf http://localhost:8080/openapi.yaml >/dev/null 2>&1; then
    dast_alert "rotate-secrets: keyorix stack did not become ready within 60s after volume wipe + restart"
    exit 1
fi
echo "Stack up and ready."

echo "Running bootstrap + post-bootstrap check via refresh-src.sh..."
"$WORKDIR/refresh-src.sh" >/dev/null

echo "Provisioning dast-viewer test user (its old record was wiped with the volume)..."
"$WORKDIR/provision-testuser.sh"

echo "Running one authenticated scan pass to prove it all works end-to-end..."
"$WORKDIR/scan-zap-auth.sh"

echo "Rotation complete."
