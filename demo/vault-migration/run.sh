#!/usr/bin/env bash
# "Migrate off Vault in 5 minutes" — a self-contained demo.
#
# Stands up Keyorix (docker compose) + a throwaway HashiCorp Vault, seeds Vault
# with sample secrets, then migrates EVERY secret into Keyorix with one command
# (`keyorix-migrate vault`, the separate migration tool) and shows them. Tears
# everything down on exit.
#
# Requires: docker, curl, jq, the `keyorix` CLI and the `keyorix-migrate` tool on PATH
#   keyorix:         curl -fsSL https://raw.githubusercontent.com/keyorixhq/keyorix/main/install.sh | sh
#   keyorix-migrate: release binary or `make build` in migrate/ (docs/migrate-from-vault.md)
# For locally-built binaries:
#   KEYORIX_BIN=/path/to/keyorix KEYORIX_MIGRATE_BIN=/path/to/keyorix-migrate ./run.sh
# The Vault and Keyorix tokens reach keyorix-migrate through files, never argv.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
COMPOSE="docker compose -f ${ROOT}/docker-compose.yml -p keyorix-demo"
KX="${KEYORIX_BIN:-keyorix}"
KM="${KEYORIX_MIGRATE_BIN:-keyorix-migrate}"
KEYORIX_URL="http://localhost:8088"
VAULT_PORT="8200"
VAULT_ADDR="http://localhost:${VAULT_PORT}"
VAULT_TOKEN="root"

# Throwaway demo credentials (compose bootstraps the admin from these). The stack
# reads its credentials from Docker secrets files, not the environment, so write
# them into a temp directory (0640, group = your primary group, which the
# containers join via KEYORIX_SECRETS_GID). init-secrets.sh keeps the four files
# written here and adds the Postgres TLS pair the compose file also needs. The
# server refuses a secret file owned by anyone but root or its own uid, so the
# files are then handed to root (keeping the group): that needs sudo.
KEYORIX_ADMIN_PASSWORD="Admin123!"
export KEYORIX_ADMIN_USERNAME="admin"
export KEYORIX_ADMIN_EMAIL="admin@keyorix.local"
DEMO_SECRETS_DIR="$(mktemp -d)"
(
  umask 037
  printf '%s\n' "demo-db-pass" > "${DEMO_SECRETS_DIR}/db_password"
  printf '%s\n' "demo-master-pass" > "${DEMO_SECRETS_DIR}/master_password"
  printf '%s\n' "${KEYORIX_ADMIN_PASSWORD}" > "${DEMO_SECRETS_DIR}/admin_password"
  openssl rand -hex 32 > "${DEMO_SECRETS_DIR}/bootstrap_token"
)
export KEYORIX_SECRETS_DIR="${DEMO_SECRETS_DIR}"
KEYORIX_SECRETS_GID="$(id -g)"
export KEYORIX_SECRETS_GID
# 65534: a uid nobody here runs as, so init-secrets.sh's "owned by the server uid" refusal
# stays quiet; the chown below is what satisfies the server.
INIT_SECRETS_SERVER_UID=65534 "${ROOT}/scripts/selfhost/init-secrets.sh" --dir "${DEMO_SECRETS_DIR}" \
  --env-file "${DEMO_SECRETS_DIR}/.env.init-secrets" >/dev/null 2>"${DEMO_SECRETS_DIR}/init-secrets.log" \
  || { cat "${DEMO_SECRETS_DIR}/init-secrets.log" >&2; echo "scripts/selfhost/init-secrets.sh failed" >&2; rm -rf "${DEMO_SECRETS_DIR}"; exit 1; }
echo "Handing the demo secret files to root (the server refuses files owned by any other account); sudo may ask for your password."
sudo chown "root:${KEYORIX_SECRETS_GID}" "${DEMO_SECRETS_DIR}"/db_password "${DEMO_SECRETS_DIR}"/master_password \
  "${DEMO_SECRETS_DIR}"/admin_password "${DEMO_SECRETS_DIR}"/bootstrap_token \
  "${DEMO_SECRETS_DIR}"/postgres_tls.crt "${DEMO_SECRETS_DIR}"/postgres_tls.key \
  || { echo "could not chown the demo secrets to root: re-run where sudo works" >&2; rm -rf "${DEMO_SECRETS_DIR}"; exit 1; }

c()  { local msg="$1"; printf '\n\033[1;34m▶ %s\033[0m\n' "$msg"; }
ok() { local msg="$1"; printf '\033[0;32m✓ %s\033[0m\n' "$msg"; }

cleanup() {
  c "Cleaning up"
  docker rm -f keyorix-demo-vault >/dev/null 2>&1 || true
  $COMPOSE down -v >/dev/null 2>&1 || true
  rm -rf "${DEMO_SECRETS_DIR}"
  ok "Demo environment removed"
}
trap cleanup EXIT

command -v "$KX" >/dev/null 2>&1 || { echo "keyorix CLI not found — install it first (see header), or set KEYORIX_BIN"; exit 1; }
command -v "$KM" >/dev/null 2>&1 || { echo "keyorix-migrate not found — the Vault import lives in this separate tool: download it or build it from migrate/ (docs/migrate-from-vault.md), then put it on PATH or set KEYORIX_MIGRATE_BIN"; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "jq is required"; exit 1; }

c "1/5  Starting Keyorix (Postgres + API + web UI)"
$COMPOSE up -d postgres backend web
printf 'Waiting for Keyorix to bootstrap'
TOKEN=""
set +e  # the early attempts fail while the backend boots — don't let that exit
for _ in $(seq 1 60); do
  TOKEN="$(curl -s -X POST "${KEYORIX_URL}/auth/login" -H 'Content-Type: application/json' \
    -d "{\"username\":\"${KEYORIX_ADMIN_USERNAME}\",\"password\":\"${KEYORIX_ADMIN_PASSWORD}\"}" \
    2>/dev/null | jq -r '.data.token // empty')"
  [[ -n "$TOKEN" ]] && break
  printf '.'; sleep 2
done
set -e
echo
[[ -n "$TOKEN" ]] || { echo "Keyorix did not come up in time"; $COMPOSE logs backend | tail -20; exit 1; }
ok "Keyorix is up — logged in as ${KEYORIX_ADMIN_USERNAME}"

c "2/5  Starting a throwaway HashiCorp Vault and seeding it"
docker rm -f keyorix-demo-vault >/dev/null 2>&1 || true
docker run -d --name keyorix-demo-vault -p "${VAULT_PORT}:8200" \
  -e "VAULT_DEV_ROOT_TOKEN_ID=${VAULT_TOKEN}" -e "VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200" \
  hashicorp/vault:latest >/dev/null
set +e
for _ in $(seq 1 30); do curl -sf "${VAULT_ADDR}/v1/sys/health" >/dev/null 2>&1 && break; sleep 1; done
set -e
vault_put() { local path="$1"; local data="$2"; curl -s -H "X-Vault-Token: ${VAULT_TOKEN}" -X POST "${VAULT_ADDR}/v1/secret/data/$path" -d "$data" >/dev/null; }
vault_put demo/prod/database '{"data":{"username":"app_user","password":"REPLACE_WITH_YOUR_DB_PASSWORD"}}'
vault_put demo/prod/stripe   '{"data":{"value":"REPLACE_WITH_YOUR_STRIPE_KEY"}}'
vault_put demo/prod/redis    '{"data":{"url":"redis://cache.prod.internal:6379"}}'
ok "Seeded Vault with 3 paths under secret/demo/prod/ (4 secrets)"

c "3/5  What's in Vault today"
echo "  secret/demo/prod/database  → username, password"
echo "  secret/demo/prod/stripe    → value"
echo "  secret/demo/prod/redis     → url"

c "4/5  Migrating EVERY secret into Keyorix — one command"
# keyorix-migrate takes numeric project/environment IDs: look up "default" / "production".
AUTH_HDR="Authorization: Bearer ${TOKEN}"
PROJECT_ID="$(curl -sf -H "$AUTH_HDR" "${KEYORIX_URL}/api/v1/projects" | jq -r '.data.projects[] | select(.name=="default") | .id' | head -1)"
[[ -n "$PROJECT_ID" ]] || { echo "could not find the 'default' project on ${KEYORIX_URL}"; exit 1; }
ENV_ID="$(curl -sf -H "$AUTH_HDR" "${KEYORIX_URL}/api/v1/projects/${PROJECT_ID}/environments" | jq -r '.data.environments[] | select(.name=="production") | .id' | head -1)"
[[ -n "$ENV_ID" ]] || { echo "could not find the 'production' environment in project ${PROJECT_ID}"; exit 1; }
# Both tokens go in 0600 files inside the demo secrets dir (removed on exit): a flag value
# would show in ps and shell history.
(umask 077; printf '%s\n' "$TOKEN" > "${DEMO_SECRETS_DIR}/keyorix.token"; printf '%s\n' "$VAULT_TOKEN" > "${DEMO_SECRETS_DIR}/vault.token")
echo "  \$ keyorix-migrate vault --server ${KEYORIX_URL} --project ${PROJECT_ID} --environment ${ENV_ID} \\"
echo "      --vault-addr ${VAULT_ADDR} --vault-mount secret --vault-path demo/prod \\"
echo "      --token-file <keyorix token file> --vault-token-file <vault token file> --apply"
"$KM" vault --server "$KEYORIX_URL" --project "$PROJECT_ID" --environment "$ENV_ID" \
  --vault-addr "$VAULT_ADDR" --vault-mount secret --vault-path demo/prod \
  --token-file "${DEMO_SECRETS_DIR}/keyorix.token" --vault-token-file "${DEMO_SECRETS_DIR}/vault.token" \
  --apply

c "5/5  The secrets now live in Keyorix"
KEYORIX_SERVER="$KEYORIX_URL" KEYORIX_TOKEN="$TOKEN" "$KX" secret list

ok "Migration complete. Open ${KEYORIX_URL} (admin / ${KEYORIX_ADMIN_PASSWORD}) to browse them in the UI."
echo
echo "That's the whole 'leave Vault' story: point Keyorix at your live Vault, run one"
echo "command, and every secret is imported — names, values, multi-field paths and all."
