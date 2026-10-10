#!/usr/bin/env bash
# scripts/demo/up.sh — one-command air-gapped Keyorix demo.
#
# Builds (once) a local air-gapped server image WITH the web UI embedded —
# the published ghcr.io/keyorixhq/keyorix-server-airgap image does NOT embed
# it (see #2752); this script works around that by running
# populate-webui-dist before the docker build itself, exactly as `make
# release`'s binary-tarball path already does. Then starts a single
# SQLite-backed container (no Postgres dependency — matches the air-gapped
# edition's single-binary pitch), seeds a realistic org through the public
# API/CLI only (never the database directly), and prints the URL + demo
# logins.
#
# Idempotent: safe to re-run. If the demo is already up and seeded, it just
# reprints the URL + logins (read from .demo-2-state, written on first run —
# a machine token is shown exactly once by the product itself, so a second
# run cannot regenerate it without destroying and re-seeding).
#
# Offline once the image exists: building the image needs network (base
# image pull, Go module download, pnpm install) exactly once; every run
# after that — including the container boot and the full seed walk below —
# makes zero outbound network calls (proven by scripts/airgap-e2e.sh and by
# this script's own CI coverage, journey17).
#
# Usage: scripts/demo/up.sh [--rebuild]
#   --rebuild   force a fresh image build even if keyorix-demo:airgap exists

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO_ROOT"

IMAGE_TAG="keyorix-demo:airgap"
CONTAINER_NAME="keyorix-demo"
VOLUME_NAME="keyorix-demo-data"
PORT="${KEYORIX_DEMO_PORT:-8080}"
STATE_FILE="$REPO_ROOT/.demo-2-state"

# Fixed, clearly-labeled demo credentials — not security-sensitive, this is a
# throwaway local demo environment, not a real deployment. Fixed values make
# re-runs idempotent without needing to persist secrets outside the state file.
ADMIN_USER="admin"
ADMIN_EMAIL="admin@keyorix.demo"
ADMIN_PASSWORD="Correct-Horse-Battery-2026"
BOOTSTRAP_TOKEN="keyorix-demo-bootstrap-token"
ALICE_PASSWORD="Nebula-Quartz-Flagstone-2026"
MASTER_PASSWORD="keyorix-demo-master-passphrase-2026"

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'
step() { echo -e "${CYAN}==>${NC} $1"; }
info() { echo -e "${BLUE}  i${NC} $1"; }
ok()   { echo -e "${GREEN}  ok${NC} $1"; }
warn() { echo -e "${YELLOW}  !${NC} $1"; }

REBUILD=false
for arg in "$@"; do
  case "$arg" in
    --rebuild) REBUILD=true ;;
    *) echo "unknown argument: $arg" >&2; exit 1 ;;
  esac
done

command -v docker >/dev/null 2>&1 || { echo "docker is required" >&2; exit 1; }

CLI_BIN="$REPO_ROOT/bin/keyorix"
if [ ! -x "$CLI_BIN" ]; then
  step "Building the CLI (used by this script to seed the demo, not a build dependency of the image)"
  make -C "$REPO_ROOT" build-cli >/dev/null
fi

# ── Build the image (once) ─────────────────────────────────────────────────
if [ "$REBUILD" = true ] || ! docker image inspect "$IMAGE_TAG" >/dev/null 2>&1; then
  step "Building the air-gapped image with the web UI embedded (needs network this one time)"
  command -v pnpm >/dev/null 2>&1 || { echo "pnpm is required to build the web UI (see web/package.json)" >&2; exit 1; }
  make -C "$REPO_ROOT" populate-webui-dist >/dev/null
  docker build -f server/Dockerfile --build-arg BUILD_TAGS=noaws,noazure,nogcp -t "$IMAGE_TAG" "$REPO_ROOT" >/dev/null
  git -C "$REPO_ROOT" checkout -- server/webui/dist/index.html 2>/dev/null || true
  ok "Built $IMAGE_TAG"
else
  info "Reusing existing image $IMAGE_TAG (pass --rebuild to force a fresh build)"
fi

# ── Idempotent re-run: already seeded ──────────────────────────────────────
if [ -f "$STATE_FILE" ] && docker ps --format '{{.Names}}' | grep -qx "$CONTAINER_NAME"; then
  info "Demo already running and seeded — reprinting connection info"
  cat "$STATE_FILE"
  exit 0
fi

# ── Start the container (fresh or resuming an existing volume) ────────────
docker volume create "$VOLUME_NAME" >/dev/null

ALREADY_SEEDED=false
if docker run --rm -v "$VOLUME_NAME:/app/data" alpine test -f /app/data/.demo-seeded 2>/dev/null; then
  ALREADY_SEEDED=true
fi

if ! docker ps --format '{{.Names}}' | grep -qx "$CONTAINER_NAME"; then
  if docker ps -a --format '{{.Names}}' | grep -qx "$CONTAINER_NAME"; then
    docker rm -f "$CONTAINER_NAME" >/dev/null
  fi
  step "Starting the air-gapped container (network enabled for the demo itself; see docs/demo/GOLDEN-PATH.md for the offline proof with --network none)"
  docker run -d --name "$CONTAINER_NAME" \
    -p "${PORT}:8080" \
    -v "$VOLUME_NAME:/app/data" \
    -w /app/data \
    -e KEYORIX_MASTER_PASSWORD="$MASTER_PASSWORD" \
    -e KEYORIX_BOOTSTRAP_TOKEN="$BOOTSTRAP_TOKEN" \
    -e KEYORIX_CONFIG_PATH=keyorix.yaml \
    --entrypoint /bin/sh \
    "$IMAGE_TAG" \
    -c '
      set -e
      if [ ! -f keyorix.yaml ]; then
        /app/keyorix-server admin init --config keyorix.yaml
        /app/keyorix-server admin encryption init --config keyorix.yaml
        /app/keyorix-server admin migrate --config keyorix.yaml
        # Break-glass is off by default (secure default); the demo turns it on
        # explicitly so `keyorix break-glass activate` works (#2943).
        printf "\nbreak_glass:\n  enabled: true\n  emergency_role: project_developer\n  default_ttl: 4h\n  max_ttl: 24h\n" >> keyorix.yaml
      fi
      exec /app/keyorix-server
    ' >/dev/null
  ok "Container started"
fi

step "Waiting for the server to be healthy"
for _ in $(seq 1 30); do
  if curl -s -o /dev/null "http://localhost:${PORT}/health"; then
    ok "Server is healthy"
    break
  fi
  sleep 1
done

if [ "$ALREADY_SEEDED" = true ]; then
  info "Data volume already seeded from a previous run — skipping seed, container just (re)started"
  if [ -f "$STATE_FILE" ]; then
    cat "$STATE_FILE"
  else
    warn "No local state file found (was it deleted?) — the demo data exists but its printed credentials are lost. Run scripts/demo/down.sh --wipe and up.sh again for a clean, fully-printed run."
  fi
  exit 0
fi

export HOME="$REPO_ROOT/.demo-2-cli-home"
mkdir -p "$HOME"
rm -f "$HOME/.keyorix/cli.yaml" 2>/dev/null || true

SERVER_URL="http://localhost:${PORT}"

step "Bootstrapping the admin account (public API, via 'keyorix system init')"
"$CLI_BIN" system init --server "$SERVER_URL" \
  --admin-username "$ADMIN_USER" --admin-email "$ADMIN_EMAIL" \
  --admin-password "$ADMIN_PASSWORD" --bootstrap-token "$BOOTSTRAP_TOKEN" >/dev/null
"$CLI_BIN" login --server "$SERVER_URL" --username "$ADMIN_USER" --password "$ADMIN_PASSWORD" >/dev/null
ok "Admin bootstrapped and logged in"

step "Seeding org structure: 2 projects, 2 groups"
"$CLI_BIN" project create --name backend-api --description "Backend API" >/dev/null
"$CLI_BIN" project create --name mobile-app --description "Mobile App" >/dev/null
"$CLI_BIN" group create --name platform-team --description "Platform team" >/dev/null
"$CLI_BIN" group create --name mobile-team --description "Mobile team" >/dev/null
ok "3 projects (default, backend-api, mobile-app), 2 groups"

step "Seeding a least-privilege user"
"$CLI_BIN" user create --username alice --email alice@keyorix.demo --password "$ALICE_PASSWORD" >/dev/null
"$CLI_BIN" rbac assign-role --user alice@keyorix.demo --role project_viewer --project backend-api >/dev/null
ok "alice: project_viewer on backend-api only"

step "Seeding secrets with versions"
"$CLI_BIN" secret create --name "stripe-api-key" --value "sk_test_demo_seed_v1" --project 1 --environment 1 >/dev/null
"$CLI_BIN" secret rotate --id 1 --value "sk_test_demo_seed_v2" >/dev/null
"$CLI_BIN" secret create --name "db-password" --value "demo-db-pass-v1" --project 2 --environment 4 >/dev/null
ok "2 secrets, one with 2 versions"

step "Seeding a machine identity"
"$CLI_BIN" machine create --name ci-app --project default --type ci >/dev/null
"$CLI_BIN" machine grant-role ci-app --project default --role project_viewer >/dev/null
MACHINE_TOKEN_OUTPUT="$("$CLI_BIN" machine token issue ci-app --name "ci-pipeline-token" --project default)"
MACHINE_TOKEN="$(echo "$MACHINE_TOKEN_OUTPUT" | grep -oE 'kx_machine_[A-Za-z0-9_-]+' | head -1)"
ok "ci-app machine identity, project_viewer on default"

step "Populating an audit trail (reveal + rotate + a machine read already happened above)"
"$CLI_BIN" secret get --id 1 --show-value >/dev/null
curl -s -H "Authorization: Bearer $MACHINE_TOKEN" "http://localhost:${PORT}/api/v1/secrets/1" >/dev/null
ok "Audit trail populated — 'keyorix audit logs' now has real events to show"

docker exec "$CONTAINER_NAME" touch /app/data/.demo-seeded

cat > "$STATE_FILE" <<EOF
======================================================================
  Keyorix air-gapped demo is up.

  URL:            $SERVER_URL
  Admin login:    $ADMIN_USER / $ADMIN_PASSWORD
  Alice login:    alice / $ALICE_PASSWORD   (least-privilege: backend-api only)
  Machine token:  $MACHINE_TOKEN
                  (ci-app, project_viewer on default — shown once, saved here)

  scripts/demo/down.sh to stop (keeps data); add --wipe to delete it.
======================================================================
EOF
cat "$STATE_FILE"
