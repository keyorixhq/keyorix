#!/bin/bash

# Keyorix Demo Seed + Walkthrough
# Seeds the exact data the demo script (keyorix-gtm.md) expects, then shows the
# headline features. Run AFTER `keyorix system init --server ...` and after the
# CLI is pointed at the server.
#
# Server mode is required: export KEYORIX_SERVER + KEYORIX_TOKEN (or run
# `keyorix connect`) so `keyorix secret create` and the user-seed curl below hit
# the running server, not a local SQLite file.

set -e

echo "🚀 Keyorix Demo Seed + Walkthrough"
echo "=================================="

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

demo_step() { echo -e "${CYAN}➤${NC} $1"; }
demo_success() { echo -e "${GREEN}✅${NC} $1"; }
demo_info() { echo -e "${BLUE}ℹ️${NC}  $1"; }
demo_warn() { echo -e "${YELLOW}⚠️${NC}  $1"; }

SERVER="${KEYORIX_SERVER:-http://localhost:8080}"

if [ -z "$KEYORIX_TOKEN" ]; then
    demo_warn "KEYORIX_TOKEN is not set. Secrets are created via the CLI's own"
    demo_warn "remote config (cli.yaml from 'keyorix connect'); the demo-user step"
    demo_warn "below needs KEYORIX_TOKEN to call the API. Run 'keyorix connect' and"
    demo_warn "export KEYORIX_TOKEN to seed the demo user automatically."
fi

echo ""
demo_step "1. Creating the three demo secrets (names match the demo script)"
./keyorix secret create --name "prod-db-password" --value "super_secure_db_pass_2024" --type "password"
./keyorix secret create --name "stripe-api-key" --value "sk_live_demo_51abc123def456" --type "api_key"
./keyorix secret create --name "jwt-signing-key" --value "$(head -c 32 /dev/urandom | base64)" --type "password"

echo ""
demo_step "2. Creating a limited-permission demo user (for the RBAC chapter)"
# New users are auto-assigned the read-only 'viewer' role, so
# 'keyorix rbac check-permission --user demo@keyorix.com --permission secrets.write'
# returns ❌ — the contrast that makes the RBAC chapter land.
if [ -n "$KEYORIX_TOKEN" ]; then
    HTTP_CODE=$(curl -s -o /tmp/keyorix-demo-user.json -w "%{http_code}" \
        -X POST "$SERVER/api/v1/users" \
        -H "Authorization: Bearer $KEYORIX_TOKEN" \
        -H "Content-Type: application/json" \
        -d '{"username":"demo","email":"demo@keyorix.com","password":"Demo#Pass!2026","display_name":"Demo User"}')
    if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "201" ]; then
        demo_success "Created demo user demo@keyorix.com (viewer role)"
    elif [ "$HTTP_CODE" = "409" ]; then
        demo_info "Demo user demo@keyorix.com already exists — skipping"
    else
        demo_warn "Demo user creation returned HTTP $HTTP_CODE (see /tmp/keyorix-demo-user.json)"
    fi
else
    demo_warn "Skipped demo-user creation (no KEYORIX_TOKEN). Create it in the web"
    demo_warn "Admin UI instead — new users get the viewer role automatically."
fi

echo ""
demo_step "3. Listing all secrets"
./keyorix secret list

echo ""
demo_step "4. RBAC: roles and a permission check"
./keyorix rbac list-roles
if [ -n "$KEYORIX_TOKEN" ]; then
    echo ""
    demo_info "Limited user does NOT have secrets.write:"
    ./keyorix rbac check-permission --user "demo@keyorix.com" --permission "secrets.write" || true
fi

echo ""
demo_step "5. System health"
./keyorix status || true
echo "API health:"
curl -s "$SERVER/health" | jq '.' 2>/dev/null || curl -s "$SERVER/health"

echo ""
echo ""
demo_success "Demo seed complete. Walkthrough script: keyorix-gtm.md → 'Demo Script'."
echo ""
echo "🔐 Highlights to show:"
echo "  • Secrets list + reveal a value + version history (web UI)"
echo "  • RBAC enforced at the API: keyorix rbac check-permission"
echo "  • Audit trail: GET /api/v1/audit/logs (or the Audit Log UI page)"
echo "  • Single binary deploy: keyorix-server + PostgreSQL"
