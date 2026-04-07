#!/bin/bash

# Keyorix Demo Script
# Shows off the key features of your secret management system

set -e

echo "🚀 Keyorix Secret Management Demo"
echo "================================="

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

demo_step() { echo -e "${CYAN}➤${NC} $1"; }
demo_success() { echo -e "${GREEN}✅${NC} $1"; }
demo_info() { echo -e "${BLUE}ℹ️${NC}  $1"; }

echo ""
demo_step "1. Creating API Keys for Different Services"
./keyorix secret create --name "github-api-token" --value "ghp_demo_token_123456" --type "token"
./keyorix secret create --name "aws-access-key" --value "AKIA_DEMO_KEY_789" --type "api_key"
./keyorix secret create --name "database-password" --value "super_secure_db_pass_2024" --type "password"

echo ""
demo_step "2. Listing All Your Secrets"
./keyorix secret list

echo ""
demo_step "3. Getting Specific Secret Details"
SECRET_ID=$(./keyorix secret list | grep "github-api-token" | awk '{print $1}' | head -1)
if [ ! -z "$SECRET_ID" ]; then
    ./keyorix secret get --id "$SECRET_ID"
    echo ""
    demo_info "To see the actual secret value, use: ./keyorix secret get --id $SECRET_ID --show-value"
fi

echo ""
demo_step "4. System Health Check"
./keyorix status

echo ""
demo_step "5. Testing API Endpoints"
echo "Health Check:"
curl -s http://localhost:8080/health | jq '.' 2>/dev/null || curl -s http://localhost:8080/health

echo ""
echo ""
demo_step "6. Available Commands"
echo "Try these commands:"
echo "  • ./keyorix secret create --name 'my-secret' --value 'my-value' --type 'password'"
echo "  • ./keyorix secret list"
echo "  • ./keyorix secret get --id <ID> --show-value"
echo "  • ./keyorix share list"
echo "  • ./keyorix status"

echo ""
demo_success "Demo Complete! Your Keyorix system is fully operational."
echo ""
echo "🌐 Web Access:"
echo "  • API Health: http://localhost:8080/health"
echo "  • API Docs: http://localhost:8080/openapi.yaml"
echo ""
echo "🔐 Security Features:"
echo "  • AES-256-GCM encryption"
echo "  • Role-based access control"
echo "  • Audit logging"
echo "  • Secret sharing with permissions"
echo ""
echo "🌍 Multi-language Support:"
echo "  • English (default)"
echo "  • Russian: KEYORIX_LANGUAGE=ru ./keyorix secret list"
echo "  • Spanish: KEYORIX_LANGUAGE=es ./keyorix secret list"
echo "  • French: KEYORIX_LANGUAGE=fr ./keyorix secret list"
echo "  • German: KEYORIX_LANGUAGE=de ./keyorix secret list"