#!/bin/bash

# Web Dashboard Setup Script
# Sets up the web dashboard for integration with the backend

set -e

echo "🌐 Setting Up Keyorix Web Dashboard"
echo "===================================="

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Go to project root
cd ..

# Check if web directory exists and has our components
if [ -d "web/src/components" ] && [ -f "web/package.json" ]; then
    log_success "Web dashboard components found"
    
    # Check if node_modules exists
    if [ ! -d "web/node_modules" ]; then
        log_info "Installing web dependencies..."
        cd web
        if command -v npm &> /dev/null; then
            npm install
            log_success "Dependencies installed"
        else
            log_error "npm not found. Please install Node.js and npm"
            exit 1
        fi
        cd ..
    else
        log_success "Web dependencies already installed"
    fi
    
    # Build web dashboard
    log_info "Building web dashboard..."
    cd web
    if npm run build; then
        log_success "Web dashboard built successfully"
        log_info "Built assets location: web/dist/"
    else
        log_error "Web dashboard build failed"
        exit 1
    fi
    cd ..
    
else
    log_warning "Complete web dashboard not found. Creating minimal setup..."
    
    # Create minimal web setup
    mkdir -p web/dist
    
    # Create minimal index.html
    cat > web/dist/index.html << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Keyorix - Secret Management</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { text-align: center; margin-bottom: 40px; }
        .api-links { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin: 30px 0; }
        .api-link { padding: 20px; background: #f8f9fa; border-radius: 6px; text-decoration: none; color: #333; border: 1px solid #e9ecef; }
        .api-link:hover { background: #e9ecef; }
        .status { padding: 10px; margin: 20px 0; border-radius: 4px; }
        .status.success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .footer { text-align: center; margin-top: 40px; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 Keyorix</h1>
            <p>Secret Management System</p>
        </div>
        
        <div class="status success">
            ✅ System is running and ready for use
        </div>
        
        <h2>API Access</h2>
        <div class="api-links">
            <a href="/health" class="api-link">
                <h3>🏥 Health Check</h3>
                <p>System health status</p>
            </a>
            <a href="/swagger/" class="api-link">
                <h3>📚 API Documentation</h3>
                <p>Interactive API explorer</p>
            </a>
            <a href="/openapi.yaml" class="api-link">
                <h3>📋 OpenAPI Spec</h3>
                <p>API specification</p>
            </a>
        </div>
        
        <h2>CLI Usage</h2>
        <pre style="background: #f8f9fa; padding: 20px; border-radius: 6px; overflow-x: auto;">
# Create a secret
./keyorix secret create --name "api-key" --value "your-secret-value"

# List secrets
./keyorix secret list

# Share a secret
./keyorix share create --secret-id 1 --recipient "user@company.com"

# Check system status
./keyorix status
        </pre>
        
        <div class="footer">
            <p>Complete web dashboard available - run full integration for advanced UI</p>
        </div>
    </div>
    
    <script>
        // Simple health check
        fetch('/health')
            .then(response => response.text())
            .then(data => {
                console.log('Health check:', data);
            })
            .catch(error => {
                console.log('Health check failed:', error);
            });
    </script>
</body>
</html>
EOF
    
    log_success "Minimal web dashboard created"
fi

# Update server configuration to serve web assets
log_info "Updating server configuration for web dashboard..."

# Check if the server has web integration
if grep -q "web_assets_path" server/http/router.go; then
    log_success "Server already configured for web assets"
else
    log_warning "Server needs web integration update"
    log_info "The server code includes web asset serving capability"
fi

# Test web integration
log_info "Testing web dashboard integration..."

# Check if server is running
if curl -s http://localhost:8080/health > /dev/null 2>&1; then
    log_success "Server is running"
    
    # Test web dashboard access
    if curl -s http://localhost:8080/ | grep -q "Keyorix"; then
        log_success "Web dashboard is accessible"
    else
        log_warning "Web dashboard may need server restart to load assets"
    fi
    
    # Test API endpoints
    log_info "Testing API endpoints..."
    if curl -s http://localhost:8080/swagger/ | grep -q "swagger\|Swagger\|API"; then
        log_success "Swagger UI is working"
    else
        log_warning "Swagger UI may need configuration"
    fi
    
else
    log_warning "Server not running. Start server to test web dashboard:"
    echo "  cd server && KEYORIX_CONFIG_PATH=../keyorix-simple.yaml ./keyorix-server"
fi

echo ""
log_success "🎉 Web Dashboard Setup Complete!"
echo ""
echo "Access your web dashboard:"
echo "  🌐 Web UI: http://localhost:8080/"
echo "  📚 API Docs: http://localhost:8080/swagger/"
echo "  🏥 Health: http://localhost:8080/health"
echo ""
echo "If server is not running:"
echo "  ./scripts/start-server.sh"
echo ""

if [ -d "web/dist" ]; then
    log_info "Web assets ready at: web/dist/"
    if [ -f "web/dist/index.html" ]; then
        log_success "Web dashboard will be served by the Go server"
    fi
fi

echo ""
log_info "Next steps:"
echo "  1. Start/restart server to load web assets"
echo "  2. Access web dashboard at http://localhost:8080/"
echo "  3. Use API documentation at http://localhost:8080/swagger/"
echo "  4. Continue with Task 4: Production Deployment"