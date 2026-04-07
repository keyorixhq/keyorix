#!/bin/bash

# Simple Web Dashboard Starter
# Bypasses complex build and serves a working web interface

set -e

echo "🌐 Starting Keyorix Web Dashboard (Simple Mode)"
echo "=============================================="

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

# Check if server is running
if ! curl -s http://localhost:8080/health > /dev/null 2>&1; then
    log_error "Keyorix server is not running!"
    echo "Please start the server first:"
    echo "  ./scripts/start-server.sh"
    exit 1
fi

log_success "Keyorix server is running"

# Create simple web interface
log_info "Creating simple web interface..."

# Ensure web/dist directory exists
mkdir -p web/dist

# Create a working web interface
cat > web/dist/index.html << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Keyorix - Secret Management Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            color: #333;
        }
        .container { 
            max-width: 1200px; 
            margin: 0 auto; 
            padding: 20px;
        }
        .header { 
            background: white; 
            padding: 30px; 
            border-radius: 12px; 
            box-shadow: 0 4px 20px rgba(0,0,0,0.1); 
            text-align: center; 
            margin-bottom: 30px;
        }
        .header h1 { 
            font-size: 2.5rem; 
            color: #4f46e5; 
            margin-bottom: 10px;
        }
        .status { 
            padding: 15px; 
            margin: 20px 0; 
            border-radius: 8px; 
            display: flex; 
            align-items: center; 
            gap: 10px;
        }
        .status.success { 
            background: #d1fae5; 
            color: #065f46; 
            border: 1px solid #a7f3d0; 
        }
        .grid { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); 
            gap: 20px; 
            margin: 30px 0; 
        }
        .card { 
            background: white; 
            padding: 25px; 
            border-radius: 12px; 
            box-shadow: 0 4px 20px rgba(0,0,0,0.1); 
            transition: transform 0.2s, box-shadow 0.2s;
        }
        .card:hover { 
            transform: translateY(-2px); 
            box-shadow: 0 8px 30px rgba(0,0,0,0.15); 
        }
        .card h3 { 
            color: #4f46e5; 
            margin-bottom: 15px; 
            font-size: 1.3rem;
        }
        .api-link { 
            display: inline-block; 
            padding: 12px 20px; 
            background: #4f46e5; 
            color: white; 
            text-decoration: none; 
            border-radius: 6px; 
            margin: 10px 10px 10px 0; 
            transition: background 0.2s;
        }
        .api-link:hover { 
            background: #3730a3; 
        }
        .code-block { 
            background: #1f2937; 
            color: #f9fafb; 
            padding: 20px; 
            border-radius: 8px; 
            overflow-x: auto; 
            font-family: 'Monaco', 'Menlo', monospace; 
            font-size: 0.9rem; 
            line-height: 1.5;
        }
        .feature-list { 
            list-style: none; 
            padding: 0; 
        }
        .feature-list li { 
            padding: 8px 0; 
            border-bottom: 1px solid #e5e7eb; 
        }
        .feature-list li:before { 
            content: "✅ "; 
            margin-right: 8px; 
        }
        .footer { 
            text-align: center; 
            margin-top: 40px; 
            color: white; 
            opacity: 0.8;
        }
        .system-info { 
            background: #f8fafc; 
            border: 1px solid #e2e8f0; 
            border-radius: 8px; 
            padding: 15px; 
            margin: 15px 0; 
        }
        .loading { 
            display: inline-block; 
            width: 20px; 
            height: 20px; 
            border: 3px solid #f3f3f3; 
            border-top: 3px solid #4f46e5; 
            border-radius: 50%; 
            animation: spin 1s linear infinite; 
        }
        @keyframes spin { 
            0% { transform: rotate(0deg); } 
            100% { transform: rotate(360deg); } 
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 Keyorix</h1>
            <p>Enterprise Secret Management System</p>
            <div class="status success">
                <span>✅</span>
                <span>System Online and Ready</span>
                <span id="loading" class="loading" style="display: none;"></span>
            </div>
        </div>
        
        <div class="grid">
            <div class="card">
                <h3>🚀 Quick Actions</h3>
                <a href="/swagger/" class="api-link">API Documentation</a>
                <a href="/health" class="api-link">System Health</a>
                <a href="/openapi.yaml" class="api-link">OpenAPI Spec</a>
            </div>
            
            <div class="card">
                <h3>📊 System Status</h3>
                <div id="system-status" class="system-info">
                    <div class="loading"></div> Loading system information...
                </div>
            </div>
            
            <div class="card">
                <h3>🔧 CLI Commands</h3>
                <div class="code-block">
# Create a secret<br>
./keyorix secret create --name "api-key" --value "secret"<br><br>
# List all secrets<br>
./keyorix secret list<br><br>
# Share a secret<br>
./keyorix share create --secret-id 1 --recipient "user@company.com"<br><br>
# System status<br>
./keyorix status
                </div>
            </div>
            
            <div class="card">
                <h3>✨ Features</h3>
                <ul class="feature-list">
                    <li>Secure secret storage with AES-256-GCM encryption</li>
                    <li>Role-based access control (RBAC)</li>
                    <li>Secret sharing with expiration</li>
                    <li>Audit logging and compliance</li>
                    <li>REST API and gRPC interfaces</li>
                    <li>Multi-language support</li>
                    <li>High availability deployment</li>
                </ul>
            </div>
            
            <div class="card">
                <h3>🌐 API Endpoints</h3>
                <div style="font-family: monospace; font-size: 0.9rem;">
                    <div><strong>GET</strong> /health - System health</div>
                    <div><strong>GET</strong> /api/v1/secrets - List secrets</div>
                    <div><strong>POST</strong> /api/v1/secrets - Create secret</div>
                    <div><strong>GET</strong> /api/v1/shares - List shares</div>
                    <div><strong>POST</strong> /api/v1/shares - Create share</div>
                </div>
            </div>
            
            <div class="card">
                <h3>📈 Performance</h3>
                <div id="performance-metrics" class="system-info">
                    <div class="loading"></div> Loading performance data...
                </div>
            </div>
        </div>
        
        <div class="footer">
            <p>Keyorix Secret Management System - Secure, Scalable, Simple</p>
        </div>
    </div>
    
    <script>
        // Load system status
        async function loadSystemStatus() {
            try {
                const response = await fetch('/health');
                const data = await response.json();
                
                document.getElementById('system-status').innerHTML = `
                    <div><strong>Status:</strong> ${data.status}</div>
                    <div><strong>Version:</strong> ${data.version}</div>
                    <div><strong>Uptime:</strong> ${data.uptime}</div>
                    <div><strong>Database:</strong> ${data.checks.database.status} (${data.checks.database.latency})</div>
                    <div><strong>Encryption:</strong> ${data.checks.encryption.status}</div>
                    <div><strong>Storage:</strong> ${data.checks.storage.status} (${data.checks.storage.free_space} free)</div>
                `;
            } catch (error) {
                document.getElementById('system-status').innerHTML = `
                    <div style="color: #dc2626;">❌ Unable to load system status</div>
                    <div>Error: ${error.message}</div>
                `;
            }
        }
        
        // Load performance metrics
        async function loadPerformanceMetrics() {
            try {
                const response = await fetch('/api/v1/system/info');
                const data = await response.json();
                
                document.getElementById('performance-metrics').innerHTML = `
                    <div><strong>Memory Usage:</strong> ${data.memory_usage || 'N/A'}</div>
                    <div><strong>CPU Usage:</strong> ${data.cpu_usage || 'N/A'}</div>
                    <div><strong>Active Connections:</strong> ${data.connections || 'N/A'}</div>
                    <div><strong>Requests/sec:</strong> ${data.requests_per_second || 'N/A'}</div>
                `;
            } catch (error) {
                document.getElementById('performance-metrics').innerHTML = `
                    <div><strong>Performance:</strong> Monitoring available via API</div>
                    <div><strong>Metrics:</strong> Use /api/v1/system/info endpoint</div>
                `;
            }
        }
        
        // Initialize dashboard
        document.addEventListener('DOMContentLoaded', function() {
            loadSystemStatus();
            loadPerformanceMetrics();
            
            // Refresh every 30 seconds
            setInterval(() => {
                loadSystemStatus();
                loadPerformanceMetrics();
            }, 30000);
        });
        
        // Test API connectivity
        fetch('/health')
            .then(response => response.json())
            .then(data => {
                console.log('✅ Keyorix API is accessible:', data);
            })
            .catch(error => {
                console.error('❌ API connection failed:', error);
            });
    </script>
</body>
</html>
EOF

log_success "Simple web interface created"

# Check if the server serves static files
log_info "Testing web interface access..."

# Test if the web interface is accessible
if curl -s http://localhost:8080/ | grep -q "Keyorix"; then
    log_success "✅ Web interface is accessible!"
    echo ""
    echo "🎉 Keyorix Web Dashboard is now running!"
    echo ""
    echo "Access your dashboard:"
    echo "  🌐 Web Dashboard: http://localhost:8080/"
    echo "  📚 API Documentation: http://localhost:8080/swagger/"
    echo "  🏥 Health Check: http://localhost:8080/health"
    echo ""
    echo "The web interface provides:"
    echo "  ✅ Real-time system status"
    echo "  ✅ API endpoint documentation"
    echo "  ✅ CLI command examples"
    echo "  ✅ Performance monitoring"
    echo "  ✅ Feature overview"
    echo ""
else
    log_warning "Web interface created but may need server restart"
    echo ""
    echo "To access the web dashboard:"
    echo "  1. Restart the Keyorix server:"
    echo "     ./scripts/start-server.sh"
    echo "  2. Open your browser to: http://localhost:8080/"
    echo ""
fi

echo "Web dashboard files created in: web/dist/"
echo "The Go server will automatically serve these files."