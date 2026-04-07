#!/bin/bash

# Production Deployment Script
# Deploys the complete Keyorix system using Docker Compose

set -e

echo "🚀 Keyorix Production Deployment"
echo "=================================="

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

# Check prerequisites
log_info "Checking prerequisites..."

if ! command -v docker &> /dev/null; then
    log_error "Docker is not installed. Please install Docker first."
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
    log_error "Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi

log_success "Prerequisites check passed"

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    log_error "Docker is not running. Please start Docker first."
    exit 1
fi

log_success "Docker is running"

# Create production environment file
log_info "Creating production environment configuration..."

cat > .env.production << 'EOF'
# Keyorix Production Environment Configuration

# Application
KEYORIX_ENV=production
KEYORIX_DOMAIN=localhost
KEYORIX_PORT=8080

# Database
DB_HOST=postgres
DB_PORT=5432
DB_NAME=keyorix
DB_USER=keyorix
DB_PASSWORD=keyorix_prod_password_change_me

# Redis
REDIS_PASSWORD=redis_password_change_me

# Security
JWT_SECRET=jwt_secret_key_change_me_in_production
ENCRYPTION_KEY=encryption_key_change_me_in_production

# Monitoring
ENABLE_MONITORING=true
GRAFANA_ADMIN_PASSWORD=admin_password_change_me

# SSL/TLS (set to true for production)
ENABLE_SSL=false
SSL_CERT_PATH=/etc/ssl/certs/keyorix.crt
SSL_KEY_PATH=/etc/ssl/private/keyorix.key
EOF

log_success "Production environment file created: .env.production"
log_warning "⚠️  IMPORTANT: Change default passwords in .env.production before production use!"

# Create secrets directory for Docker secrets
log_info "Setting up Docker secrets..."
mkdir -p secrets

# Generate secure passwords for production
echo "keyorix_prod_$(openssl rand -hex 16)" > secrets/db_password.txt
echo "grafana_admin_$(openssl rand -hex 12)" > secrets/grafana_password.txt

log_success "Docker secrets created"

# Create production Docker Compose override
log_info "Creating production Docker Compose configuration..."

cat > docker-compose.prod.yml << 'EOF'
version: '3.8'

services:
  keyorix:
    build:
      context: .
      dockerfile: server/Dockerfile
      target: production
    environment:
      - KEYORIX_ENV=production
      - KEYORIX_CONFIG_PATH=/app/config/production.yaml
    volumes:
      - keyorix_data:/app/data
      - keyorix_logs:/app/logs
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s

  postgres:
    environment:
      - POSTGRES_PASSWORD_FILE=/run/secrets/db_password
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./backups:/backups
    restart: unless-stopped
    secrets:
      - db_password

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./nginx/ssl:/etc/nginx/ssl:ro
      - nginx_logs:/var/log/nginx
    depends_on:
      - keyorix
    restart: unless-stopped

volumes:
  keyorix_data:
    driver: local
  keyorix_logs:
    driver: local
  postgres_data:
    driver: local
  nginx_logs:
    driver: local

secrets:
  db_password:
    file: ./secrets/db_password.txt
EOF

log_success "Production Docker Compose configuration created"

# Create nginx configuration for production
log_info "Creating nginx configuration..."
mkdir -p nginx

cat > nginx/nginx.conf << 'EOF'
events {
    worker_connections 1024;
}

http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;

    # Logging
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';

    access_log /var/log/nginx/access.log main;
    error_log /var/log/nginx/error.log warn;

    # Performance
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;

    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript;

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    upstream keyorix_backend {
        server keyorix:8080;
    }

    server {
        listen 80;
        server_name _;

        # Redirect HTTP to HTTPS in production
        # return 301 https://$server_name$request_uri;

        # For development, serve directly
        location / {
            proxy_pass http://keyorix_backend;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        # Health check
        location /health {
            proxy_pass http://keyorix_backend/health;
            access_log off;
        }
    }

    # HTTPS server (uncomment for production with SSL)
    # server {
    #     listen 443 ssl http2;
    #     server_name your-domain.com;
    #
    #     ssl_certificate /etc/nginx/ssl/cert.pem;
    #     ssl_certificate_key /etc/nginx/ssl/key.pem;
    #
    #     location / {
    #         proxy_pass http://keyorix_backend;
    #         proxy_set_header Host $host;
    #         proxy_set_header X-Real-IP $remote_addr;
    #         proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    #         proxy_set_header X-Forwarded-Proto $scheme;
    #     }
    # }
}
EOF

log_success "Nginx configuration created"

# Build and deploy
log_info "Building and deploying production system..."

# Stop any existing containers
docker-compose -f docker-compose.full-stack.yml down 2>/dev/null || true

# Build and start production deployment
log_info "Starting production deployment..."
docker-compose -f docker-compose.full-stack.yml -f docker-compose.prod.yml up -d --build

# Wait for services to be ready
log_info "Waiting for services to start..."
sleep 10

# Check service health
log_info "Checking service health..."

# Check if services are running
if docker-compose -f docker-compose.full-stack.yml ps | grep -q "Up"; then
    log_success "Services are running"
else
    log_error "Some services failed to start"
    docker-compose -f docker-compose.full-stack.yml logs
    exit 1
fi

# Test health endpoint
for i in {1..30}; do
    if curl -s http://localhost:8080/health > /dev/null 2>&1; then
        log_success "Application is healthy"
        break
    fi
    if [ $i -eq 30 ]; then
        log_error "Application health check failed"
        exit 1
    fi
    sleep 2
done

# Test web dashboard
if curl -s http://localhost:8080/ | grep -q "Keyorix\|html"; then
    log_success "Web dashboard is accessible"
else
    log_warning "Web dashboard may need additional setup"
fi

echo ""
log_success "🎉 Production Deployment Complete!"
echo ""
echo "Your Keyorix system is now running in production mode:"
echo ""
echo "🌐 Access Points:"
echo "  - Web Dashboard: http://localhost:8080/"
echo "  - API Documentation: http://localhost:8080/swagger/"
echo "  - Health Check: http://localhost:8080/health"
echo ""
echo "🐳 Docker Services:"
echo "  - Keyorix App: Full-stack application"
echo "  - PostgreSQL: Production database"
echo "  - Nginx: Reverse proxy and load balancer"
echo "  - Redis: Caching and session storage"
echo ""
echo "📊 Management Commands:"
echo "  - View logs: docker-compose -f docker-compose.full-stack.yml logs -f"
echo "  - Stop services: docker-compose -f docker-compose.full-stack.yml down"
echo "  - Restart: docker-compose -f docker-compose.full-stack.yml restart"
echo ""
echo "🔒 Security Notes:"
echo "  - Change default passwords in .env.production"
echo "  - Set up SSL certificates for HTTPS"
echo "  - Configure firewall rules"
echo "  - Set up backup procedures"
echo ""
log_warning "⚠️  Remember to secure your production environment!"
echo ""
echo "Next: Task 5 - Set up monitoring and health checks"