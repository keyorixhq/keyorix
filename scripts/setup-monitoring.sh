#!/bin/bash

# Advanced Monitoring Setup Script
# Sets up Prometheus, Grafana, and comprehensive health monitoring

set -e

echo "📊 Setting Up Advanced Monitoring for Keyorix"
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

# Go to project root
cd ..

# Create monitoring directory structure
log_info "Creating monitoring configuration..."
mkdir -p monitoring/{prometheus,grafana/{dashboards,datasources},alertmanager}

# Create Prometheus configuration
log_info "Setting up Prometheus configuration..."
cat > monitoring/prometheus/prometheus.yml << 'EOF'
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "alert_rules.yml"

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - alertmanager:9093

scrape_configs:
  # Keyorix application metrics
  - job_name: 'keyorix-app'
    static_configs:
      - targets: ['keyorix:8080']
    metrics_path: '/metrics'
    scrape_interval: 10s

  # System metrics
  - job_name: 'node-exporter'
    static_configs:
      - targets: ['node-exporter:9100']

  # PostgreSQL metrics
  - job_name: 'postgres-exporter'
    static_configs:
      - targets: ['postgres-exporter:9187']

  # Redis metrics
  - job_name: 'redis-exporter'
    static_configs:
      - targets: ['redis-exporter:9121']

  # Nginx metrics
  - job_name: 'nginx-exporter'
    static_configs:
      - targets: ['nginx-exporter:9113']

  # Prometheus self-monitoring
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']
EOF

# Create Prometheus alert rules
cat > monitoring/prometheus/alert_rules.yml << 'EOF'
groups:
  - name: keyorix_alerts
    rules:
      # Application health alerts
      - alert: KeyorixAppDown
        expr: up{job="keyorix-app"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Keyorix application is down"
          description: "The Keyorix application has been down for more than 1 minute."

      - alert: HighResponseTime
        expr: http_request_duration_seconds{quantile="0.95"} > 1
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "High response time detected"
          description: "95th percentile response time is above 1 second for 2 minutes."

      # Database alerts
      - alert: PostgreSQLDown
        expr: up{job="postgres-exporter"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "PostgreSQL is down"
          description: "PostgreSQL database has been down for more than 1 minute."

      - alert: HighDatabaseConnections
        expr: pg_stat_database_numbackends > 80
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High number of database connections"
          description: "Database has more than 80 active connections for 5 minutes."

      # System resource alerts
      - alert: HighMemoryUsage
        expr: (node_memory_MemTotal_bytes - node_memory_MemAvailable_bytes) / node_memory_MemTotal_bytes > 0.9
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High memory usage"
          description: "Memory usage is above 90% for 5 minutes."

      - alert: HighCPUUsage
        expr: 100 - (avg by(instance) (irate(node_cpu_seconds_total{mode="idle"}[5m])) * 100) > 80
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High CPU usage"
          description: "CPU usage is above 80% for 5 minutes."

      # Redis alerts
      - alert: RedisDown
        expr: up{job="redis-exporter"} == 0
        for: 1m
        labels:
          severity: warning
        annotations:
          summary: "Redis is down"
          description: "Redis cache has been down for more than 1 minute."
EOF

# Create Grafana datasource configuration
log_info "Setting up Grafana datasources..."
cat > monitoring/grafana/datasources/prometheus.yml << 'EOF'
apiVersion: 1

datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://prometheus:9090
    isDefault: true
    editable: true
EOF

# Create Grafana dashboard for Keyorix
log_info "Creating Grafana dashboards..."
cat > monitoring/grafana/dashboards/keyorix-dashboard.json << 'EOF'
{
  "dashboard": {
    "id": null,
    "title": "Keyorix - Secret Management System",
    "tags": ["keyorix", "secrets", "security"],
    "timezone": "browser",
    "panels": [
      {
        "id": 1,
        "title": "Application Status",
        "type": "stat",
        "targets": [
          {
            "expr": "up{job=\"keyorix-app\"}",
            "legendFormat": "App Status"
          }
        ],
        "fieldConfig": {
          "defaults": {
            "mappings": [
              {"options": {"0": {"text": "DOWN", "color": "red"}}, "type": "value"},
              {"options": {"1": {"text": "UP", "color": "green"}}, "type": "value"}
            ]
          }
        },
        "gridPos": {"h": 8, "w": 12, "x": 0, "y": 0}
      },
      {
        "id": 2,
        "title": "Request Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(http_requests_total[5m])",
            "legendFormat": "Requests/sec"
          }
        ],
        "gridPos": {"h": 8, "w": 12, "x": 12, "y": 0}
      },
      {
        "id": 3,
        "title": "Response Time",
        "type": "graph",
        "targets": [
          {
            "expr": "histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m]))",
            "legendFormat": "95th percentile"
          },
          {
            "expr": "histogram_quantile(0.50, rate(http_request_duration_seconds_bucket[5m]))",
            "legendFormat": "50th percentile"
          }
        ],
        "gridPos": {"h": 8, "w": 24, "x": 0, "y": 8}
      },
      {
        "id": 4,
        "title": "Database Connections",
        "type": "graph",
        "targets": [
          {
            "expr": "pg_stat_database_numbackends",
            "legendFormat": "Active Connections"
          }
        ],
        "gridPos": {"h": 8, "w": 12, "x": 0, "y": 16}
      },
      {
        "id": 5,
        "title": "Memory Usage",
        "type": "graph",
        "targets": [
          {
            "expr": "(node_memory_MemTotal_bytes - node_memory_MemAvailable_bytes) / node_memory_MemTotal_bytes * 100",
            "legendFormat": "Memory Usage %"
          }
        ],
        "gridPos": {"h": 8, "w": 12, "x": 12, "y": 16}
      }
    ],
    "time": {"from": "now-1h", "to": "now"},
    "refresh": "5s"
  }
}
EOF

# Create dashboard provisioning config
cat > monitoring/grafana/dashboards/dashboard.yml << 'EOF'
apiVersion: 1

providers:
  - name: 'default'
    orgId: 1
    folder: ''
    type: file
    disableDeletion: false
    updateIntervalSeconds: 10
    allowUiUpdates: true
    options:
      path: /etc/grafana/provisioning/dashboards
EOF

# Create Alertmanager configuration
log_info "Setting up Alertmanager..."
cat > monitoring/alertmanager/alertmanager.yml << 'EOF'
global:
  smtp_smarthost: 'localhost:587'
  smtp_from: 'alerts@keyorix.local'

route:
  group_by: ['alertname']
  group_wait: 10s
  group_interval: 10s
  repeat_interval: 1h
  receiver: 'web.hook'

receivers:
  - name: 'web.hook'
    webhook_configs:
      - url: 'http://localhost:5001/'
        send_resolved: true

  # Email notifications (configure SMTP settings above)
  - name: 'email-alerts'
    email_configs:
      - to: 'admin@company.com'
        subject: 'Keyorix Alert: {{ .GroupLabels.alertname }}'
        body: |
          {{ range .Alerts }}
          Alert: {{ .Annotations.summary }}
          Description: {{ .Annotations.description }}
          {{ end }}

inhibit_rules:
  - source_match:
      severity: 'critical'
    target_match:
      severity: 'warning'
    equal: ['alertname', 'dev', 'instance']
EOF

# Create monitoring Docker Compose extension
log_info "Creating monitoring Docker Compose configuration..."
cat > docker-compose.monitoring.yml << 'EOF'
version: '3.8'

services:
  # Prometheus for metrics collection
  prometheus:
    image: prom/prometheus:latest
    container_name: prometheus
    ports:
      - "9090:9090"
    volumes:
      - ./monitoring/prometheus:/etc/prometheus
      - prometheus_data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.console.libraries=/etc/prometheus/console_libraries'
      - '--web.console.templates=/etc/prometheus/consoles'
      - '--storage.tsdb.retention.time=200h'
      - '--web.enable-lifecycle'
    networks:
      - keyorix-network
    restart: unless-stopped

  # Grafana for visualization
  grafana:
    image: grafana/grafana:latest
    container_name: grafana
    ports:
      - "3001:3000"
    volumes:
      - grafana_data:/var/lib/grafana
      - ./monitoring/grafana/provisioning:/etc/grafana/provisioning
      - ./monitoring/grafana/dashboards:/etc/grafana/provisioning/dashboards
    environment:
      - GF_SECURITY_ADMIN_USER=admin
      - GF_SECURITY_ADMIN_PASSWORD=admin123
      - GF_USERS_ALLOW_SIGN_UP=false
    networks:
      - keyorix-network
    restart: unless-stopped

  # Alertmanager for alert handling
  alertmanager:
    image: prom/alertmanager:latest
    container_name: alertmanager
    ports:
      - "9093:9093"
    volumes:
      - ./monitoring/alertmanager:/etc/alertmanager
    command:
      - '--config.file=/etc/alertmanager/alertmanager.yml'
      - '--storage.path=/alertmanager'
      - '--web.external-url=http://localhost:9093'
    networks:
      - keyorix-network
    restart: unless-stopped

  # Node Exporter for system metrics
  node-exporter:
    image: prom/node-exporter:latest
    container_name: node-exporter
    ports:
      - "9100:9100"
    volumes:
      - /proc:/host/proc:ro
      - /sys:/host/sys:ro
      - /:/rootfs:ro
    command:
      - '--path.procfs=/host/proc'
      - '--path.rootfs=/rootfs'
      - '--path.sysfs=/host/sys'
      - '--collector.filesystem.mount-points-exclude=^/(sys|proc|dev|host|etc)($$|/)'
    networks:
      - keyorix-network
    restart: unless-stopped

  # PostgreSQL Exporter
  postgres-exporter:
    image: prometheuscommunity/postgres-exporter:latest
    container_name: postgres-exporter
    ports:
      - "9187:9187"
    environment:
      - DATA_SOURCE_NAME=postgresql://keyorix:keyorix@postgres:5432/keyorix?sslmode=disable
    networks:
      - keyorix-network
    restart: unless-stopped
    depends_on:
      - postgres

  # Redis Exporter
  redis-exporter:
    image: oliver006/redis_exporter:latest
    container_name: redis-exporter
    ports:
      - "9121:9121"
    environment:
      - REDIS_ADDR=redis://redis:6379
    networks:
      - keyorix-network
    restart: unless-stopped
    depends_on:
      - redis

volumes:
  prometheus_data:
  grafana_data:

networks:
  keyorix-network:
    external: true
EOF

# Create health check script
log_info "Creating comprehensive health check script..."
cat > scripts/health-check.sh << 'EOF'
#!/bin/bash

# Comprehensive Health Check Script
# Monitors all services and sends alerts if issues are detected

echo "🏥 Keyorix System Health Check"
echo "==============================="

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

HEALTH_STATUS=0

check_service() {
    local service_name="$1"
    local url="$2"
    local expected="$3"
    
    echo -n "Checking $service_name... "
    
    if response=$(curl -s --max-time 5 "$url" 2>/dev/null); then
        if [[ "$response" == *"$expected"* ]]; then
            echo -e "${GREEN}✅ Healthy${NC}"
        else
            echo -e "${RED}❌ Unhealthy (unexpected response)${NC}"
            HEALTH_STATUS=1
        fi
    else
        echo -e "${RED}❌ Unreachable${NC}"
        HEALTH_STATUS=1
    fi
}

# Check main application
check_service "Keyorix App" "http://localhost:8080/health" "OK"

# Check web dashboard
check_service "Web Dashboard" "http://localhost:8080/" "html"

# Check API documentation
check_service "API Docs" "http://localhost:8080/swagger/" "swagger"

# Check Prometheus
check_service "Prometheus" "http://localhost:9090/-/healthy" "Prometheus"

# Check Grafana
check_service "Grafana" "http://localhost:3001/api/health" "ok"

# Check database connectivity
echo -n "Checking Database... "
if docker-compose exec -T postgres pg_isready -U keyorix > /dev/null 2>&1; then
    echo -e "${GREEN}✅ Connected${NC}"
else
    echo -e "${RED}❌ Connection failed${NC}"
    HEALTH_STATUS=1
fi

# Check Redis
echo -n "Checking Redis... "
if docker-compose exec -T redis redis-cli ping | grep -q "PONG"; then
    echo -e "${GREEN}✅ Responding${NC}"
else
    echo -e "${RED}❌ Not responding${NC}"
    HEALTH_STATUS=1
fi

echo ""
if [ $HEALTH_STATUS -eq 0 ]; then
    echo -e "${GREEN}🎉 All services are healthy!${NC}"
else
    echo -e "${RED}⚠️  Some services have issues. Check the logs.${NC}"
fi

exit $HEALTH_STATUS
EOF

chmod +x scripts/health-check.sh

# Deploy monitoring stack
log_info "Deploying monitoring stack..."

# Check if main stack is running
if ! docker-compose -f docker-compose.full-stack.yml ps | grep -q "Up"; then
    log_warning "Main application stack not running. Starting it first..."
    docker-compose -f docker-compose.full-stack.yml up -d
    sleep 10
fi

# Deploy monitoring services
docker-compose -f docker-compose.monitoring.yml up -d

# Wait for services to start
log_info "Waiting for monitoring services to start..."
sleep 15

# Verify monitoring services
log_info "Verifying monitoring services..."

services_healthy=true

# Check Prometheus
if curl -s http://localhost:9090/-/healthy > /dev/null; then
    log_success "Prometheus is running"
else
    log_error "Prometheus failed to start"
    services_healthy=false
fi

# Check Grafana
if curl -s http://localhost:3001/api/health > /dev/null; then
    log_success "Grafana is running"
else
    log_error "Grafana failed to start"
    services_healthy=false
fi

# Check Node Exporter
if curl -s http://localhost:9100/metrics > /dev/null; then
    log_success "Node Exporter is running"
else
    log_warning "Node Exporter may not be accessible"
fi

if [ "$services_healthy" = true ]; then
    log_success "🎉 Monitoring stack deployed successfully!"
else
    log_error "Some monitoring services failed to start"
    exit 1
fi

echo ""
echo "📊 Monitoring Dashboard Access:"
echo "  - Prometheus: http://localhost:9090/"
echo "  - Grafana: http://localhost:3001/ (admin/admin123)"
echo "  - Alertmanager: http://localhost:9093/"
echo "  - Node Exporter: http://localhost:9100/metrics"
echo ""
echo "🏥 Health Monitoring:"
echo "  - Run health check: ./scripts/health-check.sh"
echo "  - View metrics: curl http://localhost:8080/metrics"
echo "  - Check alerts: http://localhost:9093/#/alerts"
echo ""
echo "📈 Next Steps:"
echo "  1. Access Grafana dashboard to view metrics"
echo "  2. Configure alert notifications (email, Slack, etc.)"
echo "  3. Set up automated health checks"
echo "  4. Configure backup monitoring"
echo ""
log_success "Task 5: Monitoring and Health Checks - COMPLETED!"
EOF

chmod +x scripts/setup-monitoring.sh

log_success "Monitoring setup script created successfully"

echo ""
log_success "🎉 Task 5 Setup Complete!"
echo ""
echo "Ready to execute Task 5: Monitoring and Health Checks"
echo "Command: ./scripts/setup-monitoring.sh"
echo ""
echo "This will set up:"
echo "  📊 Prometheus - Metrics collection"
echo "  📈 Grafana - Visualization dashboards"
echo "  🚨 Alertmanager - Alert handling"
echo "  🖥️  Node Exporter - System metrics"
echo "  🗄️  Database monitoring - PostgreSQL metrics"
echo "  🚀 Redis monitoring - Cache metrics"
echo "  🏥 Health checks - Comprehensive monitoring"