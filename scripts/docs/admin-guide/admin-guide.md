# Administrator Guide

## Table of Contents
1. [System Administration](#system-administration)
2. [User Management](#user-management)
3. [Security Configuration](#security-configuration)
4. [Monitoring and Maintenance](#monitoring-and-maintenance)
5. [Backup and Recovery](#backup-and-recovery)
6. [Troubleshooting](#troubleshooting)

## System Administration

### Initial Setup
1. **System Configuration**
   ```bash
   # Configure production settings
   cp server/config/production.yaml.example server/config/production.yaml
   
   # Set environment variables
   export SECRETLY_ENV=production
   export SECRETLY_DB_URL="postgresql://user:pass@localhost/keyorix"
   ```

2. **SSL Certificate Installation**
   ```bash
   # Install SSL certificates
   sudo cp ssl/cert.pem /etc/ssl/certs/keyorix.crt
   sudo cp ssl/key.pem /etc/ssl/private/keyorix.key
   
   # Update nginx configuration
   sudo systemctl reload nginx
   ```

3. **Database Setup**
   ```bash
   # Run database migrations
   ./scripts/run_migrations.sh
   
   # Verify database connection
   keyorix system health
   ```

### System Configuration

#### Environment Variables
```bash
# Core Configuration
SECRETLY_ENV=production
SECRETLY_PORT=8080
SECRETLY_HOST=0.0.0.0

# Database Configuration
SECRETLY_DB_URL=postgresql://user:pass@localhost/keyorix
SECRETLY_DB_MAX_CONNECTIONS=100
SECRETLY_DB_TIMEOUT=30s

# Security Configuration
SECRETLY_JWT_SECRET=your-jwt-secret-here
SECRETLY_ENCRYPTION_KEY=your-encryption-key-here
SECRETLY_SESSION_TIMEOUT=24h

# Monitoring Configuration
SECRETLY_METRICS_ENABLED=true
SECRETLY_METRICS_PORT=9090
SECRETLY_LOG_LEVEL=info
```

#### Production Configuration File
```yaml
# server/config/production.yaml
server:
  host: "0.0.0.0"
  port: 8080
  tls:
    enabled: true
    cert_file: "/etc/ssl/certs/keyorix.crt"
    key_file: "/etc/ssl/private/keyorix.key"

database:
  url: "${SECRETLY_DB_URL}"
  max_connections: 100
  connection_timeout: "30s"
  ssl_mode: "require"

security:
  jwt_secret: "${SECRETLY_JWT_SECRET}"
  encryption_key: "${SECRETLY_ENCRYPTION_KEY}"
  session_timeout: "24h"
  password_policy:
    min_length: 12
    require_uppercase: true
    require_lowercase: true
    require_numbers: true
    require_symbols: true

monitoring:
  enabled: true
  metrics_port: 9090
  health_check_interval: "30s"
  log_level: "info"
```

## User Management

### Creating Users
1. **Web Interface**
   - Navigate to Admin → User Management
   - Click "Add New User"
   - Fill in user details
   - Set initial permissions
   - Send invitation email

2. **CLI Method**
   ```bash
   # Create new user
   keyorix admin user create \
     --email "user@company.com" \
     --name "John Doe" \
     --role "user"
   
   # Set user permissions
   keyorix admin user permissions \
     --email "user@company.com" \
     --permissions "read,write"
   ```

### User Roles and Permissions
- **Super Admin**: Full system access
- **Admin**: User and system management
- **Manager**: Team and group management
- **User**: Standard secret management
- **Viewer**: Read-only access

### Bulk User Operations
```bash
# Import users from CSV
keyorix admin user import --file users.csv

# Export user list
keyorix admin user export --format csv

# Bulk permission updates
keyorix admin user bulk-update --file permissions.csv
```

## Security Configuration

### Authentication Settings
1. **Password Policies**
   ```yaml
   password_policy:
     min_length: 12
     max_age_days: 90
     history_count: 12
     complexity_requirements:
       uppercase: true
       lowercase: true
       numbers: true
       symbols: true
   ```

2. **Multi-Factor Authentication**
   ```yaml
   mfa:
     required: true
     methods:
       - totp
       - sms
       - hardware_key
     backup_codes: 10
   ```

### Access Control
1. **IP Restrictions**
   ```yaml
   access_control:
     ip_whitelist:
       - "192.168.1.0/24"
       - "10.0.0.0/8"
     geo_restrictions:
       allowed_countries: ["US", "CA", "GB"]
   ```

2. **Session Management**
   ```yaml
   session:
     timeout: "24h"
     max_concurrent: 5
     secure_cookies: true
     same_site: "strict"
   ```

### Audit Configuration
```yaml
audit:
  enabled: true
  log_level: "info"
  retention_days: 365
  events:
    - login
    - logout
    - secret_access
    - secret_create
    - secret_update
    - secret_delete
    - share_create
    - share_update
    - permission_change
```

## Monitoring and Maintenance

### Health Monitoring
1. **System Health Checks**
   ```bash
   # Check overall system health
   curl https://localhost/health
   
   # Detailed health information
   curl https://localhost/health/detailed
   
   # Component-specific checks
   curl https://localhost/health/database
   curl https://localhost/health/redis
   ```

2. **Monitoring Dashboards**
   - **Grafana**: http://localhost:3001/
   - **Prometheus**: http://localhost:9090/
   - **Alertmanager**: http://localhost:9093/

### Performance Monitoring
1. **Key Metrics**
   - Response time (target: <100ms)
   - Throughput (requests/second)
   - Error rate (target: <0.1%)
   - Database performance
   - Memory usage
   - CPU utilization

2. **Alert Thresholds**
   ```yaml
   alerts:
     response_time:
       warning: 200ms
       critical: 500ms
     error_rate:
       warning: 1%
       critical: 5%
     disk_usage:
       warning: 80%
       critical: 90%
   ```

### Log Management
1. **Log Locations**
   - Application logs: `/var/log/keyorix/app.log`
   - Access logs: `/var/log/keyorix/access.log`
   - Error logs: `/var/log/keyorix/error.log`
   - Audit logs: `/var/log/keyorix/audit.log`

2. **Log Rotation**
   ```bash
   # Configure logrotate
   sudo cp config/logrotate.conf /etc/logrotate.d/keyorix
   
   # Test log rotation
   sudo logrotate -d /etc/logrotate.d/keyorix
   ```

## Backup and Recovery

### Database Backup
1. **Automated Backups**
   ```bash
   # Daily backup script
   #!/bin/bash
   DATE=$(date +%Y%m%d_%H%M%S)
   pg_dump keyorix > /backups/keyorix_$DATE.sql
   
   # Compress and encrypt
   gzip /backups/keyorix_$DATE.sql
   gpg --encrypt /backups/keyorix_$DATE.sql.gz
   ```

2. **Backup Verification**
   ```bash
   # Test backup restoration
   ./scripts/test-backup-restore.sh
   
   # Verify backup integrity
   ./scripts/verify-backup.sh
   ```

### Disaster Recovery
1. **Recovery Procedures**
   ```bash
   # Stop services
   sudo systemctl stop keyorix
   
   # Restore database
   gunzip -c backup.sql.gz | psql keyorix
   
   # Restore configuration
   sudo cp backup/config/* /etc/keyorix/
   
   # Start services
   sudo systemctl start keyorix
   ```

2. **Recovery Testing**
   - Monthly recovery drills
   - Documentation updates
   - Staff training
   - Recovery time objectives (RTO: 4 hours)
   - Recovery point objectives (RPO: 1 hour)

## Troubleshooting

### Common Issues

1. **Database Connection Issues**
   ```bash
   # Check database connectivity
   pg_isready -h localhost -p 5432
   
   # Verify credentials
   psql -h localhost -U keyorix_user -d keyorix
   
   # Check connection pool
   keyorix admin db status
   ```

2. **Authentication Problems**
   ```bash
   # Reset user password
   keyorix admin user reset-password --email user@company.com
   
   # Disable 2FA temporarily
   keyorix admin user disable-2fa --email user@company.com
   
   # Check JWT configuration
   keyorix admin auth verify-jwt
   ```

3. **Performance Issues**
   ```bash
   # Check system resources
   top
   df -h
   free -m
   
   # Database performance
   keyorix admin db analyze
   
   # Clear caches
   keyorix admin cache clear
   ```

### Emergency Procedures

1. **Security Incident Response**
   - Isolate affected systems
   - Preserve evidence
   - Notify stakeholders
   - Implement containment
   - Document incident

2. **System Recovery**
   - Assess damage
   - Restore from backups
   - Verify system integrity
   - Resume operations
   - Post-incident review

### Support Escalation
1. **Level 1**: Basic troubleshooting
2. **Level 2**: Advanced technical issues
3. **Level 3**: Critical system problems
4. **Emergency**: Security incidents

Contact Information:
- **Technical Support**: support@company.com
- **Security Team**: security@company.com
- **Emergency Hotline**: +1-555-EMERGENCY
