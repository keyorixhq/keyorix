#!/bin/bash

# Task 7: Documentation and Training Creation Script
# Creates comprehensive documentation and training materials

set -e

echo "🚀 Starting Task 7: Documentation and Training Creation..."

# Create documentation directories
mkdir -p docs/{user-guide,admin-guide,api-docs,training,troubleshooting}
mkdir -p training/{videos,presentations,exercises}

echo "📚 Creating User Documentation..."

# User Guide
cat > docs/user-guide/getting-started.md << 'EOF'
# Getting Started with Keyorix

## Quick Start Guide

### 1. Accessing the System
- **Web Dashboard**: https://localhost/
- **CLI Tool**: `keyorix --help`
- **API Documentation**: https://localhost/swagger/

### 2. First Login
1. Navigate to https://localhost/
2. Use default credentials (change immediately):
   - Username: `admin`
   - Password: `admin123`
3. Complete profile setup and enable 2FA

### 3. Creating Your First Secret
1. Click "New Secret" in the dashboard
2. Enter secret name and value
3. Add tags and metadata
4. Set permissions and sharing options
5. Save the secret

### 4. Sharing Secrets
1. Select a secret from your list
2. Click "Share" button
3. Choose users or groups
4. Set permission levels (read/write/admin)
5. Configure expiration if needed

### 5. Using the CLI
```bash
# Login to CLI
keyorix auth login

# Create a secret
keyorix secret create "my-api-key" "secret-value"

# List secrets
keyorix secret list

# Share a secret
keyorix share create "my-api-key" --user "colleague@company.com"
```

## Next Steps
- Read the [Complete User Guide](complete-user-guide.md)
- Watch [Training Videos](../training/videos/)
- Try [Hands-on Exercises](../training/exercises/)
EOF

# Complete User Guide
cat > docs/user-guide/complete-user-guide.md << 'EOF'
# Complete User Guide

## Table of Contents
1. [Dashboard Overview](#dashboard-overview)
2. [Secret Management](#secret-management)
3. [Sharing and Collaboration](#sharing-and-collaboration)
4. [User Profile and Settings](#user-profile-and-settings)
5. [Security Features](#security-features)
6. [Mobile Usage](#mobile-usage)
7. [Troubleshooting](#troubleshooting)

## Dashboard Overview

### Main Dashboard
The dashboard provides a real-time overview of your secret management activity:

- **Recent Activity**: Latest actions and changes
- **Secret Statistics**: Total secrets, shared secrets, recent access
- **Security Alerts**: Important security notifications
- **Quick Actions**: Fast access to common tasks

### Navigation
- **Secrets**: Manage your secrets and access shared ones
- **Sharing**: View and manage sharing permissions
- **Profile**: Personal settings and security configuration
- **Analytics**: Usage statistics and insights
- **Admin**: Administrative functions (admin users only)

## Secret Management

### Creating Secrets
1. **Basic Information**
   - Name: Unique identifier for your secret
   - Type: Text, Password, JSON, File, or Custom
   - Value: The actual secret content

2. **Metadata**
   - Tags: Organize secrets with labels
   - Namespace: Group related secrets
   - Environment: Development, staging, production
   - Description: Additional context

3. **Security Settings**
   - Encryption: Automatic AES-256-GCM encryption
   - Access Control: Who can view/edit the secret
   - Audit Logging: Track all access and changes

### Secret Types
- **Text**: Plain text secrets like API keys
- **Password**: Secure password storage with generation
- **JSON**: Structured data like configuration objects
- **File**: Binary files and documents
- **Custom**: User-defined secret formats

### Advanced Features
- **Version History**: Track changes over time
- **Bulk Operations**: Manage multiple secrets at once
- **Search and Filter**: Find secrets quickly
- **Export/Import**: Backup and restore capabilities

## Sharing and Collaboration

### Sharing Types
1. **User Sharing**: Share with individual users
2. **Group Sharing**: Share with teams or departments
3. **Public Links**: Time-limited access links
4. **API Access**: Programmatic access for applications

### Permission Levels
- **Read**: View secret content only
- **Write**: Modify secret content and metadata
- **Admin**: Full control including sharing permissions
- **Owner**: Original creator with all privileges

### Sharing Workflow
1. Select secret(s) to share
2. Choose recipients (users/groups)
3. Set permission levels
4. Configure expiration (optional)
5. Add sharing notes (optional)
6. Send invitations

### Managing Shares
- **View Active Shares**: See all current sharing arrangements
- **Modify Permissions**: Change access levels
- **Revoke Access**: Remove sharing permissions
- **Share History**: Audit trail of sharing activities

## User Profile and Settings

### Profile Management
- **Personal Information**: Name, email, preferences
- **Avatar**: Profile picture and display settings
- **Language**: Interface language selection
- **Timezone**: Local time configuration

### Security Settings
- **Password Management**: Change password, strength requirements
- **Two-Factor Authentication**: TOTP, SMS, or hardware keys
- **Session Management**: Active sessions and timeout settings
- **API Keys**: Generate and manage API access tokens

### Preferences
- **Dashboard Layout**: Customize dashboard appearance
- **Notifications**: Email and in-app notification settings
- **Theme**: Light/dark mode and color preferences
- **Accessibility**: Screen reader and keyboard navigation

## Security Features

### Encryption
- **At Rest**: AES-256-GCM encryption for stored data
- **In Transit**: TLS 1.3 for all communications
- **Key Management**: Secure key derivation and rotation

### Authentication
- **Multi-Factor Authentication**: Required for all users
- **Session Security**: Secure session management
- **Password Policies**: Strong password requirements
- **Account Lockout**: Protection against brute force attacks

### Audit and Compliance
- **Activity Logging**: Complete audit trail
- **Access Monitoring**: Real-time access tracking
- **Compliance Reports**: GDPR, SOX, HIPAA compliance
- **Security Alerts**: Suspicious activity notifications

## Mobile Usage

### Mobile Web Interface
- **Responsive Design**: Optimized for all screen sizes
- **Touch Navigation**: Mobile-friendly interactions
- **Offline Capability**: Limited offline functionality
- **Push Notifications**: Mobile alert support

### Mobile Best Practices
- **Secure Connections**: Always use HTTPS
- **Screen Lock**: Enable device screen lock
- **App Switching**: Be aware of app switching security
- **Public WiFi**: Avoid on untrusted networks

## Troubleshooting

### Common Issues
1. **Login Problems**
   - Check username/password
   - Verify 2FA codes
   - Clear browser cache
   - Contact administrator

2. **Sharing Issues**
   - Verify recipient email addresses
   - Check permission levels
   - Review expiration settings
   - Confirm network connectivity

3. **Performance Issues**
   - Check internet connection
   - Clear browser cache
   - Disable browser extensions
   - Try different browser

### Getting Help
- **Documentation**: Comprehensive guides and references
- **Support Portal**: Submit tickets and track issues
- **Community Forum**: User discussions and tips
- **Training Resources**: Videos and tutorials

### Contact Information
- **Technical Support**: support@company.com
- **Security Issues**: security@company.com
- **General Questions**: help@company.com
- **Emergency Contact**: +1-555-HELP (24/7)
EOF

echo "👨‍💼 Creating Admin Documentation..."

# Admin Guide
cat > docs/admin-guide/admin-guide.md << 'EOF'
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
   export KEYORIX_ENV=production
   export KEYORIX_DB_URL="postgresql://user:pass@localhost/keyorix"
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
KEYORIX_ENV=production
KEYORIX_PORT=8080
KEYORIX_HOST=0.0.0.0

# Database Configuration
KEYORIX_DB_URL=postgresql://user:pass@localhost/keyorix
KEYORIX_DB_MAX_CONNECTIONS=100
KEYORIX_DB_TIMEOUT=30s

# Security Configuration
KEYORIX_JWT_SECRET=your-jwt-secret-here
KEYORIX_ENCRYPTION_KEY=your-encryption-key-here
KEYORIX_SESSION_TIMEOUT=24h

# Monitoring Configuration
KEYORIX_METRICS_ENABLED=true
KEYORIX_METRICS_PORT=9090
KEYORIX_LOG_LEVEL=info
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
  url: "${KEYORIX_DB_URL}"
  max_connections: 100
  connection_timeout: "30s"
  ssl_mode: "require"

security:
  jwt_secret: "${KEYORIX_JWT_SECRET}"
  encryption_key: "${KEYORIX_ENCRYPTION_KEY}"
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
EOF

echo "🎓 Creating Training Materials..."

# Training Overview
cat > docs/training/training-overview.md << 'EOF'
# Training Program Overview

## Training Modules

### Module 1: Introduction to Keyorix
- **Duration**: 30 minutes
- **Format**: Video + Hands-on
- **Topics**:
  - What is secret management?
  - Why use Keyorix?
  - System overview and architecture
  - Security principles

### Module 2: Getting Started
- **Duration**: 45 minutes
- **Format**: Interactive tutorial
- **Topics**:
  - Account setup and login
  - Dashboard navigation
  - Creating your first secret
  - Basic sharing concepts

### Module 3: Advanced Secret Management
- **Duration**: 60 minutes
- **Format**: Workshop
- **Topics**:
  - Secret types and metadata
  - Bulk operations
  - Search and filtering
  - Version history

### Module 4: Collaboration and Sharing
- **Duration**: 45 minutes
- **Format**: Group exercise
- **Topics**:
  - Sharing strategies
  - Permission management
  - Group collaboration
  - Audit and compliance

### Module 5: Security Best Practices
- **Duration**: 30 minutes
- **Format**: Presentation + Q&A
- **Topics**:
  - Security policies
  - Two-factor authentication
  - Access control
  - Incident response

### Module 6: Administration (Admin Only)
- **Duration**: 90 minutes
- **Format**: Technical workshop
- **Topics**:
  - User management
  - System configuration
  - Monitoring and maintenance
  - Troubleshooting

## Training Delivery Methods

### Self-Paced Learning
- **Online Modules**: Interactive web-based training
- **Video Library**: On-demand video content
- **Documentation**: Comprehensive written guides
- **Practice Environment**: Sandbox for hands-on learning

### Instructor-Led Training
- **Live Sessions**: Virtual or in-person training
- **Workshops**: Hands-on group activities
- **Q&A Sessions**: Expert-led discussion
- **Certification**: Completion certificates

### Ongoing Support
- **Office Hours**: Regular support sessions
- **User Community**: Peer-to-peer support
- **Knowledge Base**: Searchable help articles
- **Update Training**: New feature training

## Training Schedule

### New User Onboarding
- **Week 1**: Modules 1-2 (Getting Started)
- **Week 2**: Module 3 (Advanced Features)
- **Week 3**: Module 4 (Collaboration)
- **Week 4**: Module 5 (Security)

### Administrator Training
- **Prerequisites**: Complete user training
- **Duration**: 2 days intensive or 4 weeks part-time
- **Certification**: Required for admin access

### Ongoing Training
- **Monthly**: New feature updates
- **Quarterly**: Security refresher
- **Annually**: Comprehensive review

## Assessment and Certification

### Knowledge Checks
- **Module Quizzes**: 5-10 questions per module
- **Practical Exercises**: Hands-on demonstrations
- **Case Studies**: Real-world scenarios

### Certification Levels
- **Basic User**: Modules 1-3 completed
- **Advanced User**: Modules 1-5 completed
- **Administrator**: All modules + practical exam
- **Security Specialist**: Additional security training

### Continuing Education
- **Recertification**: Annual requirement
- **Advanced Topics**: Specialized training
- **Industry Updates**: Security trend awareness
EOF

# Hands-on Exercises
cat > docs/training/hands-on-exercises.md << 'EOF'
# Hands-On Training Exercises

## Exercise 1: First Secret Creation
**Objective**: Create and manage your first secret
**Duration**: 15 minutes

### Steps:
1. Log into the web dashboard
2. Navigate to the Secrets section
3. Click "New Secret"
4. Create a secret with these details:
   - Name: "my-first-api-key"
   - Type: "Text"
   - Value: "sk-1234567890abcdef"
   - Tags: "api", "development"
   - Environment: "development"
5. Save the secret
6. View the secret details
7. Edit the secret to add a description

### Verification:
- Secret appears in your secrets list
- All metadata is correctly saved
- Secret can be viewed and edited

## Exercise 2: Secret Sharing
**Objective**: Share secrets with team members
**Duration**: 20 minutes

### Steps:
1. Select the secret created in Exercise 1
2. Click the "Share" button
3. Add a colleague's email address
4. Set permission level to "Read"
5. Set expiration for 7 days
6. Add a sharing note: "API key for development testing"
7. Send the share invitation
8. View the sharing history
9. Modify the permission to "Write"
10. Revoke the share

### Verification:
- Share invitation is sent successfully
- Recipient receives access notification
- Permission changes are reflected immediately
- Share history shows all activities

## Exercise 3: CLI Usage
**Objective**: Use the command-line interface
**Duration**: 25 minutes

### Steps:
1. Install the CLI tool (if not already installed)
2. Authenticate with the server:
   ```bash
   keyorix auth login
   ```
3. List your secrets:
   ```bash
   keyorix secret list
   ```
4. Create a new secret:
   ```bash
   keyorix secret create "database-password" "super-secure-password"
   ```
5. Add metadata:
   ```bash
   keyorix secret update "database-password" --tag "database" --tag "production"
   ```
6. Share the secret:
   ```bash
   keyorix share create "database-password" --user "admin@company.com" --permission "read"
   ```
7. List shared secrets:
   ```bash
   keyorix share list
   ```

### Verification:
- CLI authentication successful
- All commands execute without errors
- Secrets created via CLI appear in web dashboard
- Sharing works between CLI and web interface

## Exercise 4: Group Collaboration
**Objective**: Set up team-based secret sharing
**Duration**: 30 minutes

### Prerequisites:
- Admin access or pre-created groups
- Multiple user accounts for testing

### Steps:
1. Create a new group (Admin only):
   - Group name: "Development Team"
   - Add 3-5 team members
2. Create project secrets:
   - "dev-database-url"
   - "dev-api-keys"
   - "dev-service-tokens"
3. Share all secrets with the "Development Team" group
4. Set different permission levels:
   - Database URL: Read-only
   - API Keys: Read/Write
   - Service Tokens: Admin
5. Test access from different user accounts
6. Create a shared namespace: "development-project"
7. Move all secrets to the shared namespace

### Verification:
- All group members can access shared secrets
- Permission levels are enforced correctly
- Namespace organization works properly
- Audit logs show all group activities

## Exercise 5: Security Configuration
**Objective**: Configure security settings
**Duration**: 20 minutes

### Steps:
1. Access your profile settings
2. Enable Two-Factor Authentication:
   - Choose TOTP method
   - Scan QR code with authenticator app
   - Enter verification code
   - Save backup codes
3. Generate an API key:
   - Create new API key
   - Set expiration date
   - Copy and securely store the key
4. Review active sessions:
   - View current sessions
   - Revoke old/unused sessions
5. Configure notification preferences:
   - Enable security alerts
   - Set email notifications for sharing
   - Configure mobile push notifications

### Verification:
- 2FA is required for next login
- API key works for programmatic access
- Session management functions properly
- Notifications are received as configured

## Exercise 6: Monitoring and Troubleshooting
**Objective**: Use monitoring tools and resolve issues
**Duration**: 25 minutes

### Steps:
1. Access the monitoring dashboard
2. Review system health metrics:
   - Response times
   - Error rates
   - Active users
   - Database performance
3. Check audit logs:
   - Filter by your user account
   - Review recent activities
   - Export audit data
4. Simulate and resolve common issues:
   - Forgotten password reset
   - Lost 2FA device recovery
   - Permission troubleshooting
   - Performance investigation
5. Use the health check endpoint:
   ```bash
   curl https://localhost/health
   ```

### Verification:
- Monitoring dashboards load correctly
- Audit logs contain expected entries
- Issue resolution procedures work
- Health checks return positive status

## Exercise 7: Advanced Features
**Objective**: Explore advanced functionality
**Duration**: 35 minutes

### Steps:
1. **Bulk Operations**:
   - Select multiple secrets
   - Apply bulk tags
   - Bulk sharing configuration
   - Bulk export/import

2. **Version History**:
   - Update a secret multiple times
   - View version history
   - Compare versions
   - Rollback to previous version

3. **Advanced Search**:
   - Search by tags
   - Filter by environment
   - Search in secret content
   - Save search queries

4. **API Integration**:
   - Use API documentation
   - Make API calls with curl
   - Integrate with external tools
   - Test error handling

### Verification:
- Bulk operations complete successfully
- Version history tracks all changes
- Search functionality finds relevant results
- API integration works as expected

## Assessment Quiz

### Questions:
1. What are the three main permission levels for secret sharing?
2. How do you enable two-factor authentication?
3. What is the difference between user sharing and group sharing?
4. How can you view the audit trail for a specific secret?
5. What should you do if you lose access to your 2FA device?

### Practical Assessment:
1. Create a secret with specific metadata
2. Share it with appropriate permissions
3. Demonstrate CLI usage
4. Show monitoring dashboard navigation
5. Explain security best practices

### Completion Criteria:
- All exercises completed successfully
- Quiz score of 80% or higher
- Practical demonstration passed
- Understanding of security principles
- Ability to troubleshoot common issues
EOF

echo "📖 Creating API Documentation..."

# API Documentation
cat > docs/api-docs/api-overview.md << 'EOF'
# API Documentation Overview

## Introduction
The Keyorix API provides programmatic access to all secret management functionality. The API follows REST principles and uses JSON for data exchange.

## Base URL
```
Production: https://your-domain.com/api/v1
Development: https://localhost/api/v1
```

## Authentication
All API requests require authentication using JWT tokens.

### Getting an API Token
1. **Web Dashboard Method**:
   - Go to Profile → API Keys
   - Click "Generate New Key"
   - Copy the token (shown only once)

2. **CLI Method**:
   ```bash
   keyorix auth token create --name "my-api-key"
   ```

### Using the Token
Include the token in the Authorization header:
```bash
curl -H "Authorization: Bearer YOUR_JWT_TOKEN" \
     https://localhost/api/v1/secrets
```

## API Endpoints

### Authentication Endpoints
- `POST /auth/login` - User login
- `POST /auth/logout` - User logout
- `POST /auth/refresh` - Refresh JWT token
- `GET /auth/me` - Get current user info

### Secret Management
- `GET /secrets` - List secrets
- `POST /secrets` - Create secret
- `GET /secrets/{id}` - Get secret details
- `PUT /secrets/{id}` - Update secret
- `DELETE /secrets/{id}` - Delete secret
- `GET /secrets/{id}/history` - Get version history

### Sharing Management
- `GET /shares` - List shares
- `POST /shares` - Create share
- `GET /shares/{id}` - Get share details
- `PUT /shares/{id}` - Update share
- `DELETE /shares/{id}` - Delete share
- `POST /shares/{id}/accept` - Accept share invitation

### User Management
- `GET /users` - List users (admin only)
- `POST /users` - Create user (admin only)
- `GET /users/{id}` - Get user details
- `PUT /users/{id}` - Update user
- `DELETE /users/{id}` - Delete user (admin only)

### System Endpoints
- `GET /health` - System health check
- `GET /metrics` - System metrics (admin only)
- `GET /audit` - Audit logs (admin only)

## Response Format
All API responses follow this format:
```json
{
  "success": true,
  "data": { ... },
  "message": "Operation completed successfully",
  "timestamp": "2025-01-31T12:00:00Z"
}
```

Error responses:
```json
{
  "success": false,
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid input data",
    "details": { ... }
  },
  "timestamp": "2025-01-31T12:00:00Z"
}
```

## Rate Limiting
- **Standard Users**: 100 requests per minute
- **Premium Users**: 1000 requests per minute
- **Admin Users**: 5000 requests per minute

Rate limit headers are included in responses:
```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1643723400
```

## Error Codes
- `400` - Bad Request
- `401` - Unauthorized
- `403` - Forbidden
- `404` - Not Found
- `409` - Conflict
- `422` - Validation Error
- `429` - Rate Limited
- `500` - Internal Server Error

## Interactive Documentation
Visit https://localhost/swagger/ for interactive API documentation with:
- Live API testing
- Request/response examples
- Schema definitions
- Authentication testing
EOF

echo "🔧 Creating Troubleshooting Guide..."

# Troubleshooting Guide
cat > docs/troubleshooting/common-issues.md << 'EOF'
# Common Issues and Solutions

## Login and Authentication Issues

### Issue: Cannot Login to Web Dashboard
**Symptoms**: Login page shows "Invalid credentials" error

**Solutions**:
1. **Check Credentials**:
   - Verify username/email is correct
   - Ensure password is typed correctly
   - Check for caps lock

2. **Reset Password**:
   ```bash
   # Admin can reset user password
   keyorix admin user reset-password --email user@company.com
   ```

3. **Check Account Status**:
   - Account may be locked after failed attempts
   - Contact administrator to unlock

### Issue: Two-Factor Authentication Problems
**Symptoms**: 2FA codes not working

**Solutions**:
1. **Time Synchronization**:
   - Ensure device time is synchronized
   - Check timezone settings

2. **Backup Codes**:
   - Use backup codes if available
   - Generate new backup codes after use

3. **Reset 2FA** (Admin only):
   ```bash
   keyorix admin user disable-2fa --email user@company.com
   ```

## Secret Management Issues

### Issue: Cannot Create Secrets
**Symptoms**: "Permission denied" or validation errors

**Solutions**:
1. **Check Permissions**:
   - Verify user has create permissions
   - Check namespace access rights

2. **Validate Input**:
   - Secret name must be unique
   - Check for invalid characters
   - Ensure required fields are filled

3. **Storage Limits**:
   - Check if storage quota is exceeded
   - Contact admin to increase limits

### Issue: Secrets Not Appearing
**Symptoms**: Created secrets don't show in list

**Solutions**:
1. **Refresh Browser**:
   - Hard refresh (Ctrl+F5)
   - Clear browser cache

2. **Check Filters**:
   - Remove active filters
   - Check namespace selection
   - Verify search terms

3. **Database Sync**:
   ```bash
   # Check database connectivity
   keyorix system health
   ```

## Sharing and Collaboration Issues

### Issue: Share Invitations Not Received
**Symptoms**: Recipients don't receive share notifications

**Solutions**:
1. **Email Configuration**:
   - Check email server settings
   - Verify SMTP configuration
   - Check spam/junk folders

2. **User Verification**:
   - Ensure recipient email is correct
   - Verify user exists in system
   - Check user notification preferences

3. **Manual Notification**:
   - Copy share link manually
   - Use alternative communication method

### Issue: Permission Denied on Shared Secrets
**Symptoms**: Cannot access shared secrets despite invitation

**Solutions**:
1. **Accept Invitation**:
   - Click accept link in email
   - Login and accept via dashboard

2. **Check Permissions**:
   - Verify permission level granted
   - Check if share has expired
   - Contact share owner

3. **Clear Cache**:
   - Logout and login again
   - Clear browser cache
   - Try different browser

## Performance Issues

### Issue: Slow Dashboard Loading
**Symptoms**: Dashboard takes long time to load

**Solutions**:
1. **Browser Optimization**:
   - Clear browser cache and cookies
   - Disable unnecessary extensions
   - Try incognito/private mode

2. **Network Issues**:
   - Check internet connection
   - Try different network
   - Use wired connection if on WiFi

3. **Server Performance**:
   ```bash
   # Check system resources
   keyorix admin system status
   
   # View performance metrics
   curl https://localhost/health/detailed
   ```

### Issue: API Requests Timing Out
**Symptoms**: API calls fail with timeout errors

**Solutions**:
1. **Increase Timeout**:
   ```bash
   # Set longer timeout in requests
   curl --max-time 60 https://localhost/api/v1/secrets
   ```

2. **Check Rate Limits**:
   - Verify not hitting rate limits
   - Implement request throttling
   - Use pagination for large datasets

3. **Server Resources**:
   - Check server CPU/memory usage
   - Scale resources if needed
   - Optimize database queries

## System Administration Issues

### Issue: Database Connection Errors
**Symptoms**: "Database connection failed" errors

**Solutions**:
1. **Check Database Status**:
   ```bash
   # Test database connectivity
   pg_isready -h localhost -p 5432
   
   # Check database logs
   sudo tail -f /var/log/postgresql/postgresql.log
   ```

2. **Connection Pool**:
   ```bash
   # Check connection pool status
   keyorix admin db status
   
   # Reset connection pool
   keyorix admin db reset-pool
   ```

3. **Database Recovery**:
   ```bash
   # Restart database service
   sudo systemctl restart postgresql
   
   # Check database integrity
   psql -c "SELECT pg_database_size('keyorix');"
   ```

### Issue: SSL Certificate Problems
**Symptoms**: "Certificate invalid" or "Connection not secure" errors

**Solutions**:
1. **Certificate Validation**:
   ```bash
   # Check certificate expiration
   openssl x509 -in /etc/ssl/certs/keyorix.crt -text -noout
   
   # Verify certificate chain
   openssl verify -CAfile ca.crt keyorix.crt
   ```

2. **Certificate Renewal**:
   ```bash
   # Renew Let's Encrypt certificate
   sudo certbot renew
   
   # Restart web server
   sudo systemctl restart nginx
   ```

3. **Self-Signed Certificates**:
   - Add certificate to browser trust store
   - Use proper CA-signed certificates for production

## Mobile and Browser Issues

### Issue: Mobile Interface Problems
**Symptoms**: Interface not responsive on mobile devices

**Solutions**:
1. **Browser Compatibility**:
   - Use supported mobile browsers
   - Update browser to latest version
   - Clear mobile browser cache

2. **Responsive Design**:
   - Check viewport settings
   - Verify CSS media queries
   - Test on different screen sizes

3. **Touch Interface**:
   - Ensure touch targets are adequate size
   - Check for touch event conflicts
   - Verify gesture support

### Issue: Browser Compatibility
**Symptoms**: Features not working in specific browsers

**Solutions**:
1. **Supported Browsers**:
   - Chrome 90+
   - Firefox 88+
   - Safari 14+
   - Edge 90+

2. **JavaScript Issues**:
   - Enable JavaScript
   - Check for script blockers
   - Disable conflicting extensions

3. **Feature Detection**:
   - Check browser feature support
   - Use progressive enhancement
   - Provide fallback options

## Emergency Procedures

### System Recovery
1. **Service Restart**:
   ```bash
   sudo systemctl restart keyorix
   sudo systemctl restart nginx
   sudo systemctl restart postgresql
   ```

2. **Database Recovery**:
   ```bash
   # Restore from backup
   gunzip -c backup.sql.gz | psql keyorix
   
   # Verify data integrity
   keyorix admin db verify
   ```

3. **Configuration Reset**:
   ```bash
   # Restore configuration from backup
   sudo cp /backup/config/* /etc/keyorix/
   
   # Restart services
   sudo systemctl restart keyorix
   ```

### Security Incident Response
1. **Immediate Actions**:
   - Isolate affected systems
   - Change all administrative passwords
   - Revoke suspicious API tokens
   - Enable additional logging

2. **Investigation**:
   - Review audit logs
   - Check access patterns
   - Identify compromised accounts
   - Document findings

3. **Recovery**:
   - Patch security vulnerabilities
   - Update security policies
   - Notify affected users
   - Implement additional controls

## Getting Help

### Self-Service Resources
- **Documentation**: Complete guides and references
- **Knowledge Base**: Searchable help articles
- **Community Forum**: User discussions and tips
- **Video Tutorials**: Step-by-step guides

### Support Channels
- **Email Support**: support@company.com
- **Live Chat**: Available during business hours
- **Phone Support**: +1-555-SUPPORT
- **Emergency Hotline**: +1-555-EMERGENCY (24/7)

### Information to Provide
When contacting support, include:
- Error messages (exact text)
- Steps to reproduce the issue
- Browser/device information
- User account details
- System logs (if available)
- Screenshots or screen recordings

### Response Times
- **Critical Issues**: 1 hour
- **High Priority**: 4 hours
- **Medium Priority**: 24 hours
- **Low Priority**: 72 hours
EOF

echo "✅ Task 7: Documentation and Training - COMPLETED!"
echo ""
echo "📚 Documentation created:"
echo "  - User guides and tutorials"
echo "  - Administrator documentation"
echo "  - API documentation"
echo "  - Training materials and exercises"
echo "  - Troubleshooting guides"
echo ""
echo "🎓 Training program includes:"
echo "  - 6 comprehensive modules"
echo "  - Hands-on exercises"
echo "  - Assessment and certification"
echo "  - Multiple delivery methods"
echo ""
echo "📖 Access documentation at:"
echo "  - User Guide: docs/user-guide/"
echo "  - Admin Guide: docs/admin-guide/"
echo "  - API Docs: docs/api-docs/"
echo "  - Training: docs/training/"
echo "  - Troubleshooting: docs/troubleshooting/"