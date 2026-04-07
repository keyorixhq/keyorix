# 🔒 Keyorix Security Guide

Comprehensive security documentation for the Keyorix secret management system.

## 🛡️ **Security Status: Production Ready**

- **Encryption**: AES-256-GCM validated and operational
- **Authentication**: Bearer token system implemented
- **Authorization**: Role-based access control (RBAC) active
- **Audit Logging**: Complete activity tracking
- **Security Tests**: 100% passing

## 🔐 **Encryption**

### Data Encryption
- **Algorithm**: AES-256-GCM (Galois/Counter Mode)
- **Key Size**: 256-bit encryption keys
- **Authentication**: Built-in authentication with GCM mode
- **Key Derivation**: Secure key derivation functions
- **Status**: ✅ Operational and tested

### Encryption at Rest
```go
// All secrets are encrypted before storage
encryptedValue, err := encryption.Encrypt(secretValue, key)
if err != nil {
    return fmt.Errorf("encryption failed: %w", err)
}
```

### Key Management
- **DEK (Data Encryption Key)**: Used for encrypting individual secrets
- **KEK (Key Encryption Key)**: Optional key for encrypting DEKs
- **Key Rotation**: Supported for enhanced security
- **Key Storage**: Secure key storage with proper permissions

## 🔑 **Authentication & Authorization**

### Authentication Methods
1. **Bearer Token Authentication**
   ```http
   Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
   ```

2. **API Key Authentication** (for service accounts)
   ```http
   X-API-Key: keyorix_api_key_...
   ```

### Role-Based Access Control (RBAC)
```yaml
Roles:
  - admin: Full system access
  - user: Standard secret management
  - viewer: Read-only access
  - service: API-only access

Permissions:
  - secret:create
  - secret:read
  - secret:update
  - secret:delete
  - secret:share
  - system:admin
```

### Permission Matrix
| Role | Create | Read | Update | Delete | Share | Admin |
|------|--------|------|--------|--------|-------|-------|
| Admin | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| User | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ |
| Viewer | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ |
| Service | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ |

## 🔍 **Audit Logging**

### Audit Events
All security-relevant events are logged:

```json
{
  "timestamp": "2025-10-08T16:30:00Z",
  "event_type": "SECRET_ACCESSED",
  "user_id": "user123",
  "secret_id": 1,
  "action": "read",
  "ip_address": "192.168.1.100",
  "user_agent": "keyorix-cli/1.0.0",
  "success": true,
  "details": {
    "secret_name": "api-key",
    "permission": "read"
  }
}
```

### Tracked Events
- Secret creation, access, modification, deletion
- Share creation, modification, revocation
- Authentication attempts (success/failure)
- Permission changes
- System configuration changes
- API access patterns

## 🌐 **API Security**

### HTTP Security Headers
```http
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Content-Security-Policy: default-src 'self'
```

### CORS Configuration
```yaml
cors:
  allowed_origins: ["https://keyorix.company.com"]
  allowed_methods: ["GET", "POST", "PUT", "DELETE"]
  allowed_headers: ["Authorization", "Content-Type"]
  max_age: 86400
```

### Rate Limiting
- **Default**: 100 requests/minute per user
- **Authentication**: 10 requests/minute per IP
- **Burst Protection**: Configurable burst limits
- **DDoS Protection**: Automatic IP blocking for abuse

## 🔒 **Secret Sharing Security**

### Permission Model
```go
type SharePermission string

const (
    PermissionRead  SharePermission = "read"
    PermissionWrite SharePermission = "write"
    PermissionAdmin SharePermission = "admin"
)
```

### Sharing Rules
1. **Owner Control**: Only secret owners can create shares
2. **Permission Inheritance**: Users cannot grant permissions they don't have
3. **Expiration**: All shares can have expiration dates
4. **Revocation**: Shares can be revoked at any time
5. **Audit Trail**: All sharing activities are logged

### Group Sharing
```yaml
Groups:
  - name: "dev-team"
    members: ["alice", "bob", "charlie"]
    permissions: ["secret:read", "secret:create"]
  
  - name: "ops-team"
    members: ["david", "eve"]
    permissions: ["secret:read", "secret:update", "system:monitor"]
```

## 🛡️ **Security Best Practices**

### Deployment Security
1. **TLS/HTTPS**: Always use encrypted connections in production
2. **Firewall**: Restrict access to necessary ports only
3. **Network Segmentation**: Deploy in secure network segments
4. **Regular Updates**: Keep system and dependencies updated
5. **Monitoring**: Implement security monitoring and alerting

### Configuration Security
```yaml
# Production security configuration
security:
  encryption_enabled: true
  auth_required: true
  tls_enabled: true
  audit_logging: true
  rate_limiting: true
  
tls:
  cert_file: "/path/to/cert.pem"
  key_file: "/path/to/key.pem"
  min_version: "1.2"
  
auth:
  token_expiry: "24h"
  refresh_token_expiry: "7d"
  max_login_attempts: 5
  lockout_duration: "15m"
```

### Database Security
- **Encryption at Rest**: All sensitive data encrypted
- **Connection Security**: Encrypted database connections
- **Access Control**: Database-level access restrictions
- **Backup Security**: Encrypted backups with secure storage

## 🚨 **Incident Response**

### Security Monitoring
```bash
# Monitor failed authentication attempts
./keyorix rbac audit-logs --event-type "AUTH_FAILED" --last 24h

# Check suspicious access patterns
./keyorix rbac audit-logs --user-id "suspicious_user" --last 7d

# Monitor privilege escalations
./keyorix rbac audit-logs --event-type "PERMISSION_GRANTED" --last 24h
```

### Emergency Procedures
1. **Compromise Detection**: Automated alerts for suspicious activity
2. **Access Revocation**: Immediate token/session invalidation
3. **Secret Rotation**: Emergency secret rotation procedures
4. **System Isolation**: Network isolation capabilities
5. **Forensic Logging**: Detailed logs for incident analysis

## 🔧 **Security Configuration**

### Minimal Security Configuration
```yaml
# keyorix-secure.yaml
security:
  encryption_enabled: true
  auth_required: true
  audit_logging: true
  
server:
  tls:
    enabled: true
    cert_file: "server.crt"
    key_file: "server.key"
    
auth:
  token_expiry: "1h"
  require_2fa: true
  
rate_limiting:
  enabled: true
  requests_per_minute: 60
```

### Enterprise Security Configuration
```yaml
# keyorix-enterprise.yaml
security:
  encryption_enabled: true
  use_kek: true
  kek_path: "/secure/kek.key"
  auth_required: true
  audit_logging: true
  compliance_mode: true
  
ldap:
  enabled: true
  server: "ldap://company.com:389"
  base_dn: "dc=company,dc=com"
  
monitoring:
  security_alerts: true
  failed_login_threshold: 3
  unusual_access_detection: true
```

## 📋 **Security Checklist**

### Pre-Production Security Review
- [ ] Encryption enabled and tested
- [ ] Authentication configured
- [ ] RBAC permissions defined
- [ ] Audit logging enabled
- [ ] TLS/HTTPS configured
- [ ] Rate limiting enabled
- [ ] Security headers configured
- [ ] Database security hardened
- [ ] Network security configured
- [ ] Monitoring and alerting setup

### Regular Security Maintenance
- [ ] Review audit logs weekly
- [ ] Rotate encryption keys quarterly
- [ ] Update dependencies monthly
- [ ] Review user permissions monthly
- [ ] Test backup/recovery procedures
- [ ] Security vulnerability scanning
- [ ] Penetration testing annually

## 🆘 **Security Support**

### Reporting Security Issues
- **Email**: security@keyorix.com
- **PGP Key**: Available on website
- **Response Time**: 24 hours for critical issues

### Security Resources
- **Security Guide**: This document
- **API Security**: See [API_REFERENCE.md](./API_REFERENCE.md)
- **Deployment Security**: See [DEPLOYMENT_GUIDE.md](../DEPLOYMENT_GUIDE.md)
- **Audit Logs**: `./keyorix rbac audit-logs --help`

## 🎯 **Security Status Summary**

**Your Keyorix system is production-ready with enterprise-grade security:**

✅ **Encryption**: AES-256-GCM operational  
✅ **Authentication**: Bearer token system active  
✅ **Authorization**: RBAC with granular permissions  
✅ **Audit Logging**: Complete activity tracking  
✅ **API Security**: Rate limiting and security headers  
✅ **Secret Sharing**: Secure permission-based sharing  
✅ **Monitoring**: Health checks and security alerts  

**Ready for production deployment with confidence!** 🚀