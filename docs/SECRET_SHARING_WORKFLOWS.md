# Secret Sharing Workflows and Examples

## Overview

This document provides practical examples and workflows for common secret sharing scenarios. These examples demonstrate best practices and real-world usage patterns for the Secret Sharing feature.

## Table of Contents
1. [Basic Workflows](#basic-workflows)
2. [Team Collaboration](#team-collaboration)
3. [DevOps Scenarios](#devops-scenarios)
4. [Enterprise Workflows](#enterprise-workflows)
5. [Automation Examples](#automation-examples)
6. [Troubleshooting Workflows](#troubleshooting-workflows)

## Basic Workflows

### Workflow 1: Share Database Credentials with Developer

**Scenario**: A DBA needs to share production database credentials with a developer for debugging.

**Steps**:
1. **DBA creates/locates the secret**
2. **Share with read-only access**
3. **Developer accesses credentials**
4. **DBA revokes access after debugging**

**Implementation**:

#### Via Web Interface
```
1. DBA navigates to "Production DB Password" secret
2. Clicks "Share" button
3. Enters developer username: "john.developer"
4. Selects "Read" permission
5. Clicks "Share Secret"
6. Developer receives notification
7. After debugging, DBA revokes access
```

#### Via CLI
```bash
# DBA shares the secret
keyorix secret share \
  --name "Production DB Password" \
  --recipient john.developer \
  --permission read \
  --note "Debugging issue #1234"

# Developer accesses the secret
keyorix secret get --name "Production DB Password"

# DBA revokes access after debugging
keyorix shares list --secret "Production DB Password"
keyorix shares revoke --id 456
```

#### Via API
```bash
# DBA shares the secret
curl -X POST "https://api.keyorix.com/api/v1/secrets/123/share" \
  -H "Authorization: Bearer dba-token" \
  -H "Content-Type: application/json" \
  -d '{
    "recipient_id": 789,
    "permission": "read",
    "note": "Debugging issue #1234"
  }'

# Developer accesses the secret
curl -X GET "https://api.keyorix.com/api/v1/secrets/123" \
  -H "Authorization: Bearer dev-token"

# DBA revokes access
curl -X DELETE "https://api.keyorix.com/api/v1/shares/456" \
  -H "Authorization: Bearer dba-token"
```

### Workflow 2: Temporary Access for Contractor

**Scenario**: Grant temporary access to API keys for a contractor working on integration.

**Steps**:
1. **Create time-limited share**
2. **Monitor contractor access**
3. **Automatic or manual revocation**

**Implementation**:
```bash
# Share with contractor
keyorix secret share \
  --name "Payment API Key" \
  --recipient contractor@company.com \
  --permission read \
  --expires-in 7d \
  --note "Integration project - expires 2025-07-29"

# Monitor access
keyorix audit logs \
  --secret "Payment API Key" \
  --user contractor@company.com \
  --since 7d

# Manual revocation if needed
keyorix shares revoke --recipient contractor@company.com
```

## Team Collaboration

### Workflow 3: Development Team Secret Sharing

**Scenario**: Share development environment secrets with the entire development team.

**Implementation**:

#### Using Groups (Recommended)
```bash
# Create or use existing development group
keyorix groups create --name "developers" \
  --description "Development team members"

# Add team members to group
keyorix groups add-member --group developers --user alice.dev
keyorix groups add-member --group developers --user bob.dev
keyorix groups add-member --group developers --user charlie.dev

# Share secrets with the entire group
keyorix secret share \
  --name "Dev Database URL" \
  --group developers \
  --permission write

keyorix secret share \
  --name "Dev API Keys" \
  --group developers \
  --permission read
```

#### Individual Sharing (Alternative)
```bash
# Share with each team member individually
for user in alice.dev bob.dev charlie.dev; do
  keyorix secret share \
    --name "Dev Database URL" \
    --recipient $user \
    --permission write
done
```

### Workflow 4: Cross-Team Collaboration

**Scenario**: Frontend team needs access to backend API secrets for integration testing.

**Implementation**:
```bash
# Backend team lead shares API secrets
keyorix secret share \
  --name "Backend API Key" \
  --group frontend-team \
  --permission read \
  --note "For integration testing only"

# Share staging environment secrets
keyorix secret share \
  --name "Staging Database URL" \
  --group frontend-team \
  --permission read

# Monitor usage
keyorix audit logs \
  --secret "Backend API Key" \
  --group frontend-team \
  --format table
```

## DevOps Scenarios

### Workflow 5: CI/CD Pipeline Secrets

**Scenario**: Share deployment secrets with CI/CD service accounts.

**Implementation**:
```bash
# Create service account for CI/CD
keyorix users create-service-account \
  --name "github-actions" \
  --description "GitHub Actions CI/CD"

# Share deployment secrets
keyorix secret share \
  --name "Production Deploy Key" \
  --recipient github-actions \
  --permission read

keyorix secret share \
  --name "Docker Registry Token" \
  --recipient github-actions \
  --permission read

# Monitor CI/CD access
keyorix audit logs \
  --user github-actions \
  --format json | jq '.[] | select(.result == "success")'
```

### Workflow 6: Infrastructure Team Rotation

**Scenario**: Rotate infrastructure secrets and update team access.

**Implementation**:
```bash
#!/bin/bash
# Infrastructure secret rotation script

# List of infrastructure secrets to rotate
SECRETS=("AWS Root Key" "Database Master Password" "SSL Certificates")
INFRA_TEAM="infrastructure-team"

for secret in "${SECRETS[@]}"; do
  echo "Rotating: $secret"
  
  # Generate new secret value
  NEW_VALUE=$(openssl rand -base64 32)
  
  # Update secret
  keyorix secret update --name "$secret" --value "$NEW_VALUE"
  
  # Ensure infrastructure team has access
  keyorix secret share \
    --name "$secret" \
    --group "$INFRA_TEAM" \
    --permission write \
    --force-update
  
  # Notify team
  keyorix notify --group "$INFRA_TEAM" \
    --message "Secret '$secret' has been rotated"
done
```

## Enterprise Workflows

### Workflow 7: Compliance Audit Preparation

**Scenario**: Prepare for security audit by reviewing all secret shares.

**Implementation**:
```bash
# Generate comprehensive sharing report
keyorix audit sharing-report \
  --format csv \
  --output sharing-audit-$(date +%Y%m%d).csv \
  --include-metadata

# Review high-privilege shares
keyorix shares list \
  --permission write \
  --format table \
  --sort-by created_at

# Check for stale shares (older than 90 days)
keyorix shares list \
  --older-than 90d \
  --format json | \
  jq '.[] | {secret_name, recipient, created_at, last_accessed}'

# Review group memberships
keyorix groups audit \
  --include-permissions \
  --format report
```

### Workflow 8: Incident Response - Compromised Account

**Scenario**: Respond to a compromised user account by revoking all their access.

**Implementation**:
```bash
#!/bin/bash
# Incident response script for compromised account

COMPROMISED_USER="john.doe"
INCIDENT_ID="INC-2025-001"

echo "Starting incident response for user: $COMPROMISED_USER"

# 1. Immediately lock the account
keyorix users lock --username "$COMPROMISED_USER" \
  --reason "Security incident $INCIDENT_ID"

# 2. Revoke all active sessions
keyorix sessions revoke-all --username "$COMPROMISED_USER"

# 3. List all secrets the user had access to
keyorix audit user-access \
  --username "$COMPROMISED_USER" \
  --output "incident-${INCIDENT_ID}-access.json"

# 4. Revoke all shares TO the user
keyorix shares revoke-all --recipient "$COMPROMISED_USER" \
  --reason "Security incident $INCIDENT_ID"

# 5. List all secrets the user owned/shared
keyorix shares list --owner "$COMPROMISED_USER" \
  --output "incident-${INCIDENT_ID}-owned.json"

# 6. Generate incident report
keyorix audit incident-report \
  --incident-id "$INCIDENT_ID" \
  --username "$COMPROMISED_USER" \
  --timeframe 30d \
  --output "incident-${INCIDENT_ID}-report.pdf"

echo "Incident response completed. Review generated reports."
```

## Automation Examples

### Workflow 9: Automated Onboarding

**Scenario**: Automatically grant new team members access to appropriate secrets.

**Implementation**:
```bash
#!/bin/bash
# New employee onboarding script

NEW_USER="$1"
TEAM="$2"
ROLE="$3"

if [ -z "$NEW_USER" ] || [ -z "$TEAM" ] || [ -z "$ROLE" ]; then
  echo "Usage: $0 <username> <team> <role>"
  exit 1
fi

echo "Onboarding $NEW_USER to $TEAM as $ROLE"

# Add user to team group
keyorix groups add-member --group "$TEAM" --user "$NEW_USER"

# Grant role-specific access
case "$ROLE" in
  "developer")
    keyorix secret share --name "Dev Environment Secrets" \
      --recipient "$NEW_USER" --permission write
    keyorix secret share --name "Test Database URL" \
      --recipient "$NEW_USER" --permission read
    ;;
  "devops")
    keyorix secret share --name "Infrastructure Secrets" \
      --recipient "$NEW_USER" --permission write
    keyorix secret share --name "CI/CD Tokens" \
      --recipient "$NEW_USER" --permission read
    ;;
  "qa")
    keyorix secret share --name "Test Environment Secrets" \
      --recipient "$NEW_USER" --permission read
    ;;
esac

# Send welcome notification
keyorix notify --user "$NEW_USER" \
  --message "Welcome to $TEAM! You now have access to team secrets."

echo "Onboarding completed for $NEW_USER"
```

### Workflow 10: Automated Secret Rotation

**Scenario**: Automatically rotate secrets and update all shares.

**Implementation**:
```python
#!/usr/bin/env python3
"""
Automated secret rotation with sharing updates
"""

import os
import json
import requests
from datetime import datetime, timedelta

class SecretRotator:
    def __init__(self, api_base, token):
        self.api_base = api_base
        self.headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
    
    def rotate_secret(self, secret_id, new_value):
        """Rotate a secret value"""
        url = f"{self.api_base}/secrets/{secret_id}"
        data = {'value': new_value}
        
        response = requests.put(url, headers=self.headers, json=data)
        response.raise_for_status()
        return response.json()
    
    def get_secret_shares(self, secret_id):
        """Get all shares for a secret"""
        url = f"{self.api_base}/secrets/{secret_id}/shares"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        return response.json()['data']['shares']
    
    def notify_share_recipients(self, secret_id, secret_name):
        """Notify all recipients of secret rotation"""
        shares = self.get_secret_shares(secret_id)
        
        for share in shares:
            recipient_id = share['recipient_id']
            message = f"Secret '{secret_name}' has been rotated. Please update your applications."
            
            # Send notification (implementation depends on notification system)
            self.send_notification(recipient_id, message)
    
    def rotate_with_notification(self, secret_id, secret_name, new_value):
        """Rotate secret and notify all recipients"""
        print(f"Rotating secret: {secret_name}")
        
        # Rotate the secret
        result = self.rotate_secret(secret_id, new_value)
        
        # Notify all recipients
        self.notify_share_recipients(secret_id, secret_name)
        
        # Log the rotation
        self.log_rotation(secret_id, secret_name)
        
        return result

# Usage example
if __name__ == "__main__":
    rotator = SecretRotator(
        api_base="https://api.keyorix.com/api/v1",
        token=os.environ['SECRETLY_TOKEN']
    )
    
    # Rotate database password
    new_password = generate_secure_password()
    rotator.rotate_with_notification(
        secret_id=123,
        secret_name="Production Database Password",
        new_value=new_password
    )
```

## Troubleshooting Workflows

### Workflow 11: Debugging Access Issues

**Scenario**: User reports they cannot access a shared secret.

**Diagnostic Steps**:
```bash
# 1. Verify the secret exists
keyorix secret get --id 123 --metadata-only

# 2. Check if user has any access
keyorix shares list --secret-id 123 --recipient john.doe

# 3. Check user's group memberships
keyorix users groups --username john.doe

# 4. Review recent audit logs
keyorix audit logs \
  --secret-id 123 \
  --user john.doe \
  --since 24h \
  --include-failures

# 5. Test access with different permission levels
keyorix test-access --secret-id 123 --user john.doe

# 6. Check for account issues
keyorix users status --username john.doe
```

### Workflow 12: Performance Investigation

**Scenario**: Slow response times when accessing shared secrets.

**Investigation Steps**:
```bash
# 1. Check system performance metrics
keyorix system metrics --component sharing --timeframe 1h

# 2. Analyze slow queries
keyorix audit slow-queries \
  --component sharing \
  --threshold 5s \
  --since 1h

# 3. Review sharing patterns
keyorix audit sharing-patterns \
  --high-volume-secrets \
  --format table

# 4. Check for bulk operations
keyorix audit bulk-operations \
  --type sharing \
  --since 1h

# 5. Monitor real-time performance
keyorix monitor sharing --real-time --duration 10m
```

---

*These workflows provide practical examples for common secret sharing scenarios. Adapt them to your specific environment and requirements.*

*Last updated: July 22, 2025*
*Version: 1.0.0*