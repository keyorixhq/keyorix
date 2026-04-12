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
