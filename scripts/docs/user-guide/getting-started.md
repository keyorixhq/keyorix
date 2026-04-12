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
