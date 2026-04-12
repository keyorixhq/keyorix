# Remote CLI Setup Guide

This guide explains how to configure the Keyorix CLI to work with remote servers, enabling team collaboration and enterprise deployment.

## Overview

The Keyorix CLI supports two storage modes:
- **Local Mode**: Stores secrets in a local SQLite database (default)
- **Remote Mode**: Connects to a remote Keyorix server via HTTP API

## Quick Start

### 1. Check Current Status

```bash
keyorix config status
```

This shows your current configuration and storage type.

### 2. Configure Remote Server

```bash
keyorix config set-remote --url https://api.keyorix.company.com --api-key your-api-key
```

Or configure interactively:

```bash
keyorix config set-remote --url https://api.keyorix.company.com
# You'll be prompted for the API key
```

### 3. Authenticate

```bash
keyorix auth login
```

This will prompt for your API key and store it securely.

### 4. Test Connection

```bash
keyorix status
```

Or test connectivity:

```bash
keyorix ping
```

## Configuration Options

### Environment Variables

You can use environment variables in your configuration:

```yaml
# keyorix.yaml
storage:
  type: "remote"
  remote:
    base_url: "https://api.keyorix.company.com"
    api_key: "${SECRETLY_API_KEY}"
    timeout_seconds: 30
    retry_attempts: 3
    tls_verify: true
```

Supported environment variables:
- `SECRETLY_API_KEY`
- `SECRETLY_TOKEN`
- `API_KEY`

### Configuration File

The CLI uses `keyorix.yaml` for configuration:

```yaml
storage:
  type: "remote"  # "local" or "remote"
  
  # Local storage configuration
  database:
    path: "./secrets.db"
  
  # Remote storage configuration
  remote:
    base_url: "https://api.keyorix.company.com"
    api_key: "${SECRETLY_API_KEY}"
    timeout_seconds: 30
    retry_attempts: 3
    tls_verify: true
```

## Commands Reference

### Configuration Commands

- `keyorix config status` - Show current configuration
- `keyorix config set-remote` - Configure remote server
- `keyorix config use-local` - Switch to local storage
- `keyorix config test-connection` - Test storage connection

### Authentication Commands

- `keyorix auth login` - Set up API key authentication
- `keyorix auth logout` - Clear authentication credentials
- `keyorix auth status` - Check authentication status

### Status Commands

- `keyorix status` - Check system health and connection
- `keyorix ping` - Test remote server connectivity

## Deployment Scenarios

### Development Environment

```bash
# Use local storage for development
keyorix config use-local
```

### Staging Environment

```bash
# Configure for staging server
keyorix config set-remote --url https://staging-api.keyorix.company.com
keyorix auth login
```

### Production Environment

```bash
# Configure for production server
keyorix config set-remote --url https://api.keyorix.company.com
keyorix auth login
```

## Troubleshooting

### Connection Issues

1. **Check network connectivity:**
   ```bash
   keyorix ping
   ```

2. **Verify server URL:**
   ```bash
   keyorix config status
   ```

3. **Test authentication:**
   ```bash
   keyorix auth status
   ```

### Common Error Messages

#### "circuit breaker is open"
The CLI has detected multiple connection failures and temporarily stopped trying to connect. Wait 30 seconds and try again.

#### "failed to create storage"
Check your configuration file and ensure all required fields are present.

#### "health check failed"
The remote server is not responding. Check if the server is running and accessible.

### Offline Mode

If the remote server is unavailable, the CLI can automatically switch to local mode:

```bash
# This will temporarily switch to local storage
keyorix config use-local
```

To switch back when connectivity is restored:

```bash
keyorix config set-remote --url your-server-url
```

## Security Considerations

### API Key Storage

API keys are stored in the configuration file. Ensure proper file permissions:

```bash
chmod 600 keyorix.yaml
```

### TLS/HTTPS

Always use HTTPS in production:

```yaml
storage:
  remote:
    base_url: "https://api.keyorix.company.com"  # Use HTTPS
    tls_verify: true  # Verify certificates
```

### Network Security

- Use VPN or private networks when possible
- Configure firewall rules to restrict access
- Monitor API key usage and rotate regularly

## Performance Optimization

### Caching

The CLI automatically caches GET requests for 5 minutes to improve performance.

### Connection Pooling

HTTP connections are reused when possible to reduce latency.

### Retry Logic

Failed requests are automatically retried with exponential backoff:
- Initial retry after 1 second
- Second retry after 4 seconds  
- Third retry after 9 seconds

## Examples

### Basic Remote Setup

```bash
# Configure remote server
keyorix config set-remote --url https://api.example.com --api-key abc123

# Verify configuration
keyorix config status

# Test connection
keyorix status

# Use normally
keyorix secret create --name "api-key" --type "api_key"
keyorix secret list
```

### Environment-Based Configuration

```bash
# Set environment variable
export SECRETLY_API_KEY="your-api-key-here"

# Configure with environment variable
keyorix config set-remote --url https://api.example.com --api-key '${SECRETLY_API_KEY}'

# The API key will be read from the environment variable
keyorix status
```

### Switching Between Environments

```bash
# Development (local)
keyorix config use-local
keyorix secret list

# Staging (remote)
keyorix config set-remote --url https://staging-api.example.com
keyorix auth login
keyorix secret list

# Production (remote)
keyorix config set-remote --url https://api.example.com  
keyorix auth login
keyorix secret list
```

## Migration Guide

### From Local to Remote

1. **Backup your local data:**
   ```bash
   cp secrets.db secrets.db.backup
   ```

2. **Configure remote server:**
   ```bash
   keyorix config set-remote --url https://your-server.com
   keyorix auth login
   ```

3. **Verify connection:**
   ```bash
   keyorix status
   ```

4. **Migrate secrets manually or use export/import tools**

### From Remote to Local

1. **Switch to local mode:**
   ```bash
   keyorix config use-local
   ```

2. **Verify local operation:**
   ```bash
   keyorix status
   ```

The CLI will automatically create a local database and you can start using it immediately.