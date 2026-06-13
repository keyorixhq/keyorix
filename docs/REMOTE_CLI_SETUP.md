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
    api_key: "${KEYORIX_API_KEY}"
    timeout_seconds: 30
    retry_attempts: 3
    tls_verify: true
```

Supported environment variables:
- `KEYORIX_API_KEY`
- `KEYORIX_TOKEN`
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
    api_key: "${KEYORIX_API_KEY}"
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

### Audit Commands

The audit trail is hash-chained and tamper-evident (ADR-029). `verify` and
`export` are read-only and require `audit.read`; `checkpoint` writes and requires
`system.write` (admin-level).

- `keyorix audit verify` - Re-walk the hash chain and report integrity. **Exits
  non-zero if the chain does not verify**, so it can run unattended (cron/CI) to
  flag tampering. Prints the chain head (`head id` + `head hash`); record
  `(chained events, head hash)` externally each run to anchor against the
  tail-truncation / genesis re-seed an on-box re-walk cannot catch alone. Add
  `--json` to emit the raw result for machine capture. When the server runs the
  signed-checkpoint scheduler (`audit_checkpoints`, ADR-029), verify also enforces
  the chain against the latest in-DB checkpoint — detecting that truncation
  **on-box** — and reports `checkpointed`.
- `keyorix audit logs` - Query the trail as a human-readable table for interactive
  investigation / compliance spot-checks. Filters: `--event-type` (e.g.
  `secret.deleted`), `--user-id`, `--project-id`, `--actor-type`
  (user|machine_identity|system), `--since`/`--until` (RFC3339), `--limit` (1–100).
  For bulk/machine consumption use `export` instead.
- `keyorix audit export` - Stream the full-fidelity audit feed as NDJSON (one
  event per line) on stdout for SIEM pull; the per-run summary and resume cursor
  go to stderr. Pull incrementally with `--after-id <cursor>`, or grab everything
  since a point in time with `--since <RFC3339> --all`. `--limit` sets page size
  (1–1000).
- `keyorix audit checkpoint` - Write a signed checkpoint of the current verified
  chain head on demand (ADR-029) so truncation is detectable **on-box**. Normally
  the server's `audit_checkpoints` scheduler writes these; run this to re-baseline
  immediately — most often right after a **DEK rotation**, when `verify` fails
  closed until a fresh checkpoint is written under the new key. Requires server
  encryption (the signing key is DEK-derived); the server refuses if the chain
  does not verify.

```bash
# Nightly tamper check (exit 1 → alert), capturing the anchor:
keyorix audit verify --json >> audit-anchors.ndjson || notify "audit chain broken"

# Incremental SIEM pull from the last cursor:
keyorix audit export --after-id "$LAST_ID" --all > batch.ndjson

# Who deleted secrets in project 5 since the start of the month?
keyorix audit logs --event-type secret.deleted --project-id 5 --since 2026-06-01T00:00:00Z

# Re-baseline on-box detection right after a DEK rotation:
keyorix audit checkpoint
```

### Rotation Commands

Manage secret-rotation policies (credential-rotation hygiene — a NIS2 / ISO
A.5.15 control) from the terminal. Reads need `secrets.read`, writes `secrets.write`,
at the policy's project/environment scope.

- `keyorix rotation list [--project-id N] [--environment-id N]` - List policies.
- `keyorix rotation create --name <n> --scope project|environment --interval-days <d>
  [--project-id N | --environment-id N] [--alert-days-before N] [--description …]` -
  Create a policy. A `project`-scoped policy needs `--project-id`; an
  `environment`-scoped one needs `--environment-id`.
- `keyorix rotation show <id>` / `keyorix rotation delete <id>` - Inspect / remove.
- `keyorix rotation status [--project-id N]` - List policy-covered secrets that are
  **overdue or approaching** their rotation deadline (the actionable posture view);
  prints a clean "all within window" when nothing is due.

```bash
# A 30-day rotation policy for project 5, warning 7 days out:
keyorix rotation create --name db-creds-30d --scope project --project-id 5 \
  --interval-days 30 --alert-days-before 7

# What needs rotating now?
keyorix rotation status
```

### Access Review Commands

Periodic access recertification (ISO 27001 A.5.18 / SOC 2 CC6.2–6.3): review who
can reach a project's secrets via an assigned role. Requires `roles.read` at the
project scope.

- `keyorix access-review --project-id N` (aliases `recert`) — lists every grant of
  access to project N's secrets: role-based standing access (the role granting it +
  the highest secrets action) and per-secret grants (ownership and direct/group
  shares). The `SOURCE` column says which mechanism conferred each grant.

Close the recertification loop by acting on each grant — every decision is audited
(`access_review.attested` / `access_review.revoked`):

- `keyorix access-review attest --project-id N --source <role|direct_share|group_share>
  --principal-id P [--role-id R | --secret-id S]` — certify a grant was reviewed and
  intentionally kept (audit-only, the evidence of recertification; changes no
  access). Requires `roles.read`.
- `keyorix access-review revoke --project-id N --source <role|direct_share|group_share>
  --principal-id P [--role-id R | --secret-id S] [--environment-id E]
  [--principal-type user|group]` — remove the grant: a project-scoped role
  assignment (`--source role --role-id R`) or a secret share (`--source
  direct_share|group_share --secret-id S`). Ownership cannot be revoked here.
  Requires `roles.assign`.

```bash
# Quarterly access review for project 5:
keyorix access-review --project-id 5

# Keep alice's editor role (role 3) — record the attestation:
keyorix access-review attest --project-id 5 --source role --principal-id 42 --role-id 3

# Revoke the devs group's (group 100) editor role at project 5:
keyorix access-review revoke --project-id 5 --source role --principal-type group \
  --principal-id 100 --role-id 3

# Revoke a direct share of secret 500 from user 42:
keyorix access-review revoke --project-id 5 --source direct_share --principal-id 42 --secret-id 500
```

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
export KEYORIX_API_KEY="your-api-key-here"

# Configure with environment variable
keyorix config set-remote --url https://api.example.com --api-key '${KEYORIX_API_KEY}'

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