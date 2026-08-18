# Remote CLI Setup Guide

This guide explains how to configure the Keyorix CLI to work with remote servers, enabling team collaboration and enterprise deployment.

## Overview

The Keyorix CLI supports two storage modes:
- **Local Mode**: Stores secrets in a local SQLite database (default)
- **Remote Mode**: Connects to a remote Keyorix server via HTTP API

Remote Mode (`storage.type: remote`) is a **CLI/client mode only** — it cannot
back a running Keyorix server (`server.http.enabled`/`server.grpc.enabled`
both refuse to boot on it, ADR-083). It is exclusively for the CLI process
itself delegating its storage to a real server it talks to over the API.

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

> **`storage.remote.api_key` should be an admin-tier user credential (a PAT or
> session token)** — the SAME kind of credential `keyorix connect <server>` uses,
> just held by whatever principal you dedicate to running the sync. `storage:
> {type: "remote"}` is a **CLI/client mode only** — it makes the CLI delegate
> its ENTIRE storage backend to the target server over HTTP, including several
> administrative primitives (invitations, access requests, dynamic-secret configs,
> groups, machine identities, and more) that have no ordinary REST route and are
> served only by the target server's `/api/v1/system/*` proxy tree, plus a large
> set of ordinary RBAC-gated routes (role/user/secret lookups, notifications,
> login/MFA proxying, legal holds, RBAC catalogs, ...) that RemoteStorage also
> calls through their normal routes. Most of that surface requires the caller to
> actually hold RBAC permissions at global scope — something only a real user
> credential can do (a machine identity can never be granted a role at global
> scope, only per-project), so a bare machine token is NOT sufficient on its own.
>
> `/api/v1/system/*` specifically (#G79) additionally accepts a node-type
> machine-identity credential as an alternative to holding `system.write` — useful
> if you want the proxy tree itself reachable by a credential with no other RBAC
> permissions at all:
> ```
> keyorix machine create --project <project-name> --name "my-node" --type node
> keyorix machine token issue "my-node" --project <project-name> --name "my-node-token"
> ```
> but that node token by itself will fail every route outside `/system` (403), so
> for full `storage.type: remote` functionality use an admin-tier user credential
> as `api_key`/`KEYORIX_REMOTE_API_KEY`, not the node token alone.

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
  shares). The `SOURCE` column says which mechanism conferred each grant. The
  `LAST-USED` column shows how long ago each **user** last accessed a secret in the
  project (from the audit trail) — `never` or a value marked `stale` (≥90 days)
  flags dormant standing access to prune; groups show `—` (not aggregated).

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

For a **tracked, periodic** recertification (ISO 27001 A.5.18 — review "at planned
intervals"), run a **campaign**: open it to snapshot the current access into
reviewable items, decide each, then close it to freeze the cycle as audit evidence.
Reads need `roles.read`, mutations `roles.assign`.

- `keyorix access-review campaign open --project-id N [--name "…"]` — open a campaign
  (snapshots current access into pending items).
- `keyorix access-review campaign list --project-id N` — campaigns + progress
  (total / pending / attested / revoked).
- `keyorix access-review campaign show --project-id N --campaign-id C` — the campaign
  and each item (snapshot + decision); note the `ITEM` ids for `decide`.
- `keyorix access-review campaign decide --project-id N --campaign-id C --item-id I
  --action attest|revoke [--reason "…"]` — decide one item (revoke removes the grant).
- `keyorix access-review campaign close --project-id N --campaign-id C [--force]` —
  close the campaign (refuses while items are pending unless `--force`).

```bash
# Open the quarterly campaign and list items to review:
keyorix access-review campaign open --project-id 5 --name "Q4 2026 access recertification"
keyorix access-review campaign show --project-id 5 --campaign-id 1

# Keep item 7, revoke item 9, then close once every item is decided:
keyorix access-review campaign decide --project-id 5 --campaign-id 1 --item-id 7 --action attest
keyorix access-review campaign decide --project-id 5 --campaign-id 1 --item-id 9 --action revoke --reason "left team"
keyorix access-review campaign close --project-id 5 --campaign-id 1
```

### Break-Glass Commands

Self-service emergency access (incident response — NIS2/DORA). Must be enabled
server-side (`break_glass` config). Activation is **not** permission-gated — the
controls are the mandatory justification, a loud audit event, an admin alert, and
auto-expiry. `list`/`revoke` are review actions (`roles.read` / `roles.assign`).

- `keyorix break-glass activate --project-id N --justification "…" [--ttl 2h]` —
  immediately self-grant the configured emergency role at project N, time-bound.
- `keyorix break-glass list --project-id N` — the project's activations (an active
  grant past its expiry shows as `expired`).
- `keyorix break-glass revoke --project-id N --activation-id A` — end an active
  grant early.

```bash
# On-call engineer elevates during a production incident:
keyorix break-glass activate --project-id 5 --justification "PROD outage INC-4821" --ttl 2h

# Security reviews emergency access after the incident:
keyorix break-glass list --project-id 5
keyorix break-glass revoke --project-id 5 --activation-id 7
```

### Compliance Commands

A single deployment-wide controls-posture report for auditors (ISO 27001 / SOC 2 /
NIS2 / DORA) — it rolls up the state of the controls Keyorix enforces. Requires
`system.read`.

- `keyorix compliance report` — print the posture: audit-trail integrity (chain
  verified + checkpointed), access-governance coverage (projects reviewed / never
  reviewed, open campaigns + pending items, dormant role grants), rotation hygiene
  (overdue / due-soon), second-factor coverage (% of active users with MFA or a
  passkey), and break-glass usage (active / total activations).

- `keyorix compliance export [--output FILE]` — export a timestamped **evidence
  pack** (the posture plus the records that substantiate it: the audit-chain anchor,
  the access-review campaigns, the break-glass register, and overdue rotations) as
  JSON, to stdout or a file — the artifact an auditor archives.

```bash
# Quarterly controls-posture snapshot:
keyorix compliance report

# Archive the evidence pack for an audit period:
keyorix compliance export --output evidence-2026Q4.json
```

### Legal Hold

A deployment-wide **litigation / investigation hold** (ISO 27001 A.5.34 /
eDiscovery / DORA record-keeping). While a hold is active, the background purge jobs
(retention purge, JIT-expiry sweep, login-attempt prune) are **blocked from
hard-deleting any records**, so data subject to the hold is preserved. Status reads
need `system.read`; placing/lifting needs `system.write`. Placing and lifting are
audited.

- `keyorix legal-hold status` — whether a hold is active (and since when / why).
- `keyorix legal-hold place --reason "…"` — place a hold (blocks all purges).
- `keyorix legal-hold lift` — release the hold (purges resume next tick).

```bash
# Freeze all deletion for an investigation, then release when cleared:
keyorix legal-hold place --reason "litigation hold — case INC-7"
keyorix legal-hold status
keyorix legal-hold lift
```

### Separation-of-Duties Commands

Separation of duties (ISO 27001 A.5.3 / SOX): define **toxic combinations** — two
permissions one principal must not hold together — and find who violates them.
Listing needs `system.read`; creating/deleting policies needs `system.write`.

- `keyorix sod policy list` — the defined policies.
- `keyorix sod policy create --name <n> --permission-a <perm> --permission-b <perm>
  [--description …]` — define a conflicting pair (the two permissions must differ).
- `keyorix sod policy delete --id N` — retire a policy.
- `keyorix sod violations` — principals whose effective permissions include both
  sides of a policy.

```bash
# Approving access and administering secrets shouldn't be the same person:
keyorix sod policy create --name "approve-vs-admin" \
  --permission-a roles.assign --permission-b secrets.delete

# Who currently violates a policy?
keyorix sod violations
```

### Data Classification

Label secrets with their data sensitivity (ISO 27001 A.5.12 / A.5.13) — `public`,
`internal`, `confidential`, or `restricted` (empty = unclassified). The label drives
the compliance classification posture (`keyorix compliance report`). Requires
`secrets.write` at the secret's scope.

- `keyorix secret classify --id N --level confidential` — set (or clear, with an
  empty `--level`) a secret's classification. The label is also accepted as
  `classification` at create time.

```bash
# Mark a production database password as restricted:
keyorix secret classify --id 42 --level restricted
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