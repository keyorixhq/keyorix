# Keyorix

**Lightweight secrets management for teams that can't use SaaS.**

On-premise. Air-gapped ready. Single binary. No Vault admin required.

---

## Why Keyorix?

| | Vault | Doppler | Keyorix |
|---|---|---|---|
| On-premise | Yes | No | Yes |
| Air-gapped | Yes | No | Yes |
| Simple ops | No | Yes | Yes |
| EU company | No | No | Yes |
| Open source | BSL | No | AGPL |
| Single binary | Yes | N/A | Yes |

Vault is powerful but requires a dedicated admin. Doppler is simple but SaaS-only. Keyorix is both simple and runs entirely in your infrastructure.

---

## Quick Start

### Install

    git clone https://github.com/keyorixhq/keyorix
    cd keyorix
    make install

### Start the server

    KEYORIX_DB_PASSWORD=yourpassword go run server/main.go

### Connect the CLI

    keyorix config set-remote --url http://localhost:8080
    keyorix auth login --api-key YOUR_TOKEN

### Create your first secret

    keyorix secret create db-password --value supersecret

### Inject secrets into any app

    keyorix run --env production -- node app.js
    keyorix run --env production -- flask run
    keyorix run --env production -- ./myapp

Secrets are injected as environment variables. db-password becomes DB_PASSWORD.

---

## Migrate from Vault

    # From Vault (Medusa YAML export)
    keyorix secret import --file vault-export.yaml --format vault --env 1

    # From .env files
    keyorix secret import --file .env --format dotenv --env 1

    # Preview before importing
    keyorix secret import --file vault-export.yaml --format vault --env 1 --dry-run

---

## Core Features

**Secrets management**
- Create, read, update, delete secrets with full versioning
- Environment separation: development, staging, production
- Tags and metadata

**Access control**
- Role-based access control (RBAC)
- Group-based permissions
- Service tokens for CI/CD and automation

**Audit and compliance**
- Every access logged: who, what, when, from where
- Two audit layers: audit_events and secret_access_logs
- NIS2 / DORA alignment for European compliance requirements

**Developer experience**
- keyorix run: inject secrets into any process
- keyorix secret import: migrate from Vault, .env files, JSON
- Web UI for teams who prefer a dashboard

---

## Architecture

Single binary. HTTP REST API on port 8080. Web UI on port 3000.
SQLite for development and small teams. PostgreSQL for production.
Air-gapped deployment: copy the binary and run. No internet access required.

---

## Security

- AES-256-GCM encryption for all secret values
- PBKDF2 key derivation
- Secrets never logged or exposed in error messages
- Constant-time token comparison (timing attack prevention)

Security issues: security@keyorix.com

---

## Roadmap

- Kubernetes service account authentication
- keyorix export: backup secrets to file
- Dynamic secrets: credentials generated on-demand with TTL
- MCP server: AI assistant integration
- SDK: Go, Python, Node.js

---

## License

Keyorix is open source under the GNU Affero General Public License v3.
Commercial licensing available for enterprise deployments. Contact: hello@keyorix.com

---

## About

Built by Andrei Beshkov, ex-Microsoft Security PM, based in Valencia, Spain.
Keyorix SL, Valencia, Spain. Your data stays in your infrastructure.
