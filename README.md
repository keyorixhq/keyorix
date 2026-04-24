# Keyorix

**Lightweight secrets management for teams that can't use SaaS.**

On-premise. Air-gapped ready. Single binary. No Vault admin required.

---

## Why Keyorix?

| | Vault | Doppler | Keyorix |
|---|---|---|---|
| On-premise | Yes | No | **Yes** |
| Air-gapped | Yes | No | **Yes** |
| Simple ops | No | Yes | **Yes** |
| EU company | No | No | **Yes** |
| Open source | BSL | No | **AGPL** |
| Single binary | Yes | N/A | **Yes** |

Vault is powerful but requires a dedicated admin. Doppler is simple but SaaS-only. Keyorix is both simple and runs entirely in your infrastructure.

---

## Install

```bash
curl -L https://raw.githubusercontent.com/keyorixhq/keyorix/main/install.sh | sh
```

Or build from source:

```bash
git clone https://github.com/keyorixhq/keyorix
cd keyorix && make install
```

---

## Quick Start

**Start the server:**

```bash
KEYORIX_MASTER_PASSWORD=yourpassword keyorix-server
```

**Connect the CLI:**

```bash
keyorix connect http://localhost:8080 --username admin --password yourpassword
```

**Create and use secrets:**

```bash
keyorix secret create --name db-password --value supersecret
keyorix run --env production -- node app.js
keyorix run --env production -- flask run
keyorix run --env production -- ./myapp
```

Secrets are injected as environment variables. `db-password` becomes `DB_PASSWORD`.

---

## Migrate from Vault

```bash
# From Vault (Medusa YAML export)
keyorix secret import --file vault-export.yaml --format vault --env 1

# From .env files
keyorix secret import --file .env --format dotenv --env 1

# Preview before importing
keyorix secret import --file vault-export.yaml --format vault --env 1 --dry-run
```

---

## SDKs

Fetch secrets directly from your application at startup. Zero hardcoded credentials.

**Go**
```bash
go get github.com/keyorixhq/keyorix-go
```
```go
token, _ := keyorix.Login(ctx, "http://your-server:8080", "admin", "password")
client := keyorix.New("http://your-server:8080", token)
dbPassword, _ := client.GetSecret(ctx, "db-password", "production")
```

**Python**
```bash
pip install keyorix
```
```python
token = keyorix.login("http://your-server:8080", "admin", "password")
client = keyorix.Client("http://your-server:8080", token)
db_password = client.get_secret("db-password", "production")
```

**Node.js**
```bash
npm install keyorix
```
```javascript
const token = await keyorix.login("http://your-server:8080", "admin", "password");
const client = new keyorix.Client("http://your-server:8080", token);
const dbPassword = await client.getSecret("db-password", "production");
```

See [example apps](https://github.com/keyorixhq/keyorix-go/tree/main/examples/petstore) for full working demos with Docker Compose.

---

## Core Features

**Secrets management**
- Create, read, update, delete secrets with full versioning
- Environment separation: development, staging, production
- Secret sharing between users and groups

**Access control**
- Role-based access control (RBAC)
- Group-based permissions
- Service tokens for CI/CD and automation

**Audit and compliance**
- Every access logged: who, what, when, from where
- Two audit layers: `audit_events` and `secret_access_logs`
- NIS2 / DORA alignment for European compliance requirements
- Dashboard expiry alerts for secrets approaching rotation deadlines

**Developer experience**
- `keyorix run` — inject secrets into any process
- `keyorix secret import` — migrate from Vault, .env files, JSON
- `keyorix connect` — single command server authentication
- Web dashboard for teams who prefer a UI

---

## Architecture

Single binary. HTTP REST API on port 8080. Web UI on port 3000.

SQLite for development and small teams. PostgreSQL for production.

Air-gapped deployment: copy the binary and run. No internet required.

---

## Security

- AES-256-GCM encryption for all secret values
- Envelope encryption: passphrase → PBKDF2 → KEK (memory only) → wrapped DEK
- Constant-time token comparison (timing attack prevention)
- Secrets never logged or exposed in error messages

Security issues: security@keyorix.com

---

## Roadmap

- Kubernetes service account authentication
- Dynamic secrets — credentials generated on-demand with TTL
- MCP server — AI assistant integration
- Java SDK
- Access anomaly detection (NIS2 incident detection)

---

## License

AGPL-3.0. Commercial licensing available for enterprise deployments.

Contact: hello@keyorix.com

---

## About

Built by Andrei Beshkov, ex-Microsoft Security PM, Valencia, Spain.

Keyorix SL — your data stays in your infrastructure.
