# Self-Hosting Keyorix

Keyorix runs entirely on your own infrastructure — no cloud dependency, no
outbound telemetry. This guide covers a Docker Compose deployment (web UI + API
server + PostgreSQL), the production concerns that actually matter (encryption
keys, backups, upgrades, TLS), and how to recover.

The stack is three containers:

| Service    | Image                              | Purpose                                  |
|------------|------------------------------------|------------------------------------------|
| `web`      | `ghcr.io/keyorixhq/keyorix-web`    | nginx serving the SPA; reverse-proxies `/api/`, `/auth/`, `/system/` to the API |
| `backend`  | `ghcr.io/keyorixhq/keyorix-server` | the Keyorix API server (Go, single binary) |
| `postgres` | `postgres:15-alpine`               | the encrypted data store                 |

## 1. Prerequisites

- Docker Engine 24+ and the Compose plugin (`docker compose version`).
- A host with at least 1 vCPU / 1 GB RAM for a small team.

## 2. Quick start

```sh
git clone https://github.com/keyorixhq/keyorix.git
cd keyorix
cp .env.example .env
# Edit .env and set strong values (see below). Then:
docker compose up -d
```

Open **http://localhost:8088** and log in with the admin credentials you set in
`.env`. That's it.

> Building from source instead of pulling published images: edit
> `docker-compose.yml` and swap the `backend` service's `image:` for the
> commented-out `build:` block.

## 3. Configuration (`.env`)

All secrets come from `.env` — there are **no baked-in default passwords**; the
stack refuses to start if the required ones are missing. Generate strong values
with `openssl rand -base64 32`.

| Variable                  | Required | Notes |
|---------------------------|----------|-------|
| `KEYORIX_DB_PASSWORD`     | ✅       | PostgreSQL password (shared by `postgres` and `backend`). |
| `KEYORIX_MASTER_PASSWORD` | ✅       | Passphrase the encryption KEK is derived from. **See the warning below.** |
| `KEYORIX_ADMIN_PASSWORD`  | optional | If set, the first admin is created on first boot (idempotent). Leave blank to run `keyorix system init` manually. |
| `KEYORIX_ADMIN_USERNAME`  | optional | Defaults to `admin`. |
| `KEYORIX_ADMIN_EMAIL`     | optional | Defaults to `admin@keyorix.local`. |

Server configuration (storage, encryption paths, ports) lives in
`keyorix.docker.yaml`, mounted read-only into the `backend` container. The full,
annotated reference is `configs/keyorix.yaml.tpl`.

## 4. ⚠️ The master password and encryption keys — read this

Secrets are encrypted with a Data Encryption Key (DEK) that is itself wrapped by
a Key Encryption Key (KEK) **derived from `KEYORIX_MASTER_PASSWORD`**. The wrapped
DEK and the KEK salt live on the `keyorix_keys` Docker volume.

Two ways to permanently lose every stored secret:

1. **Changing `KEYORIX_MASTER_PASSWORD`** after first boot. The KEK no longer
   derives, the DEK can't be unwrapped. (To rotate it intentionally, use
   `keyorix encryption rotate` — see below — never by editing `.env`.)
2. **Losing the `keyorix_keys` volume.** Back it up (next section).

### DEK rotation procedure

To generate a new Data Encryption Key and re-encrypt every secret in the database:

```sh
# 1. Stop the server (rotation acquires an exclusive lock; it refuses if the
#    server process is running and holding the key lock).
docker compose stop keyorix

# 2. Preview what will be re-encrypted — no changes made, no --confirm needed.
docker compose run --rm keyorix keyorix encryption rotate --dry-run

# 3. Perform the rotation.  --confirm is required (acknowledges write-lock).
docker compose run --rm keyorix keyorix encryption rotate --confirm

# 4. Restart the server.
docker compose start keyorix
```

The rotation re-encrypts all secrets, credentials, and session tokens in a
single transaction.  If the server crashes mid-sweep, the orphaned pending key
file is detected and cleaned up automatically on the next `--confirm` run.
Back up the `keyorix_keys` volume after a successful rotation.

Store `KEYORIX_MASTER_PASSWORD` in your own password manager / secret store. It is
not recoverable from the system.

## 5. Backup and restore

A complete backup is **two** things — the database *and* the encryption keys.
Neither alone is sufficient: the DB without the keys is unreadable ciphertext;
the keys without the DB are useless.

**Backup:**

```sh
# 1. Database
docker compose exec -T postgres pg_dump -U keyorix keyorix | gzip > keyorix-db-$(date +%F).sql.gz

# 2. Encryption keys (the keyorix_keys volume)
docker run --rm -v keyorix_keyorix_keys:/keys -v "$PWD":/backup alpine \
  tar czf /backup/keyorix-keys-$(date +%F).tar.gz -C /keys .
```

Also record `KEYORIX_MASTER_PASSWORD` separately (it is required to derive the KEK
that unwraps the backed-up DEK).

**Restore** (into a fresh stack, with the *same* `KEYORIX_MASTER_PASSWORD`):

```sh
docker compose up -d postgres
gunzip -c keyorix-db-YYYY-MM-DD.sql.gz | docker compose exec -T postgres psql -U keyorix keyorix
docker run --rm -v keyorix_keyorix_keys:/keys -v "$PWD":/backup alpine \
  tar xzf /backup/keyorix-keys-YYYY-MM-DD.tar.gz -C /keys
docker compose up -d
```

## 6. Upgrades

```sh
docker compose pull          # fetch newer published images
docker compose up -d         # recreate with the new images
```

Schema migrations run automatically on boot and are additive. **Back up first**
(section 5). To pin a version instead of `latest`, set the image tags in
`docker-compose.yml` to a release tag (e.g. `:v0.3.0`).

## 7. TLS

The default stack serves plain HTTP on `8088`. Two ways to get HTTPS:

**Bundled (recommended) — the `tls` profile.** An optional Caddy front-end that
terminates TLS and proxies to the web container:

```sh
# In .env, set KEYORIX_DOMAIN to your real domain (DNS must point here, and
# ports 80 + 443 must be reachable from the internet for the ACME challenge):
#   KEYORIX_DOMAIN=keyorix.example.com
docker compose --profile tls up -d
```

Caddy automatically provisions and renews a publicly-trusted certificate
(Let's Encrypt / ZeroSSL). Issued certs persist on the `caddy_data` volume so
restarts don't re-request them. For a `localhost` value Caddy uses its internal
CA (browsers warn unless you trust Caddy's root). When running the `tls` profile,
don't also expose web's `8088` publicly — front everything through Caddy on
80/443.

**Your own proxy.** Or terminate TLS at an existing Caddy/Traefik/nginx/LB in
front of the `web` container: point it at `web:80` and forward
`X-Forwarded-Proto: https`.

The single-binary `keyorix-server` also supports TLS directly
(`server.http.tls` in the config) for non-Docker deployments.

## 8. Metrics (Prometheus)

The backend exposes Prometheus metrics at **`GET /metrics`** (unauthenticated by
design — keep it inside your perimeter, don't expose it publicly). It includes Go
runtime + process collectors and per-route HTTP metrics
(`keyorix_http_requests_total`, `keyorix_http_request_duration_seconds`). Point
your own Prometheus at `backend:8080/metrics`.

### Background scheduler health

The periodic jobs (anomaly detection, retention purge, auto-rotation,
certificate-expiry scan, audit checkpoints, …) each export their own health, labelled
by `scheduler`:

| Metric | Type | Meaning |
|--------|------|---------|
| `keyorix_scheduler_runs_total{scheduler,outcome}` | counter | Ticks by outcome: `success`, `failure`, or `skipped`. |
| `keyorix_scheduler_run_duration_seconds{scheduler}` | histogram | Duration of ticks that actually ran (success or failure). |
| `keyorix_scheduler_last_run_timestamp_seconds{scheduler}` | gauge | Unix time of the last tick that ran. |
| `keyorix_scheduler_last_success_timestamp_seconds{scheduler}` | gauge | Unix time of the last **successful** tick. |

`skipped` is normal, not an error: in an HA deployment only one replica holds the
single-writer advisory lock (ADR-039) per tick, so the others skip — and a job can
also stand itself down (e.g. an active legal hold pauses a purge). Alert on a job that
has stopped *succeeding*, e.g.:

```
time() - keyorix_scheduler_last_success_timestamp_seconds{scheduler="auto_rotation"} > 3600
```

or, for a job that has never once succeeded since boot,
`absent(keyorix_scheduler_last_success_timestamp_seconds{scheduler="auto_rotation"})`.
Only enabled schedulers appear; the gauges are absent until a job first runs.

### Notification delivery

Every notification channel (webhook, Slack, Teams, email) exports its delivery health
under a shared `channel` label, so a wedged or failing destination is visible rather
than buried in logs:

| Metric | Type | Meaning |
|--------|------|---------|
| `keyorix_notify_deliveries_total{channel,outcome}` | counter | Deliveries by channel (`webhook`/`slack`/`teams`/`email`) and terminal outcome: `delivered`, `failed` (a permanent error or retries exhausted), or `dropped` (the bounded queue was full). |
| `keyorix_notify_delivery_retries_total{channel}` | counter | Retries made after a transient failure (a 5xx / 429 for HTTP channels, an SMTP/transport error for email). |

Transient failures are retried with exponential backoff; permanent ones (a `4xx`, a bad
address) are not retried. A rising `failed`/`dropped` rate means a destination is
unhealthy or too slow — alert on
`rate(keyorix_notify_deliveries_total{outcome=~"failed|dropped"}[5m]) > 0`.

### SIEM audit forwarding

When SIEM forwarding is enabled, the audit-event forwarder (Splunk HEC / Datadog /
webhook) exports the same delivery health — losing audit events silently is a SOC 2 /
ISO 27001 finding, so a wedged or failing SIEM should page:

| Metric | Type | Meaning |
|--------|------|---------|
| `keyorix_siem_forwards_total{outcome}` | counter | Forwards by terminal outcome: `delivered`, `failed` (a 4xx or retries exhausted), or `dropped` (the bounded queue was full). |
| `keyorix_siem_forward_retries_total` | counter | Forwards retried after a transient (5xx / 429 / transport) failure. |

Transient failures retry with exponential backoff; `4xx` is permanent. Alert on
`rate(keyorix_siem_forwards_total{outcome=~"failed|dropped"}[5m]) > 0` — a SIEM that is
dropping or failing audit events is a compliance gap.

## 9. Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| `KEYORIX_DB_PASSWORD is required` on `up` | No `.env`, or the required vars are blank. `cp .env.example .env` and fill them in. |
| Backend logs `password authentication failed` | The `postgres_data` volume was initialised with a different password. For a *new* install, `docker compose down -v` and start fresh (this wipes data — only for a clean install). |
| Backend can't decrypt secrets after a change | `KEYORIX_MASTER_PASSWORD` changed or the `keyorix_keys` volume was lost. Restore both from backup (section 5). |
| Login returns 404 | Reverse proxy not forwarding `/auth/` — Keyorix serves login at the root path, not under `/api/`. The bundled `web` image already handles this. |

## 10. Single-binary / air-gapped deployment

For environments where Docker isn't available, `keyorix-server` is a single Go
binary that runs against any PostgreSQL with `KEYORIX_MASTER_PASSWORD` +
`KEYORIX_DB_PASSWORD` set — and it can serve the **web dashboard from the binary
itself**, so the whole product is one file plus a database. No web container, no
nginx.

```sh
make build-ui      # builds web/ (the dashboard, ADR-070) and embeds it into
                   # bin/keyorix-server
KEYORIX_MASTER_PASSWORD=… KEYORIX_DB_PASSWORD=… ./bin/keyorix-server
```

Copy `keyorix-server` to the target host, point it at PostgreSQL, and the API +
UI are served on one port (default 8080). Set TLS directly via `server.http.tls`
in the config for HTTPS without a proxy.

`make build` (without the UI) produces an API-only binary that serves a small
placeholder page in place of the dashboard — use `make build-ui` for the full
single-file deployment.
