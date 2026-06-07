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
   `keyorix encryption rotate` — see ADR-010 — never by editing `.env`.)
2. **Losing the `keyorix_keys` volume.** Back it up (next section).

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

The stack serves plain HTTP on `8088` by design — terminate TLS at a reverse
proxy in front of the `web` container (Caddy, Traefik, nginx, or your cloud load
balancer). Point it at `web:80` and forward `X-Forwarded-Proto: https`. Do not
expose `8088` directly to the internet.

## 8. Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| `KEYORIX_DB_PASSWORD is required` on `up` | No `.env`, or the required vars are blank. `cp .env.example .env` and fill them in. |
| Backend logs `password authentication failed` | The `postgres_data` volume was initialised with a different password. For a *new* install, `docker compose down -v` and start fresh (this wipes data — only for a clean install). |
| Backend can't decrypt secrets after a change | `KEYORIX_MASTER_PASSWORD` changed or the `keyorix_keys` volume was lost. Restore both from backup (section 5). |
| Login returns 404 | Reverse proxy not forwarding `/auth/` — Keyorix serves login at the root path, not under `/api/`. The bundled `web` image already handles this. |

## 9. Single-binary / air-gapped deployment

For environments where Docker isn't available, `keyorix-server` is a single Go
binary (`make build` → `keyorix-server`) that runs against any PostgreSQL with
`KEYORIX_MASTER_PASSWORD` + `KEYORIX_DB_PASSWORD` set. Serving the bundled web UI
from the binary is on the roadmap; today the web UI ships as the `web` container.
