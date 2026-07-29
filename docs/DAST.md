# DAST Rig — Technical Reference

Dynamic Application Security Testing (DAST) runs continuously against a
dedicated Keyorix instance. Findings are filed automatically as GitHub Issues.

## Infrastructure

| Item | Value |
|------|-------|
| Host | Proxmox VE — `192.168.10.20` |
| Container | LXC 221 — `keyorix-dast` |
| Container IP | `192.168.10.61` |
| Base dir | `/opt/keyorix-dast/` |
| Results | `/opt/keyorix-dast/results/` |
| Cron log | `/opt/keyorix-dast/results/cron.log` |

## Target stack

A dedicated Keyorix instance runs inside Docker on the LXC container, isolated
from any production environment. The `docker-compose.yml` defines two services:

| Service | Image | Role |
|---------|-------|------|
| `postgres` | `postgres:15-alpine` | Keyorix database |
| `keyorix` | Built from `server/Dockerfile` | Keyorix server under test |

The Keyorix server is configured by `/opt/keyorix-dast/keyorix-dast.yaml`:

- HTTP on port `8080`, TLS disabled (scanner talks plain HTTP inside the Docker
  network — no certificate setup needed)
- gRPC disabled (API surface is HTTP-only for DAST purposes)
- Swagger/OpenAPI endpoint enabled (`/openapi.yaml`) so ZAP can discover routes
- Rate limiting disabled (scanner would otherwise hit its own limits)
- Storage encryption enabled; KEK injected via `KEYORIX_DAST_KEK` env var
- Soft-delete retention 30 days

Secrets for the stack live in `/opt/keyorix-dast/.env` (never committed):

```
KEYORIX_DB_PASSWORD     PostgreSQL password  (generate: openssl rand -hex 32)
KEYORIX_DAST_KEK        32-byte hex KEK — generate once, keep forever; losing
                        it makes the postgres data volume undecryptable
KEYORIX_ADMIN_PASSWORD  Bootstrap admin password
KEYORIX_BOOTSTRAP_TOKEN First-boot bootstrap token
```

The admin credentials are seeded on first boot via Keyorix's bootstrap flow and
are idempotent on subsequent restarts.

## Scanner image

A single custom Docker image (`keyorix-scanner:latest`) bundles both scanners:

```
Base:    ghcr.io/zaproxy/zaproxy:stable   (provides zap-api-scan.py,
                                            zap-full-scan.py, and the ZAP daemon)
Added:   Nuclei v3.11.0 binary             (installed into /usr/local/bin/)
         Nuclei templates                   (pre-fetched at image-build time so
                                             scans run air-gapped)
```

Built with `/opt/keyorix-dast/build-scanner.sh`. Rebuild whenever:

- ZAP releases a security fix (pull new base image)
- Nuclei templates need a forced refresh (`-update-templates`)
- `NUCLEI_VERSION` in `Dockerfile.scanner` is bumped

The image is **never pulled at scan time** (`--pull never`) to keep scans
deterministic and avoid network failures mid-scan.

## Scan types and schedule

Three scans run on a fixed cron schedule (`/etc/cron.d/keyorix-dast`,
`CRON_TZ=Europe/Madrid`):

| Scanner | Script | Schedule | What it tests |
|---------|--------|----------|---------------|
| ZAP API scan | `scan-zap.sh` | Mon, Wed, Fri — 04:00 | Every endpoint declared in `/openapi.yaml` (active scan driven by the live spec) |
| ZAP full scan | `scan-zap-full.sh` | Sunday — 04:00 | Entire app surface — spider-crawls the web UI, static assets, and any routes not in the OpenAPI spec |
| Nuclei | `scan-nuclei.sh` | Daily — 06:00 | Template-based checks (auth, JWT, token exposure, SQLi, XSS, SSRF, misconfig) against all OpenAPI paths |

All three scripts use a shared **`flock` lock** (`dast.lock`) so scans never
overlap. A later-scheduled scan waits until the running one finishes before
acquiring the lock.

## Report files

| Scanner | Format | Filename pattern |
|---------|--------|-----------------|
| ZAP API scan | HTML + JSON | `results/zap-<timestamp>.html` / `.json` |
| ZAP full scan | HTML + JSON | `results/zap-full-<timestamp>.html` / `.json` |
| Nuclei | SARIF | `results/nuclei-<timestamp>.sarif` |

Nuclei emits a minimal valid fallback SARIF if it finds nothing, so
`create-issues.sh` always has a parseable file to read.

## GitHub issue creation

`create-issues.sh` runs automatically after every scan. It:

1. Parses the Nuclei SARIF (levels `warning`/`error` → Medium/High) and the ZAP
   JSON (risk codes ≥ 1, i.e. Low and above).
2. For each finding, constructs a title of the form `[DAST] <scanner>/<id>: <name>`.
3. Checks whether an open issue with that exact title already exists in
   `keyorixhq/keyorix` (using `gh issue list --search`). If one exists, skips.
4. Creates a new issue with labels `dast` and `security` if no duplicate is found.

The script is **idempotent** — re-running it after a scan that produced
duplicate findings is safe.

The `GITHUB_TOKEN` is loaded from `/opt/keyorix-dast/.env` or from the `gh`
CLI's stored credentials (`~/.config/gh/`).

## Closing / suppressing findings

When a fix is merged:

```bash
gh issue close <number> --comment "Fixed in PR #XXXX: <one-line explanation>."
```

For findings that will reappear on every scan (e.g. `style-src 'unsafe-inline'`
required by the SPA's CSS-in-JS runtime), close the issue with an explanation
and leave a note in this file under **Known accepted exceptions**.

There is currently no per-URL suppression list in the scan scripts; add one to
`scan-zap.sh` / `scan-zap-full.sh` via ZAP's `-c` config-file option if the
volume of false positives warrants it.

## Running a scan manually

SSH into the LXC container and run any script directly:

```bash
# ZAP API scan (OpenAPI-driven)
bash /opt/keyorix-dast/scan-zap.sh

# ZAP full scan (spider)
bash /opt/keyorix-dast/scan-zap-full.sh

# Nuclei
bash /opt/keyorix-dast/scan-nuclei.sh

# File issues from the most recent reports without re-scanning
bash /opt/keyorix-dast/create-issues.sh
```

All scripts are idempotent and safe to re-run. They will compete for the
`flock` lock, so a manual run will queue behind any cron scan in progress.

## Maintaining the rig

**Update the scanner image** (ZAP base or Nuclei version):

```bash
# Edit NUCLEI_VERSION in Dockerfile.scanner if needed, then:
bash /opt/keyorix-dast/build-scanner.sh
```

**Update the Keyorix binary** (after a release):

```bash
cd /opt/keyorix-dast/src
git pull origin main
docker compose build keyorix
docker compose up -d keyorix
```

**Rotate secrets** (`.env` values):

```bash
# Edit /opt/keyorix-dast/.env, then:
docker compose up -d     # restarts only changed services
```

Do not rotate `KEYORIX_DAST_KEK` unless you also wipe and re-initialise the
postgres volume — the KEK is bound to the encrypted data on disk.

## Known accepted exceptions

| Issue | Finding | Reason |
|-------|---------|--------|
| #1213 (closed) | `CSP: style-src unsafe-inline` | Required by the SPA's CSS-in-JS / Tailwind runtime. `script-src` does not carry `unsafe-inline`, so inline script injection (the primary XSS vector) remains blocked. |
