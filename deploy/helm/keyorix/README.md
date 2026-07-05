# Keyorix Helm chart

Deploy the self-hosted [Keyorix](https://github.com/keyorixhq/keyorix) secrets
manager — API server + web UI + PostgreSQL — to Kubernetes. It mirrors the
docker-compose stack: a single-instance server holding the encryption keys on a
persistent volume, the web UI proxying to it, and a bundled (or external) Postgres.

## Quick start

From a published release (the chart is pushed to GHCR as an OCI artifact on each
`vX.Y.Z` tag):

```sh
helm install keyorix oci://ghcr.io/keyorixhq/charts/keyorix \
  --set auth.masterPassword='change-me-and-keep-it' \
  --set postgresql.auth.password='a-strong-db-password' \
  --set auth.adminPassword='Admin123!'
```

Or from a source checkout, swap the chart reference for `./deploy/helm/keyorix`.

Then follow the printed NOTES (port-forward the web service and log in). After
install you can smoke-test the deployment:

```sh
helm test keyorix
```

> ⚠️ **`auth.masterPassword` derives the encryption KEK.** Set it once and keep it
> — changing it, or losing the server's keys PVC, makes every stored secret
> undecryptable. For production, supply it via `auth.existingSecret` and back up
> the `*-server-keys` PVC.

## Key values

| Value | Default | Notes |
|-------|---------|-------|
| `auth.masterPassword` | — | **Required** (or `auth.existingSecret`). KEK passphrase. |
| `auth.existingSecret` | — | Bring your own Secret (`KEYORIX_MASTER_PASSWORD`, `KEYORIX_DB_PASSWORD`, opt. `KEYORIX_ADMIN_PASSWORD`). |
| `auth.adminPassword` | — | Optional first-boot admin bootstrap (idempotent). |
| `server.image.tag` | chart `appVersion` | Server image tag (empty pins to the chart's own `appVersion`; `server.image.digest` takes precedence if set). |
| `web.image.tag` | chart `appVersion` | Web UI image tag (same default/precedence as `server.image.tag`). |
| `server.keysPersistence.*` | 1Gi RWO | The encryption-keys PVC (`resource-policy: keep`). |
| `web.enabled` | `true` | Deploy the UI (with a k8s-adapted nginx that proxies to the server Service). |
| `ingress.*` | disabled | Ingress for the web UI. |
| `postgresql.enabled` | `true` | Bundled Postgres for evaluation. |
| `postgresql.auth.password` | — | Required when bundled DB is enabled. |
| `externalDatabase.*` | — | Used when `postgresql.enabled=false` (managed/HA Postgres). |

## Production notes

- **External database:** set `postgresql.enabled=false` and `externalDatabase.host`
  (+ `externalDatabase.password` via `auth.existingSecret`), pointing at a managed
  or HA PostgreSQL. The bundled Postgres is single-instance, for evaluation.
- **Single server instance:** the server is pinned to 1 replica — it owns the
  ReadWriteOnce keys volume and a per-instance KEK; it is not horizontally scalable.
- **Backups:** back up both the database and the `*-server-keys` PVC. You need
  both (plus the master password) to recover.
- **TLS:** terminate at the ingress (`ingress.tls` + cert-manager annotations).
