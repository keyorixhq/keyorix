# Keyorix Kubernetes sync agent

`keyorix-k8s-sync` materialises selected Keyorix secrets into native **Kubernetes
Secrets** and keeps them current as the upstream values rotate. Workloads consume the
synced Secret the usual way (env var or mounted file) — they never talk to Keyorix
directly.

It runs **in-cluster** as a small Deployment:

- authenticates to Keyorix with a **machine-identity token** (`KEYORIX_TOKEN`),
- writes Secrets via the Kubernetes API using its mounted **service-account**
  credentials (no `client-go` — a thin REST client, so the image stays tiny),
- reconciles on an interval, creating/updating a target Secret **only when its data
  changes** and never writing a Secret partially if any value fails to fetch.

## Configuration

A YAML file (default `/etc/keyorix/k8s-sync.yaml`, override with `-config` or
`KEYORIX_K8S_SYNC_CONFIG`):

```yaml
keyorix_url: https://keyorix.internal   # the Keyorix server base URL
interval: 5m                            # reconcile interval (Go duration; default 5m)
mappings:
  # Each mapping copies one Keyorix secret into one key of one Kubernetes Secret.
  # Several mappings may target the same Secret with different keys.
  - ref: production/db-password         # "<environment>/<name>" in Keyorix
    namespace: app                      # target Kubernetes namespace
    name: db-creds                      # target Kubernetes Secret name
    key: DB_PASSWORD                    # key within that Secret's data
  - ref: production/api-key
    namespace: app
    name: db-creds
    key: API_KEY
```

The Keyorix auth token is **not** in this file — it is read from the `KEYORIX_TOKEN`
environment variable (mount it from a Kubernetes Secret). Give that token a
least-privilege machine identity that can read only the referenced secrets.

## Kubernetes RBAC

The agent's service account needs to read and write Secrets in each target namespace:

```
verbs:     [get, create, patch]
resources: [secrets]
```

Bind a `Role` with those permissions in every target namespace (or a `ClusterRole`
with namespace-scoped `RoleBinding`s). The agent uses Server-Side Apply with the field
manager `keyorix-sync`, so it owns the `data` it writes and prunes keys it no longer
maps.

## Running

```
keyorix-k8s-sync -config /etc/keyorix/k8s-sync.yaml
```

Logs are counts and target identities only — secret values are never logged.

## Health & probes

The agent serves probe endpoints on `health_port` (default `8080`):

- `GET /healthz` — liveness; always `200` while the process is responsive.
- `GET /readyz` — readiness; `503` until the first reconcile completes, then `200`.
- `GET /status` — JSON of the last pass (counts + timestamp + error count; no values).

The Helm chart wires `/healthz` and `/readyz` as the Deployment's liveness and
readiness probes.

> A Helm chart that deploys the agent with its RBAC and config ships separately
> (`deploy/helm/keyorix-k8s-sync`).
