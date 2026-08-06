# Keyorix Kubernetes sync agent

`keyorix-k8s-sync` materialises selected Keyorix secrets into native **Kubernetes
Secrets** and keeps them current as the upstream values rotate. Workloads consume the
synced Secret the usual way (env var or mounted file) — they never talk to Keyorix
directly.

> Prefer the [External Secrets Operator](k8s-eso.md)? Keyorix also works as an ESO
> Webhook provider — no agent to run if you already operate ESO.

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
project_id: 42                          # the Keyorix project the token's machine identity belongs to
interval: 5m                            # reconcile interval (Go duration; default 5m)
cleanup: false                          # reap orphaned owned Secrets (see below; default off)
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

`project_id` is required: a mapping's `ref` names only an environment and a secret
(`<environment>/<name>`), never a project, because environment names are unique
per-project, not globally — two different projects can each have a `production`
environment. `project_id` pins every secret lookup this agent performs to the one
project its token belongs to (a machine identity, and so its tokens, always belongs to
exactly one project), so a same-named secret in a *different* project can never be
resolved instead of the intended one.

## Kubernetes RBAC

The agent's service account needs to read and write Secrets in each target namespace:

```
verbs:     [get, list, create, patch, delete]
resources: [secrets]
```

`list` and `delete` are used **only** by orphan cleanup (below); with `cleanup` off the
agent exercises just `get`, `create`, and `patch`. Bind a `Role` with these permissions
in every target namespace (or a `ClusterRole` with namespace-scoped `RoleBinding`s). The
Helm chart further restricts `get`/`patch`/`delete` with `resourceNames` to exactly the
Secret names in `mappings` — `create` and `list` can't be `resourceNames`-scoped (a
Kubernetes RBAC limitation: those verbs don't target a single named object), so they
remain granted on the `secrets` resource type as a whole. The agent uses Server-Side
Apply with the field manager `keyorix-sync`, so it owns the `data` it writes and prunes
keys it no longer maps.

## Orphan cleanup (`cleanup`)

Removing a *key* from a target Secret is handled automatically: the agent owns the
Secret's `data` via Server-Side Apply, so a no-longer-mapped key is pruned on the next
pass. But removing **every** mapping for a target leaves the whole Secret behind — the
agent simply stops reconciling it, and its now-stale values linger forever.

Set `cleanup: true` (or pass `-cleanup`) to reap these orphans. Every Secret the agent
creates is stamped `app.kubernetes.io/managed-by: keyorix-sync`; after the apply phase,
cleanup lists Secrets carrying that label in each namespace the config still references
and **deletes those whose target is no longer mapped**. It is deliberately conservative:

- **Label-scoped** — it only ever lists and deletes Secrets carrying the managed-by
  label, so Secrets created by an operator or another tool are never touched.
- **Config-scoped** — it only scans namespaces still present in the config. Dropping a
  namespace from the config entirely leaves its Secrets unreaped (remove the mappings
  first, let one pass reap, then drop the namespace).
- **Fail-safe on upstream errors** — a target still in the config is kept even if its
  Keyorix fetch failed this pass, so a transient 404 can never delete a live Secret. A
  ref deleted *in Keyorix* (while its mapping remains) fails that target closed and
  leaves the existing Secret in place; remove the mapping to retire it.
- **Off by default** — deleting Secrets is destructive, so cleanup must be opted into.

> Cleanup assumes a **single sync agent owns each managed namespace**. Do not point two
> agents with different mapping sets at the same namespace with cleanup on — each would
> treat the other's Secrets as orphans. Use `-cleanup -dry-run -once` to preview what
> would be deleted before enabling it for real.

## Running

```
keyorix-k8s-sync -config /etc/keyorix/k8s-sync.yaml
```

Logs are counts and target identities only — secret values are never logged.

### Flags

- `-once` — run a single reconcile pass and exit (no health server / loop). Exits
  non-zero if any target failed, so it works as a CI gate or a Kubernetes `Job`.
- `-dry-run` — report what *would* change (created/updated/unchanged/deleted counts)
  without writing any Secret. Combine with `-once` to validate config and preview a sync.
- `-cleanup` — delete orphaned owned Secrets whose mapping was removed (see *Orphan
  cleanup*). Equivalent to `cleanup: true` in the config; combine with `-dry-run` to
  preview deletions.

```
keyorix-k8s-sync -config ./k8s-sync.yaml -once -dry-run
```

## Health & probes

The agent serves probe endpoints on `health_port` (default `8080`):

- `GET /healthz` — liveness; always `200` while the process is responsive.
- `GET /readyz` — readiness; `503` until the first reconcile completes, then `200`.
- `GET /status` — JSON of the last pass (counts + timestamp + error count; no values).
- `GET /metrics` — Prometheus metrics: `keyorix_k8s_sync_reconcile_passes_total`,
  `keyorix_k8s_sync_secrets_total{outcome=…}` (`created`/`updated`/`unchanged`/`failed`/`deleted`),
  `keyorix_k8s_sync_last_run_timestamp_seconds`, and `keyorix_k8s_sync_last_failed`. The
  chart adds `prometheus.io/scrape` pod annotations.

The Helm chart wires `/healthz` and `/readyz` as the Deployment's liveness and
readiness probes.

> A Helm chart that deploys the agent with its RBAC and config ships separately
> (`deploy/helm/keyorix-k8s-sync`).
