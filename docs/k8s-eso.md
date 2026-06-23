# Keyorix with the External Secrets Operator (ESO)

The [External Secrets Operator](https://external-secrets.io/) (ESO) is the de-facto
standard for materialising secrets from an external system into native Kubernetes
Secrets. Many platform teams already run it and prefer it over per-vendor agents. Keyorix
plugs into ESO through its built-in **generic Webhook provider** — no custom controller
to install, no code running in your cluster beyond ESO itself.

This is an alternative to the [Keyorix Kubernetes sync agent](k8s-sync.md). Use whichever
fits:

| | ESO Webhook (this page) | [keyorix-k8s-sync agent](k8s-sync.md) |
|---|---|---|
| Runs | ESO you already operate | A small Keyorix Deployment |
| Config object | `ExternalSecret` (CRD) | Agent config (YAML/Helm values) |
| Reference by | `project/environment/name` | `environment/name` |
| Orphan cleanup | ESO `creationPolicy: Owner` | `cleanup: true` (ADR-057) |
| Best when | You standardise on ESO | You want a self-contained agent |

Both read over the same authenticated Keyorix API and never expose values in logs.

## How it works

For each requested key, ESO makes a single authenticated `GET` to Keyorix's secret-read
endpoint and extracts the value with a JSONPath. Keyorix enforces exactly the same
controls as for any other API caller: the machine identity's scoped `secrets.read`
permission, `max_reads` limits, secret suspension, and a full audit-log entry per read.

```
ExternalSecret ──► ESO ──GET /api/v1/secrets/value?ref=project/environment/name──► Keyorix
                    │         Authorization: Bearer <machine token>
                    └──► writes native Kubernetes Secret ──► your workload
```

## Prerequisites

1. **ESO installed** in the cluster (e.g. `helm install external-secrets
   external-secrets/external-secrets -n external-secrets --create-namespace`).
2. A **Keyorix machine-identity token** (ADR-030) whose identity holds `secrets.read`
   *only* for the secrets ESO is allowed to sync — least privilege. Create one with
   `keyorix machine create …`.
3. Network reachability from ESO pods to the Keyorix server, and — if Keyorix serves a
   private/internal TLS certificate — its **CA bundle**.

## Install

All example manifests live in [`deploy/eso/`](../deploy/eso/).

### 1. Store the token (and CA)

Create the token Secret in the namespace your `ClusterSecretStore` will reference (the
examples use `external-secrets`). Never commit a real token:

```sh
kubectl -n external-secrets create secret generic keyorix-machine-token \
  --from-literal=token="$KEYORIX_MACHINE_TOKEN"

# Only if Keyorix uses a private CA:
kubectl -n external-secrets create secret generic keyorix-ca \
  --from-file=ca.crt=./keyorix-ca.pem
```

See [`token-secret.example.yaml`](../deploy/eso/token-secret.example.yaml) for the shape.

### 2. Create the SecretStore

Apply [`cluster-secret-store.yaml`](../deploy/eso/cluster-secret-store.yaml) — a
`ClusterSecretStore` that serves every namespace. (For a single-namespace, lower-trust
setup use a namespaced `SecretStore` instead; the `provider.webhook` block is identical
but the token `secretRef` then needs no `namespace`.)

Edit `url` to your Keyorix base URL. The store injects the token from the Secret above:

```yaml
provider:
  webhook:
    url: "https://keyorix.internal/api/v1/secrets/value?ref={{ .remoteRef.key }}"
    headers:
      Accept: "application/json"
      Authorization: "Bearer {{ .keyorixToken }}"
    result:
      jsonPath: "$.data.value"   # Keyorix wraps as {"data":{"value":…}}
    secrets:
      - name: keyorixToken
        secretRef: { name: keyorix-machine-token, key: token, namespace: external-secrets }
```

`remoteRef.key` is a `project/environment/name` reference (ADR-059). If you prefer to
reference by numeric secret ID, point `url` at
`…/api/v1/secrets/{{ .remoteRef.key }}?include_value=true` instead and use the ID as the
key — both resolve through the same authorized, audited read path.

Confirm it is ready:

```sh
kubectl get clustersecretstore keyorix
# READY should be True
```

## Syncing secrets

Create an `ExternalSecret` (see [`external-secret.yaml`](../deploy/eso/external-secret.yaml))
in the namespace that needs the Secret. `remoteRef.key` is a Keyorix
**`project/environment/name`** reference:

```yaml
spec:
  refreshInterval: 5m
  secretStoreRef: { name: keyorix, kind: ClusterSecretStore }
  target:
    name: db-creds
    creationPolicy: Owner   # ESO owns the Secret and prunes keys it stops mapping
  data:
    - secretKey: DB_PASSWORD
      remoteRef: { key: "app/production/db-password" }
    - secretKey: API_KEY
      remoteRef: { key: "app/production/api-key" }
```

ESO creates the `db-creds` Secret and refreshes it every `refreshInterval`, picking up
rotations from Keyorix. Verify:

```sh
kubectl get externalsecret db-creds -n app   # SYNCED=True, READY=True
kubectl get secret db-creds -n app
```

## Using the synced Secret

The resulting Secret is an ordinary Kubernetes Secret. Mount it or expose it as env vars:

```yaml
envFrom:
  - secretRef: { name: db-creds }
```

## Security

- **Least-privilege token.** Scope the machine identity to `secrets.read` on exactly the
  secrets ESO syncs — nothing more. A leaked store token can read only those.
- **Token never leaves a Secret.** It is injected via `secrets[].secretRef`, not inlined
  in the store. Restrict RBAC on the token Secret's namespace.
- **TLS.** Always use `https` and pin Keyorix's CA via `caProvider` when it isn't
  publicly trusted, so ESO won't talk to an impostor endpoint.
- **Keyorix-side controls still apply.** Every ESO read is subject to the identity's
  scoped permission, `max_reads`, suspension, and audit logging — an ESO read is not a
  bypass. Avoid pointing ESO at secrets with a tight `max_reads`, since each refresh
  counts as a read.
- **Blast radius.** A `ClusterSecretStore` is cluster-wide; prefer namespaced
  `SecretStore`s when teams should not share one identity.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `SecretStore` not `Ready` | Token Secret missing or wrong `namespace` in `secretRef`. |
| `ExternalSecret` `SecretSyncedError`, 401/403 | Token invalid, or its identity lacks `secrets.read` for that secret. |
| 404 from the webhook | Wrong `remoteRef.key` (no such `project/environment/name`) or wrong `url`. |
| 400 from the webhook | `remoteRef.key` is not a three-part `project/environment/name` reference. |
| `x509: certificate signed by unknown authority` | Missing/incorrect `caProvider` CA bundle. |
| Empty value written | `result.jsonPath` not `$.data.value`, or `include_value=true` dropped from the URL. |

Inspect status with `kubectl describe externalsecret <name> -n <ns>` and the ESO
controller logs. Keyorix's audit log records each read (actor = the machine identity).

## Uninstalling

Delete the `ExternalSecret`s, then the `ClusterSecretStore`, then the token/CA Secrets.
With `creationPolicy: Owner`, deleting an `ExternalSecret` also removes the Secret it
created.

## Limitations

- The Webhook provider is **read-only** (ESO `GetSecret`/`GetSecretMap`). Writing back to
  Keyorix (PushSecret) is not supported.
