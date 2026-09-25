# keyorix-k8s-sync Helm chart

Deploys the [Keyorix Kubernetes sync agent](../../../docs/k8s-sync.md): it
materialises selected Keyorix secrets into native Kubernetes Secrets and refreshes
them as the upstream values rotate.

## Install

First create a Secret holding the agent's Keyorix machine-identity token:

```sh
kubectl -n keyorix create secret generic keyorix-token --from-literal=token=<TOKEN>
```

Then install with your mappings — from the published OCI chart:

```sh
helm install kx-sync oci://ghcr.io/keyorixhq/charts/keyorix-k8s-sync --version <release> \
```

…or from this repo checkout:

```sh
helm install kx-sync deploy/helm/keyorix-k8s-sync \
  --namespace keyorix --create-namespace \
  --set keyorix.url=https://keyorix.internal \
  --set keyorix.projectID=42 \
  --set keyorix.tokenSecret.name=keyorix-token \
  --set 'mappings[0].ref=production/db-password' \
  --set 'mappings[0].namespace=app' \
  --set 'mappings[0].name=db-creds' \
  --set 'mappings[0].key=DB_PASSWORD' \
  --set 'targetNamespaces={app}'
```

## Values

| Key | Description |
| --- | --- |
| `keyorix.url` | Keyorix server base URL (**required**) |
| `keyorix.projectID` | Numeric id of the Keyorix project the token's machine identity belongs to (**required**) — every `mappings[].ref` names only an environment and secret, never a project, since environment names are unique per-project, not globally |
| `keyorix.interval` | Reconcile cadence (Go duration; default `5m`) |
| `cleanup` | Reap orphaned owned Secrets when a mapping is removed (default `false`) |
| `pruneOnRevoke` | Actually delete/trim a Secret when its upstream Keyorix reference is confirmed gone or access is revoked, instead of leaving the last-known value untouched (default `false` — see [Failure modes](#failure-modes)) |
| `keyorix.tokenSecret.name` | Existing Secret holding the Keyorix token (**required**) |
| `keyorix.tokenSecret.key` | Key within that Secret (default `token`) |
| `mappings` | List of `{ref, namespace, name, key}` — Keyorix secret → Kubernetes Secret key |
| `targetNamespaces` | Namespaces the agent may write Secrets in (RoleBinding per ns); defaults to the release namespace |
| `image.repository` / `image.tag` | Agent image (tag defaults to the chart's appVersion) |
| `serviceAccount.create` / `serviceAccount.name` | ServiceAccount control |
| `resources`, `nodeSelector`, `tolerations`, `affinity`, `podAnnotations` | Standard pod scheduling/resourcing |

## Upgrading: egress NetworkPolicy

`networkPolicy.egress.enabled` (default `true`) makes the agent's OUTBOUND
traffic default-deny — previously it was unrestricted. Read this before your
next `helm upgrade` on an existing install.

**What the default rules allow:** DNS (UDP/TCP 53), plus TCP `443` and TCP
`6443` to ANY destination — by port only, not by destination, since neither
the Kubernetes API server nor `keyorix.url` is a `podSelector`-able target.
This covers the two ports a Kubernetes API server and an https Keyorix server
overwhelmingly listen on.

**Will silently stop working** if your `keyorix.url` or your cluster's API
server listens on a different port — the agent stops reconciling with no
clear error (see Troubleshooting below), just a growing gap since its last
successful sync.

**Add an `extraRules` entry** for a non-standard port — e.g. a Keyorix server
on `:8443`:

```yaml
networkPolicy:
  egress:
    extraRules:
      - ports:
          - protocol: TCP
            port: 8443
```

**To turn egress restriction off entirely:**

```yaml
networkPolicy:
  egress:
    enabled: false
```

> ⚠️ This removes ALL egress restriction on the agent pod — a compromised pod
> can then reach anything the cluster network permits. Prefer `extraRules`
> over disabling this outright.

**Troubleshooting:** an egress `NetworkPolicy` drops packets silently — the
symptom is a **connection timeout**, never "connection refused". If reconciles
stop working right after this upgrade:

```sh
kubectl -n <namespace> describe networkpolicy <release>-keyorix-k8s-sync
```

## Failure modes

- **Keyorix unreachable, or returns a 5xx:** treated as transient. The target
  Secret(s) affected are skipped for that pass — left completely untouched,
  never written with a missing/partial value — and retried at the next pass
  (see "Retry cadence" below for the backoff this now applies on repeated
  failure).
- **A specific secret is deleted upstream, or a token is revoked/expired:**
  detected (Keyorix returns 401/403/404) and counted as `revoked` — visible
  via `/status`'s `revoked` field and the
  `keyorix_k8s_sync_secrets_total{outcome="revoked"}` metric — but by default
  (`pruneOnRevoke: false`) the target Secret's last-known value is left
  completely untouched, not deleted or trimmed. This matters beyond any one
  secret: a revoked or expired agent token reads as the exact same failure on
  *every* mapping's fetch, not just one, so with pruning on by default the
  first reconcile pass after a routine credential rotation would delete or
  trim every Secret the agent manages in one shot. Set `pruneOnRevoke: true`
  to opt into actively reaping a Secret the moment its reference is confirmed
  gone/revoked — see `pruneOnRevoke`'s own values.yaml comment for the
  token-wide-revocation tradeoff before enabling it.
- **Retry cadence:** the agent's default poll interval (`keyorix.interval`,
  5m) applies as long as every pass is clean. After a pass with any failed or
  revoked target, the next pass's delay backs off exponentially (bounded at
  8x the configured interval) with up to ±20% jitter, resetting to the plain
  interval the moment a pass is fully clean again — so a sustained outage or
  revocation doesn't retry at the same cadence as healthy operation
  indefinitely, and multiple agent replicas recovering from a shared outage
  don't all retry in lockstep.

## RBAC

The chart creates a `ClusterRole` (`secrets`: `get`/`list`/`create`/`patch`/`delete`)
and a namespaced `RoleBinding` in each `targetNamespaces` entry — least privilege, no
cluster-wide Secret access. `get`/`patch`/`delete` are further scoped with
`resourceNames` to exactly the Secret names in `mappings`, so the ClusterRole cannot
touch any Secret this release doesn't manage; `create` and `list` cannot be
`resourceNames`-scoped (a Kubernetes RBAC limitation, not an oversight — see the
comment in `templates/rbac.yaml`) and so remain granted on the `secrets` resource type
as a whole. The agent uses Server-Side Apply (field manager `keyorix-sync`), so it
owns the Secret `data` it writes and prunes keys it no longer maps. `list`/`delete`
are exercised only when `cleanup: true` (orphan reaping); see
[docs/k8s-sync.md](../../../docs/k8s-sync.md#orphan-cleanup-cleanup).
