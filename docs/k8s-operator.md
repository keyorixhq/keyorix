# Keyorix Kubernetes operator

The Keyorix operator reconciles **`KeyorixSecret`** custom resources into native
Kubernetes Secrets and keeps them current as upstream values rotate. It is the
`kubectl apply`-able, per-object-status delivery model — an alternative to the
[sync agent](k8s-sync.md) and the [External Secrets Operator](k8s-eso.md) integration.

| | Operator (this page) | [sync agent](k8s-sync.md) | [ESO](k8s-eso.md) |
|---|---|---|---|
| API | `KeyorixSecret` CRD | Agent config (Helm values) | `ExternalSecret` CRD |
| Reference by | `project/environment/name` | `environment/name` | `project/environment/name` |
| Per-object status | ✅ `Ready` condition | ✗ (one agent status) | ✅ |
| Orphan cleanup | Owner-reference GC | `cleanup: true` (ADR-057) | `creationPolicy: Owner` |
| Best when | You want a native CR | A self-contained agent | You standardise on ESO |

All three read over the same authorized Keyorix API (scoped `secrets.read`, `max_reads`,
suspension, audit) and never log values.

## How it works

For each `KeyorixSecret`, the controller reads the machine-identity token from the
referenced Secret, fetches each value through the by-reference read endpoint
(`GET /api/v1/secrets/value?ref=…`, ADR-059), and creates/updates the target Secret —
**owned by the `KeyorixSecret`**, so deleting the CR garbage-collects the Secret. It then
sets a `Ready` condition and requeues after `refreshInterval`. A fetch failure never
writes a partial Secret; it records `Ready=False`/`SyncError` and backs off.

## Install

The operator ships as a Helm chart that installs the CRD, controller, ServiceAccount, and
RBAC:

```sh
helm install keyorix-operator deploy/helm/keyorix-operator \
  -n keyorix-system --create-namespace
kubectl -n keyorix-system rollout status deploy/keyorix-operator-keyorix-operator
```

For HA, run multiple replicas with leader election (only one is active):

```sh
helm upgrade keyorix-operator deploy/helm/keyorix-operator -n keyorix-system \
  --set replicas=2 --set leaderElection=true
```

### Choosing a namespace scope (ADR-076)

**By default, a single operator instance watches `KeyorixSecret` CRs in its own release
namespace only** — its RBAC (a `Role`/`RoleBinding` pair) is scoped accordingly, and the
manager itself defaults to the same namespace (read from `POD_NAMESPACE`, set via the
Downward API). This is the least-privilege choice: an unmodified `helm install` never
grants the operator access to Secrets outside the namespace you installed it into.

Two opt-in modes cover broader deployments, both resolved from the same two values so they
can never disagree with each other (`_helpers.tpl`'s `kxop.scope` — see the chart's
[README](../deploy/helm/keyorix-operator/README.md#rbac) for the underlying mechanism):

- **Bounded multi-namespace** — one operator instance managing a known, fixed set of
  namespaces (e.g. all of one team's tenants). Set `watchNamespaces`:

  ```sh
  helm install keyorix-operator-team-a deploy/helm/keyorix-operator -n team-a \
    --set 'watchNamespaces={team-a,team-b}'
  ```

  RBAC is bound via a namespace-scoped `RoleBinding` in each listed namespace; the manager
  watches exactly those namespaces.

- **Cluster-wide** — one operator instance managing `KeyorixSecret` CRs in *every*
  namespace, with no static list. Set `rbac.clusterScoped: true` explicitly:

  ```sh
  helm install keyorix-operator deploy/helm/keyorix-operator -n keyorix-system \
    --create-namespace --set rbac.clusterScoped=true
  ```

  RBAC is bound via a cluster-wide `ClusterRoleBinding` — this is now the **only** way to
  get that grant; it is no longer the default. `watchNamespaces` and
  `rbac.clusterScoped: true` are mutually exclusive — setting both makes the chart refuse
  to render (`helm template`/`helm install` fails with an error naming both values), rather
  than silently picking one.

**Upgrading from a chart version older than this default change?** Two scenarios:

- **You relied on the old cluster-wide default (neither value set).** Add
  `--set rbac.clusterScoped=true` to your `helm upgrade` to preserve that behavior across
  the upgrade. Without it, the operator narrows to its own release namespace only, which
  may stop it from reconciling `KeyorixSecret` CRs in other namespaces it previously
  watched.
- **You already set `watchNamespaces`.** `rbac.clusterScoped` defaulted to `true` before
  this release, and a plain `helm upgrade` (without `--reset-values`) carries forward a
  release's previously-recorded values by default — so your install is very likely already
  in the now-rejected combination (`rbac.clusterScoped=true` + `watchNamespaces` set). The
  upgrade will refuse to render at all, with an error containing:
  `rbac.clusterScoped=true and watchNamespaces=[...] are both set -- these are mutually
  exclusive (ADR-076)`. This is a hard block on the upgrade itself, not a permissions
  change — add `--set rbac.clusterScoped=false` explicitly to your `helm upgrade` (or the
  equivalent in your values file) to clear it.

See the CHANGELOG's `BREAKING` entry for this release for the full detail.

For an air-gapped install that mirrors the operator image to a private, authenticated
registry, set `image.repository` to the mirror and `imagePullSecrets` to a
`docker-registry` Secret in the release namespace — see the chart's
[README](../deploy/helm/keyorix-operator/README.md#private-registries).

## Usage

1. Create a least-privilege machine-identity token (ADR-030) Secret in your app
   namespace — give the identity `secrets.read` only for the secrets it will sync:

   ```sh
   kubectl -n app create secret generic keyorix-token \
     --from-literal=token="$KEYORIX_MACHINE_TOKEN"
   ```

2. Apply a `KeyorixSecret` (see
   [`examples/keyorixsecret.yaml`](../deploy/helm/keyorix-operator/examples/keyorixsecret.yaml)):

   ```yaml
   apiVersion: secrets.keyorix.io/v1alpha1
   kind: KeyorixSecret
   metadata:
     name: db-creds
     namespace: app
   spec:
     server: https://keyorix.internal
     tokenSecretRef: { name: keyorix-token, key: token }
     refreshInterval: 5m
     target: { name: db-creds, type: Opaque }
     data:
       - secretKey: DB_PASSWORD
         ref: app/production/db-password   # project/environment/name
       - secretKey: API_KEY
         ref: app/production/api-key
   ```

3. Watch it reconcile and consume the Secret as usual:

   ```sh
   kubectl get keyorixsecret -n app          # READY=True, LAST SYNC=…
   kubectl get secret db-creds -n app
   ```

   ```yaml
   envFrom:
     - secretRef: { name: db-creds }
   ```

Deleting the `KeyorixSecret` removes the `db-creds` Secret it created (owner reference).

## Spec reference

| Field | Description |
|---|---|
| `spec.server` | Keyorix base URL (`https://…`). |
| `spec.tokenSecretRef.name` / `.key` | Secret holding the machine token (`key` defaults to `token`). |
| `spec.refreshInterval` | Re-read cadence (default `5m`). |
| `spec.target.name` / `.type` | Target Secret name (defaults to the CR name) and type (default `Opaque`). |
| `spec.data[].secretKey` | Key to set in the target Secret. |
| `spec.data[].ref` | Keyorix `project/environment/name` reference to read. |

## Status & observability

- `status.conditions[Ready]` — `True` when the target Secret is up to date; `False` with
  reason `SyncError` and the cause in the message on failure.
- `status.lastSyncTime`, `status.syncedHash`, `status.observedGeneration`.
- The manager serves Prometheus metrics on `:8080/metrics` and health probes on
  `:8081/healthz`,`/readyz` (the chart wires both).

## Security

- **Least-privilege token per KeyorixSecret.** Each resource names its own token Secret;
  scope the identity to exactly the secrets it syncs.
- **Token stays in a Secret.** It is read from `tokenSecretRef`, never inlined in the CR.
- **Keyorix-side controls apply.** Every read goes through scoped `secrets.read`,
  `max_reads`, suspension, and audit — avoid pointing the operator at a tight `max_reads`
  secret, since each refresh counts as a read.
- The controller image is a distroless non-root static binary with a read-only root
  filesystem and all capabilities dropped.

## Uninstalling

`helm uninstall` removes the controller and RBAC. Helm does not delete CRDs it installed;
remove the type explicitly when you want it gone (this also deletes every `KeyorixSecret`
and the Secrets they own):

```sh
kubectl delete crd keyorixsecrets.secrets.keyorix.io
```
