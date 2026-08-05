# keyorix-operator Helm chart

Deploys the Keyorix Kubernetes **operator** — a controller that reconciles
`KeyorixSecret` custom resources into native Kubernetes Secrets and keeps them current as
upstream values rotate. See [docs/k8s-operator.md](../../../docs/k8s-operator.md).

The chart installs the `KeyorixSecret` CRD (from `crds/`), the controller Deployment, its
ServiceAccount, and RBAC. Each `KeyorixSecret` names its own Keyorix server and a
machine-identity token Secret, so no credentials live in this chart.

```sh
helm install keyorix-operator deploy/helm/keyorix-operator -n keyorix-system --create-namespace
```

## Values

| Key | Description |
| --- | --- |
| `image.repository` / `image.tag` | Operator image (tag defaults to the chart's appVersion) |
| `replicas` | Manager replicas (keep at 1 unless `leaderElection` is on) |
| `leaderElection` | Run >1 replica safely via a lease in the release namespace (default `false`) |
| `metricsPort` / `healthPort` | Manager metrics (`/metrics`) and probe (`/healthz`,`/readyz`) ports |
| `serviceAccount.create` / `serviceAccount.name` | ServiceAccount control |
| `watchNamespaces` | Restrict this instance (and its RBAC) to these namespaces instead of just its own — see [RBAC](#rbac) |
| `rbac.clusterScoped` | `true` for a genuinely cluster-wide instance (default `false`) — see [RBAC](#rbac) |
| `resources`, `nodeSelector`, `tolerations`, `affinity`, `podAnnotations` | Standard pod scheduling/resourcing |

## RBAC

A `ClusterRole` grants read on `keyorixsecrets` (+ status/finalizers) and
get/list/watch/create/update/patch/delete on `secrets` (`delete` is used only to remove the
target Secret once the upstream Keyorix reference is confirmed gone). A namespaced `Role`
grants the lease + event access leader election needs. The operator reads secret **values**
only through the Keyorix API (with each `KeyorixSecret`'s machine token) — never from the
cluster.

**By default (ADR-076) a single operator instance watches `KeyorixSecret` CRs in its own
release namespace only**, and the `ClusterRole` above is bound via a namespace-scoped
`RoleBinding` in that namespace — an unmodified `helm install` never grants access outside
where you installed it. Two opt-in modes, mutually exclusive with each other (setting both
makes the chart refuse to render, naming both values in the error):

- **`watchNamespaces: [team-a, team-b]`** — one instance managing a bounded, known set of
  namespaces. Binds a `RoleBinding` in each listed namespace.
- **`rbac.clusterScoped: true`** — one instance managing every namespace in the cluster,
  with no static list (the only way to reach this; it is no longer the default). Binds a
  cluster-wide `ClusterRoleBinding`.

```sh
# Bounded multi-namespace
helm install keyorix-operator-team-a deploy/helm/keyorix-operator -n team-a \
  --set 'watchNamespaces={team-a}'

# Cluster-wide (preserves the pre-ADR-076 default; see the CHANGELOG's BREAKING entry
# if you're upgrading an existing install that relied on it)
helm install keyorix-operator deploy/helm/keyorix-operator -n keyorix-system \
  --create-namespace --set rbac.clusterScoped=true
```

Both values feed a single named template (`_helpers.tpl`'s `kxop.scope`) that both
`rbac.yaml` and `deployment.yaml` render from, so the RBAC binding and the manager's own
`-watch-namespaces`/`-all-namespaces` flag can't drift apart — the same `ClusterRole`
object always exists (a Kubernetes RBAC object type, needed for manifest reusability
across modes), but what it's actually *bound* to is what determines real access. Do not
deploy more than one instance watching the same namespace with different configs.

## Uninstalling

`helm uninstall` removes the controller and RBAC. Helm does **not** remove CRDs it
installed from `crds/`; delete the CRD manually if you want the `KeyorixSecret` type gone
(this also deletes all `KeyorixSecret` objects and the Secrets they own):

```sh
kubectl delete crd keyorixsecrets.secrets.keyorix.io
```
