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
| `imagePullSecrets` | Names of existing `docker-registry` Secrets to pull the operator image from a private/mirrored registry — see [Private registries](#private-registries) |
| `replicas` | Manager replicas (keep at 1 unless `leaderElection` is on) |
| `leaderElection` | Run >1 replica safely via a lease in the release namespace (default `false`) |
| `metricsPort` / `healthPort` | Manager metrics (`/metrics`) and probe (`/healthz`,`/readyz`) ports |
| `serviceAccount.create` / `serviceAccount.name` | ServiceAccount control |
| `watchNamespaces` | Restrict this instance (and its RBAC) to these namespaces instead of the whole cluster — see [RBAC](#rbac) |
| `resources`, `nodeSelector`, `tolerations`, `affinity`, `podAnnotations` | Standard pod scheduling/resourcing |

## RBAC

A `ClusterRole` grants read on `keyorixsecrets` (+ status/finalizers) and
get/list/watch/create/update/patch/delete on `secrets` (`delete` is used only to remove the
target Secret once the upstream Keyorix reference is confirmed gone). A namespaced `Role`
grants the lease + event access leader election needs. The operator reads secret **values**
only through the Keyorix API (with each `KeyorixSecret`'s machine token) — never from the
cluster.

By default a single operator instance watches `KeyorixSecret` CRs across every namespace in
the cluster, so the `ClusterRole` above is bound cluster-wide via a `ClusterRoleBinding`. If
you instead run one operator instance per namespace (or per bounded tenant set), set
`watchNamespaces` to that instance's namespace(s):

```sh
helm install keyorix-operator-team-a deploy/helm/keyorix-operator -n team-a \
  --set 'watchNamespaces={team-a}'
```

This passes `-watch-namespaces` to the manager (restricting its own watch/cache to those
namespaces too) and swaps the cluster-wide `ClusterRoleBinding` for a namespace-scoped
`RoleBinding` in each listed namespace — the same `ClusterRole` stays cluster-scoped (a
Kubernetes RBAC object type), but its granted access is limited to the bound namespaces. Do
not deploy more than one instance watching the same namespace with different configs.

## Private registries

For an air-gapped deployment that mirrors `keyorix-operator`'s image to a private,
authenticated registry, create a `docker-registry` Secret in the release namespace and
reference it via `imagePullSecrets`:

```sh
kubectl create secret docker-registry my-registry-cred \
  -n keyorix-system \
  --docker-server=my-mirror.example.com \
  --docker-username=... --docker-password=...

helm install keyorix-operator deploy/helm/keyorix-operator -n keyorix-system \
  --set image.repository=my-mirror.example.com/keyorix-operator \
  --set 'imagePullSecrets[0].name=my-registry-cred'
```

## Uninstalling

`helm uninstall` removes the controller and RBAC. Helm does **not** remove CRDs it
installed from `crds/`; delete the CRD manually if you want the `KeyorixSecret` type gone
(this also deletes all `KeyorixSecret` objects and the Secrets they own):

```sh
kubectl delete crd keyorixsecrets.secrets.keyorix.io
```
