# keyorix-k8s-sync Helm chart

Deploys the [Keyorix Kubernetes sync agent](../../../docs/k8s-sync.md): it
materialises selected Keyorix secrets into native Kubernetes Secrets and refreshes
them as the upstream values rotate.

## Install

First create a Secret holding the agent's Keyorix machine-identity token:

```sh
kubectl -n keyorix create secret generic keyorix-token --from-literal=token=<TOKEN>
```

Then install with your mappings:

```sh
helm install kx-sync deploy/helm/keyorix-k8s-sync \
  --namespace keyorix --create-namespace \
  --set keyorix.url=https://keyorix.internal \
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
| `keyorix.interval` | Reconcile cadence (Go duration; default `5m`) |
| `keyorix.tokenSecret.name` | Existing Secret holding the Keyorix token (**required**) |
| `keyorix.tokenSecret.key` | Key within that Secret (default `token`) |
| `mappings` | List of `{ref, namespace, name, key}` — Keyorix secret → Kubernetes Secret key |
| `targetNamespaces` | Namespaces the agent may write Secrets in (RoleBinding per ns); defaults to the release namespace |
| `image.repository` / `image.tag` | Agent image (tag defaults to the chart's appVersion) |
| `serviceAccount.create` / `serviceAccount.name` | ServiceAccount control |
| `resources`, `nodeSelector`, `tolerations`, `affinity`, `podAnnotations` | Standard pod scheduling/resourcing |

## RBAC

The chart creates a `ClusterRole` (`secrets`: `get`/`create`/`patch`) and a namespaced
`RoleBinding` in each `targetNamespaces` entry — least privilege, no cluster-wide
Secret access. The agent uses Server-Side Apply (field manager `keyorix-sync`), so it
owns the Secret `data` it writes and prunes keys it no longer maps.
