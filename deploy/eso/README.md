# Keyorix + External Secrets Operator (ESO) examples

Example manifests for reading Keyorix secrets into native Kubernetes Secrets via ESO's
generic **Webhook** provider — no custom controller required. Full guide:
[docs/k8s-eso.md](../../docs/k8s-eso.md).

| File | What it is |
|---|---|
| `token-secret.example.yaml` | Template for the Keyorix machine-token Secret (and optional CA). Do **not** commit a real token — create it out-of-band. |
| `cluster-secret-store.yaml` | `ClusterSecretStore` wiring ESO's Webhook provider to Keyorix's secret-read API. |
| `external-secret.yaml` | `ExternalSecret` materialising Keyorix secrets (by `project/environment/name`) into a target Secret. |

## Quick start

```sh
# 1. Token (in the namespace the ClusterSecretStore references):
kubectl -n external-secrets create secret generic keyorix-machine-token \
  --from-literal=token="$KEYORIX_MACHINE_TOKEN"

# 2. Store (edit the url first):
kubectl apply -f cluster-secret-store.yaml
kubectl get clustersecretstore keyorix          # READY=True

# 3. Sync (edit namespace + project/environment/name remoteRef.key first):
kubectl apply -f external-secret.yaml
kubectl get externalsecret db-creds -n app      # SYNCED=True
```

Prerequisite: the External Secrets Operator must already be installed in the cluster.
