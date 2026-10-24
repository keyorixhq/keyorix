# scripts/k8s-e2e

Real-cluster end-to-end journeys for the Kubernetes delivery paths (`run.sh`,
`make k8s-e2e`; needs Docker, kind, helm, kubectl, openssl, go). Manual target,
not run in CI. Flow and journey list: the header of `run.sh`.

| Journey | Covers |
|---|---|
| J1 | helm install (bundled Postgres), bootstrap, MFA enrol, CLI secret round-trip |
| J2 | helm lint / template / kubeconform on all three charts, NetworkPolicies exist |
| J3 | operator: `KeyorixSecret` reaches Ready, target Secret value |
| J4 | k8s-sync agent: sync and prune-on-mapping-removal |
| J5 | External Secrets Operator webhook provider |
| J6 | `secureBaseline.existingSecret` (see below) |

## J6: secureBaseline.existingSecret

Pre-creates the TLS/metrics Secret, installs the chart pointing at it, then:

- no chart-generated `<fullname>-secure-baseline` Secret exists, and the server,
  web and Postgres workloads mount the pre-created one;
- two `helm upgrade` runs with the same values leave the Secret (resourceVersion
  and a hash of its data), the server certificate, pod UIDs, restart counts,
  workload generations and the `checksum/secure-baseline` annotation identical
  (nothing rolls);
- an upgrade pointed at a Secret missing `server.key` fails with
  `missing required key(s): server.key`, the error contains no PEM and no
  metrics token, and the running release is untouched.

Secret contents are never printed: only hashes and the sanitized error line.

J6 needs only the server and web images and no CLI login, so it runs first and
can run alone, which skips building the operator/k8s-sync images and J1-J5:

```sh
KEYORIX_K8S_E2E_ONLY=j6 KEYORIX_K8S_E2E_CLUSTER=my-cluster ./scripts/k8s-e2e/run.sh
```

Other knobs: `KEYORIX_K8S_E2E_CLUSTER` (kind cluster name),
`KEYORIX_K8S_E2E_KEEP_CLUSTER=0` (delete the cluster on exit),
`KEYORIX_K8S_E2E_IMAGE_TAG`.

## multi-replica-secret.sh: two replicas in Secret mode

Separate from `run.sh`: `scripts/k8s-e2e/multi-replica-secret.sh` installs the chart
with `server.replicas=2` in Secret mode (`server.keysSecret`,
docs/multi-replica-keys.md) on its own kind cluster (`ha-secret-keys-1-kmrs`):

- the key Secret comes from `keyorix-server admin encryption key-secret generate`
  (immutable), the auth Secret from `--from-file`; both replicas Ready, no keys PVC,
  `key_dir_lock: database`, the pod's key directory read-only, the database's
  `dek.epoch` equal to the Secret's fingerprint;
- a secret written through one pod reads back through the other;
- a DEK rotation in a workspace (`key-secret unpack`, scale to 0,
  `admin encryption rotate`, `key-secret export` as a new Secret): a pod on the old
  Secret is refused (DEK epoch), `helm upgrade` to the new one brings both back and
  the secret still reads;
- a rolling restart, then `admin verify-audit` with the checkpoint key: VALID.

Key material stays in a 0700 work directory and is never printed. Knobs:
`KEYORIX_KMRS_CLUSTER`, `KEYORIX_KMRS_KEEP_CLUSTER=1`, `KEYORIX_KMRS_IMAGE_TAG`.
It replaces `multi-replica.sh` (two replicas on a ReadWriteMany keys volume), which
the chart now refuses.
