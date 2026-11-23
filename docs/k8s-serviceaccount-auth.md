# Authenticate a Kubernetes workload with its ServiceAccount token

A pod can authenticate to Keyorix with the short-lived token Kubernetes already gives it.
There is no Keyorix token to create, store in a Kubernetes Secret, or rotate by hand.
This is machine-identity federation ([ADR-031](./adr-031-oidc-federation.md)).

**How it works.** Kubernetes mounts a projected ServiceAccount token into the pod. The token
is a JWT signed by the cluster, with `iss` (the cluster issuer), `sub`
(`system:serviceaccount:<namespace>:<name>`), `aud` and `exp`. Keyorix verifies the signature
against the issuer's keys, checks the issuer and audience, and looks up a *binding* from
`(issuer, subject)` to a machine identity. From there the request is the same as with an
opaque machine token: same roles, same scope confinement, same audit actor
(`machine_identity`).

## Before you start

- Keyorix fetches the issuer's keys (`jwks_uri`) live, so the issuer must be reachable from
  wherever Keyorix runs, even if that is only inside a private network. A deployment with no
  reachable issuer at all is not supported for federation yet; use machine tokens
  ([ADR-030](./adr-030-machine-token-authentication.md)) there. Details and the air-gapped case:
  [CONFIGURATION.md, `oidc`](./CONFIGURATION.md#oidc) and
  [ADR-075](./adr-075-airgap-oidc-federation.md).
- You need to be a project admin (to create the machine identity, grant a role and add a
  binding) and an operator (to edit the server configuration).

## 1. Trust the cluster (operator, once per cluster)

In the server configuration (see [CONFIGURATION.md](./CONFIGURATION.md#oidc)):

```yaml
oidc:
  enabled: true
  issuers:
    - name: prod-k8s
      issuer: https://kubernetes.default.svc        # must equal the token's iss
      jwks_uri: https://kubernetes.default.svc/openid/v1/jwks   # https required
      audiences: ["keyorix"]                         # token aud must contain one
      max_token_age_seconds: 3600                    # optional; default 24h
```

Find the real issuer of your cluster with
`kubectl get --raw /.well-known/openid-configuration`. The value above applies when Keyorix
runs inside the cluster. If Keyorix runs elsewhere, or on a managed cluster (EKS, GKE, AKS),
use that cluster's own public issuer and JWKS URL instead.

Use a dedicated audience such as `keyorix` for workloads. Do not list your human SSO client ID
as an audience.

## 2. One machine identity per workload

```sh
keyorix machine create --project payments --name payments-api --type k8s
```

Give it a role that covers only what the workload needs, nothing more
(`keyorix rbac list-roles` shows the available roles):

```sh
keyorix machine grant-role payments-api --project payments --role <role>
```

The role and the project (and environment) it covers decide what the workload can read. A name
like `production` in application code limits nothing by itself.

## 3. Bind the ServiceAccount to the machine identity

```sh
keyorix machine binding add payments-api \
  --project payments \
  --issuer  https://kubernetes.default.svc \
  --subject system:serviceaccount:payments-prod:payments-api
```

A `(issuer, subject)` pair maps to exactly one machine identity. The same ServiceAccount name
in another namespace (for example `payments-sandbox`) has a different subject and gets no
access. List bindings with `keyorix machine binding list payments-api`.

## 4. Mount a token with the right audience

```yaml
# Deployment.spec.template.spec
serviceAccountName: payments-api
volumes:
  - name: keyorix-token
    projected:
      sources:
        - serviceAccountToken:
            audience: keyorix          # must match issuers[].audiences
            expirationSeconds: 3600
            path: token
containers:
  - name: payments-api
    image: registry.example.internal/payments/api@sha256:<digest>
    env:
      - name: KEYORIX_URL
        value: https://keyorix.example.internal
    volumeMounts:
      - name: keyorix-token
        mountPath: /var/run/secrets/keyorix
        readOnly: true
```

Nothing secret is in Git. The manifest holds a URL, an audience and a path. The token is
issued to the pod by Kubernetes and refreshed by the kubelet before it expires.

The application sends the token as `Authorization: Bearer <jwt>`, the same way the
[SDKs](./sdks.md#authentication) send any other token type. Because the kubelet replaces the
file, **read it again** when you reconnect or refresh. Do not read it once at start-up and
keep it for days. Check how your SDK or HTTP client loads the token: it must take the new
value from the file, not from a variable set at start.

## 5. Check that it works, and that the boundary holds

1. From the pod, read a secret the role allows. It should succeed.
2. Read a secret the role does not allow (another project or environment). It should be
   denied. This is the real isolation test.
3. Repeat the read from a pod that uses a ServiceAccount with no binding. It should be denied.
4. Open the audit log. The actor is the machine identity, not a shared `deploy` user.

## Operations

| Task | Command |
|---|---|
| Cut off one workload (reversible) | `keyorix machine suspend payments-api` |
| Cut it off for good | `keyorix machine revoke payments-api` |
| Remove one ServiceAccount's access | `keyorix machine binding rm payments-api <binding-id>` |
| Cluster replaced | add an issuer entry for the new cluster, then `binding add` with the new issuer |

A suspended or revoked machine identity loses its federated access on the next request.

## Argo CD and GitOps

Let the application read the secret itself at start-up, as above, rather than rendering secrets
through Helm or a manifest plugin; otherwise the value ends up in generated manifests and in
Argo CD's cache. Git then holds only the URL, the audience, the subject and the secret *name*.

If you prefer Kubernetes `Secret` objects, use the [operator](./k8s-operator.md), the
[sync agent](./k8s-sync.md) or the [External Secrets Operator](./k8s-eso.md). Those deliver
values into the cluster. Federation, described here, is how a workload authenticates directly.

A rolled-back deployment is not automatically compatible with today's secrets: if a release
renamed a secret or changed its format, the previous version may not start. Check that the
previous supported version can start with the current secrets before removing an old name.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| 401 on every request | `iss` or `aud` in the token does not match an `issuers` entry. Decode the token locally (do not paste it anywhere) and compare. |
| 401 only after a while | The application kept the first token and never re-read the file. |
| 401 with a token that looks right | The token is older than `max_token_age_seconds` for that issuer. |
| 401 after a cluster upgrade or rebuild | The issuer or signing keys changed; update the issuer entry. |
| 403 | The token is valid and bound, but the machine identity's role does not cover that project or environment. |
| Cannot verify tokens | Keyorix cannot reach `jwks_uri`. Check that it is reachable from the server (see above). |
