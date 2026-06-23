# ADR-060: Kubernetes operator (KeyorixSecret CRD)

## Status

Accepted.

## Context

Keyorix already materialises secrets into Kubernetes two ways: the `keyorix-k8s-sync`
agent (a Deployment reconciling a static config, ADR-057) and an External Secrets
Operator integration (ESO Webhook provider). Both work, but neither is a **native
operator** — there is no Keyorix custom resource an app team can `kubectl apply`, no
per-secret status, and no Kubernetes-native lifecycle. The product roadmap calls for a
first-class operator, and competitive analysis shows it is the expected delivery model
for platform teams.

A real operator needs CRD watches, a cache, leader election, and status conditions —
which in Go means `controller-runtime`/`client-go`. That dependency tree is large and
conflicts with the deliberately dependency-free style of the sync agent and the server.

## Decision

Add a `controller-runtime`-based operator that reconciles a **`KeyorixSecret`** custom
resource (`secrets.keyorix.io/v1alpha1`) into a native Kubernetes Secret.

- **Separate Go module.** The operator lives in `operator/` with its own `go.mod`, so
  `controller-runtime`/`client-go` never enter the server/CLI module. The root build is
  unchanged; the operator has its own CI job (built with `GOWORK=off`).
- **CRD.** `KeyorixSecret.spec` carries the Keyorix `server`, a `tokenSecretRef`
  (machine-identity token, never inlined), a `refreshInterval`, a `target` Secret, and a
  `data` list of `{secretKey, ref}` where `ref` is a `project/environment/name` reference
  resolved through the by-reference read endpoint (ADR-059). Status carries a `Ready`
  condition, `lastSyncTime`, and a `syncedHash`.
- **Reconcile.** Read the token, fetch each referenced value, and create-or-update the
  target Secret with an **owner reference** to the `KeyorixSecret`. A fetch failure fails
  the whole reconcile (never a partial Secret) and records `Ready=False`/`SyncError` with
  backoff; success records `Ready=True` and requeues after `refreshInterval`.
- **Owner-reference GC.** Because the target Secret is owned by the CR, deleting the CR
  garbage-collects the Secret — orphan cleanup is native, with no agent-side reaping
  logic (contrast ADR-057's label-based cleanup, which the agent needs because its
  Secrets are not owned by a CR). The operator owns the whole `data` set, so a dropped
  mapping is pruned on the next reconcile.
- **Packaging.** A Helm chart (`deploy/helm/keyorix-operator`) ships the CRD, the
  controller Deployment, its ServiceAccount, and RBAC (cluster read on KeyorixSecrets +
  read/write on Secrets, namespaced lease/event access for optional leader election). The
  image is a distroless non-root static binary.

## Alternatives considered

- **Dependency-free informer.** Hand-roll watch/reconcile over net/http to match the sync
  agent's tiny-image style. Rejected: reimplements caching, leader election, rate-limited
  workqueues, and status handling that controller-runtime provides and that production
  operators are expected to have. The module isolation already contains the dependency
  cost.
- **Deepen the sync agent instead of a CRD.** Rejected: a static config Deployment is not
  the `kubectl apply`-able, per-object-status experience the roadmap calls for. The agent
  remains the right tool for simple, config-driven setups; the operator is the native
  option. ESO remains the choice for teams standardised on it.
- **Same Go module as the server.** Rejected: would pull controller-runtime/client-go
  (hundreds of packages) into the server/CLI build for no benefit.

## Consequences

- Three delivery models now coexist, documented side by side: the sync agent, ESO, and
  the operator. Teams pick by preference; all read through the same authorized, audited
  Keyorix API.
- The operator must be built/tested/released as its own module and image. CI gains an
  `operator` job and an operator-chart lint; release/publish plumbing adds the image and
  chart alongside the existing ones.
- The CRD is a `v1alpha1` API: breaking changes are still permitted while the shape
  settles, before a future `v1beta1`/`v1` promotion.
