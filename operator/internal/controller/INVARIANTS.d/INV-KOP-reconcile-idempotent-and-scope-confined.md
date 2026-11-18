- **INV-KOP-reconcile-idempotent-and-scope-confined** A reconcile over an already-synced
  world with a STABLE upstream is a no-op: the target Secret's `ResourceVersion` and the
  `Ready` condition reason do not change on a second pass (it converges, it does not churn
  etcd or the single shared workqueue every interval). AND every Kubernetes API object
  operation the reconcile issues stays inside the CR's own namespace — every
  `Get`/`Update`/`Create`/`Delete` names that namespace and every `List` is scoped
  `InNamespace` to it — so a namespaced-only actor can never make the (cluster-RBAC)
  operator read or write another tenant's objects. Why: `Reconcile` derives every
  `NamespacedName` and list scope from `ks.Namespace`, `CreateOrUpdate` writes only on a
  real diff, and `succeed` advances `LastTargetName` so no re-wipe recurs
  (`keyorixsecret_controller.go`). Guard: `FuzzReconcileIdempotentScopeConfined`
  (`operator/internal/controller`) runs the reconcile twice over a fake cluster that also
  holds a populated second tenant (identically-named victim/token Secrets + a peer CR) and
  an interceptor recording the namespace of every op; `TestIdempotenceOracleRedGreen` and
  `TestScopeOracleRedGreen` are the red/green proofs (a flaky upstream rewrites the Secret;
  a cross-namespace op is flagged).
