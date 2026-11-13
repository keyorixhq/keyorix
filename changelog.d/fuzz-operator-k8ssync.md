### Testing
- **Fuzz coverage for the Kubernetes operator & `internal/k8ssync` authorization
  boundary.** New fuzz targets exercise the controls that keep a namespace-scoped
  tenant — who can only create a `KeyorixSecret` custom resource or a sync config —
  from reading or writing secrets outside its scope: `FuzzValidateServer` and
  `FuzzValidateClientBaseURL` (operator confused-deputy / cleartext-token gates),
  `FuzzReconcileAuthzBoundary` (full reconcile against a controller-runtime fake API —
  namespace-scope, cross-tenant Secret integrity, and a secret-value canary that must
  never reach `.status`/Events/errors), `FuzzReconcileHostileK8sAPI` (the same reconcile
  under adversarial apiserver responses — injected Conflict/NotFound/ServerTimeout and an
  oversized token-sharing peer set — asserting no panic, bounded upstream fan-out, and no
  cross-tenant write or canary leak), and `FuzzValidateKeyorixURL` / `FuzzConfigValidate`
  (the `internal/k8ssync` sync-config transport & scope gates). Test-only; no production
  behaviour change.
