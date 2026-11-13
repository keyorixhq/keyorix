- **INV-KOP-no-cross-tenant-secret-write** The reconciler only ever creates, overwrites,
  clears or deletes a target Secret that is both labelled
  `app.kubernetes.io/managed-by=keyorix-operator` AND `metav1.IsControlledBy` the
  KeyorixSecret being reconciled, and only in that CR's own namespace. `spec.target.name`
  is attacker-controlled, so without the ownership check a tenant with only
  KeyorixSecret-create RBAC could name a victim CR's Secret and clobber or delete it on
  every reconcile (cross-tenant availability/integrity attack). Why: `applySecret`,
  `wipeTargetSecret`, `emptyManagedSecret` (`keyorixsecret_controller.go`). Guard:
  `FuzzReconcileAuthzBoundary` (oracles 1 & 2) and `FuzzReconcileHostileK8sAPI`
  (`operator/internal/controller`) — a victim Secret owned by a different CR is never
  mutated even when the attacker sets `spec.target.name` to its name, and no Secret is
  ever written outside the CR namespace.
