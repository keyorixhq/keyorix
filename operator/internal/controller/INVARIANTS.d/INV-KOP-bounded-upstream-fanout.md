- **INV-KOP-bounded-upstream-fanout** A single reconcile issues a bounded number of
  upstream Keyorix value fetches regardless of how many KeyorixSecrets share one
  `tokenSecretRef`: the mass-revocation circuit breaker's peer probe is capped at
  `massPruneProbeCap` (100), so an oversized or hostile token-sharing group cannot turn
  one confirmed-gone reconcile into an unbounded outbound fan-out (a DoS amplifier against
  the shared Keyorix server and the single cluster-wide reconciler). Why:
  `massRevocationSuspected` / `massPruneProbeCap` (`keyorixsecret_controller.go`). Guard:
  `FuzzReconcileHostileK8sAPI` (`operator/internal/controller`) seeds 200 token-sharing
  peers and asserts the per-reconcile fetch count stays within `massPruneProbeCap` plus
  the CR's own data entries.
