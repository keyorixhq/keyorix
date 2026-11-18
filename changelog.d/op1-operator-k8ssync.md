### Testing
- **Operator reconcile: idempotence/convergence + strong scope-confinement fuzz target.**
  `FuzzReconcileIdempotentScopeConfined` (`operator/internal/controller`) runs a full
  reconcile twice over a fake cluster that also holds a populated second tenant, asserting
  the reconcile converges (target Secret `ResourceVersion` and `Ready` reason stable on the
  second pass over a stable upstream), only ever touches its own namespace (every API
  object operation's namespace is recorded by an interceptor), never mutates the second
  tenant's identically-named victim/token Secrets, never leaks the fetched canary, and
  keeps upstream fetches + goroutines bounded. Red/green proofs:
  `TestIdempotenceOracleRedGreen`, `TestScopeOracleRedGreen`. Closes the idempotence and
  strong-scope gaps the existing reconcile targets left open.
- **k8ssync fetcher: resguard-metered resource bound.** `FuzzK8sSyncFetcherResource`
  (`internal/k8ssync`) wraps the shared `internal/fuzzutil/resguard` resource layer
  (NetMeter air-gap, `dials`/`net_bytes_in`, sampled `alloc_bytes`) around
  `FetchWithExpiry` against a fuzz-shaped httptest server: the fetcher never dials a
  non-loopback host and no bounded-page response shape exceeds the calibrated absolute
  ceiling. `TestResguardK8sSyncPaginationRedGreen` documents a HARDENING finding —
  `resolveID` has no client-side pagination ceiling, so a hostile/broken server advertising
  a large `total_pages` makes one resolution read an unbounded cumulative response volume,
  bounded only by the caller's context deadline.
