- **INV-MW-pat-ungated-write-gate-matches-dispatched-route** The restricted-PAT
  ungated-write gate (`RefuseRestrictedPATUngatedWrites`, `pat_restriction_writes.go`)
  is the ONLY HTTP authorization decision that re-matches the route INDEPENDENTLY of
  chi's dispatch (it calls `routes.Find(chi.NewRouteContext(), method, rctx.RoutePath)`
  to key `core.RestrictedPATWriteRefusal`, before the handler runs). Its refusal
  decision MUST be the refusal-status of the route chi ACTUALLY dispatches — a
  restricted PAT must never be authorized as route A (the pattern `Find` computed) and
  served as route B (the pattern chi dispatched). Both directions hold: a refused
  ungated write is never reachable by a restricted PAT via a path-encoding divergence
  (CH1-A, the bypass direction), and the gate never refuses a request the matched route
  does not make refused (CH1-B). Every other HTTP permission gate is a per-route
  `r.With(RequireScopedPermission(...))` middleware inside the matched route's own
  chain, so "authorized route == served route" holds for them by construction and needs
  no separate guard. Why: this is the one "route A vs route B" surface in the HTTP authz
  path (CH1); "when a verdict depends on a condition, guard the condition, not the
  conclusion" (root `CLAUDE.md`) — the condition is that `Find` and chi's dispatch agree
  on the route, so the oracle compares the gate's decision against the refusal-status of
  the dispatched route (chi's `RouteContext.RoutePattern()`), the ground truth.
  Guard: `chi_authz_route_differential_test.go` /
  `chi_authz_route_differential_fuzz_test.go` — `FuzzChiAuthzRouteDifferential` (declared
  `scripts/fuzzing/targets.d`), `TestChiAuthzRouteDifferential_Seeds` (default `go test`,
  deterministic adversarial corpus), red/green-proved by a planted decoded-path defect
  in `TestChiAuthzRouteDifferential_RedProof` (green on the real middleware, CH1-A on the
  plant). Does NOT verify: the correctness of the refusal table itself (that each entry
  SHOULD be refused — ADR-042/PAT-GUARD-3's own guards), the gRPC restricted-PAT
  interceptor (resolves by RPC name, not chi), real handler bodies/body-limits/CSRF (the
  harness uses recording stubs over the committed route inventory), or
  `r.Route`-mount-root trailing-slash shapes the flat replica may not reproduce. See
  `server/middleware/EXPECTED-DIFFERENCE.md` for the CH1-C routing-differential class
  table.
