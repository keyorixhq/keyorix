### Testing
- **CH1 differential fuzzer: go-chi routing vs. the restricted-PAT authorization
  gate.** `FuzzChiAuthzRouteDifferential` (`server/middleware`) drives the real
  `RefuseRestrictedPATUngatedWrites` middleware, the real `core.RestrictedPATWriteRefusal`
  table and a real chi router over percent-encoded, encoded-slash, dot-segment,
  double-slash, trailing-slash, case and unicode paths, asserting the gate's refusal
  decision always matches the refusal-status of the route chi actually dispatches (never
  authorized as route A and served as route B). This is the one HTTP authz surface that
  re-matches the route independently of chi; all other gates are per-route middleware.
  Guarded by `TestChiAuthzRouteDifferential_Seeds` and red/green-proved against a planted
  decoded-path defect (`TestChiAuthzRouteDifferential_RedProof`); routing-differential
  disagreement classes are enumerated in `server/middleware/EXPECTED-DIFFERENCE.md`. No
  Keyorix defect found — the gate is sound.
