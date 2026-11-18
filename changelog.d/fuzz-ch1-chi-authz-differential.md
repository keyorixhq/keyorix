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
- **CH2 run: the CH1 fuzzer was exercised for 126 minutes of real wall time**
  (14×540s chunks, ~23M executions, `-parallel 2`) against the real middleware, table
  and chi router. Zero oracle violations (no CH1-A bypass, CH1-B wrong-route refusal or
  new CH1-C routing-differential class); the interesting-input corpus saturated at ~213
  entries. No crasher, no harness bug, and no production change: the latent decoded-path
  fallback branch flagged in CH1 stayed unreachable under every fuzzed input, so the
  optional hardening was deliberately NOT applied.
