### Testing
- **Algorithmic-complexity (PerfFuzz-style) fuzzing of third-party parsers.** Added
  a shared cost oracle (`internal/fuzzutil/complexity`) that measures a single
  parse's cost with deterministic proxies (allocated bytes via
  `runtime.ReadMemStats`, an optional work counter, wall time as a sanity guard
  only) and fails above a calibrated per-byte ratio or absolute ceiling, with
  unit tests that classify a known-linear vs known-quadratic subject. Added five
  `Fuzz*Complexity` targets in `internal/libconformance` over the parsers Keyorix
  feeds untrusted or operator-supplied bytes — x/text PRECIS/NFC, golang-jwt
  decode, beevik/etree XML, protobuf runtime decode, and yaml.v3 — each
  registered in `scripts/fuzzing/targets.d/`.
