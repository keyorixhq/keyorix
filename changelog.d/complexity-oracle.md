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

### Documentation
- **Recorded a yaml.v3 O(n²) duplicate-key amplification (FINDING Y1).**
  `gopkg.in/yaml.v3` v3.0.1 decodes a mapping of duplicate keys in quadratic time
  and memory, returning its duplicate-key error only after the full quadratic
  work; distinct keys stay linear and billion-laughs is bounded. In Keyorix this
  is operator-reachable only (`keyorix secret import --format vault`, config and
  k8ssync loads — no network path); the existing 100 MiB import cap assumes a
  linear parser and does not prevent OOM under the quadratic. Characterized by
  `internal/libconformance/complexity_yaml_quadratic_test.go`; no production
  change (issue-ready hardening proposal in the campaign report).
