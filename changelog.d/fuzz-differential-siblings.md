### Testing
- **Differential fuzzing between sibling implementations (DP1).** Added three
  differential fuzz targets under `internal/libconformance`, each oracle a
  *classified disagreement* (never panic-only) gated by a committed
  EXPECTED-DIFFERENCE table (`differential_expected_difference_test.go`):
  `FuzzYAMLSiblingDifferential` (go.yaml.in/yaml/v3 v3.0.5 vs gopkg.in/yaml.v3
  v3.0.1 — accept/reject parity, decoded-value equality via a fixed canonical
  re-encoder, and a test-only duplicate-key pre-scan standing in for the absent
  `internal/yamlsafe`); `FuzzJSONSchemaValidatorDifferential`
  (santhosh-tekuri/jsonschema/v6 vs getkin/kin-openapi `openapi3` — verdict
  parity on Keyorix-shaped schemas with a fuzzed instance); and
  `FuzzJSONStrictDecodeDifferential` (the `json.NewDecoder(r.Body).Decode` path
  every HTTP handler uses vs `json.Unmarshal` / `DisallowUnknownFields` / a
  schemaless map decode — accept/reject parity on the same bytes). Each target is
  declared in `scripts/fuzzing/targets.d/` and documented in
  `internal/libconformance/INVARIANTS.d/`.
