- **INV-FUZZCLOUD-oapiruntime-types-no-panic** `github.com/oapi-codegen/runtime/types`
  as reached from `cli/internal/apiclient/types.gen.go`'s `openapi_types.Email` fields
  never panics on attacker-controlled response bytes: `(*types.Email).UnmarshalJSON`,
  `(*types.Date).UnmarshalJSON`, `(*types.Date).UnmarshalText`,
  `(*types.Duration).UnmarshalJSON`, `(*types.Duration).UnmarshalText`, and
  `(*types.File).UnmarshalJSON` all return an error (or nil) for any input, never
  panic. Additionally, for `Email` and `Date`, a successful `UnmarshalJSON` followed
  by `MarshalJSON` and a second `UnmarshalJSON` of the re-marshaled output produces
  the same value (idempotence) — a correctness property these types claim and that
  Keyorix relies on when comparing parsed values. The reachability path is:
  a hostile server sends arbitrary bytes as an HTTP response body → the generated
  `Parse*Response` function calls `json.Unmarshal(bodyBytes, &dest)` → `encoding/json`
  reflection calls `(*types.Email).UnmarshalJSON` on each `Email`-typed field.
  Does NOT cover `types.UUID` (not imported in `types.gen.go`), timing or
  constant-time properties, or semantic correctness of the parsed values. Why:
  `cli/go.mod` pins `github.com/oapi-codegen/runtime v1.7.0` as an UNTRUSTED dep
  with FUZZ=NONE in the DEPMATRIX1 coverage matrix; the `types` subpackage is the
  actual attacker-reachable surface (not `StyleParamWithLocation`, which is
  outbound-only). Guard: `FuzzOapiRuntimeEmail`, `FuzzOapiRuntimeDate`,
  `FuzzOapiRuntimeDuration`, `FuzzOapiRuntimeFile`
  (`fuzz/thirdparty/oapiruntime/oapi_runtime_types_fuzz_test.go`), panic oracle
  red-proofed by `TestOraclePanic_RedGreen` and `TestOracleIdempotence_RedGreen`
  (`oapiruntime_oracle_validation_test.go`).
