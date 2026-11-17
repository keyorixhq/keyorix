### Testing

- Add `FuzzJSONSchemaRefDifferential` (Oracle D) to `internal/libconformance`: a verdict
  differential between getkin/kin-openapi and santhosh-tekuri/jsonschema/v6 over schemas
  with `$ref`/`$defs`, which `FuzzOpenAPIVsJSONSchema` (Oracle C) cannot compare. kin resolves
  the refs through its Loader on a wrapping OpenAPI 3.0.3 document. Classifies one new
  dialect split, `openapi-ref-sibling-ignored` (OpenAPI 3.0 ignores keywords next to `$ref`),
  and inherits the Oracle-C allowlist. Pure ref-only cycles and `$dynamicRef` are crash/hang
  coverage only, and a reach test pins that. Adds a `targets.d` entry for the continuous
  fuzzing rig (15m).
