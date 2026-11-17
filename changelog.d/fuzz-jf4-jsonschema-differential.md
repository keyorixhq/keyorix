### Testing

- Add `FuzzJSONSchemaRefDifferential` (Oracle D) to `internal/libconformance`: a
  differential fuzz target over the `$ref`/`$defs`/`$dynamicRef` territory that
  `FuzzOpenAPIVsJSONSchema` (Oracle C) deliberately excludes. Covers the KFZ-2026-021
  cycle-shape (santhosh-tekuri/jsonschema/v6 handles all tested $ref cycle patterns
  without crashing), inherits the Oracle-C allowlist for dialect splits, and adds a
  `targets.d` entry for the continuous fuzzing rig (15m).
