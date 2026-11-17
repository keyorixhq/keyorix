- **INV-LIBCONF-jsonschema-ref-differential** For schemas that use `$ref` with a `"#"` or
  `"#/$defs/<name>"` target, getkin/kin-openapi and santhosh-tekuri/jsonschema/v6 must
  return the SAME accept/reject verdict on every instance both can use, except for the
  documented splits on `refDiffAllow`. kin's side is its built-in OpenAPI 3.0 validator, with
  refs resolved by `openapi3.NewLoader` after `kinRefDocument` places the schema at
  `components.schemas.S` and hoists root `$defs` into `components.schemas` (a bare
  `openapi3.Schema`, as Oracle C uses, resolves no `$ref`). kin's `EnableJSONSchema2020` is
  NOT used, because it evaluates with santhosh itself. The one `$ref`-specific split is
  `openapi-ref-sibling-ignored`: OpenAPI 3.0 ignores keywords next to `$ref`, while 2020-12
  applies them. It is keyed only when santhosh, given the schema with the siblings stripped,
  returns kin's verdict. The Oracle-C splits are inherited, since each one is reachable
  through a `$ref` target. Verdicts are NOT compared, and only a santhosh crash or hang is
  detectable, for pure ref-only cycles (`{"$ref":"#"}`, A→A via `$defs`; kin reports an
  unresolved ref) and for `$dynamicRef`/`$dynamicAnchor`/`$anchor`/`$id` (kin's 3.0 document
  validation rejects them). `TestRefDiff_SeedsReachVerdictComparison` pins that reach for
  each seed group. google/jsonschema-go (KFZ-2026-021) is not a dependency of this module and
  is not covered; `TestJSONSchemaRefDiff_CycleSafety` only smoke-tests santhosh on the same
  cycle shapes and pins its verdicts. KFZ ids live in the private KFZ fuzz-findings ledger
  (keyorix-private).
  Why: JF4 differential fuzzing session, covering the `$ref` territory where INV-LIBCONF-openapi-jsonschema-verdict compares nothing.
  Guard: `FuzzJSONSchemaRefDifferential` + `TestRefDiffAllowlistNoDead` +
  `TestRefDiff_SeedsReachVerdictComparison` + `TestJSONSchemaRefDiff_CycleSafety` +
  `TestJSONSchemaRefDiff_RedGreen` (`internal/libconformance`).
