- **INV-LIBCONF-jsonschema-ref-differential** For schemas that contain `$ref`, `$defs`,
  `$dynamicRef`, or `$dynamicAnchor` keywords AND that both getkin/kin-openapi and
  santhosh-tekuri/jsonschema/v6 can compile (kinOK=true and jsOK=true in `jsVerdict` /
  `kinVerdict`), the two validators must return the SAME accept/reject verdict, except for
  documented splits on the `refDiffAllow` list (all Oracle-C entries inherited, plus any
  $ref-territory-specific entries found and classified during JF4). A verdict split outside
  that list means one validator admits an instance the other rejects. KFZ-2026-021 shape:
  santhosh-tekuri/jsonschema/v6 v6.0.3 handles ALL tested $ref cycle patterns ({"$ref":"#"},
  A→A via $defs, recursive-tree) without crashing; a future version that reintroduces an
  unhandled cycle would cause TestJSONSchemaRefDiff_CycleSafety to crash (non-recoverable
  stack overflow), making this a crash-detection guard as well as a verdict-parity guard.
  Why: JF4 differential fuzzing session, covering territory excluded by INV-LIBCONF-openapi-jsonschema-verdict.
  Guard: `FuzzJSONSchemaRefDifferential` + `TestRefDiffAllowlistNoDead` +
  `TestJSONSchemaRefDiff_CycleSafety` + `TestJSONSchemaRefDiff_RedGreen`
  (`internal/libconformance`).
