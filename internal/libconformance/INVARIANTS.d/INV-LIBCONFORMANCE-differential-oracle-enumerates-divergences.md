- **INV-LIBCONFORMANCE-differential-oracle-enumerates-divergences** Every
  sibling-implementation differential fuzz target in this package
  (`FuzzYAMLSiblingDifferential`, `FuzzJSONSchemaValidatorDifferential`,
  `FuzzJSONStrictDecodeDifferential`) must fail on any accept/reject or
  decoded-value divergence between its two implementations whose *class* is not
  listed in the committed EXPECTED-DIFFERENCE table
  (`differential_expected_difference_test.go`: `yamlExpectedDiff`,
  `jsonSchemaExpectedDiff`, `jsonDecodeExpectedDiff`). The oracle is the
  classified disagreement, NOT a panic alone: a NEW divergence class is a finding;
  a listed one is a reviewed, justified library-version/dialect difference. This
  keeps the table honest as the slide "where equivalent libraries disagree" — a
  divergence can only be silenced by naming and justifying its class in the table,
  never by widening an assertion. Why: DP1 differential-siblings campaign (report
  `.scratch/dp1-REPORT.md`). Guard: the three `Fuzz*` targets above plus their
  seed corpora (each seed exercises a known divergence); removing a class from the
  table turns its seed red (demonstrated in the report's red/green section).
