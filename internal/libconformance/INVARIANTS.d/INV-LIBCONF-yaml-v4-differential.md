- **INV-LIBCONF-yaml-v4-differential** `FuzzYAMLV4Differential`
  (`yaml_v4_differential_fuzz_test.go`) must fail on any accept/reject divergence,
  decoded-value divergence, OR super-linear memory blow-up between
  `go.yaml.in/yaml/v3` v3.0.5 and `go.yaml.in/yaml/v4` v4.0.0 on the same input
  bytes, UNLESS the divergence's class is listed in the committed
  `yamlV4ExpectedDiff` table (`yaml_v4_differential_redproof_test.go`) and
  documented in `EXPECTED-DIFFERENCES-yaml-v3-v4-differential.md`. The oracle is
  the classified disagreement, never a panic alone: a NEW class is a finding; a
  listed one is a reviewed, justified major-version change. The ONE currently
  tolerated class — `nonspecific-tag-empty-scalar` (the non-specific tag `!` on an
  empty scalar: v3 → null, v4 → empty string) — is enforced structurally by
  `classifyYAMLV4ValueSplit`/`nilVsEmptyStringOnly`, which tolerates ONLY
  null-vs-`""` leaves with otherwise-identical structure, so an unrelated value
  divergence (different number, key set, or nil-vs-non-empty-string) still fails.
  The bounded-work oracle meters `alloc_bytes`/`mallocs` (per-input ReadMemStats
  deltas) against an absolute ceiling calibrated in
  `testdata/resguard-yaml-v4.json`; `live_heap` is deliberately NOT fatal (it is
  the whole-process heap, not a per-input delta). Why: DF2 differential-pairs
  campaign — this complements `FuzzYAMLSiblingDifferential` (which compares two
  PATCH releases of v3) by covering the v3→v4 MAJOR rewrite, where v4 has no live
  Keyorix caller yet and a divergence is a forward-looking migration hazard
  (report `/mnt/data/wave4/out/df2-REPORT.md`). Guard: the target plus its seed
  corpus and `TestYAMLV4DifferentialRedGreen` (each oracle shown red on a planted
  divergence and green on a benign/listed input); removing
  `nonspecific-tag-empty-scalar` from the table turns the `!` seed red.
