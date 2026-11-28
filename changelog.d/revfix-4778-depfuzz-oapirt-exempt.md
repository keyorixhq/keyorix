### Testing

- Dependency fuzz-gap guard: added a time-boxed exemption fragment for
  `github.com/oapi-codegen/runtime` (removed when its fuzz target lands in
  #4775) so `TestDepFuzzGaps_EveryOpenGapIsExempt` passes in enforce mode on
  main. `depmatrix` now matches `targets.d` entries by whole path segment,
  skips `.scratch` and `testdata`, and reports skipped files on stderr.
