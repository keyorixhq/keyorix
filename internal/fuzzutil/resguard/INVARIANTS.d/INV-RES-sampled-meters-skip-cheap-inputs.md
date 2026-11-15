- **INV-RES-sampled-meters-skip-cheap-inputs** The expensive meters
  (`AllocBytes`, `Mallocs`, `LiveHeap`, `WriteBytes`, the disk-walk fields) are
  measured only on a SAMPLED input — one on the `SampleEvery` cadence, or one the
  cheap wall clock already showed was slow. On an unsampled input those fields are
  a structural zero, NOT a measured zero. `Cost.Sampled` records which it was, and
  both `Budget.Check` and `Drift.Observe` skip the sampled-only meters when
  `Sampled` is false, so a cheap input is never judged "0 bytes, under budget"
  (which would be a false green) nor "heap did not grow" (a false all-clear). The
  stock `go test -fuzz` engine does not expose "this input found new coverage" to
  the target, so that third sampling trigger from the design is approximated by
  the slow-wall trigger — documented in the package doc, not silently dropped.
  Why: a meter that reports a structural zero as if it were a measurement is the
  "green check that does not cover what its name implies" failure; separating
  Sampled from the value prevents it. Guard:
  `TestBudgetSkipsUnsampledSampleOnlyMeters`, `TestDriftIgnoresUnsampled`,
  `TestMeasureCheapAndSampled` in `internal/fuzzutil/resguard/resguard_test.go`.
