- **INV-RES-sampled-meters-skip-cheap-inputs** The expensive meters are measured
  only on a SAMPLED input. `AllocBytes` and `Mallocs` (the `complexity.Measure`
  delta taken around fn) are measured only on an input on the `SampleEvery`
  cadence, recorded by `Cost.AllocSampled`. `LiveHeap` (a forced GC after fn) is
  measured on a cadence input AND on one the cheap wall clock showed was slow
  (over `SlowWall`), recorded by `Cost.Sampled`. A slow-promoted input therefore
  has `Sampled` true and `AllocSampled` false: fn has already run without the
  alloc delta, so its alloc fields stay unmeasured. On an input without the
  matching flag those fields are a structural zero, NOT a measured zero.
  `Budget.Check` and `Calibrate` skip `alloc_bytes`/`mallocs` when `AllocSampled`
  is false and `live_heap` when `Sampled` is false, and `Drift.Observe` skips an
  input when `Sampled` is false, so an input is never judged "0 bytes, under
  budget" (a false green), a calibration corpus never reads an unmeasured zero
  into a p99 (which can drop the alloc meter entirely), and Drift never reads "heap
  did not grow" (a false all-clear). `WriteBytes` and the disk-walk fields are
  cheap and measured on EVERY input, so they are not covered by this rule. The
  stock `go test -fuzz` engine does not expose "this input found new coverage" to
  the target, so that third sampling trigger from the design is approximated by
  the slow-wall trigger, documented in the package doc, not silently dropped.
  Why: a meter that reports a structural zero as if it were a measurement is the
  "green check that does not cover what its name implies" failure; separating
  the measured flags from the value prevents it. Guard:
  `TestBudgetSkipsUnsampledSampleOnlyMeters`, `TestDriftIgnoresUnsampled`,
  `TestMeasureCheapAndSampled`, `TestMeasureSlowPromotionMarksAllocUnmeasured`
  in `internal/fuzzutil/resguard/resguard_test.go`, and
  `TestMeasureSlowPromotionDoesNotFakeAlloc` in
  `internal/fuzzutil/resguard/resguard_slowpromotion_test.go`.
