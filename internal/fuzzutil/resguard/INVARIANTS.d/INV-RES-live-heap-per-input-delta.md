- **INV-RES-live-heap-per-input-delta** The `live_heap` budget meter
  (`Cost.LiveHeap`) is a PER-INPUT DELTA — the live (post-`runtime.GC()`) heap
  measured AFTER `fn` minus the live heap measured immediately BEFORE `fn`,
  clamped at 0 (`heapDelta` in `resguard.go`) — never the absolute whole-process
  `HeapAlloc`. The distinction is load-bearing: a `go test -fuzz` worker
  accumulates reachable heap across iterations (the engine's corpus and coverage
  maps, plus any caches in the code under test), so an ABSOLUTE live-heap reading
  charges every later input for memory it did not cause. That is exactly RG3's
  false positive (`FuzzResguardExtractArchive` crasher `cb1a9523e20b9df6`: a
  2-byte input measured at `live_heap=107874088` against a `budget=7434126`,
  amp 14.5×, where the 107 MB was accumulation — replaying the input alone in a
  fresh process passed). The pre-`fn` GC baseline removes the accumulation, so a
  tiny input scores ~0 while a single input that genuinely retains a large live
  heap still fails BOTH the per-byte slope `Factor·(Floor + PerByte·N)` AND the
  absolute `AbsMax` ceiling. The budget was NOT loosened: the committed
  `live_heap` ceiling for `backupfmt_extract` was re-derived by `Calibrate` from
  the corrected delta meter (floor ~22 KiB, from ExtractArchive's genuine
  retention), not hand-tuned (so INV-RES-budget-calibrated-not-handtuned still
  holds). Two carve-outs: (1) the pre-`fn` baseline is taken only on an
  ON-CADENCE sample (`index % SampleEvery == 0`); a slow-wall-PROMOTED input has
  no baseline, so its `LiveHeap` delta is 0 — not attributable — exactly as
  `AllocBytes`/`Mallocs` are already 0 on that path; (2) `Cost.LiveHeapAbs`
  carries the ABSOLUTE post-GC heap for the one consumer that needs it, `Drift`,
  which watches the absolute floor creep up over many inputs (a leak) — a shape no
  single-input delta can see. A per-input budget must never read `LiveHeapAbs`.
  Why: a resource budget asks "what did THIS input cost", and the honest answer
  for a shared, accumulating worker is a delta against a settled baseline, not a
  process-global snapshot. Guard: `TestLiveHeapIsPerInputDeltaNotAbsolute` (the
  artefact reproduction — a tiny input after a 64 MiB-retaining one),
  `TestLiveHeapDeltaDefeatsAccumulationFalsePositive` (RED: the absolute reading
  trips a clean budget; GREEN: the delta does not),
  `TestLiveHeapDeltaStillCatchesTrueAmplification` (a ~1,000,000× memory bomb
  still fires under slope AND AbsMax) and `TestLiveHeapPromotedInputHasNoDelta`,
  all in `internal/fuzzutil/resguard/resguard_test.go`; the delta vs absolute
  split is also what `TestDriftFlagsSustainedHeapGrowth` exercises (Drift reads
  `LiveHeapAbs`).
