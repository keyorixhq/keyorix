- **INV-FUZZCORS-liveheap-not-metered** The committed resguard budget
  `testdata/resguard-cors.json` keeps per-input ceilings on the
  input-attributable meters `alloc_bytes` and `mallocs` and has no `live_heap`
  ceiling. Why: one CORS serve is sub-microsecond and allocates a few KiB, so the
  post-GC whole-process live heap is dominated by the fuzz engine's own heap
  (observed 21 MiB against a 15 MiB calibrated ceiling on a 7-byte input) and
  would false-trip; amplification still fails through `alloc_bytes`/`mallocs`,
  and cross-input leaks surface through `Probe.CheckDrift`. Guard:
  `TestCORSBudget_LiveHeapNotMetered` (`fuzz/thirdparty/cors`), which also fails
  when the committed budget is missing. Does NOT verify the ceilings' values
  (`TestCORSCalibrate` regenerates them).
