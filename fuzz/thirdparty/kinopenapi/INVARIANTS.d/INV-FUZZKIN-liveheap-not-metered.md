- **INV-FUZZKIN-liveheap-not-metered** Both committed resguard budgets,
  `testdata/resguard-kinopenapi.json` (schema target) and
  `testdata/resguard-kinloader.json` (full-document loader), keep per-input
  ceilings on `alloc_bytes` and `mallocs` and have no `live_heap` ceiling. Why:
  for a sub-millisecond VisitJSON or load the post-GC whole-process live heap is
  dominated by the fuzz engine's own heap, not by input-attributable work;
  amplification still fails through `alloc_bytes`/`mallocs` and hangs through
  `fuzzutil.Guard`. Guard: `TestKinBudgets_LiveHeapNotMetered`
  (`fuzz/thirdparty/kinopenapi`), which also fails when a committed budget is
  missing. Does NOT verify the ceilings' values (`TestKinCalibrate` /
  `TestLoaderCalibrate` regenerate them).
