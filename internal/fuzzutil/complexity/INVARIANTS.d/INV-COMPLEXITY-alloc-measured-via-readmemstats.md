- **INV-COMPLEXITY-alloc-measured-via-readmemstats** The allocated-bytes proxy
  (`Cost.AllocBytes`/`Mallocs`) is sampled via `runtime.ReadMemStats`, NOT via the
  `runtime/metrics` `/gc/heap/allocs:bytes` counter. The metrics counter is flushed
  lazily from per-P mcache stats, so a single call's small allocation read back
  immediately reads as 0 and the proxy silently under-reports — the oracle would
  then pass every input, blind. `ReadMemStats` forces a stop-the-world that flushes
  every per-P cache, so the before/after delta is exact; its STW cost is irrelevant
  because a complexity fuzzer runs one input at a time and the inputs that matter
  allocate a lot. Why: measured, not assumed — the first draft used the metrics
  counter and `TestAllocOracle_MeasuresAndClassifies` reported "linear alloc
  measured 0 bytes" for a 2 KiB allocation (a guard caught its own blindness). This
  is the "prefer the machine-checked over the asserted" corollary: the mechanism was
  validated against the failure that actually happened. Guard:
  `TestAllocOracle_MeasuresAndClassifies` (`internal/fuzzutil/complexity/cost_test.go`).
