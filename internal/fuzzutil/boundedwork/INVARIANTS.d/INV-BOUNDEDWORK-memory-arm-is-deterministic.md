- **INV-BOUNDEDWORK-memory-arm-is-deterministic** The memory arm measures
  `runtime.MemStats.TotalAlloc` deltas — a monotonic, cumulative, GC-independent
  counter — and takes the median over repeats; it must never be replaced by a
  live-heap gauge (HeapAlloc/HeapInuse) that GC timing perturbs. Why: a
  deterministic function allocates a deterministic number of bytes, so the memory
  arm red-proofs cleanly and reproducibly (the yaml.v3 duplicate-key fire measured
  4.19x/doubling on all 3 of 3 replays), whereas the time arm is inherently noisy
  and is only a corroborating signal. A guard nobody has watched fire is not a
  guard; this arm is the one that fires the same way every run. Guard:
  `TestOracle_RedOnQuadraticAlloc` (`internal/fuzzutil/boundedwork`, O(n^2)
  allocation fires at exactly 4.00x/doubling) and the deterministic
  `TestCalib_YAMLDuplicateKey_FiresRed` alloc assertion (`internal/libconformance`).
