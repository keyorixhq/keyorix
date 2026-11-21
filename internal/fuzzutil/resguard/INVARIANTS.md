# resguard invariants

`resguard` is the shared resource-measurement layer for fuzz targets: a Probe
wraps one fuzz input and returns a Cost vector (RAM, CPU, disk, inodes, fds,
goroutines, threads, network dials, virtual sleeps, log bytes, DB query cost),
with a calibrated Budget, an air-gap network oracle, cost-guided coverage
buckets, a cross-input drift watcher and a secret sentinel that reuses the
`taint` package.

Format: `INV-RES-NN <rule>. Why: <source>. Guard: <test> | UNGUARDED (#issue)`.

New invariants go in `INVARIANTS.d/INV-RES-<slug>.md` (one per file), never
appended here. Every current invariant is a fragment in `INVARIANTS.d/`:
airgap-fails-nonloopback, budget-calibrated-not-handtuned, absmax-for-decompression,
sampled-meters-skip-cheap-inputs, live-heap-per-input-delta, bounded-absolute-from-product-cap, sentinel-reuses-taint,
test-only.
