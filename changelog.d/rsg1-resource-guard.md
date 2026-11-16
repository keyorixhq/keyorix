### Added

- Test-only `internal/fuzzutil/resguard`: a shared fuzz resource-measurement
  layer. A `Probe` wraps one fuzz input and returns a `Cost` vector (wall/CPU,
  goroutines, threads, fds, alloc/live-heap, disk files/dirs/symlinks/bytes/
  sparse-blocks, write bytes, network dials + bytes, virtual-time sleeps, log
  bytes and DB query/row counts). Budgets are calibrated from the seed corpus
  (p99 × factor → `testdata/resguard.json`), never hand-tuned. Includes an
  air-gap network oracle (any non-loopback dial fails the input), cost-guided
  coverage buckets (PerfFuzz on the stock `go test -fuzz` engine), a cross-input
  drift watcher for leaks, and a secret sentinel that reuses the existing
  `taint` sink. Composes `internal/fuzzutil/complexity` rather than duplicating
  its allocation meter.
