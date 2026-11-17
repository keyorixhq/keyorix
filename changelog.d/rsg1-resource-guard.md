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
  its allocation meter. A budget meter can also use an input-size-independent
  `AbsMax` ceiling (`Budget.UseAbsolute`) for decompression-shaped targets, and
  a slow-promoted input never counts its unmeasured allocation fields.
- Test-only resguard pilots: the backupfmt archive extractor (disk bomb, `AbsMax`
  red/green) and the Azure Key Vault connector (air-gap dials and metered
  retry-delay backoff), each with a committed calibrated budget.
- Test-only `internal/testutil/fuzzworld` integrity helpers: `WorldDigest` and a
  schema janitor for leaked PostgreSQL fuzz schemas, plus a reset-soundness test
  for the core sequence target on SQLite and PostgreSQL.
