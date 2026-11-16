# resguard invariants

`resguard` is the shared resource-measurement layer for fuzz targets: a Probe
wraps one fuzz input and returns a Cost vector (RAM, CPU, disk, inodes, fds,
goroutines, threads, network dials, virtual sleeps, log bytes, DB query cost),
with a calibrated Budget, an air-gap network oracle, cost-guided coverage
buckets, a cross-input drift watcher and a secret sentinel that reuses the
`taint` package.

New invariants go in `INVARIANTS.d/INV-RES-<slug>.md` (one per file), never
appended here. Current fragments:

- **INV-RES-airgap-fails-nonloopback** — the NetMeter dialer FAILS any
  non-loopback dial; code that bypasses the hardened client (#1949) is caught.
- **INV-RES-budget-calibrated-not-handtuned** — budgets come from Calibrate
  (seed-corpus p99 × factor), never hand-tuned constants.
- **INV-RES-absmax-for-decompression** — a ModeAbsolute meter is judged by an
  input-size-INDEPENDENT ceiling (AbsMax = p99(value)·factor), the right model for
  a decompression/image target where the per-byte slope false-positives; falls
  back to the slope when AbsMax is uncalibrated.
- **INV-RES-sampled-meters-skip-cheap-inputs** — a Budget never judges an
  unsampled input on a sampled-only meter (whose fields are a structural zero).
- **INV-RES-sentinel-reuses-taint** — the secret sentinel plants a value and
  routes every channel through `taint.Sink`; it adds no second needle matcher.
- **INV-RES-test-only** — nothing outside `*_test.go` imports `resguard`.
