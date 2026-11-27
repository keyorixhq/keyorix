- **INV-FUZZUTIL-first-guard-call-allocates-nothing-extra** Guard's one-time
  per-process state is built OUTSIDE every measured window, so a process's first
  `fuzzutil.Guard` call is not billed for it. Two parts: (1) the package makes
  the process's first `runtime/metrics` read in `init()` (that read builds the
  runtime's metric table, ~10 KiB, and the stall monitor's baseline sample used
  to be it); (2) `resguard.New` calls `fuzzutil.Prime()`, which starts the stall
  monitor and pools two runners and two timers (one lands in the calling P's
  private `sync.Pool` slot, one in the shared slot any P can steal from, since
  each fuzz input runs on a fresh goroutine). Why: RESGUARD-PAR-1. `f7904445a`
  (2026-11-21) gave the stall monitor a heap/GC-CPU baseline, so the first
  guarded call of every process paid the metric table inside the caller's
  `complexity.Measure` window. Each `go test -fuzz` worker is a fresh process, so
  under `-parallel=6` a different seed lands first in each worker, and a tiny one
  failed its calibrated alloc budget (`FuzzDigitorusTimestamp`: `input=4 bytes
  alloc_bytes=13912 budget=12154`, `input=0 bytes 11632 vs 6752`). The per-input
  meter was right; the input was billed for the harness. NOT covered: lazy state
  in the code UNDER TEST is still paid by its first input (the input's own work,
  absorbed by calibration), except the runtime metric table itself, which a
  library that reads `runtime/metrics` no longer pays; a caller that uses Guard
  without `resguard` (bare `complexity.Measure`) gets part (1) only and still
  pays the monitor's goroutine, ticker and first runner (~1.5-2 KiB) on its first
  call; and a pooled runner or timer evicted by two GCs before it is used is
  rebuilt inside a window (~1.6 KiB). Pool contents survive one GC, and a
  cadence input's own pre-fn GC is that one, so a single natural GC between
  `New` and the first guarded call already loses part (2)'s runner and timer;
  each `Put` pins separately, so both can still land in private slots; under
  `-race` `sync.Pool` drops a quarter of Puts at random; and a `SampleEvery: 1`
  Probe rebuilds them on every input (its two forced GCs per input empty the
  pool), so its calibration already includes that. Part (1), the ~10 KiB that
  broke digitorus, depends on none of this. Guard: part (1) by
  `TestStallMonitorStartDoesNotBuildMetricTable` in
  `internal/fuzzutil/stall_coldstart_test.go` and part (2) by
  `TestFirstMeasuredGuardCallPaysNoHarnessStartup` in
  `internal/fuzzutil/resguard/resguard_coldstart_test.go`, both in a fresh child
  process so the call really is the process's first. Red on `origin/main`
  (+9.4-10.4 KiB); mutation-killed natively by deleting the `init()` (10008 vs
  592 bytes) and by deleting the `Prime()` call (first call +1.6-1.8 KiB over a
  warm one, slack 768 bytes). Under `-race` the slack is 2048 bytes (the race
  runtime's own noise is that large), so a race run proves part (1) only.
