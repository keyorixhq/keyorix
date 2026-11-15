- **INV-RES-budget-calibrated-not-handtuned** A target's resource ceilings are
  produced by `Calibrate`, which runs the seed corpus through a Probe, takes the
  p99 of each meter and of each meter's per-input-byte ratio, and multiplies by a
  documented slack `Factor` (`DefaultFactor` = 4). There are no hand-picked
  numeric ceilings in a target; the only knob is the factor, recorded in the
  emitted `testdata/resguard.json`. Each meter budget is `Floor + PerByte·N`, so a
  larger input is judged against a larger budget and only SUPER-linear growth
  fails — the allocation budget in particular scales per input byte plus a fixed
  floor. Advisory meters (wall, CPU, goroutine/thread/fd deltas) are process-wide
  and noisy on a shared host, so they are reported for context in a failure
  message but never fail an input on their own (wall time false-fires under
  load). Why: a hand-tuned ceiling decays silently and is a comment, not a
  mechanism; a calibrated one is derived from the code's own observed behaviour.
  Guard: `TestBudgetCalibrateAndCheck` (green within slope; red on a 50 MiB alloc
  for a 100-byte input, message names the meter and amplification ratio) and
  `TestBudgetSkipsUnsampledSampleOnlyMeters` in
  `internal/fuzzutil/resguard/resguard_test.go`.
