- **INV-RES-absmax-for-decompression** A meter judged in `ModeAbsolute` is
  compared only against `AbsMax`, an input-size-INDEPENDENT ceiling
  (`p99(value across the corpus)·Factor`, computed by `Calibrate` for every
  meter), not against the per-byte slope `Factor·(Floor + PerByte·N)`. This is the
  correct model for a DECOMPRESSION or image target, where the compression ratio
  is scale-invariant: a per-byte slope calibrated on small benign inputs
  false-positives on a legitimately-larger one (RSG1 Pilot #1 — a 457-byte archive
  expanding to 65 823 bytes, 144×, tripped the slope although its output is
  harmless and within the product's own cap), and the slope's `PerByte·N` term is
  an attacker lever besides: for a decompression target the compressed input is
  cheap to pad with junk, buying a larger slope ceiling, so a padded bomb evades
  the slope while a flat absolute ceiling still fires. A target opts a meter in
  with `Budget.UseAbsolute(name…)`. Two guard rails: (1) `AbsMax` is only as good
  as its corpus — it must contain a representative legitimately-large benign
  sample or it is calibrated too small and the FP persists (the adopter owns the
  corpus; `FuzzResguardExtractArchive` adds a ~1 MiB benign archive for exactly
  this); (2) when `AbsMax` is 0 (a legacy budget predating this field) a
  `ModeAbsolute` meter falls back to the per-byte slope, so switching mode never
  silently disarms a guard. Why: the slope is the right model for a PARSER (small
  input → super-linear work) and the wrong one for pure decompression; saying so,
  and giving a second model, is the point. Guard:
  `TestBudgetAbsMaxForDecompression` (Part A reproduces the FP on a small-only
  corpus; Part B shows absolute needs an enriched corpus, then fixes the FP while
  still firing an 8 MiB bomb; Part C shows the padded bomb evading the slope but
  not the absolute ceiling) and `TestBudgetAbsMaxFallsBackToSlopeWhenUncalibrated`
  in `internal/fuzzutil/resguard/resguard_test.go`; adopted end-to-end against the
  real loader by `TestResguardBackupfmtAbsMaxRedGreen` in
  `internal/backupfmt/resguard_pilot_fuzz_test.go`.
