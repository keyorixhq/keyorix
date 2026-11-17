- **INV-RES-sentinel-reuses-taint** The secret sentinel does NOT add a third
  marker-matching mechanism beside `internal/fuzzutil/taint` and the backupfmt/
  config taint harnesses. `NewSentinel` installs its value as the taint marker
  (`taint.SetMarker`) and routes every channel it scans — log output, outbound
  network bytes, files written under TempDir, and any error/label string the
  harness passes to `ScanString` — through `taint.Sink`. The verdict is a single
  `taint.Check(t.Fatalf)`; the needle set, the violation ledger and the
  Allow/Expect rules are taint's. The sentinel scans only channels it is given;
  it is not a proof the secret never leaked anywhere (stated in the doc comment).
  Why: "prefer the machine-checked over the asserted" plus "unify, don't write a
  third copy" — three independent secret-leak scanners would decay independently.
  Guard: `TestSentinelCatchesLeakViaTaint` (green: no leak, Check silent; red:
  the value leaked into a log line and a file, Check fires) in
  `internal/fuzzutil/resguard/resguard_test.go`.
