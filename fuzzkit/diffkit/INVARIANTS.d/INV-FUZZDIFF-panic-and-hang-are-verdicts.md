- **INV-FUZZDIFF-panic-and-hang-are-verdicts** A panic or an over-timeout hang in one
  implementation is captured by `Run` as a verdict (`DecisionPanic` / `DecisionTimeout`),
  never allowed to crash or wedge the harness. A fuzzer can therefore treat "one side panics,
  the other accepts" as a reportable divergence instead of losing the whole run. Why: the kit
  fuzzes untrusted/independent code that may misbehave; a harness that dies on the first panic
  finds nothing. Guard: `TestRunPanicCapture`, `TestRunTimeout`, and the `TestCompare`
  "panic in one impl" / "timeout in one impl" rows.
<!-- section: Isolation -->
