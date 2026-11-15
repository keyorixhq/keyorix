- **INV-COMPLEXITY-budget-classifies-linear-vs-quadratic** `Budget.Check` must
  PASS a known-linear subject at large N and FIRE on a known-quadratic subject at
  the same N, for both the work-counter and the allocated-bytes proxy; the
  per-byte floor (`FloorBytes`/`FloorWork`) must absorb a constant per-call
  overhead so a tiny/empty input is not judged against a near-zero budget and
  false-fire; the absolute ceiling (`AbsMaxAllocBytes`) must fire on a
  large-constant regression the per-byte slope alone would miss; and a zero
  `Budget` (every knob opt-in) must NEVER fire. Why: these four together are the
  whole claim the oracle makes — a classifier that cannot fire on a quadratic
  subject, or that false-fires on a tiny input, converts an unknown into a false
  assurance (`a guard nobody has watched fail is not a guard`). Guard:
  `TestWorkOracle_ClassifiesLinearVsQuadratic`, `TestAllocOracle_MeasuresAndClassifies`,
  `TestAbsoluteCeiling_Independent`, `TestFloorAbsorbsTinyInputs`,
  `TestNoCeilingSetNeverFires` (`internal/fuzzutil/complexity/cost_test.go`).
