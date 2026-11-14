- **INV-FUZZDIFF-sound-oracle-only** The oracle compares only what both implementations can
  faithfully represent: the accept/reject/panic/timeout decision, and — when both accept — the
  normalised subject (`Verdict.Subject`, compared with `reflect.DeepEqual`). It never asserts
  that the shared decision is correct; a blind spot both sides share is invisible by
  construction. A `Decide` that over-normalises (collapsing distinct outcomes to one verdict)
  hides real divergences, so `Subject` must stay as faithful as the two sides can both
  represent. Why: keeps the kit honest about what it does and does not verify (see `Compare`'s
  doc comment). Guard: `TestCompare` (the subject-skew row proves accept/accept with differing
  subjects is a divergence).
<!-- section: Oracle -->
