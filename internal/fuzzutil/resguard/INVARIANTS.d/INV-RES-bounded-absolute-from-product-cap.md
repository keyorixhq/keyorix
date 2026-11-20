- **INV-RES-bounded-absolute-from-product-cap** A meter whose per-input cost is
  set by a size the input CLAIMS (a length prefix a parser sizes a buffer from
  before the body arrives), not by the bytes it carries, may be judged in
  `ModeAbsolute` with `AbsMax = calibrated AbsMax + bound` via
  `Budget.UseBoundedAbsolute(meter, bound)`, where `bound` is a ceiling the
  PRODUCT itself enforces and names as a constant (`pgxlimits.MaxProtocolMessageBodyLen`;
  the MySQL protocol's 16 MiB per-packet maximum), never a number chosen to make a
  failing target pass. The calibrated part still comes from `Calibrate` and the
  JSON is still produced by `RESGUARD_CALIBRATE=1`, so INV-RES-budget-calibrated-not-handtuned
  holds: the only added term is a named product constant. Why: the per-byte slope
  false-fires on every such input (a 9-byte pgx header costs one bounded buffer,
  measured ~775 MB before the product bound existed), which turned `fuzz-changed`
  red on unrelated PRs, and a flat hand-picked ceiling would have been 115x looser
  than needed. Limits: the oracle no longer sees an amplification below `bound`
  for these targets, and loosening the product constant loosens the oracle in step
  (the product constant has its own test). Guard: `TestBudgetUseBoundedAbsolute`
  in `internal/fuzzutil/resguard/resguard_test.go` (a tiny input costing one
  bounded buffer passes; the boundary is exact; just above fires and names the meter).
