- **INV-BOUNDEDWORK-json-scaler-keeps-one-parse-regime** `ScaleJSONArray` scales
  only a base that is one valid JSON value, and then every variant is a valid JSON
  array whose element count is the factor times the factor-1 count; any other base
  gives no variants, so `Analyze` draws no verdict. Why: plain repetition of a
  JSON value is invalid after the first value, so a decoder stops there and the
  target can never fire (REVIEW-4284-DEEP-1 MEDIUM-1); and an array of copies of a
  non-value flips between valid and invalid with the copy count (`{":0} ` has an
  odd quote count), so the call runs the scan-only error path at one size and a
  full decode at the next, a cost jump that read 3.32x per doubling on a linear
  decoder in a fuzz run. Guard: `TestScaleJSONArray_KeepsJSONValidAndGrowsElements`
  (`internal/fuzzutil/boundedwork`) and, for the committed targets,
  `TestBoundedWorkSweep_EveryTargetJudgesASeed` (`internal/boundedworksweep`).
