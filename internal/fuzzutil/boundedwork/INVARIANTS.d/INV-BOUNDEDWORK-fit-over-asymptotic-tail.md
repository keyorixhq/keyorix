- **INV-BOUNDEDWORK-fit-over-asymptotic-tail** The cost exponent is fit over the
  asymptotic TAIL of the size series — the points whose cost is within
  `maxCost/tailFraction` (256) of the maximum — by least-squares in log-log space,
  never by a geometric mean over every doubling step. Why: super-linearity is an
  asymptotic property; at small N a parser's fixed overhead (yaml's decoder state
  is ~7 KiB regardless of input) flattens the curve, so a fit that weights the
  constant-dominated head is diluted toward "linear" and misses a real quadratic.
  This was observed directly during BW1 calibration: a geometric mean over
  factors 1,2,4,8 on a 5-byte base reported the yaml duplicate-key quadratic as
  linear-ish; restricting the fit to the tail made it fire. Guard:
  `TestCalib_YAMLDuplicateKey_FiresRed` (`internal/libconformance`), which fires
  red on the real yaml.v3 duplicate-key decode (alloc ~4.19x/doubling) and would
  go green — silently — if the fit were diluted back over all steps, together with
  `TestOracle_RedOnQuadraticTime`/`TestOracle_RedOnQuadraticAlloc`
  (`internal/fuzzutil/boundedwork`, synthetic O(n^2)).
