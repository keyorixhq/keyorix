- **INV-BOUNDEDWORK-below-floor-is-not-judged** When the LARGEST measured variant
  is below both absolute floors (TimeFloor 3 ms AND AllocFloor 1 MiB), `Analyze`
  returns `Judged=false` / `SuperLinear=false` — "no verdict", never "linear".
  Why: a cheap, fast call must be structurally unable to false-trip the oracle
  regardless of its curve shape; and conversely a real quadratic whose constant is
  tiny at these sizes must be reported as not-yet-judged rather than certified
  linear (a green check that does not cover what its name implies is worse than no
  check). The floors gate on the largest variant only, so the detector fires only
  when cost is BOTH large in absolute terms AND super-linear in shape. Guard:
  `TestOracle_BelowFloorNotJudged` (`internal/fuzzutil/boundedwork`), which sets
  the floors above any reached value and asserts `Judged=false` and no fire.
