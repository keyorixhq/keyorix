# BW1 — Ecosystem-wide bounded-work & round-trip fuzz generator

**Status: IN PROGRESS.** Report path note: `/mnt/data/wave4/out/` is not writable
from this sandboxed session (filesystem is restricted to the worktree), so per the
runtime fallback this report is committed on the branch at `.scratch/bw1-REPORT.md`.
Temperature file `/sys/class/hwmon/hwmon2/temp1_input` is also outside the sandbox
and unreadable; thermal safety relies on `nice -n 10`, `GOMAXPROCS=2`, `-parallel 2`
as instructed.

Branch: `fuzz/bounded-work-generator`. Working dir: `/mnt/data/wave4/bw1`.
Module cache is offline (`GOPROXY=off`, `GOMODCACHE=/mnt/data/wave4/gomod`).

## Most reasonable reading of the task (stated up front)

- "Super-linear" = the cost curve's asymptotic exponent, not an absolute ceiling.
  The existing `fuzzutil.Guard` / per-call `TotalAlloc` envelopes already catch
  3-orders-of-magnitude amplification; this work is the complementary detector of
  quadratic growth that stays *under* those ceilings at fuzz sizes.
- A library that fires the oracle on its pinned version is a **finding**, reported
  with an upstream-ready reproducer — it is NOT committed as a CI fuzz target
  (that target would fail on its own seeds). Only libraries confirmed **linear**
  (green on the pinned version) are promoted to committed targets + `targets.d`.
- yaml calibration: the known duplicate-key quadratic is reproduced against the
  raw library (no `internal/yamlsafe` wrapper — that package does not exist in this
  tree). The calibration is an *oracle-characterisation* test asserting the
  detector classifies the known-positive and known-negative correctly.

## Pieces & status

| Piece | State |
|-------|-------|
| (1) Oracle `internal/fuzzutil/boundedwork` | DONE — self-tested red/green |
| (1a) yaml calibration (known defect) | DONE — fires red on dup keys, green on unique |
| (2) Generator `scripts/fuzzing/bwgen` | in progress |
| (3) Ecosystem sweep (40+ fns) | pending |
| Triage / findings | yaml DEFECT recorded; sweep pending |
| targets.d conf, changelog, INVARIANTS.d | pending |

## Piece 1 — the oracle (`internal/fuzzutil/boundedwork`)

`Check(fatalf, label, base, scale, call, cfg)` measures `call` across scaled
variants of `base` (factors 1,2,4,8 by default; `ScaleRepeat(minUnit)` normalises
a small seed into the asymptotic regime), takes the **median** wall-clock time and
**median GC-independent allocation** (`runtime.MemStats.TotalAlloc`, a monotonic
counter) over `Repeats` runs per size, fits `cost ~ len^p` by **least-squares
regression in log-log space over the asymptotic tail** (points within
`maxCost/256`), and fails when the per-doubling multiplier `2^p` exceeds
`MaxDoubling` (default 3.0; linear≈2x, quadratic≈4x) in either the time or the
memory arm. Absolute floors (`TimeFloor` 3 ms, `AllocFloor` 1 MiB on the *largest*
variant) mean a cheap, fast call is reported "not judged" rather than linear —
the structural anti-false-positive guarantee.

Key calibration lesson, baked into the design: **super-linearity is asymptotic.**
A geometric mean over all doubling steps diluted the yaml quadratic toward "linear"
because small inputs sit in yaml's ~7 KiB fixed-overhead regime. Fitting the tail
(dropping constant-dominated head points) is what makes the oracle fire.

### What the oracle does NOT verify (per `Check` doc comment)

- **Correctness.** The function's result is discarded. The oracle says nothing
  about whether the parse is right, round-trips, or should have errored. A function
  returning garbage in linear time passes.
- **Absolute cost / ceilings.** It judges the *shape* of the curve, not its height.
  A uniformly slow but linear parser, or one allocating a constant large buffer,
  passes. Use `fuzzutil.Guard` / a `TotalAlloc` envelope for ceilings.
- **Blow-up on a dimension the scaler does not grow.** It grows exactly what
  `scale()` grows. A billion-laughs alias bomb is invisible unless the scaler adds
  alias depth. Scalers are named for what they scale.
- **Anything below the floors.** A real quadratic with a tiny constant at 1 MiB is
  reported "not judged", not "linear".
- **Constant factors between machines.** Thresholds are ratios (machine-independent),
  but a pathologically loaded host can inflate the *time* arm; the *memory* arm is
  the deterministic one and is preferred for red-proofing.

### Red/green proof (synthetic, deterministic)

`internal/fuzzutil/boundedwork/boundedwork_test.go`:
- `TestOracle_GreenOnLinear` — O(n) fn: time 1.25x, alloc 2.00x/doubling → quiet.
- `TestOracle_RedOnQuadraticAlloc` — O(n²) alloc: 4.00x/doubling → fires (memory
  arm is fully deterministic, clean red proof).
- `TestOracle_RedOnQuadraticTime` — O(n²) time: ~4.1x/doubling → fires.
- `TestOracle_BelowFloorNotJudged` — cheap call draws no verdict.
- `TestCheck_FailsViaFatalf` — `Check` routes verdict through fatalf correctly.

## Piece 1a — yaml calibration against the real defect

`internal/libconformance/yaml_boundedwork_calibration_test.go`:
- `TestCalib_YAMLDuplicateKey_FiresRed` — duplicate-key decode fires for BOTH
  forks: `gopkg.in/yaml.v3` v3.0.1 (alloc 4.19x, time 4.46x/doubling) and
  `go.yaml.in/yaml/v3` v3.0.5 (alloc 4.19x, time 4.43x). RED.
- `TestCalib_YAMLUniqueKey_QuietGreen` — distinct-key control: alloc 1.92x,
  time 2.50x/doubling → not super-linear. GREEN. Confirms the detector keys on
  "duplicate key", not "large mapping".

## Findings so far

See the Findings table near the end (updated as the sweep runs). Confirmed:
**F-YAML-DUPKEY** — both offline yaml.v3 forks are O(N²) time+memory on
duplicate-key mappings. Reproducer and reachability trace below.

## Talk material

(to be finalised after the sweep)
