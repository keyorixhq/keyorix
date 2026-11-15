// Package boundedwork is a fuzz oracle for super-linear (quadratic or worse)
// time and memory growth in parsers, decoders and validators.
//
// Motivation. The most common real defect class in Go parsing code is not a
// panic but super-linear cost: an N-byte input that makes the parser do work
// proportional to N^2 (or worse). A plain `func Fuzz` target never catches this
// — it feeds one input of one size and only notices a crash. The disclosed
// yaml duplicate-key quadratic (KFZ-2026-085) is the standing example: a valid
// document, no panic, just O(N^2) time and memory that a never-panic harness
// sails straight past.
//
// The existing fuzzutil.Guard and the per-call TotalAlloc envelopes in
// internal/libconformance catch AMPLIFICATION — an absolute ceiling three
// orders of magnitude above any honest parse. They are blind to a quadratic
// that stays under that ceiling for fuzz-sized inputs: 8 KiB -> 64 MiB is
// caught, but 512 B -> 4 ms scaling to 4 KiB -> 256 ms is not, because 256 ms
// is still under the 3 s Guard and the allocation is still under the 64 MiB
// floor. This oracle is the complement: instead of one absolute ceiling it
// measures the SHAPE of the cost curve across scaled variants of the SAME
// input and fails when the curve is clearly super-linear.
//
// Method. Given a base input and a scaler, Check builds variants at factors
// 1, 2, 4, 8 (repeat / nest / widen the base, capped at MaxInputLen), measures
// best-of-N process CPU time and median GC-independent allocation
// (runtime.MemStats TotalAlloc, a monotonic counter) for each, and fits the cost exponent p in
// cost ~ len^p. A linear parser has p ~ 1; a quadratic one has p ~ 2. Check
// fails when the per-doubling cost multiplier (2^p) exceeds Config.MaxDoubling
// (default 3x, i.e. p ~ 1.585) averaged geometrically over the doubling steps.
//
// Determinism and false positives. TotalAlloc for a deterministic function is
// itself deterministic and GC-independent, so the MEMORY arm red-proofs cleanly.
// Time is noisy; the time arm uses process CPU time (not wall time), the minimum
// over repeats, and measures sizes round-robin, so host load does not bend the
// curve (see measure), plus the 3x margin (linear ~2x, quadratic ~4x, threshold
// 3x sits between them). Absolute floors
// (TimeFloor, AllocFloor) mean a variant whose largest measurement is tiny is
// never judged — a fast, small parse cannot false-trip regardless of curve
// shape. The oracle therefore only fires when the cost is BOTH large in
// absolute terms AND super-linear in shape.
//
// What this oracle does NOT verify: see Check's doc comment.
package boundedwork

import (
	"fmt"
	"math"
	"runtime"
	"slices"
	"time"
)

// Config tunes the oracle. The zero value is not valid; use it via Check, which
// fills every unset field with the documented default.
type Config struct {
	// Factors are the input-size multipliers measured, smallest first. Default
	// {1, 2, 4, 8}. At least three usable factors are required to judge a curve;
	// fewer (because MaxInputLen clipped the larger ones) means Check returns
	// without a verdict rather than guessing from two points.
	Factors []int

	// Repeats is how many times each factor is measured; the median is kept, to
	// damp scheduler and GC noise in the time arm. Default 5.
	Repeats int

	// MaxInputLen caps the scaled input size. A factor whose scaled input would
	// exceed this is dropped (not measured). Default 1 << 20 (1 MiB) — large
	// enough to separate linear from quadratic, small enough that a genuinely
	// quadratic sink does not run for minutes per fuzz input.
	MaxInputLen int

	// TimeFloor and AllocFloor are the absolute signal floors. If the LARGEST
	// factor's median time is below TimeFloor AND its median allocation is below
	// AllocFloor, the call is too cheap to judge and Check returns without a
	// verdict — this is what makes a small, fast parse structurally unable to
	// false-trip. Defaults: TimeFloor 3ms, AllocFloor 1<<20 (1 MiB).
	TimeFloor  time.Duration
	AllocFloor uint64

	// MaxDoubling is the largest per-doubling cost multiplier tolerated, averaged
	// (geometric mean) over the doubling steps, in whichever arm (time or memory)
	// is above its floor. 2x is ideal-linear; the disclosed quadratic is ~4x.
	// Default 3.0 sits between. Only an arm above its floor is judged, so a parse
	// that is super-linear in time but trivial in memory is still caught, and
	// vice versa.
	MaxDoubling float64

	// MinExponentArms, when >0, requires that many arms (1 or 2) to independently
	// exceed MaxDoubling before failing. Default 1 (either arm alone fails). Set
	// to 2 to demand agreement between the time and memory curves — quieter, but
	// blind to a memory-only or time-only quadratic, so the default is 1.
	MinExponentArms int
}

func (c Config) withDefaults() Config {
	if len(c.Factors) == 0 {
		c.Factors = []int{1, 2, 4, 8}
	}
	if c.Repeats <= 0 {
		c.Repeats = 5
	}
	if c.MaxInputLen <= 0 {
		c.MaxInputLen = 1 << 20
	}
	if c.TimeFloor <= 0 {
		c.TimeFloor = 3 * time.Millisecond
	}
	if c.AllocFloor == 0 {
		c.AllocFloor = 1 << 20
	}
	if c.MaxDoubling == 0 {
		c.MaxDoubling = 3.0
	}
	if c.MinExponentArms <= 0 {
		c.MinExponentArms = 1
	}
	return c
}

// Measurement is the cost of calling the function under test on one scaled input.
type Measurement struct {
	InputLen   int
	Nanos      int64  // time arm: minimum over Config.Repeats, on the clock in Verdict.TimeClock
	CPUNanos   int64  // minimum process CPU time over Config.Repeats (0 if the clock is unavailable)
	WallNanos  int64  // minimum wall-clock time over Config.Repeats
	AllocBytes uint64 // median TotalAlloc delta over Config.Repeats (GC-independent)
}

// Verdict is the full analysis Check produced, returned by Analyze for callers
// that want to inspect rather than fail. Check itself calls fatalf on a
// super-linear verdict and discards it otherwise.
type Verdict struct {
	Label        string
	Measurements []Measurement
	Judged       bool // false => below floors, no conclusion drawn
	// Per-doubling multipliers (geometric mean, normalised to a 2x length step).
	TimeDoubling  float64
	AllocDoubling float64
	TimeJudged    bool // time arm was above its floor and thus evaluated
	AllocJudged   bool
	// TimeClock is the clock the time arm used: "cpu" (process CPU time) or
	// "wall" (fallback: no CPU clock here, or the cheapest point too short to
	// resolve on it; see cpuClockMinNanos).
	TimeClock   string
	SuperLinear bool
	Reason      string
}

// RepeatBytes is the default scaler: the base bytes concatenated factor times.
// For a line-oriented format (one "a: 1\n" line) this naturally grows the
// structure the parser walks — e.g. factor duplicate mapping keys for YAML,
// which is exactly the shape of the disclosed duplicate-key quadratic — while
// keeping the document valid. factor 1 returns the base unchanged.
func RepeatBytes(base []byte, factor int) []byte {
	if factor <= 1 {
		return base
	}
	out := make([]byte, 0, len(base)*factor)
	for range factor {
		out = append(out, base...)
	}
	return out
}

// ScaleRepeat returns a scaler that first repeats base until it is at least
// minUnit bytes (so even a one-line fuzz seed reaches the asymptotic regime
// where super-linearity is visible above fixed parser overhead), then repeats
// that unit `factor` times. With factors {1,2,4,8} and minUnit 512 the measured
// sizes are ~512..4096 B — large enough that a quadratic sink is unmistakable,
// small enough that a single call stays well under a second. If base is empty,
// the scaler returns an empty slice for every factor (nothing to measure).
func ScaleRepeat(minUnit int) func(base []byte, factor int) []byte {
	return func(base []byte, factor int) []byte {
		if len(base) == 0 {
			return nil
		}
		unit := base
		if len(unit) < minUnit {
			reps := (minUnit + len(unit) - 1) / len(unit)
			unit = RepeatBytes(unit, reps)
		}
		if factor <= 1 {
			return unit
		}
		return RepeatBytes(unit, factor)
	}
}

// Check measures call across scaled variants of base and reports via fatalf
// (pass t.Fatalf) when the cost curve is clearly super-linear. scale(base,
// factor) builds the input for a given factor; pass RepeatBytes for the common
// "repeat the corpus bytes" growth, or a structural scaler (nest / widen) when
// raw repetition would not grow the work. call runs the function under test on
// one input and discards the result — only CPU time and allocation are
// observed, so a call that returns an error still contributes a measurement.
//
// What Check does NOT verify:
//   - Correctness. The function's RESULT is discarded. Check says nothing about
//     whether the parse is right, whether it round-trips, or whether it should
//     have errored. A function that returns garbage in linear time passes.
//   - Absolute cost. Check judges the SHAPE of the curve, not its height. A
//     parser that is linear but uniformly slow (or allocates a constant large
//     buffer) passes; use fuzzutil.Guard / a TotalAlloc envelope for ceilings.
//   - Exponential blow-up on a dimension the scaler does not grow. Check grows
//     exactly what scale() grows; a billion-laughs alias bomb is invisible
//     unless the scaler adds alias depth. Name the scaler for what it scales.
//   - Anything below the floors. If the largest variant is cheap (under
//     TimeFloor and AllocFloor) Check draws no conclusion — a real quadratic
//     whose constant is tiny at 1 MiB is reported as "not judged", not "linear".
//   - Constant factors between runs/machines. Thresholds are ratios, so they are
//     machine-independent, but a pathologically loaded host can still inflate
//     the time arm; the memory arm is the deterministic one and is preferred for
//     red-proofing.
func Check(fatalf func(format string, args ...any), label string, base []byte,
	scale func(base []byte, factor int) []byte, call func(input []byte), cfg Config) {
	v := Analyze(label, base, scale, call, cfg)
	if v.SuperLinear {
		fatalf("BOUNDED-WORK: %s is super-linear — %s; measurements=%s",
			label, v.Reason, formatMeasurements(v.Measurements))
	}
}

// Analyze performs the same measurement and fitting as Check but returns the
// Verdict instead of failing. Useful in calibration tests that assert on the
// verdict directly.
func Analyze(label string, base []byte, scale func(base []byte, factor int) []byte,
	call func(input []byte), cfg Config) Verdict {
	cfg = cfg.withDefaults()
	v := Verdict{Label: label}

	var inputs [][]byte
	for _, f := range cfg.Factors {
		in := scale(base, f)
		if len(in) > cfg.MaxInputLen {
			break
		}
		inputs = append(inputs, in)
	}
	if len(inputs) >= 3 {
		v.Measurements, v.TimeClock = measure(inputs, call, cfg.Repeats)
	}
	if len(v.Measurements) < 3 {
		v.Reason = "fewer than 3 usable size points (input cap reached early)"
		return v
	}

	last := v.Measurements[len(v.Measurements)-1]
	timeAbove := time.Duration(last.Nanos) >= cfg.TimeFloor
	allocAbove := last.AllocBytes >= cfg.AllocFloor
	if !timeAbove && !allocAbove {
		v.Reason = "largest variant below both floors — too cheap to judge"
		return v
	}
	v.Judged = true

	v.TimeDoubling = doublingMultiplier(v.Measurements, func(m Measurement) float64 { return float64(m.Nanos) })
	v.AllocDoubling = doublingMultiplier(v.Measurements, func(m Measurement) float64 { return float64(m.AllocBytes) })
	v.TimeJudged = timeAbove
	v.AllocJudged = allocAbove

	arms := 0
	var reasons []string
	if v.TimeJudged && v.TimeDoubling > cfg.MaxDoubling {
		arms++
		reasons = append(reasons, fmt.Sprintf("%s time grows %.2fx per input-doubling (>%.2fx)", v.TimeClock, v.TimeDoubling, cfg.MaxDoubling))
	}
	if v.AllocJudged && v.AllocDoubling > cfg.MaxDoubling {
		arms++
		reasons = append(reasons, fmt.Sprintf("alloc grows %.2fx per input-doubling (>%.2fx)", v.AllocDoubling, cfg.MaxDoubling))
	}
	if arms >= cfg.MinExponentArms {
		v.SuperLinear = true
		v.Reason = joinReasons(reasons)
	} else if len(reasons) > 0 {
		v.Reason = "super-linear in " + joinReasons(reasons) + " but MinExponentArms not met"
	} else {
		v.Reason = fmt.Sprintf("linear-ish (time %.2fx, alloc %.2fx per doubling)", v.TimeDoubling, v.AllocDoubling)
	}
	return v
}

// measure runs call on every input, Repeats rounds, and returns one Measurement
// per input: the median allocation and the MINIMUM (best-of-N) time.
//
// Time is noise-robust by construction rather than by margin:
//   - It is process CPU time (processCPUNanos), not wall time, wherever the
//     platform has it and it resolves the curve (cpuClockMinNanos), so time
//     spent descheduled on a loaded host is not counted. Otherwise the whole
//     curve falls back to wall time; the returned clock says which was used.
//   - It is the minimum over repeats, not the median: contention, preemption,
//     cache eviction and GC interference only ever ADD cost to a run, so the
//     cheapest run is the best estimate of the call's own cost.
//   - The inputs are measured round-robin (every size once per round) rather
//     than size after size, so a load burst or a frequency change lands on all
//     sizes alike instead of inflating whichever size was running at the time.
//
// Why: PR #4284's merge-queue round read 3.23x/doubling on wall-clock
// median-of-3; locally, 20 parallel runs under a busy loop read 3.88-7.32x
// (20/20 over 3.0) on wall time against 3.04-3.34x on this measure, the same
// spread as an idle host. A genuinely quadratic call is quadratic in its own
// CPU time, so none of this blunts the time arm;
// TestCalib_PlantedQuadraticTime_FiresRed (internal/libconformance) holds that.
//
// runtime.GC before each run gives TotalAlloc a clean, comparable baseline
// (TotalAlloc is a monotonic cumulative counter, so GC does not reset it — the
// GC is only to keep per-run heap state from drifting the time arm).
func measure(inputs [][]byte, call func(input []byte), repeats int) ([]Measurement, string) {
	cpus := make([][]int64, len(inputs))
	walls := make([][]int64, len(inputs))
	allocs := make([][]uint64, len(inputs))
	var m0, m1 runtime.MemStats
	for range repeats {
		for i, in := range inputs {
			runtime.GC()
			runtime.ReadMemStats(&m0)
			c0, cpuOK := processCPUNanos()
			start := time.Now()
			call(in)
			wall := time.Since(start).Nanoseconds()
			c1, cpuOK1 := processCPUNanos()
			runtime.ReadMemStats(&m1)
			cpu := int64(0)
			if cpuOK && cpuOK1 {
				cpu = c1 - c0
			}
			cpus[i] = append(cpus[i], cpu)
			walls[i] = append(walls[i], wall)
			allocs[i] = append(allocs[i], m1.TotalAlloc-m0.TotalAlloc)
		}
	}
	out := make([]Measurement, len(inputs))
	clock := "cpu"
	for i, in := range inputs {
		out[i] = Measurement{
			InputLen:   len(in),
			CPUNanos:   slices.Min(cpus[i]),
			WallNanos:  slices.Min(walls[i]),
			AllocBytes: medianUint64(allocs[i]),
		}
		if out[i].CPUNanos < cpuClockMinNanos {
			clock = "wall"
		}
	}
	for i := range out {
		out[i].Nanos = out[i].WallNanos
		if clock == "cpu" {
			out[i].Nanos = out[i].CPUNanos
		}
	}
	return out, clock
}

// cpuClockMinNanos is the shortest best-of-N CPU reading the time arm trusts.
// The process CPU clock ticks in 1 us on macOS, so a curve whose cheapest point
// is under 50 us (2% quantisation) is fit on wall time instead, for the whole
// curve: one clock per curve, never a mix. This never weakens the production
// path: with the default 3 ms TimeFloor a judged linear curve's cheapest point
// over factors 1..8 is ~375 us, and a curve this cheap is short enough that
// preemption, the load effect the CPU clock exists to remove, rarely hits it.
const cpuClockMinNanos = 50_000

// tailFraction selects the asymptotic regime for the fit: measurements whose
// cost is below maxCost/tailFraction are dropped before fitting. Super-linearity
// is an ASYMPTOTIC property — at small N a parser's fixed overhead (yaml's
// decoder state is ~7 KiB regardless of input) dominates and flattens the curve,
// so a geometric mean over every step is diluted toward "linear" by exactly the
// points where the quadratic term has not yet taken over. Dropping the
// constant-dominated head and fitting the tail is what makes the oracle fire on
// the disclosed yaml quadratic instead of averaging it away. 256 keeps roughly
// the top ~2.4 orders of magnitude of cost, which for a clean quadratic is the
// 3-4 largest size points — enough to fit, few enough to be all signal.
const tailFraction = 256

// doublingMultiplier fits cost ~ len^p over the asymptotic tail and returns 2^p:
// the factor by which cost grows when the input doubles. p is the slope of a
// least-squares line through (log len, log cost) over the tail points (those
// whose cost is within tailFraction of the maximum); the per-doubling multiplier
// is 2^p. A linear sink gives p~1 -> 2x; a quadratic one p~2 -> 4x. Fewer than
// two usable points (degenerate — all equal, or everything dropped) returns 1
// (no detectable growth), which can never trip the threshold.
func doublingMultiplier(ms []Measurement, cost func(Measurement) float64) float64 {
	maxc := 0.0
	for _, m := range ms {
		if c := cost(m); c > maxc {
			maxc = c
		}
	}
	if maxc <= 0 {
		return 1
	}
	threshold := maxc / tailFraction

	// Collect tail points in log-log space.
	var xs, ys []float64
	for _, m := range ms {
		c := cost(m)
		l := float64(m.InputLen)
		if l <= 0 || c < threshold {
			continue
		}
		xs = append(xs, math.Log(l))
		ys = append(ys, math.Log(c))
	}
	if len(xs) < 2 {
		return 1
	}

	// Least-squares slope of ys on xs.
	var sx, sy, sxx, sxy float64
	n := float64(len(xs))
	for i := range xs {
		sx += xs[i]
		sy += ys[i]
		sxx += xs[i] * xs[i]
		sxy += xs[i] * ys[i]
	}
	denom := n*sxx - sx*sx
	if denom == 0 {
		return 1 // all points at one size; no slope defined
	}
	p := (n*sxy - sx*sy) / denom
	if p < 0 {
		p = 0 // cost fell with size; treat as no growth, never negative
	}
	return math.Exp(p * math.Log(2)) // 2^p
}

func medianUint64(xs []uint64) uint64 {
	slices.Sort(xs)
	return xs[len(xs)/2]
}

func joinReasons(rs []string) string {
	out := ""
	for i, r := range rs {
		if i > 0 {
			out += "; "
		}
		out += r
	}
	return out
}

func formatMeasurements(ms []Measurement) string {
	out := "["
	for i, m := range ms {
		if i > 0 {
			out += " "
		}
		out += fmt.Sprintf("{len=%d cpu=%s wall=%s alloc=%d}", m.InputLen, time.Duration(m.CPUNanos), time.Duration(m.WallNanos), m.AllocBytes)
	}
	return out + "]"
}
