// Package complexity is a PerfFuzz-style cost oracle for algorithmic-complexity
// fuzzing. It runs a function on one input, measures the cost of that single
// call with deterministic proxies, and fails when cost grows out of proportion
// to the input size — the shape of an algorithmic-complexity DoS that a
// never-panic or correctness harness sails straight past because nothing
// crashes and the answer is still correct, it just took quadratically long.
//
// It is the ratio counterpart to internal/fuzzutil.Guard (which bounds only
// wall-clock) and to the internal/libconformance bounded-work targets (which
// bound a single generous absolute memory envelope). Guard answers "did it
// hang?"; the absolute envelope answers "did it blow a fixed ceiling?"; this
// answers the question neither does — "did cost per input byte stay bounded?",
// which fires on super-linear growth long before either an absolute ceiling or
// a 3-second hang is reached.
//
// Cost proxies, strongest first:
//
//   - Work counter (Measure…Work): a caller-supplied monotonic integer (e.g.
//     "number of nodes visited"). Fully deterministic, zero measurement noise;
//     use it whenever the library exposes, or can be made to expose, a counter.
//   - Allocated bytes: runtime.MemStats.TotalAlloc / Mallocs, sampled before
//     and after the call via runtime.ReadMemStats. This is accurate per call.
//     NOTE (measured, not assumed): the "modern" runtime/metrics counter
//     "/gc/heap/allocs:bytes" is tempting here but is flushed LAZILY from
//     per-P mcache stats — a single small allocation read back immediately
//     reads as 0, so it silently under-reports a single call's delta and is
//     unusable as a per-input proxy. ReadMemStats forces a stop-the-world that
//     flushes every per-P cache, so its delta is exact. The STW cost is
//     irrelevant here: a complexity fuzzer runs one input at a time, and the
//     inputs that matter are the ones that allocate a lot. Deterministic for a
//     given input modulo KiB-scale GC/runtime noise, swamped by the floor below.
//   - Allocation count: "/gc/heap/allocs:objects", same sampling.
//   - Wall time: measured but used ONLY as a coarse sanity guard (MaxWall),
//     never as the primary oracle — wall time is nondeterministic across a
//     shared, thermally-throttled host and would false-fire under load.
//
// This package imports neither "testing" nor any keyorix package, so it adds
// nothing to a non-test build and nothing to a fuzz binary's coverage map
// beyond the standard library (see internal/libconformance/doc.go for why leaf
// packages matter to fuzz cost). Check reports through a fatalf callback (pass
// t.Fatalf) exactly as fuzzutil.Guard does.
package complexity

import (
	"runtime"
	"time"
)

// Cost is the measured cost of a single call.
type Cost struct {
	AllocBytes   uint64        // bytes allocated during the call (cumulative-counter delta)
	AllocObjects uint64        // heap objects allocated during the call
	Work         uint64        // caller-supplied work-counter delta (0 if not measured)
	Wall         time.Duration // wall-clock of the call (sanity guard only)
}

// readAlloc returns the process-cumulative (bytes, objects) allocated so far.
// runtime.ReadMemStats forces a stop-the-world that flushes every per-P mcache,
// so the delta across a single call is exact (see package doc for why the
// runtime/metrics counter is not used).
func readAlloc() (bytes, objects uint64) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.TotalAlloc, m.Mallocs
}

// Measure runs fn once and returns its cost (allocated bytes/objects and wall
// time; Work is 0). The call itself must not allocate on behalf of the caller
// beyond fn, so the returned bytes are fn's own.
func Measure(fn func()) Cost {
	b0, o0 := readAlloc()
	start := time.Now()
	fn()
	wall := time.Since(start)
	b1, o1 := readAlloc()
	return Cost{
		AllocBytes:   b1 - b0,
		AllocObjects: o1 - o0,
		Wall:         wall,
	}
}

// MeasureWork runs fn once and additionally records the delta of a caller work
// counter read before and after. work is read via the supplied closure so the
// caller can return any monotonic counter (a package-level atomic, a field on a
// hooked parser, etc.). The work delta is the most reliable proxy because it is
// an exact integer with no measurement noise.
func MeasureWork(work func() uint64, fn func()) Cost {
	w0 := work()
	c := Measure(fn)
	c.Work = work() - w0
	return c
}

// Budget is a per-byte cost ceiling. Check fires when a single call's cost
// exceeds what a linear-ish parser of this input size could legitimately incur.
//
// The three knobs are independent; set only the ones that apply to a target:
//
//   - MaxAllocBytesPerByte + FloorBytes: alloc must stay within
//     FloorBytes + MaxAllocBytesPerByte·len(input). The floor absorbs constant
//     per-call overhead (so a 1-byte input is not judged against ~0 budget) and
//     GC/runtime noise; the slope is the actual complexity oracle.
//   - MaxWorkPerByte + FloorWork: same shape over the work counter.
//   - AbsMaxAllocBytes: a hard ceiling independent of input size — the
//     worst-case absolute cost permitted at the real upstream size limit
//     (compute it from Phase 0: ratio · limit). A regression that is "linear"
//     but with an enormous constant still fails here.
//   - MaxWall: coarse sanity only. Leave zero to disable (recommended for CI;
//     fuzzutil.Guard already bounds hangs). Set it generously for a local run.
type Budget struct {
	MaxAllocBytesPerByte float64
	FloorBytes           uint64
	AbsMaxAllocBytes      uint64

	MaxWorkPerByte float64
	FloorWork      uint64

	MaxWall time.Duration
}

// Check reports the first exceeded ceiling via fatalf (pass t.Fatalf). It
// returns true if a ceiling fired (the fuzzer will already have been told to
// fail via fatalf; the bool lets non-fuzz callers branch). inputLen is the size
// in bytes of the attacker-controlled input the ratio is measured against — NOT
// the size of any derived/expanded form, which is exactly the quantity an
// amplification attack inflates.
func (b Budget) Check(fatalf func(format string, args ...any), label string, inputLen int, c Cost) bool {
	if b.AbsMaxAllocBytes > 0 && c.AllocBytes > b.AbsMaxAllocBytes {
		fatalf("COMPLEXITY %s: allocated %d bytes for a %d-byte input, over the absolute ceiling %d (worst-case at the upstream size limit)",
			label, c.AllocBytes, inputLen, b.AbsMaxAllocBytes)
		return true
	}
	if b.MaxAllocBytesPerByte > 0 {
		budget := b.FloorBytes + uint64(float64(inputLen)*b.MaxAllocBytesPerByte)
		if c.AllocBytes > budget {
			fatalf("COMPLEXITY %s: allocated %d bytes for a %d-byte input (budget %d = %d floor + %.2f·N) — super-linear amplification",
				label, c.AllocBytes, inputLen, budget, b.FloorBytes, b.MaxAllocBytesPerByte)
			return true
		}
	}
	if b.MaxWorkPerByte > 0 {
		budget := b.FloorWork + uint64(float64(inputLen)*b.MaxWorkPerByte)
		if c.Work > budget {
			fatalf("COMPLEXITY %s: work counter %d for a %d-byte input (budget %d = %d floor + %.2f·N) — super-linear amplification",
				label, c.Work, inputLen, budget, b.FloorWork, b.MaxWorkPerByte)
			return true
		}
	}
	if b.MaxWall > 0 && c.Wall > b.MaxWall {
		fatalf("COMPLEXITY %s: wall %s for a %d-byte input exceeds sanity guard %s", label, c.Wall, inputLen, b.MaxWall)
		return true
	}
	return false
}
