package complexity

import (
	"fmt"
	"strings"
	"testing"
)

// recordFatalf captures the first fatalf call so a test can assert both that a
// ceiling fired and what it said, without failing the test itself.
func recordFatalf(msg *string) func(string, ...any) {
	return func(format string, args ...any) {
		if *msg == "" {
			*msg = fmt.Sprintf(format, args...)
		}
	}
}

// ---- known-linear and known-quadratic subjects ------------------------------

// linearWork does work proportional to n.
func linearWork(n int) uint64 {
	var w uint64
	for i := 0; i < n; i++ {
		w++
	}
	return w
}

// quadraticWork does work proportional to n*n — the classic shape of an
// algorithmic-complexity bug (e.g. an O(n^2) dedup, a backtracking matcher).
func quadraticWork(n int) uint64 {
	var w uint64
	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			w++
		}
	}
	return w
}

// linearAlloc allocates ~n bytes; quadraticAlloc allocates ~n*n bytes.
func linearAlloc(n int) []byte    { return make([]byte, n) }
func quadraticAlloc(n int) []byte { return make([]byte, n*n) }

// TestWorkOracle_ClassifiesLinearVsQuadratic is the core calibration: a single
// Budget (per-byte work ceiling) must PASS a linear subject at large N and FIRE
// on a quadratic subject at the same N. If either direction is wrong the oracle
// is miscalibrated.
func TestWorkOracle_ClassifiesLinearVsQuadratic(t *testing.T) {
	const n = 4096
	// Allow up to 8 work units per input byte plus a generous floor. Linear does
	// ~1·N; quadratic does ~N·N = N per byte, i.e. 4096 per byte >> 8.
	b := Budget{MaxWorkPerByte: 8, FloorWork: 1024}

	var out string
	cLin := MeasureWork(func() uint64 { return 0 }, func() {})
	cLin.Work = linearWork(n) // deterministic; measure the subject directly
	if b.Check(recordFatalf(&out), "linear", n, cLin) {
		t.Fatalf("linear subject wrongly flagged: %s", out)
	}

	out = ""
	cQuad := Cost{Work: quadraticWork(n)}
	if !b.Check(recordFatalf(&out), "quadratic", n, cQuad) {
		t.Fatalf("quadratic subject (work=%d, N=%d) was NOT flagged — oracle blind to O(n^2)", cQuad.Work, n)
	}
	if !strings.Contains(out, "super-linear") {
		t.Fatalf("quadratic firing message = %q, want mention of super-linear", out)
	}
}

// TestAllocOracle_MeasuresAndClassifies exercises the real runtime/metrics path
// (not a hand-set Cost) and checks the alloc proxy separates linear from
// quadratic. Separation is huge (n vs n*n) so GC/runtime noise cannot flip it.
func TestAllocOracle_MeasuresAndClassifies(t *testing.T) {
	const n = 2048
	var sink []byte

	cLin := Measure(func() { sink = linearAlloc(n) })
	cQuad := Measure(func() { sink = quadraticAlloc(n) })
	_ = sink

	if cLin.AllocBytes < uint64(n) {
		t.Fatalf("linear alloc measured %d bytes, expected >= %d — measurement broken", cLin.AllocBytes, n)
	}
	if cQuad.AllocBytes < cLin.AllocBytes*10 {
		t.Fatalf("quadratic alloc (%d) not clearly above linear (%d) — measurement noise too high", cQuad.AllocBytes, cLin.AllocBytes)
	}

	// Budget: 16 bytes/input-byte + 256 KiB floor. Linear (~n bytes for n input
	// bytes => ~1/byte) passes; quadratic (~n*n bytes => n/byte = 2048/byte) fails.
	b := Budget{MaxAllocBytesPerByte: 16, FloorBytes: 256 << 10}

	var out string
	if b.Check(recordFatalf(&out), "linear-alloc", n, cLin) {
		t.Fatalf("linear alloc wrongly flagged: %s", out)
	}
	out = ""
	if !b.Check(recordFatalf(&out), "quad-alloc", n, cQuad) {
		t.Fatalf("quadratic alloc (bytes=%d, N=%d) NOT flagged — oracle blind to O(n^2) memory", cQuad.AllocBytes, n)
	}
}

// TestAbsoluteCeiling_Independent confirms the absolute ceiling fires on a
// large-constant regression that the per-byte slope alone would miss.
func TestAbsoluteCeiling_Independent(t *testing.T) {
	b := Budget{AbsMaxAllocBytes: 1 << 20} // 1 MiB hard cap
	var out string
	// "linear" in input but a 4 MiB constant blob regardless of N.
	c := Cost{AllocBytes: 4 << 20}
	if !b.Check(recordFatalf(&out), "const-blob", 10, c) {
		t.Fatal("absolute ceiling did not fire on a 4 MiB alloc for a 10-byte input")
	}
	if !strings.Contains(out, "absolute ceiling") {
		t.Fatalf("message = %q, want absolute-ceiling wording", out)
	}
}

// TestFloorAbsorbsTinyInputs confirms a tiny input is judged against the floor,
// not against ~zero budget — otherwise every empty/1-byte input false-fires on
// constant per-call overhead.
func TestFloorAbsorbsTinyInputs(t *testing.T) {
	b := Budget{MaxAllocBytesPerByte: 1, FloorBytes: 64 << 10}
	var out string
	c := Cost{AllocBytes: 32 << 10} // 32 KiB constant overhead, 0-byte input
	if b.Check(recordFatalf(&out), "tiny", 0, c) {
		t.Fatalf("floor did not absorb constant overhead on a 0-byte input: %s", out)
	}
}

// TestNoCeilingSetNeverFires: a zero Budget must never fire (all knobs opt-in).
func TestNoCeilingSetNeverFires(t *testing.T) {
	var b Budget
	var out string
	if b.Check(recordFatalf(&out), "none", 100, Cost{AllocBytes: 1 << 30, Work: 1 << 30, Wall: 0}) {
		t.Fatalf("empty budget fired: %s", out)
	}
}
