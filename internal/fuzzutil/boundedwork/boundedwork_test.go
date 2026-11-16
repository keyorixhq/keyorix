package boundedwork

import (
	"encoding/json"
	"testing"
	"time"
)

// scaleFactor is the trivial scaler for the synthetic tests: the "input" is a
// byte slice whose length IS the work size, so factor f -> f*len bytes.
func scaleFactor(base []byte, factor int) []byte {
	return RepeatBytes(base, factor)
}

// linearWork does O(n) work and O(n) allocation — the shape of a correct parser.
func linearWork(input []byte) {
	buf := make([]byte, 0, len(input))
	var acc byte
	for _, b := range input {
		acc ^= b
		buf = append(buf, acc)
	}
	_ = buf
}

// quadraticTime does O(n^2) work with O(n) allocation — a duplicate-key style
// scan where every element is compared against every prior element.
func quadraticTime(input []byte) {
	var acc int
	for i := range input {
		for j := range input {
			if input[i] == input[j] {
				acc++
			}
		}
	}
	_ = acc
}

// quadraticAlloc allocates O(n^2) bytes: one n-sized buffer per input byte —
// the classic accidental-quadratic-memory shape (e.g. a parser that copies the
// whole remaining input at every token). O(n^2) total allocation, deterministic.
func quadraticAlloc(input []byte) {
	var sink byte
	for range input {
		buf := make([]byte, len(input))
		sink ^= buf[len(buf)-1]
	}
	_ = sink
}

// testCfg shrinks floors and repeats so the synthetic tests run fast and judge
// even the small inputs. The production default floors (3ms / 1MiB) exist to
// suppress noise on real sinks; here we deliberately lower them to exercise the
// fitting logic on cheap deterministic functions.
func testCfg() Config {
	return Config{
		Factors:     []int{1, 2, 4, 8, 16},
		Repeats:     3,
		MaxInputLen: 1 << 20,
		TimeFloor:   0, // judge regardless of absolute time
		AllocFloor:  1, // judge regardless of absolute alloc
		MaxDoubling: 3.0,
	}
}

func base(n int) []byte { return make([]byte, n) }

// TestOracle_GreenOnLinear is the GREEN half of the red-proof: a linear function
// must not trip the oracle.
func TestOracle_GreenOnLinear(t *testing.T) {
	v := Analyze("linear", base(256), scaleFactor, linearWork, testCfg())
	if v.SuperLinear {
		t.Fatalf("oracle fired on a LINEAR function (false positive): %s; %s", v.Reason, formatMeasurements(v.Measurements))
	}
	if !v.Judged {
		t.Fatalf("oracle did not judge the linear function at all: %s", v.Reason)
	}
	t.Logf("linear: time %.2fx/doubling alloc %.2fx/doubling", v.TimeDoubling, v.AllocDoubling)
}

// TestOracle_RedOnQuadraticAlloc is the deterministic RED half: O(n^2) allocation
// must trip the memory arm. TotalAlloc is deterministic for a deterministic
// function, so this is a clean, non-flaky red proof.
func TestOracle_RedOnQuadraticAlloc(t *testing.T) {
	v := Analyze("quadratic-alloc", base(256), scaleFactor, quadraticAlloc, testCfg())
	if !v.SuperLinear {
		t.Fatalf("oracle did NOT fire on O(n^2) allocation (false negative): %s; %s", v.Reason, formatMeasurements(v.Measurements))
	}
	if !v.AllocJudged || v.AllocDoubling <= 3.0 {
		t.Fatalf("expected alloc arm to exceed 3x/doubling, got %.2fx (%s)", v.AllocDoubling, v.Reason)
	}
	t.Logf("quadratic-alloc: alloc %.2fx/doubling — fired", v.AllocDoubling)
}

// TestOracle_RedOnQuadraticTime exercises the time arm. Time is noisy, so we
// assert via Analyze with a memory floor set high enough that only the time arm
// can judge, and accept that this arm is the flaky one (documented).
func TestOracle_RedOnQuadraticTime(t *testing.T) {
	cfg := testCfg()
	cfg.AllocFloor = 1 << 62 // force the memory arm below floor; only time can judge
	cfg.TimeFloor = 0
	cfg.Factors = []int{1, 2, 4, 8, 16, 32}
	v := Analyze("quadratic-time", base(512), scaleFactor, quadraticTime, cfg)
	if !v.SuperLinear {
		t.Fatalf("oracle did NOT fire on O(n^2) time (false negative): %s; %s", v.Reason, formatMeasurements(v.Measurements))
	}
	t.Logf("quadratic-time: time %.2fx/doubling — fired", v.TimeDoubling)
}

// TestOracle_BelowFloorNotJudged proves a cheap call draws no verdict rather
// than a linear one — the structural anti-false-positive guarantee.
func TestOracle_BelowFloorNotJudged(t *testing.T) {
	cfg := testCfg()
	cfg.TimeFloor = time.Hour // nothing reaches this
	cfg.AllocFloor = 1 << 62  // nor this
	v := Analyze("tiny", base(64), scaleFactor, quadraticAlloc, cfg)
	if v.Judged {
		t.Fatalf("expected no verdict below floors, but Judged=true (%s)", v.Reason)
	}
	if v.SuperLinear {
		t.Fatalf("oracle fired below floors — floors do not protect against false positives")
	}
}

// TestCheck_FailsViaFatalf proves the Check wrapper routes a super-linear verdict
// through fatalf (and stays silent otherwise).
func TestCheck_FailsViaFatalf(t *testing.T) {
	fired := false
	Check(func(string, ...any) { fired = true }, "qalloc", base(256), scaleFactor, quadraticAlloc, testCfg())
	if !fired {
		t.Fatal("Check did not call fatalf on a super-linear function")
	}
	fired = false
	Check(func(string, ...any) { fired = true }, "lin", base(256), scaleFactor, linearWork, testCfg())
	if fired {
		t.Fatal("Check called fatalf on a linear function")
	}
}

// TestScaleJSONArray_KeepsJSONValidAndGrowsElements pins the structural JSON
// scaler: every variant is one valid JSON array, factor-1 reaches minUnit, and
// factor k holds k times the factor-1 element count. Plain repetition
// (ScaleRepeat) of a JSON value is invalid after the first value, so a decoder
// stops early and its work never grows with the factor.
func TestScaleJSONArray_KeepsJSONValidAndGrowsElements(t *testing.T) {
	scale := ScaleJSONArray(512)
	for _, seed := range []string{`{"a":1}`, "0", `"x"`, "[1,2]"} {
		var n1 int
		for _, f := range []int{1, 2, 4, 8} {
			in := scale([]byte(seed), f)
			var arr []json.RawMessage
			if err := json.Unmarshal(in, &arr); err != nil {
				t.Fatalf("seed %q factor %d: not a valid JSON array: %v", seed, f, err)
			}
			if f == 1 {
				n1 = len(arr)
				if len(in) < 512 {
					t.Fatalf("seed %q: factor-1 variant is %d bytes, want >= 512", seed, len(in))
				}
			}
			if len(arr) != n1*f {
				t.Fatalf("seed %q factor %d: %d elements, want %d", seed, f, len(arr), n1*f)
			}
		}
	}
	// Not one valid JSON value: nothing to measure. `{":0} ` (from a fuzz run) has
	// an odd quote count, so an array of an even number of copies parses and an
	// odd number does not; scaling it bent a linear curve to 3.32x.
	for _, bad := range []string{"", `{":0} `, "a: 1\n", "[[[[", `{"a":1}{"a":1}`} {
		for _, f := range []int{1, 2, 4, 8} {
			if got := scale([]byte(bad), f); len(got) != 0 {
				t.Fatalf("base %q factor %d: got %d bytes, want 0 (not a single JSON value)", bad, f, len(got))
			}
		}
	}
	if got := ScaleRepeat(512)([]byte(`{"a":1}`), 2); json.Valid(got) {
		t.Fatalf("control: ScaleRepeat of a JSON object is expected to be invalid JSON")
	}
}
