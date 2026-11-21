package bcrypthostile

import (
	"os"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/resguard"
)

// rgBudgetPath is the committed resguard budget for FuzzBcryptRoundTripHostileHash.
// Regenerate with: RESGUARD_CALIBRATE=1 go test ./fuzz/thirdparty/bcrypt -run TestResguardBcryptCalibrate
const rgBudgetPath = "testdata/resguard-bcrypt.json"

// rgResult carries what rgRun computed, so FuzzBcryptRoundTripHostileHash
// asserts on the metered calls instead of repeating them.
type rgResult struct {
	hash         []byte
	genErr       error // GenerateFromPassword at MinCost
	roundTripErr error // the correct password against hash
	wrongErr     error // wrongPassword(password) against hash
}

// rgRun is the metered surface of the fuzz body: round-trip at MinCost, the
// wrong-password compare, and the cost-guarded hostile-hash compare. The fuzz
// target meters this call and asserts on its result, so the cost recorded per
// input is the cost of exactly what the target exercises, run once.
func rgRun(password, hostileHash []byte) (r rgResult) {
	if len(password) > 72 {
		password = password[:72]
	}
	r.hash, r.genErr = bcrypt.GenerateFromPassword(password, bcrypt.MinCost)
	if r.genErr == nil {
		r.roundTripErr = roundTripVerify(r.hash, password)
		r.wrongErr = bcrypt.CompareHashAndPassword(r.hash, wrongPassword(password))
	}
	// Same cost-bomb guard as before metering: never run 2^cost rounds on a
	// hostile declared cost. The result is ignored: a garbage hash normally
	// errors but could legitimately match; the oracle is no panic, bounded work.
	if cost, err := bcrypt.Cost(hostileHash); err == nil && cost <= bcrypt.DefaultCost {
		_ = bcrypt.CompareHashAndPassword(hostileHash, password)
	}
	return r
}

// rgBenignCosts measures rgRun over the benign seed pairs (valid hash, garbage
// hash, empty inputs, a max-length password) for calibration. The cost-bomb seed
// is excluded: rgRun skips it, so it would only add a near-zero sample. No
// seed is shorter than 10 bytes: Calibrate's per_byte is p99(value/n), and
// bcrypt's allocation is a near-constant floor plus a copy of the hostile hash
// (1 byte per byte), so a 1-byte seed only inflates the slope (it set per_byte
// to ~17 KB/byte, a ~6.9 MB ceiling at n=100). Short inputs stay covered by the
// floor: the ceiling is never below factor*floor. ModeAbsolute would be wrong
// here, because that hash copy does grow with input size.
func rgBenignCosts(tb testing.TB) []resguard.Cost {
	tb.Helper()
	valid, err := bcrypt.GenerateFromPassword([]byte("seed"), bcrypt.MinCost)
	if err != nil {
		tb.Fatalf("seed hash: %v", err)
	}
	long := make([]byte, 72)
	for i := range long {
		long[i] = byte('a' + i%26)
	}
	pairs := []struct{ pw, hash []byte }{
		{[]byte("correct horse battery staple"), []byte("$2a$04$abcdefghijklmnopqrstuu")},
		{[]byte(""), []byte("not-a-hash")},
		{[]byte("seed"), valid},
		{long, valid},
	}
	var costs []resguard.Cost
	for range 4 {
		for _, p := range pairs {
			probe := resguard.New(tb, resguard.Options{SampleEvery: 1})
			costs = append(costs, probe.Measure(len(p.pw)+len(p.hash), func() { rgRun(p.pw, p.hash) }))
		}
	}
	return costs
}

// TestResguardBcryptCalibrate regenerates the committed budget under RESGUARD_CALIBRATE=1.
func TestResguardBcryptCalibrate(t *testing.T) {
	b := resguard.Calibrate("bcrypt_roundtrip", rgBenignCosts(t), resguard.DefaultFactor)
	if _, ok := b.Meters["alloc_bytes"]; !ok {
		t.Fatalf("alloc_bytes should be calibrated; meters=%s", b.Summary())
	}
	// live_heap is a whole-process post-GC reading dominated by the fuzz engine's
	// own heap, not attributable to one input; alloc_bytes/mallocs stay fatal.
	delete(b.Meters, "live_heap")
	if os.Getenv("RESGUARD_CALIBRATE") == "1" {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := b.WriteJSON(rgBudgetPath); err != nil {
			t.Fatalf("write budget: %v", err)
		}
		t.Logf("wrote %s: %s", rgBudgetPath, b.Summary())
	}
}

// TestResguardBcrypt_RedGreen proves the COMMITTED budget (rgBudgetPath, the file
// the fuzz target loads) is armed and is neither vacuous nor a false positive:
// every benign cost passes it (GREEN) and a 1 GiB alloc spike trips it (RED).
func TestResguardBcrypt_RedGreen(t *testing.T) {
	b := rgLoadBudget(t)
	benign := rgBenignCosts(t)
	for i, c := range benign {
		var fired bool
		b.Check(func(string, ...any) { fired = true }, c)
		if fired {
			t.Fatalf("GREEN failed: benign cost #%d (%d bytes) tripped the committed budget: %s", i, c.InputLen, b.Summary())
		}
	}
	red := benign[0]
	red.AllocBytes = red.AllocBytes*1000 + (1 << 30)
	red.Mallocs = red.Mallocs*1000 + (1 << 20)
	red.AllocSampled = true
	var redFired bool
	b.Check(func(string, ...any) { redFired = true }, red)
	if !redFired {
		t.Fatal("RED failed: a 1 GiB alloc spike did not trip the committed budget")
	}
}

// rgLoadBudget loads the committed budget and fails closed: a missing,
// unparsable or zero-factor file, or one that does not arm the fatal
// alloc_bytes/mallocs meters, fails the caller instead of silently turning the
// resource oracle off.
func rgLoadBudget(tb testing.TB) resguard.Budget {
	tb.Helper()
	b, err := resguard.LoadBudget(rgBudgetPath)
	if err != nil {
		tb.Fatalf("no usable committed budget at %s (regenerate with RESGUARD_CALIBRATE=1 go test -run TestResguardBcryptCalibrate): %v", rgBudgetPath, err)
	}
	for _, m := range []string{"alloc_bytes", "mallocs"} {
		if mb, ok := b.Meters[m]; !ok || mb.Floor <= 0 {
			tb.Fatalf("committed budget %s does not arm the fatal meter %s: %s", rgBudgetPath, m, b.Summary())
		}
	}
	return b
}
