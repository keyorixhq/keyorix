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

// rgRun is the metered surface of the fuzz body: round-trip at MinCost, the
// wrong-password compare, and the cost-guarded hostile-hash compare. It mirrors
// FuzzBcryptRoundTripHostileHash without the assertions, so the cost recorded
// per input is the cost of what the target exercises.
func rgRun(password, hostileHash []byte) {
	if len(password) > 72 {
		password = password[:72]
	}
	if h, err := bcrypt.GenerateFromPassword(password, bcrypt.MinCost); err == nil {
		_ = bcrypt.CompareHashAndPassword(h, password)
		_ = bcrypt.CompareHashAndPassword(h, wrongPassword(password))
	}
	// Same cost-bomb guard as the fuzz body: never run 2^cost rounds on a
	// hostile declared cost.
	if cost, err := bcrypt.Cost(hostileHash); err == nil && cost <= bcrypt.DefaultCost {
		_ = bcrypt.CompareHashAndPassword(hostileHash, password)
	}
}

// rgBenignCosts measures rgRun over the benign seed pairs (valid hash, garbage
// hash, empty inputs, a max-length password) for calibration. The cost-bomb seed
// is excluded: rgRun skips it, so it would only add a near-zero sample.
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
		{[]byte("p"), nil},
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

// TestResguardBcrypt_RedGreen proves the budget is neither vacuous nor a false
// positive: a benign cost passes (GREEN), a 1 GiB alloc spike trips it (RED).
func TestResguardBcrypt_RedGreen(t *testing.T) {
	b := resguard.Calibrate("bcrypt_test", rgBenignCosts(t), resguard.DefaultFactor)
	delete(b.Meters, "live_heap")
	benign := rgBenignCosts(t)[0]
	var benignFired bool
	b.Check(func(string, ...any) { benignFired = true }, benign)
	if benignFired {
		t.Fatal("GREEN failed: benign cost tripped the budget")
	}
	red := benign
	red.AllocBytes = benign.AllocBytes*1000 + (1 << 30)
	red.Mallocs = benign.Mallocs*1000 + (1 << 20)
	red.AllocSampled = true
	var redFired bool
	b.Check(func(string, ...any) { redFired = true }, red)
	if !redFired {
		t.Fatal("RED failed: a 1 GiB alloc spike did not trip the budget")
	}
}
