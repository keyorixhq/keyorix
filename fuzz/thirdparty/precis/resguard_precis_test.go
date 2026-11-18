package precishostile

import (
	"os"
	"testing"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/resguard"
)

// rgBudgetPath is the committed resguard budget for FuzzPrecisProfileIdempotent.
// Regenerate with: RESGUARD_CALIBRATE=1 go test ./fuzz/thirdparty/precis -run TestResguardPrecisCalibrate
const rgBudgetPath = "testdata/resguard-precis.json"

// rgRun is the metered surface: String enforcement under both profiles the
// target covers (the folded identity-name profile and the opaque address profile).
func rgRun(s string) {
	_, _ = foldedProfile.String(s)
	_, _ = addressProfile.String(s)
}

// rgBenignCosts measures rgRun over benign seeds (plain, mixed-case, combining
// marks, ligatures, a long ASCII name) for calibration.
func rgBenignCosts(tb testing.TB) []resguard.Cost {
	tb.Helper()
	long := make([]byte, 256)
	for i := range long {
		long[i] = byte('a' + i%26)
	}
	seeds := []string{
		"Admin",
		"PROD_KEY",
		" leading space ",
		"café",
		"ﬀ",
		"İstanbul",
		"Å",
		string(long),
	}
	var costs []resguard.Cost
	for range 4 {
		for _, s := range seeds {
			probe := resguard.New(tb, resguard.Options{SampleEvery: 1})
			costs = append(costs, probe.Measure(len(s), func() { rgRun(s) }))
		}
	}
	return costs
}

// TestResguardPrecisCalibrate regenerates the committed budget under RESGUARD_CALIBRATE=1.
func TestResguardPrecisCalibrate(t *testing.T) {
	b := resguard.Calibrate("precis_enforce", rgBenignCosts(t), resguard.DefaultFactor)
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

// TestResguardPrecis_RedGreen proves the budget is neither vacuous nor a false
// positive: a benign cost passes (GREEN), a 1 GiB alloc spike trips it (RED).
func TestResguardPrecis_RedGreen(t *testing.T) {
	b := resguard.Calibrate("precis_test", rgBenignCosts(t), resguard.DefaultFactor)
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
