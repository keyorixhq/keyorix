package precishostile

import (
	"os"
	"testing"

	"golang.org/x/text/secure/precis"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/resguard"
)

// rgBudgetPath is the committed resguard budget for FuzzPrecisProfileIdempotent.
// Regenerate with: RESGUARD_CALIBRATE=1 go test ./fuzz/thirdparty/precis -run TestResguardPrecisCalibrate
const rgBudgetPath = "testdata/resguard-precis.json"

// rgProfiles are the profiles the target covers, in rgRun's result order: the
// folded identity-name profile and the opaque address profile.
var rgProfiles = [...]struct {
	name string
	p    *precis.Profile
}{
	{"folded", foldedProfile},
	{"address", addressProfile},
}

// rgEnforced is one profile's first String enforcement of the input.
type rgEnforced struct {
	out string
	err error
}

// rgRun is the metered surface: String enforcement under every rgProfiles
// entry. FuzzPrecisProfileIdempotent meters this call and builds its
// determinism and idempotence checks on the result, so the first enforcement
// is not repeated outside the measurement.
func rgRun(s string) (r [len(rgProfiles)]rgEnforced) {
	for i, pp := range rgProfiles {
		r[i].out, r[i].err = pp.p.String(s)
	}
	return r
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

// TestResguardPrecis_RedGreen proves the COMMITTED budget (rgBudgetPath, the file
// the fuzz target loads) is armed and is neither vacuous nor a false positive:
// every benign cost passes it (GREEN) and a 1 GiB alloc spike trips it (RED).
func TestResguardPrecis_RedGreen(t *testing.T) {
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
		tb.Fatalf("no usable committed budget at %s (regenerate with RESGUARD_CALIBRATE=1 go test -run TestResguardPrecisCalibrate): %v", rgBudgetPath, err)
	}
	for _, m := range []string{"alloc_bytes", "mallocs"} {
		if mb, ok := b.Meters[m]; !ok || mb.Floor <= 0 {
			tb.Fatalf("committed budget %s does not arm the fatal meter %s: %s", rgBudgetPath, m, b.Summary())
		}
	}
	return b
}
