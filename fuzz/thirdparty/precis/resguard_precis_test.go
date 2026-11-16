package precishostile

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/resguard"
)

// PK2: port the x/text/secure/precis target onto resguard. The existing
// idempotence + determinism + no-panic oracle is UNCHANGED; resguard meters the
// enforcement's resource cost. Fatal meters: alloc_bytes / mallocs / live_heap
// (per-byte slope). PRECIS enforcement (NFC normalise + casefold + bidi) is
// linear in input; this is a tripwire for a future super-linear regression.
// CPU/wall/goroutines advisory. Meters both profiles' String() enforcement.

const rgBudgetPath = "testdata/resguard-precis.json"

var rgWrite = flag.Bool("rgwrite", false, "regenerate the committed resguard budget JSON")

func rgRun(s string) {
	_, _ = foldedProfile.String(s)
	_, _ = addressProfile.String(s)
}

func rgBenignCorpus() []string {
	seeds := []string{"Admin", "PROD_KEY", " leading space ", "café", "İstanbul"}
	// Longer valid identity strings so the slope reflects per-byte enforce cost.
	for _, n := range []int{64, 256, 1024, 4096} {
		seeds = append(seeds, strings.Repeat("abcDEF123", n/9+1)[:n])
	}
	return seeds
}

func rgCalibrate(tb testing.TB) resguard.Budget {
	tb.Helper()
	var costs []resguard.Cost
	for _, seed := range rgBenignCorpus() {
		for range 4 {
			p := resguard.New(tb, resguard.Options{SampleEvery: 1})
			s := seed
			costs = append(costs, p.Measure(len(s), func() { rgRun(s) }))
		}
	}
	b := resguard.Calibrate("precis_enforce", costs, resguard.DefaultFactor)
	delete(b.Meters, "live_heap") // non-attributable process-heap snapshot (see yaml)
	return b
}

func TestResguardPrecisCalibrate(t *testing.T) {
	b := rgCalibrate(t)
	if _, ok := b.Meters["alloc_bytes"]; !ok {
		t.Fatalf("alloc_bytes must be calibrated; got %s", b.Summary())
	}
	if *rgWrite {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := b.WriteJSON(rgBudgetPath); err != nil {
			t.Fatalf("write budget: %v", err)
		}
		t.Logf("wrote %s: %s", rgBudgetPath, b.Summary())
	}
}

// TestResguardPrecisRedGreen proves the oracle. GREEN: a valid name passes. PRECIS
// enforcement is linear (NFC + casefold), so no natural amplifier; RED is a budget
// self-test (100× alloc of a benign enforce must trip the calibrated budget) — a
// watched regression tripwire.
func TestResguardPrecisRedGreen(t *testing.T) {
	b := rgCalibrate(t)

	benign := rgBenignCorpus()[7] // the 1024-char valid string
	pg := resguard.New(t, resguard.Options{SampleEvery: 1})
	green := pg.Measure(len(benign), func() { rgRun(benign) })
	if b.Check(func(string, ...any) {}, green) {
		t.Fatalf("benign name tripped the budget: alloc=%d for %d bytes", green.AllocBytes, len(benign))
	}

	// RED: an alloc 10× the calibrated ceiling at this input size.
	mb := b.Meters["alloc_bytes"]
	allowed := b.Factor * (mb.Floor + mb.PerByte*float64(len(benign)))
	red := green
	red.AllocBytes = uint64(allowed*10) + 1
	var msg string
	if !b.Check(func(f string, a ...any) { msg = fmt.Sprintf(f, a...) }, red) {
		t.Fatalf("a 10×-ceiling alloc amplification did NOT trip the budget (alloc=%d, ceiling=%.0f)", red.AllocBytes, allowed)
	}
	t.Logf("RED tripped (synthetic alloc=%d > 10× ceiling %.0f): %s", red.AllocBytes, allowed, msg)
}
