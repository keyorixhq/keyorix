package webauthnhostile

import (
	"flag"
	"fmt"
	"os"
	"testing"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/resguard"
)

// PK2: port the go-webauthn COSE/CBOR public-key target onto resguard. The
// existing no-panic + bounded-wall oracle is UNCHANGED; resguard meters the
// parse's resource cost. Fatal meters: alloc_bytes / mallocs / live_heap
// (per-byte slope) — a CBOR header that honoured a huge declared length without a
// limit would blow alloc; fxamacker/cbor caps it, so this is a tripwire on that
// cap regressing. CPU/wall/goroutines advisory. Meters ParsePublicKey only.

const rgBudgetPath = "testdata/resguard-webauthn.json"

var rgWrite = flag.Bool("rgwrite", false, "regenerate the committed resguard budget JSON")

func rgRun(data []byte) {
	_, _ = parseKey(data)
}

func rgBenignCorpus() [][]byte {
	// Small CBOR maps of varying size — the real COSE keys are small; the slope
	// reflects parse cost across that range.
	seeds := [][]byte{
		{0xa0},             // empty map
		{0xa1, 0x01, 0x02}, // {1:2}
		{0xa2, 0x01, 0x02, 0x03, 0x04},
	}
	// A few larger well-formed CBOR maps.
	for n := 4; n <= 40; n += 6 {
		m := []byte{0xb8, byte(n)} // map with n entries (uint8 count)
		for i := range n {
			m = append(m, 0x18, byte(i), 0x18, byte(i)) // int:int pairs
		}
		seeds = append(seeds, m)
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
	b := resguard.Calibrate("webauthn_cose", costs, resguard.DefaultFactor)
	delete(b.Meters, "live_heap") // non-attributable process-heap snapshot (see yaml)
	return b
}

func TestResguardWebAuthnCalibrate(t *testing.T) {
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

// TestResguardWebAuthnRedGreen proves the oracle. GREEN: a small CBOR map passes.
// RED: fxamacker/cbor's limits reject a huge declared length before allocating
// (the `0x9b ff ff ... ` seed is handled bounded), so no natural amplifier
// exists; RED is a budget self-test (100× alloc of a benign parse must trip the
// calibrated budget) — a watched regression tripwire.
func TestResguardWebAuthnRedGreen(t *testing.T) {
	b := rgCalibrate(t)

	benign := []byte{0xa1, 0x01, 0x02}
	pg := resguard.New(t, resguard.Options{SampleEvery: 1})
	green := pg.Measure(len(benign), func() { rgRun(benign) })
	if b.Check(func(string, ...any) {}, green) {
		t.Fatalf("benign CBOR tripped the budget: alloc=%d", green.AllocBytes)
	}

	// RED: an alloc 10× the calibrated ceiling at this input size — the RAM-spike
	// shape a future regression would produce.
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
