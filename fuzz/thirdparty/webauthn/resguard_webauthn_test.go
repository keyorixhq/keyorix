package webauthnhostile

import (
	"bytes"
	"os"
	"testing"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/resguard"
)

// rgBudgetPath is the committed resguard budget for FuzzWebAuthnParsePublicKey.
// Regenerate with: RESGUARD_CALIBRATE=1 go test ./fuzz/thirdparty/webauthn -run TestResguardWebAuthnCalibrate
const rgBudgetPath = "testdata/resguard-webauthn.json"

// coseEC2Key is a structurally valid COSE_Key (EC2, ES256, P-256) with a dummy
// 32-byte x/y: {1:2, 3:-7, -1:1, -2:x, -3:y}. The parser decodes it; whether the
// point is on the curve is not this budget's concern.
func coseEC2Key() []byte {
	var b bytes.Buffer
	b.Write([]byte{0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01})
	b.Write([]byte{0x21, 0x58, 0x20})
	b.Write(bytes.Repeat([]byte{0x11}, 32))
	b.Write([]byte{0x22, 0x58, 0x20})
	b.Write(bytes.Repeat([]byte{0x22}, 32))
	return b.Bytes()
}

// rgBenignCosts measures parseKey over benign seeds (a valid-shaped EC2 key and
// the small malformed CBOR maps the target seeds) for calibration. The huge
// declared-length array seed is excluded: it is the hostile shape the budget
// exists to bound, not a calibration sample.
func rgBenignCosts(tb testing.TB) []resguard.Cost {
	tb.Helper()
	seeds := [][]byte{
		coseEC2Key(),
		{0xa0},
		{0xa1, 0x01, 0x02},
		{},
	}
	var costs []resguard.Cost
	for range 4 {
		for _, data := range seeds {
			probe := resguard.New(tb, resguard.Options{SampleEvery: 1})
			costs = append(costs, probe.Measure(len(data), func() { _, _ = parseKey(data) }))
		}
	}
	return costs
}

// TestResguardWebAuthnCalibrate regenerates the committed budget under RESGUARD_CALIBRATE=1.
func TestResguardWebAuthnCalibrate(t *testing.T) {
	b := resguard.Calibrate("webauthn_cose", rgBenignCosts(t), resguard.DefaultFactor)
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

// TestResguardWebAuthn_RedGreen proves the COMMITTED budget (rgBudgetPath, the file
// the fuzz target loads) is armed and is neither vacuous nor a false positive:
// every benign cost passes it (GREEN) and a 1 GiB alloc spike trips it (RED).
func TestResguardWebAuthn_RedGreen(t *testing.T) {
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
		tb.Fatalf("no usable committed budget at %s (regenerate with RESGUARD_CALIBRATE=1 go test -run TestResguardWebAuthnCalibrate): %v", rgBudgetPath, err)
	}
	for _, m := range []string{"alloc_bytes", "mallocs"} {
		if mb, ok := b.Meters[m]; !ok || mb.Floor <= 0 {
			tb.Fatalf("committed budget %s does not arm the fatal meter %s: %s", rgBudgetPath, m, b.Summary())
		}
	}
	return b
}
