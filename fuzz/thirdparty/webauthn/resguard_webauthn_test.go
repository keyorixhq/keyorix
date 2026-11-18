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

// TestResguardWebAuthn_RedGreen proves the budget is neither vacuous nor a false
// positive: a benign cost passes (GREEN), a 1 GiB alloc spike trips it (RED).
func TestResguardWebAuthn_RedGreen(t *testing.T) {
	b := resguard.Calibrate("webauthn_test", rgBenignCosts(t), resguard.DefaultFactor)
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
