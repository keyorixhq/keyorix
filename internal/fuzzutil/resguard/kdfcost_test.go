package resguard

import (
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/keyorixhq/keyorix/internal/kdfmeter"
)

// TestKDFMeter_CountsThroughProbe is the red/green proof that the resguard KDF
// seam counts password-hash invocations per input and resets between them. It
// drives the PRODUCTION seam (internal/kdfmeter) — the same functions core/admin
// now call — so a green here means the meter sees real production KDF calls.
func TestKDFMeter_CountsThroughProbe(t *testing.T) {
	kdf := NewKDFMeter()
	prev := kdf.Install()
	t.Cleanup(func() { kdfmeter.SetObserver(prev) })

	p := New(t, Options{KDF: kdf})

	// Input 1: one generate + two compares.
	var hash []byte
	c1 := p.Measure(1, func() {
		h, err := kdfmeter.GenerateFromPassword([]byte("pw"), bcrypt.MinCost)
		if err != nil {
			t.Fatalf("generate: %v", err)
		}
		hash = h
		_ = kdfmeter.CompareHashAndPassword(hash, []byte("pw"))
		_ = kdfmeter.CompareHashAndPassword(hash, []byte("nope"))
	})
	if c1.KDFGenerates != 1 || c1.KDFCompares != 2 {
		t.Fatalf("input 1: KDFGenerates=%d KDFCompares=%d, want 1/2", c1.KDFGenerates, c1.KDFCompares)
	}

	// Input 2: the per-input reset must zero the counts; this input does one
	// compare only. If reset were broken the counts would accumulate (3/3+).
	c2 := p.Measure(1, func() {
		_ = kdfmeter.CompareHashAndPassword(hash, []byte("pw"))
	})
	if c2.KDFGenerates != 0 || c2.KDFCompares != 1 {
		t.Fatalf("input 2 (after reset): KDFGenerates=%d KDFCompares=%d, want 0/1", c2.KDFGenerates, c2.KDFCompares)
	}

	// The Probe resets the meter at the start of every Measure (resetSeams), so
	// the live Generates()/Compares() reflect the LAST input only — not a
	// process-cumulative total. After input 2 that is 0 generates, 1 compare.
	if kdf.Generates() != 0 || kdf.Compares() != 1 {
		t.Fatalf("live totals after last Measure = %d/%d, want 0/1 (Probe resets per input)", kdf.Generates(), kdf.Compares())
	}
}

// TestKDFMeter_NilSeamIsZeroCost confirms a Probe with no KDF seam set leaves the
// Cost's KDF fields at zero and does not panic — the "leave nil to skip" contract.
func TestKDFMeter_NilSeamIsZeroCost(t *testing.T) {
	p := New(t, Options{})
	c := p.Measure(1, func() {
		_, _ = kdfmeter.GenerateFromPassword([]byte("pw"), bcrypt.MinCost)
	})
	if c.KDFGenerates != 0 || c.KDFCompares != 0 {
		t.Fatalf("nil KDF seam must report 0/0, got %d/%d", c.KDFGenerates, c.KDFCompares)
	}
}
