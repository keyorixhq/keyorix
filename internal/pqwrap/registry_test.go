package pqwrap

import (
	"crypto/mlkem"
	"testing"
)

// TestSuiteRegistry_ClosedAndNeverClassicalOnly pins §5: the registry holds
// exactly the reviewed suites, and every one carries an ML-KEM component, so
// a downgrade to a classical-only wrap cannot be expressed in the format.
// Adding a suite means adding it here, with its own vectors.
func TestSuiteRegistry_ClosedAndNeverClassicalOnly(t *testing.T) {
	want := map[Suite]int{
		SuiteX25519MLKEM768:  mlkem.EncapsulationKeySize768,
		SuiteX25519MLKEM1024: mlkem.EncapsulationKeySize1024,
	}
	if len(suites) != len(want) {
		t.Fatalf("registry has %d suites, reviewed list has %d", len(suites), len(want))
	}
	for s, p := range suites {
		ek, ok := want[s]
		if !ok {
			t.Errorf("suite %v is not in the reviewed list", s)
			continue
		}
		if p.ekSize != ek || p.ctSize == 0 {
			t.Errorf("suite %v has no ML-KEM component of the expected size", s)
		}
	}
	if _, ok := suites[RecipientSuite]; !ok || RecipientSuite != SuiteX25519MLKEM1024 {
		t.Errorf("keyset recipients must use X25519 + ML-KEM-1024 (§7), RecipientSuite is %v", RecipientSuite)
	}
}
