package aead

import "testing"

// TestWipeDEK_ZeroesInPlace pins WipeDEK to zeroing the service's own DEK
// backing array (not a copy), and IsDEKWiped to reporting exactly that.
func TestWipeDEK_ZeroesInPlace(t *testing.T) {
	key, err := GenerateRandomKey(32)
	if err != nil {
		t.Fatal(err)
	}
	es, err := NewEncryptionService(key)
	if err != nil {
		t.Fatal(err)
	}
	ref := es.dek
	if es.IsDEKWiped() {
		t.Fatal("fresh random DEK reported as wiped")
	}
	es.WipeDEK()
	for i, b := range ref {
		if b != 0 {
			t.Fatalf("byte %d of the DEK backing array not zeroed", i)
		}
	}
	if !es.IsDEKWiped() {
		t.Fatal("IsDEKWiped false after WipeDEK")
	}
}
