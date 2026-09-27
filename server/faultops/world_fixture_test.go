// world_fixture_test.go verifies each newFaultWorld fixture gap this PR closes
// works standalone, before any opCatalog entry (PR B's job) depends on it —
// the fixtures are lazy (built on first use, see each ensure* method's own doc
// comment), so nothing in the existing opCatalog exercises them yet.
package faultops

import "testing"

func TestWorldFixture_Encryption(t *testing.T) {
	w := newFaultWorld(t, nil)
	if err := w.ensureEncryption(t); err != nil {
		t.Fatalf("ensureEncryption: %v", err)
	}
	if !w.core.SecretValueEncryptionActive() {
		t.Fatal("secret-value encryption not active after ensureEncryption")
	}
	// Calling twice must be safe (sync.Once-guarded) and not re-derive the KEK.
	if err := w.ensureEncryption(t); err != nil {
		t.Fatalf("ensureEncryption (second call): %v", err)
	}
}

func TestWorldFixture_WebAuthn(t *testing.T) {
	w := newFaultWorld(t, nil)
	if !w.core.WebAuthnEnabled() {
		t.Fatal("WebAuthnEnabled() is false after newFaultWorld — SetWebAuthn was not wired")
	}
}
