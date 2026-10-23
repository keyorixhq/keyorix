package pqwrap

import (
	"bytes"
	"testing"
)

// FuzzParseEnvelope feeds arbitrary bytes to the envelope parser and to
// Unwrap. Oracles: neither panics; a successful parse re-marshals to exactly
// the input (one canonical encoding per envelope); and Unwrap succeeds only
// on the genuine envelope seeded below, never on any mutation of it.
func FuzzParseEnvelope(f *testing.F) {
	priv := testKey(f, SuiteX25519MLKEM768, "fuzz")
	priv1024 := testKey(f, SuiteX25519MLKEM1024, "fuzz")
	ctx := []byte("fuzz-ctx")
	genuine, err := Wrap(priv.PublicKey(), PurposeDEK, ctx, bytes.Repeat([]byte{1}, 32))
	if err != nil {
		f.Fatal(err)
	}
	genuine1024, err := Wrap(priv1024.PublicKey(), PurposeBackupKey, ctx, bytes.Repeat([]byte{2}, 64))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(genuine)
	f.Add(genuine1024)
	f.Add(genuine[:offKeyID])
	f.Add([]byte("KXPW"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		e, err := ParseEnvelope(data)
		if err == nil {
			if !bytes.Equal(e.Marshal(), data) {
				t.Fatalf("parse/marshal not canonical for %x", data)
			}
		}
		if _, err := Unwrap(priv, PurposeDEK, ctx, data); err == nil && !bytes.Equal(data, genuine) {
			t.Fatalf("a non-genuine envelope unwrapped: %x", data)
		}
		if _, err := Unwrap(priv1024, PurposeBackupKey, ctx, data); err == nil && !bytes.Equal(data, genuine1024) {
			t.Fatalf("a non-genuine 1024 envelope unwrapped: %x", data)
		}
	})
}
