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
	// The genuine envelopes come from the fixed-randomness vector path, not
	// Wrap: every fuzz worker process runs this setup, and the oracle below
	// needs all of them to agree on which bytes are genuine.
	v768 := buildVector(f, vectorInputs()[0])
	v1024 := buildVector(f, vectorInputs()[3])
	priv, err := NewPrivateKeyFromSeed(SuiteX25519MLKEM768, mustHex(f, v768.Seed))
	if err != nil {
		f.Fatal(err)
	}
	priv1024, err := NewPrivateKeyFromSeed(SuiteX25519MLKEM1024, mustHex(f, v1024.Seed))
	if err != nil {
		f.Fatal(err)
	}
	ctx768, ctx1024 := mustHex(f, v768.Context), mustHex(f, v1024.Context)
	genuine, genuine1024 := mustHex(f, v768.Envelope), mustHex(f, v1024.Envelope)
	f.Add(genuine)
	f.Add(genuine1024)
	f.Add(genuine[:offKeyID])
	f.Add([]byte("KXPW"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		e, err := ParseEnvelope(data)
		if err == nil {
			out, err := e.Marshal()
			if err != nil {
				t.Fatalf("Marshal refused a parsed envelope %x: %v", data, err)
			}
			if !bytes.Equal(out, data) {
				t.Fatalf("parse/marshal not canonical for %x", data)
			}
		}
		if _, err := Unwrap(priv, PurposeDEK, ctx768, data); err == nil && !bytes.Equal(data, genuine) {
			t.Fatalf("a non-genuine envelope unwrapped: %x", data)
		}
		if _, err := Unwrap(priv1024, PurposeBackupKey, ctx1024, data); err == nil && !bytes.Equal(data, genuine1024) {
			t.Fatalf("a non-genuine 1024 envelope unwrapped: %x", data)
		}
	})
}
