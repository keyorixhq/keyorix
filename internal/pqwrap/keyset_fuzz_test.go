package pqwrap

import (
	"bytes"
	"testing"
)

// FuzzOpenKeyFile feeds arbitrary bytes to the key-file reader the server
// boots through. Oracles: no panic; a detected format never disagrees with
// what OpenKeyFile reports on success; a successful open always yields the
// one DEK sealed under the fuzz KEK (nobody without the KEK can make the
// reader accept a different DEK); and the escrow path never panics.
//
// Every worker seals its own genuine keyset (the randomness differs), but
// all of them share the KEK and DEK, so a genuine keyset from any worker
// opens in every other one to the same DEK and the oracle stays consistent.
func FuzzOpenKeyFile(f *testing.F) {
	kek, dek, id := tKEK("fuzz"), tDEK("fuzz"), tKEKID("fuzz")
	privs, pubs := tRecipients(f, "fuzz-a")
	ks := mustSeal(f, dek, kek, id, pubs)
	legacy, err := SealLegacy(dek, kek)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(ks)
	f.Add(mustSeal(f, dek, kek, id, nil))
	f.Add(legacy)
	f.Add(ks[:tKeysetHeaderSize])
	f.Add([]byte("KXKS"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		detected := DetectFormat(data)
		got, format, err := OpenKeyFile(data, kek)
		if err == nil {
			if format != detected {
				t.Fatalf("OpenKeyFile said %v, DetectFormat %v", format, detected)
			}
			if !bytes.Equal(got.DEK, dek) {
				t.Fatalf("reader accepted a key file yielding a foreign DEK: %x", data)
			}
		}
		_, _ = UnwrapRecipientSlot(data, 1, privs[0])
	})
}
