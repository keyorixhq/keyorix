package encryption

import (
	"encoding/json"
	"testing"
)

// FuzzDecrypt feeds arbitrary JSON-encoded EncryptedData blobs into Decrypt and
// DecryptWithAAD. Neither must ever panic — returning an error for any corrupt,
// truncated, or tampered input is the only acceptable outcome.
func FuzzDecrypt(f *testing.F) {
	// Fixed KEK: deterministic across all runs so the corpus is reproducible.
	kek := make([]byte, 32)
	for i := range kek {
		kek[i] = byte(i + 1)
	}
	svc, err := NewEncryptionService(kek)
	if err != nil {
		f.Fatal(err)
	}

	// Seed 1: a real encrypted blob — gives the mutator a valid JSON shape to work from.
	enc, err := svc.Encrypt([]byte("hello fuzz"), "v1")
	if err != nil {
		f.Fatal(err)
	}
	seed, err := json.Marshal(enc)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)

	// Seed 2: a real AAD-bound blob.
	encAAD, err := svc.EncryptWithAAD([]byte("hello aad fuzz"), "v1", SecretAAD(1, 2, 3))
	if err != nil {
		f.Fatal(err)
	}
	seedAAD, err := json.Marshal(encAAD)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seedAAD)

	// Seed 3: structurally valid JSON but wrong-length nonce (exercises the nonce-length guard).
	f.Add([]byte(`{"data":"AAEC","metadata":{"algorithm":"AES-256-GCM","key_version":"v1","encrypted_at":"2026-01-01T00:00:00Z","nonce":"AAAA"}}`))
	f.Add([]byte("{}"))
	f.Add([]byte(""))

	f.Fuzz(func(t *testing.T, data []byte) {
		ed, err := DeserializeEncryptedData(data)
		if err != nil {
			return // invalid JSON — expected
		}
		_, _ = svc.Decrypt(ed)
		_, _ = svc.DecryptWithAAD(ed, SecretAAD(1, 2, 3))
		_, _ = svc.DecryptWithAAD(ed, nil)
	})
}

// FuzzDecryptChunked feeds arbitrary JSON-encoded []*EncryptedData arrays into
// DecryptChunked. Reorder, splice, truncation, and corrupt-nonce inputs must all
// return errors, never panics.
func FuzzDecryptChunked(f *testing.F) {
	kek := make([]byte, 32)
	for i := range kek {
		kek[i] = byte(i + 1)
	}
	svc, err := NewEncryptionService(kek)
	if err != nil {
		f.Fatal(err)
	}

	// Seed: a real two-chunk encryption.
	chunks, err := svc.EncryptChunked([]byte("hello chunked fuzz world"), 12, "v1")
	if err != nil {
		f.Fatal(err)
	}
	seed, err := json.Marshal(chunks)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte("[]"))
	f.Add([]byte("[{}]"))
	f.Add([]byte("[{},{}]"))

	f.Fuzz(func(t *testing.T, data []byte) {
		var chunks []*EncryptedData
		if err := json.Unmarshal(data, &chunks); err != nil {
			return
		}
		_, _ = svc.DecryptChunked(chunks)
	})
}
