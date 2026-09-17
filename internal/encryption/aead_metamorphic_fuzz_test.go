package encryption

// aead_metamorphic_fuzz_test.go — FuzzAEADTamperRoundTrip.
//
// Metamorphic fuzzing of the AES-256-GCM AEAD core (Encrypt/Decrypt and the
// AAD-bound EncryptWithAAD/DecryptWithAAD). NewEncryptionService takes a raw KEK
// with no I/O, so this is pure and fast. The existing FuzzDecrypt only checks
// robustness against malformed blobs; this target asserts the AEAD security
// contract itself, all in sound directions (the plaintext/key are known, so each
// property either holds or is a real crypto defect):
//
//   - ROUND-TRIP: Decrypt(Encrypt(p)) == p, and the AAD-bound variant with a
//     matching AAD.
//   - TAMPER DETECTION (integrity): flipping any single bit of the ciphertext
//     (Data) or of the nonce must make decryption FAIL — a forged/altered
//     ciphertext is never accepted.
//   - AAD BINDING: decrypting an AAD-bound ciphertext with a DIFFERENT AAD, or
//     with no AAD, must fail (ciphertext-transplant protection); and an
//     AAD-bound ciphertext must not open on the plain (no-AAD) path.
//   - NONCE UNIQUENESS: two encryptions of the same plaintext use different
//     nonces (a repeat would be catastrophic nonce reuse under a fixed key).
//   - CROSS-KEY: a ciphertext sealed under one KEK must not open under a
//     different KEK.
//
// A violation of any of these is a real AEAD break: silent tamper acceptance,
// transplant, nonce reuse, or wrong-key acceptance.

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
)

func FuzzAEADTamperRoundTrip(f *testing.F) {
	f.Add([]byte("k"), []byte("plaintext"), []byte("aad"), uint16(0))
	f.Add([]byte{}, []byte{}, []byte{}, uint16(0))
	f.Add([]byte("key-material-32-bytes-padded!!"), []byte("hello fuzz"), []byte{}, uint16(7))
	f.Add([]byte("z%"), []byte("longer plaintext value here for coverage"), []byte("keyorix:v2:1:2:3"), uint16(129))

	f.Fuzz(func(t *testing.T, keySeed, plaintext, aad []byte, flip uint16) {
		fuzzutil.Guard(t.Fatalf, "AEAD tamper/round-trip", func() {
			checkAEADAlgebra(keySeed, plaintext, aad, flip)
		})
	})
}

// derive32 builds a 32-byte AES-256 key from arbitrary seed bytes (cycled/padded).
// Any 32 bytes is a valid key; a fixed filler keeps a short/empty seed deterministic.
func derive32(seed []byte) []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = 0x5c + byte(i) // deterministic filler so an empty seed still yields a fixed key
	}
	for i, b := range seed {
		k[i%32] ^= b
	}
	return k
}

func checkAEADAlgebra(keySeed, plaintext, aad []byte, flip uint16) {
	kek1 := derive32(keySeed)
	kek2 := append([]byte(nil), kek1...)
	kek2[0] ^= 0xFF // guaranteed different key

	svc1, err := NewEncryptionService(kek1)
	if err != nil {
		panic(fmt.Sprintf("NewEncryptionService(kek1): %v", err))
	}
	svc2, err := NewEncryptionService(kek2)
	if err != nil {
		panic(fmt.Sprintf("NewEncryptionService(kek2): %v", err))
	}

	// ---- ROUND-TRIP (no AAD) ----
	enc, err := svc1.Encrypt(plaintext, "v1")
	if err != nil {
		panic(fmt.Sprintf("Encrypt: %v", err))
	}
	got, err := svc1.Decrypt(enc)
	if err != nil {
		panic(fmt.Sprintf("round-trip: Decrypt of our own ciphertext failed: %v", err))
	}
	if !bytes.Equal(got, plaintext) {
		panic(fmt.Sprintf("round-trip: Decrypt returned %q, want %q", got, plaintext))
	}

	// ---- TAMPER: flip one bit of the ciphertext Data ----
	{
		tData := append([]byte(nil), enc.Data...)
		idx := int(flip>>3) % len(tData) // Data is >= the 16-byte GCM tag, never empty
		tData[idx] ^= 1 << (flip & 7)
		tampered := &EncryptedData{Data: tData, Metadata: enc.Metadata}
		if _, err := svc1.Decrypt(tampered); err == nil {
			panic(fmt.Sprintf("tamper-accept: Decrypt accepted a ciphertext with a flipped Data bit (idx=%d)", idx))
		}
	}

	// ---- TAMPER: flip one bit of the nonce ----
	{
		nonce, derr := base64.StdEncoding.DecodeString(enc.Metadata.Nonce)
		if derr == nil && len(nonce) > 0 {
			nidx := int(flip>>3) % len(nonce)
			nonce[nidx] ^= 1 << (flip & 7)
			md := enc.Metadata
			md.Nonce = base64.StdEncoding.EncodeToString(nonce)
			tampered := &EncryptedData{Data: enc.Data, Metadata: md}
			if out, err := svc1.Decrypt(tampered); err == nil && bytes.Equal(out, plaintext) {
				panic("tamper-accept: Decrypt accepted the original plaintext under a flipped nonce")
			}
		}
	}

	// ---- CROSS-KEY: our ciphertext must not open under a different KEK ----
	if _, err := svc2.Decrypt(enc); err == nil {
		panic("cross-key: a ciphertext sealed under kek1 decrypted under kek2")
	}

	// ---- NONCE UNIQUENESS: two encryptions use different nonces ----
	enc2, err := svc1.Encrypt(plaintext, "v1")
	if err != nil {
		panic(fmt.Sprintf("Encrypt (2nd): %v", err))
	}
	if enc.Metadata.Nonce == enc2.Metadata.Nonce {
		panic("nonce-reuse: two encryptions produced the same nonce under a fixed key")
	}

	// ---- AAD round-trip + binding (only meaningful when the AAD is non-empty) ----
	encA, err := svc1.EncryptWithAAD(plaintext, "v1", aad)
	if err != nil {
		panic(fmt.Sprintf("EncryptWithAAD: %v", err))
	}
	gotA, err := svc1.DecryptWithAAD(encA, aad)
	if err != nil {
		panic(fmt.Sprintf("aad round-trip: DecryptWithAAD with matching AAD failed: %v", err))
	}
	if !bytes.Equal(gotA, plaintext) {
		panic(fmt.Sprintf("aad round-trip: got %q, want %q", gotA, plaintext))
	}
	if len(aad) > 0 {
		// Different AAD must fail (transplant protection).
		aad2 := append([]byte(nil), aad...)
		aad2[0] ^= 0xFF
		if _, err := svc1.DecryptWithAAD(encA, aad2); err == nil {
			panic("aad-binding: DecryptWithAAD accepted a DIFFERENT AAD")
		}
		// Decrypting an AAD-bound ciphertext on the no-AAD path must fail.
		if _, err := svc1.Decrypt(encA); err == nil {
			panic("aad-binding: plain Decrypt accepted an AAD-bound ciphertext")
		}
		// Decrypting a plain (no-AAD) ciphertext WITH an AAD must fail.
		if _, err := svc1.DecryptWithAAD(enc, aad); err == nil {
			panic("aad-binding: DecryptWithAAD accepted a plain ciphertext under a non-empty AAD")
		}
	}
}
