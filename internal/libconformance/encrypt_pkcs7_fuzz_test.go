package libconformance

// FuzzPKCS7Encrypt and FuzzPKCS7EncryptUsingPSK fuzz the two pkcs7 encryption
// entry points.
//
// # Motivation
//
// Encryption is attacker-OUTPUT (Keyorix calls these to produce ciphertext
// it controls, not to process attacker-supplied ciphertext).  They are still
// worth a never-panic/never-hang harness because:
//
//   - `Encrypt` with an attacker-influenced plaintext exercises the content
//     allocation and buffer-building code path; a panic or hang under
//     adversarial plaintext content is still a defect.
//   - `EncryptUsingPSK` accepts both the content and the key as inputs; a
//     wrong-sized key returns an error from the cipher constructor, but should
//     never panic.
//
// Both functions use the `ContentEncryptionAlgorithm` package-level global to
// select the cipher.  The harnesses leave this at its default (DES-CBC) for
// Encrypt and test multiple fixed key sizes for EncryptUsingPSK to exercise
// the cipher-selection branching.
//
// # Shared oracle
//
//   - Never panic (fuzzutil.Guard catches panics from the library)
//   - Never hang  (fuzzutil.Guard, 3 s budget)
//
// # What these oracles do NOT verify
//
//   - Correctness of the ciphertext (not cross-verified)
//   - Interoperability with other implementations
//   - ML-KEM / AES-GCM content encryption paths (covered by
//     FuzzPKCS7DecryptMLKEM768 and future LS4 harnesses)
//
// # Signature drift check (LS3 requirement)
//
// Confirmed from `go doc github.com/digitorus/pkcs7` against pinned version
// v0.0.0-20261104125046-a476de3098e4 — no drift from LS1 inventory:
//
//	func Encrypt(content []byte, recipients []*x509.Certificate) ([]byte, error)
//	func EncryptUsingPSK(content []byte, key []byte) ([]byte, error)

import (
	"crypto/x509"
	"testing"

	"github.com/digitorus/pkcs7"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
)

// FuzzPKCS7Encrypt fuzzes pkcs7.Encrypt with arbitrary content and a fixed
// RSA-2048 recipient certificate.  The recipient cert is harness-controlled
// (not fuzzed); the content is the attacker-influenced input.
func FuzzPKCS7Encrypt(f *testing.F) {
	rc := buildDecryptFuzzCert(f) // RSA-2048 self-signed cert from decrypt harness

	f.Add([]byte("ls3-encrypt-fuzz-seed-content"))
	f.Add([]byte{})
	f.Add(make([]byte, 1024))
	f.Add([]byte{0x00, 0x01, 0x02, 0x03})

	f.Fuzz(func(t *testing.T, content []byte) {
		fuzzutil.Guard(t.Fatalf, "pkcs7.Encrypt", func() {
			_, _ = pkcs7.Encrypt(content, []*x509.Certificate{rc.cert})
		})
	})
}

// FuzzPKCS7EncryptUsingPSK fuzzes pkcs7.EncryptUsingPSK with arbitrary
// content and arbitrary PSK bytes.  Exercises the cipher-key-size validation
// path (DES requires 8 bytes, AES requires 16/24/32; a wrong size must return
// an error, not panic).
func FuzzPKCS7EncryptUsingPSK(f *testing.F) {
	// Seed 0: valid DES-CBC content + 8-byte key (default algorithm).
	f.Add([]byte("ls3-encrypt-psk-fuzz-seed"), []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08})
	// Seed 1: empty content, valid key.
	f.Add([]byte{}, []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08})
	// Seed 2: valid content, empty key → error from cipher, not panic.
	f.Add([]byte("content"), []byte{})
	// Seed 3: valid content, wrong key size → error from cipher, not panic.
	f.Add([]byte("content"), []byte{0x01, 0x02, 0x03})
	// Seed 4: large content, valid key.
	f.Add(make([]byte, 1024), []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08})

	f.Fuzz(func(t *testing.T, content []byte, key []byte) {
		fuzzutil.Guard(t.Fatalf, "pkcs7.EncryptUsingPSK", func() {
			_, _ = pkcs7.EncryptUsingPSK(content, key)
		})
	})
}
