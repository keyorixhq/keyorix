package libconformance

// FuzzPKCS7Decrypt fuzzes (*PKCS7).Decrypt — the RSA key-transport and
// ML-KEM decapsulation path.
//
// # Risk context (from LS1 inventory)
//
// Decrypt takes a *x509.Certificate and a crypto.PrivateKey.  It is "A*"
// (alloc-in-callee) because the decryption of the symmetric key and content
// happens in private helpers.  The LS1 risk score is 49 (Tier 1B).
//
// # Scope narrowing (documented choice)
//
// The certificate/key pair is FIXED (harness-generated, not fuzzed).  Fuzz
// input is the PKCS7 envelope only.  Rationale:
//
//   - RSA key generation (2048-bit) is expensive; doing it per fuzzer
//     iteration would dominate the per-input budget and stall throughput.
//   - The oracle (never panic, never hang) is about the library's behaviour
//     on adversarial ciphertext, not about generating valid recipient certs.
//   - A valid recipient cert is required by pkcs7.Encrypt to build any
//     realistic seed; without it, every seed is a raw DER blob that never
//     exercises the decryption code path.
//
// What this DOES NOT cover:
//   - ML-KEM/post-quantum decapsulation path (requires an ML-KEM-768/1024
//     public key; the harness uses RSA-2048 only, the same type pkcs7.Encrypt
//     uses by default for RSA recipients).  ML-KEM is left for LS3.
//   - Correct decrypted plaintext (not checked)
//   - Bounded-allocation regression for the decryption path (the BER-decode
//     allocation is covered by FuzzDigitorusPKCS7BoundedWork; the symmetric-
//     decryption allocation is bounded by the ciphertext size, which is
//     already decoded by Parse)
//
// # Oracle
//
//   - Never panic (fuzzutil.Guard)
//   - Never hang  (fuzzutil.Guard, 3 s budget)
//
// # Signature drift check (LS2 requirement)
//
// Confirmed from `go doc github.com/digitorus/pkcs7` against pinned version
// v0.0.0-20261104125046-a476de3098e4 — no drift from LS1 inventory:
//
//	func (p7 *PKCS7) Decrypt(cert *x509.Certificate, pkey crypto.PrivateKey) ([]byte, error)

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/digitorus/pkcs7"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
)

// decryptFuzzCert is the fixed recipient certificate used in FuzzPKCS7Decrypt.
// It is built once at harness setup.
type decryptFuzzCert struct {
	cert *x509.Certificate
	key  *rsa.PrivateKey
}

// buildDecryptFuzzCert generates a fresh RSA-2048 self-signed certificate
// suitable as a PKCS7 recipient.  RSA-2048 is used to match pkcs7.Encrypt's
// default key-transport algorithm (PKCS#1 v1.5).
func buildDecryptFuzzCert(tb testing.TB) *decryptFuzzCert {
	tb.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		tb.Fatalf("buildDecryptFuzzCert: generating RSA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "LS2 Fuzz Decrypt Recipient"},
		NotBefore:             time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageKeyEncipherment,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		tb.Fatalf("buildDecryptFuzzCert: creating cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		tb.Fatalf("buildDecryptFuzzCert: parsing cert: %v", err)
	}
	return &decryptFuzzCert{cert: cert, key: key}
}

// FuzzPKCS7Decrypt fuzzes the RSA-recipient decrypt path with arbitrary
// envelope bytes.  The recipient cert/key is fixed.
func FuzzPKCS7Decrypt(f *testing.F) {
	rc := buildDecryptFuzzCert(f)

	// Seed 0: a valid RSA-encrypted envelope produced by pkcs7.Encrypt.
	// This seed exercises the entire decrypt happy path and gives the fuzzer
	// a structurally correct starting point to mutate.
	goodEnv, err := pkcs7.Encrypt([]byte("ls2-decrypt-fuzz-seed"), []*x509.Certificate{rc.cert})
	if err != nil {
		f.Fatalf("FuzzPKCS7Decrypt: building seed envelope: %v", err)
	}
	f.Add(goodEnv)
	// Seed 1–3: structurally invalid inputs that exercise early-exit paths.
	f.Add([]byte{0x30, 0x03, 0x02, 0x01, 0x01})
	f.Add([]byte("0\x81\xc400\x02\x01\xf8"))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		p7, err := pkcs7.Parse(data)
		if err != nil {
			return
		}
		fuzzutil.Guard(t.Fatalf, "pkcs7.Decrypt", func() {
			_, _ = p7.Decrypt(rc.cert, rc.key)
		})
	})
}
