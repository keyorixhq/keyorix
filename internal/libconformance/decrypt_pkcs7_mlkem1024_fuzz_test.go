package libconformance

// FuzzPKCS7DecryptMLKEM1024 fuzzes (*PKCS7).Decrypt with an ML-KEM-1024
// recipient key — the second post-quantum decapsulation path.
//
// # Risk context
//
// LS3's FuzzPKCS7DecryptMLKEM768 covers the ML-KEM-768 decapsulation path.
// This harness covers the ML-KEM-1024 path, which LS3 documented as an
// explicit leftover: "The kem.go code path is identical for both; only key
// size and ciphertext length differ."  Confirmation (2026-11-21): verified in
// pkcs7@v0.0.0-20261104125046-a476de3098e4 — mlKEMDecapsulator is a type-switch
// with a symmetric branch for *mlkem.DecapsulationKey1024; encapsulateForCertificate
// has an identical branch for OIDKeyAlgorithmMLKEM1024.  No behavioural
// asymmetry found between 768 and 1024 paths.
//
// The reachability chain is the same as the 768 harness: a notary endpoint
// that calls VerifyWithOpts can also call p7.Decrypt; a panic in the ML-KEM
// parsing path (OtherRecipientInfo → kemRecipientInfo → decapsulate →
// AES key-unwrap) is directly reachable from pkcs7.Parse → p7.Decrypt.
//
// # Key construction
//
// mlkem.GenerateKey1024() produces a *mlkem.DecapsulationKey1024 that
// pkcs7's mlKEMDecapsulator() recognises.  The recipient certificate is
// constructed directly (not via x509.CreateCertificate, which does not
// support ML-KEM signing) with RawSubjectPublicKeyInfo set to the SPKI
// encoding of the encapsulation key.  This pattern mirrors pkcs7's own
// kem_test.go.
//
// # ContentEncryptionAlgorithm global
//
// ML-KEM requires AES-CBC content encryption (not the default DES-CBC).
// pkcs7.ContentEncryptionAlgorithm is set to AES256CBC before the seed
// envelope is built and restored immediately after.  This is safe: fuzz
// harness setup is single-threaded before f.Fuzz starts, and the fuzz loop
// calls only Parse and Decrypt, neither of which reads the global.
//
// # Scope narrowing (documented choice)
//
// Only ML-KEM-1024 is covered here.  ML-KEM-768 is covered by
// FuzzPKCS7DecryptMLKEM768 (decrypt_pkcs7_mlkem_fuzz_test.go).
//
// # Oracle
//
//   - Never panic (fuzzutil.Guard catches panics from the library)
//   - Never hang  (fuzzutil.Guard, 3 s budget)
//
// # What this oracle does NOT verify
//
//   - Correct decrypted plaintext (not checked)
//   - ML-KEM-768 decapsulation path (covered by FuzzPKCS7DecryptMLKEM768)
//   - Bounded allocation for the decapsulation path (covered by
//     FuzzDigitorusPKCS7BoundedWork for the BER-decode step; symmetric
//     decryption allocation is bounded by already-decoded ciphertext size)
//
// # Signature drift check (LS6 requirement)
//
// Confirmed from pkcs7@v0.0.0-20261104125046-a476de3098e4 — no drift for Decrypt:
//
//	func (p7 *PKCS7) Decrypt(cert *x509.Certificate, pkey crypto.PrivateKey) ([]byte, error)

import (
	"crypto/mlkem"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/digitorus/pkcs7"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
)

// mlkem1024FuzzCert holds the ML-KEM-1024 decapsulation key and the matching
// recipient certificate built from it.
type mlkem1024FuzzCert struct {
	cert *x509.Certificate
	key  *mlkem.DecapsulationKey1024
}

// buildMLKEM1024FuzzCert generates a fresh ML-KEM-1024 decapsulation key and
// a matching recipient certificate with the encapsulation key in its
// RawSubjectPublicKeyInfo.  The certificate is built directly (not via
// x509.CreateCertificate) following pkcs7's own kem_test.go pattern.
func buildMLKEM1024FuzzCert(tb testing.TB) *mlkem1024FuzzCert {
	tb.Helper()
	key, err := mlkem.GenerateKey1024()
	if err != nil {
		tb.Fatalf("buildMLKEM1024FuzzCert: generating ML-KEM-1024 key: %v", err)
	}
	ekBytes := key.EncapsulationKey().Bytes()

	spki := mlkemSPKI{
		Algorithm: pkix.AlgorithmIdentifier{Algorithm: pkcs7.OIDKeyAlgorithmMLKEM1024},
		PublicKey: asn1.BitString{Bytes: ekBytes, BitLength: len(ekBytes) * 8},
	}
	spkiDER, err := asn1.Marshal(spki)
	if err != nil {
		tb.Fatalf("buildMLKEM1024FuzzCert: marshaling SPKI: %v", err)
	}

	cert := &x509.Certificate{
		RawIssuer:               []byte{0x30, 0x00},
		RawSubjectPublicKeyInfo: spkiDER,
		SerialNumber:            big.NewInt(43),
		SubjectKeyId:            []byte("ls6-mlkem1024-fuzz-key-id"),
		KeyUsage:                x509.KeyUsageKeyEncipherment,
		PublicKeyAlgorithm:      x509.UnknownPublicKeyAlgorithm,
		NotBefore:               time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:                time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	return &mlkem1024FuzzCert{cert: cert, key: key}
}

// buildMLKEM1024SeedEnvelope builds a valid ML-KEM-1024 encrypted PKCS7
// envelope.  Sets pkcs7.ContentEncryptionAlgorithm to AES256CBC for
// construction (ML-KEM requires AES-CBC) and restores the original value
// immediately after.  Called once at harness setup; the global mutation is
// safe (single-threaded before f.Fuzz starts; the fuzz loop does not read
// the global).
func buildMLKEM1024SeedEnvelope(tb testing.TB, rc *mlkem1024FuzzCert) []byte {
	tb.Helper()
	prev := pkcs7.ContentEncryptionAlgorithm
	pkcs7.ContentEncryptionAlgorithm = pkcs7.EncryptionAlgorithmAES256CBC
	env, err := pkcs7.Encrypt([]byte("ls6-mlkem1024-decrypt-seed"), []*x509.Certificate{rc.cert})
	pkcs7.ContentEncryptionAlgorithm = prev
	if err != nil {
		tb.Fatalf("buildMLKEM1024SeedEnvelope: Encrypt: %v", err)
	}
	return env
}

// FuzzPKCS7DecryptMLKEM1024 fuzzes the ML-KEM-1024 decapsulation path of
// (*PKCS7).Decrypt with arbitrary envelope bytes and a fixed key.
func FuzzPKCS7DecryptMLKEM1024(f *testing.F) {
	rc := buildMLKEM1024FuzzCert(f)
	goodEnv := buildMLKEM1024SeedEnvelope(f, rc)

	// Positive control: the seed must decrypt successfully before fuzzing starts.
	// If not, the oracle is vacuous (the ML-KEM-1024 path is unreachable from the seed).
	seedP7, err := pkcs7.Parse(goodEnv)
	if err != nil {
		f.Fatalf("positive control: pkcs7.Parse(goodEnv) failed: %v", err)
	}
	plaintext, err := seedP7.Decrypt(rc.cert, rc.key)
	if err != nil {
		f.Fatalf("positive control: Decrypt(goodEnv) failed: %v — ML-KEM-1024 path not exercised", err)
	}
	if string(plaintext) != "ls6-mlkem1024-decrypt-seed" {
		f.Fatalf("positive control: Decrypt returned wrong plaintext %q", plaintext)
	}

	// Seed 0: good ML-KEM-1024 envelope → exercises the full KEM decapsulation
	// happy path (OtherRecipientInfo → kemRecipientInfo → decapsulate → AES
	// key-unwrap → content decrypt).
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
		fuzzutil.Guard(t.Fatalf, "pkcs7.Decrypt(ML-KEM-1024)", func() {
			_, _ = p7.Decrypt(rc.cert, rc.key)
		})
	})
}
