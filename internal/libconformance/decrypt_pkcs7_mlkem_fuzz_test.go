package libconformance

// FuzzPKCS7DecryptMLKEM768 fuzzes (*PKCS7).Decrypt with an ML-KEM-768
// recipient key — the post-quantum decapsulation path left uncovered by LS2.
//
// # Risk context
//
// LS2's FuzzPKCS7Decrypt uses a fixed RSA-2048 recipient certificate.  When
// a parsed PKCS7 envelope contains an OtherRecipientInfo (class 2, tag 4) with
// the KEM OID, pkcs7 dispatches to decryptKEMRecipientKey in kem.go, which
// parses the KEMRecipientInfo ASN.1 structure and calls the ML-KEM decapsulate
// function.  This path is never exercised by the RSA harness.
//
// The ML-KEM decapsulation path parses: OtherRecipientInfo → kemRecipientInfo
// (seven-field ASN.1 SEQUENCE) → Ciphertext []byte → decapsulate → AES key-unwrap.
// A bug in any of those parsing steps is reachable from the SAME notary
// endpoint that calls VerifyWithOpts, via pkcs7.Parse → p7.Decrypt.
//
// # Key construction
//
// crypto/mlkem is part of the Go 1.27 standard library (the version in use).
// mlkem.GenerateKey768() produces a *mlkem.DecapsulationKey768 that pkcs7's
// mlKEMDecapsulator() recognises.  The recipient certificate is constructed
// directly (not via x509.CreateCertificate, which does not support ML-KEM
// signing) with RawSubjectPublicKeyInfo set to the SPKI encoding of the
// encapsulation key.  This pattern mirrors pkcs7's own kem_test.go.
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
// Only ML-KEM-768 is covered (not 1024).  The kem.go code path is identical
// for both; only key size and ciphertext length differ.  The 768 harness
// exercises the full parsing and decapsulation logic.
//
// # Oracle
//
//   - Never panic (fuzzutil.Guard catches panics from the library)
//   - Never hang  (fuzzutil.Guard, 3 s budget)
//
// # What this oracle does NOT verify
//
//   - Correct decrypted plaintext (not checked)
//   - ML-KEM-1024 decapsulation path (identical code, only size differs)
//   - Bounded allocation for the decapsulation path (covered by
//     FuzzDigitorusPKCS7BoundedWork for the BER-decode step; symmetric
//     decryption allocation is bounded by already-decoded ciphertext size)
//
// # Signature drift check (LS3 requirement)
//
// Confirmed from `go doc github.com/digitorus/pkcs7` against pinned version
// v0.0.0-20261104125046-a476de3098e4 — no drift from LS1/LS2 for Decrypt:
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

// mlkemFuzzCert holds the ML-KEM-768 decapsulation key and the matching
// recipient certificate built from it.
type mlkemFuzzCert struct {
	cert *x509.Certificate
	key  *mlkem.DecapsulationKey768
}

// mlkemSPKI is the SubjectPublicKeyInfo ASN.1 structure used to encode the
// ML-KEM-768 encapsulation key into a certificate.  Mirrors the unexported
// subjectPublicKeyInfo type in pkcs7's kem.go.
type mlkemSPKI struct {
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

// buildMLKEM768FuzzCert generates a fresh ML-KEM-768 decapsulation key and
// a matching recipient certificate with the encapsulation key in its
// RawSubjectPublicKeyInfo.  The certificate is built directly (not via
// x509.CreateCertificate) following pkcs7's own kem_test.go pattern.
func buildMLKEM768FuzzCert(tb testing.TB) *mlkemFuzzCert {
	tb.Helper()
	key, err := mlkem.GenerateKey768()
	if err != nil {
		tb.Fatalf("buildMLKEM768FuzzCert: generating ML-KEM-768 key: %v", err)
	}
	ekBytes := key.EncapsulationKey().Bytes()

	spki := mlkemSPKI{
		Algorithm: pkix.AlgorithmIdentifier{Algorithm: pkcs7.OIDKeyAlgorithmMLKEM768},
		PublicKey: asn1.BitString{Bytes: ekBytes, BitLength: len(ekBytes) * 8},
	}
	spkiDER, err := asn1.Marshal(spki)
	if err != nil {
		tb.Fatalf("buildMLKEM768FuzzCert: marshaling SPKI: %v", err)
	}

	cert := &x509.Certificate{
		RawIssuer:               []byte{0x30, 0x00},
		RawSubjectPublicKeyInfo: spkiDER,
		SerialNumber:            big.NewInt(42),
		SubjectKeyId:            []byte("ls3-mlkem768-fuzz-key-id"),
		KeyUsage:                x509.KeyUsageKeyEncipherment,
		PublicKeyAlgorithm:      x509.UnknownPublicKeyAlgorithm,
		NotBefore:               time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:                time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	return &mlkemFuzzCert{cert: cert, key: key}
}

// buildMLKEM768SeedEnvelope builds a valid ML-KEM-768 encrypted PKCS7 envelope.
// Sets pkcs7.ContentEncryptionAlgorithm to AES256CBC for construction (ML-KEM
// requires AES-CBC) and restores the original value immediately after.
// Called once at harness setup; the global mutation is safe (single-threaded
// before f.Fuzz starts; the fuzz loop does not read the global).
func buildMLKEM768SeedEnvelope(tb testing.TB, rc *mlkemFuzzCert) []byte {
	tb.Helper()
	prev := pkcs7.ContentEncryptionAlgorithm
	pkcs7.ContentEncryptionAlgorithm = pkcs7.EncryptionAlgorithmAES256CBC
	env, err := pkcs7.Encrypt([]byte("ls3-mlkem768-decrypt-seed"), []*x509.Certificate{rc.cert})
	pkcs7.ContentEncryptionAlgorithm = prev
	if err != nil {
		tb.Fatalf("buildMLKEM768SeedEnvelope: Encrypt: %v", err)
	}
	return env
}

// FuzzPKCS7DecryptMLKEM768 fuzzes the ML-KEM-768 decapsulation path of
// (*PKCS7).Decrypt with arbitrary envelope bytes and a fixed key.
func FuzzPKCS7DecryptMLKEM768(f *testing.F) {
	rc := buildMLKEM768FuzzCert(f)
	goodEnv := buildMLKEM768SeedEnvelope(f, rc)

	// Positive control: the seed must decrypt successfully before fuzzing starts.
	// If not, the oracle is vacuous (the ML-KEM path is unreachable from the seed).
	seedP7, err := pkcs7.Parse(goodEnv)
	if err != nil {
		f.Fatalf("positive control: pkcs7.Parse(goodEnv) failed: %v", err)
	}
	plaintext, err := seedP7.Decrypt(rc.cert, rc.key)
	if err != nil {
		f.Fatalf("positive control: Decrypt(goodEnv) failed: %v — ML-KEM-768 path not exercised", err)
	}
	if string(plaintext) != "ls3-mlkem768-decrypt-seed" {
		f.Fatalf("positive control: Decrypt returned wrong plaintext %q", plaintext)
	}

	// Seed 0: good ML-KEM-768 envelope → exercises the full KEM decapsulation
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
		fuzzutil.Guard(t.Fatalf, "pkcs7.Decrypt(ML-KEM-768)", func() {
			_, _ = p7.Decrypt(rc.cert, rc.key)
		})
	})
}
