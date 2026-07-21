package notary

import (
	"crypto/x509"
	"testing"
)

// FuzzVerifyReceipt feeds arbitrary bytes as an RFC 3161 TimeStampToken into
// VerifyReceipt. The fuzz target is the two external ASN.1/DER parsers inside:
// digitorus/timestamp.Parse (RFC 3161 token structure) and digitorus/pkcs7.Parse
// (PKCS#7 envelope). Both must return errors on malformed input, never panic.
//
// An empty but non-nil CertPool is used so the fuzzer bypasses the nil-roots
// guard and reaches the parse layers. Chain verification will always fail (no
// trusted root is configured), which is fine — the goal is parser robustness, not
// valid receipt verification.
func FuzzVerifyReceipt(f *testing.F) {
	roots := x509.NewCertPool() // non-nil → reaches timestamp.Parse; empty → chain always fails
	message := []byte("fuzz anchor message")

	f.Add([]byte{})
	f.Add([]byte("not DER at all"))
	// Minimal DER SEQUENCE (empty) — a structurally recognisable starting point
	// for the mutator to build valid-ish DER from.
	f.Add([]byte{0x30, 0x00})
	// SEQUENCE with one content byte.
	f.Add([]byte{0x30, 0x01, 0x00})
	// Claimed length longer than actual content — classic DER truncation.
	f.Add([]byte{0x30, 0x10, 0x00})

	f.Fuzz(func(t *testing.T, token []byte) {
		// Must never panic.
		_, _ = VerifyReceipt(roots, message, token)
	})
}
