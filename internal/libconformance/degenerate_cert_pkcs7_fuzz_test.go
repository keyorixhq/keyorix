package libconformance

// FuzzPKCS7DegenerateCertificate fuzzes pkcs7.DegenerateCertificate —
// a utility that wraps a raw certificate (or certificate chain) DER blob
// into a degenerate PKCS#7 SignedData container with no signers.
//
// # Risk context (from LS1 inventory, rank 14, score 30)
//
// DegenerateCertificate is shape A (`func([]byte) (T, error)`) in bwgen's
// classification: it takes raw bytes and returns a parsed/serialised result.
// bwgen found it as a bounded-work candidate (run 2026-11-21).
//
// # bwgen usage decision
//
// bwgen's standard seeds are generic text strings ("a: 1\n", "{\"a\":1}",
// etc.) that cause DegenerateCertificate to fail immediately at the
// asn1.Unmarshal step in marshalCertificateBytes (< 1 µs, < 1 KiB alloc).
// Putting the generated file into internal/boundedworksweep would cause
// TestBoundedWorkSweep_EveryTargetJudgesASeed to fail (alloc < AllocFloor 1 MiB,
// time < TimeFloor 3 ms on every text seed → "not judged").
// Hand-writing the harness in libconformance with a real DER certificate seed
// exercises the actual code path and avoids a CI-failing "green check that
// guards nothing".
//
// # Fuzz strategy
//
// Seed: a real DER-encoded certificate.  Fuzz input is the raw cert bytes that
// get passed to DegenerateCertificate.
//
// # Oracle
//
//   - Never panic (fuzzutil.Guard catches panics from the library)
//   - Never hang  (fuzzutil.Guard, 3 s budget)
//
// The function either parses the input as ASN.1 cert bytes and wraps them, or
// returns an error.  Any panic on malformed input is a defect.
//
// # What this oracle does NOT verify
//
//   - Correctness of the SignedData wrapping (not checked)
//   - Validity of the wrapped certificate content (not checked)
//   - Round-trip stability (wrapping the same cert twice should be identical,
//     but this is not asserted here)
//
// # Signature drift check (LS3 requirement)
//
// Confirmed from `go doc github.com/digitorus/pkcs7` against pinned version
// v0.0.0-20261104125046-a476de3098e4 — no drift from LS1 inventory:
//
//	func DegenerateCertificate(cert []byte) ([]byte, error)

import (
	"testing"

	"github.com/digitorus/pkcs7"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
)

// FuzzPKCS7DegenerateCertificate fuzzes pkcs7.DegenerateCertificate with
// arbitrary byte inputs.
func FuzzPKCS7DegenerateCertificate(f *testing.F) {
	// Seed 0: a real DER-encoded RSA-2048 certificate (produced by
	// buildDecryptFuzzCert's helper pattern at harness init).  This exercises
	// the happy path where DegenerateCertificate successfully parses and wraps.
	rc := buildDecryptFuzzCert(f)
	f.Add(rc.cert.Raw)

	// Seed 1: a real ECDSA P-256 leaf cert from the verify harness PKI.
	// Different algorithm and key size; exercises the same wrapping path.
	pki := buildVerifyFuzzPKI(f)
	f.Add(pki.leaf.Raw)

	// Seed 2: minimal DER SEQUENCE — not a valid certificate but DER-ish.
	f.Add([]byte{0x30, 0x03, 0x02, 0x01, 0x01})

	// Seed 3: BER-ish prefix (matches existing pkcs7 seeds).
	f.Add([]byte("0\x81\xc400\x02\x01\xf8"))

	// Seed 4: empty input — must return an error, not panic.
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, cert []byte) {
		fuzzutil.Guard(t.Fatalf, "pkcs7.DegenerateCertificate", func() {
			_, _ = pkcs7.DegenerateCertificate(cert)
		})
	})
}
