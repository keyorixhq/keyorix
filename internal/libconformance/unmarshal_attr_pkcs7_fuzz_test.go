package libconformance

// FuzzPKCS7UnmarshalSignedAttribute and FuzzPKCS7GetOnlySigner fuzz two
// (*PKCS7) methods that operate on a parsed, attacker-controlled envelope.
//
// # Motivation
//
// UnmarshalSignedAttribute takes the first signer's AuthenticatedAttributes,
// locates an attribute by OID, and ASN.1-decodes its raw value into the
// caller-supplied out pointer.  The input is an arbitrary byte envelope that
// parses via pkcs7.Parse; the OID and out type are harness-controlled.
// Because the attribute's raw encoding comes from attacker-supplied bytes,
// the ASN.1 unmarshal path must not panic or hang on any input.
//
// GetOnlySigner returns the signer certificate for a single-signer token and
// nil otherwise.  It does no allocation beyond a linear scan; the never-panic
// oracle still matters because an unexpected nil or corrupted certificate could
// propagate up the call chain.
//
// # Shared oracle
//
// Both targets assert:
//   - Never panic (fuzzutil.Guard catches panics from the library)
//   - Never hang  (fuzzutil.Guard, 3 s budget)
//
// # Fuzz strategy
//
// The RAW BYTES are the PKCS7 envelope (same as the Parse/verify harnesses,
// not the content-only strategy used by Sign/Encrypt).  After pkcs7.Parse
// succeeds, UnmarshalSignedAttribute is called once for each of the three
// standard signed-attribute OIDs (ContentType, MessageDigest, SigningTime)
// with the appropriately typed out pointer.  Errors from the unmarshal are
// expected and silently ignored — only panics and hangs are the oracle.
//
// Seeds include a valid token from buildVerifyFuzzSeed (a token with one
// signer, containing all three standard signed attributes) plus minimal DER
// inputs.
//
// # Positive controls
//
// Before f.Fuzz begins:
//   - GetOnlySigner on the seed token (exactly one signer) must return non-nil.
//   - UnmarshalSignedAttribute for OIDAttributeSigningTime on the seed token
//     must succeed and decode a non-zero time (confirms the standard attributes
//     are present in a token built by buildVerifyFuzzSeed via AddSignerChain).
//
// # What these oracles do NOT verify
//
//   - Correctness of the unmarshaled value (no independent ASN.1 cross-check)
//   - That the attribute is present (a "not found" error is silently ignored)
//   - Signer cert chain validity or the message-digest signature
//   - GetOnlySigner's return value correctness (we only assert non-nil on the
//     known-good seed; arbitrary fuzz inputs legitimately return nil)
//
// # Signature drift check (LS4 requirement)
//
// Confirmed from pkcs7 source at
// /root/go/pkg/mod/github.com/digitorus/pkcs7@v0.0.0-20261104125046-a476de3098e4/
// on 2026-11-21 — no drift from LS1 inventory:
//
//	func (p7 *PKCS7) GetOnlySigner() *x509.Certificate
//	func (p7 *PKCS7) UnmarshalSignedAttribute(attributeType asn1.ObjectIdentifier, out interface{}) error

import (
	"encoding/asn1"
	"testing"
	"time"

	"github.com/digitorus/pkcs7"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
)

// FuzzPKCS7GetOnlySigner fuzzes (*PKCS7).GetOnlySigner on arbitrary PKCS7
// envelopes.  For the known-good seed the positive control asserts non-nil.
func FuzzPKCS7GetOnlySigner(f *testing.F) {
	pki := buildVerifyFuzzPKI(f)
	seed := buildVerifyFuzzSeed(f, pki)

	// Positive control: seed has exactly one signer; GetOnlySigner must return non-nil.
	seedP7, err := pkcs7.Parse(seed)
	if err != nil {
		f.Fatalf("positive control: pkcs7.Parse(seed) failed: %v", err)
	}
	if seedP7.GetOnlySigner() == nil {
		f.Fatalf("positive control: GetOnlySigner returned nil on a single-signer seed token — fixture is broken")
	}

	f.Add(seed)
	f.Add([]byte{0x30, 0x03, 0x02, 0x01, 0x01})
	f.Add([]byte("0\x81\xc400\x02\x01\xf8"))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		p7, err := pkcs7.Parse(data)
		if err != nil {
			return
		}
		fuzzutil.Guard(t.Fatalf, "pkcs7.GetOnlySigner", func() {
			_ = p7.GetOnlySigner()
		})
	})
}

// FuzzPKCS7UnmarshalSignedAttribute fuzzes (*PKCS7).UnmarshalSignedAttribute
// on arbitrary PKCS7 envelopes, calling it for each of the three standard
// signed-attribute OIDs with the appropriately typed out pointer.
func FuzzPKCS7UnmarshalSignedAttribute(f *testing.F) {
	pki := buildVerifyFuzzPKI(f)
	seed := buildVerifyFuzzSeed(f, pki)

	// Positive control: OIDAttributeSigningTime must unmarshal successfully from
	// the seed token (AddSignerChain populates all three standard attributes).
	seedP7, err := pkcs7.Parse(seed)
	if err != nil {
		f.Fatalf("positive control: pkcs7.Parse(seed) failed: %v", err)
	}
	var checkTime time.Time
	if err := seedP7.UnmarshalSignedAttribute(pkcs7.OIDAttributeSigningTime, &checkTime); err != nil {
		f.Fatalf("positive control: UnmarshalSignedAttribute(SigningTime) failed on seed token — fixture is broken: %v", err)
	}
	if checkTime.IsZero() {
		f.Fatalf("positive control: UnmarshalSignedAttribute(SigningTime) returned zero time on seed token — fixture is broken")
	}

	f.Add(seed)
	f.Add([]byte{0x30, 0x03, 0x02, 0x01, 0x01})
	f.Add([]byte("0\x81\xc400\x02\x01\xf8"))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		p7, err := pkcs7.Parse(data)
		if err != nil {
			return
		}

		// ContentType → asn1.ObjectIdentifier
		fuzzutil.Guard(t.Fatalf, "pkcs7.UnmarshalSignedAttribute(ContentType)", func() {
			var contentType asn1.ObjectIdentifier
			_ = p7.UnmarshalSignedAttribute(pkcs7.OIDAttributeContentType, &contentType)
		})

		// MessageDigest → []byte
		fuzzutil.Guard(t.Fatalf, "pkcs7.UnmarshalSignedAttribute(MessageDigest)", func() {
			var digest []byte
			_ = p7.UnmarshalSignedAttribute(pkcs7.OIDAttributeMessageDigest, &digest)
		})

		// SigningTime → time.Time
		fuzzutil.Guard(t.Fatalf, "pkcs7.UnmarshalSignedAttribute(SigningTime)", func() {
			var signingTime time.Time
			_ = p7.UnmarshalSignedAttribute(pkcs7.OIDAttributeSigningTime, &signingTime)
		})
	})
}
