package libconformance

// FuzzPKCS7SignWithoutAttr fuzzes the digitorus/pkcs7 SignWithoutAttr entry
// point: NewSignedData → SignWithoutAttr → Finish.
//
// # Motivation
//
// SignWithoutAttr is structurally identical to AddSigner (covered by
// FuzzPKCS7Sign, LS3) except that it omits authenticated attributes
// (ContentType, MessageDigest, SigningTime are NOT added to SignerInfo).
// The signed content is the data passed to NewSignedData; the signer cert and
// key are harness-controlled.  Keyorix code that calls SignWithoutAttr with
// attacker-influenced plaintext or configuration must not panic or hang.
//
// # Key difference from AddSigner
//
// AddSigner and AddSignerChain call a shared helper that appends
// OIDAttributeContentType, OIDAttributeMessageDigest, and
// OIDAttributeSigningTime to the signer info.  SignWithoutAttr skips that
// helper entirely — it computes and signs only the raw message digest, with an
// empty AuthenticatedAttributes field in the resulting SignerInfo.  This means
// the resulting PKCS#7 token CANNOT be verified by standard implementations
// that require authenticated attributes; it is a legacy / interoperability
// path.
//
// # Oracle
//
// Never panic, never hang (fuzzutil.Guard, 3 s budget).  No sign-then-verify
// round-trip oracle is applied because Verify() rejects tokens produced by
// SignWithoutAttr (the absence of the message-digest attribute causes
// verification to fail by design).
//
// # Fuzz strategy
//
// The signed CONTENT (data) is the fuzz input.  The signer cert and key are
// harness-controlled (fixed 3-tier ECDSA P-256 PKI from buildSignFuzzPKI,
// reused from FuzzPKCS7SignWithChain — the same PKI is shared to avoid
// duplicating the cert/key generation).
//
// # What these oracles do NOT verify
//
//   - Correctness of the signed output (no independent verifier)
//   - That authenticated attributes are absent in the output encoding
//   - Interoperability with other PKCS7 implementations
//   - Sign-then-verify round-trip (tokens produced by SignWithoutAttr are
//     not verifiable by Verify/VerifyWithChain because authenticated
//     attributes are required by those verifiers)
//
// # Signature drift check (LS4 requirement)
//
// Confirmed from pkcs7 source at
// /root/go/pkg/mod/github.com/digitorus/pkcs7@v0.0.0-20261104125046-a476de3098e4/
// on 2026-11-21 — no drift from LS1 inventory:
//
//	func (sd *SignedData) SignWithoutAttr(ee *x509.Certificate, keyOrSigner interface{}, config SignerInfoConfig) error

import (
	"testing"

	"github.com/digitorus/pkcs7"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
)

// FuzzPKCS7SignWithoutAttr fuzzes NewSignedData → SignWithoutAttr → Finish
// with arbitrary content bytes.  Uses the 3-tier PKI from buildSignFuzzPKI
// (reused from FuzzPKCS7SignWithChain — no duplication).
func FuzzPKCS7SignWithoutAttr(f *testing.F) {
	pki := buildSignFuzzPKI(f)

	f.Add([]byte("ls4-signwithoutattr-fuzz-seed-content"))
	f.Add([]byte{})
	f.Add(make([]byte, 1024))
	f.Add([]byte{0x30, 0x03, 0x02, 0x01, 0x01})

	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzutil.Guard(t.Fatalf, "pkcs7.NewSignedData+SignWithoutAttr+Finish", func() {
			sd, err := pkcs7.NewSignedData(data)
			if err != nil {
				return
			}
			if err := sd.SignWithoutAttr(pki.leaf, pki.leafKey, pkcs7.SignerInfoConfig{}); err != nil {
				return
			}
			_, _ = sd.Finish()
		})
	})
}
