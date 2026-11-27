package libconformance

// FuzzPKCS7Sign and FuzzPKCS7SignWithChain fuzz the digitorus/pkcs7 signing
// pipeline: NewSignedData → AddSigner / AddSignerChain → Finish.
//
// # Motivation
//
// The signing surface (signing is attacker-OUTPUT, not attacker-input) is lower
// priority than the verify/decrypt surface (LS2).  It is still worth a
// never-panic/never-hang harness because:
//
//   - Keyorix code could call NewSignedData / AddSigner with attacker-influenced
//     plaintext or configuration, even though the resulting ciphertext is not
//     attacker-controlled on the way in.
//   - NewSignedData wraps the input bytes in an ASN.1 SEQUENCE; allocations are
//     proportional to input size, but this was never fuzz-verified.
//   - AddSignerChain builds a signer-info structure that includes the cert's
//     issuer, serial number, and digest of the content — all paths that could
//     panic on malformed cert or config inputs.
//
// # Shared oracle
//
// Both targets assert:
//   - Never panic (fuzzutil.Guard catches panics from the library)
//   - Never hang  (fuzzutil.Guard, 3 s budget)
//
// # Fuzz strategy
//
// The signed CONTENT (data) is the fuzz input.  The signer cert and key are
// harness-controlled (fixed ECDSA P-256 PKI from buildVerifyFuzzPKI).
// Rationale: the security-relevant input is the plaintext content (attacker-
// influenced), not the signing key (harness-controlled).
//
// FuzzPKCS7SignWithChain uses a 3-tier PKI (root → intermediate → leaf) to
// exercise the intermediate-certificate code path in AddSignerChain that
// FuzzPKCS7Sign's AddSigner (empty parents) does not reach.
//
// # Round-trip oracle (LS4 addition)
//
// Both FuzzPKCS7Sign and FuzzPKCS7SignWithChain carry a sign-then-verify
// round-trip oracle (LS3 LEFTOVERS item 3, completed in LS4): when Finish()
// succeeds, the resulting token is parsed via pkcs7.Parse and verified against
// the signing PKI's own root pool via VerifyWithChain.  This asserts that a
// token the library itself produced is verifiable by that same library's
// verifier — a failure here would indicate a sign/verify asymmetry in the
// library (e.g. a digest or encoding bug that makes the token unverifiable).
//
// What the round-trip oracle does NOT verify:
//   - Interoperability with OTHER PKCS7 implementations
//   - Determinism of the output (signing uses a random nonce via ECDSA)
//   - Correctness of SignWithoutAttr output (SignWithoutAttr tokens are NOT
//     verifiable by VerifyWithChain because authenticated attributes are
//     required; see FuzzPKCS7SignWithoutAttr for that target's oracle)
//
// # RemoveAuthenticatedAttributes COMPOSE (LS5 addition)
//
// Both FuzzPKCS7Sign and FuzzPKCS7SignWithChain carry a fuzz-driven boolean
// toggle `removeAuthAttrs` (LS5 COMPOSE decision).  When true, the harness
// calls sd.RemoveAuthenticatedAttributes() between AddSigner/AddSignerChain
// and Finish(), producing a token with no authenticated attributes in its
// ASN.1 encoding.
//
// Oracle when removeAuthAttrs == true: VerifyWithChain MUST return a non-nil
// error.  Rationale: AddSigner computed the ECDSA signature over
// marshalAttributes(finalAttrs) (authenticated attrs); after removal,
// verifySignature takes the else-branch of len(AuthenticatedAttributes)>0 and
// calls ee.CheckSignature(sigalg, p7.Content, sig_over_attrs) — the data
// argument is the raw content, not the attrs the signature was over, so
// CheckSignature returns a mismatch error.  The oracle asserts this code path
// returns error (not panic) on every fuzz input.
//
// Oracle when removeAuthAttrs == false: existing round-trip oracle (verify
// must succeed).
//
// What this COMPOSE oracle does NOT verify:
//   - Which specific error VerifyWithChain returns (only non-nil is checked)
//   - RemoveAuthenticatedAttributes on a SignedData with zero signerInfos
//     (safe by Go range semantics but not explicitly exercised here)
//
// # Signature drift check (LS3 requirement)
//
// Confirmed from `go doc github.com/digitorus/pkcs7` against pinned version
// v0.0.0-20261104125046-a476de3098e4 — no drift from LS1 inventory:
//
//	func NewSignedData(data []byte) (*SignedData, error)
//	func (sd *SignedData) AddSigner(ee *x509.Certificate, keyOrSigner interface{}, config SignerInfoConfig) error
//	func (sd *SignedData) AddSignerChain(ee *x509.Certificate, keyOrSigner interface{}, parents []*x509.Certificate, config SignerInfoConfig) error
//	func (sd *SignedData) Finish() ([]byte, error)

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/digitorus/pkcs7"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
)

// signFuzzPKI holds a 3-tier PKI for the signing harnesses.
type signFuzzPKI struct {
	root            *x509.Certificate
	rootKey         *ecdsa.PrivateKey
	intermediate    *x509.Certificate
	intermediateKey *ecdsa.PrivateKey
	leaf            *x509.Certificate
	leafKey         *ecdsa.PrivateKey
}

// buildSignFuzzPKI generates a minimal 3-tier ECDSA P-256 PKI:
// self-signed root → intermediate CA → leaf.
// The 3-tier PKI is needed to exercise AddSignerChain's intermediate-
// certificate code path.  The 2-tier PKI (root → leaf) is covered by
// buildVerifyFuzzPKI used in FuzzPKCS7Sign.
func buildSignFuzzPKI(tb testing.TB) *signFuzzPKI {
	tb.Helper()
	nb := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	na := time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("buildSignFuzzPKI: root key: %v", err)
	}
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(10),
		Subject:               pkix.Name{CommonName: "LS3 Sign Fuzz Root"},
		NotBefore:             nb,
		NotAfter:              na,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		tb.Fatalf("buildSignFuzzPKI: root cert: %v", err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		tb.Fatalf("buildSignFuzzPKI: parse root cert: %v", err)
	}

	intKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("buildSignFuzzPKI: intermediate key: %v", err)
	}
	intTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(11),
		Subject:               pkix.Name{CommonName: "LS3 Sign Fuzz Intermediate"},
		NotBefore:             nb,
		NotAfter:              na,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	intDER, err := x509.CreateCertificate(rand.Reader, intTmpl, root, &intKey.PublicKey, rootKey)
	if err != nil {
		tb.Fatalf("buildSignFuzzPKI: intermediate cert: %v", err)
	}
	intermediate, err := x509.ParseCertificate(intDER)
	if err != nil {
		tb.Fatalf("buildSignFuzzPKI: parse intermediate cert: %v", err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("buildSignFuzzPKI: leaf key: %v", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(12),
		Subject:               pkix.Name{CommonName: "LS3 Sign Fuzz Leaf"},
		NotBefore:             nb,
		NotAfter:              na,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, intermediate, &leafKey.PublicKey, intKey)
	if err != nil {
		tb.Fatalf("buildSignFuzzPKI: leaf cert: %v", err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		tb.Fatalf("buildSignFuzzPKI: parse leaf cert: %v", err)
	}

	return &signFuzzPKI{
		root:            root,
		rootKey:         rootKey,
		intermediate:    intermediate,
		intermediateKey: intKey,
		leaf:            leaf,
		leafKey:         leafKey,
	}
}

// FuzzPKCS7Sign fuzzes NewSignedData → AddSigner → [RemoveAuthenticatedAttributes →] Finish
// with arbitrary content.  Uses a 2-tier PKI (root → leaf) where AddSigner is called with
// no parent certificates (the common case).  Carries a sign-then-verify round-trip oracle
// (LS4) and a RemoveAuthenticatedAttributes COMPOSE oracle (LS5); see file header for details.
func FuzzPKCS7Sign(f *testing.F) {
	pki := buildVerifyFuzzPKI(f) // 2-tier PKI reused from verify harness

	f.Add([]byte("ls3-sign-fuzz-seed-content"), false)
	f.Add([]byte("ls5-remove-auth-attrs-seed"), true)
	f.Add([]byte{}, false)
	f.Add([]byte{}, true)
	f.Add(make([]byte, 1024), false)
	f.Add([]byte{0x30, 0x03, 0x02, 0x01, 0x01}, false)

	f.Fuzz(func(t *testing.T, data []byte, removeAuthAttrs bool) {
		var token []byte
		fuzzutil.Guard(t.Fatalf, "pkcs7.NewSignedData+AddSigner+[RemoveAuthAttrs+]Finish", func() {
			sd, err := pkcs7.NewSignedData(data)
			if err != nil {
				return
			}
			if err := sd.AddSigner(pki.leaf, pki.leafKey, pkcs7.SignerInfoConfig{}); err != nil {
				return
			}
			if removeAuthAttrs {
				sd.RemoveAuthenticatedAttributes()
			}
			out, err := sd.Finish()
			if err != nil {
				return
			}
			token = out
		})
		if len(token) == 0 {
			return
		}
		// Oracle: depends on removeAuthAttrs (see file header for full reasoning).
		fuzzutil.Guard(t.Fatalf, "pkcs7.AddSigner-verify-oracle", func() {
			p7, err := pkcs7.Parse(token)
			if err != nil {
				t.Fatalf("verify-oracle: Parse failed on our own output: %v", err)
			}
			verifyErr := p7.VerifyWithChain(pki.roots)
			if removeAuthAttrs {
				if verifyErr == nil {
					t.Fatalf("remove-auth-attrs oracle: VerifyWithChain should return error on auth-attr-stripped token but returned nil")
				}
			} else {
				if verifyErr != nil {
					t.Fatalf("sign-then-verify: VerifyWithChain rejected our own signed token: %v", verifyErr)
				}
			}
		})
	})
}

// FuzzPKCS7SignWithChain fuzzes NewSignedData → AddSignerChain → [RemoveAuthenticatedAttributes →]
// Finish with arbitrary content.  Uses a 3-tier PKI (root → intermediate → leaf) to exercise the
// intermediate-certificate code path in AddSignerChain.  Carries the same round-trip oracle (LS4)
// and RemoveAuthenticatedAttributes COMPOSE oracle (LS5) as FuzzPKCS7Sign; see file header.
func FuzzPKCS7SignWithChain(f *testing.F) {
	pki := buildSignFuzzPKI(f)

	chainRoots := x509.NewCertPool()
	chainRoots.AddCert(pki.root)

	f.Add([]byte("ls3-sign-chain-fuzz-seed-content"), false)
	f.Add([]byte("ls5-chain-remove-auth-attrs-seed"), true)
	f.Add([]byte{}, false)
	f.Add([]byte{}, true)
	f.Add(make([]byte, 1024), false)
	f.Add([]byte{0x30, 0x03, 0x02, 0x01, 0x01}, false)

	f.Fuzz(func(t *testing.T, data []byte, removeAuthAttrs bool) {
		var token []byte
		fuzzutil.Guard(t.Fatalf, "pkcs7.NewSignedData+AddSignerChain+[RemoveAuthAttrs+]Finish", func() {
			sd, err := pkcs7.NewSignedData(data)
			if err != nil {
				return
			}
			parents := []*x509.Certificate{pki.intermediate}
			if err := sd.AddSignerChain(pki.leaf, pki.leafKey, parents, pkcs7.SignerInfoConfig{}); err != nil {
				return
			}
			if removeAuthAttrs {
				sd.RemoveAuthenticatedAttributes()
			}
			out, err := sd.Finish()
			if err != nil {
				return
			}
			token = out
		})
		if len(token) == 0 {
			return
		}
		// Oracle: depends on removeAuthAttrs (see file header for full reasoning).
		fuzzutil.Guard(t.Fatalf, "pkcs7.AddSignerChain-verify-oracle", func() {
			p7, err := pkcs7.Parse(token)
			if err != nil {
				t.Fatalf("verify-oracle: Parse failed on our own output: %v", err)
			}
			verifyErr := p7.VerifyWithChain(chainRoots)
			if removeAuthAttrs {
				if verifyErr == nil {
					t.Fatalf("remove-auth-attrs oracle: VerifyWithChain should return error on auth-attr-stripped token but returned nil")
				}
			} else {
				if verifyErr != nil {
					t.Fatalf("sign-then-verify: VerifyWithChain rejected our own signed token: %v", verifyErr)
				}
			}
		})
	})
}
