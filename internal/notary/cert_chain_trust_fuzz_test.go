package notary

// FuzzCertChainTrustInvariant is a fail-closed CHAIN-OF-TRUST fuzzer for
// VerifyReceipt — the one place in this codebase that makes an x509 certificate
// CHAIN trust decision over attacker-influenced bytes (notary.go's own doc comment:
// "an attacker who can write the checkpoint row ... could mint a self-signed token
// over the same bytes"; VerifyReceipt is the gate that must reject that forgery).
//
// Every OTHER candidate x509-trust context named in this task's investigation brief
// was checked and does not exist as described in this codebase (see the 2026-09-XX
// cert-chain-trust investigation notes):
//   - mTLS client-cert auth: no `tls.Config.ClientAuth`/`ClientCAs` anywhere in the
//     repo (grep confirmed zero hits); every server tls.Config leaves ClientAuth at
//     its zero value (tls.NoClientCert). Not implemented.
//   - SAML IdP signing cert: crewjam/saml compares the XML signature against the
//     EXACT admin-configured IdP certificate from metadata — a whole-cert pin, not
//     a CA-chain decision. No x509.VerifyOptions/CertPool anywhere in internal/saml.
//   - TPM/attestation: internal/crypto/tpm_provider.go seals/unseals a KEK to a TPM
//     2.0 device — no x509 certificate of any kind involved.
//   - OIDC/JWKS x5c: internal/core/oidc_jwks.go's parseJWK builds an *rsa.PublicKey /
//     *ecdsa.PublicKey directly from JWK n/e or x/y coordinates. Zero "x5c" hits
//     anywhere in the repo — no certificate chain is ever built from a JWKS.
//   - "existing FuzzValidateWithCert": no such function exists (grepped the repo and
//     GitHub code search). The closest existing target is FuzzVerifyReceipt
//     (notary_fuzz_test.go), which asserts a DIFFERENT, narrower invariant: with an
//     EMPTY (non-nil) root pool, VerifyReceipt must always reject. It never
//     constructs a real configured root R, so it cannot catch the
//     same-subject-impostor-root confusion this harness targets — that is genuinely
//     new coverage, not a duplicate.
//   - Kubernetes CA pools (internal/k8ssync, internal/dynamic/kubernetes.go) and the
//     SIEM/webhook InsecureSkipVerify toggles (server/main.go) are real
//     tls.Config{RootCAs:...} trust decisions, but every input (CA bundle, the
//     InsecureSkipVerify bool itself) is admin/operator-configured — not an
//     attacker-facing byte stream — and use plain, un-customised tls.Config (no
//     hand-rolled VerifyPeerCertificate/VerifyConnection anywhere in the repo,
//     confirmed by a repo-wide grep). Out of scope for an attacker-facing harness.
//   - internal/core/certificate.go (InspectCertificate) parses/selects a leaf from
//     an admin's OWN already-authorized secret value for DISPLAY — no
//     x509.VerifyOptions/CertPool/.Verify() anywhere in the file, so no trust
//     decision exists there to test.
//
// One seed from the original task list was investigated and dropped, not skipped
// silently: "CA:false intermediate improperly used as an issuer". digitorus/pkcs7's
// own SignedData.AddSignerChain calls verifyPartialChain, which itself calls
// cert.CheckSignatureFrom(parent) — Go's stdlib CA-constraint check — BEFORE it will
// build a token, so this test's own fixture-construction step fails with the exact
// ConstraintViolationError a correct verifier should produce, for the same reason a
// correct verifier would produce it. Constructing the malformed shape for real would
// mean reimplementing PKCS7 SignedData ASN.1 encoding by hand (bypassing the
// convenience API entirely) — disproportionate for one scenario when
// CheckSignatureFrom's CA enforcement is exactly the same, well-tested stdlib code
// path every other non-chaining scenario here already exercises.
//
// The property under test: VerifyReceipt(roots={R}, ...) ACCEPTING a token implies
// that token's signer cert independently verifies via crypto/x509 against a pool
// containing ONLY R, with the ExtKeyUsageTimeStamping EKU VerifyReceipt itself
// requires — i.e. VerifyReceipt can never accept something the standard library
// itself would reject for that exact (Roots, EKU) pair. This is intentionally
// one-directional (accept ⇒ reference-accepts); the harness never asserts the
// reverse ("should accept"), since a fuzzed/mutated token legitimately SHOULD be
// rejected far more often than not.
//
// A same-subject/same-SubjectKeyId impostor root R' cannot fool Go's x509.Verify on
// its own: chain building matches a candidate issuer by subject, but then
// CRYPTOGRAPHICALLY verifies the signature with that candidate's actual public key
// — R (real key) and R' (attacker's own key) sign differently, so subject-byte
// collision alone proves nothing. The scenarios below exist to catch a REGRESSION
// that bypasses that real check (a nil Roots silently downgrading to "just check
// the signature is self-consistent" — see pkcs7.verifySignatureAtTime's own
// `if opts.Roots != nil` gate, a real behaviour in the vendored library — or an
// accidental subject-string shortcut), not to defeat sound chain verification
// itself.
//
// Bounded work: VerifyReceipt's time + allocations must stay within a generous
// linear envelope of the token's DER size, even for a 100-certificate chain (the
// "duplicate certs" seed) — a crafted receipt must not turn parsing/verification
// into a super-linear blow-up.

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"runtime"
	"testing"
	"time"

	"github.com/digitorus/pkcs7"
	"github.com/digitorus/timestamp"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
)

// certChainMessage is the fixed "anchored message" every scenario's token binds to
// (via the SHA-256 message-imprint VerifyReceipt itself requires). Fixed so every
// scenario's HashedMessage can be computed once, deterministically.
var certChainMessage = []byte("cert-chain-trust-invariant fuzz anchor message")
var certChainMessageDigest = sha256.Sum256(certChainMessage)

// mustGenKey generates a fresh ECDSA P-256 key. ECDSA (not RSA) purely for speed —
// this fixture builds a dozen-plus certs once per process, and the trust decision
// under test does not depend on the signing algorithm.
func mustGenKey(tb testing.TB) *ecdsa.PrivateKey {
	tb.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("generating test key: %v", err)
	}
	return k
}

var certSerialCounter int64

func nextSerial() *big.Int {
	certSerialCounter++
	return big.NewInt(certSerialCounter)
}

// certSpec describes one certificate to mint for the test PKI.
type certSpec struct {
	subject      pkix.Name
	isCA         bool
	ekus         []x509.ExtKeyUsage
	notBefore    time.Time
	notAfter     time.Time
	subjectKeyID []byte
	// parent/parentKey: nil parent means self-signed (parent = the cert's own
	// template, parentKey = its own key).
	parent    *x509.Certificate
	parentKey crypto.Signer
}

func mustMintCert(tb testing.TB, spec certSpec, key *ecdsa.PrivateKey) *x509.Certificate {
	tb.Helper()
	return mustMintCertSigner(tb, spec, key)
}

// mustMintCertSigner is mustMintCert generalized to any crypto.Signer subject key
// (RSA included) — the chain-trust decision under test does not depend on the
// signer's key algorithm, so the fixture-building side shouldn't be locked to one.
func mustMintCertSigner(tb testing.TB, spec certSpec, key crypto.Signer) *x509.Certificate {
	tb.Helper()
	keyUsage := x509.KeyUsageDigitalSignature
	if spec.isCA {
		keyUsage |= x509.KeyUsageCertSign
	}
	tmpl := &x509.Certificate{
		SerialNumber:          nextSerial(),
		Subject:               spec.subject,
		NotBefore:             spec.notBefore,
		NotAfter:              spec.notAfter,
		IsCA:                  spec.isCA,
		BasicConstraintsValid: true,
		KeyUsage:              keyUsage,
		ExtKeyUsage:           spec.ekus,
		SubjectKeyId:          spec.subjectKeyID,
	}
	parent := tmpl
	parentKey := key
	if spec.parent != nil {
		parent = spec.parent
		parentKey = spec.parentKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, key.Public(), parentKey)
	if err != nil {
		tb.Fatalf("minting test cert %q: %v", spec.subject.CommonName, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		tb.Fatalf("parsing minted test cert %q: %v", spec.subject.CommonName, err)
	}
	return cert
}

// certPKI is the fixed test fixture: a configured root R, a legitimate leaf under
// it, an attacker root R' crafted to collide with R's Subject/SubjectKeyId bytes,
// and every other cert shape the seeds below need. Built ONCE per fuzz-target
// invocation (not per iteration) — matches this repo's sibling metamorphic/soak
// harnesses (e.g. FuzzOIDCVerifierClaims: sign with a fixed trusted key once, fuzz
// only the content).
type certPKI struct {
	rootR    *x509.Certificate
	rootRKey *ecdsa.PrivateKey

	leafUnderR    *x509.Certificate
	leafUnderRKey *ecdsa.PrivateKey

	// rootRPrime shares rootR's exact Subject AND SubjectKeyId bytes, but is an
	// entirely different keypair — the "same subject/SKI, different key" impostor.
	rootRPrime    *x509.Certificate
	rootRPrimeKey *ecdsa.PrivateKey

	leafUnderRPrime    *x509.Certificate
	leafUnderRPrimeKey *ecdsa.PrivateKey

	// rootRDoublePrime (R'') cross-signs rootRPrime's identity as an intermediate,
	// for the "cross-signed R' by R''" seed. Neither is R, so a chain through
	// either must still be rejected against a {R}-only root pool.
	rootRDoublePrime    *x509.Certificate
	rootRDoublePrimeKey *ecdsa.PrivateKey
	rPrimeCrossSigned   *x509.Certificate // rootRPrime's key+subject, issued by R''

	selfSignedLeaf    *x509.Certificate
	selfSignedLeafKey *ecdsa.PrivateKey

	// wrongEKULeaf chains properly to the REAL root R but carries ServerAuth, not
	// TimeStamping — VerifyReceipt's own required EKU must reject it.
	wrongEKULeaf    *x509.Certificate
	wrongEKULeafKey *ecdsa.PrivateKey

	// expiredLeaf/notYetValidLeaf chain to the real root R but their validity
	// window excludes the token's claimed time (see VerifyReceipt's own
	// CurrentTime: ts.Time — deliberately the TOKEN'S claimed time, not wall-clock
	// now, so the test must set Timestamp.Time outside the leaf's window).
	expiredLeaf    *x509.Certificate
	expiredLeafKey *ecdsa.PrivateKey

	notYetValidLeaf    *x509.Certificate
	notYetValidLeafKey *ecdsa.PrivateKey

	// A real 2-tier chain (R -> intermediate -> leaf) for the chain-order /
	// embedded-redundant-root seeds.
	intermediateUnderR    *x509.Certificate
	intermediateUnderRKey *ecdsa.PrivateKey
	leafUnderIntermediate *x509.Certificate
	leafUnderIntermKey    *ecdsa.PrivateKey

	// rsaLeafUnderR chains to the real root R like leafUnderR, but with an RSA
	// signer key — every other fixture here is ECDSA-only (mustGenKey), so without
	// this the RSA branches of pkcs7.getSignatureAlgorithm (SHA256WithRSA etc.) are
	// never exercised by this harness at all.
	rsaLeafUnderR    *x509.Certificate
	rsaLeafUnderRKey *rsa.PrivateKey
}

func buildCertPKI(tb testing.TB) *certPKI {
	tb.Helper()
	longWindow := func() (time.Time, time.Time) {
		return time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	nb, na := longWindow()
	pki := &certPKI{}

	// R: the configured trust anchor.
	pki.rootRKey = mustGenKey(tb)
	rootSKI := []byte("shared-root-subject-key-id-bytes")
	pki.rootR = mustMintCert(tb, certSpec{
		subject:      pkix.Name{CommonName: "Keyorix Test TSA Root"},
		isCA:         true,
		notBefore:    nb,
		notAfter:     na,
		subjectKeyID: rootSKI,
	}, pki.rootRKey)

	// Legit leaf under R.
	pki.leafUnderRKey = mustGenKey(tb)
	pki.leafUnderR = mustMintCert(tb, certSpec{
		subject:   pkix.Name{CommonName: "Keyorix Test TSA Leaf"},
		ekus:      []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		notBefore: nb, notAfter: na,
		parent: pki.rootR, parentKey: pki.rootRKey,
	}, pki.leafUnderRKey)

	// R': attacker root, byte-identical Subject and SubjectKeyId to R, distinct key.
	pki.rootRPrimeKey = mustGenKey(tb)
	pki.rootRPrime = mustMintCert(tb, certSpec{
		subject:   pkix.Name{CommonName: "Keyorix Test TSA Root"}, // identical to R
		isCA:      true,
		notBefore: nb, notAfter: na,
		subjectKeyID: rootSKI, // identical bytes to R's SKI
	}, pki.rootRPrimeKey)

	pki.leafUnderRPrimeKey = mustGenKey(tb)
	pki.leafUnderRPrime = mustMintCert(tb, certSpec{
		subject:   pkix.Name{CommonName: "Keyorix Test TSA Leaf"},
		ekus:      []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		notBefore: nb, notAfter: na,
		parent: pki.rootRPrime, parentKey: pki.rootRPrimeKey,
	}, pki.leafUnderRPrimeKey)

	// R'': a second attacker root, used to cross-sign R' as an intermediate.
	pki.rootRDoublePrimeKey = mustGenKey(tb)
	pki.rootRDoublePrime = mustMintCert(tb, certSpec{
		subject:   pkix.Name{CommonName: "Keyorix Test Attacker Second Root"},
		isCA:      true,
		notBefore: nb, notAfter: na,
	}, pki.rootRDoublePrimeKey)
	// Re-issue R's-prime identity (same subject+key as rootRPrime) as an
	// intermediate under R''.
	pki.rPrimeCrossSigned = mustMintCert(tb, certSpec{
		subject:   pkix.Name{CommonName: "Keyorix Test TSA Root"},
		isCA:      true,
		notBefore: nb, notAfter: na,
		subjectKeyID: rootSKI,
		parent:       pki.rootRDoublePrime, parentKey: pki.rootRDoublePrimeKey,
	}, pki.rootRPrimeKey) // NOTE: signed with rootRPrimeKey's *public* key via mustMintCert(key=...); see below.

	// Self-signed leaf, unrelated identity, not a CA.
	pki.selfSignedLeafKey = mustGenKey(tb)
	pki.selfSignedLeaf = mustMintCert(tb, certSpec{
		subject:   pkix.Name{CommonName: "Keyorix Test Attacker Self-Signed"},
		ekus:      []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		notBefore: nb, notAfter: na,
	}, pki.selfSignedLeafKey)

	// Wrong-EKU leaf, chains properly to the real root R.
	pki.wrongEKULeafKey = mustGenKey(tb)
	pki.wrongEKULeaf = mustMintCert(tb, certSpec{
		subject:   pkix.Name{CommonName: "Keyorix Test Wrong-EKU Leaf"},
		ekus:      []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		notBefore: nb, notAfter: na,
		parent: pki.rootR, parentKey: pki.rootRKey,
	}, pki.wrongEKULeafKey)

	// Expired / not-yet-valid leaves under the real root R.
	pki.expiredLeafKey = mustGenKey(tb)
	pki.expiredLeaf = mustMintCert(tb, certSpec{
		subject:   pkix.Name{CommonName: "Keyorix Test Expired Leaf"},
		ekus:      []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		notBefore: time.Date(2018, 1, 1, 0, 0, 0, 0, time.UTC),
		notAfter:  time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC),
		parent:    pki.rootR, parentKey: pki.rootRKey,
	}, pki.expiredLeafKey)

	pki.notYetValidLeafKey = mustGenKey(tb)
	pki.notYetValidLeaf = mustMintCert(tb, certSpec{
		subject:   pkix.Name{CommonName: "Keyorix Test Not-Yet-Valid Leaf"},
		ekus:      []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		notBefore: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
		notAfter:  time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC),
		parent:    pki.rootR, parentKey: pki.rootRKey,
	}, pki.notYetValidLeafKey)

	// Real 2-tier chain: R -> intermediate -> leaf.
	pki.intermediateUnderRKey = mustGenKey(tb)
	pki.intermediateUnderR = mustMintCert(tb, certSpec{
		subject:   pkix.Name{CommonName: "Keyorix Test TSA Intermediate"},
		isCA:      true,
		notBefore: nb, notAfter: na,
		parent: pki.rootR, parentKey: pki.rootRKey,
	}, pki.intermediateUnderRKey)
	pki.leafUnderIntermKey = mustGenKey(tb)
	pki.leafUnderIntermediate = mustMintCert(tb, certSpec{
		subject:   pkix.Name{CommonName: "Keyorix Test Leaf Under Intermediate"},
		ekus:      []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		notBefore: nb, notAfter: na,
		parent: pki.intermediateUnderR, parentKey: pki.intermediateUnderRKey,
	}, pki.leafUnderIntermKey)

	// RSA-keyed leaf under the real root R.
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		tb.Fatalf("generating RSA test key: %v", err)
	}
	pki.rsaLeafUnderRKey = rsaKey
	pki.rsaLeafUnderR = mustMintCertSigner(tb, certSpec{
		subject:   pkix.Name{CommonName: "Keyorix Test TSA RSA Leaf"},
		ekus:      []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		notBefore: nb, notAfter: na,
		parent: pki.rootR, parentKey: pki.rootRKey,
	}, rsaKey)

	return pki
}

// tspResponse mirrors digitorus/timestamp's unexported `response` ASN.1 shape just
// enough to pull the raw TimeStampToken bytes out of CreateResponseWithOpts's
// output — the same structure ParseResponse itself unmarshals into.
type tspResponse struct {
	Status struct {
		Status       int
		StatusString []string       `asn1:"optional"`
		FailInfo     asn1.BitString `asn1:"optional"`
	}
	TimeStampToken asn1.RawValue `asn1:"optional"`
}

// buildToken constructs a raw RFC 3161 TimeStampToken (the exact byte shape
// VerifyReceipt's `token` parameter expects) signed by signerCert/signerKey, over
// certChainMessage, claiming time claimedTime, with embed as the additional
// certificates carried alongside the signer (attacker intermediates, cross-signed
// roots, duplicates — whatever the scenario wants). addSignerCert controls whether
// the signer's own certificate is embedded at all (false models "leaf alone, no
// certs in the token").
func buildToken(tb testing.TB, signerCert *x509.Certificate, signerKey crypto.Signer, embed []*x509.Certificate, claimedTime time.Time, addSignerCert bool) []byte {
	tb.Helper()
	ts := &timestamp.Timestamp{
		HashAlgorithm: crypto.SHA256,
		HashedMessage: certChainMessageDigest[:],
		Time:          claimedTime,
		// Policy must be a syntactically valid (>=2-arc) OID or asn1.Marshal rejects
		// it outright; the value itself is never checked by VerifyReceipt.
		Policy:            asn1.ObjectIdentifier{1, 2, 3},
		Certificates:      embed,
		AddTSACertificate: addSignerCert,
	}
	full, err := ts.CreateResponseWithOpts(signerCert, signerKey, crypto.SHA256)
	if err != nil {
		tb.Fatalf("building test token: %v", err)
	}
	var resp tspResponse
	if _, err := asn1.Unmarshal(full, &resp); err != nil {
		tb.Fatalf("unwrapping test TSP response: %v", err)
	}
	return resp.TimeStampToken.FullBytes
}

// referenceAccepts independently re-derives the SAME trust decision VerifyReceipt
// is supposed to make, using crypto/x509 directly: parse the (possibly mutated)
// token, pull out its signer + embedded certs, and ask crypto/x509 whether that
// signer chains to onlyR with the TimeStamping EKU at the token's own claimed time.
// This is deliberately NOT a call into VerifyReceipt itself — it reconstructs the
// verification from the token's raw bytes each time, so it cannot inherit a bug in
// VerifyReceipt's own orchestration (wrong pool, wrong EKU, a skipped Verify call).
func referenceAccepts(token []byte, onlyR *x509.CertPool) bool {
	p7, err := pkcs7.Parse(token)
	if err != nil || len(p7.Certificates) == 0 {
		return false
	}
	signer := p7.GetOnlySigner()
	if signer == nil {
		return false
	}
	ts, err := timestamp.Parse(token)
	if err != nil {
		return false
	}
	intermediates := x509.NewCertPool()
	for _, c := range p7.Certificates {
		intermediates.AddCert(c)
	}
	_, err = signer.Verify(x509.VerifyOptions{
		Roots:         onlyR,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		CurrentTime:   ts.Time,
	})
	return err == nil
}

// certChainScenario names one chain-composition shape and builds its token.
type certChainScenario struct {
	name  string
	token []byte
}

func buildScenarios(tb testing.TB, pki *certPKI) []certChainScenario {
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC) // fixed "claimed time" for legit chains
	return []certChainScenario{
		{"legit-chain", buildToken(tb, pki.leafUnderR, pki.leafUnderRKey, nil, now, true)},
		{"impostor-subject-leaf-alone", buildToken(tb, pki.leafUnderRPrime, pki.leafUnderRPrimeKey, nil, now, true)},
		{"impostor-subject-with-intermediate", buildToken(tb, pki.leafUnderRPrime, pki.leafUnderRPrimeKey, []*x509.Certificate{pki.rootRPrime}, now, true)},
		{"leaf-alone-no-certs-embedded", buildToken(tb, pki.leafUnderR, pki.leafUnderRKey, nil, now, false)},
		{"self-signed-leaf", buildToken(tb, pki.selfSignedLeaf, pki.selfSignedLeafKey, nil, now, true)},
		{"cross-signed-rprime-by-rdoubleprime", buildToken(tb, pki.leafUnderRPrime, pki.leafUnderRPrimeKey, []*x509.Certificate{pki.rPrimeCrossSigned, pki.rootRDoublePrime}, now, true)},
		{"wrong-eku", buildToken(tb, pki.wrongEKULeaf, pki.wrongEKULeafKey, nil, now, true)},
		{"expired-relative-to-claimed-time", buildToken(tb, pki.expiredLeaf, pki.expiredLeafKey, nil, now, true)},
		{"not-yet-valid-relative-to-claimed-time", buildToken(tb, pki.notYetValidLeaf, pki.notYetValidLeafKey, nil, now, true)},
		{"legit-2tier-chain", buildToken(tb, pki.leafUnderIntermediate, pki.leafUnderIntermKey, []*x509.Certificate{pki.intermediateUnderR}, now, true)},
		// Redundant root embedded ALONGSIDE the intermediate that actually issued the
		// leaf — digitorus/pkcs7's own AddSignerChain requires parents[0] to be the
		// cert's DIRECT issuer (it calls cert.CheckSignatureFrom(parents[0])), so the
		// intermediate must come first; the redundant root appended after it is the
		// part under test (VerifyReceipt must tolerate an extra, already-trusted cert
		// showing up again in the embedded set).
		{"legit-2tier-chain-with-redundant-root", buildToken(tb, pki.leafUnderIntermediate, pki.leafUnderIntermKey, []*x509.Certificate{pki.intermediateUnderR, pki.rootR}, now, true)},
		{"duplicate-attacker-intermediates", buildToken(tb, pki.leafUnderRPrime, pki.leafUnderRPrimeKey, []*x509.Certificate{pki.rootRPrime, pki.rootRPrime, pki.rootRPrime}, now, true)},
		{"100-cert-chain", buildToken(tb, pki.leafUnderRPrime, pki.leafUnderRPrimeKey, hundredCopies(pki.rootRPrime), now, true)},
		// Appended, never inserted: scenarioSel is a stored-corpus index into this
		// slice (fuzz-seeds-are-position-encoded), so an existing entry's meaning must
		// never shift. RSA closes the only signature-algorithm family every other
		// scenario in this file leaves completely unexercised (all ECDSA via
		// mustGenKey) — see mustMintCertSigner.
		{"rsa-leaf-legit-chain", buildToken(tb, pki.rsaLeafUnderR, pki.rsaLeafUnderRKey, nil, now, true)},
	}
}

func hundredCopies(c *x509.Certificate) []*x509.Certificate {
	out := make([]*x509.Certificate, 100)
	for i := range out {
		out[i] = c
	}
	return out
}

// FuzzCertChainTrustInvariant asserts VerifyReceipt's fail-closed chain-trust
// property (package doc comment above has the full writeup): ACCEPT implies
// crypto/x509 independently agrees, against a pool containing ONLY the configured
// root, with the required TimeStamping EKU. It also asserts bounded work: time and
// allocations must stay within a generous linear envelope of the token's DER size,
// even under the 100-cert-chain seed.
//
// The fuzz input selects one of the pre-built chain-composition scenarios and
// applies a small, bounded byte-level mutation (XOR one byte, and/or truncate) to
// its DER — mutating a scenario CANNOT invalidate the oracle, because the oracle
// only ever checks "IF our validator accepts, does the reference also accept" —
// there is no direction in which a mutation could produce a false positive.
func FuzzCertChainTrustInvariant(f *testing.F) {
	pki := buildCertPKI(f)
	onlyR := x509.NewCertPool()
	onlyR.AddCert(pki.rootR)
	scenarios := buildScenarios(f, pki)

	// Positive control: the legit chain must actually be ACCEPTED by both
	// VerifyReceipt and the reference — otherwise every other scenario's "reject"
	// would pass vacuously (a validator that rejects everything trivially never
	// violates a one-directional accept-only oracle).
	legit := scenarios[0]
	if legit.name != "legit-chain" {
		f.Fatalf("internal test error: scenarios[0] is not legit-chain")
	}
	if _, err := VerifyReceipt(onlyR, certChainMessage, legit.token); err != nil {
		f.Fatalf("positive control: VerifyReceipt rejected the legit chain: %v", err)
	}
	if !referenceAccepts(legit.token, onlyR) {
		f.Fatalf("positive control: reference crypto/x509 check rejected the legit chain — the fixture itself is broken")
	}

	for i, sc := range scenarios {
		f.Add(uint8(i), uint32(0), byte(0), uint32(0))
		f.Add(uint8(i), uint32(0), byte(0xff), uint32(1)) // flip first byte
		f.Add(uint8(i), uint32(len(sc.token)/2), byte(0x7f), uint32(0))
		f.Add(uint8(i), uint32(0), byte(0), uint32(len(sc.token)+1)) // truncate to len/2 (see below)
	}

	f.Fuzz(func(t *testing.T, scenarioSel uint8, xorOffset uint32, xorByte byte, truncateSel uint32) {
		sc := scenarios[int(scenarioSel)%len(scenarios)]
		token := append([]byte(nil), sc.token...)

		if len(token) > 0 && xorByte != 0 {
			token[int(xorOffset)%len(token)] ^= xorByte
		}
		if truncateSel > 0 && len(token) > 0 {
			// truncateSel is reduced to a length within [1, len(token)] — never 0,
			// so this always exercises "truncated DER", never "empty input" (already
			// covered by FuzzVerifyReceipt).
			newLen := 1 + int(truncateSel)%len(token)
			token = token[:newLen]
		}

		var verr error
		var m0, m1 runtime.MemStats
		runtime.ReadMemStats(&m0)
		fuzzutil.Guard(t.Fatalf, "VerifyReceipt", func() {
			_, verr = VerifyReceipt(onlyR, certChainMessage, token)
		})
		runtime.ReadMemStats(&m1)

		if verr == nil {
			if !referenceAccepts(token, onlyR) {
				t.Fatalf("FAIL-CLOSED VIOLATION: VerifyReceipt accepted a %s-derived token (offset=%d xor=%#x truncate=%d, %d bytes) that crypto/x509 itself rejects against a pool containing ONLY the configured root",
					sc.name, xorOffset, xorByte, truncateSel, len(token))
			}
		}

		alloc := m1.TotalAlloc - m0.TotalAlloc
		limit := uint64(1<<20) + uint64(4096)*uint64(len(token))
		if alloc > limit {
			t.Fatalf("BOUNDED-WORK: VerifyReceipt allocated %d bytes verifying a %d-byte token (scenario %s, limit %d) — amplification regression",
				alloc, len(token), sc.name, limit)
		}
	})
}
