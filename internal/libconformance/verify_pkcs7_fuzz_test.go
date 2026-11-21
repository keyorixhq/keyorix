package libconformance

// FuzzPKCS7VerifyWithOpts, FuzzPKCS7Verify, FuzzPKCS7VerifyWithChain,
// FuzzPKCS7VerifyWithChainAtTime are fuzz targets for the four
// digitorus/pkcs7 signature-verification entry points that are uncovered by
// the three existing Parse-only harnesses.
//
// # Motivation
//
// All four functions share one security-critical shape: they parse a
// caller-supplied *PKCS7 (itself built from untrusted bytes via pkcs7.Parse)
// and then perform an x509 chain-of-trust decision.  VerifyWithOpts is the
// direct production caller in internal/notary/notary.go:179 and is therefore
// Tier 1A: the highest priority target in the LS2 plan regardless of its raw
// risk score.
//
// # Shared oracle
//
// All four targets assert:
//   - Never panic (fuzzutil.Guard catches panics from the library)
//   - Never hang  (fuzzutil.Guard kills inputs that exceed 3 s)
//
// VerifyWithOpts, VerifyWithChain, and VerifyWithChainAtTime additionally
// carry a one-directional differential oracle:
//   - ACCEPT ⇒ signer cert chains to the harness's own root pool via
//     crypto/x509 independently (verifyPKCS7ReferenceAccepts).
//     This catches certificate-chain bypass bugs where the pkcs7 library
//     accepts something that the standard library's chain verifier rejects.
//   - The oracle is intentionally NOT bidirectional: a fuzz-mutated token
//     legitimately fails verification far more often than not; asserting
//     "must be accepted" would be unsound.
//
// # Positive control
//
// A known-good seed token (signed by verifyFuzzPKI.leaf, chaining to
// verifyFuzzPKI.root) is verified BEFORE f.Fuzz begins. If that seed is
// rejected by the oracle, the differential check is vacuous (a validator
// that always rejects trivially satisfies a one-directional accept⇒accept
// oracle).  The positive control fails fast rather than letting the vacuous
// case pass silently.
//
// # What these oracles do NOT verify
//   - Correctness of the message-digest check inside pkcs7 (not cross-checked
//     with an independent reference)
//   - That VerifyWithOpts rejects invalid inputs (one-directional)
//   - TimeStamping EKU or any specific EKU (the production caller adds
//     ExtKeyUsageTimeStamping; the harness uses a broader empty-EKU check to
//     cover the library code path regardless of EKU policy)
//   - Verify() uses an empty trust store by design; no cert-chain differential
//     is possible or applied to that function
//
// # Signature drift check (LS2 requirement)
//
// Confirmed from `go doc github.com/digitorus/pkcs7` against pinned version
// v0.0.0-20261104125046-a476de3098e4 — no drift from LS1 inventory:
//
//   func (p7 *PKCS7) VerifyWithOpts(opts x509.VerifyOptions) (err error)
//   func (p7 *PKCS7) Verify() (err error)
//   func (p7 *PKCS7) VerifyWithChain(truststore *x509.CertPool) (err error)
//   func (p7 *PKCS7) VerifyWithChainAtTime(truststore *x509.CertPool, currentTime time.Time) (err error)

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

// buildTSAVerifyFuzzSeed builds a valid PKCS7 SignedData token signed by a
// leaf certificate that carries ExtKeyUsageTimeStamping.  This seed increases
// coverage of the EKU-specific chain-verification code path in VerifyWithOpts,
// which the real production caller (internal/notary/notary.go:179) exercises
// via KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}.
//
// The seed is intentionally signed by the SAME pki.root used in
// FuzzPKCS7VerifyWithOpts so that the existing differential oracle
// (ACCEPT ⇒ verifyPKCS7ReferenceAccepts) still fires: the TSA leaf chains to
// the harness root, so the reference oracle accepts the seed without EKU
// restriction, keeping the oracle consistent.
//
// What this seed does NOT verify: the oracle still uses no EKU restriction
// (broader than production). A tighter oracle specific to TimeStamping EKU
// would require a separate accept⇒TSA-accept differential, which is left as
// a future enhancement.
func buildTSAVerifyFuzzSeed(tb testing.TB, pki *verifyFuzzPKI) []byte {
	tb.Helper()
	nb := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	na := time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)

	tsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("buildTSAVerifyFuzzSeed: generating TSA key: %v", err)
	}
	tsaTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(3),
		Subject:               pkix.Name{CommonName: "LS3 Fuzz TSA Leaf"},
		NotBefore:             nb,
		NotAfter:              na,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	}
	tsaDER, err := x509.CreateCertificate(rand.Reader, tsaTmpl, pki.root, &tsaKey.PublicKey, pki.rootKey)
	if err != nil {
		tb.Fatalf("buildTSAVerifyFuzzSeed: creating TSA cert: %v", err)
	}
	tsaCert, err := x509.ParseCertificate(tsaDER)
	if err != nil {
		tb.Fatalf("buildTSAVerifyFuzzSeed: parsing TSA cert: %v", err)
	}

	content := []byte("ls3-tsa-eku-verify-fuzz-seed")
	sd, err := pkcs7.NewSignedData(content)
	if err != nil {
		tb.Fatalf("buildTSAVerifyFuzzSeed: NewSignedData: %v", err)
	}
	if err := sd.AddSignerChain(tsaCert, tsaKey, nil, pkcs7.SignerInfoConfig{}); err != nil {
		tb.Fatalf("buildTSAVerifyFuzzSeed: AddSignerChain: %v", err)
	}
	out, err := sd.Finish()
	if err != nil {
		tb.Fatalf("buildTSAVerifyFuzzSeed: Finish: %v", err)
	}
	return out
}

// verifyFuzzFixedTime is the fixed CurrentTime used in all verify harnesses.
// It is inside the PKI certs' validity window (2000–2100) and is constant so
// every run uses the same reference point.
var verifyFuzzFixedTime = time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)

// verifyFuzzPKI is the minimal test PKI shared by all four verify harnesses.
type verifyFuzzPKI struct {
	root    *x509.Certificate
	rootKey *ecdsa.PrivateKey
	leaf    *x509.Certificate
	leafKey *ecdsa.PrivateKey
	roots   *x509.CertPool
}

// buildVerifyFuzzPKI generates a minimal two-tier ECDSA P-256 PKI:
// a self-signed root CA and one leaf cert issued by it.  ECDSA P-256 is used
// for speed; the trust decision under test does not depend on the signing
// algorithm.  The PKI is built ONCE per fuzz invocation (at testing.F setup
// time), not per iteration.
func buildVerifyFuzzPKI(tb testing.TB) *verifyFuzzPKI {
	tb.Helper()
	nb := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	na := time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("buildVerifyFuzzPKI: generating root key: %v", err)
	}
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "LS2 Fuzz Root"},
		NotBefore:             nb,
		NotAfter:              na,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		tb.Fatalf("buildVerifyFuzzPKI: creating root cert: %v", err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		tb.Fatalf("buildVerifyFuzzPKI: parsing root cert: %v", err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("buildVerifyFuzzPKI: generating leaf key: %v", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "LS2 Fuzz Leaf"},
		NotBefore:             nb,
		NotAfter:              na,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, root, &leafKey.PublicKey, rootKey)
	if err != nil {
		tb.Fatalf("buildVerifyFuzzPKI: creating leaf cert: %v", err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		tb.Fatalf("buildVerifyFuzzPKI: parsing leaf cert: %v", err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(root)
	return &verifyFuzzPKI{root: root, rootKey: rootKey, leaf: leaf, leafKey: leafKey, roots: roots}
}

// buildVerifyFuzzSeed returns a valid pkcs7 SignedData blob signed by
// pki.leaf (which chains to pki.root).  This seed gives the fuzzer a
// starting point that exercises the VerifyWithOpts "accept" path, so the
// differential oracle actually fires on the seed and its nearby mutations.
func buildVerifyFuzzSeed(tb testing.TB, pki *verifyFuzzPKI) []byte {
	tb.Helper()
	content := []byte("ls2-verify-fuzz-seed-content")
	sd, err := pkcs7.NewSignedData(content)
	if err != nil {
		tb.Fatalf("buildVerifyFuzzSeed: NewSignedData: %v", err)
	}
	// nil parents: leaf is directly under root (no intermediate).
	if err := sd.AddSignerChain(pki.leaf, pki.leafKey, nil, pkcs7.SignerInfoConfig{}); err != nil {
		tb.Fatalf("buildVerifyFuzzSeed: AddSignerChain: %v", err)
	}
	out, err := sd.Finish()
	if err != nil {
		tb.Fatalf("buildVerifyFuzzSeed: Finish: %v", err)
	}
	return out
}

// verifyPKCS7ReferenceAccepts is the independent reference oracle for the
// verify harnesses.  It checks whether the signer cert in a parsed *PKCS7
// chains to the given root pool at the given time, using crypto/x509 directly
// (never via pkcs7's own verification logic).  Returns true only when:
//   - GetOnlySigner returns exactly one cert
//   - That cert chains to roots at currentTime
//
// KeyUsages is set to ExtKeyUsageAny to match pkcs7.VerifyWithOpts' own
// default: when VerifyWithOpts receives a nil KeyUsages, it inserts
// ExtKeyUsageAny before calling the x509 chain verifier (LS3: discovered when
// adding the TSA-EKU seed — a TimeStamping-EKU leaf was accepted by
// VerifyWithOpts but rejected by the previous reference oracle, which left
// KeyUsages unset and thereby defaulted to x509's ExtKeyUsageServerAuth check).
// Without this fix the oracle fires on any cert with a specific EKU, which is
// an expected difference, not a bypass.
//
// What this does NOT check:
//   - The PKCS7 message-digest signature (not a chain-trust check)
//   - Specific EKU policies (ExtKeyUsageAny is used to match the harness's
//     no-EKU-restriction opts; the production caller's TimeStamping EKU
//     restriction is exercised by the TSA seed but not enforced in the oracle)
func verifyPKCS7ReferenceAccepts(p7 *pkcs7.PKCS7, roots *x509.CertPool, currentTime time.Time) bool {
	signer := p7.GetOnlySigner()
	if signer == nil {
		return false
	}
	intermediates := x509.NewCertPool()
	for _, c := range p7.Certificates {
		intermediates.AddCert(c)
	}
	_, err := signer.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   currentTime,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	return err == nil
}

// FuzzPKCS7VerifyWithOpts fuzzes (*PKCS7).VerifyWithOpts — Tier 1A, the
// direct production caller in internal/notary/notary.go:179.
//
// Fuzz strategy: arbitrary bytes → pkcs7.Parse → VerifyWithOpts with a fixed
// cert pool.  The PKI and pool are HARNESS-controlled (a self-signed test
// root), so fuzzing covers the verify logic, not cert-chain generation.
func FuzzPKCS7VerifyWithOpts(f *testing.F) {
	pki := buildVerifyFuzzPKI(f)
	seed := buildVerifyFuzzSeed(f, pki)

	// Positive control: the seed must be accepted BEFORE f.Fuzz begins.
	// If not, the differential oracle would be vacuous (always "no accept to check").
	seedP7, err := pkcs7.Parse(seed)
	if err != nil {
		f.Fatalf("positive control: pkcs7.Parse(seed) failed: %v", err)
	}
	if err := seedP7.VerifyWithOpts(x509.VerifyOptions{
		Roots:       pki.roots,
		CurrentTime: verifyFuzzFixedTime,
	}); err != nil {
		f.Fatalf("positive control: VerifyWithOpts rejected the seed token: %v", err)
	}
	if !verifyPKCS7ReferenceAccepts(seedP7, pki.roots, verifyFuzzFixedTime) {
		f.Fatalf("positive control: reference crypto/x509 check rejected the seed token — fixture is broken")
	}

	// tsaSeed: a valid token signed by a TSA-EKU leaf (LS3 addition).
	// Increases coverage of the EKU-specific chain-verification path that the
	// real production caller (notary.go:179 KeyUsages: TimeStamping) exercises.
	// The oracle is unchanged (no EKU restriction, broader than production).
	tsaSeed := buildTSAVerifyFuzzSeed(f, pki)
	f.Add(seed)
	f.Add(tsaSeed)
	f.Add([]byte{0x30, 0x03, 0x02, 0x01, 0x01}) // minimal DER SEQUENCE
	f.Add([]byte("0\x81\xc400\x02\x01\xf8"))    // BER-ish prefix (from existing pkcs7 seeds)
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		p7, err := pkcs7.Parse(data)
		if err != nil {
			return // parse failure is expected for most fuzz inputs; not our oracle
		}

		opts := x509.VerifyOptions{
			Roots:       pki.roots,
			CurrentTime: verifyFuzzFixedTime,
		}
		var verr error
		fuzzutil.Guard(t.Fatalf, "pkcs7.VerifyWithOpts", func() {
			verr = p7.VerifyWithOpts(opts)
		})

		// Differential: ACCEPT ⇒ signer cert chains to our root via crypto/x509.
		// A bug here means VerifyWithOpts accepted something the standard library
		// would reject for the same (Roots, CurrentTime) pair.
		if verr == nil {
			if !verifyPKCS7ReferenceAccepts(p7, pki.roots, verifyFuzzFixedTime) {
				t.Fatalf("FAIL-CLOSED VIOLATION: pkcs7.VerifyWithOpts accepted but crypto/x509 chain check rejects the signer cert against the same root pool (input %x)", data)
			}
		}
	})
}

// FuzzPKCS7Verify fuzzes (*PKCS7).Verify — the empty-trust-store wrapper.
//
// Verify() uses an empty *x509.CertPool (no chain verification), so only the
// message-digest signature is checked.  No differential oracle applies (there
// is nothing to compare chain trust against).  Oracle: never panic, never hang.
func FuzzPKCS7Verify(f *testing.F) {
	pki := buildVerifyFuzzPKI(f)
	seed := buildVerifyFuzzSeed(f, pki)

	f.Add(seed)
	f.Add([]byte{0x30, 0x03, 0x02, 0x01, 0x01})
	f.Add([]byte("0\x81\xc400\x02\x01\xf8"))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		p7, err := pkcs7.Parse(data)
		if err != nil {
			return
		}
		fuzzutil.Guard(t.Fatalf, "pkcs7.Verify", func() {
			_ = p7.Verify()
		})
	})
}

// FuzzPKCS7VerifyWithChain fuzzes (*PKCS7).VerifyWithChain with the same
// cert pool and differential oracle as FuzzPKCS7VerifyWithOpts.
func FuzzPKCS7VerifyWithChain(f *testing.F) {
	pki := buildVerifyFuzzPKI(f)
	seed := buildVerifyFuzzSeed(f, pki)

	// Positive control.
	seedP7, err := pkcs7.Parse(seed)
	if err != nil {
		f.Fatalf("positive control: pkcs7.Parse(seed) failed: %v", err)
	}
	if err := seedP7.VerifyWithChain(pki.roots); err != nil {
		f.Fatalf("positive control: VerifyWithChain rejected the seed token: %v", err)
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
		var verr error
		fuzzutil.Guard(t.Fatalf, "pkcs7.VerifyWithChain", func() {
			verr = p7.VerifyWithChain(pki.roots)
		})
		if verr == nil {
			if !verifyPKCS7ReferenceAccepts(p7, pki.roots, verifyFuzzFixedTime) {
				t.Fatalf("FAIL-CLOSED VIOLATION: pkcs7.VerifyWithChain accepted but crypto/x509 chain check rejects the signer cert (input %x)", data)
			}
		}
	})
}

// FuzzPKCS7VerifyWithChainAtTime fuzzes (*PKCS7).VerifyWithChainAtTime —
// the explicit-time variant of VerifyWithChain.  Uses the same cert pool and
// differential oracle, with verifyFuzzFixedTime as the fixed currentTime.
func FuzzPKCS7VerifyWithChainAtTime(f *testing.F) {
	pki := buildVerifyFuzzPKI(f)
	seed := buildVerifyFuzzSeed(f, pki)

	// Positive control.
	seedP7, err := pkcs7.Parse(seed)
	if err != nil {
		f.Fatalf("positive control: pkcs7.Parse(seed) failed: %v", err)
	}
	if err := seedP7.VerifyWithChainAtTime(pki.roots, verifyFuzzFixedTime); err != nil {
		f.Fatalf("positive control: VerifyWithChainAtTime rejected the seed token: %v", err)
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
		var verr error
		fuzzutil.Guard(t.Fatalf, "pkcs7.VerifyWithChainAtTime", func() {
			verr = p7.VerifyWithChainAtTime(pki.roots, verifyFuzzFixedTime)
		})
		if verr == nil {
			if !verifyPKCS7ReferenceAccepts(p7, pki.roots, verifyFuzzFixedTime) {
				t.Fatalf("FAIL-CLOSED VIOLATION: pkcs7.VerifyWithChainAtTime accepted but crypto/x509 chain check rejects the signer cert (input %x)", data)
			}
		}
	})
}
