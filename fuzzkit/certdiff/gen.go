package certdiff

// Frankencert-style chain generator. A small set of mutation "knobs" is decoded
// from the fuzzer's bytes; from the knobs a complete X.509 chain (root ->
// optional intermediates -> leaf) is built with crypto/x509.CreateCertificate.
// The SAME generated chain is then handed to both verifiers (Go crypto/x509 and
// the openssl CLI) so the only thing that can differ is the trust DECISION, never
// the input bytes each side parses.
//
// Key material is drawn from a fixed-seed stream and all validity windows are
// relative to a single pinned "now" (fixedNow). Note: the certs are NOT
// byte-identical across two builds of the same knobs — Go injects entropy into
// ECDSA signing (crypto/internal/randutil.MaybeReadByte), so signatures vary.
// That is fine for the oracle: the trust DECISION depends on structure, not
// signature bytes, so a minimised/replayed divergence still reproduces (see
// TestBuildStructurallyStable). None of this is production key generation — it is
// a test fixture.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"math/big"
	"time"
)

// fixedNow is the instant both verifiers are pinned to (Go via
// VerifyOptions.CurrentTime, openssl via -attime). Choosing a fixed instant
// removes wall-clock time as a source of divergence.
var fixedNow = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

// A deterministic byte stream used as the randomness source for key generation
// and serial numbers, so the key material is stable across builds (the ECDSA
// signatures still vary — see the file doc comment).
type detReader struct{ state uint64 }

func newDetReader(seed uint64) *detReader { return &detReader{state: seed | 1} }

func (r *detReader) Read(p []byte) (int, error) {
	for i := range p {
		// xorshift64*, deterministic and good enough for a test fixture.
		r.state ^= r.state >> 12
		r.state ^= r.state << 25
		r.state ^= r.state >> 27
		p[i] = byte((r.state * 0x2545F4914F6CDD1D) >> 56)
	}
	return len(p), nil
}

// pre-generated ECDSA P-256 keys (fast, and above openssl's default security
// level so signature-algorithm policy never confounds the trust decision).
var (
	rootKey  = mustKey(1)
	interKey = mustKey(2)
	leafKey  = mustKey(3)
	altKey   = mustKey(4) // an untrusted key, for forged-signature cases
)

func mustKey(seed uint64) *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), newDetReader(seed))
	if err != nil {
		panic(err)
	}
	return k
}

// knobs are the Frankencert mutation axes. Each is decoded from one or more
// fuzz bytes (see decodeKnobs). The zero value is a plain, valid chain with no
// intermediates.
type knobs struct {
	numInter         int  // 0, 1 or 2 intermediates
	interNotCA       bool // intermediate's BasicConstraints omits CA:true
	interPathLenZero bool // intermediate asserts pathLenConstraint:0
	leafExpired      bool // leaf notAfter is before fixedNow
	leafFuture       bool // leaf notBefore is after fixedNow
	wrongSigner      bool // leaf signature is made with altKey (won't verify)
	unknownCritExt   bool // leaf carries an unknown critical extension
	nameConstrain    bool // top intermediate permits dNSName "example.com"
	leafBadName      bool // leaf SAN is outside the permitted name constraint
	bcNonCritical    bool // intermediate BasicConstraints marked non-critical
}

// decodeKnobs maps raw fuzz bytes onto the knob struct. Missing bytes read as 0
// so short inputs are valid (they describe a plain chain).
func decodeKnobs(b []byte) knobs {
	at := func(i int) byte {
		if i < len(b) {
			return b[i]
		}
		return 0
	}
	return knobs{
		numInter:         int(at(0) % 3),
		interNotCA:       at(1)&1 == 1,
		interPathLenZero: at(2)&1 == 1,
		leafExpired:      at(3)&1 == 1,
		leafFuture:       at(4)&1 == 1,
		wrongSigner:      at(5)&1 == 1,
		unknownCritExt:   at(6)&1 == 1,
		nameConstrain:    at(7)&1 == 1,
		leafBadName:      at(8)&1 == 1,
		bcNonCritical:    at(9)&1 == 1,
	}
}

// chain is the generated artifact handed to both verifiers.
type chain struct {
	root   *x509.Certificate
	inters []*x509.Certificate
	leaf   *x509.Certificate
	now    time.Time
	// leafFP is a stable identifier of the leaf (its SHA-256 over DER), used as
	// the "subject" both verifiers must agree on when both accept. Because both
	// verify the identical leaf, agreement here is by construction — the oracle's
	// real signal is accept/reject (documented in certdiff.go).
	leafFP string
}

func serial(seed int64) *big.Int { return big.NewInt(1000 + seed) }

// buildChain constructs the certificates described by k. A build error (an
// impossible template) is returned; callers treat it as "skip this input",
// never as a divergence.
func buildChain(k knobs) (*chain, error) {
	// --- root (self-signed CA) ---
	// CA validity is deliberately WIDE (±10 years) so that a verifier which
	// clamps "now" into the leaf's window (the planted relaxation in the red
	// proof) keeps the CA valid and the divergence is attributable solely to the
	// leaf-expiry relaxation, not to the CA falling out of its window.
	rootTmpl := &x509.Certificate{
		SerialNumber:          serial(0),
		Subject:               pkix.Name{CommonName: "diffkit-root"},
		NotBefore:             fixedNow.Add(-3650 * 24 * time.Hour),
		NotAfter:              fixedNow.Add(3650 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	rootDER, err := x509.CreateCertificate(newDetReader(100), rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		return nil, err
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		return nil, err
	}

	// --- intermediates ---
	var inters []*x509.Certificate
	parent := root
	parentKey := rootKey
	for i := 0; i < k.numInter; i++ {
		tmpl := &x509.Certificate{
			SerialNumber:          serial(int64(i + 1)),
			Subject:               pkix.Name{CommonName: "diffkit-inter"},
			NotBefore:             fixedNow.Add(-3650 * 24 * time.Hour),
			NotAfter:              fixedNow.Add(3650 * 24 * time.Hour),
			IsCA:                  !k.interNotCA,
			BasicConstraintsValid: true,
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		}
		if !k.bcNonCritical {
			// BasicConstraints is critical by default in Go's encoder; nothing to do.
		} else {
			// Force BasicConstraints to be encoded non-critical by supplying it as a
			// raw extension and disabling the automatic one.
			bc, _ := asn1.Marshal(basicConstraints{IsCA: tmpl.IsCA})
			tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, pkix.Extension{
				Id: oidBasicConstraints, Critical: false, Value: bc,
			})
			tmpl.BasicConstraintsValid = false
		}
		if k.interPathLenZero && i == 0 {
			tmpl.MaxPathLen = 0
			tmpl.MaxPathLenZero = true
		}
		// Apply the name constraint on the top-most intermediate only.
		if k.nameConstrain && i == 0 {
			tmpl.PermittedDNSDomains = []string{"example.com"}
			tmpl.PermittedDNSDomainsCritical = true
		}
		der, err := x509.CreateCertificate(newDetReader(uint64(200+i)), tmpl, parent, &interKey.PublicKey, parentKey)
		if err != nil {
			return nil, err
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
		inters = append(inters, c)
		parent = c
		parentKey = interKey
	}

	// --- leaf ---
	nb := fixedNow.Add(-1 * time.Hour)
	na := fixedNow.Add(1 * time.Hour)
	if k.leafExpired {
		nb = fixedNow.Add(-48 * time.Hour)
		na = fixedNow.Add(-24 * time.Hour)
	}
	if k.leafFuture {
		nb = fixedNow.Add(24 * time.Hour)
		na = fixedNow.Add(48 * time.Hour)
	}
	san := "host.example.com"
	if k.leafBadName {
		san = "host.evil.test"
	}
	leafTmpl := &x509.Certificate{
		SerialNumber:          serial(900),
		Subject:               pkix.Name{CommonName: san},
		NotBefore:             nb,
		NotAfter:              na,
		IsCA:                  false,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		DNSNames:              []string{san},
	}
	if k.unknownCritExt {
		leafTmpl.ExtraExtensions = append(leafTmpl.ExtraExtensions, pkix.Extension{
			// A private-arc OID that neither verifier knows, marked critical.
			Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}, Critical: true, Value: []byte{0x05, 0x00},
		})
	}
	signerParent := parent
	signerKey := parentKey
	if k.wrongSigner {
		// Forge the signature: sign the leaf with altKey via an "evil twin" parent
		// that shares the real parent's Subject but carries altKey's public key.
		// Go's CreateCertificate requires the signing key to match the parent's
		// public key, so we cannot simply pass a mismatched key; the twin makes the
		// call legal while producing a leaf whose signature will NOT verify against
		// the real parent in the trusted chain (both verifiers must reject).
		twinTmpl := &x509.Certificate{
			SerialNumber:          serial(950),
			Subject:               parent.Subject,
			NotBefore:             fixedNow.Add(-3650 * 24 * time.Hour),
			NotAfter:              fixedNow.Add(3650 * 24 * time.Hour),
			IsCA:                  true,
			BasicConstraintsValid: true,
			KeyUsage:              x509.KeyUsageCertSign,
		}
		twinDER, terr := x509.CreateCertificate(newDetReader(400), twinTmpl, twinTmpl, &altKey.PublicKey, altKey)
		if terr != nil {
			return nil, terr
		}
		twin, terr := x509.ParseCertificate(twinDER)
		if terr != nil {
			return nil, terr
		}
		signerParent = twin
		signerKey = altKey
	}
	leafDER, err := x509.CreateCertificate(newDetReader(300), leafTmpl, signerParent, &leafKey.PublicKey, signerKey)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		// A forged-signature leaf still parses; a genuinely malformed template is a skip.
		return nil, err
	}
	sum := sha256.Sum256(leafDER)
	return &chain{root: root, inters: inters, leaf: leaf, now: fixedNow, leafFP: hex.EncodeToString(sum[:])}, nil
}

type basicConstraints struct {
	IsCA       bool `asn1:"optional"`
	MaxPathLen int  `asn1:"optional,default:-1"`
}

var (
	oidBasicConstraints = asn1.ObjectIdentifier{2, 5, 29, 19}
)
