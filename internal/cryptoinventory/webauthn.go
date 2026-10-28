package cryptoinventory

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
)

// WebAuthnCredentialInput is one stored passkey: its COSE_Key public key (as the
// credential store holds it) and when it was registered. The public key is read
// only to learn its algorithm and size; nothing of it is emitted.
type WebAuthnCredentialInput struct {
	PublicKey []byte
	CreatedAt time.Time
}

// WebAuthnKey is the algorithm of one credential public key.
type WebAuthnKey struct {
	Algorithm   string
	KeySizeBits int
	PostQuantum bool
}

// ClassifyWebAuthnKey reads the algorithm and size from a COSE_Key. Anything that
// does not parse, or that is a key type this version does not model, is an error:
// the caller records it as unclassifiable (scored by the fail-closed rule).
func ClassifyWebAuthnKey(coseKey []byte) (WebAuthnKey, error) {
	var hdr webauthncose.PublicKeyData
	if err := webauthncbor.Unmarshal(coseKey, &hdr); err != nil {
		return WebAuthnKey{}, errors.New("credential public key is not a COSE_Key")
	}
	coseAlg := webauthncose.COSEAlgorithmIdentifier(hdr.Algorithm).String()
	if webauthncose.COSEKeyType(hdr.KeyType) == webauthncose.AKP {
		// Only the ML-DSA parameter sets (FIPS 204) are post-quantum; any other
		// algorithm on an AKP key is not modelled and must not score as PQ.
		name, ok := coseMLDSA[hdr.Algorithm]
		if !ok {
			return WebAuthnKey{}, errors.New("credential AKP public key names an algorithm that is not ML-DSA")
		}
		return WebAuthnKey{Algorithm: fmt.Sprintf("%s (COSE %d)", name, hdr.Algorithm), PostQuantum: true}, nil
	}
	pub, err := webauthncose.ParsePublicKey(coseKey)
	if err != nil {
		return WebAuthnKey{}, errors.New("credential public key is not a supported COSE key")
	}
	switch k := pub.(type) {
	case webauthncose.EC2PublicKeyData:
		bits, ok := map[int64]int{int64(webauthncose.P256): 256, int64(webauthncose.P384): 384, int64(webauthncose.P521): 521}[k.Curve]
		if !ok {
			return WebAuthnKey{}, errors.New("credential EC2 public key is on a curve that is not modelled")
		}
		return WebAuthnKey{Algorithm: fmt.Sprintf("ECDSA-P%d (COSE %s)", bits, coseAlg), KeySizeBits: bits}, nil
	case webauthncose.RSAPublicKeyData:
		bits := rsaBits(k.Modulus)
		return WebAuthnKey{Algorithm: fmt.Sprintf("RSA-%d (COSE %s)", bits, coseAlg), KeySizeBits: bits}, nil
	case webauthncose.OKPPublicKeyData:
		return WebAuthnKey{Algorithm: "Ed25519 (COSE " + coseAlg + ")", KeySizeBits: 256}, nil
	}
	return WebAuthnKey{}, errors.New("credential public key type is not modelled")
}

// coseMLDSA names the COSE algorithm identifiers registered for ML-DSA
// (draft-ietf-cose-dilithium); go-webauthn does not export them.
var coseMLDSA = map[int64]string{-48: "ML-DSA-44", -49: "ML-DSA-65", -50: "ML-DSA-87"}

func rsaBits(modulus []byte) int {
	for len(modulus) > 0 && modulus[0] == 0 {
		modulus = modulus[1:]
	}
	if len(modulus) == 0 {
		return 0
	}
	n := len(modulus) * 8
	for b := modulus[0]; b&0x80 == 0; b <<= 1 {
		n--
	}
	return n
}

// webAuthnCredentialAssets groups the enumerated credentials by algorithm: one
// asset per distinct algorithm, with the credential count and registration range
// in its notes. Credentials whose key cannot be classified share one fail-closed
// asset and raise a warning.
func webAuthnCredentialAssets(rpID string, creds []WebAuthnCredentialInput) ([]Asset, []string) {
	type group struct {
		key         WebAuthnKey
		count       int
		first, last time.Time
	}
	groups := map[string]*group{}
	var unknown group
	for _, c := range creds {
		k, err := ClassifyWebAuthnKey(c.PublicKey)
		g := &unknown
		if err == nil {
			if groups[k.Algorithm] == nil {
				groups[k.Algorithm] = &group{key: k}
			}
			g = groups[k.Algorithm]
		}
		if g.count == 0 || c.CreatedAt.Before(g.first) {
			g.first = c.CreatedAt
		}
		if g.count == 0 || c.CreatedAt.After(g.last) {
			g.last = c.CreatedAt
		}
		g.count++
	}
	names := make([]string, 0, len(groups))
	for n := range groups {
		names = append(names, n)
	}
	sort.Strings(names)

	mk := func(id string, g group, k WebAuthnKey) Asset {
		first := g.first.UTC()
		return Asset{ID: id, Name: "WebAuthn passkey public keys (" + k.Algorithm + ")", Class: ClassWebAuthn,
			Primitive: "signature", Algorithm: k.Algorithm, KeySizeBits: k.KeySizeBits,
			Asymmetric: !k.PostQuantum, PostQuantum: k.PostQuantum, CreatedAt: &first,
			Storage: "database: each credential's public key and signature counter",
			Notes: fmt.Sprintf("%d credential(s) registered %s to %s; relying party %s; private keys stay on the authenticator",
				g.count, g.first.UTC().Format("2006-01-02"), g.last.UTC().Format("2006-01-02"), rpID)}
	}
	var assets []Asset
	for _, n := range names {
		g := groups[n]
		assets = append(assets, mk("webauthn-passkeys."+slug(n), *g, g.key))
	}
	var warns []string
	if unknown.count > 0 {
		a := mk("webauthn-passkeys.unknown", unknown, WebAuthnKey{Algorithm: "unknown"})
		a.Name = "WebAuthn passkey public keys (unclassifiable)"
		assets = append(assets, a)
		warns = append(warns, fmt.Sprintf("%d WebAuthn credential(s) have a public key that could not be classified", unknown.count))
	}
	return assets, warns
}

func slug(s string) string {
	return strings.Trim(nonSlug.ReplaceAllString(strings.ToLower(s), "-"), "-")
}
