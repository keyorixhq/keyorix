package webauthnrp

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"fmt"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
)

// checkAttestationKeyAlg binds the algorithm an attestation statement names to
// the key that made its signature: the first x5c certificate (the TPM AIK, the
// packed or android-key attestation certificate, the fido-u2f certificate).
//
// go-webauthn v0.18.2 maps the statement's COSE alg to an x509 signature
// algorithm and calls Certificate.CheckSignature, which checks the key TYPE
// (RSA vs ECDSA) but not the CURVE: ES256K (-47) maps to ECDSA-with-SHA256 and
// verifies against a P-256 key (#4545), ES384 verifies against a P-256 key, and
// fido-u2f accepts any ECDSA certificate although §8.6 requires P-256. WebAuthn
// §5.8.5 fixes the curve of each ECDSA alg, and §8.3/§8.2/§8.4 require the
// signature to be made "using the algorithm specified in alg", so a mismatch is
// a malformed statement: it is refused, never accepted on the signature alone.
//
// It runs after the library accepted the registration, so it only ever turns an
// acceptance into a refusal. A compound statement is refused if any of its
// sub-statements mismatches, even when the library's "any" scope would have
// accepted on another one. apple carries no alg (its nonce binds the key),
// packed without x5c is self attestation (the library already requires alg to
// equal the credential key's alg there), and none carries nothing to check.
func checkAttestationKeyAlg(att *protocol.AttestationObject) error {
	if protocol.AttestationFormat(att.Format) == protocol.AttestationFormatCompound {
		for _, sub := range att.SubStatements {
			if err := checkStatementKeyAlg(sub.Format, sub.AttStatement); err != nil {
				return err
			}
		}
		return nil
	}
	return checkStatementKeyAlg(att.Format, att.AttStatement)
}

func checkStatementKeyAlg(format string, stmt map[string]any) error {
	var alg webauthncose.COSEAlgorithmIdentifier
	switch protocol.AttestationFormat(format) {
	case protocol.AttestationFormatTPM, protocol.AttestationFormatAndroidKey:
		a, ok := stmt["alg"].(int64)
		if !ok {
			return attAlgError(format, "statement has no integer alg")
		}
		alg = webauthncose.COSEAlgorithmIdentifier(a)
	case protocol.AttestationFormatPacked:
		if _, hasX5C := stmt["x5c"]; !hasX5C {
			return nil // self attestation
		}
		a, ok := stmt["alg"].(int64)
		if !ok {
			return attAlgError(format, "statement has no integer alg")
		}
		alg = webauthncose.COSEAlgorithmIdentifier(a)
	case protocol.AttestationFormatFIDOUniversalSecondFactor:
		alg = webauthncose.AlgES256 // §8.6: the attestation key is P-256, the signature ES256
	default:
		return nil
	}
	x5c, ok := stmt["x5c"].([]any)
	if !ok || len(x5c) == 0 {
		return attAlgError(format, "statement has no x5c certificate")
	}
	raw, ok := x5c[0].([]byte)
	if !ok {
		return attAlgError(format, "first x5c entry is not a certificate")
	}
	cert, err := x509.ParseCertificate(raw)
	if err != nil {
		return attAlgError(format, "first x5c certificate does not parse")
	}
	if !attestationKeyMatchesAlg(alg, cert.PublicKey) {
		return attAlgError(format, fmt.Sprintf("alg %s (%d) does not match the %s attestation key", alg, int64(alg), keyKind(cert.PublicKey)))
	}
	return nil
}

// attestationKeyMatchesAlg is the accepted alg-to-key table. Every alg not
// listed is refused: ES256K (-47) because no x509 certificate Go parses can
// carry a secp256k1 key, so a statement claiming it never matches its x5c key;
// the ML-DSA algs because no shipping authenticator attests with them and the
// x5c chain for them is untested here (widen this table, with a fixture, when
// one does).
func attestationKeyMatchesAlg(alg webauthncose.COSEAlgorithmIdentifier, pub any) bool {
	switch alg {
	case webauthncose.AlgES256, webauthncose.AlgESP256:
		return ecdsaOn(pub, elliptic.P256())
	case webauthncose.AlgES384, webauthncose.AlgESP384:
		return ecdsaOn(pub, elliptic.P384())
	case webauthncose.AlgES512, webauthncose.AlgESP512:
		return ecdsaOn(pub, elliptic.P521())
	case webauthncose.AlgEdDSA, webauthncose.AlgEd25519:
		_, ok := pub.(ed25519.PublicKey)
		return ok
	case webauthncose.AlgRS256, webauthncose.AlgRS384, webauthncose.AlgRS512, webauthncose.AlgRS1,
		webauthncose.AlgPS256, webauthncose.AlgPS384, webauthncose.AlgPS512:
		_, ok := pub.(*rsa.PublicKey)
		return ok
	default:
		return false
	}
}

func ecdsaOn(pub any, curve elliptic.Curve) bool {
	k, ok := pub.(*ecdsa.PublicKey)
	return ok && k.Curve == curve
}

func keyKind(pub any) string {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		return "ECDSA " + k.Curve.Params().Name
	case *rsa.PublicKey:
		return "RSA"
	case ed25519.PublicKey:
		return "Ed25519"
	default:
		return fmt.Sprintf("%T", pub)
	}
}

// attAlgError is the library's own attestation-format error, the type the
// library returns for a TPM/packed signature that does not verify, so core and
// the handlers see the same *protocol.Error they already map.
func attAlgError(format, detail string) error {
	return protocol.ErrAttestationFormat.WithDetails(fmt.Sprintf("%s attestation: %s", format, detail))
}
