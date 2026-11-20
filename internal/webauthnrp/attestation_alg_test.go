package webauthnrp

// The same alg-to-key binding as TestTPMAttestation_AlgMustMatchAIKKey, for the
// other formats whose signature go-webauthn checks with
// x509.Certificate.CheckSignature (curve-blind): packed with x5c (basic
// attestation) and a compound statement carrying one. Every case goes through
// FinishRegistration on the RP as keyorix builds it, so on a tree without
// checkAttestationKeyAlg the packed and compound "refused" cases are accepted
// (the red half of the proof). The fido-u2f cases pin the library's own P-256
// check (§8.6), which already refuses a P-384 certificate; they are a
// regression pin, not part of the red proof.

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
)

// attCertFor is a §8.2.1-shaped attestation certificate for key, self-signed by
// a fixed P-256 issuer key (keyorix's RP validates no chain).
func attCertFor(t *testing.T, key crypto.Signer) []byte {
	t.Helper()
	issuer := tpmDetKey(t, "packed issuer")
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject: pkix.Name{
			Country: []string{"US"}, Organization: []string{"Keyorix Test"},
			OrganizationalUnit: []string{"Authenticator Attestation"}, CommonName: "keyorix alg-binding test",
		},
		NotBefore: time.Unix(0, 0), NotAfter: time.Unix(4102444800, 0),
		BasicConstraintsValid: true, IsCA: false,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), issuer)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// signWith signs msg with key, hashing with h (PKCS #1 v1.5 for RSA, ASN.1 ECDSA).
func signWith(t *testing.T, key crypto.Signer, h crypto.Hash, msg []byte) []byte {
	t.Helper()
	var digest []byte
	switch h {
	case crypto.SHA256:
		d := sha256.Sum256(msg)
		digest = d[:]
	case crypto.SHA384:
		d := sha512.Sum384(msg)
		digest = d[:]
	default:
		t.Fatalf("hash %v", h)
	}
	sig, err := key.Sign(rand.Reader, digest, h)
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

func p384Key(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.ParseRawPrivateKey(elliptic.P384(), bytes.Repeat([]byte{0x3C}, 48))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// attResponse is the registration JSON for an attestation object of format
// format with statement stmt, over the TPM fixture's credential and ceremony.
func attResponse(t *testing.T, fx *tpmFixture, format string, stmt any) []byte {
	t.Helper()
	att, err := webauthncbor.Marshal(map[string]any{"fmt": format, "attStmt": stmt, "authData": fx.authData})
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.RawURLEncoding.EncodeToString
	b, err := json.Marshal(map[string]any{
		"id": b64(tpmCredID), "rawId": b64(tpmCredID), "type": "public-key",
		"response": map[string]any{"clientDataJSON": b64(fx.clientData), "attestationObject": b64(att)},
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// packedStmt is a packed basic attestation statement: alg, a signature over
// authData || H(clientData) by key hashed with h, and key's certificate.
func packedStmt(t *testing.T, fx *tpmFixture, alg int64, key crypto.Signer, h crypto.Hash) map[string]any {
	t.Helper()
	cdh := sha256.Sum256(fx.clientData)
	sig := signWith(t, key, h, append(append([]byte{}, fx.authData...), cdh[:]...))
	return map[string]any{"alg": alg, "sig": sig, "x5c": [][]byte{attCertFor(t, key)}}
}

// u2fStmt is a fido-u2f statement signed (ES256 over SHA-256) by key.
func u2fStmt(t *testing.T, fx *tpmFixture, key crypto.Signer) map[string]any {
	t.Helper()
	raw, err := fx.credKey.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	rpIDHash := sha256.Sum256([]byte(tpmRPID))
	cdh := sha256.Sum256(fx.clientData)
	data := []byte{0x00}
	data = append(data, rpIDHash[:]...)
	data = append(data, cdh[:]...)
	data = append(data, tpmCredID...)
	data = append(data, raw...) // 0x04 || X || Y
	return map[string]any{"sig": signWith(t, key, crypto.SHA256, data), "x5c": [][]byte{attCertFor(t, key)}}
}

// TestAttestation_AlgMustMatchCertKey: for packed (x5c), fido-u2f and compound,
// a statement whose alg does not name its certificate key's type and curve is
// refused with the library's attestation-format *protocol.Error; the genuine
// combinations stay accepted.
func TestAttestation_AlgMustMatchCertKey(t *testing.T) {
	fx := newTPMFixture(t)
	p256 := tpmDetKey(t, "packed attestation")
	p384 := p384Key(t)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	goodPacked := packedStmt(t, fx, -7, p256, crypto.SHA256)
	es256kPacked := packedStmt(t, fx, algES256K, p256, crypto.SHA256)
	cases := []struct {
		name   string
		format string
		stmt   any
		accept bool
	}{
		{"packed ES256 with a P-256 cert", "packed", goodPacked, true},
		{"packed ES384 with a P-384 cert", "packed", packedStmt(t, fx, -35, p384, crypto.SHA384), true},
		{"packed RS256 with an RSA cert", "packed", packedStmt(t, fx, -257, rsaKey, crypto.SHA256), true},
		{"packed ES256K (-47) with a P-256 cert", "packed", es256kPacked, false},
		{"packed ES256 with a P-384 cert", "packed", packedStmt(t, fx, -7, p384, crypto.SHA256), false},
		{"fido-u2f with a P-256 cert", "fido-u2f", u2fStmt(t, fx, p256), true},
		{"fido-u2f with a P-384 cert", "fido-u2f", u2fStmt(t, fx, p384), false},
		{"compound of two genuine packed statements", "compound", []any{
			map[string]any{"fmt": "packed", "attStmt": goodPacked},
			map[string]any{"fmt": "packed", "attStmt": packedStmt(t, fx, -257, rsaKey, crypto.SHA256)},
		}, true},
		{"compound carrying a packed ES256K (-47) with a P-256 cert", "compound", []any{
			map[string]any{"fmt": "packed", "attStmt": goodPacked},
			map[string]any{"fmt": "packed", "attStmt": es256kPacked},
		}, false},
	}
	rp := newKeyorixRP(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := finishErr(rp, attResponse(t, fx, tc.format, tc.stmt))
			if tc.accept {
				if err != nil {
					t.Fatalf("genuine attestation rejected: %v", err)
				}
				return
			}
			requireAttFormatRefusal(t, tc.name, err)
		})
	}
}
