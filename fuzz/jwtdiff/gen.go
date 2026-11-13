package jwtdiff

// JWT/JWS token generator. The fuzzer's bytes are decoded into "knobs" that
// describe an attacker-controlled token: which algorithm goes in the header,
// which key signs it (the genuine one, a wrong one, or the RSA public key abused
// as an HMAC secret — the classic RS/HS confusion), and how the registered
// claims (exp, nbf, aud) are shaped. The SAME token string and the SAME pinned
// verification config are then handed to both verifiers (golang-jwt and the
// independent stdlib reference), so only the accept/reject-plus-subject DECISION
// can differ.
//
// Keys are generated once per process with crypto/rand; the trust decision
// depends on the knobs, not on the exact key bytes, so minimise/replay within a
// process are stable.

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"time"
)

var fixedNow = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

const expectedAud = "keyorix-client"

var b64 = base64.RawURLEncoding

// Genuine keys (the verifier pins to these) and attacker keys (same type, wrong
// value). Generated once; see file doc.
var (
	rsaKey      = mustRSA()
	attackerRSA = mustRSA()
	ecKey       = mustEC()
	attackerEC  = mustEC()
	hmacSecret  = []byte("genuine-hmac-secret-0123456789abcdef")
	attackerHS  = []byte("attacker-hmac-secret-0123456789abcd")
	// rsaPubDER is the genuine RSA public key in DER — the "secret" an RS/HS
	// confusion attacker would try to pass off as an HMAC key.
	rsaPubDER = mustMarshalPub(&rsaKey.PublicKey)
)

func mustRSA() *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return k
}

func mustEC() *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return k
}

func mustMarshalPub(k *rsa.PublicKey) []byte {
	der, err := x509.MarshalPKIXPublicKey(k)
	if err != nil {
		panic(err)
	}
	return der
}

// algName maps the small alg code to its JWS "alg" header value.
const (
	algRS256 = 0
	algES256 = 1
	algHS256 = 2
	algNone  = 3
)

func algName(code uint8) string {
	switch code {
	case algRS256:
		return "RS256"
	case algES256:
		return "ES256"
	case algHS256:
		return "HS256"
	default:
		return "none"
	}
}

type knobs struct {
	expectedAlg uint8 // verifier is PINNED to this family: RS256|ES256|HS256
	tokenAlg    uint8 // header alg the attacker chose: RS256|ES256|HS256|none
	wrongKey    bool  // sign with the attacker key of tokenAlg's type
	rsPubAsHMAC bool  // sign HS256 using the genuine RSA public key DER as the secret
	expKind     uint8 // 0 valid(future) | 1 expired | 2 missing
	nbfKind     uint8 // 0 none | 1 past(ok) | 2 future(reject)
	audKind     uint8 // 0 string-ok | 1 array-ok | 2 wrong | 3 missing | 4 array-without
	tamperSig   bool
	addKid      bool
}

func decodeKnobs(b []byte) knobs {
	at := func(i int) byte {
		if i < len(b) {
			return b[i]
		}
		return 0
	}
	return knobs{
		expectedAlg: at(0) % 3,
		tokenAlg:    at(1) % 4,
		wrongKey:    at(2)&1 == 1,
		rsPubAsHMAC: at(3)&1 == 1,
		expKind:     at(4) % 3,
		nbfKind:     at(5) % 3,
		audKind:     at(6) % 5,
		tamperSig:   at(7)&1 == 1,
		addKid:      at(8)&1 == 1,
	}
}

// verifyConfig is the pinned verifier state both implementations share.
type verifyConfig struct {
	expectedAlg string
	rsaPub      *rsa.PublicKey
	ecPub       *ecdsa.PublicKey
	hmacKey     []byte
	aud         string
	now         time.Time
}

func configFor(k knobs) verifyConfig {
	return verifyConfig{
		expectedAlg: algName(k.expectedAlg),
		rsaPub:      &rsaKey.PublicKey,
		ecPub:       &ecKey.PublicKey,
		hmacKey:     hmacSecret,
		aud:         expectedAud,
		now:         fixedNow,
	}
}

// buildToken produces the compact JWS string described by k.
func buildToken(k knobs) string {
	header := map[string]any{"alg": algName(k.tokenAlg), "typ": "JWT"}
	if k.addKid {
		header["kid"] = "key-xyz"
	}
	payload := map[string]any{
		"sub": "user-123",
		"iss": "https://idp.example",
	}
	switch k.audKind {
	case 0:
		payload["aud"] = expectedAud
	case 1:
		payload["aud"] = []any{"other", expectedAud}
	case 2:
		payload["aud"] = "someone-else"
	case 3:
		// missing
	case 4:
		payload["aud"] = []any{"a", "b"}
	}
	switch k.expKind {
	case 0:
		payload["exp"] = fixedNow.Add(1 * time.Hour).Unix()
	case 1:
		payload["exp"] = fixedNow.Add(-1 * time.Hour).Unix()
	case 2:
		// missing exp
	}
	switch k.nbfKind {
	case 1:
		payload["nbf"] = fixedNow.Add(-1 * time.Hour).Unix()
	case 2:
		payload["nbf"] = fixedNow.Add(1 * time.Hour).Unix()
	}

	hj, _ := json.Marshal(header)
	pj, _ := json.Marshal(payload)
	signingInput := b64.EncodeToString(hj) + "." + b64.EncodeToString(pj)

	var sig []byte
	switch k.tokenAlg {
	case algNone:
		sig = nil
	case algHS256:
		secret := hmacSecret
		if k.rsPubAsHMAC {
			secret = rsaPubDER
		} else if k.wrongKey {
			secret = attackerHS
		}
		m := hmac.New(sha256.New, secret)
		m.Write([]byte(signingInput))
		sig = m.Sum(nil)
	case algRS256:
		key := rsaKey
		if k.wrongKey {
			key = attackerRSA
		}
		h := sha256.Sum256([]byte(signingInput))
		sig, _ = rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h[:])
	case algES256:
		key := ecKey
		if k.wrongKey {
			key = attackerEC
		}
		h := sha256.Sum256([]byte(signingInput))
		r, s, _ := ecdsa.Sign(rand.Reader, key, h[:])
		sig = ecdsaRS(r, s)
	}
	if k.tamperSig && len(sig) > 0 {
		sig[len(sig)-1] ^= 0x01
	}
	return signingInput + "." + b64.EncodeToString(sig)
}

// ecdsaRS encodes r,s as the fixed-width 64-byte R||S form JWS ES256 uses.
func ecdsaRS(r, s *big.Int) []byte {
	out := make([]byte, 64)
	r.FillBytes(out[:32])
	s.FillBytes(out[32:])
	return out
}
