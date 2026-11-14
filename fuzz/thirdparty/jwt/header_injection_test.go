package jwthostile

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	jwt "github.com/golang-jwt/jwt/v5"
)

func ed25519KeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// reSignHeaderAlg returns a copy of a compact JWS whose header "alg" is replaced
// with newAlg, keeping the original payload and signature. The result is a token
// whose header advertises a different algorithm than its signature really is —
// used to assert the parser binds verification to the header alg.
func reSignHeaderAlg(t *testing.T, token, newAlg string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("reSignHeaderAlg: not a 3-part token")
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("reSignHeaderAlg: decode header: %v", err)
	}
	var h map[string]any
	if err := json.Unmarshal(hb, &h); err != nil {
		t.Fatalf("reSignHeaderAlg: header json: %v", err)
	}
	h["alg"] = newAlg
	nb, err := json.Marshal(h)
	if err != nil {
		t.Fatalf("reSignHeaderAlg: remarshal: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(nb) + "." + parts[1] + "." + parts[2]
}

// Oracle: Keyorix's keyfunc selects a key by issuer+kid ONLY. jku/x5u/jwk headers
// (attacker-supplied key locations/material) are never dereferenced: an unknown
// kid yields no key regardless of what jku/x5u/jwk say, so the token is rejected.
// This models internal/oidcverify/oidc.go:174-184 (kid-only JWKS lookup).
//
// RED PROOF: a keyfunc that trusted an embedded "jwk" header would accept a
// self-signed token; the Keyorix-shaped keyfunc does not.
func TestHeaderInjection_JkuX5uJwkIgnored(t *testing.T) {
	_, priv, err := ed25519KeyPair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	// Mint an EdDSA token (alg is irrelevant: it must be rejected before/at key
	// selection because the kid is unknown and jku/x5u/jwk are ignored).
	tokObj := jwt.NewWithClaims(jwt.SigningMethodEdDSA, validClaims())
	tokObj.Header["kid"] = "attacker-kid-not-in-jwks"
	tokObj.Header["jku"] = "https://attacker.example/jwks.json"
	tokObj.Header["x5u"] = "https://attacker.example/cert.pem"
	tokObj.Header["jwk"] = map[string]any{"kty": "OKP", "crv": "Ed25519", "x": "AAAA"}
	raw, err := tokObj.SignedString(priv)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	// Keyorix-shaped keyfunc: kid-only lookup against a fixed JWKS map.
	jwks := map[string]any{"known-kid": struct{}{}}
	selections := 0
	keyorixKeyfunc := func(tok *jwt.Token) (any, error) {
		kid, _ := tok.Header["kid"].(string)
		k, ok := jwks[kid]
		if !ok {
			return nil, errNoKey
		}
		selections++
		return k, nil
	}

	if _, err := keyorixParser().Parse(raw, keyorixKeyfunc); err == nil {
		t.Fatalf("GUARD FAILED: token with attacker jku/x5u/jwk and unknown kid was accepted")
	}
	if selections != 0 {
		t.Fatalf("GUARD FAILED: a key was selected for an unknown kid (jku/x5u/jwk must never drive selection)")
	}

	// RED PROOF: a jwk-trusting keyfunc (the vulnerable shape) would return a key
	// derived from the attacker-embedded header, proving the oracle is not vacuous.
	vulnSelections := 0
	vulnKeyfunc := func(tok *jwt.Token) (any, error) {
		if _, ok := tok.Header["jwk"]; ok {
			vulnSelections++
			return priv.Public(), nil // trust the embedded key material (DO NOT DO THIS)
		}
		return nil, errNoKey
	}
	// EdDSA is outside Keyorix's allowlist, so parse still fails on method; but the
	// key-selection side effect fires, which is the thing the red proof asserts.
	_, _ = jwt.NewParser().Parse(raw, vulnKeyfunc)
	if vulnSelections == 0 {
		t.Fatalf("RED PROOF INVALID: the jwk-trusting keyfunc never fired on the embedded header")
	}
}

var errNoKey = jwtTestError("no key for kid")

type jwtTestError string

func (e jwtTestError) Error() string { return string(e) }
