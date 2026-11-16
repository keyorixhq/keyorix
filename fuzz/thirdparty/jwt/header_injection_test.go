package jwthostile

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	jwt "github.com/golang-jwt/jwt/v5"

	"github.com/keyorixhq/keyorix/internal/oidcverify"
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

// recordingJWKS is an oidcverify.JWKSResolver stub. It serves exactly one trusted
// key under one (issuer, kid) and records every (issuer, kid) it is asked for. The
// resolver interface carries no URL, so "never received a URL" is structural; what
// the recording proves is that key selection is driven by (iss, kid) alone.
type recordingJWKS struct {
	issuer, kid string
	key         any
	asked       [][2]string
}

func (r *recordingJWKS) Key(_ context.Context, issuer, kid string) (any, error) {
	r.asked = append(r.asked, [2]string{issuer, kid})
	if issuer == r.issuer && kid == r.kid {
		return r.key, nil
	}
	return nil, errNoKey
}

// rsaJWK renders an RSA public key as the JWK object an attacker would embed in a
// "jwk" header.
func rsaJWK(pub *rsa.PublicKey) map[string]any {
	e := big.NewInt(int64(pub.E)).Bytes()
	return map[string]any{
		"kty": "RSA",
		"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(e),
	}
}

// Oracle: Keyorix selects the verification key by issuer+kid ONLY. jku/x5u/jwk
// headers (attacker-supplied key locations/material) are never dereferenced: an
// unknown kid yields no key regardless of what jku/x5u/jwk say, so the token is
// rejected.
//
// GREEN half drives the REAL internal/oidcverify.OIDCVerifier (the production
// OIDC keyfunc, OIDCVerifier.VerifyWithExpiry) over a recording JWKSResolver stub.
// The attack token uses an ALLOWED alg (RS256), is signed by the attacker's key
// (whose real public half is embedded in the "jwk" header), and carries an unknown
// kid plus hostile jku/x5u/jwk. It must be rejected, and the resolver must have
// been asked only for (issuer, "attacker-kid").
//
// The token MUST use an allowed alg: golang-jwt checks the alg allowlist BEFORE it
// calls the keyfunc, so a token with a disallowed alg (e.g. EdDSA) fails on the
// method alone and the keyfunc never runs — which made an earlier version of this
// test unable to go red for a jwk-trusting keyfunc.
//
// POSITIVE CONTROL: a legitimate token with kid=known-kid IS accepted and the
// resolver IS consulted, so the resolver is reachable and the rejection above is
// attributable to kid-only selection, not to an unrelated failure.
//
// RED PROOF: the same attack token under the same allowlist parser
// (keyorixParser) with a jwk-TRUSTING keyfunc IS accepted (err == nil), so the
// attack token is genuinely dangerous to a vulnerable keyfunc and the GREEN
// rejection is not an artefact of a malformed token.
func TestHeaderInjection_JkuX5uJwkIgnored(t *testing.T) {
	const issuer = "https://issuer.example"
	const aud = "keyorix"

	attackerKey := mustRSA(t)
	trustedKey := mustRSA(t)

	claims := func() jwt.RegisteredClaims {
		c := validClaims()
		c.Issuer = issuer
		c.Audience = jwt.ClaimStrings{aud}
		return c
	}

	attackTok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims())
	attackTok.Header["kid"] = "attacker-kid"
	attackTok.Header["jku"] = "https://attacker.example/jwks.json"
	attackTok.Header["x5u"] = "https://attacker.example/cert.pem"
	attackTok.Header["jwk"] = rsaJWK(&attackerKey.PublicKey)
	attackRaw, err := attackTok.SignedString(attackerKey)
	if err != nil {
		t.Fatalf("mint attack token: %v", err)
	}

	legitTok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims())
	legitTok.Header["kid"] = "known-kid"
	legitRaw, err := legitTok.SignedString(trustedKey)
	if err != nil {
		t.Fatalf("mint legit token: %v", err)
	}

	newVerifier := func(res *recordingJWKS) *oidcverify.OIDCVerifier {
		v, err := oidcverify.NewOIDCVerifier(
			[]oidcverify.OIDCTrustedIssuer{{Issuer: issuer, Audiences: []string{aud}}}, res)
		if err != nil {
			t.Fatalf("NewOIDCVerifier: %v", err)
		}
		return v
	}

	// POSITIVE CONTROL.
	ctlRes := &recordingJWKS{issuer: issuer, kid: "known-kid", key: &trustedKey.PublicKey}
	if _, sub, err := newVerifier(ctlRes).Verify(context.Background(), legitRaw); err != nil || sub != "alice" {
		t.Fatalf("POSITIVE CONTROL FAILED: legit token with known kid rejected (sub=%q err=%v); the GREEN half would be vacuous", sub, err)
	}
	if len(ctlRes.asked) != 1 || ctlRes.asked[0] != [2]string{issuer, "known-kid"} {
		t.Fatalf("POSITIVE CONTROL FAILED: resolver asked %v, want exactly one (iss, known-kid) lookup", ctlRes.asked)
	}

	// GREEN: attack token rejected; selection driven by (iss, kid) only.
	res := &recordingJWKS{issuer: issuer, kid: "known-kid", key: &trustedKey.PublicKey}
	if _, _, err := newVerifier(res).Verify(context.Background(), attackRaw); err == nil {
		t.Fatalf("GUARD FAILED: token with attacker jku/x5u/jwk and unknown kid was accepted")
	}
	if len(res.asked) != 1 || res.asked[0] != [2]string{issuer, "attacker-kid"} {
		t.Fatalf("GUARD FAILED: resolver asked %v, want exactly one (iss, attacker-kid) lookup (jku/x5u/jwk must never drive selection)", res.asked)
	}

	// RED PROOF: a jwk-trusting keyfunc (the vulnerable shape) under the SAME
	// allowlist parser accepts the SAME attack token.
	vulnSelections := 0
	vulnKeyfunc := func(tok *jwt.Token) (any, error) {
		if _, ok := tok.Header["jwk"]; ok {
			vulnSelections++
			return &attackerKey.PublicKey, nil // trust the embedded key material (DO NOT DO THIS)
		}
		return nil, errNoKey
	}
	if _, err := keyorixParser().Parse(attackRaw, vulnKeyfunc); err != nil {
		t.Fatalf("RED PROOF INVALID: a jwk-trusting keyfunc did not accept the attack token (err=%v); the token cannot distinguish a vulnerable keyfunc", err)
	}
	if vulnSelections != 1 {
		t.Fatalf("RED PROOF INVALID: jwk-trusting keyfunc fired %d times, want 1", vulnSelections)
	}
}

var errNoKey = jwtTestError("no key for kid")

type jwtTestError string

func (e jwtTestError) Error() string { return string(e) }
