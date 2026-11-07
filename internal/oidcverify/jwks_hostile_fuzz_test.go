package oidcverify

// jwks_hostile_fuzz_test.go: FuzzJWKSHostileIdP is the hostile-backend
// record-and-mutate target for the OIDC JWKS fetch path (rules: internal/
// fuzzutil/hostile/RULES.md). The IdP's JWKS document is served from a local
// httptest server and mutated field by field, plus framing/encoding/redirect/
// network faults. Two tokens are verified through the real HTTPJWKSResolver and
// OIDCVerifier:
//
//	A: signed by the legitimate key, kid "k1". May verify only if the DELIVERED
//	   document, read by the strict decoder below, really contains that key.
//	B: signed by an attacker key but carrying kid "k1". Must NEVER verify: no
//	   mutation of the legitimate document can introduce the attacker key, so a
//	   successful verification is a forged identity.
//
// The strict JWKS decoder follows RFC 7517/7518: kty "RSA", use absent or "sig",
// n and e base64url (no padding) of the exact legitimate modulus/exponent.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/hostile"
)

const (
	hostileIssuer = "https://issuer.example.test"
	hostileAud    = "kx-hostile-aud"
	hostileKid    = "k1"
)

var (
	hostileKeysOnce sync.Once
	hostileKeyA     *rsa.PrivateKey // legitimate IdP key
	hostileKeyB     *rsa.PrivateKey // attacker key
)

func hostileKeys() (*rsa.PrivateKey, *rsa.PrivateKey) {
	hostileKeysOnce.Do(func() {
		var err error
		if hostileKeyA, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
			panic(err)
		}
		if hostileKeyB, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
			panic(err)
		}
	})
	return hostileKeyA, hostileKeyB
}

func hostileJWKS(pub *rsa.PublicKey) []byte {
	doc := map[string]any{"keys": []any{
		map[string]any{"kty": "RSA", "kid": hostileKid, "use": "sig", "alg": "RS256",
			"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())},
		map[string]any{"kty": "RSA", "kid": "k2", "use": "sig", "alg": "RS256",
			"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e": "AQAB"},
	}}
	b, _ := json.Marshal(doc)
	return b
}

// strictJWKSHasKey reports whether the delivered document, read strictly,
// publishes pub under hostileKid as a signature key.
func strictJWKSHasKey(body []byte, pub *rsa.PublicKey) bool {
	var d struct {
		Keys []struct {
			Kty string  `json:"kty"`
			Kid string  `json:"kid"`
			Use *string `json:"use"`
			N   string  `json:"n"`
			E   string  `json:"e"`
		} `json:"keys"`
	}
	if json.Unmarshal(body, &d) != nil {
		return false
	}
	for _, k := range d.Keys {
		if k.Kid != hostileKid || k.Kty != "RSA" || (k.Use != nil && *k.Use != "sig" && *k.Use != "") {
			continue
		}
		n, err1 := base64.RawURLEncoding.DecodeString(k.N)
		e, err2 := base64.RawURLEncoding.DecodeString(k.E)
		if err1 != nil || err2 != nil {
			continue
		}
		if new(big.Int).SetBytes(n).Cmp(pub.N) == 0 && new(big.Int).SetBytes(e).Cmp(big.NewInt(int64(pub.E))) == 0 {
			return true
		}
	}
	return false
}

func hostileToken(key *rsa.PrivateKey) string {
	now := time.Now()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": hostileIssuer, "aud": hostileAud, "sub": "alice",
		"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
	})
	tok.Header["kid"] = hostileKid
	s, err := tok.SignedString(key)
	if err != nil {
		panic(err)
	}
	return s
}

func FuzzJWKSHostileIdP(f *testing.F) {
	f.Add([]byte{})
	for _, p := range []hostile.Program{
		{Ops: []hostile.Op{{Code: 0, A: 3}}},        // n -> null
		{Ops: []hostile.Op{{Code: 1, A: 2}}},        // kid removed
		{Ops: []hostile.Op{{Code: 6, A: 2, B: 14}}}, // kid -> canary
		{Ops: []hostile.Op{{Code: 3, A: 1, B: 1}}},  // duplicate kty
		{Ops: []hostile.Op{{Code: 2, A: 1, B: 1}}},  // kty -> number
		{Ops: []hostile.Op{{Code: 7, A: 0, B: 2}}},  // oversized list
		{Ops: []hostile.Op{{Code: 5, A: 0, B: 3}}},  // deep nesting
		{Redir: 1},             // cross-origin redirect
		{Redir: 3},             // same-origin redirect once
		{Redir: 2},             // redirect loop
		{Fault: 2}, {Fault: 5}, // network faults
		{Enc: 2}, {Trunc: 17}, // gzip bomb, truncation
		{Ops: []hostile.Op{{Code: 14, A: 3, B: 6}}}, // crossover
	} {
		f.Add(hostile.Encode(p))
	}

	a, b := hostileKeys()
	valid := hostileJWKS(&a.PublicKey)

	f.Fuzz(func(t *testing.T, prog []byte) {
		p := hostile.Decode(prog)
		h := hostile.New(hostile.Config{
			Routes: []hostile.Route{{Name: "jwks", Method: "GET", Prefix: "/jwks", Valid: func(int, *http.Request) hostile.Resp {
				return hostile.Resp{Status: 200, CT: "application/json", Body: valid}
			}}},
			Program: p, AllowRedirect: true, RequestCeiling: 3,
		})
		defer h.Close()

		res, err := NewHTTPJWKSResolver(map[string]string{hostileIssuer: h.URL() + "/jwks"})
		if err != nil {
			t.Fatalf("resolver: %v", err)
		}
		v, err := NewOIDCVerifier([]OIDCTrustedIssuer{{Issuer: hostileIssuer, Audiences: []string{hostileAud}}}, res)
		if err != nil {
			t.Fatalf("verifier: %v", err)
		}

		var iss, sub string
		errA := h.Run("OIDCVerifier.Verify(legit token)", func(ctx context.Context) error {
			var e error
			iss, sub, e = v.Verify(ctx, hostileToken(a))
			return e
		})
		if p.Pristine() && (errA != nil || iss != hostileIssuer || sub != "alice") {
			h.Violate("O6 LIVENESS: pristine Verify returned %q %q %v", iss, sub, errA)
		}
		if errA == nil {
			body, kind := h.Delivery("jwks", func(b []byte) bool { return strictJWKSHasKey(b, &a.PublicKey) })
			switch {
			case kind == "status":
				h.Violate("O5/bad-status-accepted: a token verified against a JWKS response whose final HTTP status was not 200")
			case kind == "bad":
				h.Violate("O5/incomplete: a token verified against a JWKS exchange whose content was incomplete, redirected away or non-200")
			case kind == "transport":
				h.Violate("O5/transport-error-ignored: a token verified although the JWKS response ended in a transport/framing/gzip error after the full JSON value")
			case hostile.HasDuplicateKeys(body):
				// duplicate member names: no single correct reading (RFC 8259)
			case !strictJWKSHasKey(body, &a.PublicKey):
				h.Violate("O5/jwks-key: token verified but the delivered JWKS does not (strictly) publish the signing key under kid %q; delivered %d bytes", hostileKid, len(body))
			case iss != hostileIssuer || sub != "alice":
				h.Violate("O5/identity: verified identity %q %q differs from the token", iss, sub)
			}
		}

		var fiss, fsub string
		errB := h.Run("OIDCVerifier.Verify(attacker-signed token)", func(ctx context.Context) error {
			var e error
			fiss, fsub, e = v.Verify(ctx, hostileToken(b))
			return e
		})
		if errB == nil {
			h.Violate("O5/FORGED-IDENTITY: a token signed by an attacker key verified as %q %q", fiss, fsub)
		}
		h.Finish(t.Fatalf)
	})
}
