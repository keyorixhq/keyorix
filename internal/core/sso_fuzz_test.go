package core

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
)

// FuzzVerifyIDToken fuzzes KeyorixCore.verifyIDToken, the interactive-SSO login
// path: the id_token an external IdP returns is validated here on every SSO
// sign-in. It is the browser-facing sibling of OIDCVerifier.Verify (machine
// federation), so it gets the same treatment — assert no panic, result-shape
// consistency, and the signature-bypass rejection invariant.
func FuzzVerifyIDToken(f *testing.F) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		f.Fatal(err)
	}
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		f.Fatal(err)
	}
	p := &SSOProvider{Name: "okta", Issuer: "https://idp.test", ClientID: "client-1"}
	c := &KeyorixCore{
		now:          time.Now,
		ssoJWKS:      staticResolver{kid: "kid-1", key: &key.PublicKey},
		ssoProviders: map[string]*SSOProvider{"okta": p},
	}
	const nonce = "N1"

	// trustedKeySigned records every token signed with the trusted key. The fuzzer
	// never holds that private key, so it is the sound set of tokens that may
	// legitimately verify (see the rejection invariant below).
	trustedKeySigned := map[string]bool{}
	sign := func(signKey *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		tok.Header["kid"] = kid
		s, serr := tok.SignedString(signKey)
		if serr != nil {
			f.Fatal(serr)
		}
		if signKey == key {
			trustedKeySigned[s] = true
		}
		return s
	}
	base := func() jwt.MapClaims {
		return jwt.MapClaims{
			"iss": "https://idp.test", "aud": "client-1", "sub": "okta|123",
			"email": "ada@x.io", "nonce": nonce,
			"exp": time.Now().Add(time.Hour).Unix(),
		}
	}

	// --- Seed corpus (mirrors TestVerifyIDToken's cases) ----------------------
	f.Add("")
	valid := sign(key, "kid-1", base())
	f.Add(valid)
	f.Add(valid[:len(valid)-5]) // truncated
	f.Add(valid[5:])            // front cut off
	f.Add(valid + "x")          // trailing garbage

	wrongNonce := base()
	wrongNonce["nonce"] = "N2"
	f.Add(sign(key, "kid-1", wrongNonce))

	wrongAud := base()
	wrongAud["aud"] = "other-client"
	f.Add(sign(key, "kid-1", wrongAud))

	wrongIss := base()
	wrongIss["iss"] = "https://evil.test"
	f.Add(sign(key, "kid-1", wrongIss))

	expired := base()
	expired["exp"] = time.Now().Add(-2 * time.Hour).Unix()
	f.Add(sign(key, "kid-1", expired))

	noSub := base()
	delete(noSub, "sub")
	f.Add(sign(key, "kid-1", noSub))

	multiAudNoAzp := base()
	multiAudNoAzp["aud"] = []string{"client-1", "other-trusted"}
	f.Add(sign(key, "kid-1", multiAudNoAzp)) // multi-aud without azp — must be rejected

	f.Add(sign(other, "kid-1", base()))     // untrusted signing key
	f.Add(sign(key, "kid-unknown", base())) // unknown kid

	// HMAC alg confusion — must be rejected (asymmetric only).
	hmacTok := jwt.NewWithClaims(jwt.SigningMethodHS256, base())
	hmacTok.Header["kid"] = "kid-1"
	if hs, herr := hmacTok.SignedString([]byte("secret")); herr == nil {
		f.Add(hs)
	}
	// alg:none — must be rejected.
	noneTok := jwt.NewWithClaims(jwt.SigningMethodNone, base())
	noneTok.Header["kid"] = "kid-1"
	if ns, nerr := noneTok.SignedString(jwt.UnsafeAllowNoneSignatureType); nerr == nil {
		f.Add(ns)
	}
	f.Add("not.a.jwt")
	f.Add("...")
	f.Add("a.b.c.d")

	f.Fuzz(func(t *testing.T, raw string) {
		var sub string
		var verr error
		// Guard bounds the per-input wall clock (hang / amplification), consistent
		// with OIDCVerifierVerify and the notary targets; assertions run after.
		fuzzutil.Guard(t.Fatalf, "verifyIDToken", func() {
			sub, _, _, _, verr = c.verifyIDToken(context.Background(), p, nonce, raw)
		})
		if verr != nil {
			if sub != "" {
				t.Fatalf("verifyIDToken returned an error but a non-empty subject: sub=%q err=%v raw=%q", sub, verr, raw)
			}
			return
		}
		if sub == "" {
			t.Fatalf("verifyIDToken returned success (nil error) with an empty subject: raw=%q", raw)
		}
		// Rejection invariant (signature-bypass detection). The fuzzer never holds
		// the trusted private key, so the only tokens that may legitimately verify
		// are ones this harness signed with it. A success on any other input means a
		// signature was accepted that we never produced — alg:none, HMAC/alg
		// confusion, a stripped or unchecked signature, or a kid/issuer trick.
		// Claim-level rejections (nonce/aud/iss/exp/azp) are covered by
		// TestVerifyIDToken; trustedKeySigned is the sound superset, so this yields
		// no false positives.
		if !trustedKeySigned[raw] {
			t.Fatalf("SIGNATURE BYPASS: verifyIDToken accepted a token the harness never signed with the trusted key: sub=%q raw=%q", sub, raw)
		}
	})
}
