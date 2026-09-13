package core

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// FuzzOIDCVerifierVerify fuzzes OIDCVerifier.Verify, the JWT parsing entry point
// for machine-identity federation (ADR-031): an external workload presents this
// raw string as a Bearer credential on every authenticated request once OIDC
// federation is enabled, which makes it the single most attacker-exposed
// token-parsing boundary in the codebase — unlike the opaque session/PAT/machine
// tokens (server/middleware/auth.go), which are validated by a DB lookup rather
// than decoded/parsed.
//
// This asserts Verify (a) never panics on arbitrary input, and (b) never returns
// a partially-populated success — a non-empty issuer/subject together with a nil
// error — for malformed input; on any failure it must return a clean error with
// issuer/subject left empty, mirroring how every rejection path in oidc.go already
// returns ("", "", err).
func FuzzOIDCVerifierVerify(f *testing.F) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		f.Fatal(err)
	}
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		f.Fatal(err)
	}
	v, err := NewOIDCVerifier(
		[]OIDCTrustedIssuer{{Issuer: "https://k8s.local", Audiences: []string{"keyorix"}}},
		staticResolver{kid: "kid-1", key: &key.PublicKey},
	)
	if err != nil {
		f.Fatal(err)
	}

	// trustedKeySigned records every token this harness signs with the trusted
	// key. The fuzzer never holds that private key, so this is the sound set of
	// tokens that may legitimately verify — used by the rejection invariant below.
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
			"iss": "https://k8s.local", "sub": "sa", "aud": []string{"keyorix"},
			"iat": time.Now().Unix(),
			"exp": time.Now().Add(time.Hour).Unix(),
		}
	}

	// --- Seed corpus, harvested from oidc_test.go's TestOIDCVerify_* table -----
	f.Add("") // empty string

	valid := sign(key, "kid-1", base())
	f.Add(valid)                // genuinely valid token
	f.Add(valid[:len(valid)-5]) // truncated (end cut off)
	f.Add(valid[5:])            // corrupted (front cut off)
	f.Add(valid + "x")          // trailing garbage appended

	untrustedIss := base()
	untrustedIss["iss"] = "https://evil.local"
	f.Add(sign(key, "kid-1", untrustedIss))

	wrongAud := base()
	wrongAud["aud"] = []string{"some-other-service"}
	f.Add(sign(key, "kid-1", wrongAud))

	expired := base()
	expired["exp"] = time.Now().Add(-2 * time.Hour).Unix()
	f.Add(sign(key, "kid-1", expired))

	f.Add(sign(other, "kid-1", base()))     // signed by an untrusted key, wrong kid claimed
	f.Add(sign(key, "kid-unknown", base())) // unknown kid

	noSub := base()
	delete(noSub, "sub")
	f.Add(sign(key, "kid-1", noSub))

	// HMAC algorithm confusion — must be rejected (asymmetric algorithms only).
	hmacTok := jwt.NewWithClaims(jwt.SigningMethodHS256, base())
	hmacTok.Header["kid"] = "kid-1"
	if hs, herr := hmacTok.SignedString([]byte("secret")); herr == nil {
		f.Add(hs)
	}

	// alg:none (unsigned) — must be rejected. Not signed with the trusted key, so
	// the rejection invariant flags it immediately if Verify ever accepts it.
	noneTok := jwt.NewWithClaims(jwt.SigningMethodNone, base())
	noneTok.Header["kid"] = "kid-1"
	if ns, nerr := noneTok.SignedString(jwt.UnsafeAllowNoneSignatureType); nerr == nil {
		f.Add(ns)
	}

	noIat := base()
	delete(noIat, "iat")
	f.Add(sign(key, "kid-1", noIat))

	staleIat := base()
	staleIat["iat"] = time.Now().Add(-48 * time.Hour).Unix()
	staleIat["exp"] = time.Now().Add(10 * 365 * 24 * time.Hour).Unix()
	f.Add(sign(key, "kid-1", staleIat))

	multiAudNoAzp := base()
	multiAudNoAzp["aud"] = []string{"keyorix", "some-other-trusted-service"}
	f.Add(sign(key, "kid-1", multiAudNoAzp))

	f.Add("not.a.jwt")
	f.Add("...")
	f.Add("a.b.c.d") // wrong number of dot-separated segments

	f.Fuzz(func(t *testing.T, raw string) {
		issuer, subject, verr := v.Verify(context.Background(), raw)
		if verr != nil {
			if issuer != "" || subject != "" {
				t.Fatalf("Verify returned an error but a non-empty issuer/subject: issuer=%q subject=%q err=%v raw=%q", issuer, subject, verr, raw)
			}
			return
		}
		if issuer == "" || subject == "" {
			t.Fatalf("Verify returned success (nil error) with an empty issuer/subject: issuer=%q subject=%q raw=%q", issuer, subject, raw)
		}
		// Rejection invariant (signature-bypass detection). The fuzzer never holds
		// the trusted private key, so the only tokens that may legitimately verify
		// are ones this harness signed with it. A success on any other input means a
		// signature was accepted that we never produced — alg:none, HMAC/alg
		// confusion, a stripped or unchecked signature, or a kid/issuer trick.
		// Claim-level rejections (exp/aud/iss) are covered by TestOIDCVerify_*;
		// trustedKeySigned is the sound superset here, so this yields no false positives.
		if !trustedKeySigned[raw] {
			t.Fatalf("SIGNATURE BYPASS: Verify accepted a token the harness never signed with the trusted key: issuer=%q subject=%q raw=%q", issuer, subject, raw)
		}
	})
}
