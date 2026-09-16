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

// FuzzVerifyIDTokenClaims soaks KeyorixCore.verifyIDToken (interactive-SSO login)
// from INSIDE the signature wall — the browser-facing sibling of
// FuzzOIDCVerifierClaims. FuzzVerifyIDToken already fuzzes the raw token bytes and
// asserts the signature-bypass invariant, but the fuzzer holds no key, so nearly
// every mutated input dies at the signature check and the claim logic behind it is
// barely wetted. This harness signs every token with the trusted key so the
// signature always verifies, pouring the fuzzer into the claim semantics — which on
// this path include the OIDC nonce check that the machine-federation path
// (OIDCVerifier.Verify) does not have.
//
// Invariants (sound — only the direction that cannot false-positive against
// verifyIDToken's rules in sso.go):
//   - never panics / hangs (Guard);
//   - result shape: a non-nil error leaves the subject empty; a nil error returns a
//     non-empty subject;
//   - fail-closed rejection: a wrong issuer, a (single) audience that isn't the
//     client_id, a nonce that doesn't match the server's expected nonce, or a token
//     expired well past the 60s leeway MUST be rejected. Each independently forces
//     rejection regardless of the other claims, so requiring err != nil yields no
//     false positives. (Accept is not asserted — azp/subject add further legitimate
//     rejections whose boundaries would make "must accept" unsound.)
func FuzzVerifyIDTokenClaims(f *testing.F) {
	const trustedIss = "https://idp.test"
	const clientID = "client-1"
	const expectedNonce = "N1"

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		f.Fatal(err)
	}
	p := &SSOProvider{Name: "okta", Issuer: trustedIss, ClientID: clientID}
	c := &KeyorixCore{
		now:          time.Now,
		ssoJWKS:      staticResolver{kid: "kid-1", key: &key.PublicKey},
		ssoProviders: map[string]*SSOProvider{"okta": p},
	}

	// sign always uses the trusted key + kid, so the signature check never fails —
	// the fuzzer explores claim values, not signatures.
	sign := func(claims jwt.MapClaims) string {
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		tok.Header["kid"] = "kid-1"
		s, serr := tok.SignedString(key)
		if serr != nil {
			f.Fatal(serr)
		}
		return s
	}

	// Seeds spanning accept + each rejection reason.
	f.Add("okta|123", clientID, trustedIss, expectedNonce, int64(3600))
	f.Add("", clientID, trustedIss, expectedNonce, int64(3600))                  // empty subject
	f.Add("okta|123", "other-client", trustedIss, expectedNonce, int64(3600))    // wrong audience
	f.Add("okta|123", clientID, "https://evil.test", expectedNonce, int64(3600)) // untrusted issuer
	f.Add("okta|123", clientID, trustedIss, "N2", int64(3600))                   // wrong nonce
	f.Add("okta|123", clientID, trustedIss, expectedNonce, int64(-7200))         // long expired
	f.Add("okta|123", clientID, trustedIss, expectedNonce, int64(-30))           // within leeway

	f.Fuzz(func(t *testing.T, sub, aud, iss, nonce string, expOffset int64) {
		// Clamp so now.Add can't overflow the time type (a spurious panic).
		if expOffset > 1_000_000_000 {
			expOffset = 1_000_000_000
		}
		if expOffset < -1_000_000_000 {
			expOffset = -1_000_000_000
		}
		claims := jwt.MapClaims{
			"iss":   iss,
			"aud":   aud, // single audience: allowed iff aud == clientID
			"sub":   sub,
			"nonce": nonce,
			"email": "ada@x.io",
			"exp":   time.Now().Add(time.Duration(expOffset) * time.Second).Unix(),
		}
		raw := sign(claims)

		var gotSub string
		var verr error
		fuzzutil.Guard(t.Fatalf, "KeyorixCore.verifyIDToken(claims)", func() {
			gotSub, _, _, _, verr = c.verifyIDToken(context.Background(), p, expectedNonce, raw)
		})

		if verr != nil {
			if gotSub != "" {
				t.Fatalf("verifyIDToken returned an error but a non-empty subject: sub=%q err=%v", gotSub, verr)
			}
			return
		}
		if gotSub == "" {
			t.Fatalf("verifyIDToken returned success (nil error) with an empty subject")
		}
		// Fail-closed rejection invariant. Any ONE of these forces rejection in
		// sso.go, so acceptance here is a real bug.
		if iss != trustedIss {
			t.Fatalf("CLAIM BYPASS: accepted an id_token whose issuer %q is not the provider issuer (sub=%q)", iss, gotSub)
		}
		if aud != clientID {
			t.Fatalf("CLAIM BYPASS: accepted an id_token whose audience %q is not the client id (sub=%q)", aud, gotSub)
		}
		if nonce != expectedNonce {
			t.Fatalf("NONCE BYPASS: accepted an id_token whose nonce %q != expected %q (sub=%q)", nonce, expectedNonce, gotSub)
		}
		if expOffset <= -120 { // 60s leeway + 60s margin
			t.Fatalf("CLAIM BYPASS: accepted an id_token expired %ds ago, well past the 60s leeway (sub=%q)", -expOffset, gotSub)
		}
	})
}
