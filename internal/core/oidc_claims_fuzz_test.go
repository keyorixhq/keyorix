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

// FuzzOIDCVerifierClaims soaks OIDCVerifier.Verify from INSIDE the signature wall.
// FuzzOIDCVerifierVerify already fuzzes the raw token bytes and asserts the
// signature-bypass invariant — but because the fuzzer never holds the trusted
// key, almost every mutated input dies at the signature check, so the claim-
// validation logic behind it (issuer/audience/azp/exp/iat/max-age) is barely
// wetted. This harness pours past that wall: every iteration is signed with the
// trusted key, so the signature always verifies and the fuzzer's energy goes
// entirely into the claim semantics.
//
// Invariants (all sound — they only assert the direction that cannot false-
// positive against Verify's actual rules in oidc.go):
//
//   - never panics / hangs (Guard);
//   - result shape: a non-nil error must leave issuer AND subject empty, and a
//     nil error must return both non-empty (Verify returns ("","",err) on every
//     rejection path and (iss,sub,nil) only on success);
//   - fail-closed rejection: a token whose issuer isn't the trusted one, whose
//     (single) audience isn't allow-listed, or which is expired well past the
//     60s clock-skew leeway MUST be rejected. Each condition independently forces
//     rejection regardless of the other claims, so requiring err != nil here
//     yields no false positives. (The accept direction is deliberately not
//     asserted — azp/iat/max-age add further legitimate rejection reasons whose
//     boundaries would make an "must accept" claim unsound.)
func FuzzOIDCVerifierClaims(f *testing.F) {
	const trustedIss = "https://k8s.local"
	const trustedAud = "keyorix"

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		f.Fatal(err)
	}
	v, err := NewOIDCVerifier(
		[]OIDCTrustedIssuer{{Issuer: trustedIss, Audiences: []string{trustedAud}}},
		staticResolver{kid: "kid-1", key: &key.PublicKey},
	)
	if err != nil {
		f.Fatal(err)
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

	// Seeds spanning accept and each rejection reason.
	f.Add("sa", trustedAud, trustedIss, int64(3600), "")
	f.Add("", trustedAud, trustedIss, int64(3600), "")             // empty subject
	f.Add("sa", "other-svc", trustedIss, int64(3600), "")          // wrong audience
	f.Add("sa", trustedAud, "https://evil.local", int64(3600), "") // untrusted issuer
	f.Add("sa", trustedAud, trustedIss, int64(-7200), "")          // long expired
	f.Add("sa", trustedAud, trustedIss, int64(-30), "")            // within leeway
	f.Add("service-account:ns/name", trustedAud, trustedIss, int64(1), "x")

	f.Fuzz(func(t *testing.T, sub, aud, iss string, expOffset int64, extra string) {
		// Clamp the exp offset so now.Add can't overflow the time type (a spurious
		// panic that isn't a real defect); ~31 years each way is plenty of range.
		if expOffset > 1_000_000_000 {
			expOffset = 1_000_000_000
		}
		if expOffset < -1_000_000_000 {
			expOffset = -1_000_000_000
		}
		now := time.Now()
		claims := jwt.MapClaims{
			"iss":   iss,
			"sub":   sub,
			"aud":   []string{aud}, // single audience: aud allowed iff aud == trustedAud
			"iat":   now.Unix(),
			"exp":   now.Add(time.Duration(expOffset) * time.Second).Unix(),
			"extra": extra, // unused custom claim — soaks the JSON claim decode
		}
		raw := sign(claims)

		var issuer, subject string
		var verr error
		fuzzutil.Guard(t.Fatalf, "OIDCVerifier.Verify(claims)", func() {
			issuer, subject, verr = v.Verify(context.Background(), raw)
		})

		if verr != nil {
			if issuer != "" || subject != "" {
				t.Fatalf("Verify returned an error but a non-empty issuer/subject: issuer=%q subject=%q err=%v", issuer, subject, verr)
			}
			return
		}
		if issuer == "" || subject == "" {
			t.Fatalf("Verify returned success (nil error) with an empty issuer/subject: issuer=%q subject=%q", issuer, subject)
		}
		// Fail-closed rejection invariant. Any ONE of these forces rejection in
		// oidc.go, so an acceptance here is a real bug (accepted a token for the
		// wrong issuer/audience, or an expired one).
		if iss != trustedIss {
			t.Fatalf("CLAIM BYPASS: accepted a token whose issuer %q is not the trusted issuer (subject=%q)", iss, subject)
		}
		if aud != trustedAud {
			t.Fatalf("CLAIM BYPASS: accepted a token whose audience %q is not allow-listed (subject=%q)", aud, subject)
		}
		if expOffset <= -120 { // 60s leeway + 60s margin past it
			t.Fatalf("CLAIM BYPASS: accepted a token expired %ds ago, well past the 60s leeway (subject=%q)", -expOffset, subject)
		}
	})
}
