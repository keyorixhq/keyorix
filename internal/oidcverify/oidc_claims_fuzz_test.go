package oidcverify

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

		// --- Fixed assertions run on EVERY iteration (before the fuzzed-token path,
		// so an over-rejection mutant that rejects the fuzzed token cannot skip them
		// via the early return below). ---
		//
		// signHdr signs an otherwise-perfect token (trusted issuer/audience, present
		// subject, fresh iat, unexpired) with optional extra headers/claims applied by
		// mut. The base token is unconditionally valid, so correct code accepts it
		// unless mut introduces a reason to reject.
		signHdr := func(mut func(tok *jwt.Token, c jwt.MapClaims)) string {
			c := jwt.MapClaims{
				"iss": trustedIss, "sub": "svc",
				"aud": []string{trustedAud},
				"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
			}
			tok := jwt.NewWithClaims(jwt.SigningMethodRS256, c)
			tok.Header["kid"] = "kid-1"
			if mut != nil {
				mut(tok, c)
			}
			s, serr := tok.SignedString(key)
			if serr != nil {
				t.Fatalf("signHdr: %v", serr)
			}
			return s
		}

		// LIVENESS (accept direction). The fuzzer never asserts that a valid token is
		// accepted (azp/iat/max-age add legitimate rejection reasons that make a blanket
		// "must accept" unsound over arbitrary input) — so every mutant that merely
		// rejects MORE (an inverted guard, a flipped comparison) survived. Pin it with
		// one fixed, unconditionally-valid token: correct code must accept it, so this
		// only fails under a real over-rejection regression.
		if _, _, lerr := v.Verify(context.Background(), signHdr(nil)); lerr != nil {
			t.Fatalf("LIVENESS: Verify rejected an unconditionally-valid token: %v", lerr)
		}
		// FAIL-CLOSED: a token with a "crit" header naming an extension this verifier
		// does not understand MUST be rejected (RFC 7515 §4.1.11), however valid its
		// claims. The fuzzer never sets headers.
		critRaw := signHdr(func(tok *jwt.Token, _ jwt.MapClaims) {
			tok.Header["crit"] = []string{"exp"}
		})
		if _, _, cerr := v.Verify(context.Background(), critRaw); cerr == nil {
			t.Fatalf("CRIT BYPASS: Verify accepted a token with an unrecognized crit header")
		}
		// FAIL-CLOSED: a token naming MORE THAN ONE audience with no azp is ambiguous
		// about its true recipient and MUST be rejected, even though one audience is
		// allow-listed. The fuzzer only ever sends a single audience.
		multiRaw := signHdr(func(_ *jwt.Token, c jwt.MapClaims) {
			c["aud"] = []string{trustedAud, "other-rp"} // one allowed, one not; no azp
		})
		if _, _, merr := v.Verify(context.Background(), multiRaw); merr == nil {
			t.Fatalf("AZP BYPASS: Verify accepted a multi-audience token with no azp claim")
		}
		// LIVENESS (multi-audience accept): a multi-audience token WHOSE azp is a
		// trusted audience is the legitimate disambiguated case and MUST be accepted —
		// pins that the azp==\"\" reject does not spill onto a validly-azp'd token.
		multiAzpRaw := signHdr(func(_ *jwt.Token, c jwt.MapClaims) {
			c["aud"] = []string{trustedAud, "other-rp"}
			c["azp"] = trustedAud
		})
		if _, _, aerr := v.Verify(context.Background(), multiAzpRaw); aerr != nil {
			t.Fatalf("LIVENESS: Verify rejected a multi-audience token with a trusted azp: %v", aerr)
		}

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
