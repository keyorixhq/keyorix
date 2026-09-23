package core

// jwt_one_clock_per_verify_test.go — #1983: asserts that every time-based
// check performed by one verification (the JWT library's own exp/nbf/iat-
// future checks, via jwt.WithTimeFunc, AND OIDCVerifier.Verify's manual
// max-age check) reads the SAME injected clock, not a mix of the injected
// clock and the library's real wall-clock time.Now().
//
// Each test pins the verifier's clock to a fixed instant far in the past
// (2020) and signs a token whose exp/iat are only valid relative to THAT
// instant, not real wall-clock time. A verifier that (bug) still lets the
// JWT library read real time.Now() for exp/nbf would reject this token as
// expired; a verifier that correctly pins the library to the injected clock
// accepts it. A negative control (no clock override -- real time.Now()) with
// the identical token proves the claims aren't trivially valid regardless of
// clock, so the positive result is actually load-bearing.
//
// New file only; does not touch any existing OIDC/SSO test file.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

func TestOIDCVerify_ExpNbfCheckedAgainstInjectedClock_NotRealTime(t *testing.T) {
	t.Parallel()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	pinned := time.Date(2020, 1, 1, 12, 0, 0, 0, time.UTC)
	raw := signToken(t, key, "kid-1", jwt.MapClaims{
		"iss": "https://k8s.local",
		"sub": "system:serviceaccount:ci:deployer",
		"aud": []string{"keyorix"},
		"iat": pinned.Add(-10 * time.Minute).Unix(),
		"exp": pinned.Add(time.Hour).Unix(), // only valid relative to `pinned`, long expired against real time.Now()
	})

	// Negative control: unmodified verifier (real wall-clock) must reject this
	// token as expired -- proving the claims aren't trivially acceptable.
	control := newTestVerifier(t, key)
	_, _, err = control.Verify(context.Background(), raw)
	require.Error(t, err, "sanity: a 2020-dated token must be rejected against the real (2026+) wall clock")

	// Pin the verifier's clock to `pinned`. If the library's exp/nbf check
	// still read real time.Now() (the mixed-clock bug #1983 fixes), this
	// would fail identically to the control. Success proves the library's
	// check and the max-age check below both used v.effectiveNow().
	v := newTestVerifier(t, key)
	v.now = func() time.Time { return pinned }
	_, subject, err := v.Verify(context.Background(), raw)
	require.NoError(t, err, "a token valid only relative to the injected clock must verify once that clock is wired into the JWT library's own exp/nbf/max-age checks")
	require.Equal(t, "system:serviceaccount:ci:deployer", subject)
}

func TestVerifyIDToken_ExpNbfCheckedAgainstInjectedClock_NotRealTime(t *testing.T) {
	t.Parallel()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	const issuer = "https://idp.test"
	const clientID = "client-1"
	const nonce = "expected-nonce"
	p := &SSOProvider{Name: "okta", Issuer: issuer, ClientID: clientID}

	pinned := time.Date(2020, 1, 1, 12, 0, 0, 0, time.UTC)
	raw := signToken(t, key, "kid-1", jwt.MapClaims{
		"iss":   issuer,
		"sub":   "okta|123",
		"aud":   clientID,
		"iat":   pinned.Add(-10 * time.Minute).Unix(),
		"exp":   pinned.Add(time.Hour).Unix(),
		"nonce": nonce,
	})

	control := &KeyorixCore{now: time.Now, ssoJWKS: staticResolver{kid: "kid-1", key: &key.PublicKey}}
	_, _, _, _, err = control.verifyIDToken(context.Background(), p, nonce, raw)
	require.Error(t, err, "sanity: a 2020-dated id_token must be rejected against the real (2026+) wall clock")

	c := &KeyorixCore{
		now:     func() time.Time { return pinned },
		ssoJWKS: staticResolver{kid: "kid-1", key: &key.PublicKey},
	}
	sub, _, _, _, err := c.verifyIDToken(context.Background(), p, nonce, raw)
	require.NoError(t, err, "an id_token valid only relative to the injected clock must verify once that clock is wired into the JWT library's exp/nbf checks")
	require.Equal(t, "okta|123", sub)
}
