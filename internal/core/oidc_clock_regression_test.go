// oidc_clock_regression_test.go — #1653 (follow-up to #1632): exploit-shaped
// test for OIDCVerifier.Verify's max-age check. v.now().Sub(claims.IssuedAt.Time)
// is NOT monotonic-safe (claims.IssuedAt is parsed from the JWT, round-tripped,
// its monotonic reading stripped) -- a host clock stepped backward makes a
// stale token's computed age look smaller, extending acceptance of it past its
// configured max-age. Note: the JWT library's OWN exp/nbf validation uses the
// real wall clock (no jwt.WithTimeFunc configured), independent of v.now -- so
// this test keeps `exp` valid against real time throughout and controls only
// v.now (via effectiveNow's clamp) to exercise the max-age check specifically.
package core

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

// TestOIDCVerify_ClockSteppedBackward_StaleTokenStaysRejected is the
// exploit-shaped test. Sequence:
//
//  1. At a baseline v.now() two hours after the token's iat (exceeding the
//     issuer's 1-hour MaxTokenAge), Verify correctly refuses the token for
//     being too old -- and this warms effectiveNow's watermark to that
//     baseline.
//  2. Step v.now() BACKWARD to only 10 minutes after iat (well within the
//     1-hour budget if trusted naively) and Verify again with the SAME
//     token. Before the fix, this age computes as ~10 minutes and the stale
//     token is wrongly accepted. After the fix, effectiveNow clamps to the
//     step-1 watermark, so age is still computed as ~2 hours and the token
//     stays refused.
func TestOIDCVerify_ClockSteppedBackward_StaleTokenStaysRejected(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	v, err := NewOIDCVerifier(
		[]OIDCTrustedIssuer{{Issuer: "https://k8s.local", Audiences: []string{"keyorix"}, MaxTokenAge: time.Hour}},
		staticResolver{kid: "kid-1", key: &key.PublicKey},
	)
	require.NoError(t, err)

	realNow := time.Now()
	iat := realNow.Add(-30 * time.Minute)
	raw := signToken(t, key, "kid-1", jwt.MapClaims{
		"iss": "https://k8s.local",
		"sub": "system:serviceaccount:ci:deployer",
		"aud": []string{"keyorix"},
		"iat": iat.Unix(),
		"exp": realNow.Add(time.Hour).Unix(), // valid against the JWT library's own real-clock exp check throughout
	})

	// Step 1: v.now() two hours ahead of iat -- exceeds the 1h MaxTokenAge,
	// correctly refused, and warms effectiveNow's watermark.
	baseline := realNow.Add(2 * time.Hour)
	v.now = func() time.Time { return baseline }
	_, _, err = v.Verify(context.Background(), raw)
	require.ErrorContains(t, err, "exceeds max age", "sanity: the token must read as too old at the baseline time before the clock ever moves")

	// Step 2: the exploit. Step v.now() BACKWARD to only 10 minutes after iat.
	steppedBack := iat.Add(10 * time.Minute)
	v.now = func() time.Time { return steppedBack }
	_, _, err = v.Verify(context.Background(), raw)
	require.ErrorContains(t, err, "exceeds max age", "a stale token must still be rejected after the clock steps backward to look freshly within the max-age budget")
}

// TestOIDCVerify_ClockSteppedBackward_FreshTokenStillAccepted is the positive
// control: a genuinely fresh token, verified after a SMALL in-tolerance
// backward step (well under the OIDC verifier's own leeway), must still be
// accepted.
func TestOIDCVerify_ClockSteppedBackward_FreshTokenStillAccepted(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	v, err := NewOIDCVerifier(
		[]OIDCTrustedIssuer{{Issuer: "https://k8s.local", Audiences: []string{"keyorix"}, MaxTokenAge: time.Hour}},
		staticResolver{kid: "kid-1", key: &key.PublicKey},
	)
	require.NoError(t, err)

	realNow := time.Now()
	raw := signToken(t, key, "kid-1", jwt.MapClaims{
		"iss": "https://k8s.local",
		"sub": "system:serviceaccount:ci:deployer",
		"aud": []string{"keyorix"},
		"iat": realNow.Unix(),
		"exp": realNow.Add(time.Hour).Unix(),
	})

	v.now = func() time.Time { return realNow.Add(-1 * time.Second) }
	_, _, err = v.Verify(context.Background(), raw)
	require.NoError(t, err, "a fresh token must still verify after a small in-tolerance backward step")
}

// TestOIDCEffectiveNow_ClampsBackwardReadingToWatermark is a direct unit test
// of the clamp itself.
func TestOIDCEffectiveNow_ClampsBackwardReadingToWatermark(t *testing.T) {
	v := &OIDCVerifier{}
	watermark := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	v.clockWatermark = watermark

	backward := watermark.Add(-time.Hour)
	v.now = func() time.Time { return backward }
	require.Equal(t, watermark, v.effectiveNow(), "a backward-looking reading must clamp up to the watermark")

	forward := watermark.Add(time.Hour)
	v.now = func() time.Time { return forward }
	require.Equal(t, forward, v.effectiveNow(), "a forward reading must pass through unchanged and advance the watermark")
	require.Equal(t, forward, v.clockWatermark)
}
