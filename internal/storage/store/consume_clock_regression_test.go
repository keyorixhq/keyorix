// consume_clock_regression_test.go — #1632: exploit-shaped tests for
// ConsumeMFAChallenge and ConsumeWebAuthnSession's defense against a
// backward-stepped host clock. Both methods bind `now` directly into a SQL
// `expires_at > ?` bound with no seam and, before this fix, no defense
// against that comparison being fooled by an operator or NTP-less clock
// correction stepping the host clock backward past a challenge/session's
// real expiration — letting it be consumed for the first time past its real
// window. This cannot enable literal replay of an ALREADY-consumed row (the
// `used_at IS NULL` predicate is clock-independent), so these tests target
// the narrower, still-security-relevant hazard: a never-consumed-but-expired
// row being consumed for the first time after the clock steps back.
package store

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func newConsumeClockRegressionStore(t *testing.T) *LocalStorage {
	t.Helper()
	return newS27bStore(t, &models.MFAChallenge{}, &models.WebAuthnSession{})
}

// TestConsumeMFAChallenge_ClockSteppedBackwardPastExpiry_StillRefused is the
// exploit-shaped test: establishes a genuinely-expired-by-baseline challenge,
// then steps the clock backward to before both the baseline and the
// challenge's own expiry, and asserts consumption is still refused.
//
// Before the fix: the backward-stepped now reads as "not yet expired"
// (expires_at > now) and the challenge is consumed — this assertion fails,
// red. After the fix: consumeClockLooksRegressed detects the second call's
// now is earlier than the watermark the first call already established and
// refuses regardless of what expires_at says — green.
func TestConsumeMFAChallenge_ClockSteppedBackwardPastExpiry_StillRefused(t *testing.T) {
	ls := newConsumeClockRegressionStore(t)
	ctx := context.Background()

	baseline := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	realExpiry := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)  // expired by baseline
	steppedBack := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC) // before BOTH baseline and realExpiry

	require.NoError(t, ls.db.Create(&models.MFAChallenge{
		UserID: 1, TokenHash: "mfa-clock-regression-target",
		ExpiresAt: realExpiry, CreatedAt: realExpiry.Add(-time.Hour),
	}).Error)

	// Step 1: at the baseline, already expired — correctly refused, and this
	// warms the shared consume-clock watermark to baseline.
	_, err := ls.ConsumeMFAChallenge(ctx, "mfa-clock-regression-target", baseline)
	require.Error(t, err, "sanity: the challenge must read as expired at the baseline time before the clock ever moves")

	// Step 2: the exploit. Step the clock BACKWARD past both the watermark
	// and the challenge's own expiry.
	_, err = ls.ConsumeMFAChallenge(ctx, "mfa-clock-regression-target", steppedBack)
	require.Error(t, err, "consumption must still be refused after the clock steps backward past the challenge's expiry")
}

// TestConsumeMFAChallenge_ClockSteppedBackward_LegitimatelyActiveChallengeStillConsumes
// is the positive control: a challenge that has never expired, consumed
// after the SAME kind of backward clock step (still within tolerance or
// after a fresh watermark), must still succeed.
func TestConsumeMFAChallenge_ClockSteppedBackward_LegitimatelyActiveChallengeStillConsumes(t *testing.T) {
	ls := newConsumeClockRegressionStore(t)
	ctx := context.Background()

	baseline := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	farFuture := time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)

	require.NoError(t, ls.db.Create(&models.MFAChallenge{
		UserID: 1, TokenHash: "mfa-clock-regression-control",
		ExpiresAt: farFuture, CreatedAt: baseline,
	}).Error)

	// A small, in-tolerance backward step (well under
	// consumeClockRegressionTolerance) must not trip the guard on the very
	// first call — ordinary NTP slew must not become a false-positive refusal
	// even before any watermark has been established.
	_, err := ls.ConsumeMFAChallenge(ctx, "mfa-clock-regression-control", baseline.Add(-5*time.Second))
	require.NoError(t, err, "a small in-tolerance backward step must not refuse a legitimately unexpired, never-consumed challenge")
}

// TestConsumeWebAuthnSession_ClockSteppedBackwardPastExpiry_StillRefused is
// ConsumeMFAChallenge's exploit test, repeated for the structurally
// identical ConsumeWebAuthnSession (same `used_at IS NULL AND expires_at >
// ?` predicate).
func TestConsumeWebAuthnSession_ClockSteppedBackwardPastExpiry_StillRefused(t *testing.T) {
	ls := newConsumeClockRegressionStore(t)
	ctx := context.Background()

	baseline := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	realExpiry := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	steppedBack := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)

	require.NoError(t, ls.db.Create(&models.WebAuthnSession{
		UserID: 1, TokenHash: "wa-clock-regression-target", Purpose: "login",
		ExpiresAt: realExpiry, CreatedAt: realExpiry.Add(-time.Hour),
	}).Error)

	_, err := ls.ConsumeWebAuthnSession(ctx, "wa-clock-regression-target", baseline)
	require.Error(t, err, "sanity: the session must read as expired at the baseline time before the clock ever moves")

	_, err = ls.ConsumeWebAuthnSession(ctx, "wa-clock-regression-target", steppedBack)
	require.Error(t, err, "consumption must still be refused after the clock steps backward past the session's expiry")
}

// TestConsumeWebAuthnSession_ClockSteppedBackward_LegitimatelyActiveSessionStillConsumes
// is ConsumeMFAChallenge's positive control, repeated for ConsumeWebAuthnSession.
func TestConsumeWebAuthnSession_ClockSteppedBackward_LegitimatelyActiveSessionStillConsumes(t *testing.T) {
	ls := newConsumeClockRegressionStore(t)
	ctx := context.Background()

	baseline := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	farFuture := time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)

	require.NoError(t, ls.db.Create(&models.WebAuthnSession{
		UserID: 1, TokenHash: "wa-clock-regression-control", Purpose: "login",
		ExpiresAt: farFuture, CreatedAt: baseline,
	}).Error)

	_, err := ls.ConsumeWebAuthnSession(ctx, "wa-clock-regression-control", baseline.Add(-5*time.Second))
	require.NoError(t, err, "a small in-tolerance backward step must not refuse a legitimately unexpired, never-consumed session")
}

// TestConsumeClockWatermark_SharedAcrossMFAAndWebAuthn proves the design
// choice stated in consumeClockLooksRegressed's doc comment: the watermark
// is ONE process-wide fact ("has this LocalStorage's clock been stepped
// backward"), not kept per-method. Warming it via an MFA challenge
// consumption must also protect a WebAuthn session consumption on the same
// LocalStorage instance.
func TestConsumeClockWatermark_SharedAcrossMFAAndWebAuthn(t *testing.T) {
	ls := newConsumeClockRegressionStore(t)
	ctx := context.Background()

	baseline := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	steppedBack := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	farFuture := time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)

	// Warm the watermark to baseline via an MFA challenge consumption
	// (succeeds — never expired).
	require.NoError(t, ls.db.Create(&models.MFAChallenge{
		UserID: 1, TokenHash: "shared-watermark-mfa", ExpiresAt: farFuture, CreatedAt: baseline,
	}).Error)
	_, err := ls.ConsumeMFAChallenge(ctx, "shared-watermark-mfa", baseline)
	require.NoError(t, err)

	// A WebAuthn session that would otherwise still be genuinely unexpired
	// relative to steppedBack must nonetheless be refused, because the clock
	// now looks regressed relative to what the MFA consumption above already
	// observed.
	require.NoError(t, ls.db.Create(&models.WebAuthnSession{
		UserID: 1, TokenHash: "shared-watermark-webauthn", Purpose: "login",
		ExpiresAt: farFuture, CreatedAt: steppedBack,
	}).Error)
	_, err = ls.ConsumeWebAuthnSession(ctx, "shared-watermark-webauthn", steppedBack)
	require.Error(t, err, "a backward step observed via ConsumeMFAChallenge must also refuse a subsequent ConsumeWebAuthnSession on the same store")
}

// TestConsumeClockLooksRegressed_FreshWatermarkNeverRefuses covers the
// zero-value watermark case directly: a fresh LocalStorage (no prior
// consumption has ever established a baseline) must never refuse solely
// because the watermark is unset.
func TestConsumeClockLooksRegressed_FreshWatermarkNeverRefuses(t *testing.T) {
	ls := newConsumeClockRegressionStore(t)
	assert.False(t, ls.consumeClockLooksRegressed(time.Date(1999, 1, 1, 0, 0, 0, 0, time.UTC)),
		"an unset watermark must never itself cause a refusal")
}
