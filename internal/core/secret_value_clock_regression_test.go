// secret_value_clock_regression_test.go — #1632: the worst site in the
// time-handling sweep, its own test. enforceSecretReadGuards (versions.go)
// is the actual secret-VALUE disclosure guard; before this fix, it compared
// a bare time.Now() against secret.Expiration with no seam and no defense
// against the comparison being fooled by a backward-stepped wall clock — an
// operator, or an NTP-less clock correction, stepping the host clock back
// past a secret's real expiration would disclose its plaintext value. This
// is exploit-shaped, not unit-shaped: it establishes a genuinely-expired
// secret, moves the clock backward past that expiration, and asserts the
// value is still refused — plus a positive control proving a legitimately
// unexpired secret still resolves normally.
package core

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

func newClockRegressionCore(t *testing.T) (*KeyorixCore, *gorm.DB) {
	t.Helper()
	// Defensive, not relying solely on this package's TestMain: at least two
	// other tests (secret_update_expiration_test.go, secret_value_crypto_test.go)
	// call i18n.ResetForTesting() in their own cleanup, which de-initializes
	// the package-level i18n singleton for whichever test runs next in the
	// same binary -- a pre-existing test-isolation gap, not introduced here,
	// that this test tripped over by being the first to reach an i18n.T()
	// call path without its own defensive re-init.
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.SecretNode{}, &models.SecretVersion{}, &models.AuditEvent{}, &models.SecretAccessSchedule{}))
	c := &KeyorixCore{storage: store.NewLocalStorage(db)}
	return c, db
}

// TestGetSecretValue_ClockSteppedBackwardPastExpiry_StillRefused is the
// exploit-shaped test #1632 asks for. Sequence:
//
//  1. At a baseline "current" time, read the secret once — it is already
//     genuinely expired relative to that baseline, so this both establishes
//     the correct starting behavior AND warms the in-memory
//     secretExpiryWatermark (service.go) to the baseline time.
//  2. Step c.now() BACKWARD to a time before the secret's own Expiration
//     (simulating an operator or NTP correction moving the host clock back
//     by more than an hour — the #1632 threat model) and read again.
//
// Before the fix (a bare time.Now(), or c.now() with no regression check):
// step 2's backward clock reads as "not yet expired" (now < Expiration) and
// the plaintext value is disclosed — this assertion fails, red.
//
// After the fix: checkSecretExpiryClockNotRegressed (versions.go) detects
// that step 2's c.now() is earlier than the watermark step 1 already
// observed and refuses the read regardless of what Expiration says —
// green.
func TestGetSecretValue_ClockSteppedBackwardPastExpiry_StillRefused(t *testing.T) {
	c, db := newClockRegressionCore(t)
	ctx := context.Background()

	baseline := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	realExpiration := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) // genuinely expired by baseline
	steppedBack := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)    // before BOTH baseline and realExpiration

	secret := &models.SecretNode{
		ProjectID: 1, EnvironmentID: 1, Name: "clock-regression-target",
		IsSecret: true, Status: "active", Type: "generic",
		Expiration: &realExpiration,
	}
	require.NoError(t, db.Create(secret).Error)
	require.NoError(t, db.Create(&models.SecretVersion{
		SecretNodeID: secret.ID, VersionNumber: 1, EncryptedValue: []byte("top-secret-value"),
	}).Error)

	// Step 1: read at the baseline. Already expired relative to baseline —
	// correctly refused, and warms the watermark to baseline.
	c.now = func() time.Time { return baseline }
	_, err := c.GetSecretValueByVersion(ctx, secret.ID, 1)
	require.Error(t, err, "sanity: the secret must read as expired at the baseline time before the clock ever moves")

	// Step 2: the exploit. Step the clock BACKWARD past both the watermark
	// and the secret's own Expiration.
	c.now = func() time.Time { return steppedBack }
	_, err = c.GetSecretValueByVersion(ctx, secret.ID, 1)
	require.Error(t, err, "a secret-value read must still be refused after the clock steps backward past the secret's expiration -- a backward clock step must never disclose an expired secret's value")
}

// TestGetSecretValue_ClockSteppedBackward_LegitimatelyUnexpiredSecretStillResolves
// is the positive control: a secret that has never expired, read after the
// SAME kind of backward clock step, must still resolve normally. The fix
// must refuse a clock that looks regressed relative to what this process
// has already seen -- it must not become a blanket refusal that breaks
// ordinary reads whenever the clock is merely, legitimately, still early in
// the process's lifetime (e.g. right after boot, before any watermark has
// been established).
func TestGetSecretValue_ClockSteppedBackward_LegitimatelyUnexpiredSecretStillResolves(t *testing.T) {
	c, db := newClockRegressionCore(t)
	ctx := context.Background()

	baseline := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	farFuture := time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC) // never expired, ever, in this test

	secret := &models.SecretNode{
		ProjectID: 1, EnvironmentID: 1, Name: "clock-regression-control",
		IsSecret: true, Status: "active", Type: "generic",
		Expiration: &farFuture,
	}
	require.NoError(t, db.Create(secret).Error)
	require.NoError(t, db.Create(&models.SecretVersion{
		SecretNodeID: secret.ID, VersionNumber: 1, EncryptedValue: []byte("still-valid-value"),
	}).Error)

	c.now = func() time.Time { return baseline }
	value, err := c.GetSecretValueByVersion(ctx, secret.ID, 1)
	require.NoError(t, err, "positive control: a legitimately unexpired secret must resolve at the baseline time")
	assert.Equal(t, []byte("still-valid-value"), value)

	// A SMALL, in-tolerance backward step (well under
	// secretExpiryClockRegressionTolerance) must not trip the guard --
	// ordinary NTP slew must not become a false-positive refusal.
	c.now = func() time.Time { return baseline.Add(-5 * time.Second) }
	value, err = c.GetSecretValueByVersion(ctx, secret.ID, 1)
	require.NoError(t, err, "a small in-tolerance backward step must not refuse a legitimately unexpired secret")
	assert.Equal(t, []byte("still-valid-value"), value)
}

// TestCheckSecretExpiryClockNotRegressed_FreshWatermarkNeverRefuses covers
// the zero-value watermark case directly (no prior call has ever
// established a baseline -- e.g. the very first secret-value read after
// process boot): it must never refuse solely because the watermark is
// unset.
func TestCheckSecretExpiryClockNotRegressed_FreshWatermarkNeverRefuses(t *testing.T) {
	c := &KeyorixCore{}
	err := c.checkSecretExpiryClockNotRegressed(time.Date(1999, 1, 1, 0, 0, 0, 0, time.UTC))
	require.NoError(t, err, "an unset watermark must never itself cause a refusal")
}
