package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestVerifyMFAStepUp_UserNotFound verifies that a missing user returns an error.
func TestVerifyMFAStepUp_UserNotFound(t *testing.T) {
	c, _, _ := newMFATestCore(t)
	err := c.VerifyMFAStepUp(context.Background(), 9999, "000000")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "user not found")
}

// TestVerifyMFAStepUp_InactiveAccount verifies that an inactive account is rejected.
func TestVerifyMFAStepUp_InactiveAccount(t *testing.T) {
	c, db, _ := newMFATestCore(t)
	// Mark alice as deprovisioned (AccountLoginBlocked returns true for this state).
	require.NoError(t, db.Model(&models.User{}).Where("id = ?", 1).Update("account_state", AccountDeprovisioned).Error)

	err := c.VerifyMFAStepUp(context.Background(), 1, "000000")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not active")
}

// TestVerifyMFAStepUp_AccountLocked verifies that a locked-out account is rejected.
func TestVerifyMFAStepUp_AccountLocked(t *testing.T) {
	c, db, fixed := newMFATestCore(t)
	c.loginLockout = LoginLockoutPolicy{Enabled: true, MaxAttempts: 3, Window: time.Hour, BaseCooldown: 15 * time.Minute, MaxCooldown: time.Hour}

	// Manually set the lock to be active.
	lockedUntil := fixed.Add(time.Hour)
	require.NoError(t, db.Model(&models.User{}).Where("id = ?", 1).Update("login_locked_until", lockedUntil).Error)

	err := c.VerifyMFAStepUp(context.Background(), 1, "000000")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "locked")
}

// TestVerifyMFAStepUp_MFANotEnabled verifies that a user without MFA cannot step-up.
func TestVerifyMFAStepUp_MFANotEnabled(t *testing.T) {
	c, _, _ := newMFATestCore(t)
	// alice was created without MFA enabled (MFAEnabled defaults to false).
	err := c.VerifyMFAStepUp(context.Background(), 1, "000000")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "MFA is not enabled")
}

// TestVerifyMFAStepUp_WrongCode verifies that an incorrect TOTP code is rejected.
func TestVerifyMFAStepUp_WrongCode(t *testing.T) {
	c, _, fixed := newMFATestCore(t)
	ctx := context.Background()
	activateMFAForTest(t, c, fixed)

	err := c.VerifyMFAStepUp(ctx, 1, "000000")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid code")
}

// TestVerifyMFAStepUp_CorrectTOTPCode_GrantCreated verifies that a correct TOTP code
// successfully creates an MFAStepUpGrant in the database.
func TestVerifyMFAStepUp_CorrectTOTPCode_GrantCreated(t *testing.T) {
	c, db, fixed := newMFATestCore(t)
	ctx := context.Background()
	secret, _ := activateMFAForTest(t, c, fixed)

	code, err := totp.GenerateCode(secret, fixed)
	require.NoError(t, err)

	err = c.VerifyMFAStepUp(ctx, 1, code)
	require.NoError(t, err)

	// Verify the grant was written to the DB. The core clock is fixed; the grant
	// should have ExpiresAt = fixed + mfaStepUpWindow (15 min).
	var grant models.MFAStepUpGrant
	require.NoError(t, db.Where("user_id = ?", 1).First(&grant).Error,
		"VerifyMFAStepUp must write an MFAStepUpGrant row")
	assert.Equal(t, uint(1), grant.UserID)
}

// TestVerifyMFAStepUp_CorrectRecoveryCode_GrantCreated verifies that a correct recovery
// code also successfully creates an MFAStepUpGrant.
func TestVerifyMFAStepUp_CorrectRecoveryCode_GrantCreated(t *testing.T) {
	c, db, fixed := newMFATestCore(t)
	ctx := context.Background()
	_, codes := activateMFAForTest(t, c, fixed)

	err := c.VerifyMFAStepUp(ctx, 1, codes[0])
	require.NoError(t, err)

	// Verify the grant was written to the DB.
	var grant models.MFAStepUpGrant
	require.NoError(t, db.Where("user_id = ?", 1).First(&grant).Error,
		"VerifyMFAStepUp via recovery code must write an MFAStepUpGrant row")
	assert.Equal(t, uint(1), grant.UserID)
}

// TestVerifyMFAStepUp_AntiReplay_SameTOTPStepRejectedTwice verifies that replaying the
// same TOTP code within the same step window is rejected by the anti-replay check.
func TestVerifyMFAStepUp_AntiReplay_SameTOTPStepRejectedTwice(t *testing.T) {
	c, _, fixed := newMFATestCore(t)
	ctx := context.Background()
	secret, _ := activateMFAForTest(t, c, fixed)

	code, err := totp.GenerateCode(secret, fixed)
	require.NoError(t, err)

	// First use must succeed.
	err = c.VerifyMFAStepUp(ctx, 1, code)
	require.NoError(t, err)

	// Second use of the same code must be rejected.
	err = c.VerifyMFAStepUp(ctx, 1, code)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid code", "replaying the same TOTP step must be rejected")
}

// TestHasActiveMFAStepUp_NoGrant verifies that a user with no grant returns false.
func TestHasActiveMFAStepUp_NoGrant(t *testing.T) {
	c, _, _ := newMFATestCore(t)
	ctx := context.Background()

	active, err := c.HasActiveMFAStepUp(ctx, 1, models.MFAStepUpPurposeRestrictedSecretRead)
	require.NoError(t, err)
	assert.False(t, active, "no grant — HasActiveMFAStepUp must return false")
}

// TestHasActiveMFAStepUp_ExpiredGrant verifies that an expired grant is treated as absent.
func TestHasActiveMFAStepUp_ExpiredGrant(t *testing.T) {
	c, db, fixed := newMFATestCore(t)
	ctx := context.Background()

	// Insert an already-expired grant directly. The core clock is fixed (to the
	// past), so use a time even further in the past to ensure it's expired
	// relative to the fixed clock.
	expiredAt := fixed.Add(-1 * time.Minute)
	require.NoError(t, db.Create(&models.MFAStepUpGrant{UserID: 1, Purpose: models.MFAStepUpPurposeRestrictedSecretRead, ExpiresAt: expiredAt}).Error)

	active, err := c.HasActiveMFAStepUp(ctx, 1, models.MFAStepUpPurposeRestrictedSecretRead)
	require.NoError(t, err)
	assert.False(t, active, "expired grant must not be treated as active")
}

// TestHasActiveMFAStepUp_ActiveGrant verifies that a non-expired grant returns true.
func TestHasActiveMFAStepUp_ActiveGrant(t *testing.T) {
	c, db, fixed := newMFATestCore(t)
	ctx := context.Background()

	// Insert a future-expiring grant relative to the fixed clock.
	future := fixed.Add(15 * time.Minute)
	require.NoError(t, db.Create(&models.MFAStepUpGrant{UserID: 1, Purpose: models.MFAStepUpPurposeRestrictedSecretRead, ExpiresAt: future}).Error)

	active, err := c.HasActiveMFAStepUp(ctx, 1, models.MFAStepUpPurposeRestrictedSecretRead)
	require.NoError(t, err)
	assert.True(t, active, "active (non-expired) grant must return true")
}
