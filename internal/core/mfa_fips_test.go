package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// forceTOTPFIPS turns the refusal on for one (non-parallel) test.
func forceTOTPFIPS(t *testing.T) {
	t.Helper()
	prev := totpFIPSEnforced
	totpFIPSEnforced = func() bool { return true }
	t.Cleanup(func() { totpFIPSEnforced = prev })
}

// failedLoginCount reads alice's lockout counter.
func failedLoginCount(t *testing.T, db *gorm.DB) int {
	t.Helper()
	var u models.User
	require.NoError(t, db.First(&u, 1).Error)
	return u.FailedLoginAttempts
}

// The refusal is pre-verdict on every path: typed (errors.Is), not counted
// toward the lockout, audited mfa.error and never mfa.failed. Login and step-up
// also carry ErrMFAVerificationUnavailable so the handler hands the budget slot
// back.
func TestTOTP_FIPSRefusal_PreVerdictOnEveryPath(t *testing.T) {
	ctx := context.Background()
	c, db, _ := newMFATestCore(t)
	c.loginLockout = LoginLockoutPolicy{Enabled: true, MaxAttempts: 5, Window: time.Hour, BaseCooldown: 15 * time.Minute, MaxCooldown: time.Hour}
	seedActivatedTOTP(t, c, db) // enrol before the refusal is on
	forceTOTPFIPS(t)

	_, _, err := c.BeginMFAEnrollment(ctx, 1)
	assert.ErrorIs(t, err, ErrTOTPUnavailableInFIPSMode, "enrol")
	_, err = c.ActivateMFA(ctx, 1, "123456", mfaTestPassword, "")
	assert.ErrorIs(t, err, ErrTOTPUnavailableInFIPSMode, "activate")

	ch, err := c.CreateMFAChallenge(ctx, 1)
	require.NoError(t, err)
	_, _, _, err = c.VerifyMFALogin(ctx, ch, "123456", "ua", "1.2.3.4")
	assert.ErrorIs(t, err, ErrTOTPUnavailableInFIPSMode, "login")
	assert.ErrorIs(t, err, ErrMFAVerificationUnavailable, "login must be pre-verdict")

	err = c.VerifyMFAStepUp(ctx, 1, "123456")
	assert.ErrorIs(t, err, ErrTOTPUnavailableInFIPSMode, "stepup")
	assert.ErrorIs(t, err, ErrMFAVerificationUnavailable, "stepup must be pre-verdict")
	assert.False(t, errors.Is(err, ErrReauthRejected), "stepup must not keep the slot")

	err = c.DisableMFA(ctx, 1, "123456", "")
	assert.ErrorIs(t, err, ErrTOTPUnavailableInFIPSMode, "reauth")
	assert.False(t, errors.Is(err, ErrReauthRejected), "reauth must not keep the slot")

	assert.Zero(t, failedLoginCount(t, db), "nothing was evaluated, nothing may be counted")
	var failed, errored int64
	require.NoError(t, db.Model(&models.AuditEvent{}).Where("event_type = ?", "mfa.failed").Count(&failed).Error)
	require.NoError(t, db.Model(&models.AuditEvent{}).Where("event_type = ?", "mfa.error").Count(&errored).Error)
	assert.Zero(t, failed)
	assert.Equal(t, int64(3), errored, "login, stepup and reauth refusals are audited")

	var u models.User
	require.NoError(t, db.First(&u, 1).Error)
	assert.True(t, u.MFAEnabled, "a refused DisableMFA disables nothing")
}

// Re-auth with input that is not TOTP-shaped (a password) skips the TOTP path
// and keeps the usual accounting: a wrong password is still counted, so the
// FIPS refusal opens no unthrottled password-guessing path.
func TestTOTP_FIPSRefusal_ReauthPasswordStillCounted(t *testing.T) {
	ctx := context.Background()
	c, db, _ := newMFATestCore(t)
	c.loginLockout = LoginLockoutPolicy{Enabled: true, MaxAttempts: 5, Window: time.Hour, BaseCooldown: 15 * time.Minute, MaxCooldown: time.Hour}
	seedActivatedTOTP(t, c, db)
	forceTOTPFIPS(t)

	err := c.DisableMFA(ctx, 1, "not-the-password", "")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrReauthRejected)
	assert.False(t, errors.Is(err, ErrTOTPUnavailableInFIPSMode))
	assert.Equal(t, 1, failedLoginCount(t, db), "a wrong password is counted as before")
}

// Recovery codes do not use SHA-1 and keep working as the login second factor.
func TestTOTP_FIPSRefusal_RecoveryCodeLoginStillWorks(t *testing.T) {
	ctx := context.Background()
	c, db, _ := newMFATestCore(t)
	seedActivatedTOTP(t, c, db)
	codes, hashes, err := generateRecoveryCodes(1)
	require.NoError(t, err)
	require.NoError(t, db.Create(&models.MFARecoveryCode{UserID: 1, CodeHash: hashes[0]}).Error)
	forceTOTPFIPS(t)

	ch, err := c.CreateMFAChallenge(ctx, 1)
	require.NoError(t, err)
	sess, _, _, err := c.VerifyMFALogin(ctx, ch, codes[0], "ua", "1.2.3.4")
	require.NoError(t, err)
	assert.NotNil(t, sess)
}
