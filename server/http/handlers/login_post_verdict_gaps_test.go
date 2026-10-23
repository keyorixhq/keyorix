package handlers

// #3557: two login post-verdict panics #3267/#3277/#3349 did not cover, driven
// over HTTP through the production middleware.Recovery (postLogin /
// postVerify), so a panic is answered here exactly as a client would see it.

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// expirePassword turns on a 1-day max age and backdates user 1's password, so
// every login of hers runs the password-expiry gate's SetAccountState write.
func (e *lockoutOracleEnv) expirePassword(t *testing.T) {
	t.Helper()
	e.h.coreService.SetPasswordPolicy(core.PasswordPolicy{MaxAgeDays: 1})
	old := time.Now().Add(-30 * 24 * time.Hour)
	require.NoError(t, e.db.Model(&models.User{}).Where("id = ?", 1).Update("password_changed_at", old).Error)
}

// TestLogin_PasswordExpiryGateFaultCostsTheSameAsAWrongPassword is #3557 (1).
// The gate's write runs only after the password matched, so its fault must be
// answered and charged exactly like a wrong password. Its error kind already
// was (#2894); its PANIC reached the Recovery 500, which a wrong password never
// gets, with the lockout uncounted.
func TestLogin_PasswordExpiryGateFaultCostsTheSameAsAWrongPassword(t *testing.T) {
	for _, kind := range []faultstorage.FaultKind{faultstorage.KindError, faultstorage.KindPanic} {
		t.Run(kind.String(), func(t *testing.T) {
			ctrlEnv := newLockoutOracleEnv(t)
			ctrlEnv.expirePassword(t)
			ctrlEnv.driveToThresholdMinusOne(t)
			control := ctrlEnv.observe(t, ctrlEnv.postLogin(t, "still-not-her-password"))
			require.True(t, control.locked, "control: a wrong password at threshold-1 must lock the account")

			probeEnv := newLockoutOracleEnv(t)
			probeEnv.expirePassword(t)
			probeEnv.driveToThresholdMinusOne(t)
			probeEnv.fs.Arm(&faultstorage.FaultSpec{
				Method: "SetAccountState", NthCall: 1, Kind: kind, Err: assert.AnError,
			})
			w := probeEnv.postLogin(t, lockoutOracleTestPassword)
			require.True(t, probeEnv.fs.Fired(), "the gate's write must actually have been faulted")
			probe := probeEnv.observe(t, w)

			requireIndistinguishable(t, control, probe, "login/SetAccountState/"+kind.String())
			var sessions int64
			require.NoError(t, probeEnv.db.Model(&models.Session{}).Count(&sessions).Error)
			assert.Zero(t, sessions, "a post-verdict fault must leave no live session")
			assert.Equal(t, int64(1), waitForAuditEvent(t, probeEnv.db, "auth.login_error"),
				"the denial must be audited auth.login_error")
		})
	}
}

// commitThenPanicRecoveryConsume runs the real ConsumeMFARecoveryCode once and
// then panics: the consume landed, the caller never learns it.
type commitThenPanicRecoveryConsume struct {
	corestorage.Storage
	fired atomic.Bool
}

func (s *commitThenPanicRecoveryConsume) ConsumeMFARecoveryCode(ctx context.Context, userID uint, codeHash string, now time.Time) (bool, error) {
	if s.fired.CompareAndSwap(false, true) {
		_, _ = s.Storage.ConsumeMFARecoveryCode(ctx, userID, codeHash, now)
		panic("injected panic after commit: ConsumeMFARecoveryCode")
	}
	return s.Storage.ConsumeMFARecoveryCode(ctx, userID, codeHash, now)
}

// TestVerifyMFA_RecoveryCodeConsumePanicIsAnsweredLikeItsError is #3557 (2).
// The conditional consume IS the recovery-code check (a wrong code reaches it
// too), so a fault there is pre-verdict and answered "unavailable", uncounted,
// slot handed back, audited mfa.error. A PANIC used to reach the Recovery 500
// with nothing audited, so a consume that landed before the panic burned a
// correct recovery code without a trace. Now the panic, also one after the
// consume committed, is answered byte-identically to the error kind and is
// audited.
func TestVerifyMFA_RecoveryCodeConsumePanicIsAnsweredLikeItsError(t *testing.T) {
	recoveryCode := func(t *testing.T, e *lockoutOracleEnv) string {
		t.Helper()
		// With TOTP active, the re-auth takes a current code, not the password.
		totpCode, err := totp.GenerateCode(e.totpSecret, e.clock)
		require.NoError(t, err)
		codes, err := e.h.coreService.RegenerateMFARecoveryCodes(context.Background(), 1, totpCode)
		require.NoError(t, err)
		require.NotEmpty(t, codes)
		return codes[0]
	}

	ctrlEnv := newLockoutOracleEnvWithMFA(t)
	ctrlCode := recoveryCode(t, ctrlEnv)
	ctrlCh, err := ctrlEnv.h.coreService.CreateMFAChallenge(context.Background(), 1)
	require.NoError(t, err)
	ctrlEnv.fs.Arm(&faultstorage.FaultSpec{
		Method: "ConsumeMFARecoveryCode", NthCall: 1, Kind: faultstorage.KindError, Err: assert.AnError,
	})
	ctrlW := ctrlEnv.postVerify(t, ctrlCh, ctrlCode)
	require.True(t, ctrlEnv.fs.Fired())
	control := ctrlEnv.observe(t, ctrlW)
	require.Equal(t, http.StatusServiceUnavailable, control.status, "control: a consume error is 'unavailable'")

	var wrap *commitThenPanicRecoveryConsume
	probeEnv := newLockoutOracleEnvWithMFAOver(t, func(s corestorage.Storage, _ *gorm.DB) corestorage.Storage {
		wrap = &commitThenPanicRecoveryConsume{Storage: s}
		return wrap
	})
	probeCode := recoveryCode(t, probeEnv)
	probeCh, err := probeEnv.h.coreService.CreateMFAChallenge(context.Background(), 1)
	require.NoError(t, err)
	w := probeEnv.postVerify(t, probeCh, probeCode)
	require.True(t, wrap.fired.Load(), "the consume must actually have panicked")
	probe := probeEnv.observe(t, w)

	requireIndistinguishable(t, control, probe, "mfa/verify/ConsumeMFARecoveryCode/panic-after-commit")
	var mfaErrors int64
	require.NoError(t, probeEnv.db.Model(&models.AuditEvent{}).Where("event_type = ?", "mfa.error").Count(&mfaErrors).Error)
	assert.Equal(t, int64(1), mfaErrors, "the burned code must leave an mfa.error audit row")
	var sessions int64
	require.NoError(t, probeEnv.db.Model(&models.Session{}).Count(&sessions).Error)
	assert.Zero(t, sessions)
}
