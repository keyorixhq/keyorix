// mfa_recovery_reauth_internal_test.go — the parts of #4224's recovery-code
// re-auth that only the unexported helpers expose (mfa_recovery_reauth.go);
// the behaviour through DisableMFA/RegenerateMFARecoveryCodes is in
// mfa_recovery_reauth_test.go.
package core

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// A burst that locked the account after the caller's snapshot is seen under
// the row lock, before the code is consumed or the change runs.
func TestReauthWithRecoveryCode_LockedUnderTheRowLock(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, db, fixed := newMFATestCore(t)
	c.loginLockout = recoveryReauthPolicy
	_, codes := activateMFAForTest(t, c, fixed)
	var snapshot models.User
	require.NoError(t, db.First(&snapshot, 1).Error)
	until := time.Now().Add(time.Hour)
	require.NoError(t, db.Model(&models.User{}).Where("id = ?", 1).Update("login_locked_until", until).Error)

	applied := false
	handled, err := c.reauthWithRecoveryCode(ctx, &snapshot, codes[0], "disable", func(storage.Storage) error {
		applied = true
		return nil
	})
	require.True(t, handled)
	require.ErrorIs(t, err, ErrReauthRejected)
	assert.Contains(t, err.Error(), "temporarily locked")
	assert.False(t, applied, "the change must not run")
	assert.Equal(t, int64(mfaRecoveryCodeCount), unusedRecoveryCodes(t, db), "the code was not consumed")
	assert.Empty(t, auditDescriptions(t, db, "mfa.failed"), "nothing was evaluated")
}

func TestIsRecoveryCodeShaped(t *testing.T) {
	t.Parallel()
	codes, _, err := generateRecoveryCodes(20)
	require.NoError(t, err)
	for _, code := range codes {
		assert.True(t, isRecoveryCodeShaped(code), code)
		assert.True(t, isRecoveryCodeShaped(strings.ToLower(code)), code)
		assert.True(t, isRecoveryCodeShaped(strings.ReplaceAll(code, "-", "")), code)
	}
	assert.True(t, isRecoveryCodeShaped("PQRST-23456"), "TestRecoveryReauth_RecoveryShapedPasswordWithGrantStillWorks relies on it")
	for _, s := range []string{"", "123456", "ABCDE-FGHI", "ABCDE-FGHJKL", "ABCD0-FGHJK", "ABCDE_FGHJK", mfaTestPassword} {
		assert.False(t, isRecoveryCodeShaped(s), s)
	}
}
