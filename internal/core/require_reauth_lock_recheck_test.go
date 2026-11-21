// require_reauth_lock_recheck_test.go — #2888: requireReauth checked only the
// caller's snapshot of the account (loginLocked(user)), never re-reading the
// lockout once the code or password matched, unlike login, MFA verify, step-up
// and WebAuthn (recheckLockAfterCredentialMatched). A correct guess racing a
// burst that locked the account therefore passed, and cleared the counter.
package core

import (
	"context"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestRequireReauth_LockedAfterSnapshotIsRefused(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, db, fixed := newMFATestCore(t)
	c.loginLockout = postVerdictParityPolicy
	secret, _ := activateMFAForTest(t, c, fixed)

	var snapshot models.User
	require.NoError(t, db.First(&snapshot, 1).Error)
	// Locked by a concurrent burst after the caller read its snapshot.
	until := time.Now().Add(time.Hour)
	require.NoError(t, db.Model(&models.User{}).Where("id = ?", 1).
		Updates(map[string]any{"login_locked_until": until, "failed_login_attempts": 5}).Error)

	good, err := totp.GenerateCode(secret, fixed)
	require.NoError(t, err)
	rerr := c.requireReauth(ctx, &snapshot, good, "test")
	require.Error(t, rerr, "a correct code must not pass on a now-locked account")
	var rejected *reauthRejectedError
	require.ErrorAs(t, rerr, &rejected, "answered like a wrong code")

	var after models.User
	require.NoError(t, db.First(&after, 1).Error)
	require.NotNil(t, after.LoginLockedUntil, "the lock must not be cleared by the correct code")
	assert.WithinDuration(t, until, *after.LoginLockedUntil, time.Second)
}

func TestRequireReauth_RecheckFaultCostsTheSameAsAWrongCode(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	cc, cdb, cfixed := newMFATestCore(t)
	cc.loginLockout = postVerdictParityPolicy
	activateMFAForTest(t, cc, cfixed)
	putAtThresholdMinusOne(t, cdb, 1)
	require.Error(t, cc.DisableMFA(ctx, 1, "000000", ""))
	control := readLockoutState(t, cdb, 1)

	pc, pdb, pfixed := newMFATestCore(t)
	pc.loginLockout = postVerdictParityPolicy
	secret, _ := activateMFAForTest(t, pc, pfixed)
	putAtThresholdMinusOne(t, pdb, 1)
	good, err := totp.GenerateCode(secret, pfixed)
	require.NoError(t, err)
	fs, restore := armRecheckFault(pc)
	perr := pc.DisableMFA(ctx, 1, good, "")
	restore()
	require.True(t, fs.Fired(), "the recheck's LockUserForUpdate must have been reached")
	require.Error(t, perr, "a correct code with a failed lock recheck must not disable MFA")
	probe := readLockoutState(t, pdb, 1)

	requireSameLockoutCost(t, control, probe, "DisableMFA/requireReauth recheck")
	var u models.User
	require.NoError(t, pdb.First(&u, 1).Error)
	assert.True(t, u.MFAEnabled, "MFA must still be enabled")
}
