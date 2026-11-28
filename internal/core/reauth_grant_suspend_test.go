// reauth_grant_suspend_test.go — a user whose account is disabled must not keep a
// working re-auth step-up grant (REAUTH-SUSPEND-1, SESSION-AUTH-VERIFY-1 point c).
//
// FinishWebAuthnReauth mints a short-lived MFAStepUpPurposeReauth grant (no
// session). Before this fix nothing deleted it when the account was suspended /
// deactivated / deleted / SCIM-deprovisioned, and consuming it did not check the
// account was still active, so a user suspended right after re-authenticating
// kept an elevated grant. Two layers now close that:
//  1. every account-disabling path purges the user's grants right after the
//     disable commits (purgeStepUpGrants, best-effort);
//  2. requireReauth re-reads the account before spending a grant
//     (userStillActiveForGrant), so a grant inserted AFTER the purge (the
//     suspend-between-check-and-insert race) is refused with the same generic
//     error as an absent grant.
package core

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// newSuspendTestCore is newMFATestCore plus the tables guardLastAdminDeactivation
// and the PAT revoke read (the MFA harness omits them; without them the guard
// fails closed and refuses every suspend), with MFA activated for user 1.
func newSuspendTestCore(t *testing.T) (*KeyorixCore, *gorm.DB, time.Time) {
	t.Helper()
	c, db, fixed := newMFATestCore(t)
	require.NoError(t, db.AutoMigrate(&models.PersonalAccessToken{}, &models.Group{}, &models.UserGroup{},
		&models.GroupRole{}, &models.Project{}, &models.Environment{}))
	activateMFAForTest(t, c, fixed)
	return c, db, fixed
}

func mintReauthGrantFor(t *testing.T, db *gorm.DB, userID uint, fixed time.Time) {
	t.Helper()
	require.NoError(t, db.Create(&models.MFAStepUpGrant{
		UserID: userID, Purpose: models.MFAStepUpPurposeReauth, ExpiresAt: fixed.Add(15 * time.Minute),
	}).Error)
}

func countGrantsFor(t *testing.T, db *gorm.DB, userID uint) int64 {
	t.Helper()
	var n int64
	require.NoError(t, db.Model(&models.MFAStepUpGrant{}).Where("user_id = ?", userID).Count(&n).Error)
	return n
}

// requireStepUpActionRefused drives a requireReauth-gated action with the
// account password (the grant is what would make it succeed) and asserts the
// generic refusal, and that the action had no effect.
func requireStepUpActionRefused(t *testing.T, c *KeyorixCore, userID uint) {
	t.Helper()
	_, err := c.RegenerateMFARecoveryCodes(context.Background(), userID, "", mfaTestPassword)
	require.Error(t, err, "a disabled account's re-auth grant must not satisfy a step-up action")
	assert.Contains(t, err.Error(), "invalid code or password",
		"refusal must be the same generic error as an absent grant")
}

// Suspend after re-auth: the grant is gone and the step-up action is refused.
func TestSuspendUser_PurgesReauthGrants_StepUpActionRefused(t *testing.T) {
	t.Parallel()
	c, db, fixed := newSuspendTestCore(t)
	ctx := context.Background()
	mintReauthGrantFor(t, db, 1, fixed)
	require.EqualValues(t, 1, countGrantsFor(t, db, 1))

	require.NoError(t, c.SuspendUser(ctx, 0, 1))

	assert.EqualValues(t, 0, countGrantsFor(t, db, 1), "suspension must purge the user's re-auth grants")
	requireStepUpActionRefused(t, c, 1)
}

// The race: the grant is inserted after the suspension's purge (it was created
// between the suspend's check and its insert). Nothing purged it, so the use-time
// account check is what refuses it.
func TestRequireReauth_GrantCreatedAfterSuspend_RefusedAtUse(t *testing.T) {
	t.Parallel()
	c, db, fixed := newSuspendTestCore(t)
	ctx := context.Background()

	require.NoError(t, c.SuspendUser(ctx, 0, 1))
	mintReauthGrantFor(t, db, 1, fixed) // lands after the purge
	require.EqualValues(t, 1, countGrantsFor(t, db, 1))

	requireStepUpActionRefused(t, c, 1)
}

// An active user is unaffected: another user's suspension leaves their grant
// intact and usable, and ReactivateUser does not break a freshly minted one.
func TestSuspendUser_ActiveUserGrantUnaffected(t *testing.T) {
	t.Parallel()
	c, db, fixed := newSuspendTestCore(t)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "bob", UsernameFolded: "bob", Email: "b@b.com",
		EmailFolded: "b@b.com", PasswordHash: "x", AccountState: "active"}).Error)
	mintReauthGrantFor(t, db, 1, fixed)
	mintReauthGrantFor(t, db, 2, fixed)

	require.NoError(t, c.SuspendUser(ctx, 0, 2))

	assert.EqualValues(t, 0, countGrantsFor(t, db, 2))
	assert.EqualValues(t, 1, countGrantsFor(t, db, 1), "an active user's grant must survive someone else's suspension")
	codes, err := c.RegenerateMFARecoveryCodes(ctx, 1, "", mfaTestPassword)
	require.NoError(t, err, "an active user's grant must still satisfy re-auth")
	assert.NotEmpty(t, codes)

	require.NoError(t, c.ReactivateUser(ctx, 0, 2))
	mintReauthGrantFor(t, db, 1, fixed)
	_, err = c.RegenerateMFARecoveryCodes(ctx, 1, "", mfaTestPassword)
	require.NoError(t, err)
}

// Sibling account-disabling paths purge too.
func TestDeleteUser_PurgesReauthGrants(t *testing.T) {
	t.Parallel()
	c, db, fixed := newSuspendTestCore(t)
	ctx := context.Background()
	mintReauthGrantFor(t, db, 1, fixed)

	require.NoError(t, c.DeleteUser(ctx, 1, 1))

	assert.EqualValues(t, 0, countGrantsFor(t, db, 1), "deleting a user must purge their re-auth grants")
}

func TestRevokeUserCredentialsForDeactivation_PurgesReauthGrants(t *testing.T) {
	t.Parallel()
	c, db, fixed := newSuspendTestCore(t)
	mintReauthGrantFor(t, db, 1, fixed)

	c.RevokeUserCredentialsForDeactivation(context.Background(), 1)

	assert.EqualValues(t, 0, countGrantsFor(t, db, 1))
}

// A deactivated (IsActive=false) account is refused at use even if its
// account_state still reads active (UpdateUser deactivation writes is_active).
func TestRequireReauth_DeactivatedAccountGrantRefusedAtUse(t *testing.T) {
	t.Parallel()
	c, db, fixed := newSuspendTestCore(t)
	mintReauthGrantFor(t, db, 1, fixed)
	require.NoError(t, db.Model(&models.User{}).Where("id = ?", 1).Update("is_active", false).Error)

	requireStepUpActionRefused(t, c, 1)
}

// TestMFAOpsRefusalTextMatchesWrongPassword: for a suspended account, all three
// MFA mutation ops must produce the EXACT same error text as a wrong password on
// an active account. Any deviation leaks account state to the caller.
//
// Baseline: calling with the correct password but no step-up grant also returns
// "invalid code or password" (the grant is what enables the correct-password path
// to succeed; without it, the password alone is insufficient for MFA-enabled
// accounts). This baseline is used rather than a genuinely wrong password because
// it exercises the same path the ACTIVE-user case would take, and shows that the
// suspended-actor guard uses an identical message despite firing earlier.
func TestMFAOpsRefusalTextMatchesWrongPassword(t *testing.T) {
	t.Parallel()
	c, _, _ := newSuspendTestCore(t)
	ctx := context.Background()

	// Get the "wrong credential" text for each op on an active account
	// (correct password, MFA enabled, no step-up grant → "invalid code or password").
	_, activateActiveErr := c.ActivateMFA(ctx, 1, "123456", mfaTestPassword, "")
	require.Error(t, activateActiveErr, "active-account baseline must refuse (no step-up grant)")
	disableActiveErr := c.DisableMFA(ctx, 1, "", mfaTestPassword, "")
	require.Error(t, disableActiveErr, "active-account baseline must refuse (no step-up grant)")
	_, regenActiveErr := c.RegenerateMFARecoveryCodes(ctx, 1, "", mfaTestPassword)
	require.Error(t, regenActiveErr, "active-account baseline must refuse (no step-up grant)")

	// Suspend the account.
	require.NoError(t, c.SuspendUser(ctx, 0, 1))

	// Now call with the actual password on the suspended account.
	_, err := c.ActivateMFA(ctx, 1, "123456", mfaTestPassword, "")
	require.Error(t, err)
	assert.Equal(t, activateActiveErr.Error(), err.Error(),
		"ActivateMFA: suspended-actor text must match wrong-credential text")

	err = c.DisableMFA(ctx, 1, "", mfaTestPassword, "")
	require.Error(t, err)
	assert.Equal(t, disableActiveErr.Error(), err.Error(),
		"DisableMFA: suspended-actor text must match wrong-credential text")

	_, err = c.RegenerateMFARecoveryCodes(ctx, 1, "", mfaTestPassword)
	require.Error(t, err)
	assert.Equal(t, regenActiveErr.Error(), err.Error(),
		"RegenerateMFARecoveryCodes: suspended-actor text must match wrong-credential text")
}
