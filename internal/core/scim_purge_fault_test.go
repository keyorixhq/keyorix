package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// Failure paths of the SCIM lifecycle purge steps (SCIM-HARDEN-1 item 4). Each
// arms one storage fault under the real LocalStorage and asserts the EFFECT on
// the rows, not only the returned error: a refused or rolled-back call must leave
// the account, its PATs and its sessions exactly as they were, and a best-effort
// post-commit step that fails must not undo or block the committed offboarding.

type scimFaultRow struct {
	IsActive     bool
	AccountState string
	Deleted      bool
	LivePATs     int64
	Sessions     int64
}

func scimFaultSnapshot(t *testing.T, db *gorm.DB) scimFaultRow {
	t.Helper()
	var u models.User
	require.NoError(t, db.Unscoped().First(&u, 1).Error)
	var pats, sessions int64
	require.NoError(t, db.Model(&models.PersonalAccessToken{}).Where("user_id = ? AND revoked = ?", 1, false).Count(&pats).Error)
	require.NoError(t, db.Model(&models.Session{}).Where("user_id = ?", 1).Count(&sessions).Error)
	return scimFaultRow{IsActive: u.IsActive, AccountState: u.AccountState, Deleted: u.DeletedAt.Valid, LivePATs: pats, Sessions: sessions}
}

// newSCIMFaultCore is newSCIMDeactivatePATCore plus a live session and an unspent
// step-up grant, so every purge step has something to purge.
func newSCIMFaultCore(t *testing.T) (*KeyorixCore, *gorm.DB, string, *[]string) {
	t.Helper()
	c, db, raw, evicted := newSCIMDeactivatePATCore(t)
	expiry := time.Now().Add(time.Hour)
	_, err := c.storage.CreateSession(context.Background(), &models.Session{UserID: 1, SessionToken: "scim-fault-sess", ExpiresAt: &expiry})
	require.NoError(t, err)
	require.NoError(t, db.Create(&models.MFAStepUpGrant{UserID: 1, Purpose: models.MFAStepUpPurposeReauth, ExpiresAt: expiry}).Error)
	*evicted = nil
	return c, db, raw, evicted
}

func withFault(c *KeyorixCore, spec *faultstorage.FaultSpec) *faultstorage.FaultyStorage {
	fs := faultstorage.NewFaultyStorage(c.storage, spec)
	c.storage = fs
	return fs
}

// TestSCIMUserOps_GetUserFaultChangesNothing: the ownership pre-check's GetUser
// failing must refuse the operation (fail closed) with nothing written, for the
// deactivate, deprovision and read paths alike.
func TestSCIMUserOps_GetUserFaultChangesNothing(t *testing.T) {
	t.Parallel()
	no := false
	ops := map[string]func(c *KeyorixCore) error{
		"UpdateSCIMUser(active=false)": func(c *KeyorixCore) error {
			_, err := c.UpdateSCIMUser(context.Background(), 2, 1, nil, nil, &no)
			return err
		},
		"DeprovisionSCIMUser": func(c *KeyorixCore) error { return c.DeprovisionSCIMUser(context.Background(), 2, 1) },
		"GetSCIMUser": func(c *KeyorixCore) error {
			_, err := c.GetSCIMUser(context.Background(), 1)
			return err
		},
	}
	for name, op := range ops {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			c, db, raw, evicted := newSCIMFaultCore(t)
			before := scimFaultSnapshot(t, db)
			fs := withFault(c, &faultstorage.FaultSpec{Method: "GetUser", NthCall: 1, Kind: faultstorage.KindError, Err: errors.New("injected: GetUser")})

			require.Error(t, op(c))
			require.True(t, fs.Fired(), "the ownership pre-check must have been reached")
			assert.Equal(t, before, scimFaultSnapshot(t, db))
			assert.Empty(t, *evicted, "nothing may be evicted when nothing was revoked")
			_, _, _, _, err := c.ValidatePATToken(context.Background(), raw)
			assert.NoError(t, err, "the PAT must still work: the operation was refused")
		})
	}
}

// TestUpdateSCIMUser_PATRevokeFaultRollsBackDeactivation: the PAT revoke runs
// inside the deactivation's transaction (#3419), so its failure must roll the
// whole update back: no half-deactivated account (blocked but PATs live, or
// state written but is_active not), no session sweep, no eviction. Both a revoke
// that never ran (KindError) and one that ran and then reported failure
// (KindEffectThenError) must end in the pre-call state.
func TestUpdateSCIMUser_PATRevokeFaultRollsBackDeactivation(t *testing.T) {
	t.Parallel()
	for _, kind := range []faultstorage.FaultKind{faultstorage.KindError, faultstorage.KindEffectThenError} {
		t.Run(kind.String(), func(t *testing.T) {
			t.Parallel()
			c, db, raw, evicted := newSCIMFaultCore(t)
			before := scimFaultSnapshot(t, db)
			fs := withFault(c, &faultstorage.FaultSpec{Method: "RevokeAllPersonalAccessTokensForUser", NthCall: 1, Kind: kind,
				Err: errors.New("injected: RevokeAllPersonalAccessTokensForUser")})

			no := false
			_, err := c.UpdateSCIMUser(context.Background(), 2, 1, nil, nil, &no)
			require.True(t, fs.Fired(), "the deactivation must reach the PAT revoke")
			require.Error(t, err, "a failed revoke must fail the deactivation, not report success")

			assert.Equal(t, before, scimFaultSnapshot(t, db), "the whole deactivation must roll back")
			assert.Empty(t, *evicted)
			_, _, _, _, err = c.ValidatePATToken(context.Background(), raw)
			assert.NoError(t, err, "the account was not deactivated, so its PAT is untouched")

			// A retry once storage recovers completes the offboarding.
			fs.Arm(nil)
			_, err = c.UpdateSCIMUser(context.Background(), 2, 1, nil, nil, &no)
			require.NoError(t, err)
			after := scimFaultSnapshot(t, db)
			assert.False(t, after.IsActive)
			assert.Zero(t, after.LivePATs)
		})
	}
}

// TestSCIMOffboarding_StepUpPurgeFaultDoesNotUndoOffboarding: purging step-up
// grants is a best-effort, post-commit step (purgeStepUpGrants). When it errors or
// panics, the deactivation or deprovision has already committed and must stay
// committed (PATs revoked, sessions gone, account blocked), the call must still
// report success to the IdP, and the leftover grant must not be spendable because
// the account is no longer active (userStillActiveForGrant re-reads it).
func TestSCIMOffboarding_StepUpPurgeFaultDoesNotUndoOffboarding(t *testing.T) {
	t.Parallel()
	no := false
	ops := map[string]func(c *KeyorixCore) error{
		"UpdateSCIMUser(active=false)": func(c *KeyorixCore) error {
			_, err := c.UpdateSCIMUser(context.Background(), 2, 1, nil, nil, &no)
			return err
		},
		"DeprovisionSCIMUser": func(c *KeyorixCore) error { return c.DeprovisionSCIMUser(context.Background(), 2, 1) },
	}
	for name, op := range ops {
		for _, kind := range []faultstorage.FaultKind{faultstorage.KindError, faultstorage.KindPanic} {
			t.Run(name+"/"+kind.String(), func(t *testing.T) {
				t.Parallel()
				c, db, raw, evicted := newSCIMFaultCore(t)
				fs := withFault(c, &faultstorage.FaultSpec{Method: "DeleteMFAStepUpGrantsFor", NthCall: 1, Kind: kind,
					Err: errors.New("injected: DeleteMFAStepUpGrantsFor")})

				require.NoError(t, op(c), "a best-effort purge failure must not fail a committed offboarding")
				require.True(t, fs.Fired(), "the step-up purge must have been attempted")

				after := scimFaultSnapshot(t, db)
				assert.False(t, after.IsActive)
				assert.Zero(t, after.LivePATs, "PATs must be revoked")
				assert.Zero(t, after.Sessions, "sessions must be gone")
				assert.Contains(t, *evicted, sha256Hex(raw), "the revoked PAT must be evicted from the auth cache")

				var grants int64
				require.NoError(t, db.Model(&models.MFAStepUpGrant{}).Where("user_id = ?", 1).Count(&grants).Error)
				require.Equal(t, int64(1), grants, "precondition: the purge really failed and left the grant behind")
				fs.Arm(nil)
				ok, err := c.userStillActiveForGrant(context.Background(), 1)
				if name == "DeprovisionSCIMUser" {
					assert.Error(t, err, "a deprovisioned (soft-deleted) account cannot be read for a grant")
				} else {
					assert.NoError(t, err)
				}
				assert.False(t, ok, "a leftover step-up grant must not be spendable by an offboarded account")
			})
		}
	}
}
