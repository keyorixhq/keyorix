package core

// invitation_accept_residue_test.go — #4410 (INVITE-ACCEPT-NOV-1 item 4). An abandoned
// invitation accept soft-deleted the account it had created but left what CreateUser
// gave it: the baseline system_viewer role (a RestoreUser brought it back) and the
// password-history row. removeInvitationAcceptAccount now removes both with the account,
// in one transaction. A membership the grant created is revoked, not left `active`
// with no role (revokeInvitationMembershipRow). The spent link, the kept LoginAttempt
// slot and that revoked membership row stay, by design (see its doc comment).

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// residue counts the rows CreateUser wrote for an account besides the user row.
func (w *inviteAcceptStepWorld) residue(t *testing.T, userID uint) (roles, history int64) {
	t.Helper()
	db := w.st.DB()
	require.NoError(t, db.Model(&models.UserRole{}).Where("user_id = ?", userID).Count(&roles).Error)
	require.NoError(t, db.Model(&models.PasswordHistory{}).Where("user_id = ?", userID).Count(&history).Error)
	return roles, history
}

func TestCompleteInvitationAccept_AbandonRemovesBaselineRoleAndPasswordHistory(t *testing.T) {
	ctx := context.Background()

	// Calibration: a completed accept leaves exactly what the undo must remove, so
	// the zero counts below are not vacuous.
	t.Run("calibration: a completed accept has the baseline role and a history row", func(t *testing.T) {
		w := newInviteAcceptStepWorld(t, false)
		w.requireAcceptSucceeds(t, w.rawTok)
		u, err := w.st.GetUserByEmail(ctx, w.email)
		require.NoError(t, err)
		viewer, err := w.st.GetRoleByName(ctx, "system_viewer")
		require.NoError(t, err)
		global, err := w.st.GetUserRoleIDsExact(ctx, u.ID, Scope{})
		require.NoError(t, err)
		assert.Contains(t, global, viewer.ID)
		_, history := w.residue(t, u.ID)
		assert.Equal(t, int64(1), history)
	})

	for _, tc := range []struct {
		method string
		kind   faultstorage.FaultKind
	}{
		{"MarkSetupTokenConsumed", faultstorage.KindError},
		{"CreateProjectMembership", faultstorage.KindError},
		{"AssignRole", faultstorage.KindPanic}, // #2: the project role, after the membership
		{"UpdateProjectInvitation", faultstorage.KindError},
	} {
		t.Run(tc.method+"/"+tc.kind.String(), func(t *testing.T) {
			w := newInviteAcceptStepWorld(t, false)
			nth := 1
			if tc.method == "AssignRole" {
				nth = 2
			}
			fs := faultstorage.NewFaultyStorage(w.st, &faultstorage.FaultSpec{Method: tc.method, NthCall: nth, Kind: tc.kind, Err: errors.New("injected")})
			w.c.storage = fs
			_, err := w.c.CompleteSetup(ctx, w.rawTok, strongPw, "ua", "1.2.3.4")
			w.c.storage = w.st
			require.True(t, fs.Fired())
			require.ErrorIs(t, err, ErrInvitationAcceptAbandoned)

			accounts := w.accountRows(t)
			require.Len(t, accounts, 1, "the accept created one account")
			require.True(t, accounts[0].DeletedAt.Valid, "and removed it")
			roles, history := w.residue(t, accounts[0].ID)
			// Before: roles == 1 (system_viewer) and history == 1.
			assert.Zero(t, roles, "no role is left on the removed account: a RestoreUser must not bring the baseline back")
			assert.Zero(t, history, "the removed account's password history goes with it")
			var live int64
			require.NoError(t, w.st.DB().Model(&models.ProjectMembership{}).
				Where("user_id = ? AND state <> ?", accounts[0].ID, MembershipRevoked).Count(&live).Error)
			// Before: a grant that panicked, or one that succeeded before the accept
			// write failed, left the membership `active` with no role behind it.
			assert.Zero(t, live, "no live membership is left for the removed account")
		})
	}
}
