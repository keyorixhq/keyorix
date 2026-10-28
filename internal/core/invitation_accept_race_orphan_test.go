package core

// invitation_accept_race_orphan_test.go — AUDIT-503-MAP-1 item 4.
//
// completeInvitationAccept creates the invitee's account, spends the setup link and
// grants the invitation's roles BEFORE it flips the invitation to accepted, and that
// last write is conditional on the invitation still being pending (#412). When an
// admin's revoke (or the lazy expiry) wins the race in that window, the write
// no-ops, the grants are reverted and the accept fails closed
// (invitation.accept_race_reverted) — but the account created for it stayed ACTIVE:
// no grant, no invitation, a link that can never be replayed, yet a password that
// logs in and a row in every user list. Every other failure after the account exists
// removes it (abandonInvitationAccept); this path now does too.
//
// The race is modelled the way it happens: the revoke lands in the database between
// the pending check at the top and the conditional write at the end (here: right after
// the project grant commits).

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// raceRevoke returns w's store armed so the invitation is revoked right after the
// project grant commits.
func (w *inviteAcceptStepWorld) raceRevoke(t *testing.T) storage.Storage {
	t.Helper()
	return hooked(w.st, &storeHooks{
		CreateProjectMembership: func(next storage.Storage, ctx context.Context, m *models.ProjectMembership) (*models.ProjectMembership, error) {
			got, err := next.CreateProjectMembership(ctx, m)
			if err == nil {
				require.NoError(t, w.st.DB().Model(&models.ProjectInvitation{}).Where("id = ?", w.inv.ID).
					Update("state", InvitationRevoked).Error)
			}
			return got, err
		},
	})
}

func (w *inviteAcceptStepWorld) auditRows(t *testing.T, eventType string) []models.AuditEvent {
	t.Helper()
	var rows []models.AuditEvent
	require.NoError(t, w.st.DB().Where("event_type = ?", eventType).Find(&rows).Error)
	return rows
}

func TestCompleteInvitationAccept_RaceWithRevoke_RemovesTheNewAccount(t *testing.T) {
	ctx := context.Background()

	t.Run("account removed, grants reverted, invitation stays revoked, audit names it", func(t *testing.T) {
		w := newInviteAcceptStepWorld(t, false)
		w.c.storage = w.raceRevoke(t)

		res, err := w.c.CompleteSetup(ctx, w.rawTok, strongPw, "ua", "1.2.3.4")
		w.c.storage = w.st
		require.Error(t, err)
		assert.Nil(t, res, "no session is minted for a revoked invitation")
		assert.Contains(t, err.Error(), "this invitation was revoked")

		// The orphan: before, an ACTIVE account with no grant and no invitation.
		_, gerr := w.st.GetUserByEmail(ctx, w.email)
		require.Error(t, gerr, "the account created for the lost race must not stay active")
		rows := w.accountRows(t)
		require.Len(t, rows, 1)
		require.True(t, rows[0].DeletedAt.Valid, "the account must be removed")
		project, rerr := w.st.GetUserRoleIDsExact(ctx, rows[0].ID, storage.Scope{ProjectID: w.proj.ID})
		require.NoError(t, rerr)
		assert.Empty(t, project, "the grant just made must be reverted")

		// The revoke wins: the invitation is NOT put back to pending (unlike the other
		// failure paths, nobody should resend a revoked invitation).
		inv, ierr := w.st.GetProjectInvitation(ctx, w.inv.ID)
		require.NoError(t, ierr)
		assert.Equal(t, InvitationRevoked, inv.State)

		reverted := w.auditRows(t, "invitation.accept_race_reverted")
		require.Len(t, reverted, 1)
		assert.Contains(t, reverted[0].Description, fmt.Sprintf("invitation %d", w.inv.ID))
		assert.Contains(t, reverted[0].Description, fmt.Sprintf("user %d", rows[0].ID))
		assert.Contains(t, reverted[0].Description, "was removed", "the row says the account went too")
		assert.Empty(t, w.auditRows(t, "invitation.accept_orphaned_account_cleanup_failed"))
	})

	t.Run("removal fails: loud audit row, never silent", func(t *testing.T) {
		w := newInviteAcceptStepWorld(t, false)
		fs := faultstorage.NewFaultyStorage(w.raceRevoke(t), &faultstorage.FaultSpec{
			Method: "DeleteUser", NthCall: 1, Kind: faultstorage.KindError, Err: errors.New("injected delete failure")})
		w.c.storage = fs

		_, err := w.c.CompleteSetup(ctx, w.rawTok, strongPw, "ua", "1.2.3.4")
		w.c.storage = w.st
		require.True(t, fs.Fired(), "the DeleteUser fault must have fired")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "this invitation was revoked")

		failed := w.auditRows(t, "invitation.accept_orphaned_account_cleanup_failed")
		require.Len(t, failed, 1, "a leftover account must be reported for manual cleanup")
		assert.Contains(t, failed[0].Description, "MANUAL CLEANUP REQUIRED")
		reverted := w.auditRows(t, "invitation.accept_race_reverted")
		require.Len(t, reverted, 1)
		assert.Contains(t, reverted[0].Description, "could NOT be removed")
	})
}
