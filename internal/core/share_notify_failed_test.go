package core

// PURGE-TX-TAILS-1 item 2 (CORE-ORACLE-DRAIN-1 leftover): the share / revoke
// notifiers run AFTER their share write committed, under
// runPostCommitNotificationFor, so a failed or panicking notification
//
//   - never turns the committed share or revoke into an error, and
//   - is recorded as a "notification.failed" audit event, like the access-request
//     notifiers (INV-CORE-access-request-notify-never-fails-committed-transition),
//     instead of only being logged.
//
// The faults are real: a gorm callback that fails / panics the notifications INSERT
// (the same technique as sharing_notify_panic_test.go), and the faultstorage double
// for the group-member lookup. Effects are asserted from the database, not from
// return values.

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// failNotificationInsert makes every INSERT into notifications fail (panics when
// doPanic) on replica A until the returned remove func is called, and returns a fire
// counter so a test cannot pass vacuously.
func (f *ctaReview) failNotificationInsert(name string, doPanic bool) (fired func() int, remove func()) {
	f.t.Helper()
	n := 0
	require.NoError(f.t, f.dbA.Callback().Create().Before("gorm:begin_transaction").Register(name,
		func(tx *gorm.DB) {
			if tx.Statement.Table != "notifications" {
				return
			}
			n++
			if doPanic {
				panic("injected CreateNotification panic")
			}
			_ = tx.AddError(errors.New("injected CreateNotification error"))
		}))
	return func() int { return n }, func() { _ = f.dbA.Callback().Create().Remove(name) }
}

// failedNotificationRows returns the notification.failed audit rows, oldest first.
func (f *ctaReview) failedNotificationRows() []models.AuditEvent {
	f.t.Helper()
	var rows []models.AuditEvent
	require.NoError(f.t, f.setupDB.Where("event_type = ?", auditNotificationFailed).Order("id").Find(&rows).Error)
	return rows
}

func TestShareNotifiers_FailedNotificationAfterCommit_IsRecorded(t *testing.T) {
	f := newCTAReviewSQLite(t)
	owner := f.user("notifyfail-owner", "project_admin")
	recipient := f.user("notifyfail-recipient", "project_viewer")
	secret := f.secret("notifyfail-secret", owner.ID)

	for _, doPanic := range []bool{false, true} {
		kind := "error"
		if doPanic {
			kind = "panic"
		}

		t.Run("ShareSecret/"+kind, func(t *testing.T) {
			fired, remove := f.failNotificationInsert("share-notify-fail-share-"+kind, doPanic)
			defer remove()
			before := len(f.failedNotificationRows())

			share, err := f.coreA.ShareSecret(f.ctx, &ShareSecretRequest{
				SecretID: secret.ID, RecipientID: recipient.ID, Permission: "read", SharedBy: owner.ID,
			})
			require.NoError(t, err, "a committed share must report success when its notification fails")
			require.NotNil(t, share)
			require.Positive(t, fired(), "the notification insert fault must have fired, or this proves nothing")
			assert.EqualValues(t, 1, f.liveShareCount(share.ID), "the share stays committed")

			rows := f.failedNotificationRows()
			require.Len(t, rows, before+1, "the failed notification is recorded as one notification.failed event")
			last := rows[len(rows)-1]
			assert.Contains(t, last.Description, "secret_share.notify")
			assert.Contains(t, last.Description, "share of secret")
			require.NotNil(t, last.SecretNodeID)
			assert.Equal(t, secret.ID, *last.SecretNodeID)
			require.NotNil(t, last.UserID)
			assert.Equal(t, owner.ID, *last.UserID, "the sharer is the actor")
			require.NotNil(t, last.Success)
			assert.False(t, *last.Success, "recorded as a failure (Success=false)")

			// Clean up for the next iteration: the share must be revocable below.
			remove()
			require.NoError(t, f.coreA.RevokeShare(f.ctx, share.ID, owner.ID))
		})

		t.Run("RevokeShare/"+kind, func(t *testing.T) {
			share, err := f.setup.ShareSecret(f.ctx, &ShareSecretRequest{
				SecretID: secret.ID, RecipientID: recipient.ID, Permission: "read", SharedBy: owner.ID,
			})
			require.NoError(t, err)
			fired, remove := f.failNotificationInsert("share-notify-fail-revoke-"+kind, doPanic)
			defer remove()
			before := len(f.failedNotificationRows())

			require.NoError(t, f.coreA.RevokeShare(f.ctx, share.ID, owner.ID),
				"a committed revoke must report success when its notification fails")
			require.Positive(t, fired())
			assert.Zero(t, f.liveShareCount(share.ID), "the revoke stays committed")

			rows := f.failedNotificationRows()
			require.Len(t, rows, before+1)
			assert.Contains(t, rows[len(rows)-1].Description, "secret_share.revoke_notify")
		})
	}
}

// TestShareNotifiers_PanickingGroupMemberLookup_DoesNotFailTheRevoke: the group
// fan-out resolves its recipients with ListGroupMembers after the revoke committed.
// A panic (or error) there must not fail the revoke, and must be recorded.
func TestShareNotifiers_PanickingGroupMemberLookup_DoesNotFailTheRevoke(t *testing.T) {
	f := newCTAReviewSQLite(t)
	owner := f.user("notifylookup-owner", "project_admin")
	member := f.user("notifylookup-member", "project_viewer")
	secret := f.secret("notifylookup-secret", owner.ID)

	group, err := f.setup.CreateGroup(f.ctx, f.adminID, &CreateGroupRequest{Name: "notifylookup-group"})
	require.NoError(t, err)
	require.NoError(t, f.setup.AddUserToGroup(f.ctx, f.adminID, false, member.ID, group.ID, 0))
	viewer, err := f.setup.Storage().GetRoleByName(f.ctx, "project_viewer")
	require.NoError(t, err)
	require.NoError(t, f.setup.Storage().AssignRoleToGroup(f.ctx, group.ID, viewer.ID, Scope{ProjectID: f.projectID}))

	for _, kind := range []faultstorage.FaultKind{faultstorage.KindPanic, faultstorage.KindError} {
		t.Run(kind.String(), func(t *testing.T) {
			share, err := f.setup.ShareSecretWithGroup(f.ctx, &GroupShareSecretRequest{
				SecretID: secret.ID, GroupID: group.ID, Permission: "read", SharedBy: owner.ID,
			})
			require.NoError(t, err)
			before := len(f.failedNotificationRows())

			orig := f.coreA.storage
			faulty := faultstorage.NewFaultyStorage(orig, nil)
			f.coreA.storage = faulty
			defer func() { f.coreA.storage = orig }()
			faulty.Arm(&faultstorage.FaultSpec{Method: "ListGroupMembers", NthCall: 1, Kind: kind, Err: errors.New("injected member lookup fault")})

			require.NoError(t, f.coreA.RevokeShare(f.ctx, share.ID, owner.ID),
				"a committed group revoke must report success when the member lookup fails")
			require.True(t, faulty.Fired(), "the lookup fault must have fired")
			assert.Zero(t, f.liveShareCount(share.ID), "the revoke stays committed")

			rows := f.failedNotificationRows()
			require.Len(t, rows, before+1, "the failed lookup is recorded")
			assert.Contains(t, rows[len(rows)-1].Description, "secret_share.group_revoke_notify")
			assert.Contains(t, rows[len(rows)-1].Description, "injected member lookup fault")
		})
	}
}
