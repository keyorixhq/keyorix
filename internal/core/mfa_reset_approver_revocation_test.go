package core

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// #3800 (revocation must win): the approver's own admin role and active state are
// re-checked on the approver's row lock inside the approval transaction, not only
// before it. An approver demoted or suspended after requireMFAResetActor read them
// must not complete the reset: no decision, no credential change, no success row.
func TestMFAReset_ApproverChangedInsideApproval_Refused(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(f *mfaResetFixture, role uint, tx storage.Storage) error
		want   error
	}{
		{"suspended", func(f *mfaResetFixture, _ uint, tx storage.Storage) error {
			return tx.SetAccountState(context.Background(), f.b.ID, AccountSuspended, f.now)
		}, ErrMFAResetAdminRequired},
		{"deactivated", func(f *mfaResetFixture, _ uint, tx storage.Storage) error {
			u, err := tx.GetUser(context.Background(), f.b.ID)
			if err != nil {
				return err
			}
			u.IsActive = false
			_, err = tx.UpdateUser(context.Background(), u)
			return err
		}, ErrMFAResetAdminRequired},
		{"lost the admin role", func(f *mfaResetFixture, role uint, tx storage.Storage) error {
			return tx.RemoveRole(context.Background(), f.b.ID, role, storage.Scope{})
		}, ErrMFAResetAdminRequired},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newMFAResetFixture(t)
			req := f.request(t)
			role := f.adminRoleID(t) // read before the hook: inside the transaction only tx may be used
			ran := f.changeInsideApproval(t, f.b.ID, func(tx storage.Storage) error { return tc.change(f, role, tx) })
			f.assertApprovalRefused(t, req, tc.want)
			assert.True(t, *ran, "the change never ran inside the approval transaction")
			ok, _ := f.approvalRows(t) // its DENIED row is TestMFAReset_InTxRefusal_LeavesDeniedRow's
			assert.Zero(t, ok, "a refused approval left a success row")
		})
	}
}

// The approval locks the requester, approver and target rows in ascending user-ID
// order whichever of the two admins approves, so two admins approving each other's
// requests at once cannot deadlock (Postgres would abort one with a deadlock error).
func TestMFAReset_ApprovalLocksUsersInIDOrder(t *testing.T) {
	f := newMFAResetFixture(t)
	req := f.request(t)
	var order []uint
	base := f.c.storage
	f.c.storage = hooked(base, &storeHooks{
		WrapTx: true,
		LockUserForUpdate: func(next storage.Storage, ctx context.Context, uid uint) (*models.User, error) {
			if next != base {
				order = append(order, uid)
			}
			return next.LockUserForUpdate(ctx, uid)
		},
	})
	t.Cleanup(func() { f.c.storage = base })

	_, err := f.c.ApproveMFAReset(context.Background(), f.b.ID, false, req.ID, f.code(t, f.b.ID))
	require.NoError(t, err)
	require.ElementsMatch(t, []uint{f.a.ID, f.b.ID, f.target.ID}, order, "the approval must lock requester, approver and target")
	assert.IsIncreasing(t, order, "row locks must be taken in ascending user-ID order")
}
