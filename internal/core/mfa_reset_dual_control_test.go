package core

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// REVFIX-3751-1: dual control needs two CURRENT, usable admins, and every rule the
// approval relies on holds on the row lock inside the approval's own transaction,
// not only in the reads before it.

// adminRoleID is the global-admin role the fixture's admins hold.
func (f *mfaResetFixture) adminRoleID(t *testing.T) uint {
	t.Helper()
	ids, err := f.st.GetUserRoleIDsAt(context.Background(), f.a.ID, storage.Scope{})
	require.NoError(t, err)
	require.NotEmpty(t, ids)
	return ids[0]
}

// assertApprovalRefused: B's approval of req fails with want, the request stays
// pending and the target keeps every factor.
func (f *mfaResetFixture) assertApprovalRefused(t *testing.T, req *models.MFAResetRequest, want error) {
	t.Helper()
	_, err := f.c.ApproveMFAReset(context.Background(), f.b.ID, false, req.ID, f.code(t, f.b.ID))
	require.ErrorIs(t, err, want)
	assert.Equal(t, models.MFAResetStatusPending, f.requestStatus(t, req.ID))
	assert.Zero(t, f.auditCount(t, EventMFAReset), "a refused approval reset the target")
	f.assertTargetIntact(t)
}

// A request whose requester was suspended or deactivated after opening it cannot be
// approved: the incident team suspending a compromised admin must not leave that
// admin's pending requests approvable by anyone else.
func TestMFAReset_RequesterNoLongerActive_ApprovalRefused(t *testing.T) {
	t.Run("suspended", func(t *testing.T) {
		f := newMFAResetFixture(t)
		req := f.request(t)
		require.NoError(t, f.c.SuspendUser(context.Background(), f.cAdmin.ID, f.a.ID))
		f.assertApprovalRefused(t, req, ErrMFAResetRequesterChanged)
	})
	t.Run("deactivated", func(t *testing.T) {
		f := newMFAResetFixture(t)
		req := f.request(t)
		u := f.reload(t, f.a.ID)
		u.IsActive = false
		_, err := f.st.UpdateUser(context.Background(), u)
		require.NoError(t, err)
		require.False(t, f.reload(t, f.a.ID).IsActive)
		f.assertApprovalRefused(t, req, ErrMFAResetRequesterChanged)
	})
	t.Run("deprovisioned", func(t *testing.T) {
		f := newMFAResetFixture(t)
		req := f.request(t)
		require.NoError(t, f.st.SetAccountState(context.Background(), f.a.ID, AccountDeprovisioned, f.now))
		f.assertApprovalRefused(t, req, ErrMFAResetRequesterChanged)
	})
	t.Run("lost the admin role", func(t *testing.T) {
		f := newMFAResetFixture(t)
		req := f.request(t)
		require.NoError(t, f.st.RemoveRole(context.Background(), f.a.ID, f.adminRoleID(t), storage.Scope{}))
		f.assertApprovalRefused(t, req, ErrMFAResetRequesterChanged)
	})
}

// changeInsideApproval wraps the core's storage so that change runs on the
// approval transaction's own handle right before the transaction locks user id:
// a change that committed after every pre-transaction read, which only a check on
// the row lock can see. It reports whether the change ran. change must use only
// the handle it is given (SQLite: the transaction holds the one connection).
func (f *mfaResetFixture) changeInsideApproval(t *testing.T, id uint, change func(tx storage.Storage) error) *bool {
	t.Helper()
	ran := new(bool)
	base := f.c.storage
	f.c.storage = hooked(base, &storeHooks{
		WrapTx: true,
		LockUserForUpdate: func(next storage.Storage, ctx context.Context, uid uint) (*models.User, error) {
			if uid == id && next != base && !*ran {
				*ran = true
				require.NoError(t, change(next))
			}
			return next.LockUserForUpdate(ctx, uid)
		},
	})
	t.Cleanup(func() { f.c.storage = base })
	return ran
}

// The target rules (local, active, not a global admin) are re-checked on the row
// lock inside the approval transaction, as the host command does.
func TestMFAReset_TargetChangedInsideApproval_Refused(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(f *mfaResetFixture, role uint, tx storage.Storage) error
		want   error
	}{
		{"promoted to global admin", func(f *mfaResetFixture, role uint, tx storage.Storage) error {
			return tx.AssignRole(context.Background(), f.target.ID, role, storage.Scope{})
		}, ErrMFAResetGlobalAdmin},
		{"suspended", func(f *mfaResetFixture, _ uint, tx storage.Storage) error {
			return tx.SetAccountState(context.Background(), f.target.ID, AccountSuspended, f.now)
		}, ErrMFAResetAccountBlocked},
		{"linked to an identity provider", func(f *mfaResetFixture, _ uint, tx storage.Storage) error {
			u, err := tx.GetUser(context.Background(), f.target.ID)
			if err != nil {
				return err
			}
			u.ExternalID = "okta|target"
			_, err = tx.UpdateUser(context.Background(), u)
			return err
		}, ErrMFAResetExternalIdentity},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newMFAResetFixture(t)
			req := f.request(t)
			role := f.adminRoleID(t) // read before the hook: inside the transaction only tx may be used
			ran := f.changeInsideApproval(t, f.target.ID, func(tx storage.Storage) error { return tc.change(f, role, tx) })
			f.assertApprovalRefused(t, req, tc.want)
			assert.True(t, *ran, "the change never ran inside the approval transaction")
		})
	}
}

// The requester rules (still a global admin, active, not login-blocked) are also
// re-checked inside the approval transaction.
func TestMFAReset_RequesterChangedInsideApproval_Refused(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(f *mfaResetFixture, role uint, tx storage.Storage) error
	}{
		{"suspended", func(f *mfaResetFixture, _ uint, tx storage.Storage) error {
			return tx.SetAccountState(context.Background(), f.a.ID, AccountSuspended, f.now)
		}},
		{"lost the admin role", func(f *mfaResetFixture, role uint, tx storage.Storage) error {
			return tx.RemoveRole(context.Background(), f.a.ID, role, storage.Scope{})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newMFAResetFixture(t)
			req := f.request(t)
			role := f.adminRoleID(t) // read before the hook: inside the transaction only tx may be used
			ran := f.changeInsideApproval(t, f.a.ID, func(tx storage.Storage) error { return tc.change(f, role, tx) })
			f.assertApprovalRefused(t, req, ErrMFAResetRequesterChanged)
			assert.True(t, *ran, "the change never ran inside the approval transaction")
		})
	}
}

// Changes between request and approval that the pre-transaction reads see.
func TestMFAReset_TargetChangedBeforeApproval_Refused(t *testing.T) {
	t.Run("suspended", func(t *testing.T) {
		f := newMFAResetFixture(t)
		req := f.request(t)
		require.NoError(t, f.c.SuspendUser(context.Background(), f.b.ID, f.target.ID))
		_, err := f.c.ApproveMFAReset(context.Background(), f.b.ID, false, req.ID, f.code(t, f.b.ID))
		require.ErrorIs(t, err, ErrMFAResetAccountBlocked)
		assert.Equal(t, models.MFAResetStatusPending, f.requestStatus(t, req.ID))
		assert.Zero(t, f.auditCount(t, EventMFAReset))
	})
	t.Run("promoted to global admin", func(t *testing.T) {
		f := newMFAResetFixture(t)
		req := f.request(t)
		require.NoError(t, f.st.AssignRole(context.Background(), f.target.ID, f.adminRoleID(t), storage.Scope{}))
		_, err := f.c.ApproveMFAReset(context.Background(), f.b.ID, false, req.ID, f.code(t, f.b.ID))
		require.ErrorIs(t, err, ErrMFAResetGlobalAdmin)
		assert.Equal(t, models.MFAResetStatusPending, f.requestStatus(t, req.ID))
		assert.Zero(t, f.auditCount(t, EventMFAReset))
	})
}

// The online path refuses an IdP-managed and a suspended target at request time,
// as the host command does.
func TestMFAReset_RequestRefusesExternalOrBlockedTarget(t *testing.T) {
	ctx := context.Background()
	t.Run("linked to an identity provider", func(t *testing.T) {
		f := newMFAResetFixture(t)
		u := f.reload(t, f.target.ID)
		u.ExternalID = "okta|target"
		_, err := f.st.UpdateUser(ctx, u)
		require.NoError(t, err)
		_, err = f.c.RequestMFAReset(ctx, f.a.ID, false, MFAResetRequestInput{User: "target", Reason: "x", VerifiedBy: "ticket", Code: f.code(t, f.a.ID)})
		require.ErrorIs(t, err, ErrMFAResetExternalIdentity)
		assert.Zero(t, f.auditCount(t, EventMFAResetRequested))
	})
	t.Run("suspended", func(t *testing.T) {
		f := newMFAResetFixture(t)
		require.NoError(t, f.c.SuspendUser(ctx, f.b.ID, f.target.ID))
		_, err := f.c.RequestMFAReset(ctx, f.a.ID, false, MFAResetRequestInput{User: "target", Reason: "x", VerifiedBy: "ticket", Code: f.code(t, f.a.ID)})
		require.ErrorIs(t, err, ErrMFAResetAccountBlocked)
		assert.Zero(t, f.auditCount(t, EventMFAResetRequested))
	})
}

// "Already pending" is decided inside the create transaction: a request for the same
// target that commits after the pre-transaction read (here: while the requester's
// code is being checked) still makes the second one fail, so at most one request
// per target is ever pending.
func TestMFAReset_ConcurrentRequestForSameTarget_OnlyOnePending(t *testing.T) {
	f := newMFAResetFixture(t)
	ctx := context.Background()
	base := f.c.storage
	raced := false
	f.c.storage = hooked(base, &storeHooks{
		MarkTOTPStepUsed: func(next storage.Storage, ctx context.Context, userID uint, step int64) (bool, error) {
			if userID == f.a.ID && !raced {
				raced = true
				_, err := base.CreateMFAResetRequest(ctx, &models.MFAResetRequest{
					TargetUserID: f.target.ID, RequestedBy: f.cAdmin.ID, Reason: "the other admin's request",
					VerifiedBy: "ticket", Status: models.MFAResetStatusPending, CreatedAt: f.now, ExpiresAt: f.now.Add(MFAResetRequestTTL),
				})
				require.NoError(t, err)
			}
			return next.MarkTOTPStepUsed(ctx, userID, step)
		},
	})
	t.Cleanup(func() { f.c.storage = base })

	_, err := f.c.RequestMFAReset(ctx, f.a.ID, false, MFAResetRequestInput{User: "target", Reason: "lost phone", VerifiedBy: "video", Code: f.code(t, f.a.ID)})
	require.True(t, raced, "the competing request was never inserted")
	require.ErrorIs(t, err, ErrMFAResetAlreadyPending)

	pending, err := f.st.ListMFAResetRequests(ctx, true)
	require.NoError(t, err)
	assert.Len(t, pending, 1, "two requests for one target are pending")
	assert.Zero(t, f.auditCount(t, EventMFAResetRequested))
}
