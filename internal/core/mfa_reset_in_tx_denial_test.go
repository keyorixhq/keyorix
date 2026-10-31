package core

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// MFA-RESET-TAILS-2 item 2 (REVIEW-3838-DEEP-1 L2): an approval refused INSIDE the
// approval transaction (the request decided meanwhile, the approver, requester or
// target changed on the row lock) leaves a DENIED mfa.reset_approved row, as the
// same refusals before the transaction do (TestMFAReset_PreTxRefusal_LeavesDeniedRow).
// The row is written after the rollback: on the transaction handle it would roll
// back with the approval.

// approvalRows counts the mfa.reset_approved rows by outcome.
func (f *mfaResetFixture) approvalRows(t *testing.T) (succeeded, denied int) {
	t.Helper()
	logs, _, err := f.st.GetAuditLogs(context.Background(), &storage.AuditFilter{Actions: []string{EventMFAResetApproved}})
	require.NoError(t, err)
	for _, l := range logs {
		if l.Success != nil && !*l.Success {
			denied++
		} else {
			succeeded++
		}
	}
	return succeeded, denied
}

// assertInTxRefusalAudited: B's approval is refused with want, the request stays
// pending, the target keeps every factor, and exactly one DENIED row (and no
// success row) was added.
func (f *mfaResetFixture) assertInTxRefusalAudited(t *testing.T, req *models.MFAResetRequest, want error) {
	t.Helper()
	okBefore, deniedBefore := f.approvalRows(t)
	f.assertApprovalRefused(t, req, want)
	okAfter, deniedAfter := f.approvalRows(t)
	assert.Equal(t, okBefore, okAfter, "a refused approval left a success row")
	assert.Equal(t, deniedBefore+1, deniedAfter, "a refusal inside the approval transaction must leave one DENIED row")
}

func TestMFAReset_InTxRefusal_LeavesDeniedRow(t *testing.T) {
	type change func(f *mfaResetFixture, role uint, tx storage.Storage) error
	for _, tc := range []struct {
		name   string
		on     func(f *mfaResetFixture) uint // whose row lock the change runs before
		change change
		want   error
	}{
		{"approver suspended", func(f *mfaResetFixture) uint { return f.b.ID }, func(f *mfaResetFixture, _ uint, tx storage.Storage) error {
			return tx.SetAccountState(context.Background(), f.b.ID, AccountSuspended, f.now)
		}, ErrMFAResetAdminRequired},
		{"approver lost the admin role", func(f *mfaResetFixture) uint { return f.b.ID }, func(f *mfaResetFixture, role uint, tx storage.Storage) error {
			return tx.RemoveRole(context.Background(), f.b.ID, role, storage.Scope{})
		}, ErrMFAResetAdminRequired},
		{"approver lost the second factor", func(f *mfaResetFixture) uint { return f.b.ID }, func(f *mfaResetFixture, _ uint, tx storage.Storage) error {
			return tx.SetUserMFAEnabled(context.Background(), f.b.ID, false)
		}, ErrMFAResetActorNeedsMFA},
		{"requester suspended", func(f *mfaResetFixture) uint { return f.a.ID }, func(f *mfaResetFixture, _ uint, tx storage.Storage) error {
			return tx.SetAccountState(context.Background(), f.a.ID, AccountSuspended, f.now)
		}, ErrMFAResetRequesterChanged},
		{"target promoted to global admin", func(f *mfaResetFixture) uint { return f.target.ID }, func(f *mfaResetFixture, role uint, tx storage.Storage) error {
			return tx.AssignRole(context.Background(), f.target.ID, role, storage.Scope{})
		}, ErrMFAResetGlobalAdmin},
		{"target suspended", func(f *mfaResetFixture) uint { return f.target.ID }, func(f *mfaResetFixture, _ uint, tx storage.Storage) error {
			return tx.SetAccountState(context.Background(), f.target.ID, AccountSuspended, f.now)
		}, ErrMFAResetAccountBlocked},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newMFAResetFixture(t)
			req := f.request(t)
			role := f.adminRoleID(t) // read before the hook: inside the transaction only tx may be used
			ran := f.changeInsideApproval(t, tc.on(f), func(tx storage.Storage) error { return tc.change(f, role, tx) })
			f.assertInTxRefusalAudited(t, req, tc.want)
			assert.True(t, *ran, "the change never ran inside the approval transaction")
		})
	}
}

// The request is decided by someone else after the pre-transaction status read:
// the conditional decision matches no row and the approval is refused. The
// competing cancellation runs on the approval's own handle, so it rolls back with
// it and the request is still pending afterwards.
func TestMFAReset_InTxRefusal_RequestDecidedMeanwhile_LeavesDeniedRow(t *testing.T) {
	f := newMFAResetFixture(t)
	req := f.request(t)
	base := f.c.storage
	ran := false
	f.c.storage = hooked(base, &storeHooks{
		WrapTx: true,
		DecideMFAResetRequestIfPending: func(next storage.Storage, ctx context.Context, id uint, status string, decidedBy uint, now time.Time) (bool, error) {
			if next != base && !ran {
				ran = true
				matched, err := next.DecideMFAResetRequestIfPending(ctx, id, models.MFAResetStatusCancelled, f.cAdmin.ID, now)
				require.NoError(t, err)
				require.True(t, matched)
			}
			return next.DecideMFAResetRequestIfPending(ctx, id, status, decidedBy, now)
		},
	})
	t.Cleanup(func() { f.c.storage = base })

	f.assertInTxRefusalAudited(t, req, ErrMFAResetRequestDecided)
	assert.True(t, ran, "the competing decision never ran inside the approval transaction")
}

// Calibration: a refusal BEFORE the transaction still leaves exactly one DENIED
// row (the in-transaction path must not add a second), and a successful approval
// leaves none.
func TestMFAReset_InTxRefusal_Calibration(t *testing.T) {
	t.Run("self-approval before the transaction", func(t *testing.T) {
		f := newMFAResetFixture(t)
		req := f.request(t)
		_, deniedBefore := f.approvalRows(t)
		_, err := f.c.ApproveMFAReset(context.Background(), f.a.ID, false, req.ID, f.code(t, f.a.ID))
		require.ErrorIs(t, err, ErrMFAResetSelfApproval)
		_, deniedAfter := f.approvalRows(t)
		assert.Equal(t, deniedBefore+1, deniedAfter)
	})
	t.Run("successful approval", func(t *testing.T) {
		f := newMFAResetFixture(t)
		req := f.request(t)
		_, err := f.c.ApproveMFAReset(context.Background(), f.b.ID, false, req.ID, f.code(t, f.b.ID))
		require.NoError(t, err)
		ok, denied := f.approvalRows(t)
		assert.Equal(t, 1, ok)
		assert.Zero(t, denied)
	})
}
