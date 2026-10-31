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

// REVIEW-3860-DEEP-1 L1: the pre-transaction twins of TestMFAReset_InTxRefusal_*.
// The same refusals (request expired, requester changed, target changed, approver
// without a second factor), committed BEFORE the approval starts, also leave
// exactly one DENIED mfa.reset_approved row and no success row. Without them a
// suspension or promotion got a DENIED row only if it landed inside the short
// window of the approval transaction.
func TestMFAReset_PreTxRefusal_LeavesDeniedRow(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(t *testing.T, f *mfaResetFixture)
		want   error
	}{
		{"request expired", func(_ *testing.T, f *mfaResetFixture) {
			f.now = f.now.Add(MFAResetRequestTTL + time.Minute)
		}, ErrMFAResetRequestExpired},
		{"requester suspended", func(t *testing.T, f *mfaResetFixture) {
			require.NoError(t, f.c.SuspendUser(context.Background(), f.cAdmin.ID, f.a.ID))
		}, ErrMFAResetRequesterChanged},
		{"requester lost the admin role", func(t *testing.T, f *mfaResetFixture) {
			require.NoError(t, f.st.RemoveRole(context.Background(), f.a.ID, f.adminRoleID(t), storage.Scope{}))
		}, ErrMFAResetRequesterChanged},
		{"target suspended", func(t *testing.T, f *mfaResetFixture) {
			require.NoError(t, f.c.SuspendUser(context.Background(), f.cAdmin.ID, f.target.ID))
		}, ErrMFAResetAccountBlocked},
		{"target promoted to global admin", func(t *testing.T, f *mfaResetFixture) {
			require.NoError(t, f.st.AssignRole(context.Background(), f.target.ID, f.adminRoleID(t), storage.Scope{}))
		}, ErrMFAResetGlobalAdmin},
		{"target linked to an IdP", func(t *testing.T, f *mfaResetFixture) {
			u := f.reload(t, f.target.ID)
			u.ExternalID = "okta|target"
			_, err := f.st.UpdateUser(context.Background(), u)
			require.NoError(t, err)
		}, ErrMFAResetExternalIdentity},
		{"approver lost the second factor", func(t *testing.T, f *mfaResetFixture) {
			require.NoError(t, f.st.SetUserMFAEnabled(context.Background(), f.b.ID, false))
		}, ErrMFAResetActorNeedsMFA},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newMFAResetFixture(t)
			req := f.request(t)
			tc.change(t, f)
			okBefore, deniedBefore := f.approvalRows(t)
			_, err := f.c.ApproveMFAReset(context.Background(), f.b.ID, false, req.ID, f.code(t, f.b.ID))
			require.ErrorIs(t, err, tc.want)
			assert.Equal(t, models.MFAResetStatusPending, f.requestStatus(t, req.ID))
			assert.Zero(t, f.auditCount(t, EventMFAReset), "a refused approval reset the target")
			okAfter, deniedAfter := f.approvalRows(t)
			assert.Equal(t, okBefore, okAfter, "a refused approval left a success row")
			assert.Equal(t, deniedBefore+1, deniedAfter, "a refusal before the approval transaction must leave one DENIED row")
		})
	}
}
