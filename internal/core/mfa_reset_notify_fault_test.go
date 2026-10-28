package core

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// MFA-RESET-TESTS-1 item 3 (faultops sweep findings).
//
// The admin notice after an MFA reset step is best effort and runs AFTER the commit.
// The sweep (server/faultops, TestMFAResetOpsFaultSweep) found that a PANIC in the
// recipient lookup (ListUsers, then the per-user role reads) escaped notifyMFAResetAdmins:
// the transport turned it into a 500 for a step that had already committed, and for an
// approval that lost the one-time password, which exists only in that response. A
// returned error was already logged and swallowed; a panic must be too.

// faultAfterCommit makes the recipient lookup fail with panicking (true) or an error
// (false). ListUsers is called only by that lookup in the approve and cancel paths
// (the approver count that also lists users is in RequestMFAReset).
func (f *mfaResetFixture) faultRecipientLookup(t *testing.T, panicking bool) {
	t.Helper()
	base := f.c.storage
	f.c.storage = hooked(base, &storeHooks{
		WrapTx: true,
		ListUsers: func(next storage.Storage, ctx context.Context, filter *storage.UserFilter) ([]*models.User, int64, error) {
			if panicking {
				panic("injected: recipient lookup")
			}
			return nil, 0, errors.New("injected: recipient lookup")
		},
	})
	t.Cleanup(func() { f.c.storage = base })
}

func TestMFAReset_RecipientFaultAfterCommit_IsBestEffort(t *testing.T) {
	for _, panicking := range []bool{false, true} {
		name := map[bool]string{false: "error", true: "panic"}[panicking]
		t.Run("approve/"+name, func(t *testing.T) {
			f := newMFAResetFixture(t)
			req := f.request(t)
			f.faultRecipientLookup(t, panicking)
			res, err := f.c.ApproveMFAReset(context.Background(), f.b.ID, false, req.ID, f.code(t, f.b.ID))
			require.NoError(t, err, "a committed approval was reported as failed")
			require.NotNil(t, res)
			assert.NotEmpty(t, res.OneTimePassword, "the one-time password exists only in this response")
			assert.Equal(t, models.MFAResetStatusApproved, f.requestStatus(t, req.ID))
			assert.True(t, f.reload(t, f.target.ID).MFAEnrolmentRequired)
		})
		t.Run("cancel/"+name, func(t *testing.T) {
			f := newMFAResetFixture(t)
			req := f.request(t)
			f.faultRecipientLookup(t, panicking)
			require.NoError(t, f.c.CancelMFAReset(context.Background(), f.b.ID, false, req.ID),
				"a committed cancellation was reported as failed")
			assert.Equal(t, models.MFAResetStatusCancelled, f.requestStatus(t, req.ID))
		})
	}
}

// The reads BEFORE the commit are the authorization decision and fail closed: a fault
// on the actor's admin check refuses the cancellation and leaves the request pending.
// This is what makes the later, swallowed recipient reads non-load-bearing.
func TestMFAReset_ActorAdminCheckFault_FailsClosed(t *testing.T) {
	f := newMFAResetFixture(t)
	req := f.request(t)
	base := f.c.storage
	f.c.storage = hooked(base, &storeHooks{
		WrapTx: true,
		GetUserRoleIDsAt: func(next storage.Storage, ctx context.Context, userID uint, scope storage.Scope) ([]uint, error) {
			return nil, errors.New("injected: role read")
		},
	})
	t.Cleanup(func() { f.c.storage = base })
	err := f.c.CancelMFAReset(context.Background(), f.b.ID, false, req.ID)
	require.Error(t, err)
	assert.Equal(t, models.MFAResetStatusPending, f.requestStatus(t, req.ID), "the request was cancelled despite the failed admin check")
}
