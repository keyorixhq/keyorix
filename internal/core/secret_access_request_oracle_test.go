package core

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
)

// AUTHZ-ORACLE-1 item 2: ApproveSecretAccessRequest / RejectSecretAccessRequest
// sit on routes with no permission gate, so their admin-authority check is the
// only authorization. It used to run after the kind, state, secret and expiry
// checks, so any signed-in user could read a request's existence, kind and state
// off the refusal, and approving an expired request wrote it to "expired" before
// the caller was authorized. A caller without authority now gets "access request
// not found" for every request ID, and nothing is written.
func TestSecretAccessRequestResolve_UnauthorizedCallerGetsIdenticalRefusal(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	secretID, requesterID, approverID, projectID := seedClassificationGateFixture(t, st, ClassificationRestricted)
	ctx := context.Background()

	pending, err := c.RequestSecretAccess(ctx, secretID, requesterID, "")
	require.NoError(t, err)
	roleReq, err := c.RequestProjectAccess(ctx, projectID, requesterID, "viewer", "")
	require.NoError(t, err)

	other, err := st.CreateUser(ctx, foldedTestUser(t, "requester-2", "requester-2@example.com"))
	require.NoError(t, err)
	viewer, err := st.GetRoleByName(ctx, "project_viewer")
	require.NoError(t, err)
	require.NoError(t, st.AssignRole(ctx, other.ID, viewer.ID, storage.Scope{ProjectID: projectID}))
	approved, err := c.RequestSecretAccess(ctx, secretID, other.ID, "")
	require.NoError(t, err)
	_, err = c.ApproveSecretAccessRequest(ctx, approved.ID, approverID)
	require.NoError(t, err)

	third, err := st.CreateUser(ctx, foldedTestUser(t, "requester-3", "requester-3@example.com"))
	require.NoError(t, err)
	require.NoError(t, st.AssignRole(ctx, third.ID, viewer.ID, storage.Scope{ProjectID: projectID}))
	expired, err := c.RequestSecretAccess(ctx, secretID, third.ID, "")
	require.NoError(t, err)
	past := time.Now().Add(-time.Hour)
	expired.ExpiresAt = &past
	ok, err := st.UpdateAccessRequest(ctx, expired)
	require.NoError(t, err)
	require.True(t, ok)

	nonAdmin, err := st.CreateUser(ctx, foldedTestUser(t, "nonadmin-oracle", "nonadmin-oracle@example.com"))
	require.NoError(t, err)

	ids := map[string]uint{
		"missing":      999999,
		"pending":      pending.ID,
		"project/role": roleReq.ID,
		"approved":     approved.ID,
		"expired":      expired.ID,
	}
	resolve := map[string]func(id, actor uint) error{
		"approve": func(id, actor uint) error { _, err := c.ApproveSecretAccessRequest(ctx, id, actor); return err },
		"reject": func(id, actor uint) error {
			_, err := c.RejectSecretAccessRequest(ctx, id, actor, 0, "no")
			return err
		},
	}
	for op, fn := range resolve {
		for _, actor := range []uint{nonAdmin.ID, requesterID} {
			for label, id := range ids {
				err := fn(id, actor)
				require.Error(t, err, "%s %s by %d", op, label, actor)
				assert.Equal(t, "access request not found", err.Error(), "%s %s by %d", op, label, actor)
			}
		}
	}

	// Nothing was written by the refused calls.
	for label, want := range map[string]string{
		"pending": AccessRequestPending, "expired": AccessRequestPending, "approved": AccessRequestApproved,
	} {
		got, err := st.GetAccessRequest(ctx, ids[label])
		require.NoError(t, err)
		assert.Equal(t, want, got.State, "%s request changed state under an unauthorized caller", label)
	}

	// An admin still gets the specific answers.
	_, err = c.ApproveSecretAccessRequest(ctx, roleReq.ID, approverID)
	assert.ErrorContains(t, err, "not a secret-scoped")
	_, err = c.ApproveSecretAccessRequest(ctx, approved.ID, approverID)
	assert.ErrorContains(t, err, "only a pending request")
	_, err = c.ApproveSecretAccessRequest(ctx, expired.ID, approverID)
	assert.ErrorContains(t, err, "has expired")
	_, err = c.ApproveSecretAccessRequest(ctx, 999999, approverID)
	assert.EqualError(t, err, "access request not found")
}
