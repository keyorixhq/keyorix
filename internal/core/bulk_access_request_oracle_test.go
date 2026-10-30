package core

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// AUTHZ-ORACLE-1 item 2: the bulk approve/reject routes are gated on roles.assign
// anywhere, and the per-item check is roles.assign at the request's own project.
// An approver who holds it only in project A must get the same per-item error for
// a request in project B as for an ID that does not exist; before the fix the
// first said "permission denied" and the second "access request not found", so
// the batch answer listed which IDs exist in projects the approver cannot see.
func TestBulkAccessRequests_OtherProjectRequestAnswersLikeMissingID(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()

	projA, err := st.CreateProject(ctx, &models.Project{Name: "bulk-oracle-a"})
	require.NoError(t, err)
	projB, err := st.CreateProject(ctx, &models.Project{Name: "bulk-oracle-b"})
	require.NoError(t, err)

	approver, err := st.CreateUser(ctx, foldedTestUser(t, "bulk-oracle-approver", "bulk-oracle-approver@example.com"))
	require.NoError(t, err)
	admin, err := st.GetRoleByName(ctx, "admin")
	require.NoError(t, err)
	require.NoError(t, st.AssignRole(ctx, approver.ID, admin.ID, storage.Scope{ProjectID: projA.ID}))

	requester, err := st.CreateUser(ctx, foldedTestUser(t, "bulk-oracle-requester", "bulk-oracle-requester@example.com"))
	require.NoError(t, err)
	inB, err := c.RequestProjectAccess(ctx, projB.ID, requester.ID, "viewer", "")
	require.NoError(t, err)
	const missing = uint(999999)

	approveRes, err := c.BulkApproveAccessRequests(ctx, []uint{inB.ID, missing}, approver.ID, 0)
	require.NoError(t, err)
	require.Empty(t, approveRes.Approved)
	require.Len(t, approveRes.Failed, 2)
	assert.Equal(t, approveRes.Failed[1].Error, approveRes.Failed[0].Error,
		"a request in another project must answer like a missing ID: %+v", approveRes.Failed)

	rejectRes, err := c.BulkRejectAccessRequests(ctx, []uint{inB.ID, missing}, approver.ID, 0, "no")
	require.NoError(t, err)
	require.Empty(t, rejectRes.Rejected)
	require.Len(t, rejectRes.Failed, 2)
	assert.Equal(t, rejectRes.Failed[1].Error, rejectRes.Failed[0].Error,
		"a request in another project must answer like a missing ID: %+v", rejectRes.Failed)

	got, err := st.GetAccessRequest(ctx, inB.ID)
	require.NoError(t, err)
	assert.Equal(t, AccessRequestPending, got.State, "the refused request must stay pending")
}
