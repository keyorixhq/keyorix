package core_test

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/testhelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func seedPendingRequest(t *testing.T, h *testhelper.RBACTestHelper, requester uint) uint {
	req, err := h.Storage.CreateAccessRequest(context.Background(), &models.AccessRequest{
		ProjectID: 2, UserID: requester, SuggestedRole: "editor", State: "pending",
	})
	require.NoError(t, err)
	return req.ID
}

// With the default threshold (1), a single approval grants the role immediately.
func TestApprove_SingleControlDefault(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(&models.AccessRequest{}, &models.AccessRequestApproval{}, &models.AuditEvent{}))

	ctx := context.Background()
	h.CreateTestUser(t, "alice", 10)  // requester
	h.CreateTestUser(t, "admin1", 11) // approver
	reqID := seedPendingRequest(t, h, 10)

	req, err := h.CoreService.ApproveAccessRequestWithExpiry(ctx, 2, reqID, 11, "", 0)
	require.NoError(t, err)
	assert.Equal(t, "approved", req.State)

	ids, err := h.Storage.GetUserRoleIDsAt(ctx, 10, storage.Scope{ProjectID: 2})
	require.NoError(t, err)
	assert.Contains(t, ids, uint(3), "editor granted on the single approval")
}

// With a threshold of 2, the role is granted only after two distinct approvers;
// the requester can't approve, and an approver can't approve twice.
func TestApprove_DualControl(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(&models.AccessRequest{}, &models.AccessRequestApproval{}, &models.AuditEvent{}))

	ctx := context.Background()
	h.CreateTestUser(t, "alice", 10)  // requester
	h.CreateTestUser(t, "admin1", 11) // approver 1
	h.CreateTestUser(t, "admin2", 12) // approver 2
	h.CoreService.SetDualControlPolicy(2)
	reqID := seedPendingRequest(t, h, 10)

	// First approval: still pending, no grant yet.
	req, err := h.CoreService.ApproveAccessRequestWithExpiry(ctx, 2, reqID, 11, "", 0)
	require.NoError(t, err)
	assert.Equal(t, "pending", req.State)
	assert.Equal(t, 1, req.ApprovalsReceived)
	assert.Equal(t, 2, req.RequiredApprovals)
	ids, _ := h.Storage.GetUserRoleIDsAt(ctx, 10, storage.Scope{ProjectID: 2})
	assert.NotContains(t, ids, uint(3), "no grant before the threshold")

	// Same approver again → rejected.
	_, err = h.CoreService.ApproveAccessRequestWithExpiry(ctx, 2, reqID, 11, "", 0)
	require.Error(t, err)
	// The requester cannot approve their own request.
	_, err = h.CoreService.ApproveAccessRequestWithExpiry(ctx, 2, reqID, 10, "", 0)
	require.Error(t, err)

	// Second distinct approver reaches the threshold → granted.
	req, err = h.CoreService.ApproveAccessRequestWithExpiry(ctx, 2, reqID, 12, "", 0)
	require.NoError(t, err)
	assert.Equal(t, "approved", req.State)
	ids, _ = h.Storage.GetUserRoleIDsAt(ctx, 10, storage.Scope{ProjectID: 2})
	assert.Contains(t, ids, uint(3), "editor granted once two approvers signed off")
}

// The listing annotates a pending request with its M-of-K progress.
func TestListAccessRequests_AnnotatesProgress(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(&models.AccessRequest{}, &models.AccessRequestApproval{}, &models.AuditEvent{}))

	ctx := context.Background()
	h.CreateTestUser(t, "alice", 10)
	h.CreateTestUser(t, "admin1", 11)
	h.CoreService.SetDualControlPolicy(2)
	reqID := seedPendingRequest(t, h, 10)
	_, err := h.CoreService.ApproveAccessRequestWithExpiry(ctx, 2, reqID, 11, "", 0)
	require.NoError(t, err)

	list, err := h.CoreService.ListAccessRequests(ctx, 2)
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, "pending", list[0].State)
	assert.Equal(t, 1, list[0].ApprovalsReceived)
	assert.Equal(t, 2, list[0].RequiredApprovals)
}
