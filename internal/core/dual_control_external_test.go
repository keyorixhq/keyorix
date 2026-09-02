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
	// #93/#107/#141: the approver must themselves hold every permission of the
	// role being granted (editor: secrets.read/write, users.read) — grant them
	// "admin" globally so the ceiling check's admin bypass applies.
	h.AssignUserRole(t, 11, 2, nil)
	reqID := seedPendingRequest(t, h, 10)

	req, err := h.CoreService.ApproveAccessRequestWithExpiry(ctx, 2, reqID, 11, 0, "", 0)
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
	// #93/#107/#141: the threshold-crossing approver must themselves hold every
	// permission of the role being granted — grant both "admin" globally so the
	// ceiling check's admin bypass applies regardless of which one crosses it.
	h.AssignUserRole(t, 11, 2, nil)
	h.AssignUserRole(t, 12, 2, nil)
	h.CoreService.SetDualControlPolicy(2)
	reqID := seedPendingRequest(t, h, 10)

	// First approval: still pending, no grant yet.
	req, err := h.CoreService.ApproveAccessRequestWithExpiry(ctx, 2, reqID, 11, 0, "", 0)
	require.NoError(t, err)
	assert.Equal(t, "pending", req.State)
	assert.Equal(t, 1, req.ApprovalsReceived)
	assert.Equal(t, 2, req.RequiredApprovals)
	ids, _ := h.Storage.GetUserRoleIDsAt(ctx, 10, storage.Scope{ProjectID: 2})
	assert.NotContains(t, ids, uint(3), "no grant before the threshold")

	// Same approver again → rejected.
	_, err = h.CoreService.ApproveAccessRequestWithExpiry(ctx, 2, reqID, 11, 0, "", 0)
	require.Error(t, err)
	// The requester cannot approve their own request.
	_, err = h.CoreService.ApproveAccessRequestWithExpiry(ctx, 2, reqID, 10, 0, "", 0)
	require.Error(t, err)

	// Second distinct approver reaches the threshold → granted.
	req, err = h.CoreService.ApproveAccessRequestWithExpiry(ctx, 2, reqID, 12, 0, "", 0)
	require.NoError(t, err)
	assert.Equal(t, "approved", req.State)
	ids, _ = h.Storage.GetUserRoleIDsAt(ctx, 10, storage.Scope{ProjectID: 2})
	assert.Contains(t, ids, uint(3), "editor granted once two approvers signed off")
}

// Regression: under K-of-N control the threshold-crossing approver must not be able to
// substitute a higher role than the other approvers consented to — the granted role is
// locked to the request's suggested_role. Before the fix, only the last approver's
// granted_role was used, so one approver could escalate after K-1 others signed off.
func TestApprove_DualControl_RoleLockedToRequest(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(&models.AccessRequest{}, &models.AccessRequestApproval{}, &models.AuditEvent{}))

	ctx := context.Background()
	h.CreateTestUser(t, "alice", 10)  // requester — asks for "editor"
	h.CreateTestUser(t, "admin1", 11) // approver 1
	h.CreateTestUser(t, "admin2", 12) // approver 2 (would-be escalator)
	// #93/#107/#141: the threshold-crossing approver must themselves hold every
	// permission of the role being granted — grant both "admin" globally so the
	// ceiling check's admin bypass applies (independent of the dual-control
	// role-lock this test actually exercises).
	h.AssignUserRole(t, 11, 2, nil)
	h.AssignUserRole(t, 12, 2, nil)
	h.CoreService.SetDualControlPolicy(2)
	reqID := seedPendingRequest(t, h, 10) // SuggestedRole "editor"

	// First approver signs off on the request as-stated.
	_, err := h.CoreService.ApproveAccessRequestWithExpiry(ctx, 2, reqID, 11, 0, "", 0)
	require.NoError(t, err)

	// The second (threshold-crossing) approver tries to escalate to a higher EXISTING
	// role ("admin", id 2) than the requested "editor". Without the fix this would
	// succeed (the last approver's role wins); the request must instead be rejected.
	_, err = h.CoreService.ApproveAccessRequestWithExpiry(ctx, 2, reqID, 12, 0, "admin", 0)
	require.Error(t, err, "an approver must not substitute a different role under dual control")
	ids, _ := h.Storage.GetUserRoleIDsAt(ctx, 10, storage.Scope{ProjectID: 2})
	assert.NotContains(t, ids, uint(2), "the escalated role (admin) must not be granted")

	// Approving the request as-stated (matching role) grants exactly the requested role.
	req, err := h.CoreService.ApproveAccessRequestWithExpiry(ctx, 2, reqID, 12, 0, "editor", 0)
	require.NoError(t, err)
	assert.Equal(t, "approved", req.State)
	assert.Equal(t, "editor", req.GrantedRole)
	ids, _ = h.Storage.GetUserRoleIDsAt(ctx, 10, storage.Scope{ProjectID: 2})
	assert.Contains(t, ids, uint(3), "the requested role (editor) is granted, not the escalated one")
}

// A multi-approver request with no role stated at request time is rejected — there is
// nothing for the approvers to consent to in common.
func TestApprove_DualControl_RequiresRoleAtRequestTime(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(&models.AccessRequest{}, &models.AccessRequestApproval{}, &models.AuditEvent{}))

	ctx := context.Background()
	h.CreateTestUser(t, "alice", 10)
	h.CreateTestUser(t, "admin1", 11)
	h.CoreService.SetDualControlPolicy(2)
	req, err := h.Storage.CreateAccessRequest(ctx, &models.AccessRequest{
		ProjectID: 2, UserID: 10, SuggestedRole: "", State: "pending",
	})
	require.NoError(t, err)

	// Even with a role supplied by the approver, multi-party control won't accept a
	// request that named no role for everyone to review.
	_, err = h.CoreService.ApproveAccessRequestWithExpiry(ctx, 2, req.ID, 11, 0, "editor", 0)
	require.Error(t, err)
}

// #1573: two DISTINCT machine identities approving under K=2 dual control must
// both count — before the fix, ApproverID is 0 for every machine caller
// (ADR-030, no UserID), so hasAlreadyApproved's ApproverID-only comparison
// treated the second machine's genuinely distinct approval as a duplicate of
// the first, and the threshold could never be reached via machine approvers.
// Exploit-shaped: two different approverMachineID values, both approverID=0
// (the real production shape).
//
// Target role is a fresh permission-less role, not "editor": FIX-1
// (requireGranterHoldsRolePermissions's actorID==0 fast-path no longer trusts
// a machine caller unconditionally) means the threshold-crossing grant now
// runs the real ceiling check for a machine approver too — and that check
// resolves permissions via c.Authorize(ctx, actorID, ...), which is keyed on
// UserID (always 0 for a machine caller), not the machine's real principal ID
// via AuthorizePrincipal/GetMachineRoleIDsAt. A machine actor therefore cannot
// currently satisfy the ceiling for any role bundling a real permission,
// including one it may legitimately hold via machine_identity_roles — a
// separate, pre-existing gap in requireGranterHoldsRolePermissions (already
// present for actorIsMachine=true on AssignUserRoleWithExpiry since #1542),
// not something this test is exercising. Using a permission-less role isolates
// this test to its actual subject — the distinct-approver dedup logic — same
// as TestAssignUserRole_EmptyRoleAlwaysGrantable's pattern for the identical
// "nothing to ceiling-check" case.
func TestApprove_DualControl_TwoDistinctMachineApprovers(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(&models.AccessRequest{}, &models.AccessRequestApproval{}, &models.AuditEvent{}))
	h.CreateTestRole(t, "empty-role", "no bundled permissions", 99)

	ctx := context.Background()
	h.CreateTestUser(t, "alice", 10) // requester (human — RequestProjectAccess requires nonzero UserID)
	h.CoreService.SetDualControlPolicy(2)
	req0, err := h.Storage.CreateAccessRequest(ctx, &models.AccessRequest{
		ProjectID: 2, UserID: 10, SuggestedRole: "empty-role", State: "pending",
	})
	require.NoError(t, err)
	reqID := req0.ID

	// Machine 101 approves: still pending, no grant yet.
	req, err := h.CoreService.ApproveAccessRequestWithExpiry(ctx, 2, reqID, 0, 101, "", 0)
	require.NoError(t, err, "the first machine approver must succeed")
	assert.Equal(t, "pending", req.State)
	assert.Equal(t, 1, req.ApprovalsReceived)

	// Machine 202 — a GENUINELY DIFFERENT machine, same approverID (0) — approves next.
	// Before the fix this was rejected as "you have already approved this request".
	req, err = h.CoreService.ApproveAccessRequestWithExpiry(ctx, 2, reqID, 0, 202, "", 0)
	require.NoError(t, err, "a second, distinct machine approver must not be treated as a duplicate of the first")
	assert.Equal(t, "approved", req.State)
	ids, _ := h.Storage.GetUserRoleIDsAt(ctx, 10, storage.Scope{ProjectID: 2})
	assert.Contains(t, ids, uint(99), "empty-role granted once two distinct machine approvers signed off")
}

// Positive control: dual control must still reject a genuine duplicate — the
// SAME machine identity attempting to approve twice. The fix must narrow the
// false-positive (two different machines colliding on ApproverID=0) without
// widening a false-negative (the same machine approving twice).
//
// Target role is a fresh permission-less role, not "editor" (seedPendingRequest's
// default) — see TestApprove_DualControl_TwoDistinctMachineApprovers's comment:
// a machine approver cannot currently satisfy requireGranterHoldsRolePermissions
// for any role bundling a real permission (a separate, pre-existing gap, not
// something this test exercises). Using a permission-less role isolates this
// test to its actual subject — same-machine dedup.
func TestApprove_DualControl_SameMachineApproverTwiceRejected(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(&models.AccessRequest{}, &models.AccessRequestApproval{}, &models.AuditEvent{}))
	h.CreateTestRole(t, "empty-role", "no bundled permissions", 99)

	ctx := context.Background()
	h.CreateTestUser(t, "alice", 10)
	h.CoreService.SetDualControlPolicy(2)
	req0, err := h.Storage.CreateAccessRequest(ctx, &models.AccessRequest{
		ProjectID: 2, UserID: 10, SuggestedRole: "empty-role", State: "pending",
	})
	require.NoError(t, err)
	reqID := req0.ID

	req, err := h.CoreService.ApproveAccessRequestWithExpiry(ctx, 2, reqID, 0, 101, "", 0)
	require.NoError(t, err)
	assert.Equal(t, "pending", req.State)

	_, err = h.CoreService.ApproveAccessRequestWithExpiry(ctx, 2, reqID, 0, 101, "", 0)
	require.Error(t, err, "the same machine approving twice must still be rejected as a duplicate")
}

// The listing annotates a pending request with its M-of-K progress.
func TestListAccessRequests_AnnotatesProgress(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(&models.AccessRequest{}, &models.AccessRequestApproval{}, &models.AuditEvent{}))

	ctx := context.Background()
	h.CreateTestUser(t, "alice", 10)
	h.CreateTestUser(t, "admin1", 11)
	// #93/#107/#141: the approver must themselves hold every permission of the
	// role being granted (editor: secrets.read/write, users.read) — grant them
	// "admin" globally so the ceiling check's admin bypass applies.
	h.AssignUserRole(t, 11, 2, nil)
	h.CoreService.SetDualControlPolicy(2)
	reqID := seedPendingRequest(t, h, 10)
	_, err := h.CoreService.ApproveAccessRequestWithExpiry(ctx, 2, reqID, 11, 0, "", 0)
	require.NoError(t, err)

	list, err := h.CoreService.ListAccessRequests(ctx, 2)
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, "pending", list[0].State)
	assert.Equal(t, 1, list[0].ApprovalsReceived)
	assert.Equal(t, 2, list[0].RequiredApprovals)
}
