// bulk_access_request_machine_actor_test.go — INV-CORE-14 (#2495).
//
// BulkApproveAccessRequests' own doc comment claims it "delegates to the
// existing ApproveAccessRequest per item so all invariants (state check,
// self-approval guard, dual-control, role validation, project liveness,
// privilege ceiling) are enforced exactly once." For one dimension that was
// false: it dropped the approver's MACHINE identity on the floor.
//
// #1573 made the single-request approval path machine-aware end to end — the
// HTTP handler derives approverMachineID from actor.MachineIdentityID, which
// drives WithSelfMachineGranter, the real actorIsMachine value for
// requireGranterHoldsRolePermissions, the distinct-approver tuple in
// hasAlreadyApproved, and the ApproverMachineIdentityID/
// ResolvedByMachineIdentityID audit columns. The bulk path was never updated.
// It called the 4-argument ApproveAccessRequest wrapper, which hardcodes
// approverMachineID=0, so for a machine caller:
//
//  1. The escalation-by-proxy ceiling was handed actorIsMachine=false while
//     approverID was 0 (every machine caller's UserID, ADR-030) — exactly the
//     (actorID==0 && !actorIsMachine) "trusted local CLI / system pseudo-actor"
//     exemption at the top of requireGranterHoldsRolePermissions, which returns
//     nil immediately. The whole ceiling was skipped.
//  2. The per-item authorization used the user-only Authorize against
//     approverID=0, which no user row can ever satisfy, so EVERY item failed
//     "permission denied" — the feature did not work for machine identities at
//     all, and that accident is the only thing that kept (1) from being live.
//  3. ApproverMachineIdentityID/ResolvedByMachineIdentityID were recorded as 0,
//     losing the attribution #1573 added, and two distinct machine approvers
//     collided as one in hasAlreadyApproved (#1573's own defect, reintroduced
//     on this path).
//
// The pairing below is deliberate, and neither half is sufficient alone:
// TestBulkApprove_MachineApproverHoldingEveryPermission_Succeeds makes the path
// genuinely reachable by a machine actor (red before the fix: "permission
// denied"), and TestBulkApprove_MachineApproverMissingPermission_RefusedByCeiling
// asserts the ceiling then actually applies on it. Without the first, the second
// would pass for the wrong reason — the accidental gate in (2) refuses
// everything, including what the ceiling should have refused, which is
// indistinguishable from the ceiling working.
package core_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/testhelper"
)

const (
	// Seeded by RBACTestHelper: role 2 "admin" bundles roles.assign plus every
	// permission "editor" (role 3) bundles, so a machine granted it clears the
	// ceiling for an editor grant. Role 3 "editor" bundles secrets.read,
	// secrets.write and users.read but NOT roles.assign.
	bulkAdminRoleID  = uint(2)
	bulkEditorRoleID = uint(3)
	// Machine identity IDs. No MachineIdentity row is needed — the ceiling
	// resolves a machine's authority through machine_identity_roles
	// (GetMachineRoleIDsAt), the same shape dual_control_external_test.go uses.
	bulkMachineFullID    = uint(101)
	bulkMachinePartialID = uint(202)
	bulkRequesterID      = uint(10)
	bulkProjectID        = uint(2)
)

// newBulkMachineApproverWorld builds a real-storage install with one pending
// access request (project 2, requester 10, suggested role "editor") and returns
// the helper plus the request ID.
func newBulkMachineApproverWorld(t *testing.T) (*testhelper.RBACTestHelper, uint) {
	t.Helper()
	h := testhelper.NewRBACTestHelper(t)
	t.Cleanup(h.Cleanup)
	require.NoError(t, h.DB.AutoMigrate(&models.AccessRequest{}, &models.AccessRequestApproval{}, &models.AuditEvent{}))

	ctx := context.Background()
	// The requester is a human: RequestProjectAccess requires a nonzero UserID,
	// and the maker-cannot-be-checker guard compares approverID to req.UserID.
	h.CreateTestUser(t, "alice", bulkRequesterID)
	req, err := h.Storage.CreateAccessRequest(ctx, &models.AccessRequest{
		ProjectID: bulkProjectID, UserID: bulkRequesterID, SuggestedRole: "editor", State: "pending",
	})
	require.NoError(t, err)
	return h, req.ID
}

// A machine identity holding roles.assign AND every permission the granted role
// bundles must be able to bulk-approve. Before #2495 the bulk path authorized
// each item with the user-only Authorize against approverID=0 — a machine
// caller's UserID — which no role resolution can satisfy, so this returned
// "permission denied" for every item and the machine-approver feature the
// single-request path already supports was unreachable in bulk.
func TestBulkApprove_MachineApproverHoldingEveryPermission_Succeeds(t *testing.T) {
	t.Parallel()
	h, reqID := newBulkMachineApproverWorld(t)
	ctx := context.Background()

	require.NoError(t, h.Storage.AssignMachineRole(ctx, bulkMachineFullID, bulkAdminRoleID,
		storage.Scope{ProjectID: bulkProjectID}))

	res, err := h.CoreService.BulkApproveAccessRequests(ctx, []uint{reqID}, 0, bulkMachineFullID)
	require.NoError(t, err)
	assert.Empty(t, res.Failed, "a machine approver holding roles.assign and every bundled permission "+
		"must not be refused: %+v", res.Failed)
	assert.Equal(t, []uint{reqID}, res.Approved)

	ids, err := h.Storage.GetUserRoleIDsAt(ctx, bulkRequesterID, storage.Scope{ProjectID: bulkProjectID})
	require.NoError(t, err)
	assert.Contains(t, ids, bulkEditorRoleID, "the approved request must actually have granted the role")
}

// The security half: a machine identity holding roles.assign but NOT the
// permissions the granted role bundles must be REFUSED by the
// escalation-by-proxy ceiling, and no grant may land.
//
// This assertion is why the actorIsMachine value has to be derived rather than
// hardcoded. With approverMachineID dropped (actorIsMachine=false, approverID=0)
// requireGranterHoldsRolePermissions takes its system-pseudo-actor exemption and
// returns nil before checking anything — so once the authorization in the
// sibling test above is made actor-aware, this grant goes through with no
// ceiling at all. Mutation-verified: threading the real actor kind back out
// while keeping the actor-aware authorization makes this test go red (grant
// performed) and the sibling test stay green.
func TestBulkApprove_MachineApproverMissingPermission_RefusedByCeiling(t *testing.T) {
	t.Parallel()
	h, reqID := newBulkMachineApproverWorld(t)
	ctx := context.Background()

	// "assigner-only" bundles roles.assign and nothing else: enough to reach the
	// endpoint and pass the per-item authorization, not enough to grant "editor".
	h.CreateTestRole(t, "assigner-only", "roles.assign and nothing else", 98)
	h.ExecuteRawSQL(t, `INSERT OR IGNORE INTO role_permissions (role_id, permission_id)
		SELECT r.id, p.id FROM roles r, permissions p WHERE r.name = ? AND p.name = ?`,
		"assigner-only", "roles.assign")
	require.NoError(t, h.Storage.AssignMachineRole(ctx, bulkMachinePartialID, 98,
		storage.Scope{ProjectID: bulkProjectID}))

	res, err := h.CoreService.BulkApproveAccessRequests(ctx, []uint{reqID}, 0, bulkMachinePartialID)
	require.NoError(t, err, "a per-item refusal is reported in Failed, not as a call error")
	assert.Empty(t, res.Approved, "a machine approver that does not itself hold the granted role's "+
		"permissions must not be able to grant them")
	require.Len(t, res.Failed, 1)
	assert.Contains(t, res.Failed[0].Error, "you do not hold permission",
		"the refusal must come from the escalation-by-proxy ceiling, not from an unrelated gate — "+
			"a refusal for the wrong reason is indistinguishable from the ceiling being skipped")

	ids, err := h.Storage.GetUserRoleIDsAt(ctx, bulkRequesterID, storage.Scope{ProjectID: bulkProjectID})
	require.NoError(t, err)
	assert.NotContains(t, ids, bulkEditorRoleID, "no role may have been granted")

	reloaded, err := h.Storage.GetAccessRequest(ctx, reqID)
	require.NoError(t, err)
	assert.Equal(t, "pending", reloaded.State, "the refused request must stay pending")
}

// Attribution: a machine approver's identity must reach the stored record, so
// the audit trail can say WHICH machine approved. The bulk path recorded 0 —
// the same attribution loss #1573 fixed on the single-request path.
func TestBulkApprove_MachineApproverIsRecordedOnTheRequest(t *testing.T) {
	t.Parallel()
	h, reqID := newBulkMachineApproverWorld(t)
	ctx := context.Background()

	require.NoError(t, h.Storage.AssignMachineRole(ctx, bulkMachineFullID, bulkAdminRoleID,
		storage.Scope{ProjectID: bulkProjectID}))
	res, err := h.CoreService.BulkApproveAccessRequests(ctx, []uint{reqID}, 0, bulkMachineFullID)
	require.NoError(t, err)
	require.Empty(t, res.Failed, "%+v", res.Failed)

	reloaded, err := h.Storage.GetAccessRequest(ctx, reqID)
	require.NoError(t, err)
	assert.Equal(t, bulkMachineFullID, reloaded.ResolvedByMachineIdentityID,
		"the approving machine identity must be recorded, not 0")
}

// Bulk REJECT has the same attribution hole: it passed a literal 0 for
// approverMachineID straight into RejectAccessRequest.
func TestBulkReject_MachineRejecterIsRecordedOnTheRequest(t *testing.T) {
	t.Parallel()
	h, reqID := newBulkMachineApproverWorld(t)
	ctx := context.Background()

	require.NoError(t, h.Storage.AssignMachineRole(ctx, bulkMachineFullID, bulkAdminRoleID,
		storage.Scope{ProjectID: bulkProjectID}))
	res, err := h.CoreService.BulkRejectAccessRequests(ctx, []uint{reqID}, 0, bulkMachineFullID, "not needed")
	require.NoError(t, err)
	assert.Empty(t, res.Failed, "%+v", res.Failed)
	assert.Equal(t, []uint{reqID}, res.Rejected)

	reloaded, err := h.Storage.GetAccessRequest(ctx, reqID)
	require.NoError(t, err)
	assert.Equal(t, bulkMachineFullID, reloaded.ResolvedByMachineIdentityID,
		"the rejecting machine identity must be recorded, not 0")
}

// Calibration, human side: the human-approver path must behave exactly as before
// (approverMachineID=0 reduces to the original user-only resolution). Without
// this, a change that simply made every caller "machine" would pass the tests
// above.
func TestBulkApprove_HumanApproverStillWorksUnchanged(t *testing.T) {
	t.Parallel()
	h, reqID := newBulkMachineApproverWorld(t)
	ctx := context.Background()

	const approverID = uint(11)
	h.CreateTestUser(t, "approver", approverID)
	h.AssignUserRole(t, approverID, bulkAdminRoleID, ptrUintBulk(bulkProjectID))

	res, err := h.CoreService.BulkApproveAccessRequests(ctx, []uint{reqID}, approverID, 0)
	require.NoError(t, err)
	assert.Empty(t, res.Failed, "%+v", res.Failed)
	assert.Equal(t, []uint{reqID}, res.Approved)

	reloaded, err := h.Storage.GetAccessRequest(ctx, reqID)
	require.NoError(t, err)
	assert.Equal(t, uint(0), reloaded.ResolvedByMachineIdentityID, "a human approval records no machine identity")
	assert.Equal(t, approverID, reloaded.ResolvedBy)
}

// Calibration, human refusal side: a human approver missing the granted role's
// permissions is still refused by the ceiling, unchanged.
func TestBulkApprove_HumanApproverMissingPermission_StillRefused(t *testing.T) {
	t.Parallel()
	h, reqID := newBulkMachineApproverWorld(t)
	ctx := context.Background()

	const approverID = uint(12)
	h.CreateTestUser(t, "weakapprover", approverID)
	h.CreateTestRole(t, "assigner-only", "roles.assign and nothing else", 98)
	h.ExecuteRawSQL(t, `INSERT OR IGNORE INTO role_permissions (role_id, permission_id)
		SELECT r.id, p.id FROM roles r, permissions p WHERE r.name = ? AND p.name = ?`,
		"assigner-only", "roles.assign")
	h.AssignUserRole(t, approverID, 98, ptrUintBulk(bulkProjectID))

	res, err := h.CoreService.BulkApproveAccessRequests(ctx, []uint{reqID}, approverID, 0)
	require.NoError(t, err)
	assert.Empty(t, res.Approved)
	require.Len(t, res.Failed, 1)
	assert.Contains(t, res.Failed[0].Error, "you do not hold permission")

	ids, err := h.Storage.GetUserRoleIDsAt(ctx, bulkRequesterID, storage.Scope{ProjectID: bulkProjectID})
	require.NoError(t, err)
	assert.NotContains(t, ids, bulkEditorRoleID)
}

// A principal with neither a machine identity nor a user ID (the true
// unauthenticated shape) must not be able to bulk-approve anything. This pins
// the one case the system-pseudo-actor exemption would otherwise wave through if
// the actor kind were ever reintroduced as a hardcoded value.
func TestBulkApprove_NoPrincipalAtAll_Refused(t *testing.T) {
	t.Parallel()
	h, reqID := newBulkMachineApproverWorld(t)

	res, err := h.CoreService.BulkApproveAccessRequests(context.Background(), []uint{reqID}, 0, 0)
	require.NoError(t, err)
	assert.Empty(t, res.Approved, "an unauthenticated caller must approve nothing")
	require.Len(t, res.Failed, 1)

	ids, err := h.Storage.GetUserRoleIDsAt(context.Background(), bulkRequesterID, storage.Scope{ProjectID: bulkProjectID})
	require.NoError(t, err)
	assert.NotContains(t, ids, bulkEditorRoleID)
}

func ptrUintBulk(v uint) *uint { return &v }
