// access_request_proxy_authority_ceiling_test.go — Part 3 usage-based guard
// pass: UpdateAccessRequestProxy re-derived an actor-authority check only for
// the "approved" state transition; reject/withdraw/expire went straight to
// storage with no equivalent check, diverging from what each state's real
// business-logic path enforces locally (core.WithdrawAccessRequest's
// self-only check, the local reject route's roles.assign gate).
// CreateAccessRequestApprovalProxy similarly recorded an approval vote with
// no authority ceiling at all. See the corresponding findings in
// keyorix-private/adversarial-review for the full exploit scenarios.
package http

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/identity"
)

// TestAccessRequestProxy_WithdrawRequiresRequesterIdentity proves a
// system.write-only caller cannot force-withdraw a DIFFERENT user's pending
// access request through the proxy -- only the original requester can.
func TestAccessRequestProxy_WithdrawRequiresRequesterIdentity(t *testing.T) {
	f := newMachinePrivilegeCeilingFixture(t)
	ctx := context.Background()

	requester, err := f.core.CreateUser(ctx, &core.CreateUserRequest{
		Username: "withdraw_ceiling_requester", Email: "withdraw_ceiling_requester@example.com", Password: "Rq9!Qr7#Kp2$Lm5@",
	})
	require.NoError(t, err)

	roleName, err := identity.NewFoldedName("ceiling_test_withdraw_role")
	require.NoError(t, err)
	_, err = f.core.Storage().CreateRole(ctx, roleName, "test-only role")
	require.NoError(t, err)

	req, err := f.core.RequestProjectAccess(ctx, f.projectID, requester.ID, "ceiling_test_withdraw_role", "need role access for a task, at least 20 chars")
	require.NoError(t, err)

	status, body := f.do(t, f.swToken, http.MethodPut, fmt.Sprintf("/api/v1/system/access-requests/%d", req.ID), map[string]any{
		"id": req.ID, "project_id": f.projectID, "user_id": requester.ID,
		"state": "withdrawn",
	})
	t.Logf("PUT /system/access-requests/%d (system.write-only, not the requester, state=withdrawn): status=%d body=%s", req.ID, status, body)
	require.Equal(t, http.StatusNotFound, status,
		"a caller who is not the original requester must not be able to withdraw their access request through the proxy")

	updated, err := f.core.Storage().GetAccessRequest(ctx, req.ID)
	require.NoError(t, err)
	require.Equal(t, core.AccessRequestPending, updated.State, "the request must remain pending, not silently withdrawn by a non-owner")
}

// TestAccessRequestProxy_WithdrawByRealRequesterSucceeds proves the other
// half: the actual requester can still withdraw their own request.
func TestAccessRequestProxy_WithdrawByRealRequesterSucceeds(t *testing.T) {
	f := newMachinePrivilegeCeilingFixture(t)
	ctx := context.Background()

	_, err := f.core.CreateUser(ctx, &core.CreateUserRequest{
		Username: "withdraw_ceiling_self", Email: "withdraw_ceiling_self@example.com", Password: "Rq9!Qr7#Kp2$Lm5@",
	})
	require.NoError(t, err)
	requester, err := f.core.GetUserByEmail(ctx, "withdraw_ceiling_self@example.com")
	require.NoError(t, err)
	// The whole /system proxy group requires system.write at the router
	// level, independent of this test's actual subject (the ownership
	// check) -- grant the requester the same system.write-only role
	// newMachinePrivilegeCeilingFixture already created for f.swToken, so a
	// real spoke-relayed self-withdraw can even reach the handler.
	require.NoError(t, f.core.AssignRoleToUser(ctx, "withdraw_ceiling_self@example.com", "ceiling_test_system_writer"))

	roleName, err := identity.NewFoldedName("ceiling_test_withdraw_self_role")
	require.NoError(t, err)
	_, err = f.core.Storage().CreateRole(ctx, roleName, "test-only role")
	require.NoError(t, err)

	req, err := f.core.RequestProjectAccess(ctx, f.projectID, requester.ID, "ceiling_test_withdraw_self_role", "need role access for a task, at least 20 chars")
	require.NoError(t, err)

	selfToken := loginTestUser(t, f.core, "withdraw_ceiling_self", "Rq9!Qr7#Kp2$Lm5@")
	status, body := f.do(t, selfToken, http.MethodPut, fmt.Sprintf("/api/v1/system/access-requests/%d", req.ID), map[string]any{
		"id": req.ID, "project_id": f.projectID, "user_id": requester.ID,
		"state": "withdrawn",
	})
	t.Logf("PUT /system/access-requests/%d (real requester, state=withdrawn): status=%d body=%s", req.ID, status, body)
	require.Equal(t, http.StatusOK, status, "the original requester must still be able to withdraw their own request")
}

// TestAccessRequestProxy_RejectRequiresRolesAssignAtProjectScope proves a
// system.write-only caller (no roles.assign anywhere) cannot reject ANY
// project's pending access request -- the same authority the local
// human-facing reject route requires via router-level middleware, which this
// proxy bypasses.
func TestAccessRequestProxy_RejectRequiresRolesAssignAtProjectScope(t *testing.T) {
	f := newMachinePrivilegeCeilingFixture(t)
	ctx := context.Background()

	requester, err := f.core.CreateUser(ctx, &core.CreateUserRequest{
		Username: "reject_ceiling_requester", Email: "reject_ceiling_requester@example.com", Password: "Rq9!Qr7#Kp2$Lm5@",
	})
	require.NoError(t, err)

	roleName, err := identity.NewFoldedName("ceiling_test_reject_role")
	require.NoError(t, err)
	_, err = f.core.Storage().CreateRole(ctx, roleName, "test-only role")
	require.NoError(t, err)

	req, err := f.core.RequestProjectAccess(ctx, f.projectID, requester.ID, "ceiling_test_reject_role", "need role access for a task, at least 20 chars")
	require.NoError(t, err)

	status, body := f.do(t, f.swToken, http.MethodPut, fmt.Sprintf("/api/v1/system/access-requests/%d", req.ID), map[string]any{
		"id": req.ID, "project_id": f.projectID, "user_id": requester.ID,
		"state": "rejected", "reason": "no thanks",
	})
	t.Logf("PUT /system/access-requests/%d (system.write-only, no roles.assign, state=rejected): status=%d body=%s", req.ID, status, body)
	require.Equal(t, http.StatusForbidden, status,
		"a caller with no roles.assign at the request's project must not be able to reject it")

	updated, err := f.core.Storage().GetAccessRequest(ctx, req.ID)
	require.NoError(t, err)
	require.Equal(t, core.AccessRequestPending, updated.State, "the request must remain pending, not silently rejected")
}

// TestAccessRequestProxy_RejectWithRolesAssignSucceeds proves the other
// half: a caller who genuinely holds roles.assign can still reject.
func TestAccessRequestProxy_RejectWithRolesAssignSucceeds(t *testing.T) {
	f := newMachinePrivilegeCeilingFixture(t)
	ctx := context.Background()

	requester, err := f.core.CreateUser(ctx, &core.CreateUserRequest{
		Username: "reject_ceiling_ok_requester", Email: "reject_ceiling_ok_requester@example.com", Password: "Rq9!Qr7#Kp2$Lm5@",
	})
	require.NoError(t, err)

	roleName, err := identity.NewFoldedName("ceiling_test_reject_ok_role")
	require.NoError(t, err)
	_, err = f.core.Storage().CreateRole(ctx, roleName, "test-only role")
	require.NoError(t, err)

	req, err := f.core.RequestProjectAccess(ctx, f.projectID, requester.ID, "ceiling_test_reject_ok_role", "need role access for a task, at least 20 chars")
	require.NoError(t, err)

	status, body := f.do(t, f.assignToken, http.MethodPut, fmt.Sprintf("/api/v1/system/access-requests/%d", req.ID), map[string]any{
		"id": req.ID, "project_id": f.projectID, "user_id": requester.ID,
		"state": "rejected", "reason": "no thanks",
	})
	t.Logf("PUT /system/access-requests/%d (system.write + roles.assign, state=rejected): status=%d body=%s", req.ID, status, body)
	require.Equal(t, http.StatusOK, status, "a caller genuinely holding roles.assign must still be able to reject")
}

// TestAccessRequestProxy_ExpireRequiresRolesAssignAtProjectScope proves the
// same ceiling applies to the "expired" state transition, which has no
// direct client-facing equivalent at all locally.
func TestAccessRequestProxy_ExpireRequiresRolesAssignAtProjectScope(t *testing.T) {
	f := newMachinePrivilegeCeilingFixture(t)
	ctx := context.Background()

	requester, err := f.core.CreateUser(ctx, &core.CreateUserRequest{
		Username: "expire_ceiling_requester", Email: "expire_ceiling_requester@example.com", Password: "Rq9!Qr7#Kp2$Lm5@",
	})
	require.NoError(t, err)

	roleName, err := identity.NewFoldedName("ceiling_test_expire_role")
	require.NoError(t, err)
	_, err = f.core.Storage().CreateRole(ctx, roleName, "test-only role")
	require.NoError(t, err)

	req, err := f.core.RequestProjectAccess(ctx, f.projectID, requester.ID, "ceiling_test_expire_role", "need role access for a task, at least 20 chars")
	require.NoError(t, err)

	status, body := f.do(t, f.swToken, http.MethodPut, fmt.Sprintf("/api/v1/system/access-requests/%d", req.ID), map[string]any{
		"id": req.ID, "project_id": f.projectID, "user_id": requester.ID,
		"state": "expired",
	})
	t.Logf("PUT /system/access-requests/%d (system.write-only, no roles.assign, state=expired): status=%d body=%s", req.ID, status, body)
	require.Equal(t, http.StatusForbidden, status,
		"a caller with no roles.assign at the request's project must not be able to force-expire it ahead of its real TTL")
}

// TestCreateAccessRequestApprovalProxy_RequiresApprovalCeiling proves a
// system.write-only caller with no role-grant authority cannot plant a
// phantom dual-control approval vote on a project/role-scoped request.
func TestCreateAccessRequestApprovalProxy_RequiresApprovalCeiling(t *testing.T) {
	f := newMachinePrivilegeCeilingFixture(t)
	ctx := context.Background()

	requester, err := f.core.CreateUser(ctx, &core.CreateUserRequest{
		Username: "approval_ceiling_requester", Email: "approval_ceiling_requester@example.com", Password: "Rq9!Qr7#Kp2$Lm5@",
	})
	require.NoError(t, err)

	// Unlike the attribution-only tests above, this one needs the target role
	// to bundle a REAL permission the system.write-only caller doesn't hold
	// -- a permission-less role is vacuously "held" by anyone and would pass
	// the ceiling check trivially, testing nothing.
	roleName, err := identity.NewFoldedName("ceiling_test_approval_ceiling_role")
	require.NoError(t, err)
	role, err := f.core.Storage().CreateRole(ctx, roleName, "test-only role: bundles secrets.delete")
	require.NoError(t, err)
	perms, err := f.core.ListPermissions(ctx)
	require.NoError(t, err)
	var secretsDeleteID uint
	for _, p := range perms {
		if p.Name == "secrets.delete" {
			secretsDeleteID = p.ID
		}
	}
	require.NotZero(t, secretsDeleteID, "secrets.delete permission must already be seeded by bootstrap")
	require.NoError(t, f.core.AssignPermissionToRole(ctx, 0, role.ID, secretsDeleteID, false))

	req, err := f.core.RequestProjectAccess(ctx, f.projectID, requester.ID, "ceiling_test_approval_ceiling_role", "need role access for a task, at least 20 chars")
	require.NoError(t, err)

	status, body := f.do(t, f.swToken, http.MethodPost, fmt.Sprintf("/api/v1/system/access-requests/%d/approvals", req.ID), map[string]any{
		"created_at": time.Now(),
	})
	t.Logf("POST /system/access-requests/%d/approvals (system.write-only, no role-grant authority): status=%d body=%s", req.ID, status, body)
	require.Equal(t, http.StatusForbidden, status,
		"a caller with no authority over the requested role must not be able to plant a dual-control approval vote")

	approvals, err := f.core.Storage().ListAccessRequestApprovals(ctx, req.ID)
	require.NoError(t, err)
	require.Empty(t, approvals, "no phantom approval row must have been persisted")
}

// TestCreateAccessRequestApprovalProxy_SelfApprovalRefused proves the
// requester cannot approve their own request through this proxy either.
func TestCreateAccessRequestApprovalProxy_SelfApprovalRefused(t *testing.T) {
	f := newMachinePrivilegeCeilingFixture(t)
	ctx := context.Background()

	_, err := f.core.CreateUser(ctx, &core.CreateUserRequest{
		Username: "approval_ceiling_self", Email: "approval_ceiling_self@example.com", Password: "Rq9!Qr7#Kp2$Lm5@",
	})
	require.NoError(t, err)
	requester, err := f.core.GetUserByEmail(ctx, "approval_ceiling_self@example.com")
	require.NoError(t, err)
	// Grant system.write (required by the whole /system proxy group at the
	// router level, independent of this test's subject) AND make the target
	// role permission-less, so the ceiling check trivially passes -- if
	// self-approval weren't separately refused, this request would
	// otherwise succeed, making the assertion below actually test what it
	// claims to.
	require.NoError(t, f.core.AssignRoleToUser(ctx, "approval_ceiling_self@example.com", "ceiling_test_system_writer"))

	roleName, err := identity.NewFoldedName("ceiling_test_approval_self_role")
	require.NoError(t, err)
	_, err = f.core.Storage().CreateRole(ctx, roleName, "test-only role")
	require.NoError(t, err)

	req, err := f.core.RequestProjectAccess(ctx, f.projectID, requester.ID, "ceiling_test_approval_self_role", "need role access for a task, at least 20 chars")
	require.NoError(t, err)

	selfToken := loginTestUser(t, f.core, "approval_ceiling_self", "Rq9!Qr7#Kp2$Lm5@")
	status, body := f.do(t, selfToken, http.MethodPost, fmt.Sprintf("/api/v1/system/access-requests/%d/approvals", req.ID), map[string]any{
		"created_at": time.Now(),
	})
	t.Logf("POST /system/access-requests/%d/approvals (requester approving their own request): status=%d body=%s", req.ID, status, body)
	require.Equal(t, http.StatusForbidden, status, "a requester must not be able to approve their own access request")
}

// loginTestUser logs in an already-created user and returns their session
// token, for tests that need to act AS a specific non-admin user (rather
// than the fixture's fixed system.write-only / admin tokens).
func loginTestUser(t *testing.T, c *core.KeyorixCore, username, password string) string {
	t.Helper()
	sess, _, err := c.Login(context.Background(), &core.LoginRequest{Username: username, Password: password})
	require.NoError(t, err)
	return sess.SessionToken
}
