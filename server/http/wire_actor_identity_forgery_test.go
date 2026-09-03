// wire_actor_identity_forgery_test.go — regression coverage for the
// wire-supplied-actor-identity bug class found during independent
// verification of the G80 campaign (2026-08-25): a handler authorizes an
// actor identity supplied on the REQUEST BODY (invited_by, resolved_by)
// instead of the AUTHENTICATED caller (actorID(r)). A caller holding only
// system.write could name a real administrator in that field and clear the
// authority check meant to require the ADMIN to have made the call.
package http

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	coreStorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/identity"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// TestWireActorForgery_CreateInvitationProxy_CannotForgeInvitedBy is the
// literal exploit the independent verification session ran live: a
// system.write-only caller, naming a real admin as invited_by, must not be
// able to create a system_admin invitation for an attacker-controlled email.
func TestWireActorForgery_CreateInvitationProxy_CannotForgeInvitedBy(t *testing.T) {
	f := newMachinePrivilegeCeilingFixture(t)

	status, body := f.do(t, f.swToken, http.MethodPost, "/api/v1/system/invitations", map[string]any{
		"email": "attacker-controlled@example.com", "state": "pending",
		"system_role": "system_admin", "invited_by": f.adminID,
		"expires_at": time.Now().Add(24 * time.Hour),
	})
	t.Logf("POST /system/invitations (system.write-only, invited_by forged to real admin %d): status=%d body=%s", f.adminID, status, body)
	require.Equal(t, http.StatusForbidden, status,
		"a caller with no authority to grant system_admin must not be able to plant a system_admin invitation by naming a real admin in invited_by")

	invitations, err := f.core.Storage().ListProjectInvitations(context.Background(), 0)
	require.NoError(t, err)
	for _, inv := range invitations {
		require.NotEqual(t, "attacker-controlled@example.com", inv.Email, "no invitation must have been persisted for the attacker-controlled email")
	}
}

// TestWireActorForgery_CreateInvitationProxy_RealAdminSucceeds proves the
// other half: an actual admin, authenticated as themselves, can still create
// a system_admin invitation -- the fix is a real identity check, not a
// blanket denial.
func TestWireActorForgery_CreateInvitationProxy_RealAdminSucceeds(t *testing.T) {
	f := newMachinePrivilegeCeilingFixture(t)
	adminToken := createTestToken(t, f.core) // re-login as the bootstrap admin

	status, body := f.do(t, adminToken, http.MethodPost, "/api/v1/system/invitations", map[string]any{
		"email": "legitimate-invite@example.com", "state": "pending",
		"system_role": "system_admin", "invited_by": f.adminID,
		"expires_at": time.Now().Add(24 * time.Hour),
	})
	t.Logf("POST /system/invitations (real admin, invited_by=self): status=%d body=%s", status, body)
	require.Equal(t, http.StatusOK, status, "a genuine admin authenticating as themselves must still be able to create a system_admin invitation")
}

// TestWireActorForgery_CreateInvitationProxy_PersistedInvitedByIsAlwaysCaller
// closes a gap in the two tests above: both only exercise a FORBIDDEN path
// (system_admin is admin-tier, so the ceiling rejects the request before
// model.InvitedBy is ever assigned), so neither can tell whether the
// persisted attribution fix (model.InvitedBy = actorID(r), invitations_proxy.go)
// is load-bearing or dead code. FIX-1 replaced the name-based ceiling
// (requireAuthorityForRole, which cleared for ANY non-admin-tier role name
// regardless of the caller's real permissions) with
// requireGranterHoldsRolePermissions, which derives the ceiling from the
// role's actual bundled permissions -- so the invited role here must be
// created with NO bundled permissions for a system.write-only caller to
// still clear it. Using a permission-less role isolates this test to its
// actual subject -- persisted-attribution -- not the ceiling itself.
func TestWireActorForgery_CreateInvitationProxy_PersistedInvitedByIsAlwaysCaller(t *testing.T) {
	f := newMachinePrivilegeCeilingFixture(t)
	ctx := context.Background()
	caller, err := f.core.GetUserByEmail(ctx, "sys_write_only@example.com")
	require.NoError(t, err)

	roleName, err := identity.NewFoldedName("ceiling_test_non_admin_invitee_role")
	require.NoError(t, err)
	_, err = f.core.Storage().CreateRole(ctx, roleName, "test-only role: no bundled permissions")
	require.NoError(t, err)

	status, body := f.do(t, f.swToken, http.MethodPost, "/api/v1/system/invitations", map[string]any{
		"project_id": f.projectID, "email": "attribution-forge-target@example.com", "state": "pending",
		"role": "ceiling_test_non_admin_invitee_role", "invited_by": f.adminID,
		"expires_at": time.Now().Add(24 * time.Hour),
	})
	t.Logf("POST /system/invitations (system.write-only, non-admin role, invited_by forged to real admin %d): status=%d body=%s", f.adminID, status, body)
	require.Equal(t, http.StatusOK, status, "a non-admin-role invite must succeed for a system.write caller -- this test needs the request to actually persist to check attribution")

	invitations, err := f.core.Storage().ListProjectInvitations(ctx, f.projectID)
	require.NoError(t, err)
	var found *models.ProjectInvitation
	for _, inv := range invitations {
		if inv.Email == "attribution-forge-target@example.com" {
			found = inv
			break
		}
	}
	require.NotNil(t, found, "the invitation must have been persisted")
	require.Equal(t, caller.ID, found.InvitedBy, "InvitedBy must record the authenticated caller, not the wire-supplied forgery")
	require.NotEqual(t, f.adminID, found.InvitedBy, "InvitedBy must not be the forged admin ID")
}

// TestWireActorForgery_UpdateAccessRequestProxy_CannotForgeResolvedBy is the
// same class against UpdateAccessRequestProxy: a system.write-only caller,
// naming a real admin as resolved_by, must not be able to approve someone
// else's pending access request to a restricted secret.
func TestWireActorForgery_UpdateAccessRequestProxy_CannotForgeResolvedBy(t *testing.T) {
	f := newMachinePrivilegeCeilingFixture(t)
	ctx := context.Background()

	_, err := f.core.CreateUser(ctx, &core.CreateUserRequest{
		Username: "wire_forge_requester", Email: "wire_forge_requester@example.com", Password: "Rq9!Qr7#Kp2$Lm5@",
	})
	require.NoError(t, err)
	requester, err := f.core.GetUserByEmail(ctx, "wire_forge_requester@example.com")
	require.NoError(t, err)

	secret, err := f.core.Storage().CreateSecret(ctx, &models.SecretNode{
		ProjectID: f.projectID, Name: "wire-forge-restricted-secret", Type: "generic", Classification: "restricted",
	})
	require.NoError(t, err)
	req, err := f.core.RequestSecretAccess(ctx, secret.ID, requester.ID, "need read access for an audit, at least 20 chars")
	require.NoError(t, err)

	status, body := f.do(t, f.swToken, http.MethodPut, fmt.Sprintf("/api/v1/system/access-requests/%d", req.ID), map[string]any{
		"id": req.ID, "project_id": f.projectID, "user_id": requester.ID, "secret_id": secret.ID,
		"state": "approved", "reason": "approved", "resolved_by": f.adminID, "resolved_at": time.Now(),
	})
	t.Logf("PUT /system/access-requests/%d (system.write-only, resolved_by forged to real admin %d): status=%d body=%s", req.ID, f.adminID, status, body)
	require.Equal(t, http.StatusForbidden, status,
		"a caller with no admin authority must not be able to approve access to a restricted secret by naming a real admin in resolved_by")

	updated, err := f.core.Storage().GetAccessRequest(ctx, req.ID)
	require.NoError(t, err)
	require.Equal(t, core.AccessRequestPending, updated.State, "the request must remain pending, not silently approved")
}

// TestWireActorForgery_UpdateAccessRequestProxy_PersistedResolvedByIsAlwaysCaller
// closes the same gap as the invitation-proxy counterpart above: the SecretID!=nil
// (restricted-secret) path used by CannotForgeResolvedBy is denied by
// RequireAdminAuthorityAt before ResolvedBy is ever assigned, so it can't tell
// whether `existing.ResolvedBy = resolverID` is load-bearing. FIX-1 replaced
// the name-based ceiling on the project/role-scoped path (SecretID==nil) with
// requireGranterHoldsRolePermissions, which derives the ceiling from the
// role's actual bundled permissions -- so the granted role here must be a
// fresh permission-less role, not "project_viewer" (which bundles
// secrets.read the system.write-only caller doesn't hold), for this to still
// reach a real 200. Using a permission-less role isolates this test to its
// actual subject -- persisted-attribution -- not the ceiling itself.
func TestWireActorForgery_UpdateAccessRequestProxy_PersistedResolvedByIsAlwaysCaller(t *testing.T) {
	f := newMachinePrivilegeCeilingFixture(t)
	ctx := context.Background()
	caller, err := f.core.GetUserByEmail(ctx, "sys_write_only@example.com")
	require.NoError(t, err)

	_, err = f.core.CreateUser(ctx, &core.CreateUserRequest{
		Username: "wire_forge_requester3", Email: "wire_forge_requester3@example.com", Password: "Rq9!Qr7#Kp2$Lm5@",
	})
	require.NoError(t, err)
	requester, err := f.core.GetUserByEmail(ctx, "wire_forge_requester3@example.com")
	require.NoError(t, err)

	roleName, err := identity.NewFoldedName("ceiling_test_non_admin_grant_role")
	require.NoError(t, err)
	_, err = f.core.Storage().CreateRole(ctx, roleName, "test-only role: no bundled permissions")
	require.NoError(t, err)

	req, err := f.core.RequestProjectAccess(ctx, f.projectID, requester.ID, "ceiling_test_non_admin_grant_role", "need role access for a task, at least 20 chars")
	require.NoError(t, err)

	status, body := f.do(t, f.swToken, http.MethodPut, fmt.Sprintf("/api/v1/system/access-requests/%d", req.ID), map[string]any{
		"id": req.ID, "project_id": f.projectID, "user_id": requester.ID, "granted_role": "ceiling_test_non_admin_grant_role",
		"state": "approved", "reason": "approved", "resolved_by": f.adminID, "resolved_at": time.Now(),
	})
	t.Logf("PUT /system/access-requests/%d (system.write-only, non-admin role, resolved_by forged to real admin %d): status=%d body=%s", req.ID, f.adminID, status, body)
	require.Equal(t, http.StatusOK, status, "a non-admin-role project access approval must succeed for a system.write caller -- this test needs the request to actually persist to check attribution")

	updated, err := f.core.Storage().GetAccessRequest(ctx, req.ID)
	require.NoError(t, err)
	require.Equal(t, caller.ID, updated.ResolvedBy, "ResolvedBy must record the authenticated caller, not the wire-supplied forgery")
	require.NotEqual(t, f.adminID, updated.ResolvedBy, "ResolvedBy must not be the forged admin ID")
}

// TestWireActorForgery_UpdateAccessRequestProxy_RealAdminSucceeds proves the
// other half for UpdateAccessRequestProxy: a genuine admin, authenticated as
// themselves, can still approve access to a restricted secret.
func TestWireActorForgery_UpdateAccessRequestProxy_RealAdminSucceeds(t *testing.T) {
	f := newMachinePrivilegeCeilingFixture(t)
	ctx := context.Background()
	adminToken := createTestToken(t, f.core)

	_, err := f.core.CreateUser(ctx, &core.CreateUserRequest{
		Username: "wire_forge_requester2", Email: "wire_forge_requester2@example.com", Password: "Rq9!Qr7#Kp2$Lm5@",
	})
	require.NoError(t, err)
	requester, err := f.core.GetUserByEmail(ctx, "wire_forge_requester2@example.com")
	require.NoError(t, err)

	secret, err := f.core.Storage().CreateSecret(ctx, &models.SecretNode{
		ProjectID: f.projectID, Name: "wire-forge-restricted-secret-2", Type: "generic", Classification: "restricted",
	})
	require.NoError(t, err)
	req, err := f.core.RequestSecretAccess(ctx, secret.ID, requester.ID, "need read access for an audit, at least 20 chars")
	require.NoError(t, err)

	status, body := f.do(t, adminToken, http.MethodPut, fmt.Sprintf("/api/v1/system/access-requests/%d", req.ID), map[string]any{
		"id": req.ID, "project_id": f.projectID, "user_id": requester.ID, "secret_id": secret.ID,
		"state": "approved", "reason": "approved", "resolved_by": f.adminID, "resolved_at": time.Now(),
	})
	t.Logf("PUT /system/access-requests/%d (real admin approving as themselves): status=%d body=%s", req.ID, status, body)
	require.Equal(t, http.StatusOK, status, "a genuine admin authenticating as themselves must still be able to approve access to a restricted secret")
}

// TestWireActorForgery_CreateAccessRequestApprovalProxy_ApproverIsAlwaysCaller
// (G80 documented-exception re-verification sweep, 2026-08-25) proves
// CreateAccessRequestApprovalProxy no longer trusts a wire-supplied
// approver_id: naming an arbitrary ID on the wire persists an approval
// attributed to the AUTHENTICATED caller instead, closing the dual-control
// bypass where a single caller could POST N approvals with N fabricated
// approver_ids and drive ApprovalsReceived past RequiredApprovals with zero
// real, independent approvers.
func TestWireActorForgery_CreateAccessRequestApprovalProxy_ApproverIsAlwaysCaller(t *testing.T) {
	f := newMachinePrivilegeCeilingFixture(t)
	ctx := context.Background()

	requester, err := f.core.CreateUser(ctx, &core.CreateUserRequest{
		Username: "approval_forge_requester", Email: "approval_forge_requester@example.com", Password: "Rq9!Qr7#Kp2$Lm5@",
	})
	require.NoError(t, err)
	req, err := f.core.Storage().CreateAccessRequest(ctx, &models.AccessRequest{
		ProjectID: f.projectID, UserID: requester.ID, SuggestedRole: "developer", State: "pending", CreatedAt: time.Now(),
	})
	require.NoError(t, err)

	adminToken := createTestToken(t, f.core)
	status, body := f.do(t, adminToken, http.MethodPost, fmt.Sprintf("/api/v1/system/access-requests/%d/approvals", req.ID), map[string]any{
		"approver_id": 999999, "created_at": time.Now(),
	})
	t.Logf("POST /system/access-requests/%d/approvals (approver_id forged to 999999): status=%d body=%s", req.ID, status, body)
	require.Equal(t, http.StatusOK, status)

	approvals, err := f.core.Storage().ListAccessRequestApprovals(ctx, req.ID)
	require.NoError(t, err)
	require.Len(t, approvals, 1)
	require.NotEqual(t, uint(999999), approvals[0].ApproverID, "the forged approver_id must never be persisted")
	require.Equal(t, f.adminID, approvals[0].ApproverID, "the approval must be attributed to the authenticated caller, not the wire value")
}

// TestWireActorForgery_UpdateAccessReviewItemProxy_CannotSelfCertify
// (G80 documented-exception re-verification sweep, 2026-08-25) proves
// UpdateAccessReviewItemProxy's self-certification guard is now anchored to
// the AUTHENTICATED caller, not a wire-supplied decided_by: before the fix, a
// caller could name a real, different reviewer in decided_by while the
// PrincipalID mismatch check trivially passed, recording someone who never
// looked at the request. Now the caller reviewing their OWN access item is
// refused regardless of what decided_by claims, and a genuinely different
// authenticated reviewer still succeeds.
func TestWireActorForgery_UpdateAccessReviewItemProxy_CannotSelfCertify(t *testing.T) {
	f := newMachinePrivilegeCeilingFixture(t)
	ctx := context.Background()

	campaign, err := f.core.Storage().CreateAccessReviewCampaign(ctx, &models.AccessReviewCampaign{
		ProjectID: f.projectID, Name: "wire-forge-campaign", State: "open", CreatedBy: f.adminID, CreatedAt: time.Now(),
	})
	require.NoError(t, err)
	require.NoError(t, f.core.Storage().CreateAccessReviewItems(ctx, []*models.AccessReviewItem{{
		CampaignID: campaign.ID, PrincipalType: "user", PrincipalID: f.adminID, PrincipalName: "admin",
		Source: "role", AccessLevel: "read", Decision: "pending",
	}}))
	items, err := f.core.Storage().ListAccessReviewItems(ctx, campaign.ID)
	require.NoError(t, err)
	require.Len(t, items, 1)
	itemID := items[0].ID

	// The item's own subject (admin) tries to certify it, naming a DIFFERENT
	// real reviewer in decided_by on the wire — must be refused because the
	// AUTHENTICATED caller is the subject, regardless of what the wire claims.
	adminToken := createTestToken(t, f.core)
	otherReviewerToken := f.assignToken
	otherReviewer, err := f.core.GetUserByEmail(ctx, "sys_write_roles_assign@example.com")
	require.NoError(t, err)
	status, body := f.do(t, adminToken, http.MethodPut, fmt.Sprintf("/api/v1/system/access-review-campaigns/items/%d", itemID), map[string]any{
		"campaign_id": campaign.ID, "principal_type": "user", "principal_id": f.adminID, "decision": "attested", "decided_by": otherReviewer.ID,
	})
	t.Logf("PUT .../items/%d (subject self-certifying, decided_by forged to real reviewer %d): status=%d body=%s", itemID, otherReviewer.ID, status, body)
	require.Equal(t, http.StatusForbidden, status, "the item's own subject must not be able to self-certify by naming a different reviewer in decided_by")

	fetched, err := f.core.Storage().GetAccessReviewItem(ctx, itemID)
	require.NoError(t, err)
	require.Equal(t, "pending", fetched.Decision, "the item must remain pending after a refused self-certification attempt")

	// A genuinely different, authenticated reviewer succeeds.
	status, body = f.do(t, otherReviewerToken, http.MethodPut, fmt.Sprintf("/api/v1/system/access-review-campaigns/items/%d", itemID), map[string]any{
		"campaign_id": campaign.ID, "principal_type": "user", "principal_id": f.adminID, "decision": "attested",
	})
	t.Logf("PUT .../items/%d (real independent reviewer): status=%d body=%s", itemID, status, body)
	require.Equal(t, http.StatusOK, status, "a genuinely different authenticated reviewer must still be able to certify the item")

	fetched, err = f.core.Storage().GetAccessReviewItem(ctx, itemID)
	require.NoError(t, err)
	require.Equal(t, "attested", fetched.Decision)
	require.Equal(t, otherReviewer.ID, fetched.DecidedBy, "DecidedBy must be the authenticated reviewer, not any wire value")
}

// TestWireActorForgery_RevokeBreakGlassActivationProxy_RevokedByIsAlwaysCaller
// (G80 documented-exception re-verification sweep, 2026-08-25) proves
// RevokeBreakGlassActivationProxy's RevokedBy — used as the role-removal
// actor, the persisted activation field, and the audit event — is now the
// AUTHENTICATED caller. Before the fix, any system.write holder could revoke
// an emergency access grant and attribute it, in both the activation record
// and the audit trail, to an arbitrary user ID: a non-repudiation break on
// the break-glass control.
func TestWireActorForgery_RevokeBreakGlassActivationProxy_RevokedByIsAlwaysCaller(t *testing.T) {
	f := newMachinePrivilegeCeilingFixture(t)
	ctx := context.Background()

	wireForgeBgEmergencyRoleName, err := identity.NewFoldedName("wire_forge_bg_emergency_role")
	require.NoError(t, err)
	role, err := f.core.Storage().CreateRole(ctx, wireForgeBgEmergencyRoleName, "")
	require.NoError(t, err)
	require.NoError(t, f.core.Storage().AssignRole(ctx, f.adminID, role.ID, coreStorage.Scope{ProjectID: f.projectID}))
	activation, err := f.core.Storage().CreateBreakGlassActivation(ctx, &models.BreakGlassActivation{
		ProjectID: f.projectID, UserID: f.adminID, RoleID: role.ID, RoleName: role.Name,
		Justification: "wire-actor-forgery regression test", State: core.BreakGlassActive,
	})
	require.NoError(t, err)

	adminToken := createTestToken(t, f.core)
	status, body := f.do(t, adminToken, http.MethodPost, fmt.Sprintf("/api/v1/system/break-glass/%d/revoke", activation.ID), map[string]any{
		"revoked_by": 999999, "revoked_at": time.Now(),
	})
	t.Logf("POST .../break-glass/%d/revoke (revoked_by forged to 999999): status=%d body=%s", activation.ID, status, body)
	require.Equal(t, http.StatusOK, status)

	updated, err := f.core.Storage().GetBreakGlassActivation(ctx, activation.ID)
	require.NoError(t, err)
	require.NotEqual(t, uint(999999), updated.RevokedBy, "the forged revoked_by must never be persisted")

	realAdminID, err := f.core.GetUserByEmail(ctx, "testadmin@example.com")
	require.NoError(t, err)
	require.Equal(t, realAdminID.ID, updated.RevokedBy, "RevokedBy must be the authenticated caller, not the wire value")

	roleIDs, err := f.core.Storage().GetUserRoleIDsAt(ctx, f.adminID, coreStorage.Scope{ProjectID: f.projectID})
	require.NoError(t, err)
	require.NotContains(t, roleIDs, role.ID, "the emergency role grant must actually be removed")
}

// TestWireActorForgery_CreateMachineIdentityProxy_CreatedByIsAlwaysCaller
// (G80 documented-exception re-verification sweep, 2026-08-25) proves
// CreateMachineIdentityProxy's CreatedBy is now the AUTHENTICATED caller —
// the SAME function already ceiling-checks that caller two lines earlier —
// rather than a wire-supplied value.
func TestWireActorForgery_CreateMachineIdentityProxy_CreatedByIsAlwaysCaller(t *testing.T) {
	f := newMachinePrivilegeCeilingFixture(t)

	status, body := f.do(t, f.assignToken, http.MethodPost, "/api/v1/system/machine-identities", map[string]any{
		"name": "created-by-forge-target", "project_id": f.projectID, "identity_type": "service", "created_by": 999999,
	})
	t.Logf("POST /system/machine-identities (created_by forged to 999999): status=%d body=%s", status, body)
	require.Equal(t, http.StatusOK, status)

	assignUser, err := f.core.GetUserByEmail(context.Background(), "sys_write_roles_assign@example.com")
	require.NoError(t, err)
	machines, err := f.core.Storage().ListMachineIdentities(context.Background(), f.projectID)
	require.NoError(t, err)
	var found *models.MachineIdentity
	for _, m := range machines {
		if m.Name == "created-by-forge-target" {
			found = m
		}
	}
	require.NotNil(t, found, "the machine identity must have been created")
	require.NotEqual(t, uint(999999), found.CreatedBy, "the forged created_by must never be persisted")
	require.Equal(t, assignUser.ID, found.CreatedBy, "CreatedBy must be the authenticated caller, not the wire value")
}
