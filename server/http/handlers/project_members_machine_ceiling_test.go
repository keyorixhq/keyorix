package handlers

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/server/middleware"
	"github.com/stretchr/testify/require"
)

// authzdiff known-06 (historical name D6): AddProjectMember and
// UpdateProjectMember (POST/PUT /api/v1/projects/{id}/members[/{userId}])
// never tagged ctx with core.WithSelfMachineGranter for a machine-authenticated
// actor before calling into core.AddProjectMember/SetProjectMemberRole. Without
// that tag, requireGranterHoldsRolePermissions' checkGranterHoldsPermission
// treats ANY machine actor as an untagged /system-proxy-style relay and
// unconditionally refuses -- case actorIsMachine: return false, nil -- which
// happened to fail CLOSED here (the opposite failure mode from known-01/D1 and
// known-03/D3, which failed OPEN or refused unconditionally in the wrong
// direction). D6 is still a real correctness defect: a machine actor that
// genuinely holds roles.assign (plus every permission the target role bundles)
// at the project's scope could never add or update a project member AS ITSELF,
// contradicting the harness's cross-layer differential (core's own
// AddProjectMember/SetProjectMemberRole never special-cased machine actors this
// way -- only these two HTTP handlers' omission of the tag did).
//
// This file is project_members.go's counterpart to
// groups_members_machine_ceiling_test.go's TestAddGroupMember_* pair, which
// fixed the structurally identical problem for AddGroupMember.
//
// AddProjectMember's error-status switch was ALSO missing an
// errors.Is(err, core.ErrPermissionDenied) case (unlike UpdateProjectMember's,
// which already has one) -- found and fixed in the same commit, since without
// it this ceiling refusal fell through to the switch's 500 default instead of
// 403, which the positive/negative pair below would otherwise not catch.

// projectMemberCeilingFixture creates a fresh core, bootstraps project 1,
// creates a target user to add/update as a member, and a machine identity
// holding actorRoleNames at project 1's scope (so the test can vary whether
// the machine's own authority is sufficient to grant targetRoleName).
func projectMemberCeilingFixture(t *testing.T, suffix string, actorRoleNames []string) (h *CatalogHandler, targetUserID, machineID uint) {
	t.Helper()
	cs := freshCoreS11(t)
	h = NewCatalogHandler(cs)
	bootstrapS11(t, cs, suffix)
	ctx := context.Background()

	target, err := cs.CreateUser(ctx, &core.CreateUserRequest{
		Username: "pmceiling-target-" + suffix, Email: "pmceiling-target-" + suffix + "@example.com",
		DisplayName: "Target", Password: "Kx#Vr9$Mn2!Zp4@Qw",
	})
	require.NoError(t, err)

	machine, err := cs.CreateMachineIdentity(ctx, 1, "pmceiling-machine-"+suffix, core.MachineTypeService, "", "", 0, 0)
	require.NoError(t, err)

	for _, roleName := range actorRoleNames {
		role, err := cs.Storage().GetRoleByName(ctx, roleName)
		require.NoError(t, err)
		require.NoError(t, cs.Storage().AssignMachineRole(ctx, machine.ID, role.ID, storage.Scope{ProjectID: 1}))
	}

	return h, target.ID, machine.ID
}

// machineReqCtx returns r's context with a machine UserContext for machineID
// attached, the way middleware.Authenticate would for a real machine bearer
// token.
func machineReqCtx(r *http.Request, machineID uint) context.Context {
	uc := &middleware.UserContext{
		UserID:            0,
		ActorType:         core.ActorTypeMachine,
		MachineIdentityID: &machineID,
	}
	return context.WithValue(r.Context(), middleware.GetUserContextKey(), uc)
}

// TestAddProjectMember_MachineActorMissingRolePermissionsBlocked: a machine
// actor holding only project_viewer (no roles.assign, so it fails
// requireGranterHoldsRolePermissions' baseline check even once correctly
// resolved against its own permissions) must be refused 403 when adding a
// project_admin member -- not silently succeed with 201, and not 500 (which is
// what the pre-fix missing errors.Is(core.ErrPermissionDenied) case in
// AddProjectMember's switch would have produced even after the ceiling itself
// was fixed).
func TestAddProjectMember_MachineActorMissingRolePermissionsBlocked(t *testing.T) {
	h, targetID, machineID := projectMemberCeilingFixture(t, "addblocked", []string{"project_viewer"})

	body := fmt.Sprintf(`{"user_id":%d,"role":"project_admin"}`, targetID)
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req = req.WithContext(machineReqCtx(req, machineID))
	req = withChiParamS8(req, "id", "1")
	w := httptest.NewRecorder()

	h.AddProjectMember(w, req)

	require.Equal(t, 403, w.Code, "a machine actor holding only project_viewer must be refused when granting project_admin membership, not silently succeed or 500 -- response body: %s", w.Body.String())
}

// TestAddProjectMember_MachineActorHoldingRolePermissionsAllowed: a machine
// actor that itself holds project_admin -- which bundles roles.assign in its
// own RolePermission rows, so holding it trivially satisfies both
// requireGranterHoldsRolePermissions' baseline check and its per-permission
// loop over project_admin's own bundle -- must be allowed to add a
// project_admin member AS ITSELF. Proves the fix resolves the machine's real
// permissions (via the new WithSelfMachineGranter tag) rather than leaving
// every machine actor refused unconditionally.
func TestAddProjectMember_MachineActorHoldingRolePermissionsAllowed(t *testing.T) {
	h, targetID, machineID := projectMemberCeilingFixture(t, "addallowed", []string{"project_admin"})

	body := fmt.Sprintf(`{"user_id":%d,"role":"project_admin"}`, targetID)
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req = req.WithContext(machineReqCtx(req, machineID))
	req = withChiParamS8(req, "id", "1")
	w := httptest.NewRecorder()

	h.AddProjectMember(w, req)

	require.Equal(t, 201, w.Code, "a machine actor holding project_admin must be allowed to add a project_admin member as itself -- response body: %s", w.Body.String())
}

// TestUpdateProjectMember_MachineActorMissingRolePermissionsBlocked: the same
// ceiling gap in UpdateProjectMember (SetProjectMemberRole), exercised via a
// brand-new member (no existing project role) so SetProjectMemberRole's
// len(existing)==0 branch runs requireGranterHoldsRolePermissions exactly like
// AddProjectMember's.
func TestUpdateProjectMember_MachineActorMissingRolePermissionsBlocked(t *testing.T) {
	h, targetID, machineID := projectMemberCeilingFixture(t, "updblocked", []string{"project_viewer"})

	req := httptest.NewRequest("PUT", "/", strings.NewReader(`{"role":"project_admin"}`))
	req = req.WithContext(machineReqCtx(req, machineID))
	req = withChiParamsS8(req, map[string]string{"id": "1", "userId": fmt.Sprintf("%d", targetID)})
	w := httptest.NewRecorder()

	h.UpdateProjectMember(w, req)

	require.Equal(t, 403, w.Code, "a machine actor holding only project_viewer must be refused when granting project_admin membership via update, not silently succeed -- response body: %s", w.Body.String())
}

// TestUpdateProjectMember_MachineActorHoldingRolePermissionsAllowed is the
// UpdateProjectMember positive control mirroring
// TestAddProjectMember_MachineActorHoldingRolePermissionsAllowed above.
func TestUpdateProjectMember_MachineActorHoldingRolePermissionsAllowed(t *testing.T) {
	h, targetID, machineID := projectMemberCeilingFixture(t, "updallowed", []string{"project_admin"})

	req := httptest.NewRequest("PUT", "/", strings.NewReader(`{"role":"project_admin"}`))
	req = req.WithContext(machineReqCtx(req, machineID))
	req = withChiParamsS8(req, map[string]string{"id": "1", "userId": fmt.Sprintf("%d", targetID)})
	w := httptest.NewRecorder()

	h.UpdateProjectMember(w, req)

	require.Equal(t, 200, w.Code, "a machine actor holding project_admin must be allowed to grant project_admin membership via update as itself -- response body: %s", w.Body.String())
}
