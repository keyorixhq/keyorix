package handlers

import (
	"context"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/server/middleware"
	"github.com/stretchr/testify/require"
)

// Part 3 usage-based guard pass finding: AddGroupMember (POST
// /api/v1/groups/{id}/members) hardcoded actorIsMachine=false when calling
// core.AddUserToGroup, regardless of the real authenticated caller's actor
// kind. AddUserToGroup's own ceiling check is gated by
// `actorID != 0 || actorIsMachine` -- for a machine caller (UserID==0 per
// ADR-030) the hardcoded false made this evaluate false, silently skipping
// the entire per-role authority-ceiling check (validateGroupJoinRoles) for
// every machine-authenticated request, letting a machine identity holding
// only roles.assign add a user to ANY group regardless of what roles that
// group confers. Fixed by deriving actorIsMachine via isMachineActor(r) and
// tagging ctx with WithSelfMachineGranter so a genuinely-permissioned
// machine caller can still succeed.
func TestAddGroupMember_MachineActorMissingRolePermissionsBlocked(t *testing.T) {
	cs := freshCoreS11(t)
	h, err := NewGroupHandler(cs)
	require.NoError(t, err)
	bootstrapS11(t, cs, "machceiling")
	ctx := context.Background()

	target, err := cs.CreateUser(ctx, &core.CreateUserRequest{
		Username: "machceiling-target", Email: "machceiling-target@example.com",
		DisplayName: "Target", Password: "Kx#Vr9$Mn2!Zp4@Qw",
	})
	require.NoError(t, err)

	machine, err := cs.CreateMachineIdentity(ctx, 1, "machceiling-machine", core.MachineTypeService, "", "", 0, 0)
	require.NoError(t, err)

	grp, err := cs.CreateGroup(ctx, 1, &core.CreateGroupRequest{Name: "machceiling-admin-group"})
	require.NoError(t, err)

	viewerRole, err := cs.Storage().GetRoleByName(ctx, "project_viewer")
	require.NoError(t, err)
	adminRole, err := cs.Storage().GetRoleByName(ctx, "project_admin")
	require.NoError(t, err)
	// The machine holds only project_viewer -- nowhere near enough to grant
	// membership in a group that confers project_admin.
	require.NoError(t, cs.Storage().AssignMachineRole(ctx, machine.ID, viewerRole.ID, storage.Scope{ProjectID: 1}))
	require.NoError(t, cs.Storage().AssignRoleToGroupWithExpiry(ctx, grp.ID, adminRole.ID, storage.Scope{ProjectID: 1}, time.Now().Add(time.Hour)))

	uc := &middleware.UserContext{
		UserID:            0,
		ActorType:         core.ActorTypeMachine,
		MachineIdentityID: &machine.ID,
	}
	body := `{"user_id":` + fmt.Sprintf("%d", target.ID) + `,"project_id":1}`
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req = req.WithContext(context.WithValue(req.Context(), middleware.GetUserContextKey(), uc))
	req = withChiParamS8(req, "id", fmt.Sprintf("%d", grp.ID))
	w := httptest.NewRecorder()

	h.AddGroupMember(w, req)

	require.Equal(t, 403, w.Code, "a machine actor holding only project_viewer must be refused when the target group confers project_admin, not silently succeed with 200 -- response body: %s", w.Body.String())
}

// Positive control: a machine actor that DOES hold the group's role's full
// permission set must still be allowed to add a member -- proving the fix
// resolves the machine's real permissions rather than blanket-refusing every
// machine caller.
func TestAddGroupMember_MachineActorHoldingRolePermissionsAllowed(t *testing.T) {
	cs := freshCoreS11(t)
	h, err := NewGroupHandler(cs)
	require.NoError(t, err)
	bootstrapS11(t, cs, "machceiling2")
	ctx := context.Background()

	target, err := cs.CreateUser(ctx, &core.CreateUserRequest{
		Username: "machceiling2-target", Email: "machceiling2-target@example.com",
		DisplayName: "Target", Password: "Kx#Vr9$Mn2!Zp4@Qw",
	})
	require.NoError(t, err)

	machine, err := cs.CreateMachineIdentity(ctx, 1, "machceiling2-machine", core.MachineTypeService, "", "", 0, 0)
	require.NoError(t, err)

	grp, err := cs.CreateGroup(ctx, 1, &core.CreateGroupRequest{Name: "machceiling2-dev-group"})
	require.NoError(t, err)

	devRole, err := cs.Storage().GetRoleByName(ctx, "project_developer")
	require.NoError(t, err)
	require.NoError(t, cs.Storage().AssignMachineRole(ctx, machine.ID, devRole.ID, storage.Scope{ProjectID: 1}))
	require.NoError(t, cs.Storage().AssignRoleToGroupWithExpiry(ctx, grp.ID, devRole.ID, storage.Scope{ProjectID: 1}, time.Now().Add(time.Hour)))

	uc := &middleware.UserContext{
		UserID:            0,
		ActorType:         core.ActorTypeMachine,
		MachineIdentityID: &machine.ID,
	}
	body := `{"user_id":` + fmt.Sprintf("%d", target.ID) + `,"project_id":1}`
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req = req.WithContext(context.WithValue(req.Context(), middleware.GetUserContextKey(), uc))
	req = withChiParamS8(req, "id", fmt.Sprintf("%d", grp.ID))
	w := httptest.NewRecorder()

	h.AddGroupMember(w, req)

	require.Equal(t, 200, w.Code, "a machine actor holding the group's own role's full permission set must be allowed to add a member -- response body: %s", w.Body.String())
}
