package handlers

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/storage"
)

// CORE-ACTOR-RACE-1 item 4: what DELETE /api/v1/projects/{id}/members/{userId}
// does today for a machine token. Facts pinned, behaviour NOT changed (whether a
// machine may remove members is a policy question left to the coordinator):
//
//   - The route's only gate is RequireScopedPermission(roles.assign, project scope)
//     (router.go), which a machine holding a project role that bundles roles.assign
//     passes like a human does.
//   - core.RemoveProjectMember takes no machine-actor argument, has no privilege
//     ceiling for anyone (a project-scoped roles.assign holder can remove a project
//     admin), and refuses only "not a member" (404) and the project's last
//     roles.assign holder (409).
//   - The removal is attributed in the role.removed audit rows as the machine:
//     actor_type machine_identity, machine_identity_id set, user_id NULL (the
//     handler passes userCtx.UserID, which is 0 for a machine; emitAudit stamps the
//     machine from the context the auth middleware tags, auth.go).
//
// The handler is called directly, so the route gate is not exercised here; the
// context carries what middleware.Authenticate sets for a machine bearer token:
// the UserContext and core.WithActorType/WithMachineActor (auth.go).

func machineRemoveReqCtx(r *http.Request, machineID uint) context.Context {
	ctx := machineReqCtx(r, machineID)
	ctx = core.WithActorType(ctx, core.ActorTypeMachine)
	return core.WithMachineActor(ctx, machineID)
}

func TestRemoveProjectMember_MachineActor_AllowedAndAttributedToTheMachine(t *testing.T) {
	cases := []struct {
		name, targetRole string
		otherAdmin       bool
	}{
		{name: "viewer member", targetRole: "project_viewer"},
		// A human project admin, with another human admin left so the last-admin
		// guard does not apply: no ceiling stops the machine.
		{name: "human project admin", targetRole: "project_admin", otherAdmin: true},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, targetID, machineID := projectMemberCeilingFixture(t, fmt.Sprintf("rm%d", i), []string{"project_admin"})
			cs := h.coreService
			ctx := context.Background()
			st := cs.Storage()
			role, err := st.GetRoleByName(ctx, tc.targetRole)
			require.NoError(t, err)
			require.NoError(t, st.AssignRole(ctx, targetID, role.ID, storage.Scope{ProjectID: 1}))
			if tc.otherAdmin {
				other, err := cs.CreateUser(ctx, &core.CreateUserRequest{
					Username: fmt.Sprintf("rm-other-%d", i), Email: fmt.Sprintf("rm-other-%d@example.com", i),
					DisplayName: "Other", Password: "Kx#Vr9$Mn2!Zp4@Qw",
				})
				require.NoError(t, err)
				require.NoError(t, st.AssignRole(ctx, other.ID, role.ID, storage.Scope{ProjectID: 1}))
			}

			req := httptest.NewRequest("DELETE", "/", nil)
			req = req.WithContext(machineRemoveReqCtx(req, machineID))
			req = withChiParamsS8(req, map[string]string{"id": "1", "userId": fmt.Sprintf("%d", targetID)})
			w := httptest.NewRecorder()
			h.RemoveProjectMember(w, req)

			require.Equal(t, http.StatusOK, w.Code, "today a machine holding roles.assign removes members: %s", w.Body.String())
			left, err := st.GetUserRoleIDsExact(ctx, targetID, storage.Scope{ProjectID: 1})
			require.NoError(t, err)
			require.Empty(t, left, "the member's project roles must be gone")

			action := core.EventRoleRemoved
			pid := uint(1)
			rows, _, err := st.GetAuditLogs(ctx, &storage.AuditFilter{Action: &action, ProjectID: &pid, Page: 1, PageSize: 50})
			require.NoError(t, err)
			require.NotEmpty(t, rows, "the removal must leave a role.removed row")
			for _, ev := range rows {
				require.Equal(t, core.ActorTypeMachine, ev.ActorType, "role.removed row %d", ev.ID)
				require.NotNil(t, ev.MachineIdentityID, "role.removed row %d must name the machine", ev.ID)
				require.Equal(t, machineID, *ev.MachineIdentityID)
				require.Nil(t, ev.UserID, "a machine's removal must not be attributed to a user")
			}
		})
	}
}

// Contrast with the add route: the same machine is ceiling-checked there, and a
// machine without roles.assign's bundle gets 403 (TestAddProjectMember_
// MachineActorMissingRolePermissionsBlocked); the remove route has no such check
// below the route gate. Here: the last-admin guard is the one refusal that applies
// to a machine too (409).
func TestRemoveProjectMember_MachineActor_LastAdminStillRefused(t *testing.T) {
	h, targetID, machineID := projectMemberCeilingFixture(t, "rmlast", []string{"project_viewer"})
	cs := h.coreService
	ctx := context.Background()
	role, err := cs.Storage().GetRoleByName(ctx, "project_admin")
	require.NoError(t, err)
	require.NoError(t, cs.Storage().AssignRole(ctx, targetID, role.ID, storage.Scope{ProjectID: 1}))

	req := httptest.NewRequest("DELETE", "/", nil)
	req = req.WithContext(machineRemoveReqCtx(req, machineID))
	req = withChiParamsS8(req, map[string]string{"id": "1", "userId": fmt.Sprintf("%d", targetID)})
	w := httptest.NewRecorder()
	h.RemoveProjectMember(w, req)

	require.Equal(t, http.StatusConflict, w.Code, w.Body.String())
}
