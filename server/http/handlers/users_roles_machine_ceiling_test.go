package handlers

import (
	"context"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// INV-CORE-direct-machine-grant-handlers-tag-self-granter, found by
// TestEveryDirectMachineGrantEntryTagsSelfGranter: UpdateUserRoles
// (PUT /api/v1/users/{id}/roles) passed `actor.ActorKind() == machine` to
// core.SetUserRoles but never tagged ctx with core.WithSelfMachineGranter, so a
// directly authenticated machine actor was refused unconditionally by
// requireGranterHoldsRolePermissions (fail-closed) even when it genuinely holds
// every permission of the role it replaces the user's roles with. Same shape as
// project_members_machine_ceiling_test.go (known-06) and AddGroupMember.

func putUserRolesAsMachine(t *testing.T, actorRoleNames []string, suffix string) *httptest.ResponseRecorder {
	t.Helper()
	cf, targetID, machineID := projectMemberCeilingFixture(t, suffix, actorRoleNames)
	h := NewUsersRolesHandler(cf.coreService)
	role, err := cf.coreService.Storage().GetRoleByName(context.Background(), "project_admin")
	require.NoError(t, err)

	body := fmt.Sprintf(`{"role_ids":[%d],"project_id":1}`, role.ID)
	req := httptest.NewRequest("PUT", "/", strings.NewReader(body))
	req = req.WithContext(machineReqCtx(req, machineID))
	req = withChiParamS8(req, "id", fmt.Sprintf("%d", targetID))
	w := httptest.NewRecorder()
	h.UpdateUserRoles(w, req)
	return w
}

// A machine actor holding only project_viewer cannot replace a user's project
// roles with project_admin: refused 403 by the ceiling (negative control; green
// before and after the tag fix, it proves the ceiling is still evaluated
// against the machine's own permissions).
func TestUpdateUserRoles_MachineActorMissingRolePermissionsBlocked(t *testing.T) {
	w := putUserRolesAsMachine(t, []string{"project_viewer"}, "urblocked")
	require.Equal(t, 403, w.Code, "response body: %s", w.Body.String())
}

// A machine actor holding project_admin (which bundles roles.assign and every
// permission project_admin grants) must be allowed to do it as itself. Fails
// with 403 before the WithSelfMachineGranter tag is added.
func TestUpdateUserRoles_MachineActorHoldingRolePermissionsAllowed(t *testing.T) {
	w := putUserRolesAsMachine(t, []string{"project_admin"}, "urallowed")
	require.Equal(t, 200, w.Code, "response body: %s", w.Body.String())
}
