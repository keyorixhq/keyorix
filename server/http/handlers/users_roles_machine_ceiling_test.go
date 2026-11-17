package handlers

import (
	"context"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/storage"
)

// INV-CORE-direct-machine-grant-handlers-tag-self-granter, found by
// TestEveryDirectMachineGrantEntryTagsSelfGranter: UpdateUserRoles
// (PUT /api/v1/users/{id}/roles) passed `actor.ActorKind() == machine` to
// core.SetUserRoles but never tagged ctx with core.WithSelfMachineGranter, so a
// directly authenticated machine actor was refused unconditionally by
// requireGranterHoldsRolePermissions (fail-closed) even when it genuinely holds
// every permission of the role it replaces the user's roles with. Same shape as
// project_members_machine_ceiling_test.go (known-06) and AddGroupMember.

// putUserRolesAsMachine replaces the target user's project-1 roles with
// project_admin, acting as a machine that holds machineRoleIDs at project 1.
func putUserRolesAsMachine(t *testing.T, suffix string, machineRoleIDs func(cs *core.KeyorixCore) []uint) *httptest.ResponseRecorder {
	t.Helper()
	cf, targetID, machineID := projectMemberCeilingFixture(t, suffix, nil)
	cs := cf.coreService
	ctx := context.Background()
	for _, id := range machineRoleIDs(cs) {
		require.NoError(t, cs.Storage().AssignMachineRole(ctx, machineID, id, storage.Scope{ProjectID: 1}))
	}
	h := NewUsersRolesHandler(cs)
	role, err := cs.Storage().GetRoleByName(ctx, "project_admin")
	require.NoError(t, err)

	body := fmt.Sprintf(`{"role_ids":[%d],"project_id":1}`, role.ID)
	req := httptest.NewRequest("PUT", "/", strings.NewReader(body))
	req = req.WithContext(machineReqCtx(req, machineID))
	req = withChiParamS8(req, "id", fmt.Sprintf("%d", targetID))
	w := httptest.NewRecorder()
	h.UpdateUserRoles(w, req)
	return w
}

// A machine actor holding roles.assign and nothing else cannot replace a
// user's project roles with project_admin. It passes the roles.assign
// baseline, so the 403 must come from the per-permission loop (a permission of
// project_admin's bundle other than roles.assign), which proves the ceiling is
// evaluated against the machine's own permissions. Before the tag fix the
// machine was refused at the baseline (the error names "roles.assign"), so this
// test is red there too.
func TestUpdateUserRoles_MachineActorMissingRolePermissionsBlocked(t *testing.T) {
	w := putUserRolesAsMachine(t, "urblocked", func(cs *core.KeyorixCore) []uint {
		return []uint{assignerOnlyRole(t, cs, "ur-assigner-only")}
	})
	require.Equal(t, 403, w.Code, "response body: %s", w.Body.String())
	require.Contains(t, w.Body.String(), "you do not hold permission", "the refusal must be the grant ceiling")
	require.NotContains(t, w.Body.String(), "roles.assign",
		"the machine holds roles.assign, so the refusal must name a permission it lacks, not the baseline")
}

// A machine actor holding project_admin (which bundles roles.assign and every
// permission project_admin grants) must be allowed to do it as itself. Fails
// with 403 before the WithSelfMachineGranter tag is added.
func TestUpdateUserRoles_MachineActorHoldingRolePermissionsAllowed(t *testing.T) {
	w := putUserRolesAsMachine(t, "urallowed", func(cs *core.KeyorixCore) []uint {
		role, err := cs.Storage().GetRoleByName(context.Background(), "project_admin")
		require.NoError(t, err)
		return []uint{role.ID}
	})
	require.Equal(t, 200, w.Code, "response body: %s", w.Body.String())
}
