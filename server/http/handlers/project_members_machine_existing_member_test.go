package handlers

// project_members_machine_existing_member_test.go — PUT
// /projects/{id}/members/{userId} by a machine on an EXISTING member (#3990).
// project_members_machine_ceiling_test.go covers a brand-new member, where
// SetProjectMemberRole always judged the ceiling. On an existing member a no-op
// (the member already holds exactly the named role) or a narrowing (the member
// holds [A, B], the request names A) adds nothing, so no ceiling ran and a
// machine holding roles.assign alone answered 200 and, for a narrowing, removed
// B. A machine is now judged on the named role there too: refused 403 without
// that role's permissions, allowed with them (main's ceiling-based policy).

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/identity"
)

// assignerOnlyRole creates a role bundling roles.assign and nothing else:
// enough to pass the route gate and the ceiling's baseline, not enough to grant
// project_viewer (secrets.read and the rest of its bundle).
func assignerOnlyRole(t *testing.T, cs *core.KeyorixCore, name string) uint {
	t.Helper()
	ctx := context.Background()
	folded, err := identity.NewFoldedName(name)
	require.NoError(t, err)
	role, err := cs.Storage().CreateRole(ctx, folded, "roles.assign only")
	require.NoError(t, err)
	perms, err := cs.Storage().ListPermissions(ctx)
	require.NoError(t, err)
	var assignPermID uint
	for _, p := range perms {
		if p.Name == "roles.assign" {
			assignPermID = p.ID
		}
	}
	require.NotZero(t, assignPermID, "roles.assign must be seeded")
	require.NoError(t, cs.Storage().AssignPermissionToRole(ctx, role.ID, assignPermID))
	return role.ID
}

// existingMemberFixture: project 1, a target user already holding targetRoles at
// project 1, and a machine holding machineRoleIDs there.
func existingMemberFixture(t *testing.T, suffix string, targetRoles []string, machineRoleIDs func(cs *core.KeyorixCore) []uint) (cs *core.KeyorixCore, h *CatalogHandler, targetID, machineID uint) {
	t.Helper()
	cs = freshCoreS11(t)
	h = NewCatalogHandler(cs)
	bootstrapS11(t, cs, suffix)
	ctx := context.Background()

	target, err := cs.CreateUser(ctx, &core.CreateUserRequest{
		Username: "pmexisting-target-" + suffix, Email: "pmexisting-target-" + suffix + "@example.com",
		DisplayName: "Target", Password: "Kx#Vr9$Mn2!Zp4@Qw",
	})
	require.NoError(t, err)
	for _, name := range targetRoles {
		role, err := cs.Storage().GetRoleByName(ctx, name)
		require.NoError(t, err)
		require.NoError(t, cs.Storage().AssignRole(ctx, target.ID, role.ID, storage.Scope{ProjectID: 1}))
	}

	machine, err := cs.CreateMachineIdentity(ctx, 1, "pmexisting-machine-"+suffix, core.MachineTypeService, "", "", 0, 0)
	require.NoError(t, err)
	for _, id := range machineRoleIDs(cs) {
		require.NoError(t, cs.Storage().AssignMachineRole(ctx, machine.ID, id, storage.Scope{ProjectID: 1}))
	}
	return cs, h, target.ID, machine.ID
}

func roleIDsByName(t *testing.T, names ...string) func(cs *core.KeyorixCore) []uint {
	return func(cs *core.KeyorixCore) []uint {
		var ids []uint
		for _, n := range names {
			role, err := cs.Storage().GetRoleByName(context.Background(), n)
			require.NoError(t, err)
			ids = append(ids, role.ID)
		}
		return ids
	}
}

func putMemberRoleAsMachine(h *CatalogHandler, machineID, targetID uint, role string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPut, "/", strings.NewReader(fmt.Sprintf(`{"role":%q}`, role)))
	req = req.WithContext(machineReqCtx(req, machineID))
	req = withChiParamsS8(req, map[string]string{"id": "1", "userId": fmt.Sprintf("%d", targetID)})
	w := httptest.NewRecorder()
	h.UpdateProjectMember(w, req)
	return w
}

func projectRoleNames(t *testing.T, cs *core.KeyorixCore, userID uint) []string {
	t.Helper()
	members, err := cs.ListProjectMembers(context.Background(), 1)
	require.NoError(t, err)
	var held []string
	for _, m := range members {
		if m.UserID == userID {
			held = append(held, m.RoleName)
		}
	}
	return held
}

func TestUpdateProjectMember_MachineExistingMember_JudgedByCeiling(t *testing.T) {
	assignerOnly := func(name string) func(cs *core.KeyorixCore) []uint {
		return func(cs *core.KeyorixCore) []uint { return []uint{assignerOnlyRole(t, cs, name)} }
	}

	t.Run("no-op without the role's permissions is refused", func(t *testing.T) {
		cs, h, targetID, machineID := existingMemberFixture(t, "noopblocked", []string{"project_viewer"}, assignerOnly("pmexisting-assigner-noop"))
		w := putMemberRoleAsMachine(h, machineID, targetID, "project_viewer")
		require.Equal(t, http.StatusForbidden, w.Code, "body: %s", w.Body.String())
		assert.Contains(t, w.Body.String(), "you do not hold permission")
		assert.ElementsMatch(t, []string{"project_viewer"}, projectRoleNames(t, cs, targetID))
	})
	t.Run("narrowing without the role's permissions is refused and removes nothing", func(t *testing.T) {
		cs, h, targetID, machineID := existingMemberFixture(t, "narrowblocked", []string{"project_viewer", "project_developer"}, assignerOnly("pmexisting-assigner-narrow"))
		w := putMemberRoleAsMachine(h, machineID, targetID, "project_viewer")
		require.Equal(t, http.StatusForbidden, w.Code, "body: %s", w.Body.String())
		assert.Contains(t, w.Body.String(), "you do not hold permission")
		assert.ElementsMatch(t, []string{"project_viewer", "project_developer"}, projectRoleNames(t, cs, targetID),
			"a refused narrowing must not remove any role")
	})
	// Positive controls: a machine that holds the named role's permissions keeps
	// main's ceiling-based allow for the same two shapes.
	t.Run("no-op with the role's permissions is allowed", func(t *testing.T) {
		cs, h, targetID, machineID := existingMemberFixture(t, "noopallowed", []string{"project_viewer"}, roleIDsByName(t, "project_admin"))
		w := putMemberRoleAsMachine(h, machineID, targetID, "project_viewer")
		require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
		assert.ElementsMatch(t, []string{"project_viewer"}, projectRoleNames(t, cs, targetID))
	})
	t.Run("narrowing with the role's permissions is allowed", func(t *testing.T) {
		cs, h, targetID, machineID := existingMemberFixture(t, "narrowallowed", []string{"project_viewer", "project_developer"}, roleIDsByName(t, "project_admin"))
		w := putMemberRoleAsMachine(h, machineID, targetID, "project_viewer")
		require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
		assert.ElementsMatch(t, []string{"project_viewer"}, projectRoleNames(t, cs, targetID))
	})
}

// TestAddProjectMember_HumanFailingCeilingAnswers403: the POST status fix for a
// human caller. AddProjectMember's error switch had no ErrPermissionDenied case,
// so a ceiling refusal answered 500; main fixed the switch (a0cdf37be) and
// pinned it for a machine caller only.
func TestAddProjectMember_HumanFailingCeilingAnswers403(t *testing.T) {
	cs := freshCoreS11(t)
	h := NewCatalogHandler(cs)
	bootstrapS11(t, cs, "humanceil")
	ctx := context.Background()

	actor, err := cs.CreateUser(ctx, &core.CreateUserRequest{
		Username: "pmhuman-actor", Email: "pmhuman-actor@example.com",
		DisplayName: "Actor", Password: "Kx#Vr9$Mn2!Zp4@Qw",
	})
	require.NoError(t, err)
	target, err := cs.CreateUser(ctx, &core.CreateUserRequest{
		Username: "pmhuman-target", Email: "pmhuman-target@example.com",
		DisplayName: "Target", Password: "Kx#Vr9$Mn2!Zp4@Qw",
	})
	require.NoError(t, err)
	require.NoError(t, cs.Storage().AssignRole(ctx, actor.ID, assignerOnlyRole(t, cs, "pmhuman-assigner"), storage.Scope{ProjectID: 1}))

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(fmt.Sprintf(`{"user_id":%d,"role":"project_viewer"}`, target.ID)))
	req = withUserCtxID2(req, actor.ID, "pmhuman-actor")
	req = withChiParamsS8(req, map[string]string{"id": "1"})
	w := httptest.NewRecorder()
	h.AddProjectMember(w, req)

	require.Equal(t, http.StatusForbidden, w.Code, "a ceiling refusal is a 403, not a 500: %s", w.Body.String())
	assert.Empty(t, projectRoleNames(t, cs, target.ID), "nothing may be granted")
}
