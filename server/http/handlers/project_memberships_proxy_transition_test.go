// project_memberships_proxy_transition_test.go — G80 Wave 2 (#1546, ADR-088).
// TransitionMembershipProxy used to persist the wire body's ENTIRE membership
// row via a raw conditional write with no authority check and no role-grant
// side effect — a caller reaching this route directly could activate an
// admin-tier membership (bypassing RequireAuthorityForRole entirely) and the
// role grant the legitimate path (core.TransitionMembership) applies as a
// side effect of activation would never be created. Fixed by full delegation
// to core.TransitionMembership, which applies both.
package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/identity"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/server/middleware"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupTransitionMembershipFixture seeds a project, a target member, and a
// PROVISIONED membership carrying an admin-tier role ("project_admin") ready
// to transition to "active" — the one transition core.TransitionMembership
// gates with RequireAuthorityForRole. Returns the core service, the
// membership, and the seeded admin (for building authorized requests).
func setupTransitionMembershipFixture(t *testing.T) (cs *core.KeyorixCore, membership *models.ProjectMembership, admin *models.User) {
	t.Helper()
	cs, _ = freshCoreS12WithAdmin(t)
	ctx := context.Background()

	var err error
	admin, err = cs.GetUserByUsername(ctx, "testuser_s12")
	require.NoError(t, err)

	project, err := cs.Storage().CreateProject(ctx, &models.Project{Name: "g80-1546-project"})
	require.NoError(t, err)

	if _, err := cs.Storage().GetRoleByName(ctx, "project_admin"); err != nil {
		projectAdminName, err := identity.NewFoldedName("project_admin")
		require.NoError(t, err)
		_, err = cs.Storage().CreateRole(ctx, projectAdminName, "test")
		require.NoError(t, err)
	}

	target, err := cs.CreateUser(ctx, &core.CreateUserRequest{
		Username: "g80-1546-target", Email: "g80-1546-target@example.com",
		DisplayName: "G80 1546 Target", Password: "NotArealpassword123!",
	})
	require.NoError(t, err)

	membership, err = cs.Storage().CreateProjectMembership(ctx, &models.ProjectMembership{
		ProjectID: project.ID, UserID: target.ID, Role: "project_admin", State: core.MembershipProvisioned,
	})
	require.NoError(t, err)
	return cs, membership, admin
}

// TestTransitionMembershipProxy_ActivatingAdminRoleRequiresAuthority_RealServer
// is #1546's ceiling half: an actor with NO admin authority at the project
// attempts to activate an admin-tier ("project_admin") membership directly
// through the raw proxy. Must be refused, and the membership must remain
// provisioned (not silently activated).
func TestTransitionMembershipProxy_ActivatingAdminRoleRequiresAuthority_RealServer(t *testing.T) {
	cs, membership, _ := setupTransitionMembershipFixture(t)
	h := NewCatalogHandler(cs)
	ctx := context.Background()

	nobody, err := cs.CreateUser(ctx, &core.CreateUserRequest{
		Username: "g80-1546-nobody", Email: "g80-1546-nobody@example.com",
		DisplayName: "G80 1546 Nobody", Password: "NotArealpassword123!",
	})
	require.NoError(t, err)

	body, err := json.Marshal(map[string]interface{}{
		"membership": map[string]interface{}{"id": membership.ID, "project_id": membership.ProjectID, "state": core.MembershipActive},
		"from_state": core.MembershipProvisioned,
	})
	require.NoError(t, err)
	req := httptest.NewRequest("PUT", "/", bytes.NewReader(body))
	uc := &middleware.UserContext{UserID: nobody.ID}
	req = req.WithContext(context.WithValue(req.Context(), middleware.GetUserContextKey(), uc))
	req = withChiParams(req, map[string]string{"id": machineUintToStr(membership.ID)})
	w := httptest.NewRecorder()
	h.TransitionMembershipProxy(w, req)
	assert.NotEqual(t, 200, w.Code, "activating an admin-tier membership without authority must be refused: %s", w.Body.String())

	reloaded, err := cs.Storage().GetProjectMembership(ctx, membership.ID)
	require.NoError(t, err)
	assert.Equal(t, core.MembershipProvisioned, reloaded.State, "the membership must remain provisioned, not silently activated")

	ids, err := cs.Storage().GetUserRoleIDsExact(ctx, membership.UserID, core.Scope{ProjectID: membership.ProjectID})
	require.NoError(t, err)
	assert.Empty(t, ids, "no role grant may exist for a rejected activation")
}

// TestTransitionMembershipProxy_ActivationGrantsRole_RealServer is #1546's
// side-effect half and the positive control: an actor WITH admin authority at
// the project activates the same admin-tier membership, and the role grant
// core.TransitionMembership applies as a side effect of activation must
// actually be created — not just the membership row flipped to active.
func TestTransitionMembershipProxy_ActivationGrantsRole_RealServer(t *testing.T) {
	cs, membership, admin := setupTransitionMembershipFixture(t)
	h := NewCatalogHandler(cs)
	ctx := context.Background()

	body, err := json.Marshal(map[string]interface{}{
		"membership": map[string]interface{}{"id": membership.ID, "project_id": membership.ProjectID, "state": core.MembershipActive},
		"from_state": core.MembershipProvisioned,
	})
	require.NoError(t, err)
	req := httptest.NewRequest("PUT", "/", bytes.NewReader(body))
	uc := &middleware.UserContext{UserID: admin.ID}
	req = req.WithContext(context.WithValue(req.Context(), middleware.GetUserContextKey(), uc))
	req = withChiParams(req, map[string]string{"id": machineUintToStr(membership.ID)})
	w := httptest.NewRecorder()
	h.TransitionMembershipProxy(w, req)
	require.Equal(t, 200, w.Code, "an authorized admin activating the membership must succeed: %s", w.Body.String())

	reloaded, err := cs.Storage().GetProjectMembership(ctx, membership.ID)
	require.NoError(t, err)
	assert.Equal(t, core.MembershipActive, reloaded.State)
	require.NotNil(t, reloaded.ActivatedAt)

	role, err := cs.Storage().GetRoleByName(ctx, "project_admin")
	require.NoError(t, err)
	ids, err := cs.Storage().GetUserRoleIDsExact(ctx, membership.UserID, core.Scope{ProjectID: membership.ProjectID})
	require.NoError(t, err)
	assert.Contains(t, ids, role.ID, "activation must grant the membership's role, not just flip the membership's own state")
}
