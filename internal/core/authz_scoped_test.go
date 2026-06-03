package core_test

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/testhelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Seeded role IDs from the RBAC test helper.
const (
	roleSuperAdmin = uint(1)
	roleAdmin      = uint(2)
	roleEditor     = uint(3) // secrets.read, secrets.write
	roleViewer     = uint(4) // secrets.read
)

func ptr(u uint) *uint { return &u }

// assignScoped inserts a user_role row at an exact project/environment scope.
func assignScoped(t *testing.T, h *testhelper.RBACTestHelper, userID, roleID, projectID, environmentID uint) {
	t.Helper()
	require.NoError(t, h.DB.Create(&models.UserRole{
		UserID: userID, RoleID: roleID, ProjectID: projectID, EnvironmentID: environmentID,
	}).Error)
}

func TestAuthorize_ProjectScopedDeniesOtherProjects(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	u := h.CreateTestUser(t, "viewerA", 100)
	h.AssignUserRole(t, u.ID, roleViewer, ptr(1)) // viewer on project 1 (all envs)

	ctx := context.Background()
	allowed, err := h.CoreService.Authorize(ctx, u.ID, "secrets.read", core.Scope{ProjectID: 1})
	require.NoError(t, err)
	assert.True(t, allowed, "viewer should read in its own project")

	allowed, err = h.CoreService.Authorize(ctx, u.ID, "secrets.read", core.Scope{ProjectID: 2})
	require.NoError(t, err)
	assert.False(t, allowed, "viewer must not read in another project")

	allowed, err = h.CoreService.Authorize(ctx, u.ID, "secrets.write", core.Scope{ProjectID: 1})
	require.NoError(t, err)
	assert.False(t, allowed, "viewer has no write even in its own project")
}

func TestAuthorize_ProjectWideGrantCoversAllEnvironments(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	u := h.CreateTestUser(t, "editorP", 101)
	h.AssignUserRole(t, u.ID, roleEditor, ptr(1)) // editor on project 1, all envs

	ctx := context.Background()
	for _, env := range []uint{1, 2, 3} {
		allowed, err := h.CoreService.Authorize(ctx, u.ID, "secrets.write", core.Scope{ProjectID: 1, EnvironmentID: env})
		require.NoError(t, err)
		assert.True(t, allowed, "project-wide editor should write in every environment (env %d)", env)
	}
}

func TestAuthorize_EnvironmentScopedIsExact(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	u := h.CreateTestUser(t, "editorProd", 102)
	assignScoped(t, h, u.ID, roleEditor, 1, 1) // editor only on project 1 / env 1

	ctx := context.Background()

	allowed, err := h.CoreService.Authorize(ctx, u.ID, "secrets.write", core.Scope{ProjectID: 1, EnvironmentID: 1})
	require.NoError(t, err)
	assert.True(t, allowed, "editor writes in its exact environment")

	allowed, err = h.CoreService.Authorize(ctx, u.ID, "secrets.write", core.Scope{ProjectID: 1, EnvironmentID: 2})
	require.NoError(t, err)
	assert.False(t, allowed, "editor must not write in a sibling environment")

	allowed, err = h.CoreService.Authorize(ctx, u.ID, "secrets.write", core.Scope{ProjectID: 1})
	require.NoError(t, err)
	assert.False(t, allowed, "an env-specific grant must not satisfy a project-wide action")
}

func TestAuthorize_GroupInheritedRole(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	u := h.CreateTestUser(t, "groupy", 103)
	g := h.CreateTestGroup(t, "readers", "readers group", 50)
	h.AssignUserToGroup(t, u.ID, g.ID)
	require.NoError(t, h.DB.Create(&models.GroupRole{
		GroupID: g.ID, RoleID: roleViewer, ProjectID: 2, EnvironmentID: 0,
	}).Error)

	ctx := context.Background()
	allowed, err := h.CoreService.Authorize(ctx, u.ID, "secrets.read", core.Scope{ProjectID: 2})
	require.NoError(t, err)
	assert.True(t, allowed, "user should inherit the group's project-2 viewer role")

	allowed, err = h.CoreService.Authorize(ctx, u.ID, "secrets.read", core.Scope{ProjectID: 1})
	require.NoError(t, err)
	assert.False(t, allowed, "group grant must not leak to other projects")
}

func TestAuthorize_GlobalAdminBypassesScope(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	u := h.CreateTestUser(t, "rootuser", 104)
	h.AssignUserRole(t, u.ID, roleAdmin, nil) // global admin (project 0)

	ctx := context.Background()
	for _, sc := range []core.Scope{{}, {ProjectID: 1}, {ProjectID: 2, EnvironmentID: 3}, {ProjectID: 9, EnvironmentID: 9}} {
		allowed, err := h.CoreService.Authorize(ctx, u.ID, "secrets.delete", sc)
		require.NoError(t, err)
		assert.True(t, allowed, "global admin bypasses scope for %+v", sc)
	}
}

func TestAuthorize_ProjectScopedAdminDoesNotBypassElsewhere(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	u := h.CreateTestUser(t, "projadmin", 105)
	h.AssignUserRole(t, u.ID, roleAdmin, ptr(1)) // admin only on project 1

	ctx := context.Background()
	allowed, err := h.CoreService.Authorize(ctx, u.ID, "secrets.delete", core.Scope{ProjectID: 1, EnvironmentID: 2})
	require.NoError(t, err)
	assert.True(t, allowed, "project-1 admin bypasses within project 1")

	allowed, err = h.CoreService.Authorize(ctx, u.ID, "secrets.delete", core.Scope{ProjectID: 2})
	require.NoError(t, err)
	assert.False(t, allowed, "project-1 admin has no power in project 2")
}

func TestAuthorize_GlobalGrantCoversEveryScope(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	u := h.CreateTestUser(t, "globalviewer", 106)
	h.AssignUserRole(t, u.ID, roleViewer, nil) // viewer at global scope

	ctx := context.Background()
	allowed, err := h.CoreService.Authorize(ctx, u.ID, "secrets.read", core.Scope{ProjectID: 7, EnvironmentID: 3})
	require.NoError(t, err)
	assert.True(t, allowed, "a global viewer can read in any project/environment")
}

func TestAuthorize_NoRolesDenied(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	u := h.CreateTestUser(t, "norole", 107)

	allowed, err := h.CoreService.Authorize(context.Background(), u.ID, "secrets.read", core.Scope{ProjectID: 1})
	require.NoError(t, err)
	assert.False(t, allowed, "a user with no roles is denied")
}

func TestAuthorize_SuperAdminBypass(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	u := h.CreateTestUser(t, "super", 108)
	h.AssignUserRole(t, u.ID, roleSuperAdmin, nil)

	allowed, err := h.CoreService.Authorize(context.Background(), u.ID, "system.admin", core.Scope{ProjectID: 4})
	require.NoError(t, err)
	assert.True(t, allowed, "super_admin bypasses scope and permission checks")
}
