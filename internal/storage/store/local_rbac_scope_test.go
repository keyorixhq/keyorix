package store

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// These tests pin the scope-matching SQL behind GetUserRoleIDsAt /
// GetUserGroupRoleIDsAt — the tenant-isolation boundary every user authorization
// decision rests on. A grant applies iff (project is global 0 OR equal) AND
// (environment is global 0 OR equal). The parenthesisation of the two OR clauses
// is security-critical: were the parens lost, SQL precedence (AND over OR) would
// turn `… AND env_id = 0 OR env_id = ?` into a cross-tenant leak (a grant at one
// project's env matching every project at that env). The cross-leak cases below
// would catch that regression.

func newRBACScopeTestStore(t *testing.T) *LocalStorage {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.UserRole{}, &models.GroupRole{}, &models.UserGroup{}, &models.Role{}, &models.Group{},
		&models.Project{}, &models.Environment{}, &models.Permission{}, &models.RolePermission{},
	))
	return NewLocalStorage(db)
}

func sc(project, env uint) storage.Scope {
	return storage.Scope{ProjectID: project, EnvironmentID: env}
}

func TestGetUserRoleIDsAt_ScopeBoundary(t *testing.T) {
	ls := newRBACScopeTestStore(t)
	ctx := context.Background()
	// user 1 grants: role 10 global, 20 project-5, 30 project-5/env-9, 40 project-6.
	grants := []models.UserRole{
		{UserID: 1, RoleID: 10, ProjectID: 0, EnvironmentID: 0},
		{UserID: 1, RoleID: 20, ProjectID: 5, EnvironmentID: 0},
		{UserID: 1, RoleID: 30, ProjectID: 5, EnvironmentID: 9},
		{UserID: 1, RoleID: 40, ProjectID: 6, EnvironmentID: 0},
	}
	for _, g := range grants {
		require.NoError(t, ls.db.Create(&g).Error)
	}

	cases := []struct {
		name  string
		scope storage.Scope
		want  []uint
	}{
		{"global scope sees only global grants", sc(0, 0), []uint{10}},
		{"project 5, env 0", sc(5, 0), []uint{10, 20}},
		{"project 5, env 9 sees global+project+env grant", sc(5, 9), []uint{10, 20, 30}},
		{"project 6, env 9 must NOT leak project-5's env-9 grant", sc(6, 9), []uint{10, 40}},
		{"project 6, env 8", sc(6, 8), []uint{10, 40}},
		{"unknown project sees only global", sc(99, 0), []uint{10}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ls.GetUserRoleIDsAt(ctx, 1, tc.scope)
			require.NoError(t, err)
			assert.ElementsMatch(t, tc.want, got)
		})
	}

	t.Run("a user with no grants gets nothing", func(t *testing.T) {
		got, err := ls.GetUserRoleIDsAt(ctx, 2, sc(5, 9))
		require.NoError(t, err)
		assert.Empty(t, got)
	})
}

// #161: a role bound directly to a project must stop authorizing the moment the
// project is soft-deleted, and resume once the project is restored — mirroring
// how groups.deleted_at already gates group-inherited roles. Before this fix,
// GetUserRoleIDsAt had no join against the projects table at all, so a
// project-scoped role kept authorizing regardless of the project's own
// soft-delete state.
func TestGetUserRoleIDsAt_DeletedProjectStopsAuthorizing(t *testing.T) {
	ls := newRBACScopeTestStore(t)
	ctx := context.Background()
	require.NoError(t, ls.db.Create(&models.Project{ID: 5, Name: "proj-5"}).Error)
	require.NoError(t, ls.db.Create(&models.UserRole{UserID: 1, RoleID: 20, ProjectID: 5, EnvironmentID: 0}).Error)

	got, err := ls.GetUserRoleIDsAt(ctx, 1, sc(5, 0))
	require.NoError(t, err)
	assert.ElementsMatch(t, []uint{20}, got, "live project: the project-scoped grant authorizes")

	require.NoError(t, ls.db.Delete(&models.Project{}, 5).Error)
	got, err = ls.GetUserRoleIDsAt(ctx, 1, sc(5, 0))
	require.NoError(t, err)
	assert.Empty(t, got, "soft-deleted project: the grant must stop authorizing")

	require.NoError(t, ls.db.Model(&models.Project{}).Unscoped().Where("id = ?", 5).Update("deleted_at", nil).Error)
	got, err = ls.GetUserRoleIDsAt(ctx, 1, sc(5, 0))
	require.NoError(t, err)
	assert.ElementsMatch(t, []uint{20}, got, "restored project: the grant authorizes again")
}

// #161: the same deleted_at gate applies to an ENVIRONMENT-scoped direct grant.
func TestGetUserRoleIDsAt_DeletedEnvironmentStopsAuthorizing(t *testing.T) {
	ls := newRBACScopeTestStore(t)
	ctx := context.Background()
	require.NoError(t, ls.db.Create(&models.Project{ID: 5, Name: "proj-5"}).Error)
	require.NoError(t, ls.db.Create(&models.Environment{ID: 9, ProjectID: 5, Name: "prod"}).Error)
	require.NoError(t, ls.db.Create(&models.UserRole{UserID: 1, RoleID: 30, ProjectID: 5, EnvironmentID: 9}).Error)

	got, err := ls.GetUserRoleIDsAt(ctx, 1, sc(5, 9))
	require.NoError(t, err)
	assert.ElementsMatch(t, []uint{30}, got, "live environment: the env-scoped grant authorizes")

	require.NoError(t, ls.db.Delete(&models.Environment{}, 9).Error)
	got, err = ls.GetUserRoleIDsAt(ctx, 1, sc(5, 9))
	require.NoError(t, err)
	assert.Empty(t, got, "soft-deleted environment: the grant must stop authorizing")

	require.NoError(t, ls.db.Model(&models.Environment{}).Unscoped().Where("id = ?", 9).Update("deleted_at", nil).Error)
	got, err = ls.GetUserRoleIDsAt(ctx, 1, sc(5, 9))
	require.NoError(t, err)
	assert.ElementsMatch(t, []uint{30}, got, "restored environment: the grant authorizes again")
}

// #161: the missing join was ALSO present on the group-inherited path
// (GetUserGroupRoleIDsAt) — a group-bound role scoped to a since-soft-deleted
// project previously kept authorizing every group member.
func TestGetUserGroupRoleIDsAt_DeletedProjectStopsAuthorizing(t *testing.T) {
	ls := newRBACScopeTestStore(t)
	ctx := context.Background()
	require.NoError(t, ls.db.Create(&models.Project{ID: 5, Name: "proj-5"}).Error)
	require.NoError(t, ls.db.Create(&models.Group{ID: 100, Name: "g100"}).Error)
	require.NoError(t, ls.db.Create(&models.UserGroup{UserID: 1, GroupID: 100}).Error)
	require.NoError(t, ls.db.Create(&models.GroupRole{GroupID: 100, RoleID: 50, ProjectID: 5, EnvironmentID: 0}).Error)

	got, err := ls.GetUserGroupRoleIDsAt(ctx, 1, sc(5, 0))
	require.NoError(t, err)
	assert.ElementsMatch(t, []uint{50}, got, "live project: the group's project-scoped grant authorizes")

	require.NoError(t, ls.db.Delete(&models.Project{}, 5).Error)
	got, err = ls.GetUserGroupRoleIDsAt(ctx, 1, sc(5, 0))
	require.NoError(t, err)
	assert.Empty(t, got, "soft-deleted project: the group's grant must stop authorizing")

	require.NoError(t, ls.db.Model(&models.Project{}).Unscoped().Where("id = ?", 5).Update("deleted_at", nil).Error)
	got, err = ls.GetUserGroupRoleIDsAt(ctx, 1, sc(5, 0))
	require.NoError(t, err)
	assert.ElementsMatch(t, []uint{50}, got, "restored project: the group's grant authorizes again")
}

func TestGetUserRoleIDsExact_NoGlobalMatching(t *testing.T) {
	ls := newRBACScopeTestStore(t)
	ctx := context.Background()
	require.NoError(t, ls.db.Create(&models.UserRole{UserID: 1, RoleID: 10, ProjectID: 0, EnvironmentID: 0}).Error)
	require.NoError(t, ls.db.Create(&models.UserRole{UserID: 1, RoleID: 20, ProjectID: 5, EnvironmentID: 9}).Error)

	// Exact matching does NOT fold in the global grant.
	got, err := ls.GetUserRoleIDsExact(ctx, 1, sc(5, 9))
	require.NoError(t, err)
	assert.ElementsMatch(t, []uint{20}, got)

	got, err = ls.GetUserRoleIDsExact(ctx, 1, sc(0, 0))
	require.NoError(t, err)
	assert.ElementsMatch(t, []uint{10}, got)

	got, err = ls.GetUserRoleIDsExact(ctx, 1, sc(5, 0))
	require.NoError(t, err)
	assert.Empty(t, got, "no grant exists at exactly project 5 / env 0")
}

func TestGetUserGroupRoleIDsAt_ScopeBoundary(t *testing.T) {
	ls := newRBACScopeTestStore(t)
	ctx := context.Background()
	// user 1 ∈ group 100; group 100 grants role 50 project-5/env-9, role 60 global.
	// A live (non-deleted) group is required — the authz query excludes deleted groups.
	require.NoError(t, ls.db.Create(&models.Group{ID: 100, Name: "g100"}).Error)
	require.NoError(t, ls.db.Create(&models.UserGroup{UserID: 1, GroupID: 100}).Error)
	require.NoError(t, ls.db.Create(&models.GroupRole{GroupID: 100, RoleID: 50, ProjectID: 5, EnvironmentID: 9}).Error)
	require.NoError(t, ls.db.Create(&models.GroupRole{GroupID: 100, RoleID: 60, ProjectID: 0, EnvironmentID: 0}).Error)
	// A different group the user is NOT in — must never be inherited.
	require.NoError(t, ls.db.Create(&models.GroupRole{GroupID: 200, RoleID: 70, ProjectID: 5, EnvironmentID: 9}).Error)

	got, err := ls.GetUserGroupRoleIDsAt(ctx, 1, sc(5, 9))
	require.NoError(t, err)
	assert.ElementsMatch(t, []uint{50, 60}, got, "inherits in-scope group grants + global")

	got, err = ls.GetUserGroupRoleIDsAt(ctx, 1, sc(6, 9))
	require.NoError(t, err)
	assert.ElementsMatch(t, []uint{60}, got, "project-5/env-9 group grant must NOT leak to project 6")

	got, err = ls.GetUserGroupRoleIDsAt(ctx, 1, sc(5, 0))
	require.NoError(t, err)
	assert.ElementsMatch(t, []uint{60}, got, "env-9 group grant does not apply at project-level env 0")

	got, err = ls.GetUserGroupRoleIDsAt(ctx, 2, sc(5, 9))
	require.NoError(t, err)
	assert.Empty(t, got, "a user in no group inherits nothing")
}

// TestGetUserGroupRoleIDsAt_ProjectScopedMembership verifies that a project-scoped
// group membership (UserGroup.ProjectID != 0) only grants roles within the matching
// project, while global memberships (ProjectID=0) still apply everywhere.
func TestGetUserGroupRoleIDsAt_ProjectScopedMembership(t *testing.T) {
	ls := newRBACScopeTestStore(t)
	ctx := context.Background()

	// Group 200 grants role 55 globally (group_roles.project_id = 0).
	// group_roles scoping is unchanged — we're testing user_groups.project_id.
	require.NoError(t, ls.db.Create(&models.Group{ID: 200, Name: "g200"}).Error)
	require.NoError(t, ls.db.Create(&models.GroupRole{GroupID: 200, RoleID: 55, ProjectID: 0, EnvironmentID: 0}).Error)

	// User 3 has a project-scoped membership in group 200 (only active for project 7).
	require.NoError(t, ls.db.Create(&models.UserGroup{UserID: 3, GroupID: 200, ProjectID: 7}).Error)

	// At project 7: scoped membership applies → role 55 is inherited.
	got, err := ls.GetUserGroupRoleIDsAt(ctx, 3, sc(7, 0))
	require.NoError(t, err)
	assert.ElementsMatch(t, []uint{55}, got, "scoped membership grants roles at its own project")

	// At project 8: scoped membership does NOT apply → no roles.
	got, err = ls.GetUserGroupRoleIDsAt(ctx, 3, sc(8, 0))
	require.NoError(t, err)
	assert.Empty(t, got, "scoped membership must not grant roles in a different project")

	// At the global scope (project 0): scoped membership does NOT apply.
	got, err = ls.GetUserGroupRoleIDsAt(ctx, 3, sc(0, 0))
	require.NoError(t, err)
	assert.Empty(t, got, "scoped membership must not apply at global scope")
}

// TestGetUserGroupRoleIDsAt_GlobalMembership verifies that a global membership
// (UserGroup.ProjectID=0) applies at every project scope, not just one.
func TestGetUserGroupRoleIDsAt_GlobalMembership(t *testing.T) {
	ls := newRBACScopeTestStore(t)
	ctx := context.Background()

	require.NoError(t, ls.db.Create(&models.Group{ID: 300, Name: "g300"}).Error)
	require.NoError(t, ls.db.Create(&models.GroupRole{GroupID: 300, RoleID: 66, ProjectID: 0, EnvironmentID: 0}).Error)

	// User 4 has a GLOBAL membership (ProjectID=0) in group 300.
	require.NoError(t, ls.db.Create(&models.UserGroup{UserID: 4, GroupID: 300, ProjectID: 0}).Error)

	// Global membership applies at any project scope.
	for _, pid := range []uint{0, 1, 5, 99} {
		got, err := ls.GetUserGroupRoleIDsAt(ctx, 4, sc(pid, 0))
		require.NoError(t, err)
		assert.ElementsMatch(t, []uint{66}, got, "global membership applies at project %d", pid)
	}
}
