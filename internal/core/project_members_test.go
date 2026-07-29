package core

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// grantGlobalAdmin gives actorID the "admin" role at the global scope, so it
// satisfies the #93/#107/#141 grant-ceiling check (AssignUserRole requires the
// granting actor already hold every permission bundled into the role being
// granted; the admin bypass in Authorize covers that trivially) for these
// project-member tests, which weren't otherwise concerned with the actor's own
// authority. A GLOBAL grant doesn't show up in a per-project assignment listing
// (ListProjectRoleAssignments filters on the exact project ID), so it also does
// NOT get counted as "another project admin" by guardLastProjectAdmin — the
// last-project-admin scenarios these tests exercise are unaffected.
func grantGlobalAdmin(t *testing.T, st *store.LocalStorage, actorID uint) {
	t.Helper()
	ctx := context.Background()
	role, err := st.GetRoleByName(ctx, "admin")
	require.NoError(t, err)
	require.NoError(t, st.AssignRole(ctx, actorID, role.ID, storage.Scope{}))
}

func TestProjectMemberLifecycle(t *testing.T) {
	c, st := newBootstrappedCore(t)
	ctx := context.Background()
	const proj = uint(7)

	u, err := st.CreateUser(ctx, &models.User{Username: "alice", Email: "alice@example.com", IsActive: true})
	require.NoError(t, err)

	// No members initially.
	members, err := c.ListProjectMembers(ctx, proj)
	require.NoError(t, err)
	assert.Empty(t, members)

	const actor = uint(99)
	grantGlobalAdmin(t, st, actor)

	// Add as project_viewer.
	require.NoError(t, c.AddProjectMember(ctx, actor, proj, u.ID, "project_viewer"))
	members, err = c.ListProjectMembers(ctx, proj)
	require.NoError(t, err)
	require.Len(t, members, 1)
	assert.Equal(t, "alice", members[0].Username)
	assert.Equal(t, "project_viewer", members[0].RoleName)

	// Adding the same role again is a conflict.
	require.Error(t, c.AddProjectMember(ctx, actor, proj, u.ID, "project_viewer"))

	// Change role to project_developer — replaces, doesn't accumulate.
	require.NoError(t, c.SetProjectMemberRole(ctx, actor, proj, u.ID, "project_developer"))
	members, err = c.ListProjectMembers(ctx, proj)
	require.NoError(t, err)
	require.Len(t, members, 1, "member should have exactly one project role after change")
	assert.Equal(t, "project_developer", members[0].RoleName)

	// Membership is project-scoped: another project sees nothing.
	other, err := c.ListProjectMembers(ctx, proj+1)
	require.NoError(t, err)
	assert.Empty(t, other)

	// Remove.
	require.NoError(t, c.RemoveProjectMember(ctx, actor, proj, u.ID))
	members, err = c.ListProjectMembers(ctx, proj)
	require.NoError(t, err)
	assert.Empty(t, members)

	// Removing a non-member errors.
	require.Error(t, c.RemoveProjectMember(ctx, actor, proj, u.ID))
}

func TestAddProjectMemberUnknownRole(t *testing.T) {
	c, st := newBootstrappedCore(t)
	ctx := context.Background()
	u, err := st.CreateUser(ctx, &models.User{Username: "bob", Email: "bob@example.com", IsActive: true})
	require.NoError(t, err)
	require.Error(t, c.AddProjectMember(ctx, 99, 1, u.ID, "no_such_role"))
}

// AddProjectMember/SetProjectMemberRole/RemoveProjectMember grant/revoke the same
// underlying role assignment as /user-roles, so they must land in the RBAC audit
// trail identically (#234) — previously these bypassed AssignUserRole/RemoveUserRole
// and wrote nothing.
func TestProjectMemberGrantIsRBACAudited(t *testing.T) {
	c, st := newBootstrappedCore(t)
	ctx := context.Background()
	const proj = uint(9)
	const actor = uint(55)
	grantGlobalAdmin(t, st, actor)

	u, err := st.CreateUser(ctx, &models.User{Username: "carol", Email: "carol@example.com", IsActive: true})
	require.NoError(t, err)

	require.NoError(t, c.AddProjectMember(ctx, actor, proj, u.ID, "project_viewer"))

	entries, _, err := c.ListRBACAuditLogs(ctx, 1, 50)
	require.NoError(t, err)
	var assigned *RBACAuditEntry
	for _, e := range entries {
		if e.Action == EventRoleAssigned && e.TargetUserID != nil && *e.TargetUserID == u.ID {
			assigned = e
		}
	}
	require.NotNil(t, assigned, "expected a role.assigned entry for the project-member grant")
	require.NotNil(t, assigned.ActorUserID)
	assert.Equal(t, actor, *assigned.ActorUserID)
	require.NotNil(t, assigned.ProjectID)
	assert.Equal(t, proj, *assigned.ProjectID)

	require.NoError(t, c.RemoveProjectMember(ctx, actor, proj, u.ID))

	entries, _, err = c.ListRBACAuditLogs(ctx, 1, 50)
	require.NoError(t, err)
	var removed *RBACAuditEntry
	for _, e := range entries {
		if e.Action == EventRoleRemoved && e.TargetUserID != nil && *e.TargetUserID == u.ID {
			removed = e
		}
	}
	require.NotNil(t, removed, "expected a role.removed entry for the project-member revoke")
	require.NotNil(t, removed.ActorUserID)
	assert.Equal(t, actor, *removed.ActorUserID)
}

// #232: removing a project member must also revoke any environment-scoped grant
// (e.g. "prod-only access") the user separately holds in the same project — a
// prior version only deleted the exact project-level (environment_id = 0) row,
// leaving the environment-scoped one live and invisible to the offboarding admin.
func TestRemoveProjectMember_RevokesEnvironmentScopedGrantToo(t *testing.T) {
	c, st := newBootstrappedCore(t)
	ctx := context.Background()
	const proj = uint(7)
	const prodEnv = uint(99)
	const actor = uint(55)
	grantGlobalAdmin(t, st, actor)

	u, err := st.CreateUser(ctx, &models.User{Username: "carol", Email: "carol@example.com", IsActive: true})
	require.NoError(t, err)

	role, err := st.GetRoleByName(ctx, "project_developer")
	require.NoError(t, err)

	// Project-level membership (what the Members UI shows)...
	require.NoError(t, c.AddProjectMember(ctx, actor, proj, u.ID, "project_developer"))
	// ...plus a SEPARATE environment-scoped grant (e.g. "prod-only access"),
	// created the way POST /user-roles would (gated by GLOBAL roles.assign).
	require.NoError(t, st.AssignRole(ctx, u.ID, role.ID, storage.Scope{ProjectID: proj, EnvironmentID: prodEnv}))

	// Sanity: both grants are live before removal.
	projectScoped, err := st.GetUserRoleIDsExact(ctx, u.ID, storage.Scope{ProjectID: proj})
	require.NoError(t, err)
	require.Len(t, projectScoped, 1)
	envScoped, err := st.GetUserRoleIDsExact(ctx, u.ID, storage.Scope{ProjectID: proj, EnvironmentID: prodEnv})
	require.NoError(t, err)
	require.Len(t, envScoped, 1)

	require.NoError(t, c.RemoveProjectMember(ctx, actor, proj, u.ID))

	// Neither the project-level NOR the environment-scoped grant survives.
	projectScoped, err = st.GetUserRoleIDsExact(ctx, u.ID, storage.Scope{ProjectID: proj})
	require.NoError(t, err)
	assert.Empty(t, projectScoped, "project-level grant must be revoked")
	envScoped, err = st.GetUserRoleIDsExact(ctx, u.ID, storage.Scope{ProjectID: proj, EnvironmentID: prodEnv})
	require.NoError(t, err)
	assert.Empty(t, envScoped, "environment-scoped grant must be revoked too — the gap #232 closes")
}

// #236: the sole remaining project admin must not be removable/demotable via the
// ordinary member-management API — doing so would leave the project with zero
// project-scoped admins.
func TestRemoveProjectMember_RefusesLastAdmin(t *testing.T) {
	c, st := newBootstrappedCore(t)
	ctx := context.Background()
	const proj = uint(7)
	const actor = uint(55)
	grantGlobalAdmin(t, st, actor)

	u, err := st.CreateUser(ctx, &models.User{Username: "dave", Email: "dave@example.com", IsActive: true})
	require.NoError(t, err)
	require.NoError(t, c.AddProjectMember(ctx, actor, proj, u.ID, "project_admin"))

	err = c.RemoveProjectMember(ctx, actor, proj, u.ID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "last administrator")

	// The membership is untouched.
	members, err := c.ListProjectMembers(ctx, proj)
	require.NoError(t, err)
	require.Len(t, members, 1)
	assert.Equal(t, "project_admin", members[0].RoleName)
}

// #236: demoting the sole remaining project admin to a non-admin role is refused
// the same way removal is — SetProjectMemberRole must not be a bypass.
func TestSetProjectMemberRole_RefusesLastAdminDemotion(t *testing.T) {
	c, st := newBootstrappedCore(t)
	ctx := context.Background()
	const proj = uint(7)
	const actor = uint(55)
	grantGlobalAdmin(t, st, actor)

	u, err := st.CreateUser(ctx, &models.User{Username: "erin", Email: "erin@example.com", IsActive: true})
	require.NoError(t, err)
	require.NoError(t, c.AddProjectMember(ctx, actor, proj, u.ID, "project_admin"))

	err = c.SetProjectMemberRole(ctx, actor, proj, u.ID, "project_viewer")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "last administrator")

	members, err := c.ListProjectMembers(ctx, proj)
	require.NoError(t, err)
	require.Len(t, members, 1)
	assert.Equal(t, "project_admin", members[0].RoleName, "role must be unchanged after a refused demotion")
}

// #236 (negative case): removing a NON-last admin — another project admin still
// present — must still succeed. The guard must not over-block ordinary removals.
func TestRemoveProjectMember_AllowsNonLastAdmin(t *testing.T) {
	c, st := newBootstrappedCore(t)
	ctx := context.Background()
	const proj = uint(7)
	const actor = uint(55)
	grantGlobalAdmin(t, st, actor)

	u1, err := st.CreateUser(ctx, &models.User{Username: "frank", Email: "frank@example.com", IsActive: true})
	require.NoError(t, err)
	u2, err := st.CreateUser(ctx, &models.User{Username: "grace", Email: "grace@example.com", IsActive: true})
	require.NoError(t, err)
	require.NoError(t, c.AddProjectMember(ctx, actor, proj, u1.ID, "project_admin"))
	require.NoError(t, c.AddProjectMember(ctx, actor, proj, u2.ID, "project_admin"))

	// Removing one of two admins succeeds — the other keeps the project governed.
	require.NoError(t, c.RemoveProjectMember(ctx, actor, proj, u1.ID))

	members, err := c.ListProjectMembers(ctx, proj)
	require.NoError(t, err)
	require.Len(t, members, 1)
	assert.Equal(t, "grace", members[0].Username)

	// Now grace IS the last admin — removing her is refused.
	err = c.RemoveProjectMember(ctx, actor, proj, u2.ID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "last administrator")
}

// CWE-284: removing a project member must revoke any per-secret ACL grants the
// user holds on secrets in that project. Without this, a removed member retains
// access because AuthorizeSecret checks ACL grants before project-scope RBAC
// and short-circuits on the first match.
func TestRemoveProjectMember_RevokesSecretACLGrants(t *testing.T) {
	c, st := newBootstrappedCore(t)
	ctx := context.Background()
	const proj = uint(5)
	const env = uint(5)
	const actor = uint(55)
	grantGlobalAdmin(t, st, actor)

	// Seed the project and environment so the secret can be created.
	require.NoError(t, st.DB().Create(&models.Project{ID: proj, Name: "acl-project"}).Error)
	require.NoError(t, st.DB().Create(&models.Environment{ID: env, ProjectID: proj, Name: "env"}).Error)

	// Create a secret in the project.
	sec := &models.SecretNode{ProjectID: proj, EnvironmentID: env, Name: "db-password", IsSecret: true, Status: "active"}
	require.NoError(t, st.DB().Create(sec).Error)

	// Create a user and add them to the project.
	u, err := st.CreateUser(ctx, &models.User{Username: "ivy", Email: "ivy@example.com", IsActive: true})
	require.NoError(t, err)
	require.NoError(t, c.AddProjectMember(ctx, actor, proj, u.ID, "project_viewer"))

	// Grant the user a per-secret ACL on the secret.
	require.NoError(t, c.GrantSecretACL(ctx, actor, sec.ID, u.ID, []string{"secrets.read"}))

	// Sanity: the ACL is live before removal.
	acls, err := c.ListSecretACLs(ctx, sec.ID)
	require.NoError(t, err)
	require.Len(t, acls, 1, "ACL grant must exist before member removal")

	// Remove the user from the project.
	require.NoError(t, c.RemoveProjectMember(ctx, actor, proj, u.ID))

	// ACL grant must be gone after offboarding.
	acls, err = c.ListSecretACLs(ctx, sec.ID)
	require.NoError(t, err)
	assert.Empty(t, acls, "SecretACL grant must be revoked when the user is removed from the project")

	// AuthorizeSecret must also deny: HasSecretACL returns false, and the
	// project-scope RBAC fallback denies a user with no remaining role.
	allowed, err := c.AuthorizeSecret(ctx, u.ID, sec.ID, "secrets.read")
	require.NoError(t, err)
	assert.False(t, allowed, "removed member must not retain access via stale ACL grant")
}

// #236 (negative case): a non-admin member (no roles.assign) can always be freely
// removed — the guard only fires for the LAST roles.assign holder.
func TestRemoveProjectMember_NonAdminAlwaysRemovable(t *testing.T) {
	c, st := newBootstrappedCore(t)
	ctx := context.Background()
	const proj = uint(7)
	const actor = uint(55)
	grantGlobalAdmin(t, st, actor)

	u, err := st.CreateUser(ctx, &models.User{Username: "henry", Email: "henry@example.com", IsActive: true})
	require.NoError(t, err)
	require.NoError(t, c.AddProjectMember(ctx, actor, proj, u.ID, "project_viewer"))

	require.NoError(t, c.RemoveProjectMember(ctx, actor, proj, u.ID))
	members, err := c.ListProjectMembers(ctx, proj)
	require.NoError(t, err)
	assert.Empty(t, members)
}
