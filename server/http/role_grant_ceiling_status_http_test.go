package http

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// seedAssignerWithoutSecretsWrite turns the world's actor (user 2) into a global
// roles.assign (plus the group-wide users.read route gate) holder and adds role 21 (proj_writer), which bundles secrets.write, a
// permission the actor does not hold. Granting role 21 is therefore beyond the grant
// ceiling.
func seedAssignerWithoutSecretsWrite(t *testing.T, w *roleScopeHTTPWorld) {
	t.Helper()
	require.NoError(t, w.db.Where("user_id = ?", 2).Delete(&models.UserRole{}).Error) // no global admin
	require.NoError(t, w.db.Create(&models.Permission{ID: 100, Name: "roles.assign", Resource: "roles", Action: "assign"}).Error)
	require.NoError(t, w.db.Create(&models.Permission{ID: 101, Name: "secrets.write", Resource: "secrets", Action: "write"}).Error)
	require.NoError(t, w.db.Create(&models.Role{ID: 20, Name: "proj_assigner", NameFolded: "proj_assigner"}).Error)
	require.NoError(t, w.db.Create(&models.Role{ID: 21, Name: "proj_writer", NameFolded: "proj_writer"}).Error)
	require.NoError(t, w.db.Create(&models.Permission{ID: 102, Name: "users.read", Resource: "users", Action: "read"}).Error)
	require.NoError(t, w.db.Create(&models.RolePermission{RoleID: 20, PermissionID: 100}).Error)
	require.NoError(t, w.db.Create(&models.RolePermission{RoleID: 20, PermissionID: 102}).Error) // the group-wide route gate
	require.NoError(t, w.db.Create(&models.RolePermission{RoleID: 21, PermissionID: 101}).Error)
	require.NoError(t, w.db.Create(&models.UserRole{UserID: 2, RoleID: 20}).Error)
}

// TestUpdateUserRolesHTTP_RoleBeyondGrantCeiling_Forbidden: PUT /api/v1/users/{id}/roles
// by a project-scoped roles.assign holder asking for a role that bundles a permission
// they do not hold. The ceiling refusal is a permission denial: 403, nothing changed,
// never the 500 "Failed to update user roles".
func TestUpdateUserRolesHTTP_RoleBeyondGrantCeiling_Forbidden(t *testing.T) {
	w := newRoleScopeHTTPWorld(t)
	seedAssignerWithoutSecretsWrite(t, w)

	before := w.userGrants(t, 3)
	status, body := w.put(t, "/api/v1/users/3/roles", `{"role_ids":[21],"project_id":2}`)
	require.Equal(t, http.StatusForbidden, status, body)
	require.Contains(t, body, "cannot grant this role", "the 403 is the core ceiling refusal, not the route middleware")
	require.NotContains(t, body, "Failed to update user roles")
	require.Equal(t, before, w.userGrants(t, 3), "the refused grant changed the user's roles")
}

// TestAssignRoleToGroupHTTP_RoleBeyondGrantCeiling_Forbidden: POST
// /api/v1/groups/{id}/roles, both the permanent and the time-bound variant, for a role
// beyond the actor's ceiling. 403 with no grant row, not the 500 "Failed to assign role
// to group".
func TestAssignRoleToGroupHTTP_RoleBeyondGrantCeiling_Forbidden(t *testing.T) {
	w := newRoleScopeHTTPWorld(t)
	seedAssignerWithoutSecretsWrite(t, w)

	status, body := w.post(t, "/api/v1/groups/7/roles", `{"role_id":21,"project_id":2}`)
	require.Equal(t, http.StatusForbidden, status, body)
	require.Contains(t, body, "cannot grant this role", "the 403 is the core ceiling refusal, not the route middleware")
	require.NotContains(t, body, "Failed to assign role to group")
	require.Empty(t, w.groupGrants(t, 7), "the refused grant wrote a row")

	status, body = w.post(t, "/api/v1/groups/7/roles",
		`{"role_id":21,"project_id":2,"expires_at":"2099-01-01T00:00:00Z"}`)
	require.Equal(t, http.StatusForbidden, status, body)
	require.Empty(t, w.groupGrants(t, 7), "the refused time-bound grant wrote a row")
}
