package http

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// TestUpdateUserRolesHTTP_SelfReplacementLosingRolesAssign_ChangesNothing is #3684 over
// PUT /api/v1/users/{id}/roles: the global admin (user 2) replaces their OWN global
// roles with a role they could grant only through the admin role the replacement
// removes. A second global admin exists, so the last-admin guard lets user 2 drop it.
// Before the fix the removal committed, the grant was refused afterwards and the
// answer was 503 MutationPartiallyApplied with retry_safe true, leaving user 2 with no
// role; the retry was refused. Now the request is refused before anything commits.
func TestUpdateUserRolesHTTP_SelfReplacementLosingRolesAssign_ChangesNothing(t *testing.T) {
	w := newRoleScopeHTTPWorld(t)
	now := time.Now()
	require.NoError(t, w.db.AutoMigrate(&models.PendingAuditEvent{}))
	require.NoError(t, w.db.Create(&models.User{ID: 4, Username: "admin2", Email: "admin2@test.com", IsActive: true, AccountState: "active", CreatedAt: now, UpdatedAt: now}).Error)
	require.NoError(t, w.db.Create(&models.UserRole{UserID: 4, RoleID: 1}).Error) // second global admin
	require.NoError(t, w.db.Create(&models.Role{ID: 12, Name: "viewer", NameFolded: "viewer"}).Error)

	before := w.userGrants(t, 2)
	status, body := w.put(t, "/api/v1/users/2/roles", `{"role_ids":[12],"project_id":0}`)
	// The refusal is a permission denial (the ceiling), exactly 403: not a 503 partial
	// mutation, not a 200, and not some other 4xx/5xx.
	require.Equal(t, http.StatusForbidden, status, body)
	require.Contains(t, body, "cannot grant this role", "the 403 is the core ceiling refusal, not the route middleware")
	require.NotContains(t, body, "MutationPartiallyApplied", "nothing may be applied")
	require.Equal(t, before, w.userGrants(t, 2), "the refused self-replacement changed the actor's roles")
}

// TestUpdateProjectMemberHTTP_RoleBeyondGrantCeiling_Forbidden: PUT
// /api/v1/projects/{id}/members/{userId} by a project-scoped roles.assign holder asking
// for a role that bundles a permission they do not hold. The grant ceiling refuses it
// (a typed permission denial); the answer is exactly 403 with nothing changed, not the
// 500 the handler used to send for every unrecognised error (PAT-SCOPE-TAILS-1).
func TestUpdateProjectMemberHTTP_RoleBeyondGrantCeiling_Forbidden(t *testing.T) {
	w := newRoleScopeHTTPWorld(t)
	require.NoError(t, w.db.AutoMigrate(&models.PendingAuditEvent{}))
	require.NoError(t, w.db.Where("user_id = ?", 2).Delete(&models.UserRole{}).Error) // no global admin
	require.NoError(t, w.db.Create(&models.Permission{ID: 100, Name: "roles.assign", Resource: "roles", Action: "assign"}).Error)
	require.NoError(t, w.db.Create(&models.Permission{ID: 101, Name: "secrets.write", Resource: "secrets", Action: "write"}).Error)
	require.NoError(t, w.db.Create(&models.Role{ID: 20, Name: "proj_assigner", NameFolded: "proj_assigner"}).Error)
	require.NoError(t, w.db.Create(&models.Role{ID: 21, Name: "proj_writer", NameFolded: "proj_writer"}).Error)
	require.NoError(t, w.db.Create(&models.RolePermission{RoleID: 20, PermissionID: 100}).Error)
	require.NoError(t, w.db.Create(&models.RolePermission{RoleID: 21, PermissionID: 101}).Error)
	require.NoError(t, w.db.Create(&models.UserRole{UserID: 2, RoleID: 20, ProjectID: 2}).Error) // actor: roles.assign at project 2 only
	require.NoError(t, w.db.Create(&models.UserRole{UserID: 3, RoleID: 10, ProjectID: 2}).Error) // target: an existing member

	before := w.userGrants(t, 3)
	status, body := w.put(t, "/api/v1/projects/2/members/3", `{"role":"proj_writer"}`)
	require.Equal(t, http.StatusForbidden, status, body)
	require.Contains(t, body, "cannot grant this role", "the 403 is the core ceiling refusal, not the route middleware")
	require.NotContains(t, body, "MutationPartiallyApplied", "nothing may be applied")
	require.Equal(t, before, w.userGrants(t, 3), "the refused grant changed the member's roles")
}
