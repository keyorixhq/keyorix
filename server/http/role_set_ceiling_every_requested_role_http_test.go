package http

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// FU-OWNERSHIP-1 through the real router. User 2 holds roles.assign alone at project 2
// and globally, so every route gate passes, and may not grant proj_writer (21), which
// bundles secrets.write. The core tests read the role sets over every shape of target;
// these pin the answer each route gives.

func newCeilingRouteWorld(t *testing.T) *roleScopeHTTPWorld {
	t.Helper()
	w := newRoleScopeHTTPWorld(t)
	require.NoError(t, w.db.AutoMigrate(&models.PendingAuditEvent{}, &models.ProjectMembership{}))
	require.NoError(t, w.db.Where("user_id = ?", 2).Delete(&models.UserRole{}).Error) // no global admin
	require.NoError(t, w.db.Create(&models.Permission{ID: 100, Name: "roles.assign", Resource: "roles", Action: "assign"}).Error)
	require.NoError(t, w.db.Create(&models.Permission{ID: 101, Name: "secrets.write", Resource: "secrets", Action: "write"}).Error)
	require.NoError(t, w.db.Create(&models.Role{ID: 20, Name: "proj_assigner", NameFolded: "proj_assigner"}).Error)
	require.NoError(t, w.db.Create(&models.Role{ID: 21, Name: "proj_writer", NameFolded: "proj_writer"}).Error)
	require.NoError(t, w.db.Create(&models.Permission{ID: 102, Name: "users.read", Resource: "users", Action: "read"}).Error) // the /users route group's gate
	require.NoError(t, w.db.Create(&models.RolePermission{RoleID: 20, PermissionID: 100}).Error)
	require.NoError(t, w.db.Create(&models.RolePermission{RoleID: 20, PermissionID: 102}).Error)
	require.NoError(t, w.db.Create(&models.RolePermission{RoleID: 21, PermissionID: 101}).Error)
	require.NoError(t, w.db.Create(&models.UserRole{UserID: 2, RoleID: 20, ProjectID: 2}).Error)
	require.NoError(t, w.db.Create(&models.UserRole{UserID: 2, RoleID: 20}).Error)
	return w
}

// TestRoleSetRoutes_RoleBeyondCeiling_403EvenWhenAlreadyHeld: the no-op and the
// narrowing on both replacement routes used to answer 200.
func TestRoleSetRoutes_RoleBeyondCeiling_403EvenWhenAlreadyHeld(t *testing.T) {
	routes := map[string]func(w *roleScopeHTTPWorld) (int, string){
		"PUT /projects/{id}/members/{userId}": func(w *roleScopeHTTPWorld) (int, string) {
			return w.put(t, "/api/v1/projects/2/members/3", `{"role":"proj_writer"}`)
		},
		"PUT /users/{id}/roles": func(w *roleScopeHTTPWorld) (int, string) {
			return w.put(t, "/api/v1/users/3/roles", `{"role_ids":[21],"project_id":2}`)
		},
	}
	shapes := map[string][]uint{"no-op": {21}, "narrowing": {21, 10}}
	for route, call := range routes {
		for shape, held := range shapes {
			t.Run(route+" "+shape, func(t *testing.T) {
				w := newCeilingRouteWorld(t)
				for _, id := range held {
					require.NoError(t, w.db.Create(&models.UserRole{UserID: 3, RoleID: id, ProjectID: 2}).Error)
				}
				before := w.userGrants(t, 3)
				status, body := call(w)
				require.Equal(t, http.StatusForbidden, status, body)
				require.Contains(t, body, "cannot grant this role", "the 403 is the core ceiling refusal, not the route middleware")
				require.Equal(t, before, w.userGrants(t, 3), "the refused request changed the member's roles")
			})
		}
	}
}

// TestMemberCreateRoutes_RoleBeyondCeiling_403: POST /projects/{id}/memberships
// answered the ceiling refusal 500 (no ErrPermissionDenied case in its error switch).
func TestMemberCreateRoutes_RoleBeyondCeiling_403(t *testing.T) {
	for _, path := range []string{"/api/v1/projects/2/members", "/api/v1/projects/2/memberships"} {
		t.Run(path, func(t *testing.T) {
			w := newCeilingRouteWorld(t)
			status, body := w.post(t, path, `{"user_id":3,"role":"proj_writer"}`)
			require.Equal(t, http.StatusForbidden, status, body)
			require.Contains(t, body, "cannot grant this role", "the 403 is the core ceiling refusal, not the route middleware")
			require.Empty(t, w.userGrants(t, 3), "the refused request wrote a grant")
		})
	}
}
