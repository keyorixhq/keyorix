package store_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Roles ---

func TestRemoteStorage_CreateRole(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/api/v1/roles", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{"id": 1, "name": "admin", "description": "Admin role"}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	role, err := rs.CreateRole(context.Background(), &models.Role{Name: "admin"})
	require.NoError(t, err)
	assert.Equal(t, uint(1), role.ID)
	assert.Equal(t, "admin", role.Name)
}

func TestRemoteStorage_GetRole(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/api/v1/roles/5", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{"id": 5, "name": "editor", "description": "Editor role"}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	role, err := rs.GetRole(context.Background(), 5)
	require.NoError(t, err)
	assert.Equal(t, uint(5), role.ID)
	assert.Equal(t, "editor", role.Name)
}

func TestRemoteStorage_GetRoleByName(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/api/v1/roles/by-name", r.URL.Path)
		assert.Equal(t, "admin", r.URL.Query().Get("name"))
		_, _ = w.Write(apiOK(map[string]interface{}{"id": 2, "name": "admin", "description": "Admin role"}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	role, err := rs.GetRoleByName(context.Background(), "admin")
	require.NoError(t, err)
	assert.Equal(t, uint(2), role.ID)
	assert.Equal(t, "admin", role.Name)
}

func TestRemoteStorage_UpdateRole(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "PUT", r.Method)
		assert.Equal(t, "/api/v1/roles/3", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{"id": 3, "name": "updated", "description": "Updated"}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	role, err := rs.UpdateRole(context.Background(), &models.Role{ID: 3, Name: "updated"})
	require.NoError(t, err)
	assert.Equal(t, uint(3), role.ID)
	assert.Equal(t, "updated", role.Name)
}

func TestRemoteStorage_DeleteRole(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "DELETE", r.Method)
		assert.Equal(t, "/api/v1/roles/7", r.URL.Path)
		_, _ = w.Write(apiOK(nil))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.DeleteRole(context.Background(), 7)
	require.NoError(t, err)
}

func TestRemoteStorage_ListRoles(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/api/v1/roles", r.URL.Path)
		_, _ = w.Write(apiOK([]map[string]interface{}{
			{"id": 1, "name": "admin", "description": "Admin"},
			{"id": 2, "name": "viewer", "description": "Viewer"},
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	roles, err := rs.ListRoles(context.Background())
	require.NoError(t, err)
	require.Len(t, roles, 2)
	assert.Equal(t, "admin", roles[0].Name)
}

// --- RBAC assignment ---

func TestRemoteStorage_AssignRole(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/api/v1/rbac/assign-role", r.URL.Path)
		_, _ = w.Write(apiOK(nil))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.AssignRole(context.Background(), 10, 1, corestorage.Scope{ProjectID: 0, EnvironmentID: 0})
	require.NoError(t, err)
}

func TestRemoteStorage_RemoveRole(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/api/v1/rbac/remove-role", r.URL.Path)
		_, _ = w.Write(apiOK(nil))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.RemoveRole(context.Background(), 10, 1, corestorage.Scope{ProjectID: 0, EnvironmentID: 0})
	require.NoError(t, err)
}

func TestRemoteStorage_GetGroupRoleGrants(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/api/v1/system/rbac/groups/4/role-grants", r.URL.Path)
		_, _ = w.Write(apiOK([]map[string]interface{}{
			{"id": 1, "name": "admin", "description": "Admin"},
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	grants, err := rs.GetGroupRoleGrants(context.Background(), 4)
	require.NoError(t, err)
	require.Len(t, grants, 1)
	assert.Equal(t, uint(1), grants[0].ID)
}

func TestRemoteStorage_AssignRoleWithExpiry(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/api/v1/system/rbac/assign-role-with-expiry", r.URL.Path)
		_, _ = w.Write(apiOK(nil))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	expires := time.Now().Add(24 * time.Hour)
	err = rs.AssignRoleWithExpiry(context.Background(), 10, 1, corestorage.Scope{ProjectID: 5}, expires)
	require.NoError(t, err)
}

func TestRemoteStorage_AssignRoleToGroupWithExpiry(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/api/v1/system/rbac/assign-role-to-group-with-expiry", r.URL.Path)
		_, _ = w.Write(apiOK(nil))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	expires := time.Now().Add(24 * time.Hour)
	err = rs.AssignRoleToGroupWithExpiry(context.Background(), 3, 1, corestorage.Scope{ProjectID: 5}, expires)
	require.NoError(t, err)
}

func TestRemoteStorage_DeleteExpiredRoleGrants(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/api/v1/system/retention/role-grants/purge-expired", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{
			"removed": []map[string]interface{}{
				{"principal_type": "user", "principal_id": 10, "role_id": 1, "project_id": 0, "environment_id": 0},
			},
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	removed, err := rs.DeleteExpiredRoleGrants(context.Background(), time.Now())
	require.NoError(t, err)
	require.Len(t, removed, 1)
	assert.Equal(t, "user", removed[0].PrincipalType)
}

func TestRemoteStorage_RemoveAllProjectRoleGrants(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/api/v1/system/rbac/remove-all-project-role-grants", r.URL.Path)
		_, _ = w.Write(apiOK(nil))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.RemoveAllProjectRoleGrants(context.Background(), 10, 5)
	require.NoError(t, err)
}

func TestRemoteStorage_GetUserRoles(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/api/v1/users/12/roles", r.URL.Path)
		_, _ = w.Write(apiOK([]map[string]interface{}{
			{"id": 1, "name": "admin", "description": "Admin"},
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	roles, err := rs.GetUserRoles(context.Background(), 12)
	require.NoError(t, err)
	require.Len(t, roles, 1)
	assert.Equal(t, "admin", roles[0].Name)
}

func TestRemoteStorage_GetUserPermissions(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/api/v1/users/12/permissions", r.URL.Path)
		_, _ = w.Write(apiOK([]map[string]interface{}{
			{"id": 1, "name": "secrets.read", "resource": "secrets", "action": "read"},
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	perms, err := rs.GetUserPermissions(context.Background(), 12)
	require.NoError(t, err)
	require.Len(t, perms, 1)
	assert.Equal(t, "secrets.read", perms[0].Name)
}

func TestRemoteStorage_GetUserGroupPermissions_Unsupported(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfig("http://127.0.0.1:0"))
	require.NoError(t, err)

	_, err = rs.GetUserGroupPermissions(context.Background(), 1)
	assert.Error(t, err)
}

// --- Permission management (unsupported in remote mode) ---

func TestRemoteStorage_CreatePermission_Unsupported(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfig("http://127.0.0.1:0"))
	require.NoError(t, err)

	_, err = rs.CreatePermission(context.Background(), &models.Permission{Name: "test.read"})
	assert.Error(t, err)
}

func TestRemoteStorage_AssignPermissionToRole_Unsupported(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfig("http://127.0.0.1:0"))
	require.NoError(t, err)

	err = rs.AssignPermissionToRole(context.Background(), 1, 2)
	assert.Error(t, err)
}

func TestRemoteStorage_ListPermissions(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/api/v1/permissions", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{
			"permissions": []map[string]interface{}{
				{"id": 1, "name": "secrets.read", "resource": "secrets", "action": "read"},
				{"id": 2, "name": "secrets.write", "resource": "secrets", "action": "write"},
			},
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	perms, err := rs.ListPermissions(context.Background())
	require.NoError(t, err)
	require.Len(t, perms, 2)
	assert.Equal(t, "secrets.read", perms[0].Name)
}

func TestRemoteStorage_GetPermission(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/api/v1/permissions/3", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{
			"id": 3, "name": "roles.read", "resource": "roles", "action": "read",
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	perm, err := rs.GetPermission(context.Background(), 3)
	require.NoError(t, err)
	assert.Equal(t, uint(3), perm.ID)
	assert.Equal(t, "roles.read", perm.Name)
}

func TestRemoteStorage_GetRolePermissions(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/api/v1/roles/2/permissions", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{
			"role_id":   2,
			"role_name": "editor",
			"permissions": []map[string]interface{}{
				{"id": 1, "name": "secrets.read", "resource": "secrets", "action": "read"},
			},
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	perms, err := rs.GetRolePermissions(context.Background(), 2)
	require.NoError(t, err)
	require.Len(t, perms, 1)
	assert.Equal(t, "secrets.read", perms[0].Name)
}

func TestRemoteStorage_RemovePermissionFromRole_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "DELETE", r.Method)
		assert.Equal(t, "/api/v1/roles/2/permissions/5", r.URL.Path)
		_, _ = w.Write(apiOK(nil))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.RemovePermissionFromRole(context.Background(), 2, 5)
	require.NoError(t, err)
}

// --- Connect ref grants ---

func TestRemoteStorage_ListConnectRefGrantsByConnector(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/api/v1/system/connect-grants/by-connector/my-connector", r.URL.Path)
		_, _ = w.Write(apiOK([]map[string]interface{}{
			{"id": 1, "role_id": 2, "connector": "my-connector", "ref_prefix": "secrets/"},
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	grants, err := rs.ListConnectRefGrantsByConnector(context.Background(), "my-connector")
	require.NoError(t, err)
	require.Len(t, grants, 1)
	assert.Equal(t, uint(1), grants[0].ID)
	assert.Equal(t, "my-connector", grants[0].Connector)
}

func TestRemoteStorage_ListConnectRefGrants(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/api/v1/system/connect-grants", r.URL.Path)
		_, _ = w.Write(apiOK([]map[string]interface{}{
			{"id": 1, "role_id": 2, "connector": "conn-a", "ref_prefix": ""},
			{"id": 2, "role_id": 3, "connector": "conn-b", "ref_prefix": "prod/"},
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	grants, err := rs.ListConnectRefGrants(context.Background())
	require.NoError(t, err)
	require.Len(t, grants, 2)
	assert.Equal(t, "conn-a", grants[0].Connector)
}

func TestRemoteStorage_CreateConnectRefGrant(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/api/v1/system/connect-grants", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{
			"id": 10, "role_id": 2, "connector": "my-conn", "ref_prefix": "staging/",
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	grant, err := rs.CreateConnectRefGrant(context.Background(), &models.ConnectRefGrant{
		RoleID:    2,
		Connector: "my-conn",
		RefPrefix: "staging/",
	})
	require.NoError(t, err)
	assert.Equal(t, uint(10), grant.ID)
	assert.Equal(t, "my-conn", grant.Connector)
}

func TestRemoteStorage_DeleteConnectRefGrant(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "DELETE", r.Method)
		assert.Equal(t, "/api/v1/system/connect-grants/10", r.URL.Path)
		_, _ = w.Write(apiOK(nil))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.DeleteConnectRefGrant(context.Background(), 10)
	require.NoError(t, err)
}

// --- Group roles ---

func TestRemoteStorage_GetGroupRoles(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/api/v1/groups/8/roles", r.URL.Path)
		_, _ = w.Write(apiOK([]map[string]interface{}{
			{"id": 1, "name": "admin", "description": "Admin"},
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	roles, err := rs.GetGroupRoles(context.Background(), 8)
	require.NoError(t, err)
	require.Len(t, roles, 1)
	assert.Equal(t, "admin", roles[0].Name)
}

func TestRemoteStorage_ListGroupRoleAssignments(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/api/v1/system/rbac/groups/6/role-assignments", r.URL.Path)
		_, _ = w.Write(apiOK([]map[string]interface{}{
			{"principal_type": "group", "principal_id": 6, "role_id": 2, "project_id": 0, "environment_id": 0},
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	assignments, err := rs.ListGroupRoleAssignments(context.Background(), 6)
	require.NoError(t, err)
	require.Len(t, assignments, 1)
	assert.Equal(t, "group", assignments[0].PrincipalType)
	assert.Equal(t, uint(2), assignments[0].RoleID)
}

func TestRemoteStorage_AssignRoleToGroup(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/api/v1/groups/8/roles", r.URL.Path)
		_, _ = w.Write(apiOK(nil))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.AssignRoleToGroup(context.Background(), 8, 2, corestorage.Scope{ProjectID: 0})
	require.NoError(t, err)
}

func TestRemoteStorage_RemoveRoleFromGroup(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "DELETE", r.Method)
		assert.Equal(t, "/api/v1/groups/8/roles/2", r.URL.Path)
		_, _ = w.Write(apiOK(nil))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.RemoveRoleFromGroup(context.Background(), 8, 2, corestorage.Scope{})
	require.NoError(t, err)
}

// TestRemoteStorage_RemoveRoleFromGroup_SendsScope is the #G80 regression:
// scope was previously discarded entirely (the parameter was named `_`), so a
// scoped revocation (e.g. project 5's roles.assign grant) could never hit its
// target — the server-side handler reads project_id/environment_id from the
// query string, so the client must actually send them.
func TestRemoteStorage_RemoveRoleFromGroup_SendsScope(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "DELETE", r.Method)
		assert.Equal(t, "/api/v1/groups/8/roles/2", r.URL.Path)
		assert.Equal(t, "5", r.URL.Query().Get("project_id"))
		assert.Equal(t, "3", r.URL.Query().Get("environment_id"))
		_, _ = w.Write(apiOK(nil))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.RemoveRoleFromGroup(context.Background(), 8, 2, corestorage.Scope{ProjectID: 5, EnvironmentID: 3})
	require.NoError(t, err)
}

// --- Server-internal authorization primitives (unsupported in remote mode) ---

func TestRemoteStorage_GetUserRoleIDsAt_Unsupported(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfig("http://127.0.0.1:0"))
	require.NoError(t, err)

	_, err = rs.GetUserRoleIDsAt(context.Background(), 1, corestorage.Scope{})
	assert.Error(t, err)
}

func TestRemoteStorage_GetUserRoleIDsExact_Unsupported(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfig("http://127.0.0.1:0"))
	require.NoError(t, err)

	_, err = rs.GetUserRoleIDsExact(context.Background(), 1, corestorage.Scope{})
	assert.Error(t, err)
}

func TestRemoteStorage_IsProjectMember_Unsupported(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfig("http://127.0.0.1:0"))
	require.NoError(t, err)

	_, err = rs.IsProjectMember(context.Background(), 1, 2)
	assert.Error(t, err)
}

func TestRemoteStorage_GetUserGroupRoleIDsAt_Unsupported(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfig("http://127.0.0.1:0"))
	require.NoError(t, err)

	_, err = rs.GetUserGroupRoleIDsAt(context.Background(), 1, corestorage.Scope{})
	assert.Error(t, err)
}

func TestRemoteStorage_GetUserRoleScopes_Unsupported(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfig("http://127.0.0.1:0"))
	require.NoError(t, err)

	_, err = rs.GetUserRoleScopes(context.Background(), 1)
	assert.Error(t, err)
}

func TestRemoteStorage_RoleSetHasPermission_Unsupported(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfig("http://127.0.0.1:0"))
	require.NoError(t, err)

	_, err = rs.RoleSetHasPermission(context.Background(), []uint{1, 2}, "secrets.read")
	assert.Error(t, err)
}

// --- Project / Environment catalog ---

func TestRemoteStorage_CreateProject_Unsupported(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfig("http://127.0.0.1:0"))
	require.NoError(t, err)

	_, err = rs.CreateProject(context.Background(), &models.Project{Name: "test"})
	assert.Error(t, err)
}

func TestRemoteStorage_CreateEnvironment_Unsupported(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfig("http://127.0.0.1:0"))
	require.NoError(t, err)

	_, err = rs.CreateEnvironment(context.Background(), &models.Environment{Name: "prod"})
	assert.Error(t, err)
}

func TestRemoteStorage_ListProjects(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/api/v1/system/projects", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{
			"projects": []map[string]interface{}{
				{"id": 1, "name": "project-alpha", "description": "Alpha"},
			},
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	projects, err := rs.ListProjects(context.Background())
	require.NoError(t, err)
	require.Len(t, projects, 1)
	assert.Equal(t, "project-alpha", projects[0].Name)
}

func TestRemoteStorage_ListProjectsWithCounts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/api/v1/system/projects/with-counts", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{
			"projects": []map[string]interface{}{
				{"ID": 1, "Name": "alpha", "Description": "", "secret_count": 5, "environment_count": 2},
			},
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	projects, err := rs.ListProjectsWithCounts(context.Background(), false)
	require.NoError(t, err)
	require.Len(t, projects, 1)
	assert.Equal(t, int64(5), projects[0].SecretCount)
}

func TestRemoteStorage_GetProject(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/api/v1/system/projects/9", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{"id": 9, "name": "my-project"}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	project, err := rs.GetProject(context.Background(), 9)
	require.NoError(t, err)
	assert.Equal(t, uint(9), project.ID)
	assert.Equal(t, "my-project", project.Name)
}

func TestRemoteStorage_UpdateProject(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "PUT", r.Method)
		assert.Equal(t, "/api/v1/system/projects/9", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{"id": 9, "name": "updated-project"}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	project, err := rs.UpdateProject(context.Background(), &models.Project{ID: 9, Name: "updated-project"})
	require.NoError(t, err)
	assert.Equal(t, uint(9), project.ID)
	assert.Equal(t, "updated-project", project.Name)
}

func TestRemoteStorage_DeleteProject(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "DELETE", r.Method)
		assert.Equal(t, "/api/v1/system/projects/9", r.URL.Path)
		_, _ = w.Write(apiOK(nil))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.DeleteProject(context.Background(), 9)
	require.NoError(t, err)
}

func TestRemoteStorage_DeleteProjectIfEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/api/v1/system/projects/9/delete-if-empty", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{"blocking_secret_count": 0}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	count, err := rs.DeleteProjectIfEmpty(context.Background(), 9)
	require.NoError(t, err)
	assert.Equal(t, 0, count)
}

func TestRemoteStorage_RestoreProject(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/api/v1/system/projects/9/restore", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{
			"restored_environments": 2,
			"restored_secrets":      7,
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	envs, secrets, err := rs.RestoreProject(context.Background(), 9)
	require.NoError(t, err)
	assert.Equal(t, 2, envs)
	assert.Equal(t, 7, secrets)
}

func TestRemoteStorage_ListEnvironments(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/api/v1/system/environments", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{
			"environments": []map[string]interface{}{
				{"id": 1, "project_id": 9, "name": "production"},
			},
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	envs, err := rs.ListEnvironments(context.Background())
	require.NoError(t, err)
	require.Len(t, envs, 1)
	assert.Equal(t, "production", envs[0].Name)
}

func TestRemoteStorage_ListEnvironmentsByProject(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/api/v1/system/projects/9/environments", r.URL.Path)
		assert.Equal(t, "false", r.URL.Query().Get("include_deleted"))
		_, _ = w.Write(apiOK(map[string]interface{}{
			"environments": []map[string]interface{}{
				{"id": 1, "project_id": 9, "name": "staging"},
			},
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	envs, err := rs.ListEnvironmentsByProject(context.Background(), 9)
	require.NoError(t, err)
	require.Len(t, envs, 1)
	assert.Equal(t, "staging", envs[0].Name)
}

func TestRemoteStorage_ListEnvironmentsByProjectIncludingDeleted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/api/v1/system/projects/9/environments", r.URL.Path)
		assert.Equal(t, "true", r.URL.Query().Get("include_deleted"))
		_, _ = w.Write(apiOK(map[string]interface{}{
			"environments": []map[string]interface{}{
				{"id": 1, "project_id": 9, "name": "old-env"},
				{"id": 2, "project_id": 9, "name": "production"},
			},
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	envs, err := rs.ListEnvironmentsByProjectIncludingDeleted(context.Background(), 9)
	require.NoError(t, err)
	require.Len(t, envs, 2)
}

func TestRemoteStorage_GetEnvironment(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/api/v1/system/environments/4", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{"id": 4, "project_id": 9, "name": "production"}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	env, err := rs.GetEnvironment(context.Background(), 4)
	require.NoError(t, err)
	assert.Equal(t, uint(4), env.ID)
	assert.Equal(t, "production", env.Name)
}

func TestRemoteStorage_DeleteEnvironment(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "DELETE", r.Method)
		assert.Equal(t, "/api/v1/system/environments/4", r.URL.Path)
		_, _ = w.Write(apiOK(nil))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.DeleteEnvironment(context.Background(), 4)
	require.NoError(t, err)
}

func TestRemoteStorage_RestoreEnvironment(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/api/v1/system/projects/9/environments/4/restore", r.URL.Path)
		_, _ = w.Write(apiOK(nil))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.RestoreEnvironment(context.Background(), 9, 4)
	require.NoError(t, err)
}

func TestRemoteStorage_ListProjectMembers(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/api/v1/system/projects/9/members", r.URL.Path)
		_, _ = w.Write(apiOK(map[string]interface{}{
			"members": []map[string]interface{}{
				{"user_id": 10, "username": "alice", "display_name": "Alice", "email": "alice@example.com", "role_id": 1, "role_name": "admin"},
			},
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	members, err := rs.ListProjectMembers(context.Background(), 9)
	require.NoError(t, err)
	require.Len(t, members, 1)
	assert.Equal(t, "alice", members[0].Username)
}

func TestRemoteStorage_ListProjectRoleAssignments(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/api/v1/system/rbac/project-role-assignments", r.URL.Path)
		assert.Equal(t, "9", r.URL.Query().Get("project_id"))
		_, _ = w.Write(apiOK([]map[string]interface{}{
			{"principal_type": "user", "principal_id": 10, "role_id": 1, "project_id": 9, "environment_id": 0},
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	assignments, err := rs.ListProjectRoleAssignments(context.Background(), 9)
	require.NoError(t, err)
	require.Len(t, assignments, 1)
	assert.Equal(t, "user", assignments[0].PrincipalType)
}

func TestRemoteStorage_ListProjectMachineRoleAssignments(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/api/v1/system/rbac/project-machine-role-assignments", r.URL.Path)
		assert.Equal(t, "9", r.URL.Query().Get("project_id"))
		_, _ = w.Write(apiOK([]map[string]interface{}{
			{"principal_type": "machine", "principal_id": 20, "role_id": 2, "project_id": 9, "environment_id": 0},
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	assignments, err := rs.ListProjectMachineRoleAssignments(context.Background(), 9)
	require.NoError(t, err)
	require.Len(t, assignments, 1)
	assert.Equal(t, "machine", assignments[0].PrincipalType)
}

func TestRemoteStorage_ListGlobalAdminAssignmentsForUpdate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/api/v1/system/rbac/global-admin-assignments", r.URL.Path)
		_, _ = w.Write(apiOK([]map[string]interface{}{
			{"principal_type": "user", "principal_id": 1, "role_id": 1, "project_id": 0, "environment_id": 0},
		}))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	assignments, err := rs.ListGlobalAdminAssignmentsForUpdate(context.Background(), []uint{1, 2})
	require.NoError(t, err)
	require.Len(t, assignments, 1)
	assert.Equal(t, uint(1), assignments[0].RoleID)
}

func TestRemoteStorage_RemoveGlobalAdminRoleGuarded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/api/v1/system/rbac/global-admin-role/remove-guarded", r.URL.Path)
		_, _ = w.Write(apiOK(nil))
	}))
	defer srv.Close()

	rs, err := store.NewRemoteStorage(testConfig(srv.URL))
	require.NoError(t, err)

	err = rs.RemoveGlobalAdminRoleGuarded(context.Background(), 10, 1, []uint{1, 2})
	require.NoError(t, err)
}
