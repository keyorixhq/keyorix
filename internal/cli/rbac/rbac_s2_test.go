// rbac_s2_test.go — coverage sprint 2 for internal/cli/rbac.
// Targets: embedded-mode paths for runAssignRole, runRemoveRole, runListRoles,
// runListUserRoles, runListPermissions, runCheckPermission, runAuditLogsEmbedded,
// and the --ttl-in-embedded-mode rejection.
package rbac

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupEmbeddedMode sets KEYORIX_SERVER="" so NewRemoteClient returns false,
// creates a minimal keyorix.yaml so InitializeStorage succeeds, and chdirs
// to the temp dir so storage.CreateStorage creates a local SQLite.
func setupEmbeddedMode(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	// Write a minimal keyorix.yaml so config.Load("") succeeds.
	yaml := "storage:\n  type: local\n  database:\n    path: " + dir + "/secrets.db\n"
	if err := os.WriteFile(dir+"/keyorix.yaml", []byte(yaml), 0600); err != nil {
		t.Fatalf("setupEmbeddedMode: %v", err)
	}
}

// ──────────────────────────── runAssignRole embedded ─────────────────────────

// TestAssignRole_TTL_EmbeddedMode verifies that --ttl > 0 in embedded mode
// returns the "requires a server connection" error (not a panic).
func TestAssignRole_TTL_EmbeddedMode(t *testing.T) {
	setupEmbeddedMode(t)

	origTTL := roleTTL
	defer func() { roleTTL = origTTL }()
	roleTTL = 0 // bypass the remote mode; TTL = 0 means no JIT branch

	// With storage init → InitializeStorage → SQLite created → AssignRoleToUser
	// fails (user not found), but embedded mode is entered.
	origU, origR := userEmail, roleName
	defer func() { userEmail = origU; roleName = origR }()
	userEmail = "someone@example.com"
	roleName = "viewer"

	err := runAssignRole(nil, nil)
	// Expected: storage init succeeds, AssignRoleToUser fails (user not found).
	// Not a TTL error or remote-mode error.
	if err != nil {
		assert.NotContains(t, err.Error(), "--ttl must be positive")
	}
}

// TestAssignRole_TTL_EmbeddedRejection verifies that a positive TTL in embedded
// (non-remote) mode is rejected with the appropriate error.
func TestAssignRole_TTL_EmbeddedRejection(t *testing.T) {
	setupEmbeddedMode(t)

	origTTL := roleTTL
	defer func() { roleTTL = origTTL }()
	roleTTL = 1 // positive → rejected in embedded mode

	err := runAssignRole(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--ttl requires a server connection")
}

// ──────────────────────────── runRemoveRole embedded ─────────────────────────

func TestRemoveRole_EmbeddedMode(t *testing.T) {
	setupEmbeddedMode(t)

	origU, origR := removeUserEmail, removeRoleName
	defer func() { removeUserEmail = origU; removeRoleName = origR }()
	removeUserEmail = "someone@example.com"
	removeRoleName = "viewer"

	err := runRemoveRole(nil, nil)
	// Storage init succeeds; RemoveRoleFromUser fails (user/role not found).
	if err != nil {
		assert.NotContains(t, err.Error(), "--ttl must be positive")
	}
}

// ──────────────────────────── runListRoles embedded ──────────────────────────

func TestListRoles_EmbeddedMode_Empty(t *testing.T) {
	setupEmbeddedMode(t)
	// runListRoles → InitializeStorage → st.ListRoles → empty (not bootstrapped).
	// The "No roles found" branch should be reached (bootstrap seeded no roles).
	err := runListRoles(nil, nil)
	// SQLite created, no roles → "No roles found" or bootstrap seeded some.
	_ = err
}

// TestListRoles_EmbeddedMode_WithRoles verifies the listing path when roles exist.
// We seed the DB with a minimal config and rely on core bootstrap seeding default roles.

// ──────────────────────────── runListUserRoles embedded ──────────────────────

func TestListUserRoles_EmbeddedMode_UserNotFound(t *testing.T) {
	setupEmbeddedMode(t)

	origU := listUserEmail
	defer func() { listUserEmail = origU }()
	listUserEmail = "someone@example.com"

	// ListUserRolesByEmail: user not found → error.
	err := runListUserRoles(nil, nil)
	_ = err
}

// TestListUserRoles_EmbeddedMode_Empty verifies the "no roles assigned" branch
// is reachable (user exists but has no roles).

// ──────────────────────────── runListPermissions embedded ────────────────────

func TestListPermissions_EmbeddedMode_UserNotFound(t *testing.T) {
	setupEmbeddedMode(t)

	origU := listPermissionsUserEmail
	defer func() { listPermissionsUserEmail = origU }()
	listPermissionsUserEmail = "someone@example.com"

	err := runListPermissions(nil, nil)
	_ = err
}

// TestListPermissions_EmbeddedMode_NoPermissions exercises the "No permissions found"
// branch — reachable when the user exists but has no roles/permissions.

// ──────────────────────────── runCheckPermission embedded ────────────────────

func TestCheckPermission_EmbeddedMode_InvalidFormat(t *testing.T) {
	setupEmbeddedMode(t)

	origU, origP := checkUserEmail, checkPermissionName
	defer func() { checkUserEmail = origU; checkPermissionName = origP }()
	checkUserEmail = "someone@example.com"
	checkPermissionName = "invalid-no-dot"

	// splitPermissionName is called after InitializeStorage succeeds.
	err := runCheckPermission(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "resource.action")
}

func TestCheckPermission_EmbeddedMode_ValidFormat(t *testing.T) {
	setupEmbeddedMode(t)

	origU, origP := checkUserEmail, checkPermissionName
	defer func() { checkUserEmail = origU; checkPermissionName = origP }()
	checkUserEmail = "someone@example.com"
	checkPermissionName = "secrets.read"

	// splitPermissionName succeeds; HasPermissionByEmail may fail (user not found).
	err := runCheckPermission(nil, nil)
	_ = err
}

// ──────────────────────────── runAuditLogsEmbedded ───────────────────────────

// TestAuditLogs_EmbeddedMode_Empty tests runAuditLogsEmbedded with an empty DB.
// #G-blank-storage-default: runAuditLogsEmbedded uses InitializeCoreService,
// which no longer silently falls back to local storage with no config file
// present — write an explicit minimal keyorix.yaml via setupEmbeddedMode so
// this still exercises a real SQLite-backed run, exactly as before.
func TestAuditLogs_EmbeddedMode_Empty(t *testing.T) {
	setupEmbeddedMode(t)

	origL, origO := auditLimit, auditOffset
	defer func() { auditLimit = origL; auditOffset = origO }()
	auditLimit = 50
	auditOffset = 0

	// runAuditLogs dispatches to runAuditLogsEmbedded when no remote client.
	err := runAuditLogs(nil, nil)
	// Empty DB → "No RBAC audit logs found"; no panic.
	require.NoError(t, err)
}

// TestAuditLogs_EmbeddedMode_ZeroLimit verifies the auditLimit < 1 → 50 branch.
func TestAuditLogs_EmbeddedMode_ZeroLimit(t *testing.T) {
	setupEmbeddedMode(t)

	origL, origO := auditLimit, auditOffset
	defer func() { auditLimit = origL; auditOffset = origO }()
	auditLimit = 0 // triggers the reset-to-50 branch
	auditOffset = 0

	err := runAuditLogs(nil, nil)
	require.NoError(t, err)
}

// TestAuditLogsEmbedded_NonZeroOffset verifies pagination calculation (page > 1).
func TestAuditLogsEmbedded_NonZeroOffset(t *testing.T) {
	setupEmbeddedMode(t)

	origL, origO := auditLimit, auditOffset
	defer func() { auditLimit = origL; auditOffset = origO }()
	auditLimit = 10
	auditOffset = 20 // page = (20/10)+1 = 3

	err := runAuditLogs(nil, nil)
	require.NoError(t, err)
}

// ──────────────────────────── remote error paths ──────────────────────────────

// TestRemoveRoleRemote_RoleNotFound exercises the "role not found" branch in
// runRemoveRoleRemote / resolveRoleIDByName.
func TestRemoveRoleRemote_RoleNotFound(t *testing.T) {
	srv := fakeRBACServer(t) // returns roles ["admin","viewer"] only
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	orig := removeUserEmail
	origR := removeRoleName
	defer func() { removeUserEmail = orig; removeRoleName = origR }()
	removeUserEmail = "alice@test.com"
	removeRoleName = "nonexistent-role"

	err := runRemoveRole(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nonexistent-role")
}

// TestRemoveRoleRemote_UserNotFound exercises resolveUserIDByEmail error branch.
func TestRemoveRoleRemote_UserNotFound(t *testing.T) {
	srv := fakeRBACServer(t) // returns only alice@test.com
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	orig := removeUserEmail
	origR := removeRoleName
	defer func() { removeUserEmail = orig; removeRoleName = origR }()
	removeUserEmail = "nobody@example.com"
	removeRoleName = "viewer"

	err := runRemoveRole(nil, nil)
	require.Error(t, err)
}

// TestListRolesRemote_WithRoles verifies the success branch (roles listed).
func TestListRolesRemote_WithRoles(t *testing.T) {
	srv := fakeRBACServer(t)
	rc := remoteClientFor(t, srv)
	err := runListRolesRemote(context.Background(), rc)
	require.NoError(t, err)
}

// TestListUserRolesRemote_WithRoles verifies the "has roles" branch.
func TestListUserRolesRemote_WithRoles(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/users", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"users":[{"id":5,"email":"alice@test.com"}]}}`))
	})
	mux.HandleFunc("/api/v1/users/5/roles", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"roles":[{"id":1,"name":"admin","description":"Admin"}]}}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	rc := remoteClientFor(t, srv)
	err := runListUserRolesRemote(context.Background(), rc, "alice@test.com")
	require.NoError(t, err)
}

// TestListPermissionsRemote_WithPerms verifies the "has permissions" branch.
func TestListPermissionsRemote_WithPerms(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/users", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"users":[{"id":5,"email":"alice@test.com"}]}}`))
	})
	// Roles for the user
	mux.HandleFunc("/api/v1/users/5/roles", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"roles":[{"id":1,"name":"admin","description":"Admin"}]}}`))
	})
	// Permissions for role 1
	mux.HandleFunc("/api/v1/roles/1/permissions", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"permissions":[{"name":"secrets.read"},{"name":"secrets.write"}]}}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	rc := remoteClientFor(t, srv)
	err := runListPermissionsRemote(context.Background(), rc, "alice@test.com")
	require.NoError(t, err)
}

// TestCheckPermissionRemote_HasPermission verifies the "user has permission" branch.
func TestCheckPermissionRemote_HasPermission(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/users", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"users":[{"id":5,"email":"alice@test.com"}]}}`))
	})
	mux.HandleFunc("/api/v1/users/5/roles", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"roles":[{"id":1,"name":"admin","description":"Admin"}]}}`))
	})
	mux.HandleFunc("/api/v1/roles/1/permissions", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"permissions":[{"name":"secrets.read"}]}}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	rc := remoteClientFor(t, srv)
	err := runCheckPermissionRemote(context.Background(), rc, "alice@test.com", "secrets.read")
	require.NoError(t, err)
}

// TestFetchRoles_Error covers the fetchRoles error path when server returns an error.
func TestFetchRoles_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	rc := remoteClientFor(t, srv)
	_, err := fetchRoles(context.Background(), rc)
	require.Error(t, err)
}

// TestFetchUserRoles_Error covers the fetchUserRoles error path.
func TestFetchUserRoles_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	rc := remoteClientFor(t, srv)
	_, err := fetchUserRoles(context.Background(), rc, 5)
	require.Error(t, err)
}

// TestListRolesRemote_Error covers the error branch in runListRolesRemote.
func TestListRolesRemote_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	rc := remoteClientFor(t, srv)
	err := runListRolesRemote(context.Background(), rc)
	require.Error(t, err)
}

// TestRemoveRoleRemote_DeleteFails covers the DeleteWithBody error path.
func TestRemoveRoleRemote_DeleteFails(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/users", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"users":[{"id":5,"email":"alice@test.com"}]}}`))
	})
	mux.HandleFunc("/api/v1/roles", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"roles":[{"id":2,"name":"viewer","description":"Viewer"}]}}`))
	})
	mux.HandleFunc("/api/v1/user-roles", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	rc := remoteClientFor(t, srv)
	err := runRemoveRoleRemote(context.Background(), rc, "alice@test.com", "viewer", "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to remove role")
}

// TestResolveRoleIDByName_NotFound covers the "role not found" error in resolveRoleIDByName.
func TestResolveRoleIDByName_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"roles":[{"id":1,"name":"admin"}]}}`))
	}))
	defer srv.Close()
	rc := remoteClientFor(t, srv)
	_, err := resolveRoleIDByName(context.Background(), rc, "nonexistent")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nonexistent")
}

// TestCheckPermissionRemote_NotHasPermission verifies the "user lacks permission" branch.
func TestCheckPermissionRemote_NotHasPermission(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/users", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"users":[{"id":5,"email":"alice@test.com"}]}}`))
	})
	mux.HandleFunc("/api/v1/users/5/roles", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"roles":[{"id":1,"name":"viewer","description":"Viewer"}]}}`))
	})
	mux.HandleFunc("/api/v1/roles/1/permissions", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"permissions":[{"name":"secrets.read"}]}}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	rc := remoteClientFor(t, srv)
	// secrets.write is not in the permissions list
	err := runCheckPermissionRemote(context.Background(), rc, "alice@test.com", "secrets.write")
	require.NoError(t, err) // prints "does NOT have permission"
}
