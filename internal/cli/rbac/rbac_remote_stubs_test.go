package rbac

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRunListRolesRemote_Empty verifies the "No roles found" branch.
func TestRunListRolesRemote_Empty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"roles":[]}}`))
	}))
	defer srv.Close()
	rc := remoteClientFor(t, srv)
	require.NoError(t, runListRolesRemote(context.Background(), rc))
}

// TestRunListUserRolesRemote_Empty verifies the "No roles" branch for a user with no roles.
func TestRunListUserRolesRemote_Empty(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/users", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"users":[{"id":5,"email":"alice@test.com"}]}}`))
	})
	mux.HandleFunc("/api/v1/users/5/roles", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"roles":[]}}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	rc := remoteClientFor(t, srv)
	require.NoError(t, runListUserRolesRemote(context.Background(), rc, "alice@test.com"))
}

// TestRunListPermissionsRemote_Empty verifies the "No permissions" branch.
func TestRunListPermissionsRemote_Empty(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/users", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"users":[{"id":5,"email":"alice@test.com"}]}}`))
	})
	mux.HandleFunc("/api/v1/users/5/roles", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"roles":[]}}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	rc := remoteClientFor(t, srv)
	require.NoError(t, runListPermissionsRemote(context.Background(), rc, "alice@test.com"))
}

// TestAssignRoleCmd_Remote exercises the RunE body for assign-role in remote mode.
func TestAssignRoleCmd_Remote(t *testing.T) {
	srv := fakeRBACServer(t)
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	orig := userEmail
	origR := roleName
	origTTL := roleTTL
	defer func() { userEmail = orig; roleName = origR; roleTTL = origTTL }()

	userEmail = "alice@test.com"
	roleName = "viewer"
	roleTTL = 0

	require.NoError(t, runAssignRole(nil, nil))
}

// TestRemoveRoleCmd_Remote exercises the RunE body for remove-role in remote mode.
func TestRemoveRoleCmd_Remote(t *testing.T) {
	srv := fakeRBACServer(t)
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	orig := removeUserEmail
	origR := removeRoleName
	defer func() { removeUserEmail = orig; removeRoleName = origR }()

	removeUserEmail = "alice@test.com"
	removeRoleName = "viewer"

	require.NoError(t, runRemoveRole(nil, nil))
}

// TestListRolesCmd_Remote exercises the RunE body for list-roles in remote mode.
func TestListRolesCmd_Remote(t *testing.T) {
	srv := fakeRBACServer(t)
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	require.NoError(t, runListRoles(nil, nil))
}

// TestListUserRolesCmd_Remote exercises the RunE body for list-user-roles in remote mode.
func TestListUserRolesCmd_Remote(t *testing.T) {
	srv := fakeRBACServer(t)
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	orig := listUserEmail
	defer func() { listUserEmail = orig }()
	listUserEmail = "alice@test.com"

	require.NoError(t, runListUserRoles(nil, nil))
}

// TestCheckPermissionCmd_Remote exercises the RunE body for check-permission in remote mode.
func TestCheckPermissionCmd_Remote(t *testing.T) {
	srv := fakeRBACServer(t)
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	orig := checkUserEmail
	origP := checkPermissionName
	defer func() { checkUserEmail = orig; checkPermissionName = origP }()

	checkUserEmail = "alice@test.com"
	checkPermissionName = "secrets.read"

	require.NoError(t, runCheckPermission(nil, nil))
}

// TestListPermissionsCmd_Remote exercises the RunE body for list-permissions in remote mode.
func TestListPermissionsCmd_Remote(t *testing.T) {
	srv := fakeRBACServer(t)
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	orig := listPermissionsUserEmail
	defer func() { listPermissionsUserEmail = orig }()
	listPermissionsUserEmail = "alice@test.com"

	require.NoError(t, runListPermissions(nil, nil))
}

// TestAuditLogsCmd_Remote exercises the RunE body for audit-logs in remote mode.
func TestAuditLogsCmd_Remote(t *testing.T) {
	srv := fakeRBACServer(t)
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	origL, origO := auditLimit, auditOffset
	defer func() { auditLimit = origL; auditOffset = origO }()
	auditLimit = 50
	auditOffset = 0

	require.NoError(t, runAuditLogs(nil, nil))
}

// TestAuditLogsCmd_NoLogs verifies the "no logs" branch.
func TestAuditLogsCmd_NoLogs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"logs":[],"total":0,"page":1,"page_size":50,"total_pages":0}}`))
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	origL, origO := auditLimit, auditOffset
	defer func() { auditLimit = origL; auditOffset = origO }()
	auditLimit = 50
	auditOffset = 0

	require.NoError(t, runAuditLogs(nil, nil))
}

// TestPrintAuditEntry exercises all conditional branches.
func TestPrintAuditEntry(t *testing.T) {
	actorID := uint(1)
	targetID := uint(5)
	groupID := uint(2)
	roleID := uint(3)
	permID := uint(4)
	projectID := uint(7)

	// All fields populated — should not panic.
	printAuditEntry("2026-07-01T10:00:00Z", "role.assigned",
		&actorID, &targetID, &groupID, &roleID, &permID, &projectID, "detail")

	// Nil/zero fields — should not panic.
	printAuditEntry("2026-07-01T10:00:00Z", "role.removed",
		nil, nil, nil, nil, nil, nil, "")

	// Zero project (should be omitted).
	zeroProject := uint(0)
	printAuditEntry("2026-07-01T10:00:00Z", "perm.added",
		&actorID, nil, nil, nil, &permID, &zeroProject, "")
}

// TestCheckPermissionRemote_InvalidPermName verifies invalid permission name is rejected.
func TestCheckPermissionRemote_InvalidPermName(t *testing.T) {
	srv := fakeRBACServer(t)
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	orig := checkUserEmail
	origP := checkPermissionName
	defer func() { checkUserEmail = orig; checkPermissionName = origP }()

	checkUserEmail = "alice@test.com"
	checkPermissionName = "invalid-no-dot"

	err := runCheckPermission(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "resource.action")
}
