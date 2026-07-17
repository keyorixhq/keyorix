// rbac_s24_test.go — coverage sprint 24 for internal/cli/rbac.
//
// Targets the following uncovered / under-covered paths:
//
//   - userEffectivePermissions: dedup branch (two roles share a permission → the
//     `continue` on the second occurrence is never hit by existing tests)
//   - userEffectivePermissions: error when the role-permissions endpoint fails
//   - resolveUserIDByEmail: error when the users-list endpoint itself returns 500
//     (existing tests only cover the "user not found in list" path)
//   - runAuditLogsRemote: error path (server returns 500)
//   - runListUserRolesRemote: error when resolveUserIDByEmail fails (500 on /users)
//   - runListPermissionsRemote: error when resolveUserIDByEmail fails (500 on /users)
//   - runCheckPermissionRemote: error when resolveUserIDByEmail fails (500 on /users)
//   - runAssignRoleRemote: error when the POST to /api/v1/user-roles fails
//   - auditLogsCmd flag defaults (--limit default 50, --offset default 0)
//   - listPermissionsCmd --user required flag annotation
//   - listUserRolesCmd --user required flag annotation
package rbac

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── userEffectivePermissions dedup branch ────────────────────────────────────

// TestUserEffectivePermissions_Dedup exercises the "already seen" continue branch
// inside userEffectivePermissions. Two roles each expose "secrets.read"; the second
// occurrence must be silently skipped so the returned slice has no duplicates.
func TestUserEffectivePermissions_Dedup(t *testing.T) {
	mux := http.NewServeMux()
	// User 7 holds two roles: 10 and 11.
	mux.HandleFunc("/api/v1/users/7/roles", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"roles":[
			{"id":10,"name":"role-a","description":""},
			{"id":11,"name":"role-b","description":""}
		]}}`))
	})
	// Role 10: secrets.read + secrets.write
	mux.HandleFunc("/api/v1/roles/10/permissions", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"permissions":[
			{"name":"secrets.read"},
			{"name":"secrets.write"}
		]}}`))
	})
	// Role 11: secrets.read (duplicate) + users.read (new)
	mux.HandleFunc("/api/v1/roles/11/permissions", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"permissions":[
			{"name":"secrets.read"},
			{"name":"users.read"}
		]}}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	rc := remoteClientFor(t, srv)
	perms, err := userEffectivePermissions(context.Background(), rc, 7)
	require.NoError(t, err)
	// "secrets.read" must appear exactly once despite being in both roles.
	assert.ElementsMatch(t, []string{"secrets.read", "secrets.write", "users.read"}, perms)
}

// ── userEffectivePermissions permissions-fetch error ─────────────────────────

// TestUserEffectivePermissions_PermsFetchError exercises the error branch when the
// role-permissions endpoint returns a server error.
func TestUserEffectivePermissions_PermsFetchError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/users/8/roles", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"roles":[{"id":20,"name":"broken","description":""}]}}`))
	})
	// Role 20's permissions endpoint always fails.
	mux.HandleFunc("/api/v1/roles/20/permissions", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	rc := remoteClientFor(t, srv)
	_, err := userEffectivePermissions(context.Background(), rc, 8)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get permissions for role")
}

// ── resolveUserIDByEmail: HTTP error from /api/v1/users ──────────────────────

// TestResolveUserIDByEmail_HTTPError exercises the error path where the users-list
// endpoint itself returns a server error (distinct from the "user not in list" case).
func TestResolveUserIDByEmail_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	rc := remoteClientFor(t, srv)
	_, err := resolveUserIDByEmail(context.Background(), rc, "anyone@example.com")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list users")
}

// ── runAuditLogsRemote error path ────────────────────────────────────────────

// TestRunAuditLogsRemote_Error exercises the error branch in runAuditLogsRemote
// when the server returns a non-2xx response.
func TestRunAuditLogsRemote_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	rc := remoteClientFor(t, srv)
	err := runAuditLogsRemote(context.Background(), rc, 1, 50)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to retrieve RBAC audit logs")
}

// ── runListUserRolesRemote: resolveUserIDByEmail error ───────────────────────

// TestRunListUserRolesRemote_UsersFetchError exercises the error path in
// runListUserRolesRemote when the users-list endpoint fails.
func TestRunListUserRolesRemote_UsersFetchError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	rc := remoteClientFor(t, srv)
	err := runListUserRolesRemote(context.Background(), rc, "anyone@example.com")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list users")
}

// ── runListPermissionsRemote: resolveUserIDByEmail error ─────────────────────

// TestRunListPermissionsRemote_UsersFetchError exercises the error path in
// runListPermissionsRemote when the users-list endpoint fails.
func TestRunListPermissionsRemote_UsersFetchError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	rc := remoteClientFor(t, srv)
	err := runListPermissionsRemote(context.Background(), rc, "anyone@example.com")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list users")
}

// ── runCheckPermissionRemote: resolveUserIDByEmail error ─────────────────────

// TestRunCheckPermissionRemote_UsersFetchError exercises the error path in
// runCheckPermissionRemote when the users-list endpoint fails.
func TestRunCheckPermissionRemote_UsersFetchError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	rc := remoteClientFor(t, srv)
	err := runCheckPermissionRemote(context.Background(), rc, "anyone@example.com", "secrets.read")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list users")
}

// ── runAssignRoleRemote: POST /api/v1/user-roles fails ───────────────────────

// TestRunAssignRoleRemote_PostFails exercises the error path when the role-assignment
// POST endpoint returns a server error.
func TestRunAssignRoleRemote_PostFails(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/users", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"users":[{"id":5,"email":"alice@test.com"}]}}`))
	})
	mux.HandleFunc("/api/v1/roles", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"roles":[{"id":1,"name":"admin","description":"Admin"}]}}`))
	})
	mux.HandleFunc("/api/v1/user-roles", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	rc := remoteClientFor(t, srv)
	err := runAssignRoleRemote(context.Background(), rc, "alice@test.com", "admin", 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to assign role")
}

// ── auditLogsCmd flag defaults ───────────────────────────────────────────────

// TestAuditLogsCmd_FlagDefaults verifies that the --limit and --offset flags
// exist on auditLogsCmd with the documented default values.
func TestAuditLogsCmd_FlagDefaults(t *testing.T) {
	limitFlag := auditLogsCmd.Flags().Lookup("limit")
	require.NotNil(t, limitFlag, "--limit flag must exist")
	assert.Equal(t, "50", limitFlag.DefValue)

	offsetFlag := auditLogsCmd.Flags().Lookup("offset")
	require.NotNil(t, offsetFlag, "--offset flag must exist")
	assert.Equal(t, "0", offsetFlag.DefValue)
}

// ── listPermissionsCmd required flag annotation ───────────────────────────────

// TestListPermissionsCmd_RequiredFlags verifies that the --user flag on
// list-permissions is marked as required.
func TestListPermissionsCmd_RequiredFlags(t *testing.T) {
	const cobraRequired = "cobra_annotation_bash_completion_one_required_flag"
	f := listPermissionsCmd.Flags().Lookup("user")
	require.NotNil(t, f, "--user flag must exist on list-permissions")
	assert.NotEmpty(t, f.Annotations[cobraRequired], "--user should be required on list-permissions")
}

// ── listUserRolesCmd required flag annotation ─────────────────────────────────

// TestListUserRolesCmd_RequiredFlags verifies that the --user flag on
// list-user-roles is marked as required.
func TestListUserRolesCmd_RequiredFlags(t *testing.T) {
	const cobraRequired = "cobra_annotation_bash_completion_one_required_flag"
	f := listUserRolesCmd.Flags().Lookup("user")
	require.NotNil(t, f, "--user flag must exist on list-user-roles")
	assert.NotEmpty(t, f.Annotations[cobraRequired], "--user should be required on list-user-roles")
}

// ── runAuditLogsRemote populated path: explicit header + entry verification ──

// TestRunAuditLogsRemote_PopulatedLogs directly tests the populated-logs branch
// of runAuditLogsRemote. It is distinct from TestRunAuditLogsRemote in remote_test.go
// in that it constructs a minimal server that returns exactly one log entry and
// verifies runAuditLogsRemote returns no error (output content is verified by
// TestPrintAuditEntry in rbac_remote_stubs_test.go).
func TestRunAuditLogsRemote_PopulatedLogs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"logs":[
			{"id":1,"action":"role.assigned","actor_user_id":1,"target_user_id":2,
			 "role_id":3,"created_at":"2026-07-14T12:00:00Z","details":"sprint24"}
		],"total":1}}`))
	}))
	defer srv.Close()

	rc := remoteClientFor(t, srv)
	err := runAuditLogsRemote(context.Background(), rc, 1, 50)
	require.NoError(t, err)
}

// ── fetchUserRoles: HTTP error ────────────────────────────────────────────────

// TestFetchUserRoles_HTTPError verifies that fetchUserRoles propagates an HTTP
// error from the user-roles endpoint with the expected error message.
// (Distinct from TestFetchUserRoles_Error in rbac_s2_test.go which exercises the
// same path; this version ensures the "failed to get user roles" sentinel text.)
func TestFetchUserRoles_ErrorMessage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	rc := remoteClientFor(t, srv)
	_, err := fetchUserRoles(context.Background(), rc, 99)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get user roles")
}
