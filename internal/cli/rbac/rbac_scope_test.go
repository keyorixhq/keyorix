package rbac

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/testhelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── Local-mode (direct-DB) scope tests ───────────────────────────────────────

// TestAssignUserRoleScoped_ProjectScope verifies that AssignUserRoleScoped stores
// the grant with the correct ProjectID and zero EnvironmentID.
func TestAssignUserRoleScoped_ProjectScope(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()

	user := h.CreateTestUser(t, "scopeuser", 20)
	user.Email = "scopeuser@test.com"
	h.DB.Save(user)

	ctx := context.Background()

	// Assign role scoped to project 2 ("production" seeded in seedTestData).
	scope := storage.Scope{ProjectID: 2}
	svc := core.NewKeyorixCore(h.Storage)
	err := svc.AssignUserRoleScoped(ctx, user.Email, "editor", scope)
	require.NoError(t, err)

	// Verify the stored grant has the expected scope.
	rows := h.QueryRawSQL(t, `
		SELECT ur.project_id, ur.environment_id
		FROM user_roles ur
		JOIN roles r ON ur.role_id = r.id
		WHERE ur.user_id = ? AND r.name = 'editor'`, user.ID)
	defer rows.Close() //nolint:errcheck

	require.True(t, rows.Next(), "expected one user_role row")
	var projectID, environmentID uint
	require.NoError(t, rows.Scan(&projectID, &environmentID))
	assert.Equal(t, uint(2), projectID)
	assert.Equal(t, uint(0), environmentID)
}

// TestAssignUserRoleScoped_ProjectAndEnvScope verifies that AssignUserRoleScoped
// stores the grant with both ProjectID and EnvironmentID set.
func TestAssignUserRoleScoped_ProjectAndEnvScope(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()

	user := h.CreateTestUser(t, "scopeuser2", 21)
	user.Email = "scopeuser2@test.com"
	h.DB.Save(user)

	ctx := context.Background()

	// Assign role scoped to project 2 / environment 1.
	scope := storage.Scope{ProjectID: 2, EnvironmentID: 1}
	svc := core.NewKeyorixCore(h.Storage)
	err := svc.AssignUserRoleScoped(ctx, user.Email, "viewer", scope)
	require.NoError(t, err)

	rows := h.QueryRawSQL(t, `
		SELECT ur.project_id, ur.environment_id
		FROM user_roles ur
		JOIN roles r ON ur.role_id = r.id
		WHERE ur.user_id = ? AND r.name = 'viewer'`, user.ID)
	defer rows.Close() //nolint:errcheck

	require.True(t, rows.Next(), "expected one user_role row")
	var projectID, environmentID uint
	require.NoError(t, rows.Scan(&projectID, &environmentID))
	assert.Equal(t, uint(2), projectID)
	assert.Equal(t, uint(1), environmentID)
}

// TestAssignUserRoleScoped_GlobalFallback verifies that passing Scope{} (the zero
// value) still assigns globally (ProjectID == 0).
func TestAssignUserRoleScoped_GlobalFallback(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()

	user := h.CreateTestUser(t, "globaluser", 22)
	user.Email = "globaluser@test.com"
	h.DB.Save(user)

	ctx := context.Background()

	svc := core.NewKeyorixCore(h.Storage)
	err := svc.AssignUserRoleScoped(ctx, user.Email, "viewer", storage.Scope{})
	require.NoError(t, err)

	rows := h.QueryRawSQL(t, `
		SELECT ur.project_id, ur.environment_id
		FROM user_roles ur
		JOIN roles r ON ur.role_id = r.id
		WHERE ur.user_id = ? AND r.name = 'viewer'`, user.ID)
	defer rows.Close() //nolint:errcheck

	require.True(t, rows.Next(), "expected one user_role row for global grant")
	var projectID, environmentID uint
	require.NoError(t, rows.Scan(&projectID, &environmentID))
	assert.Equal(t, uint(0), projectID, "global grant must have ProjectID == 0")
	assert.Equal(t, uint(0), environmentID)
}

// TestRemoveUserRoleScoped_ProjectScope verifies that a scoped grant can be
// removed by the matching scope.
func TestRemoveUserRoleScoped_ProjectScope(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()

	user := h.CreateTestUser(t, "removeuser", 23)
	user.Email = "removeuser@test.com"
	h.DB.Save(user)

	ctx := context.Background()
	scope := storage.Scope{ProjectID: 2}
	svc := core.NewKeyorixCore(h.Storage)

	require.NoError(t, svc.AssignUserRoleScoped(ctx, user.Email, "editor", scope))
	require.NoError(t, svc.RemoveUserRoleScoped(ctx, user.Email, "editor", scope))

	rows := h.QueryRawSQL(t, `
		SELECT COUNT(*) FROM user_roles ur
		JOIN roles r ON ur.role_id = r.id
		WHERE ur.user_id = ? AND r.name = 'editor'`, user.ID)
	defer rows.Close() //nolint:errcheck

	require.True(t, rows.Next())
	var count int
	require.NoError(t, rows.Scan(&count))
	assert.Equal(t, 0, count, "scoped grant should be removed")
}

// ── Scope flag CLI-layer tests (assign-role / remove-role flags) ──────────────

// TestAssignRoleCmd_ScopeFlags verifies that --project and --environment flags
// exist on the assign-role command.
func TestAssignRoleCmd_ScopeFlags(t *testing.T) {
	projectFlag := assignRoleCmd.Flags().Lookup("project")
	require.NotNil(t, projectFlag, "--project flag should exist on assign-role")

	envFlag := assignRoleCmd.Flags().Lookup("environment")
	require.NotNil(t, envFlag, "--environment flag should exist on assign-role")
}

// TestRemoveRoleCmd_ScopeFlags verifies that --project and --environment flags
// exist on the remove-role command.
func TestRemoveRoleCmd_ScopeFlags(t *testing.T) {
	projectFlag := removeRoleCmd.Flags().Lookup("project")
	require.NotNil(t, projectFlag, "--project flag should exist on remove-role")

	envFlag := removeRoleCmd.Flags().Lookup("environment")
	require.NotNil(t, envFlag, "--environment flag should exist on remove-role")
}

// ── Remote-mode scope tests ───────────────────────────────────────────────────

// TestRunAssignRoleRemote_WithProject verifies that project_id is included in the
// POST body when --project is supplied in remote mode.
func TestRunAssignRoleRemote_WithProject(t *testing.T) {
	var gotBody map[string]interface{}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/users", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"users":[{"id":5,"email":"alice@test.com"}]}}`))
	})
	mux.HandleFunc("/api/v1/roles", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"roles":[{"id":1,"name":"editor","description":""}]}}`))
	})
	mux.HandleFunc("/api/v1/projects", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"projects":[{"id":3,"name":"staging"}]}}`))
	})
	mux.HandleFunc("/api/v1/user-roles", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"data":{"user_id":5,"role_id":1}}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	rc := remoteClientFor(t, srv)

	err := runAssignRoleRemote(context.Background(), rc, "alice@test.com", "editor", 0, "staging", "")
	require.NoError(t, err)
	assert.Equal(t, float64(3), gotBody["project_id"], "project_id must be resolved and sent")
	assert.Nil(t, gotBody["environment_id"], "environment_id must be absent when --environment is not set")
}

// TestRunAssignRoleRemote_WithProjectAndEnv verifies that both project_id and
// environment_id appear in the POST body when both flags are supplied.
func TestRunAssignRoleRemote_WithProjectAndEnv(t *testing.T) {
	var gotBody map[string]interface{}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/users", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"users":[{"id":5,"email":"alice@test.com"}]}}`))
	})
	mux.HandleFunc("/api/v1/roles", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"roles":[{"id":1,"name":"editor","description":""}]}}`))
	})
	mux.HandleFunc("/api/v1/projects", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"projects":[{"id":3,"name":"staging"}]}}`))
	})
	mux.HandleFunc("/api/v1/environments", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"environments":[{"id":2,"name":"dev"}]}}`))
	})
	mux.HandleFunc("/api/v1/user-roles", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"data":{"user_id":5,"role_id":1}}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	rc := remoteClientFor(t, srv)

	err := runAssignRoleRemote(context.Background(), rc, "alice@test.com", "editor", 0, "staging", "dev")
	require.NoError(t, err)
	assert.Equal(t, float64(3), gotBody["project_id"])
	assert.Equal(t, float64(2), gotBody["environment_id"])
}

// TestRunRemoveRoleRemote_WithProject verifies that project_id is included in the
// DELETE body when --project is supplied in remote mode.
func TestRunRemoveRoleRemote_WithProject(t *testing.T) {
	var gotBody map[string]interface{}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/users", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"users":[{"id":5,"email":"alice@test.com"}]}}`))
	})
	mux.HandleFunc("/api/v1/roles", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"roles":[{"id":1,"name":"editor","description":""}]}}`))
	})
	mux.HandleFunc("/api/v1/projects", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"projects":[{"id":3,"name":"staging"}]}}`))
	})
	mux.HandleFunc("/api/v1/user-roles", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusNoContent)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	rc := remoteClientFor(t, srv)

	err := runRemoveRoleRemote(context.Background(), rc, "alice@test.com", "editor", "staging", "")
	require.NoError(t, err)
	assert.Equal(t, float64(3), gotBody["project_id"])
	assert.Nil(t, gotBody["environment_id"])
}

// TestScopeSuffix verifies scopeSuffix helper produces expected strings.
func TestScopeSuffix(t *testing.T) {
	assert.Equal(t, "", scopeSuffix("", ""))
	assert.Equal(t, " in project 'myproj'", scopeSuffix("myproj", ""))
	assert.Equal(t, " in project 'myproj' / environment 'prod'", scopeSuffix("myproj", "prod"))
}
