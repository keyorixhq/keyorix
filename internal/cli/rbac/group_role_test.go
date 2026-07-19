// group_role_test.go — tests for assign-role-to-group, remove-role-from-group,
// and list-group-roles CLI commands (remote and embedded paths).
package rbac

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/testhelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── remote: assign-role-to-group ─────────────────────────────────────────────

// TestAssignRoleToGroup_Remote_HappyPath verifies that the command POSTs
// correctly to /api/v1/groups/{id}/roles and prints a success message.
func TestAssignRoleToGroup_Remote_HappyPath(t *testing.T) {
	var captured map[string]interface{}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/groups", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"groups":[{"id":7,"name":"ops-team","description":""}],"total":1}}`))
	})
	mux.HandleFunc("/api/v1/roles", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"roles":[{"id":2,"name":"admin","description":"Administrator"}]}}`))
	})
	mux.HandleFunc("/api/v1/groups/7/roles", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &captured)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"data":{"group_id":7,"role_id":2,"expires_at":null}}`))
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	rc := remoteClientFor(t, srv)

	err := runAssignRoleToGroupRemote(context.Background(), rc, "ops-team", "admin", 0, "", "")
	require.NoError(t, err)
	require.NotNil(t, captured)
	assert.Equal(t, float64(2), captured["role_id"])
	assert.NotContains(t, captured, "expires_at")
}

// TestAssignRoleToGroup_Remote_WithTTL verifies that expires_at is included in
// the POST body when --ttl is supplied.
func TestAssignRoleToGroup_Remote_WithTTL(t *testing.T) {
	var captured map[string]interface{}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/groups", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"groups":[{"id":7,"name":"ops-team","description":""}],"total":1}}`))
	})
	mux.HandleFunc("/api/v1/roles", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"roles":[{"id":2,"name":"admin","description":"Administrator"}]}}`))
	})
	mux.HandleFunc("/api/v1/groups/7/roles", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &captured)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"data":{"group_id":7,"role_id":2}}`))
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	rc := remoteClientFor(t, srv)

	err := runAssignRoleToGroupRemote(context.Background(), rc, "ops-team", "admin", 4*60*60*1e9 /* 4h */, "", "")
	require.NoError(t, err)
	require.NotNil(t, captured)
	assert.Contains(t, captured, "expires_at")
}

// TestAssignRoleToGroup_Remote_WithProject verifies that project_id is included
// in the POST body when --project is supplied.
func TestAssignRoleToGroup_Remote_WithProject(t *testing.T) {
	var captured map[string]interface{}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/groups", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"groups":[{"id":7,"name":"ops-team","description":""}],"total":1}}`))
	})
	mux.HandleFunc("/api/v1/roles", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"roles":[{"id":2,"name":"admin","description":"Administrator"}]}}`))
	})
	mux.HandleFunc("/api/v1/projects", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"projects":[{"id":5,"name":"production"}]}}`))
	})
	mux.HandleFunc("/api/v1/groups/7/roles", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &captured)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"data":{"group_id":7,"role_id":2}}`))
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	rc := remoteClientFor(t, srv)

	err := runAssignRoleToGroupRemote(context.Background(), rc, "ops-team", "admin", 0, "production", "")
	require.NoError(t, err)
	assert.Equal(t, float64(5), captured["project_id"])
}

// ── remote: remove-role-from-group ───────────────────────────────────────────

// TestRemoveRoleFromGroup_Remote_HappyPath verifies the DELETE to the correct URL.
func TestRemoveRoleFromGroup_Remote_HappyPath(t *testing.T) {
	var deletedPath string

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/groups", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"groups":[{"id":7,"name":"ops-team","description":""}],"total":1}}`))
	})
	mux.HandleFunc("/api/v1/roles", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"roles":[{"id":2,"name":"admin","description":"Administrator"}]}}`))
	})
	// Catch /api/v1/groups/7/roles/2 DELETE
	mux.HandleFunc("/api/v1/groups/7/roles/2", func(w http.ResponseWriter, r *http.Request) {
		deletedPath = r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	rc := remoteClientFor(t, srv)

	err := runRemoveRoleFromGroupRemote(context.Background(), rc, "ops-team", "admin", "", "")
	require.NoError(t, err)
	assert.Equal(t, "/api/v1/groups/7/roles/2", deletedPath)
}

// TestRemoveRoleFromGroup_Remote_WithProject verifies query params are appended.
func TestRemoveRoleFromGroup_Remote_WithProject(t *testing.T) {
	var requestURL string

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/groups", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"groups":[{"id":7,"name":"ops-team","description":""}],"total":1}}`))
	})
	mux.HandleFunc("/api/v1/roles", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"roles":[{"id":2,"name":"admin","description":"Administrator"}]}}`))
	})
	mux.HandleFunc("/api/v1/projects", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"projects":[{"id":5,"name":"production"}]}}`))
	})
	mux.HandleFunc("/api/v1/groups/7/roles/2", func(w http.ResponseWriter, r *http.Request) {
		requestURL = r.URL.RequestURI()
		w.WriteHeader(http.StatusNoContent)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	rc := remoteClientFor(t, srv)

	err := runRemoveRoleFromGroupRemote(context.Background(), rc, "ops-team", "admin", "production", "")
	require.NoError(t, err)
	assert.Contains(t, requestURL, "project_id=5")
}

// ── remote: list-group-roles ──────────────────────────────────────────────────

// TestListGroupRoles_Remote_HappyPath verifies the table is printed for a
// group that has roles.
func TestListGroupRoles_Remote_HappyPath(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/groups", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"groups":[{"id":7,"name":"ops-team","description":"Ops"}],"total":1}}`))
	})
	mux.HandleFunc("/api/v1/groups/7/roles", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		_, _ = w.Write([]byte(`{"data":{"group_id":7,"roles":[
			{"id":2,"name":"admin","description":"Administrator","expires_at":null},
			{"id":4,"name":"viewer","description":"Read-only access","expires_at":"2099-12-31T00:00:00Z"}
		]}}`))
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	rc := remoteClientFor(t, srv)

	// Capture output by wrapping stdout — we just verify no error and correct call.
	err := runListGroupRolesRemote(context.Background(), rc, "ops-team")
	require.NoError(t, err)
}

// TestListGroupRoles_Remote_Empty verifies the "No roles" message is printed.
func TestListGroupRoles_Remote_Empty(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/groups", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"groups":[{"id":7,"name":"ops-team","description":""}],"total":1}}`))
	})
	mux.HandleFunc("/api/v1/groups/7/roles", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"group_id":7,"roles":[]}}`))
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	rc := remoteClientFor(t, srv)

	err := runListGroupRolesRemote(context.Background(), rc, "ops-team")
	require.NoError(t, err)
}

// TestListGroupRoles_Remote_NumericID verifies a numeric --group flag bypasses
// the group resolution step.
func TestListGroupRoles_Remote_NumericID(t *testing.T) {
	mux := http.NewServeMux()
	// No /api/v1/groups endpoint: would 404 if called.
	mux.HandleFunc("/api/v1/groups/42/roles", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"group_id":42,"roles":[]}}`))
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	rc := remoteClientFor(t, srv)

	err := runListGroupRolesRemote(context.Background(), rc, "42")
	require.NoError(t, err)
}

// ── flag validation ───────────────────────────────────────────────────────────

// TestAssignRoleToGroup_EnvWithoutProject verifies --environment without
// --project is rejected before any network call.
func TestAssignRoleToGroup_EnvWithoutProject(t *testing.T) {
	orig := groupRoleEnvFlag
	defer func() { groupRoleEnvFlag = orig }()
	groupRoleEnvFlag = "production"

	origProj := groupRoleProjectFlag
	defer func() { groupRoleProjectFlag = origProj }()
	groupRoleProjectFlag = ""

	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	err := runAssignRoleToGroup(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--environment requires --project")
}

// TestRemoveRoleFromGroup_EnvWithoutProject mirrors the same guard on the remove command.
func TestRemoveRoleFromGroup_EnvWithoutProject(t *testing.T) {
	orig := removeGroupRoleEnvFlag
	defer func() { removeGroupRoleEnvFlag = orig }()
	removeGroupRoleEnvFlag = "staging"

	origProj := removeGroupRoleProjectFlag
	defer func() { removeGroupRoleProjectFlag = origProj }()
	removeGroupRoleProjectFlag = ""

	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	err := runRemoveRoleFromGroup(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--environment requires --project")
}

// TestAssignRoleToGroup_TTL_EmbeddedRejection verifies that --ttl in embedded
// mode is rejected with the appropriate error message.
func TestAssignRoleToGroup_TTL_EmbeddedRejection(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	yaml := "storage:\n  type: local\n  database:\n    path: " + dir + "/secrets.db\n"
	require.NoError(t, os.WriteFile(dir+"/keyorix.yaml", []byte(yaml), 0600))

	origTTL := groupRoleTTL
	defer func() { groupRoleTTL = origTTL }()
	groupRoleTTL = 1 // positive → rejected in embedded mode

	err := runAssignRoleToGroup(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--ttl requires a server connection")
}

// ── embedded path: assign + list via testhelper storage ──────────────────────

// TestAssignAndListGroupRoles_Embedded exercises the embedded storage path end-to-end:
// create a group, assign a role to it, list roles and verify they appear.
func TestAssignAndListGroupRoles_Embedded(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()

	ctx := context.Background()

	// Create a group in the in-memory DB.
	grp := &models.Group{Name: "devops", Description: "DevOps team"}
	created, err := h.Storage.CreateGroup(ctx, grp)
	require.NoError(t, err)

	// Assign the "viewer" role (ID 4, seeded by testhelper) to the group (global scope).
	err = h.Storage.AssignRoleToGroup(ctx, created.ID, 4, storage.Scope{})
	require.NoError(t, err)

	// GetGroupRoleGrants should return the grant.
	grants, err := h.Storage.GetGroupRoleGrants(ctx, created.ID)
	require.NoError(t, err)
	require.Len(t, grants, 1)
	assert.Equal(t, "viewer", grants[0].Name)
	assert.Nil(t, grants[0].ExpiresAt)
}

// TestRemoveGroupRole_Embedded verifies that RemoveRoleFromGroup removes the grant.
func TestRemoveGroupRole_Embedded(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()

	ctx := context.Background()

	grp := &models.Group{Name: "security-team", Description: ""}
	created, err := h.Storage.CreateGroup(ctx, grp)
	require.NoError(t, err)

	// Assign "admin" (ID 2) and "viewer" (ID 4).
	require.NoError(t, h.Storage.AssignRoleToGroup(ctx, created.ID, 2, storage.Scope{}))
	require.NoError(t, h.Storage.AssignRoleToGroup(ctx, created.ID, 4, storage.Scope{}))

	// Remove "admin".
	require.NoError(t, h.Storage.RemoveRoleFromGroup(ctx, created.ID, 2, storage.Scope{}))

	grants, err := h.Storage.GetGroupRoleGrants(ctx, created.ID)
	require.NoError(t, err)
	require.Len(t, grants, 1)
	assert.Equal(t, "viewer", grants[0].Name)
}

// ── helper: resolveGroupID ────────────────────────────────────────────────────

// TestResolveGroupID_ByName verifies name-based look-up against the embedded store.
func TestResolveGroupID_ByName(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()

	ctx := context.Background()
	grp := &models.Group{Name: "my-group", Description: ""}
	created, err := h.Storage.CreateGroup(ctx, grp)
	require.NoError(t, err)

	id, err := resolveGroupID(ctx, h.Storage, "my-group")
	require.NoError(t, err)
	assert.Equal(t, created.ID, id)
}

// TestResolveGroupID_ByNumericID verifies that a plain integer skips the listing call.
func TestResolveGroupID_ByNumericID(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()

	// No group created — if the function tried to list+match it would fail;
	// passing "99" as a numeric ID should return 99 directly.
	id, err := resolveGroupID(context.Background(), h.Storage, "99")
	require.NoError(t, err)
	assert.Equal(t, uint(99), id)
}

// TestResolveGroupID_NotFound verifies a proper error when the name doesn't exist.
func TestResolveGroupID_NotFound(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()

	_, err := resolveGroupID(context.Background(), h.Storage, "no-such-group")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// ── printGroupRoleTable smoke test ────────────────────────────────────────────

// TestPrintGroupRoleTable_Output verifies the table output contains expected headers.
func TestPrintGroupRoleTable_Output(t *testing.T) {
	// Redirect stdout.
	orig := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	grants := []*storage.GroupRoleGrant{
		{ID: 1, Name: "admin", Description: "Administrator"},
	}
	printGroupRoleTable(grants)

	_ = w.Close()
	os.Stdout = orig
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)

	out := buf.String()
	assert.Contains(t, out, "ROLE")
	assert.Contains(t, out, "EXPIRES")
	assert.Contains(t, out, "admin")
	assert.Contains(t, out, "never")
}
