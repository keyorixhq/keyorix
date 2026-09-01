// rbac_scope_cov_test.go — coverage tests for RBAC CLI scope flags and
// embedded-mode code paths that were not exercised by the existing test suite.
//
// Targets:
//   - resolveScope: all branches (project only, project+env, errors)
//   - runAssignRole embedded: success with and without scope
//   - runRemoveRole embedded: success with and without scope
//   - runAssignRoleToGroup embedded: success path
//   - runRemoveRoleFromGroup embedded: success path
//   - runListGroupRoles embedded: with-roles and empty branches
//   - resolveRoleIDEmbedded: success and error
//   - printGroupRoleTable: ExpiresAt branch
//   - printRemoteGroupRoleTable: ExpiresAt branch
//   - resolveProjectIDByName remote: GET error and not-found
//   - resolveEnvironmentIDByName remote: GET error and not-found
//   - runRemoveRoleRemote: project + env paths
//   - runAssignRoleRemote: project + env paths

package rbac

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/identity"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── resolveScope ──────────────────────────────────────────────────────────────

// TestResolveScope_ProjectOnly verifies project-only scope resolution.
func TestResolveScope_ProjectOnly(t *testing.T) {
	_, st := initEmbeddedDB(t)
	ctx := context.Background()

	proj, err := st.CreateProject(ctx, &models.Project{Name: "scope-proj-only"})
	require.NoError(t, err)

	scope, err := resolveScope(ctx, st, "scope-proj-only", "")
	require.NoError(t, err)
	assert.Equal(t, proj.ID, scope.ProjectID)
	assert.Equal(t, uint(0), scope.EnvironmentID)
}

// TestResolveScope_ProjectNotFound ensures LookupProjectIDByName failure is surfaced.
func TestResolveScope_ProjectNotFound(t *testing.T) {
	_, st := initEmbeddedDB(t)
	ctx := context.Background()

	_, err := resolveScope(ctx, st, "no-such-project", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to resolve project")
}

// TestResolveScope_ProjectAndEnv verifies project+environment scope resolution.
func TestResolveScope_ProjectAndEnv(t *testing.T) {
	_, st := initEmbeddedDB(t)
	ctx := context.Background()

	proj, err := st.CreateProject(ctx, &models.Project{Name: "scope-proj-env"})
	require.NoError(t, err)
	env, err := st.CreateEnvironment(ctx, &models.Environment{Name: "staging", ProjectID: proj.ID})
	require.NoError(t, err)

	scope, err := resolveScope(ctx, st, "scope-proj-env", "STAGING") // case-insensitive
	require.NoError(t, err)
	assert.Equal(t, proj.ID, scope.ProjectID)
	assert.Equal(t, env.ID, scope.EnvironmentID)
}

// TestResolveScope_EnvNotFound verifies not-found error for missing environment.
func TestResolveScope_EnvNotFound(t *testing.T) {
	_, st := initEmbeddedDB(t)
	ctx := context.Background()

	proj, err := st.CreateProject(ctx, &models.Project{Name: "scope-proj-noenv"})
	require.NoError(t, err)
	// Create a different env so the list is non-empty.
	_, err = st.CreateEnvironment(ctx, &models.Environment{Name: "other-env", ProjectID: proj.ID})
	require.NoError(t, err)

	_, err = resolveScope(ctx, st, "scope-proj-noenv", "missing-env")
	require.Error(t, err)
	assert.Contains(t, err.Error(), `environment "missing-env" not found`)
}

// TestResolveScope_Empty verifies the fast-return for an empty project flag.
func TestResolveScope_Empty(t *testing.T) {
	_, st := initEmbeddedDB(t)
	scope, err := resolveScope(context.Background(), st, "", "")
	require.NoError(t, err)
	assert.Equal(t, corestorage.Scope{}, scope)
}

// ── runAssignRole embedded ────────────────────────────────────────────────────

// TestRunAssignRole_Embedded_GlobalScope verifies the embedded happy path for a
// global (no project) role assignment.
func TestRunAssignRole_Embedded_GlobalScope(t *testing.T) {
	_, st := initEmbeddedDB(t)
	ctx := context.Background()

	_, err := st.CreateUser(ctx, &models.User{Username: "assign-global", Email: "assign-global@example.com"})
	require.NoError(t, err)
	assignGlobalRoleName, err := identity.NewFoldedName("assign-global-role")
	require.NoError(t, err)
	_, err = st.CreateRole(ctx, assignGlobalRoleName, "test")
	require.NoError(t, err)

	orig, origR, origP, origE := userEmail, roleName, assignProjectFlag, assignEnvFlag
	defer func() { userEmail = orig; roleName = origR; assignProjectFlag = origP; assignEnvFlag = origE }()
	userEmail = "assign-global@example.com"
	roleName = "assign-global-role"
	assignProjectFlag = ""
	assignEnvFlag = ""

	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	require.NoError(t, runAssignRole(nil, nil))
}

// TestRunAssignRole_Embedded_WithProject verifies scope propagation when --project
// is set in embedded mode.
func TestRunAssignRole_Embedded_WithProject(t *testing.T) {
	_, st := initEmbeddedDB(t)
	ctx := context.Background()

	_, err := st.CreateUser(ctx, &models.User{Username: "assign-proj", Email: "assign-proj@example.com"})
	require.NoError(t, err)
	assignProjRoleName, err := identity.NewFoldedName("assign-proj-role")
	require.NoError(t, err)
	_, err = st.CreateRole(ctx, assignProjRoleName, "test")
	require.NoError(t, err)
	_, err = st.CreateProject(ctx, &models.Project{Name: "assign-proj-project"})
	require.NoError(t, err)

	orig, origR, origP, origE := userEmail, roleName, assignProjectFlag, assignEnvFlag
	defer func() { userEmail = orig; roleName = origR; assignProjectFlag = origP; assignEnvFlag = origE }()
	userEmail = "assign-proj@example.com"
	roleName = "assign-proj-role"
	assignProjectFlag = "assign-proj-project"
	assignEnvFlag = ""

	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	require.NoError(t, runAssignRole(nil, nil))
}

// TestRunAssignRole_Embedded_ScopeError verifies resolveScope error propagation.
func TestRunAssignRole_Embedded_ScopeError(t *testing.T) {
	initEmbeddedDB(t)

	orig, origR, origP, origE := userEmail, roleName, assignProjectFlag, assignEnvFlag
	defer func() { userEmail = orig; roleName = origR; assignProjectFlag = origP; assignEnvFlag = origE }()
	userEmail = "nobody@example.com"
	roleName = "anyrole"
	assignProjectFlag = "no-such-project"
	assignEnvFlag = ""

	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	err := runAssignRole(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to resolve project")
}

// ── runRemoveRole embedded ────────────────────────────────────────────────────

// TestRunRemoveRole_Embedded_GlobalScope verifies the embedded happy path for
// removing a global role assignment.
func TestRunRemoveRole_Embedded_GlobalScope(t *testing.T) {
	_, st := initEmbeddedDB(t)
	ctx := context.Background()

	user, err := st.CreateUser(ctx, &models.User{Username: "remove-global", Email: "remove-global@example.com"})
	require.NoError(t, err)
	removeGlobalRoleName, err := identity.NewFoldedName("remove-global-role")
	require.NoError(t, err)
	role, err := st.CreateRole(ctx, removeGlobalRoleName, "test")
	require.NoError(t, err)
	require.NoError(t, st.AssignRole(ctx, user.ID, role.ID, corestorage.Scope{}))

	origU, origR, origP, origE := removeUserEmail, removeRoleName, removeProjectFlag, removeEnvFlag
	defer func() {
		removeUserEmail = origU
		removeRoleName = origR
		removeProjectFlag = origP
		removeEnvFlag = origE
	}()
	removeUserEmail = "remove-global@example.com"
	removeRoleName = "remove-global-role"
	removeProjectFlag = ""
	removeEnvFlag = ""

	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	require.NoError(t, runRemoveRole(nil, nil))
}

// TestRunRemoveRole_Embedded_WithProjectAndEnv verifies project+env scope for
// the remove command.
func TestRunRemoveRole_Embedded_WithProjectAndEnv(t *testing.T) {
	_, st := initEmbeddedDB(t)
	ctx := context.Background()

	user, err := st.CreateUser(ctx, &models.User{Username: "remove-scoped", Email: "remove-scoped@example.com"})
	require.NoError(t, err)
	removeScopedRoleName, err := identity.NewFoldedName("remove-scoped-role")
	require.NoError(t, err)
	role, err := st.CreateRole(ctx, removeScopedRoleName, "test")
	require.NoError(t, err)
	proj, err := st.CreateProject(ctx, &models.Project{Name: "remove-scoped-proj"})
	require.NoError(t, err)
	env, err := st.CreateEnvironment(ctx, &models.Environment{Name: "prod", ProjectID: proj.ID})
	require.NoError(t, err)
	require.NoError(t, st.AssignRole(ctx, user.ID, role.ID, corestorage.Scope{ProjectID: proj.ID, EnvironmentID: env.ID}))

	origU, origR, origP, origE := removeUserEmail, removeRoleName, removeProjectFlag, removeEnvFlag
	defer func() {
		removeUserEmail = origU
		removeRoleName = origR
		removeProjectFlag = origP
		removeEnvFlag = origE
	}()
	removeUserEmail = "remove-scoped@example.com"
	removeRoleName = "remove-scoped-role"
	removeProjectFlag = "remove-scoped-proj"
	removeEnvFlag = "prod"

	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	require.NoError(t, runRemoveRole(nil, nil))
}

// TestRunRemoveRole_Embedded_ScopeError verifies resolveScope error propagation.
func TestRunRemoveRole_Embedded_ScopeError(t *testing.T) {
	initEmbeddedDB(t)

	origU, origR, origP, origE := removeUserEmail, removeRoleName, removeProjectFlag, removeEnvFlag
	defer func() {
		removeUserEmail = origU
		removeRoleName = origR
		removeProjectFlag = origP
		removeEnvFlag = origE
	}()
	removeUserEmail = "nobody@example.com"
	removeRoleName = "anyrole"
	removeProjectFlag = "nonexistent-project"
	removeEnvFlag = ""

	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	err := runRemoveRole(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to resolve project")
}

// ── runAssignRoleToGroup embedded ─────────────────────────────────────────────

// TestRunAssignRoleToGroup_Embedded_GlobalScope exercises the embedded happy path.
func TestRunAssignRoleToGroup_Embedded_GlobalScope(t *testing.T) {
	_, st := initEmbeddedDB(t)
	ctx := context.Background()

	_, err := st.CreateGroup(ctx, &models.Group{Name: "embed-group-assign", Description: ""})
	require.NoError(t, err)
	embedGroupRoleAssignName, err := identity.NewFoldedName("embed-group-role-assign")
	require.NoError(t, err)
	_, err = st.CreateRole(ctx, embedGroupRoleAssignName, "test")
	require.NoError(t, err)

	origG, origR, origP, origE, origT := groupRoleGroupFlag, groupRoleName, groupRoleProjectFlag, groupRoleEnvFlag, groupRoleTTL
	defer func() {
		groupRoleGroupFlag = origG
		groupRoleName = origR
		groupRoleProjectFlag = origP
		groupRoleEnvFlag = origE
		groupRoleTTL = origT
	}()
	groupRoleGroupFlag = "embed-group-assign"
	groupRoleName = "embed-group-role-assign"
	groupRoleProjectFlag = ""
	groupRoleEnvFlag = ""
	groupRoleTTL = 0

	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	require.NoError(t, runAssignRoleToGroup(nil, nil))
}

// TestRunAssignRoleToGroup_Embedded_WithProject exercises project-scoped assign.
func TestRunAssignRoleToGroup_Embedded_WithProject(t *testing.T) {
	_, st := initEmbeddedDB(t)
	ctx := context.Background()

	_, err := st.CreateGroup(ctx, &models.Group{Name: "embed-group-proj", Description: ""})
	require.NoError(t, err)
	embedGroupRoleProjName, err := identity.NewFoldedName("embed-group-role-proj")
	require.NoError(t, err)
	_, err = st.CreateRole(ctx, embedGroupRoleProjName, "test")
	require.NoError(t, err)
	_, err = st.CreateProject(ctx, &models.Project{Name: "embed-group-project"})
	require.NoError(t, err)

	origG, origR, origP, origE, origT := groupRoleGroupFlag, groupRoleName, groupRoleProjectFlag, groupRoleEnvFlag, groupRoleTTL
	defer func() {
		groupRoleGroupFlag = origG
		groupRoleName = origR
		groupRoleProjectFlag = origP
		groupRoleEnvFlag = origE
		groupRoleTTL = origT
	}()
	groupRoleGroupFlag = "embed-group-proj"
	groupRoleName = "embed-group-role-proj"
	groupRoleProjectFlag = "embed-group-project"
	groupRoleEnvFlag = ""
	groupRoleTTL = 0

	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	require.NoError(t, runAssignRoleToGroup(nil, nil))
}

// TestRunAssignRoleToGroup_Embedded_RoleNotFound verifies error when role name is invalid.
func TestRunAssignRoleToGroup_Embedded_RoleNotFound(t *testing.T) {
	_, st := initEmbeddedDB(t)
	ctx := context.Background()

	_, err := st.CreateGroup(ctx, &models.Group{Name: "embed-group-noRole", Description: ""})
	require.NoError(t, err)

	origG, origR, origP, origE, origT := groupRoleGroupFlag, groupRoleName, groupRoleProjectFlag, groupRoleEnvFlag, groupRoleTTL
	defer func() {
		groupRoleGroupFlag = origG
		groupRoleName = origR
		groupRoleProjectFlag = origP
		groupRoleEnvFlag = origE
		groupRoleTTL = origT
	}()
	groupRoleGroupFlag = "embed-group-noRole"
	groupRoleName = "nonexistent-role"
	groupRoleProjectFlag = ""
	groupRoleEnvFlag = ""
	groupRoleTTL = 0

	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	err = runAssignRoleToGroup(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to resolve role")
}

// ── runRemoveRoleFromGroup embedded ──────────────────────────────────────────

// TestRunRemoveRoleFromGroup_Embedded_Success exercises the embedded happy path.
func TestRunRemoveRoleFromGroup_Embedded_Success(t *testing.T) {
	_, st := initEmbeddedDB(t)
	ctx := context.Background()

	grp, err := st.CreateGroup(ctx, &models.Group{Name: "embed-grp-remove", Description: ""})
	require.NoError(t, err)
	embedGrpRoleRemoveName, err := identity.NewFoldedName("embed-grp-role-remove")
	require.NoError(t, err)
	role, err := st.CreateRole(ctx, embedGrpRoleRemoveName, "test")
	require.NoError(t, err)
	require.NoError(t, st.AssignRoleToGroup(ctx, grp.ID, role.ID, corestorage.Scope{}))

	origG, origR, origP, origE := removeGroupRoleGroupFlag, removeGroupRoleName, removeGroupRoleProjectFlag, removeGroupRoleEnvFlag
	defer func() {
		removeGroupRoleGroupFlag = origG
		removeGroupRoleName = origR
		removeGroupRoleProjectFlag = origP
		removeGroupRoleEnvFlag = origE
	}()
	removeGroupRoleGroupFlag = "embed-grp-remove"
	removeGroupRoleName = "embed-grp-role-remove"
	removeGroupRoleProjectFlag = ""
	removeGroupRoleEnvFlag = ""

	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	require.NoError(t, runRemoveRoleFromGroup(nil, nil))
}

// ── runListGroupRoles embedded ────────────────────────────────────────────────

// TestRunListGroupRoles_Embedded_WithRoles exercises the table-print branch.
func TestRunListGroupRoles_Embedded_WithRoles(t *testing.T) {
	_, st := initEmbeddedDB(t)
	ctx := context.Background()

	grp, err := st.CreateGroup(ctx, &models.Group{Name: "embed-grp-list", Description: ""})
	require.NoError(t, err)
	embedGrpListRoleName, err := identity.NewFoldedName("embed-grp-list-role")
	require.NoError(t, err)
	role, err := st.CreateRole(ctx, embedGrpListRoleName, "test")
	require.NoError(t, err)
	require.NoError(t, st.AssignRoleToGroup(ctx, grp.ID, role.ID, corestorage.Scope{}))

	origG := listGroupRoleGroupFlag
	defer func() { listGroupRoleGroupFlag = origG }()
	listGroupRoleGroupFlag = "embed-grp-list"

	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	require.NoError(t, runListGroupRoles(nil, nil))
}

// TestRunListGroupRoles_Embedded_Empty exercises the "No roles assigned" branch.
func TestRunListGroupRoles_Embedded_Empty(t *testing.T) {
	_, st := initEmbeddedDB(t)
	ctx := context.Background()

	_, err := st.CreateGroup(ctx, &models.Group{Name: "embed-grp-empty", Description: ""})
	require.NoError(t, err)

	origG := listGroupRoleGroupFlag
	defer func() { listGroupRoleGroupFlag = origG }()
	listGroupRoleGroupFlag = "embed-grp-empty"

	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	require.NoError(t, runListGroupRoles(nil, nil))
}

// ── resolveRoleIDEmbedded ─────────────────────────────────────────────────────

// TestResolveRoleIDEmbedded_Success verifies a known role is resolved.
func TestResolveRoleIDEmbedded_Success(t *testing.T) {
	_, st := initEmbeddedDB(t)
	ctx := context.Background()

	embedResolveRoleName, err := identity.NewFoldedName("embed-resolve-role")
	require.NoError(t, err)
	role, err := st.CreateRole(ctx, embedResolveRoleName, "test")
	require.NoError(t, err)

	id, err := resolveRoleIDEmbedded(ctx, st, "embed-resolve-role")
	require.NoError(t, err)
	assert.Equal(t, role.ID, id)
}

// TestResolveRoleIDEmbedded_Error verifies error when the role doesn't exist.
func TestResolveRoleIDEmbedded_Error(t *testing.T) {
	_, st := initEmbeddedDB(t)

	_, err := resolveRoleIDEmbedded(context.Background(), st, "no-such-role")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to resolve role")
}

// ── printGroupRoleTable ExpiresAt branch ──────────────────────────────────────

// TestPrintGroupRoleTable_WithExpiry ensures the non-"never" branch of ExpiresAt
// prints a formatted timestamp.
func TestPrintGroupRoleTable_WithExpiry(t *testing.T) {
	orig := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	exp := time.Date(2030, 1, 15, 12, 0, 0, 0, time.UTC)
	grants := []*corestorage.GroupRoleGrant{
		{ID: 1, Name: "editor", Description: "Edit access", ExpiresAt: &exp},
	}
	printGroupRoleTable(grants)

	_ = w.Close()
	os.Stdout = orig
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)

	out := buf.String()
	assert.Contains(t, out, "editor")
	assert.Contains(t, out, "2030-01-15")
}

// TestPrintRemoteGroupRoleTable_WithExpiry ensures the non-"never" branch for
// the remote variant also prints a formatted timestamp.
func TestPrintRemoteGroupRoleTable_WithExpiry(t *testing.T) {
	orig := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	exp := time.Date(2030, 6, 1, 9, 30, 0, 0, time.UTC)
	roles := []remoteGroupRole{
		{ID: 1, Name: "reader", Description: "Read-only", ExpiresAt: &exp},
	}
	printRemoteGroupRoleTable(roles)

	_ = w.Close()
	os.Stdout = orig
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)

	out := buf.String()
	assert.Contains(t, out, "reader")
	assert.Contains(t, out, "2030-06-01")
}

// ── resolveProjectIDByName remote error paths ─────────────────────────────────

// TestResolveProjectIDByName_GETError verifies rc.Get error propagation.
func TestResolveProjectIDByName_GETError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/projects", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"boom"}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	rc := remoteClientFor(t, srv)

	_, err := resolveProjectIDByName(context.Background(), rc, "any")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list projects")
}

// TestResolveProjectIDByName_NotFound verifies not-found error when project is absent.
func TestResolveProjectIDByName_NotFound(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/projects", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"projects":[{"id":1,"name":"other-proj"}]}}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	rc := remoteClientFor(t, srv)

	_, err := resolveProjectIDByName(context.Background(), rc, "missing-project")
	require.Error(t, err)
	assert.Contains(t, err.Error(), `"missing-project" not found`)
}

// ── resolveEnvironmentIDByName remote error paths ─────────────────────────────

// TestResolveEnvironmentIDByName_GETError verifies rc.Get error propagation.
func TestResolveEnvironmentIDByName_GETError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/projects/1/environments", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"down"}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	rc := remoteClientFor(t, srv)

	_, err := resolveEnvironmentIDByName(context.Background(), rc, 1, "any")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list environments")
}

// TestResolveEnvironmentIDByName_NotFound verifies not-found error.
func TestResolveEnvironmentIDByName_NotFound(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/projects/1/environments", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"environments":[{"id":1,"name":"staging"}]}}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	rc := remoteClientFor(t, srv)

	_, err := resolveEnvironmentIDByName(context.Background(), rc, 1, "production")
	require.Error(t, err)
	assert.Contains(t, err.Error(), `"production" not found`)
}

// TestResolveEnvironmentIDByName_ScopedToProject verifies the resolver only
// matches environments within the requested project's scope, never falling
// back to a deployment-wide match — regression test for G78 (cross-project
// scope confusion via resolveEnvironmentIDByName's former unscoped
// GET /api/v1/environments listing).
func TestResolveEnvironmentIDByName_ScopedToProject(t *testing.T) {
	mux := http.NewServeMux()
	// Two projects, each with an environment literally named "prod" but a
	// different environment ID — the classic decoy-name-collision setup.
	mux.HandleFunc("/api/v1/projects/1/environments", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"environments":[{"id":101,"name":"prod"}]}}`))
	})
	mux.HandleFunc("/api/v1/projects/2/environments", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"environments":[{"id":202,"name":"prod"}]}}`))
	})
	// The deployment-wide listing must never be consulted by the fixed
	// resolver; if it is, resolving project A's "prod" here would wrongly
	// pick up project B's environment ID.
	mux.HandleFunc("/api/v1/environments", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"environments":[{"id":202,"name":"prod"},{"id":101,"name":"prod"}]}}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	rc := remoteClientFor(t, srv)

	envID, err := resolveEnvironmentIDByName(context.Background(), rc, 1, "prod")
	require.NoError(t, err)
	assert.Equal(t, uint(101), envID, "must resolve project A's own \"prod\" environment, never project B's")

	envID, err = resolveEnvironmentIDByName(context.Background(), rc, 2, "prod")
	require.NoError(t, err)
	assert.Equal(t, uint(202), envID, "must resolve project B's own \"prod\" environment, never project A's")
}

// ── runRemoveRoleRemote project+env path ──────────────────────────────────────

// TestRunRemoveRoleRemote_WithProjectAndEnv verifies project+env query params.
func TestRunRemoveRoleRemote_WithProjectAndEnv(t *testing.T) {
	var requestURI string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/users", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"users":[{"id":5,"email":"alice@test.com"}]}}`))
	})
	mux.HandleFunc("/api/v1/roles", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"roles":[{"id":1,"name":"admin","description":""}]}}`))
	})
	mux.HandleFunc("/api/v1/projects", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"projects":[{"id":3,"name":"myproject"}]}}`))
	})
	mux.HandleFunc("/api/v1/projects/3/environments", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"environments":[{"id":7,"name":"production"}]}}`))
	})
	mux.HandleFunc("/api/v1/user-roles", func(w http.ResponseWriter, r *http.Request) {
		requestURI = r.URL.RequestURI()
		w.WriteHeader(http.StatusNoContent)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	rc := remoteClientFor(t, srv)

	err := runRemoveRoleRemote(context.Background(), rc, "alice@test.com", "admin", "myproject", "production")
	require.NoError(t, err)
	_ = requestURI // just verify no error; URL encoding varies by DeleteWithBody
}

// TestRunRemoveRoleRemote_ProjectError verifies project-resolution error in remote remove.
func TestRunRemoveRoleRemote_ProjectError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/users", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"users":[{"id":5,"email":"alice@test.com"}]}}`))
	})
	mux.HandleFunc("/api/v1/roles", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"roles":[{"id":1,"name":"admin","description":""}]}}`))
	})
	mux.HandleFunc("/api/v1/projects", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	rc := remoteClientFor(t, srv)

	err := runRemoveRoleRemote(context.Background(), rc, "alice@test.com", "admin", "any-project", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list projects")
}

// ── runAssignRoleRemote project+env path ──────────────────────────────────────

// TestRunAssignRoleRemote_EnvError verifies error propagation when environment
// resolution fails during remote assign-role with --project + --environment.
func TestRunAssignRoleRemote_EnvError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/users", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"users":[{"id":5,"email":"alice@test.com"}]}}`))
	})
	mux.HandleFunc("/api/v1/roles", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"roles":[{"id":1,"name":"admin","description":""}]}}`))
	})
	mux.HandleFunc("/api/v1/projects", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"projects":[{"id":3,"name":"myproject"}]}}`))
	})
	mux.HandleFunc("/api/v1/projects/3/environments", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	rc := remoteClientFor(t, srv)

	err := runAssignRoleRemote(context.Background(), rc, "alice@test.com", "admin", 0, "myproject", "production")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list environments")
}

// TestRunAssignRoleRemote_ProjectError verifies error from project resolution.
func TestRunAssignRoleRemote_ProjectError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/users", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"users":[{"id":5,"email":"alice@test.com"}]}}`))
	})
	mux.HandleFunc("/api/v1/roles", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"roles":[{"id":1,"name":"admin","description":""}]}}`))
	})
	mux.HandleFunc("/api/v1/projects", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	rc := remoteClientFor(t, srv)

	err := runAssignRoleRemote(context.Background(), rc, "alice@test.com", "admin", 0, "bad-project", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list projects")
}

// ── embedded InitializeStorage error path (no config file) ───────────────────

// noConfigDir creates a fresh temp dir with NO keyorix.yaml and changes into it.
// This causes InitializeStorage() → config.Load("") → SafeReadFile to fail.
func noConfigDir(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
}

// TestRunAssignRoleToGroup_InitStorageError verifies the InitializeStorage error
// return in runAssignRoleToGroup (TTL=0, no env without project, no remote).
func TestRunAssignRoleToGroup_InitStorageError(t *testing.T) {
	noConfigDir(t)
	origG, origR, origT := groupRoleGroupFlag, groupRoleName, groupRoleTTL
	defer func() { groupRoleGroupFlag = origG; groupRoleName = origR; groupRoleTTL = origT }()
	groupRoleGroupFlag = "any-group"
	groupRoleName = "any-role"
	groupRoleTTL = 0

	err := runAssignRoleToGroup(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load config")
}

// TestRunAssignRoleToGroup_GroupNotFound verifies the resolveGroupID error return.
func TestRunAssignRoleToGroup_GroupNotFound(t *testing.T) {
	_, st := initEmbeddedDB(t)
	ctx := context.Background()

	// Seed a role so resolveRoleIDEmbedded would succeed if we got that far.
	gGrpNfRoleName, err := identity.NewFoldedName("g-grp-nf-role")
	require.NoError(t, err)
	_, err = st.CreateRole(ctx, gGrpNfRoleName, "test")
	require.NoError(t, err)

	origG, origR, origP, origE, origT := groupRoleGroupFlag, groupRoleName, groupRoleProjectFlag, groupRoleEnvFlag, groupRoleTTL
	defer func() {
		groupRoleGroupFlag = origG
		groupRoleName = origR
		groupRoleProjectFlag = origP
		groupRoleEnvFlag = origE
		groupRoleTTL = origT
	}()
	groupRoleGroupFlag = "no-such-group-xyz"
	groupRoleName = "g-grp-nf-role"
	groupRoleProjectFlag = ""
	groupRoleEnvFlag = ""
	groupRoleTTL = 0

	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	err = runAssignRoleToGroup(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// TestRunAssignRoleToGroup_ScopeError verifies the resolveScope error return when
// the --project flag resolves to a non-existent project.
func TestRunAssignRoleToGroup_ScopeError(t *testing.T) {
	_, st := initEmbeddedDB(t)
	ctx := context.Background()

	_, err := st.CreateGroup(ctx, &models.Group{Name: "grp-scope-err", Description: ""})
	require.NoError(t, err)
	grpScopeErrRoleName, err := identity.NewFoldedName("grp-scope-err-role")
	require.NoError(t, err)
	_, err = st.CreateRole(ctx, grpScopeErrRoleName, "test")
	require.NoError(t, err)

	origG, origR, origP, origE, origT := groupRoleGroupFlag, groupRoleName, groupRoleProjectFlag, groupRoleEnvFlag, groupRoleTTL
	defer func() {
		groupRoleGroupFlag = origG
		groupRoleName = origR
		groupRoleProjectFlag = origP
		groupRoleEnvFlag = origE
		groupRoleTTL = origT
	}()
	groupRoleGroupFlag = "grp-scope-err"
	groupRoleName = "grp-scope-err-role"
	groupRoleProjectFlag = "no-such-project-xyz"
	groupRoleEnvFlag = ""
	groupRoleTTL = 0

	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	err = runAssignRoleToGroup(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to resolve project")
}

// ── runRemoveRoleFromGroup embedded error paths ────────────────────────────────

// TestRunRemoveRoleFromGroup_InitStorageError verifies the InitializeStorage error.
func TestRunRemoveRoleFromGroup_InitStorageError(t *testing.T) {
	noConfigDir(t)
	origG, origR := removeGroupRoleGroupFlag, removeGroupRoleName
	defer func() { removeGroupRoleGroupFlag = origG; removeGroupRoleName = origR }()
	removeGroupRoleGroupFlag = "any-group"
	removeGroupRoleName = "any-role"

	err := runRemoveRoleFromGroup(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load config")
}

// TestRunRemoveRoleFromGroup_GroupNotFound verifies the resolveGroupID error return.
func TestRunRemoveRoleFromGroup_GroupNotFound(t *testing.T) {
	initEmbeddedDB(t)

	origG, origR, origP, origE := removeGroupRoleGroupFlag, removeGroupRoleName, removeGroupRoleProjectFlag, removeGroupRoleEnvFlag
	defer func() {
		removeGroupRoleGroupFlag = origG
		removeGroupRoleName = origR
		removeGroupRoleProjectFlag = origP
		removeGroupRoleEnvFlag = origE
	}()
	removeGroupRoleGroupFlag = "no-such-group-abc"
	removeGroupRoleName = "any-role"
	removeGroupRoleProjectFlag = ""
	removeGroupRoleEnvFlag = ""

	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	err := runRemoveRoleFromGroup(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// TestRunRemoveRoleFromGroup_RoleNotFound verifies the resolveRoleIDEmbedded error.
func TestRunRemoveRoleFromGroup_RoleNotFound(t *testing.T) {
	_, st := initEmbeddedDB(t)
	ctx := context.Background()

	_, err := st.CreateGroup(ctx, &models.Group{Name: "rrfg-role-nf", Description: ""})
	require.NoError(t, err)

	origG, origR, origP, origE := removeGroupRoleGroupFlag, removeGroupRoleName, removeGroupRoleProjectFlag, removeGroupRoleEnvFlag
	defer func() {
		removeGroupRoleGroupFlag = origG
		removeGroupRoleName = origR
		removeGroupRoleProjectFlag = origP
		removeGroupRoleEnvFlag = origE
	}()
	removeGroupRoleGroupFlag = "rrfg-role-nf"
	removeGroupRoleName = "nonexistent-role-xyz"
	removeGroupRoleProjectFlag = ""
	removeGroupRoleEnvFlag = ""

	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	err = runRemoveRoleFromGroup(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to resolve role")
}

// TestRunRemoveRoleFromGroup_ScopeError verifies the resolveScope error return.
func TestRunRemoveRoleFromGroup_ScopeError(t *testing.T) {
	_, st := initEmbeddedDB(t)
	ctx := context.Background()

	_, err := st.CreateGroup(ctx, &models.Group{Name: "rrfg-scope-err", Description: ""})
	require.NoError(t, err)
	rrfgScopeRoleName, err := identity.NewFoldedName("rrfg-scope-role")
	require.NoError(t, err)
	_, err = st.CreateRole(ctx, rrfgScopeRoleName, "test")
	require.NoError(t, err)

	origG, origR, origP, origE := removeGroupRoleGroupFlag, removeGroupRoleName, removeGroupRoleProjectFlag, removeGroupRoleEnvFlag
	defer func() {
		removeGroupRoleGroupFlag = origG
		removeGroupRoleName = origR
		removeGroupRoleProjectFlag = origP
		removeGroupRoleEnvFlag = origE
	}()
	removeGroupRoleGroupFlag = "rrfg-scope-err"
	removeGroupRoleName = "rrfg-scope-role"
	removeGroupRoleProjectFlag = "bad-project-xyz"
	removeGroupRoleEnvFlag = ""

	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	err = runRemoveRoleFromGroup(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to resolve project")
}

// ── runListGroupRoles embedded error paths ─────────────────────────────────────

// TestRunListGroupRoles_InitStorageError verifies the InitializeStorage error.
func TestRunListGroupRoles_InitStorageError(t *testing.T) {
	noConfigDir(t)
	origG := listGroupRoleGroupFlag
	defer func() { listGroupRoleGroupFlag = origG }()
	listGroupRoleGroupFlag = "any-group"

	err := runListGroupRoles(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load config")
}

// TestRunListGroupRoles_GroupNotFound verifies the resolveGroupID error.
func TestRunListGroupRoles_GroupNotFound(t *testing.T) {
	initEmbeddedDB(t)

	origG := listGroupRoleGroupFlag
	defer func() { listGroupRoleGroupFlag = origG }()
	listGroupRoleGroupFlag = "no-such-group-list"

	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	err := runListGroupRoles(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// ── runAssignRole / runRemoveRole embedded error paths ────────────────────────

// TestRunAssignRole_AssignError verifies the AssignUserRoleScoped error return.
func TestRunAssignRole_AssignError(t *testing.T) {
	initEmbeddedDB(t)
	// No user/role seeded — AssignUserRoleScoped will fail because the user doesn't exist.
	orig, origR, origP, origE := userEmail, roleName, assignProjectFlag, assignEnvFlag
	defer func() { userEmail = orig; roleName = origR; assignProjectFlag = origP; assignEnvFlag = origE }()
	userEmail = "nonexistent-user@example.com"
	roleName = "nonexistent-role"
	assignProjectFlag = ""
	assignEnvFlag = ""

	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	err := runAssignRole(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to assign role")
}

// TestRunRemoveRole_RemoveError verifies the RemoveUserRoleScoped error return.
func TestRunRemoveRole_RemoveError(t *testing.T) {
	initEmbeddedDB(t)
	// No role assignment exists — RemoveUserRoleScoped will fail.
	origU, origR, origP, origE := removeUserEmail, removeRoleName, removeProjectFlag, removeEnvFlag
	defer func() {
		removeUserEmail = origU
		removeRoleName = origR
		removeProjectFlag = origP
		removeEnvFlag = origE
	}()
	removeUserEmail = "nobody-remove@example.com"
	removeRoleName = "nonexistent-remove-role"
	removeProjectFlag = ""
	removeEnvFlag = ""

	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	err := runRemoveRole(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to remove role")
}

// ── remote error paths for group commands ─────────────────────────────────────

// TestResolveGroupIDRemote_NotFound verifies not-found error from group lookup.
func TestResolveGroupIDRemote_NotFound(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/groups", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"groups":[{"id":1,"name":"other-group","description":""}],"total":1}}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	rc := remoteClientFor(t, srv)

	_, _, err := resolveGroupIDRemote(context.Background(), rc, "no-such-group")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// TestRunAssignRoleToGroupRemote_EnvError verifies env resolution error.
func TestRunAssignRoleToGroupRemote_EnvError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/groups", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"groups":[{"id":7,"name":"ops-team","description":""}],"total":1}}`))
	})
	mux.HandleFunc("/api/v1/roles", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"roles":[{"id":2,"name":"admin","description":""}]}}`))
	})
	mux.HandleFunc("/api/v1/projects", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"projects":[{"id":5,"name":"production"}]}}`))
	})
	mux.HandleFunc("/api/v1/projects/5/environments", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	rc := remoteClientFor(t, srv)

	err := runAssignRoleToGroupRemote(context.Background(), rc, "ops-team", "admin", 0, "production", "bad-env")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list environments")
}

// TestRunRemoveRoleFromGroupRemote_GroupError verifies group resolution error.
func TestRunRemoveRoleFromGroupRemote_GroupError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/groups", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	rc := remoteClientFor(t, srv)

	err := runRemoveRoleFromGroupRemote(context.Background(), rc, "ops-team", "admin", "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list groups")
}

// TestRunRemoveRoleFromGroupRemote_RoleError verifies role resolution error.
func TestRunRemoveRoleFromGroupRemote_RoleError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/groups", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"groups":[{"id":7,"name":"ops-team","description":""}],"total":1}}`))
	})
	mux.HandleFunc("/api/v1/roles", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	rc := remoteClientFor(t, srv)

	err := runRemoveRoleFromGroupRemote(context.Background(), rc, "ops-team", "admin", "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list roles")
}

// TestRunRemoveRoleFromGroupRemote_ProjectError verifies project resolution error.
func TestRunRemoveRoleFromGroupRemote_ProjectError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/groups", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"groups":[{"id":7,"name":"ops-team","description":""}],"total":1}}`))
	})
	mux.HandleFunc("/api/v1/roles", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"roles":[{"id":2,"name":"admin","description":""}]}}`))
	})
	mux.HandleFunc("/api/v1/projects", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	rc := remoteClientFor(t, srv)

	err := runRemoveRoleFromGroupRemote(context.Background(), rc, "ops-team", "admin", "bad-project", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list projects")
}

// TestRunRemoveRoleFromGroupRemote_EnvError verifies env resolution error.
func TestRunRemoveRoleFromGroupRemote_EnvError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/groups", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"groups":[{"id":7,"name":"ops-team","description":""}],"total":1}}`))
	})
	mux.HandleFunc("/api/v1/roles", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"roles":[{"id":2,"name":"admin","description":""}]}}`))
	})
	mux.HandleFunc("/api/v1/projects", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"projects":[{"id":5,"name":"production"}]}}`))
	})
	mux.HandleFunc("/api/v1/projects/5/environments", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	rc := remoteClientFor(t, srv)

	err := runRemoveRoleFromGroupRemote(context.Background(), rc, "ops-team", "admin", "production", "bad-env")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list environments")
}

// TestRunListGroupRolesRemote_GroupError verifies group resolution error.
func TestRunListGroupRolesRemote_GroupError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/groups", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	rc := remoteClientFor(t, srv)

	err := runListGroupRolesRemote(context.Background(), rc, "bad-group")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list groups")
}

// ── remaining remote error paths ──────────────────────────────────────────────

// TestResolveRoleIDByName_FetchError verifies fetchRoles error propagation.
func TestResolveRoleIDByName_FetchError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/roles", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	rc := remoteClientFor(t, srv)

	_, err := resolveRoleIDByName(context.Background(), rc, "any-role")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list roles")
}

// TestRunRemoveRoleRemote_EnvError verifies env resolution error in remove.
func TestRunRemoveRoleRemote_EnvError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/users", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"users":[{"id":5,"email":"alice@test.com"}]}}`))
	})
	mux.HandleFunc("/api/v1/roles", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"roles":[{"id":1,"name":"admin","description":""}]}}`))
	})
	mux.HandleFunc("/api/v1/projects", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"projects":[{"id":3,"name":"myproject"}]}}`))
	})
	mux.HandleFunc("/api/v1/projects/3/environments", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	rc := remoteClientFor(t, srv)

	err := runRemoveRoleRemote(context.Background(), rc, "alice@test.com", "admin", "myproject", "bad-env")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list environments")
}

// TestRunListUserRolesRemote_FetchError verifies fetchUserRoles error propagation.
func TestRunListUserRolesRemote_FetchError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/users", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"users":[{"id":5,"email":"alice@test.com"}]}}`))
	})
	mux.HandleFunc("/api/v1/users/5/roles", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	rc := remoteClientFor(t, srv)

	err := runListUserRolesRemote(context.Background(), rc, "alice@test.com")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get user roles")
}

// TestRunListPermissionsRemote_PermsError verifies userEffectivePermissions error.
func TestRunListPermissionsRemote_PermsError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/users", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"users":[{"id":5,"email":"alice@test.com"}]}}`))
	})
	mux.HandleFunc("/api/v1/users/5/roles", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	rc := remoteClientFor(t, srv)

	err := runListPermissionsRemote(context.Background(), rc, "alice@test.com")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get user roles")
}

// TestRunCheckPermissionRemote_PermsError verifies userEffectivePermissions error.
func TestRunCheckPermissionRemote_PermsError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/users", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"users":[{"id":5,"email":"alice@test.com"}]}}`))
	})
	mux.HandleFunc("/api/v1/users/5/roles", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	rc := remoteClientFor(t, srv)

	err := runCheckPermissionRemote(context.Background(), rc, "alice@test.com", "secrets.read")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get user roles")
}

// ── missing top-level function dispatch paths ─────────────────────────────────

// groupRemoteServer builds a minimal httptest server sufficient for the group
// commands to succeed: group lookup, role lookup, and the mutating endpoint.
func groupRemoteServer(t *testing.T, assignPath, assignResp string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/groups", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"groups":[{"id":7,"name":"ops-team","description":""}],"total":1}}`))
	})
	mux.HandleFunc("/api/v1/roles", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"roles":[{"id":2,"name":"member","description":"Member"}]}}`))
	})
	if assignPath != "" {
		mux.HandleFunc(assignPath, func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost || r.Method == http.MethodDelete || r.Method == http.MethodGet {
				if r.Method == http.MethodPost {
					w.WriteHeader(http.StatusCreated)
				} else if r.Method == http.MethodDelete {
					w.WriteHeader(http.StatusNoContent)
				}
				_, _ = w.Write([]byte(assignResp))
			}
		})
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// TestRunAssignRoleToGroup_NegativeTTL verifies the --ttl < 0 guard.
func TestRunAssignRoleToGroup_NegativeTTL(t *testing.T) {
	origT := groupRoleTTL
	defer func() { groupRoleTTL = origT }()
	groupRoleTTL = -1 * time.Second

	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	err := runAssignRoleToGroup(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--ttl must be positive")
}

// TestRunAssignRoleToGroup_RemoteDispatch exercises the remote-client dispatch line
// inside runAssignRoleToGroup (line 75: return runAssignRoleToGroupRemote(...)).
func TestRunAssignRoleToGroup_RemoteDispatch(t *testing.T) {
	srv := groupRemoteServer(t, "/api/v1/groups/7/roles",
		`{"data":{"group_id":7,"role_id":2}}`)
	origG, origR, origP, origE, origT := groupRoleGroupFlag, groupRoleName, groupRoleProjectFlag, groupRoleEnvFlag, groupRoleTTL
	defer func() {
		groupRoleGroupFlag = origG
		groupRoleName = origR
		groupRoleProjectFlag = origP
		groupRoleEnvFlag = origE
		groupRoleTTL = origT
	}()
	groupRoleGroupFlag = "ops-team"
	groupRoleName = "member"
	groupRoleProjectFlag = ""
	groupRoleEnvFlag = ""
	groupRoleTTL = 0

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")
	err := runAssignRoleToGroup(nil, nil)
	require.NoError(t, err)
}

// TestRunRemoveRoleFromGroup_RemoteDispatch exercises the remote-client dispatch line
// inside runRemoveRoleFromGroup.
func TestRunRemoveRoleFromGroup_RemoteDispatch(t *testing.T) {
	srv := groupRemoteServer(t, "/api/v1/groups/7/roles/2", "")
	origG, origR, origP, origE := removeGroupRoleGroupFlag, removeGroupRoleName, removeGroupRoleProjectFlag, removeGroupRoleEnvFlag
	defer func() {
		removeGroupRoleGroupFlag = origG
		removeGroupRoleName = origR
		removeGroupRoleProjectFlag = origP
		removeGroupRoleEnvFlag = origE
	}()
	removeGroupRoleGroupFlag = "ops-team"
	removeGroupRoleName = "member"
	removeGroupRoleProjectFlag = ""
	removeGroupRoleEnvFlag = ""

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")
	err := runRemoveRoleFromGroup(nil, nil)
	require.NoError(t, err)
}

// TestRunListGroupRoles_RemoteDispatch exercises the remote-client dispatch line
// inside runListGroupRoles.
func TestRunListGroupRoles_RemoteDispatch(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/groups", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"groups":[{"id":7,"name":"ops-team","description":""}],"total":1}}`))
	})
	mux.HandleFunc("/api/v1/groups/7/roles", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"group_id":7,"roles":[]}}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	origG := listGroupRoleGroupFlag
	defer func() { listGroupRoleGroupFlag = origG }()
	listGroupRoleGroupFlag = "ops-team"

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")
	err := runListGroupRoles(nil, nil)
	require.NoError(t, err)
}

// ── assign-role / remove-role top-level error paths ───────────────────────────

// TestRunAssignRole_EnvWithoutProject verifies the guard in embedded mode when
// --environment is set without --project.
func TestRunAssignRole_EnvWithoutProject(t *testing.T) {
	origP, origE := assignProjectFlag, assignEnvFlag
	defer func() { assignProjectFlag = origP; assignEnvFlag = origE }()
	assignProjectFlag = ""
	assignEnvFlag = "production"

	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	err := runAssignRole(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--environment requires --project")
}

// TestRunAssignRole_InitStorageError verifies the InitializeStorage error path.
func TestRunAssignRole_InitStorageError(t *testing.T) {
	noConfigDir(t)
	orig, origR, origP, origE, origT := userEmail, roleName, assignProjectFlag, assignEnvFlag, roleTTL
	defer func() {
		userEmail = orig
		roleName = origR
		assignProjectFlag = origP
		assignEnvFlag = origE
		roleTTL = origT
	}()
	userEmail = "any@example.com"
	roleName = "any"
	assignProjectFlag = ""
	assignEnvFlag = ""
	roleTTL = 0

	err := runAssignRole(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load config")
}

// TestRunRemoveRole_EnvWithoutProject verifies the guard when --environment is
// set without --project in embedded mode.
func TestRunRemoveRole_EnvWithoutProject(t *testing.T) {
	origP, origE := removeProjectFlag, removeEnvFlag
	defer func() { removeProjectFlag = origP; removeEnvFlag = origE }()
	removeProjectFlag = ""
	removeEnvFlag = "production"

	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	err := runRemoveRole(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--environment requires --project")
}

// TestRunRemoveRole_InitStorageError verifies the InitializeStorage error path.
func TestRunRemoveRole_InitStorageError(t *testing.T) {
	noConfigDir(t)
	origU, origR, origP, origE := removeUserEmail, removeRoleName, removeProjectFlag, removeEnvFlag
	defer func() {
		removeUserEmail = origU
		removeRoleName = origR
		removeProjectFlag = origP
		removeEnvFlag = origE
	}()
	removeUserEmail = "any@example.com"
	removeRoleName = "any"
	removeProjectFlag = ""
	removeEnvFlag = ""

	err := runRemoveRole(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load config")
}

// ── runAssignRoleRemote user/role fetch error paths ───────────────────────────

// TestRunAssignRoleRemote_UserFetchError verifies user resolution error in remote assign.
func TestRunAssignRoleRemote_UserFetchError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/users", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	rc := remoteClientFor(t, srv)

	err := runAssignRoleRemote(context.Background(), rc, "alice@test.com", "admin", 0, "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list users")
}

// TestRunAssignRoleRemote_RoleFetchError verifies role resolution error in remote assign.
func TestRunAssignRoleRemote_RoleFetchError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/users", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"users":[{"id":5,"email":"alice@test.com"}]}}`))
	})
	mux.HandleFunc("/api/v1/roles", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	rc := remoteClientFor(t, srv)

	err := runAssignRoleRemote(context.Background(), rc, "alice@test.com", "admin", 0, "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list roles")
}

// ── runAssignRoleToGroupRemote group/role error paths ──────────────────────────

// TestRunAssignRoleToGroupRemote_GroupError verifies group resolution error.
func TestRunAssignRoleToGroupRemote_GroupError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/groups", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	rc := remoteClientFor(t, srv)

	err := runAssignRoleToGroupRemote(context.Background(), rc, "ops-team", "admin", 0, "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list groups")
}

// TestRunAssignRoleToGroupRemote_RoleError verifies role resolution error.
func TestRunAssignRoleToGroupRemote_RoleError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/groups", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"groups":[{"id":7,"name":"ops-team","description":""}],"total":1}}`))
	})
	mux.HandleFunc("/api/v1/roles", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	rc := remoteClientFor(t, srv)

	err := runAssignRoleToGroupRemote(context.Background(), rc, "ops-team", "admin", 0, "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list roles")
}

// TestRunAssignRoleToGroupRemote_TTLSuffix exercises the time-bound print branch.
func TestRunAssignRoleToGroupRemote_TTLSuffix(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/groups", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"groups":[{"id":7,"name":"ops-team","description":""}],"total":1}}`))
	})
	mux.HandleFunc("/api/v1/roles", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"roles":[{"id":2,"name":"admin","description":""}]}}`))
	})
	mux.HandleFunc("/api/v1/groups/7/roles", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"data":{"group_id":7,"role_id":2}}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	rc := remoteClientFor(t, srv)

	// TTL > 0 exercises the "time-bound" print branch (line 280-281).
	err := runAssignRoleToGroupRemote(context.Background(), rc, "ops-team", "admin", 2*time.Hour, "", "")
	require.NoError(t, err)
}

// TestRunRemoveRoleFromGroupRemote_WithEnv exercises the env query-param path.
func TestRunRemoveRoleFromGroupRemote_WithEnv(t *testing.T) {
	var requestURI string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/groups", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"groups":[{"id":7,"name":"ops-team","description":""}],"total":1}}`))
	})
	mux.HandleFunc("/api/v1/roles", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"roles":[{"id":2,"name":"admin","description":""}]}}`))
	})
	mux.HandleFunc("/api/v1/projects", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"projects":[{"id":5,"name":"production"}]}}`))
	})
	mux.HandleFunc("/api/v1/projects/5/environments", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"environments":[{"id":9,"name":"prod"}]}}`))
	})
	mux.HandleFunc("/api/v1/groups/7/roles/2", func(w http.ResponseWriter, r *http.Request) {
		requestURI = r.URL.RequestURI()
		w.WriteHeader(http.StatusNoContent)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	rc := remoteClientFor(t, srv)

	err := runRemoveRoleFromGroupRemote(context.Background(), rc, "ops-team", "admin", "production", "prod")
	require.NoError(t, err)
	assert.Contains(t, requestURI, "environment_id=9")
}

// TestRunListGroupRolesRemote_GetRolesError verifies GetGroupRoles error.
func TestRunListGroupRolesRemote_GetRolesError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/groups", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"groups":[{"id":7,"name":"ops-team","description":""}],"total":1}}`))
	})
	mux.HandleFunc("/api/v1/groups/7/roles", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	rc := remoteClientFor(t, srv)

	err := runListGroupRolesRemote(context.Background(), rc, "ops-team")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get group roles")
}

// ── runAssignRoleToGroupRemote remaining branches ─────────────────────────────

// TestRunAssignRoleToGroupRemote_ProjectError verifies project resolution error.
func TestRunAssignRoleToGroupRemote_ProjectError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/groups", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"groups":[{"id":7,"name":"ops-team","description":""}],"total":1}}`))
	})
	mux.HandleFunc("/api/v1/roles", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"roles":[{"id":2,"name":"admin","description":""}]}}`))
	})
	mux.HandleFunc("/api/v1/projects", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	rc := remoteClientFor(t, srv)

	err := runAssignRoleToGroupRemote(context.Background(), rc, "ops-team", "admin", 0, "bad-project", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list projects")
}

// TestRunAssignRoleToGroupRemote_WithProjectAndEnv verifies project+env success path.
func TestRunAssignRoleToGroupRemote_WithProjectAndEnv(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/groups", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"groups":[{"id":7,"name":"ops-team","description":""}],"total":1}}`))
	})
	mux.HandleFunc("/api/v1/roles", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"roles":[{"id":2,"name":"admin","description":""}]}}`))
	})
	mux.HandleFunc("/api/v1/projects", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"projects":[{"id":5,"name":"production"}]}}`))
	})
	mux.HandleFunc("/api/v1/projects/5/environments", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"environments":[{"id":9,"name":"prod"}]}}`))
	})
	mux.HandleFunc("/api/v1/groups/7/roles", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"data":{"group_id":7,"role_id":2}}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	rc := remoteClientFor(t, srv)

	err := runAssignRoleToGroupRemote(context.Background(), rc, "ops-team", "admin", 0, "production", "prod")
	require.NoError(t, err)
}

// TestRunAssignRoleToGroupRemote_PostError verifies the POST failure path.
func TestRunAssignRoleToGroupRemote_PostError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/groups", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"groups":[{"id":7,"name":"ops-team","description":""}],"total":1}}`))
	})
	mux.HandleFunc("/api/v1/roles", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"roles":[{"id":2,"name":"admin","description":""}]}}`))
	})
	mux.HandleFunc("/api/v1/groups/7/roles", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	rc := remoteClientFor(t, srv)

	err := runAssignRoleToGroupRemote(context.Background(), rc, "ops-team", "admin", 0, "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to assign role")
}

// ── runRemoveRoleFromGroupRemote Delete error ─────────────────────────────────

// TestRunRemoveRoleFromGroupRemote_DeleteError verifies rc.Delete error propagation.
func TestRunRemoveRoleFromGroupRemote_DeleteError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/groups", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"groups":[{"id":7,"name":"ops-team","description":""}],"total":1}}`))
	})
	mux.HandleFunc("/api/v1/roles", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"roles":[{"id":2,"name":"admin","description":""}]}}`))
	})
	mux.HandleFunc("/api/v1/groups/7/roles/2", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	rc := remoteClientFor(t, srv)

	err := runRemoveRoleFromGroupRemote(context.Background(), rc, "ops-team", "admin", "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to remove role")
}

// TestRunRemoveRoleFromGroupRemote_WithEnvSuccess exercises the env body param path.
func TestRunRemoveRoleFromGroupRemote_WithEnvSuccess(t *testing.T) {
	var requestURI string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/groups", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"groups":[{"id":7,"name":"ops-team","description":""}],"total":1}}`))
	})
	mux.HandleFunc("/api/v1/roles", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"roles":[{"id":2,"name":"admin","description":""}]}}`))
	})
	mux.HandleFunc("/api/v1/projects", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"projects":[{"id":5,"name":"prod"}]}}`))
	})
	mux.HandleFunc("/api/v1/projects/5/environments", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"environments":[{"id":9,"name":"staging"}]}}`))
	})
	mux.HandleFunc("/api/v1/groups/7/roles/2", func(w http.ResponseWriter, r *http.Request) {
		requestURI = r.URL.RequestURI()
		w.WriteHeader(http.StatusNoContent)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	rc := remoteClientFor(t, srv)

	err := runRemoveRoleFromGroupRemote(context.Background(), rc, "ops-team", "admin", "prod", "staging")
	require.NoError(t, err)
	assert.Contains(t, requestURI, "environment_id=9")
}

// ── runCheckPermission embedded path ─────────────────────────────────────────

// TestRunCheckPermission_Embedded_HasPermission exercises the "has permission" branch.
func TestRunCheckPermission_Embedded_HasPermission(t *testing.T) {
	_, st := initEmbeddedDB(t)
	ctx := context.Background()

	user, err := st.CreateUser(ctx, &models.User{Username: "chkperm-yes", Email: "chkperm-yes@example.com"})
	require.NoError(t, err)
	chkPermRoleName, err := identity.NewFoldedName("chkperm-role")
	require.NoError(t, err)
	role, err := st.CreateRole(ctx, chkPermRoleName, "test")
	require.NoError(t, err)
	perm, err := st.CreatePermission(ctx, &models.Permission{
		Name: "chkperm.read", Resource: "chkperm", Action: "read", Description: "test",
	})
	require.NoError(t, err)
	require.NoError(t, st.AssignRole(ctx, user.ID, role.ID, corestorage.Scope{}))
	require.NoError(t, st.AssignPermissionToRole(ctx, role.ID, perm.ID))

	origU, origP := checkUserEmail, checkPermissionName
	defer func() { checkUserEmail = origU; checkPermissionName = origP }()
	checkUserEmail = "chkperm-yes@example.com"
	checkPermissionName = "chkperm.read"

	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	require.NoError(t, runCheckPermission(nil, nil))
}

// TestRunCheckPermission_Embedded_NoPermission exercises the "no permission" branch.
func TestRunCheckPermission_Embedded_NoPermission(t *testing.T) {
	_, st := initEmbeddedDB(t)
	ctx := context.Background()

	_, err := st.CreateUser(ctx, &models.User{Username: "chkperm-no", Email: "chkperm-no@example.com"})
	require.NoError(t, err)

	origU, origP := checkUserEmail, checkPermissionName
	defer func() { checkUserEmail = origU; checkPermissionName = origP }()
	checkUserEmail = "chkperm-no@example.com"
	checkPermissionName = "secrets.read"

	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	require.NoError(t, runCheckPermission(nil, nil))
}

// TestRunCheckPermission_InitStorageError verifies the InitializeStorage error path.
func TestRunCheckPermission_InitStorageError(t *testing.T) {
	noConfigDir(t)
	origU, origP := checkUserEmail, checkPermissionName
	defer func() { checkUserEmail = origU; checkPermissionName = origP }()
	checkUserEmail = "any@example.com"
	checkPermissionName = "secrets.read"

	err := runCheckPermission(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load config")
}

// ── embedded InitStorage error for list-roles, list-user-roles, list-permissions ──

// TestRunListRoles_InitStorageError verifies InitializeStorage error in runListRoles.
func TestRunListRoles_InitStorageError(t *testing.T) {
	noConfigDir(t)
	err := runListRoles(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load config")
}

// TestRunListUserRoles_InitStorageError verifies InitializeStorage error in runListUserRoles.
func TestRunListUserRoles_InitStorageError(t *testing.T) {
	noConfigDir(t)
	origU := listUserEmail
	defer func() { listUserEmail = origU }()
	listUserEmail = "any@example.com"

	err := runListUserRoles(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load config")
}

// TestRunListPermissions_InitStorageError verifies InitializeStorage error.
func TestRunListPermissions_InitStorageError(t *testing.T) {
	noConfigDir(t)
	origU := listPermissionsUserEmail
	defer func() { listPermissionsUserEmail = origU }()
	listPermissionsUserEmail = "any@example.com"

	err := runListPermissions(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load config")
}
