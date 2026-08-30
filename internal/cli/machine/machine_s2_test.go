// machine_s2_test.go — sprint-2 coverage for the machine CLI package.
// Targets: resolveProjectContext local path, fetchMachineIdentities local path,
// lifecycleRunE closure, runRevoke, transitionMachine local path,
// runBindingAdd/List/Rm local paths, runCreate project-resolve error.
package machine

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupMachineLocalDB writes a keyorix.yaml, chdirs to the temp dir, and
// seeds a project+machine identity via the core service so that the local CLI
// RunE functions have something to operate on.
// Returns projectID, machineID, and the machine name.
// Also sets KEYORIX_CLI_ACTOR to an admin user ID so binding operations succeed.
func setupMachineLocalDB(t *testing.T) (projectID uint, machineID uint, machineName string) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	t.Setenv("KEYORIX_PROJECT", "testproject")

	dbPath := filepath.Join(dir, "test.db")
	require.NoError(t, config.Save("keyorix.yaml", &config.Config{
		Locale:  config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
		Storage: config.StorageConfig{Type: "local", Database: config.DatabaseConfig{Path: dbPath}},
	}))

	svc, err := common.InitializeCoreService()
	require.NoError(t, err)
	ctx := context.Background()

	// Set a bootstrap token so BootstrapSystem can create the first admin + seed
	// default roles (system_admin, etc.) required for binding operations.
	const testBootstrapToken = "test-bootstrap-tok-s2"
	svc.SetBootstrapToken(testBootstrapToken)

	result, err := svc.BootstrapSystem(ctx, &core.BootstrapRequest{
		Username:    "admin",
		Email:       "admin@example.com",
		Password:    "Xk9$mPqLn2#vRt7w!",
		DisplayName: "Admin",
		Token:       testBootstrapToken,
	})
	require.NoError(t, err)

	// Set KEYORIX_CLI_ACTOR to the admin user's ID so binding operations pass authority checks.
	t.Setenv("KEYORIX_CLI_ACTOR", fmt.Sprintf("%d", result.User.ID))

	proj, err := svc.CreateProject(ctx, "testproject", "Test project")
	require.NoError(t, err)
	projectID = proj.ID

	m, err := svc.CreateMachineIdentity(ctx, projectID, "ci-bot", "ci", "CI runner", "", 0, 0)
	require.NoError(t, err)
	machineID = m.ID
	machineName = m.Name
	return projectID, machineID, machineName
}

// ── resolveProjectContext (local path) ────────────────────────────────────────

// TestResolveProjectContext_Local exercises the local code path where the
// project is found in the SQLite DB.
func TestResolveProjectContext_Local(t *testing.T) {
	setupMachineLocalDB(t)

	name, id, err := resolveProjectContext("testproject")
	require.NoError(t, err)
	assert.Equal(t, "testproject", name)
	assert.NotZero(t, id)
}

// TestResolveProjectContext_Local_NotFound exercises the error path when the
// project doesn't exist.
func TestResolveProjectContext_Local_NotFound(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	dbPath := filepath.Join(dir, "test.db")
	require.NoError(t, config.Save("keyorix.yaml", &config.Config{
		Locale:  config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
		Storage: config.StorageConfig{Type: "local", Database: config.DatabaseConfig{Path: dbPath}},
	}))

	_, _, err := resolveProjectContext("nonexistent")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nonexistent")
}

// ── fetchMachineIdentities (local path) ───────────────────────────────────────

// TestFetchMachineIdentities_Local exercises the local DB path.
func TestFetchMachineIdentities_Local(t *testing.T) {
	projectID, _, _ := setupMachineLocalDB(t)

	ids, err := fetchMachineIdentities(context.Background(), projectID)
	require.NoError(t, err)
	require.NotEmpty(t, ids)
	assert.Equal(t, "ci-bot", ids[0].Name)
}

// TestFetchMachineIdentities_Local_EmptyProject exercises local path with no machines.
func TestFetchMachineIdentities_Local_EmptyProject(t *testing.T) {
	projectID, _, _ := setupMachineLocalDB(t)

	// Create a second project with no machines.
	svc, err := common.InitializeCoreService()
	require.NoError(t, err)
	proj2, err := svc.CreateProject(context.Background(), "emptyproj", "")
	require.NoError(t, err)

	ids, err := fetchMachineIdentities(context.Background(), proj2.ID)
	require.NoError(t, err)
	assert.Empty(t, ids)
	_ = projectID
}

// ── runList (local path) ──────────────────────────────────────────────────────

// TestRunList_Local drives runList through the local path.
func TestRunList_Local(t *testing.T) {
	setupMachineLocalDB(t)

	orig := listProjectName
	defer func() { listProjectName = orig }()
	listProjectName = "testproject"

	err := runList(nil, nil)
	assert.NoError(t, err)
}

// ── runCreate (local path) ────────────────────────────────────────────────────

// TestRunCreate_Local creates a machine identity via the local service path.
func TestRunCreate_Local(t *testing.T) {
	setupMachineLocalDB(t)

	origP, origN, origT, origD, origC := createProjectName, createName, createType, createDescription, createClassification
	defer func() {
		createProjectName = origP
		createName = origN
		createType = origT
		createDescription = origD
		createClassification = origC
	}()
	createProjectName = "testproject"
	createName = "new-machine"
	createType = "ci"
	createDescription = "new CI runner"
	createClassification = ""

	err := runCreate(nil, nil)
	assert.NoError(t, err)
}

// ── runDescribe (local path) ──────────────────────────────────────────────────

// TestRunDescribe_Local drives runDescribe in local mode.
func TestRunDescribe_Local(t *testing.T) {
	_, _, machineName := setupMachineLocalDB(t)

	orig := describeProjectName
	defer func() { describeProjectName = orig }()
	describeProjectName = "testproject"

	err := runDescribe(nil, []string{machineName})
	assert.NoError(t, err)
}

// ── lifecycleRunE (local path) ─────────────────────────────────────────────────

// TestLifecycleRunE_Suspend_Local exercises lifecycleRunE("suspend", ...) via
// the local service path.
func TestLifecycleRunE_Suspend_Local(t *testing.T) {
	_, _, machineName := setupMachineLocalDB(t)

	orig := lifecycleProjectName
	defer func() { lifecycleProjectName = orig }()
	lifecycleProjectName = "testproject"

	fn := lifecycleRunE("suspend", core.MachineSuspended)
	err := fn(nil, []string{machineName})
	assert.NoError(t, err)
}

// TestLifecycleRunE_Reactivate_Local exercises lifecycleRunE for reactivation.
func TestLifecycleRunE_Reactivate_Local(t *testing.T) {
	_, _, machineName := setupMachineLocalDB(t)

	orig := lifecycleProjectName
	defer func() { lifecycleProjectName = orig }()
	lifecycleProjectName = "testproject"

	// Suspend first.
	fn := lifecycleRunE("suspend", core.MachineSuspended)
	require.NoError(t, fn(nil, []string{machineName}))

	// Then reactivate.
	fn2 := lifecycleRunE("activate", core.MachineActive)
	err := fn2(nil, []string{machineName})
	assert.NoError(t, err)
}

// TestLifecycleRunE_MachineNotFound exercises the error path when the machine
// reference doesn't match.
func TestLifecycleRunE_MachineNotFound(t *testing.T) {
	setupMachineLocalDB(t)

	orig := lifecycleProjectName
	defer func() { lifecycleProjectName = orig }()
	lifecycleProjectName = "testproject"

	fn := lifecycleRunE("suspend", core.MachineSuspended)
	err := fn(nil, []string{"nonexistent-machine"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// ── runRevoke (local path) ────────────────────────────────────────────────────

// TestRunRevoke_Local_WithForce exercises runRevoke with --force in local mode.
func TestRunRevoke_Local_WithForce(t *testing.T) {
	_, _, machineName := setupMachineLocalDB(t)

	orig, origForce := lifecycleProjectName, revokeForce
	defer func() { lifecycleProjectName = orig; revokeForce = origForce }()
	lifecycleProjectName = "testproject"
	revokeForce = true

	err := runRevoke(nil, []string{machineName})
	assert.NoError(t, err)
}

// TestRunRevoke_Local_NameConfirmation exercises runRevoke with typed-name
// confirmation in local mode.
func TestRunRevoke_Local_NameConfirmation(t *testing.T) {
	projectID, _, machineName := setupMachineLocalDB(t)

	revokeForce = false
	defer func() { revokeForce = false }()

	cmd := &cobra.Command{}
	cmd.SetIn(strings.NewReader(machineName + "\n"))

	m, findErr := findMachineByRef(context.Background(), projectID, machineName)
	require.NoError(t, findErr)

	err := revokeMachine(cmd, context.Background(), projectID, m)
	assert.NoError(t, err)
}

// ── transitionMachine (local path) ───────────────────────────────────────────

// TestTransitionMachine_Local exercises the local service path.
func TestTransitionMachine_Local(t *testing.T) {
	projectID, _, machineName := setupMachineLocalDB(t)

	// Find the machine.
	m, err := findMachineByRef(context.Background(), projectID, machineName)
	require.NoError(t, err)

	// Suspend via local path.
	err = transitionMachine(context.Background(), projectID, m, "suspend", core.MachineSuspended)
	assert.NoError(t, err)
}

// ── runBindingList (local path) ───────────────────────────────────────────────

// TestRunBindingList_Local exercises runBindingList in local mode.
func TestRunBindingList_Local(t *testing.T) {
	_, _, machineName := setupMachineLocalDB(t)

	orig := bindingProjectName
	defer func() { bindingProjectName = orig }()
	bindingProjectName = "testproject"

	// Empty binding list should succeed.
	err := runBindingList(nil, []string{machineName})
	assert.NoError(t, err)
}

// ── runBindingAdd (local path) ────────────────────────────────────────────────

// TestRunBindingAdd_Local exercises runBindingAdd in local mode.
func TestRunBindingAdd_Local(t *testing.T) {
	_, _, machineName := setupMachineLocalDB(t)

	origP, origI, origS := bindingProjectName, bindingIssuer, bindingSubject
	defer func() { bindingProjectName = origP; bindingIssuer = origI; bindingSubject = origS }()
	bindingProjectName = "testproject"
	bindingIssuer = "https://token.example.com"
	bindingSubject = "system:serviceaccount:prod:ci"

	err := runBindingAdd(nil, []string{machineName})
	assert.NoError(t, err)
}

// ── runBindingRm (local path) ─────────────────────────────────────────────────

// TestRunBindingRm_Local exercises runBindingRm in local mode.
func TestRunBindingRm_Local(t *testing.T) {
	_, _, machineName := setupMachineLocalDB(t)

	// First create a binding to remove.
	origP, origI, origS := bindingProjectName, bindingIssuer, bindingSubject
	defer func() { bindingProjectName = origP; bindingIssuer = origI; bindingSubject = origS }()
	bindingProjectName = "testproject"
	bindingIssuer = "https://to-remove.example.com"
	bindingSubject = "sub-to-remove"
	require.NoError(t, runBindingAdd(nil, []string{machineName}))

	// Retrieve the binding ID.
	_, projectID, _ := resolveProjectContext("testproject") //nolint:dogsled
	svc, err := common.InitializeCoreService()
	require.NoError(t, err)
	m, err := findMachineByRef(context.Background(), projectID, machineName)
	require.NoError(t, err)
	bindings, err := svc.ListOIDCBindings(context.Background(), projectID, m.ID)
	require.NoError(t, err)
	require.NotEmpty(t, bindings)

	bindingIDStr := fmt.Sprintf("%d", bindings[0].ID)
	err = runBindingRm(nil, []string{machineName, bindingIDStr})
	assert.NoError(t, err)
}

// ── remote error paths ────────────────────────────────────────────────────────

// TestRunCreate_ProjectNotFound_Remote verifies runCreate returns error when
// project is not found on the server.
func TestRunCreate_ProjectNotFound_Remote(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"projects":[]}}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	origP, origN := createProjectName, createName
	defer func() { createProjectName = origP; createName = origN }()
	createProjectName = "doesnotexist"
	createName = "ci-bot"

	err := runCreate(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "doesnotexist")
}

// TestRunBindingAdd_MachineNotFound_Remote verifies runBindingAdd returns error
// when machine is not found in the project.
func TestRunBindingAdd_MachineNotFound_Remote(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/projects":
			_, _ = w.Write([]byte(`{"data":{"projects":[{"id":9,"name":"myproject"}]}}`))
		case "/api/v1/projects/9/machine-identities":
			_, _ = w.Write([]byte(`{"data":{"machine_identities":[]}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	origP, origI, origS := bindingProjectName, bindingIssuer, bindingSubject
	defer func() { bindingProjectName = origP; bindingIssuer = origI; bindingSubject = origS }()
	bindingProjectName = "myproject"
	bindingIssuer = "https://issuer.example.com"
	bindingSubject = "sub"

	err := runBindingAdd(nil, []string{"ghost-machine"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// TestTokenHygieneCmd_NotConnected verifies the "not connected" error path.
func TestTokenHygieneCmd_NotConnected(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	err := tokenHygieneCmd.RunE(tokenHygieneCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

// TestTokenHygieneCmd_EmptyResult exercises the "no stale tokens" path.
func TestTokenHygieneCmd_EmptyResult(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"tokens":[]}}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	err := tokenHygieneCmd.RunE(tokenHygieneCmd, nil)
	assert.NoError(t, err)
}

// TestTokenHygieneCmd_WithResults exercises the table-printing path.
func TestTokenHygieneCmd_WithResults(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"tokens":[{"id":1,"machine_identity_id":2,"name":"ci","token_prefix":"kx_machine_ci","expired":true,"stale":false}]}}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	err := tokenHygieneCmd.RunE(tokenHygieneCmd, nil)
	assert.NoError(t, err)
}
