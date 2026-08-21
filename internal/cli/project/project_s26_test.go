// project_s26_test.go — s26 coverage blitz: remaining error/edge branches in
// env create/delete, verifyEnvironmentBelongsToProject, resolveProjectContext,
// runCreate (dup name with --envs), and runUse (LoadCLIConfig / SaveCLIConfig
// fallback paths).
package project

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── runEnvCreate — embedded CreateEnvironment failure ────────────────────────

// TestRunEnvCreate_Embedded_CreateFails verifies that an invalid environment
// name (fails core validation) is surfaced as a "failed to create environment"
// error from the embedded path of runEnvCreate.
func TestRunEnvCreate_Embedded_CreateFails(t *testing.T) {
	setupEmbedded(t)
	svc := embeddedCore(t)
	_, err := svc.CreateProject(context.Background(), "web", "")
	require.NoError(t, err)

	envProjectFlag = "web"
	envCreateName = "" // fails validateEnvironmentName ("name is required")

	err = runEnvCreate(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create environment")
}

// ── runEnvDelete — embedded resolveProjectContext / init / delete errors ─────

// TestRunEnvDelete_Embedded_ProjectFlagNotFound verifies that a --project flag
// naming a nonexistent project is refused before any delete is attempted.
func TestRunEnvDelete_Embedded_ProjectFlagNotFound(t *testing.T) {
	setupEmbedded(t)
	origConfirm := envDeleteConfirm
	origProject := envProjectFlag
	t.Cleanup(func() { envDeleteConfirm = origConfirm; envProjectFlag = origProject })
	envDeleteConfirm = true
	envProjectFlag = "no-such-project"

	err := runEnvDelete(nil, []string{"1"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// TestRunEnvDelete_Embedded_BrokenService_Confirmed verifies the embedded
// InitializeCoreService failure branch inside runEnvDelete itself (distinct
// from resolveProjectContext's own InitializeCoreService call, which is
// skipped here by leaving --project unset).
func TestRunEnvDelete_Embedded_BrokenService_Confirmed(t *testing.T) {
	setupBrokenService(t)
	origConfirm := envDeleteConfirm
	origProject := envProjectFlag
	t.Cleanup(func() { envDeleteConfirm = origConfirm; envProjectFlag = origProject })
	envDeleteConfirm = true
	envProjectFlag = "" // skip the --project cross-check branch entirely

	err := runEnvDelete(nil, []string{"1"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to initialize service")
}

// TestRunEnvDelete_Embedded_DeleteFails verifies that deleting a nonexistent
// environment ID surfaces svc.DeleteEnvironment's "not found" error wrapped as
// "failed to delete environment".
func TestRunEnvDelete_Embedded_DeleteFails(t *testing.T) {
	setupEmbedded(t)
	origConfirm := envDeleteConfirm
	origProject := envProjectFlag
	t.Cleanup(func() { envDeleteConfirm = origConfirm; envProjectFlag = origProject })
	envDeleteConfirm = true
	envProjectFlag = ""

	err := runEnvDelete(nil, []string{"999999"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to delete environment")
}

// ── verifyEnvironmentBelongsToProject — embedded ─────────────────────────────

// TestVerifyEnvironmentBelongsToProject_Embedded_Mismatch verifies the
// embedded cross-check refuses an environment id that belongs to a different
// project than the one named.
func TestVerifyEnvironmentBelongsToProject_Embedded_Mismatch(t *testing.T) {
	setupEmbedded(t)
	ctx := context.Background()
	svc := embeddedCore(t)

	projA, err := svc.CreateProjectWithEnvs(ctx, "proj-a", "", []string{"prod"})
	require.NoError(t, err)
	projB, err := svc.CreateProjectWithEnvs(ctx, "proj-b", "", []string{"prod"})
	require.NoError(t, err)

	envsA, err := svc.ListEnvironmentsByProject(ctx, projA.ID)
	require.NoError(t, err)
	require.NotEmpty(t, envsA)

	err = verifyEnvironmentBelongsToProject(ctx, projB.ID, envsA[0].ID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not belong to project")
}

// TestVerifyEnvironmentBelongsToProject_Embedded_Match verifies the positive
// counterpart: an environment id that does belong to the named project passes.
func TestVerifyEnvironmentBelongsToProject_Embedded_Match(t *testing.T) {
	setupEmbedded(t)
	ctx := context.Background()
	svc := embeddedCore(t)

	proj, err := svc.CreateProjectWithEnvs(ctx, "proj-a", "", []string{"prod"})
	require.NoError(t, err)
	envs, err := svc.ListEnvironmentsByProject(ctx, proj.ID)
	require.NoError(t, err)
	require.NotEmpty(t, envs)

	err = verifyEnvironmentBelongsToProject(ctx, proj.ID, envs[0].ID)
	require.NoError(t, err)
}

// TestRunEnvDelete_Remote_VerifyGetEnvironmentsError verifies that a server
// error on GET /api/v1/projects/{id}/environments during the --project
// cross-check (verifyEnvironmentBelongsToProject) is surfaced distinctly from
// a resolveProjectContext failure: the project list call succeeds, but the
// subsequent environments call used to verify env ownership fails.
func TestRunEnvDelete_Remote_VerifyGetEnvironmentsError(t *testing.T) {
	setupRemote(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/projects":
			_, _ = w.Write([]byte(`{"success":true,"data":{"projects":[{"id":1,"name":"web"}]}}`))
		default:
			// /api/v1/projects/1/environments (verify step) → 500
			w.WriteHeader(http.StatusInternalServerError)
		}
	})
	origConfirm := envDeleteConfirm
	origProject := envProjectFlag
	t.Cleanup(func() { envDeleteConfirm = origConfirm; envProjectFlag = origProject })
	envDeleteConfirm = true
	envProjectFlag = "web"

	err := runEnvDelete(nil, []string{"10"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to verify environment")
}

// ── runStatsEmbedded — InitializeCoreService failure ─────────────────────────

// TestProjectStats_Embedded_ServiceInitError forces InitializeCoreService to
// fail by pointing the DB path at a directory (SQLite cannot open a directory),
// mirroring TestProjectHealth_Embedded_ServiceInitError.
func TestProjectStats_Embedded_ServiceInitError(t *testing.T) {
	dir := t.TempDir()
	dbDirPath := filepath.Join(dir, "isadirectory")
	require.NoError(t, os.MkdirAll(dbDirPath, 0o700))

	cfgPath := filepath.Join(dir, "keyorix.yaml")
	require.NoError(t, config.Save(cfgPath, &config.Config{
		Locale:  config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
		Storage: config.StorageConfig{Type: "local", Database: config.DatabaseConfig{Path: dbDirPath}},
	}))
	t.Setenv("KEYORIX_CONFIG_PATH", cfgPath)
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("KEYORIX_TOKEN", "")
	t.Setenv("KEYORIX_SERVER", "")
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(func() { statsFormat = "table" })

	err := runStatsEmbedded(context.Background(), "any-project")
	require.Error(t, err, "expected error when storage cannot be opened")
	assert.Contains(t, err.Error(), "failed to initialize service")
}

// ── resolveProjectContext — remote not-found ─────────────────────────────────

// TestResolveProjectContext_Remote_NotFound verifies that a remote project
// list not containing the named project is reported as "not found".
func TestResolveProjectContext_Remote_NotFound(t *testing.T) {
	setupRemote(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"data":{"projects":[{"id":1,"name":"other"}]}}`))
	})

	_, _, err := resolveProjectContext("ghost")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// ── runCreate — embedded duplicate name with --envs ──────────────────────────

// TestRunCreate_Embedded_DupName_WithEnvs verifies that the
// CreateProjectWithEnvs error branch (used when --envs is set) surfaces a
// duplicate-name failure, distinct from the no-envs CreateProject branch
// already covered by TestRunCreate_Embedded_DupName.
func TestRunCreate_Embedded_DupName_WithEnvs(t *testing.T) {
	setupEmbedded(t)
	svc := embeddedCore(t)
	_, err := svc.CreateProject(context.Background(), "dupe2", "")
	require.NoError(t, err)

	createName = "dupe2"
	createEnvs = "dev,prod"
	err = runCreate(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create project")
}

// ── runUse — LoadCLIConfig / SaveCLIConfig branches ──────────────────────────

// TestRunUse_Embedded_LoadConfigFallback verifies that a malformed existing
// cli.yaml causes LoadCLIConfig to error, and runUse falls back to
// cliconfig.DefaultCLIConfig() rather than failing outright.
func TestRunUse_Embedded_LoadConfigFallback(t *testing.T) {
	setupEmbedded(t)
	svc := embeddedCore(t)
	_, err := svc.CreateProject(context.Background(), "web", "")
	require.NoError(t, err)

	// Write a malformed cli.yaml at the exact path getDefaultCLIConfigPath()
	// resolves to ($XDG_CONFIG_HOME/keyorix/cli.yaml) so LoadCLIConfig("")
	// hits its YAML-parse error branch instead of the file-not-exist branch.
	cliDir := filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "keyorix")
	require.NoError(t, os.MkdirAll(cliDir, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(cliDir, "cli.yaml"), []byte("not: valid: yaml: [["), 0o600))

	out := captureStdout(t, func() { require.NoError(t, runUse(nil, []string{"web"})) })
	assert.Contains(t, out, `Active project set to "web"`)
}

// TestRunUse_Embedded_SaveConfigError verifies that a SaveCLIConfig failure
// (config directory cannot be created because a file already occupies that
// path) is surfaced as "failed to save config".
func TestRunUse_Embedded_SaveConfigError(t *testing.T) {
	setupEmbedded(t)
	svc := embeddedCore(t)
	_, err := svc.CreateProject(context.Background(), "web", "")
	require.NoError(t, err)

	// Occupy the "keyorix" path (which SaveCLIConfig's MkdirAll needs to be a
	// directory) with a regular file, so os.MkdirAll fails.
	xdg := os.Getenv("XDG_CONFIG_HOME")
	require.NoError(t, os.WriteFile(filepath.Join(xdg, "keyorix"), []byte("blocker"), 0o600))

	err = runUse(nil, []string{"web"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to save config")
}
