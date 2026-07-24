package project

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	coreStorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)


// setupHealthRemote creates a mock HTTP server backed by handler, sets the
// KEYORIX_* env vars so common.NewRemoteClient returns true, and returns the
// client plus a cleanup function.
func setupHealthRemote(t *testing.T, handler http.HandlerFunc) (*common.RemoteClient, func()) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")
	t.Setenv("KEYORIX_PROJECT", "")
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(func() {
		healthLimit = 20
		healthFormat = "table"
	})
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)
	return rc, srv.Close
}

// captureHealthStdout captures os.Stdout output from fn.
func captureHealthStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w
	defer func() { os.Stdout = orig }()
	fn()
	require.NoError(t, w.Close())
	out, _ := io.ReadAll(r)
	return string(out)
}

// projectsAndHealthHandler serves /api/v1/projects and /api/v1/projects/1/health
// in the real sendSuccess envelope shape.
func projectsAndHealthHandler(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/api/v1/projects":
		_, _ = w.Write([]byte(`{"success":true,"data":{"projects":[{"id":1,"name":"web","description":"the web project"}]}}`))
	case "/api/v1/projects/1/health":
		_, _ = w.Write([]byte(`{"success":true,"data":{` +
			`"project_id":1,` +
			`"total_secrets":42,` +
			`"high_risk_count":3,` +
			`"medium_risk_count":11,` +
			`"low_risk_count":28,` +
			`"secrets":[` +
			`{"secret_id":5,"secret_name":"prod-db-password","score":91,"band":"high","factors":[{"key":"rotation","label":"Rotation age","score":100,"weight":0.3,"detail":"not rotated in 180 days"}]},` +
			`{"secret_id":8,"secret_name":"api-key-external","score":72,"band":"high","factors":[{"key":"exposure","label":"Exposure","score":90,"weight":0.2,"detail":"shared with 6 principals"}]},` +
			`{"secret_id":3,"secret_name":"stripe-webhook","score":68,"band":"medium","factors":[{"key":"expiry","label":"Expiry","score":40,"weight":0.3,"detail":"no expiry set"}]}` +
			`]}}`))
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func TestProjectHealth_Remote_TableFormat(t *testing.T) {
	rc, done := setupHealthRemote(t, projectsAndHealthHandler)
	defer done()

	healthFormat = "table"
	out := captureHealthStdout(t, func() {
		require.NoError(t, runHealthRemote(t.Context(), rc, "web"))
	})

	// Header line with project and counts.
	assert.Contains(t, out, "web")
	assert.Contains(t, out, "42 secrets")
	assert.Contains(t, out, "3 HIGH")
	assert.Contains(t, out, "11 MEDIUM")
	assert.Contains(t, out, "28 LOW")

	// Table rows.
	assert.Contains(t, out, "prod-db-password")
	assert.Contains(t, out, "91")
	assert.Contains(t, out, "HIGH")
	assert.Contains(t, out, "api-key-external")
	assert.Contains(t, out, "stripe-webhook")
	assert.Contains(t, out, "MEDIUM")
}

func TestProjectHealth_Remote_JSONFormat(t *testing.T) {
	rc, done := setupHealthRemote(t, projectsAndHealthHandler)
	defer done()

	healthFormat = "json"
	out := captureHealthStdout(t, func() {
		require.NoError(t, runHealthRemote(t.Context(), rc, "web"))
	})

	// Output must be valid JSON containing the expected fields.
	assert.Contains(t, out, `"project_id":1`)
	assert.Contains(t, out, `"total_secrets":42`)
	assert.Contains(t, out, `"high_risk_count":3`)
	assert.Contains(t, out, `"medium_risk_count":11`)
	assert.Contains(t, out, `"low_risk_count":28`)
	assert.Contains(t, out, `"prod-db-password"`)
	assert.Contains(t, out, `"score":91`)
}

// ── Additional remote error paths ──────────────────────────────────────────

func TestProjectHealth_Remote_ListProjectsError(t *testing.T) {
	_, done := setupHealthRemote(t, func(w http.ResponseWriter, r *http.Request) {
		// All requests fail with 500.
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"success":false,"error":"StorageError","message":"db down","code":500}`))
	})
	defer done()

	rc, ok := common.NewRemoteClient()
	require.True(t, ok)

	err := runHealthRemote(t.Context(), rc, "web")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list projects")
}

func TestProjectHealth_Remote_ProjectNotFound(t *testing.T) {
	rc, done := setupHealthRemote(t, func(w http.ResponseWriter, r *http.Request) {
		// /api/v1/projects returns an empty list.
		_, _ = w.Write([]byte(`{"success":true,"data":{"projects":[]}}`))
	})
	defer done()

	err := runHealthRemote(t.Context(), rc, "nonexistent")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestProjectHealth_Remote_HealthEndpointError(t *testing.T) {
	rc, done := setupHealthRemote(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/projects":
			_, _ = w.Write([]byte(`{"success":true,"data":{"projects":[{"id":1,"name":"web"}]}}`))
		default:
			// Health endpoint returns 500.
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"success":false,"error":"InternalError","message":"failed","code":500}`))
		}
	})
	defer done()

	err := runHealthRemote(t.Context(), rc, "web")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get project health")
}

func TestProjectHealth_Remote_LimitParam(t *testing.T) {
	var capturedPath string
	rc, done := setupHealthRemote(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/projects":
			_, _ = w.Write([]byte(`{"success":true,"data":{"projects":[{"id":1,"name":"web"}]}}`))
		default:
			capturedPath = r.URL.RequestURI()
			_, _ = w.Write([]byte(`{"success":true,"data":{"project_id":1,"total_secrets":0,"high_risk_count":0,"medium_risk_count":0,"low_risk_count":0,"secrets":[]}}`))
		}
	})
	defer done()

	// Set a non-default limit to trigger the ?limit= query string branch.
	healthLimit = 5
	require.NoError(t, runHealthRemote(t.Context(), rc, "web"))
	assert.Contains(t, capturedPath, "limit=5")
}

func TestProjectHealth_Remote_UnsupportedFormat(t *testing.T) {
	rc, done := setupHealthRemote(t, projectsAndHealthHandler)
	defer done()

	healthFormat = "xml" // unsupported
	err := runHealthRemote(t.Context(), rc, "web")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported format")
}

func TestProjectHealth_Remote_TableNoSecrets(t *testing.T) {
	rc, done := setupHealthRemote(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/projects":
			_, _ = w.Write([]byte(`{"success":true,"data":{"projects":[{"id":1,"name":"empty"}]}}`))
		default:
			_, _ = w.Write([]byte(`{"success":true,"data":{"project_id":1,"total_secrets":0,"high_risk_count":0,"medium_risk_count":0,"low_risk_count":0,"secrets":[]}}`))
		}
	})
	defer done()

	healthFormat = "table"
	out := captureHealthStdout(t, func() {
		require.NoError(t, runHealthRemote(t.Context(), rc, "empty"))
	})
	assert.Contains(t, out, "No secrets found")
}

func TestProjectHealth_TopFactorDetail_NoFactors(t *testing.T) {
	// topFactorDetail must return "" for an empty factor slice (not panic).
	result := topFactorDetail(nil)
	assert.Equal(t, "", result)
}

func TestProjectHealth_TopFactorDetail_MultipleFactors(t *testing.T) {
	factors := []healthRiskFactor{
		{Key: "rotation", Score: 50, Detail: "medium detail"},
		{Key: "expiry", Score: 100, Detail: "highest detail"},
		{Key: "usage", Score: 30, Detail: "low detail"},
	}
	result := topFactorDetail(factors)
	assert.Equal(t, "highest detail", result)
}

// ── Embedded mode ──────────────────────────────────────────────────────────

// setupHealthEmbedded configures an isolated on-disk SQLite database for the
// health command in embedded mode (no KEYORIX_SERVER/TOKEN set).
func setupHealthEmbedded(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "keyorix.yaml")
	require.NoError(t, config.Save(cfgPath, &config.Config{
		Locale:  config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
		Storage: config.StorageConfig{Type: "local", Database: config.DatabaseConfig{Path: filepath.Join(dir, "test.db")}},
	}))
	t.Setenv("KEYORIX_CONFIG_PATH", cfgPath)
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("KEYORIX_TOKEN", "")
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_PROJECT", "")
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(func() {
		healthLimit = 20
		healthFormat = "table"
	})
}

func TestProjectHealth_Embedded_NotFound(t *testing.T) {
	setupHealthEmbedded(t)

	err := runHealthEmbedded(context.Background(), "no-such-project")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestProjectHealth_Embedded_EmptyProject_Table(t *testing.T) {
	setupHealthEmbedded(t)

	// Create a project via the create command so it exists in the embedded DB.
	createName = "alpha"
	createDescription = ""
	createEnvs = "dev"
	require.NoError(t, runCreate(nil, nil))
	t.Cleanup(func() { createName, createDescription, createEnvs = "", "", "" })

	healthFormat = "table"
	out := captureHealthStdout(t, func() {
		require.NoError(t, runHealthEmbedded(context.Background(), "alpha"))
	})
	assert.Contains(t, out, "alpha")
	assert.Contains(t, out, "0 secrets")
}

func TestProjectHealth_Embedded_EmptyProject_JSON(t *testing.T) {
	setupHealthEmbedded(t)

	createName = "beta"
	createDescription = ""
	createEnvs = "prod"
	require.NoError(t, runCreate(nil, nil))
	t.Cleanup(func() { createName, createDescription, createEnvs = "", "", "" })

	healthFormat = "json"
	out := captureHealthStdout(t, func() {
		require.NoError(t, runHealthEmbedded(context.Background(), "beta"))
	})
	assert.Contains(t, out, `"total_secrets"`)
	assert.Contains(t, out, `"project_id"`)
}

func TestProjectHealth_Embedded_WithSecrets(t *testing.T) {
	setupHealthEmbedded(t)
	ctx := context.Background()

	// Create project + environment via CLI.
	createName = "gamma"
	createDescription = ""
	createEnvs = "prod"
	require.NoError(t, runCreate(nil, nil))
	t.Cleanup(func() { createName, createDescription, createEnvs = "", "", "" })

	// Seed a secret via the core service so TopRiskSecrets is non-empty
	// and exercises the factor-conversion loop inside runHealthEmbedded.
	svc, err := common.InitializeCoreService()
	require.NoError(t, err)
	projects, err := svc.ListProjects(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, projects)
	var gammaID uint
	for _, p := range projects {
		if p.Name == "gamma" {
			gammaID = p.ID
		}
	}
	require.NotZero(t, gammaID, "project gamma must have been created")

	envs, err := svc.ListEnvironmentsByProject(ctx, gammaID)
	require.NoError(t, err)
	require.NotEmpty(t, envs, "project gamma must have at least one environment")

	_, err = svc.CreateSecret(ctx, &core.CreateSecretRequest{
		Name:          "gamma-secret",
		Value:         []byte("s3cr3t"),
		ProjectID:     gammaID,
		EnvironmentID: envs[0].ID,
		Type:          "password",
		CreatedBy:     "test",
	})
	require.NoError(t, err)

	healthFormat = "table"
	out := captureHealthStdout(t, func() {
		require.NoError(t, runHealthEmbedded(ctx, "gamma"))
	})
	assert.Contains(t, out, "gamma")
	assert.Contains(t, out, "1 secrets")
}

// TestProjectHealth_RunE_Remote verifies that healthCmd.RunE dispatches to the
// remote path when KEYORIX_SERVER + KEYORIX_TOKEN are set.
func TestProjectHealth_RunE_Remote(t *testing.T) {
	setupHealthRemote(t, projectsAndHealthHandler)

	healthFormat = "table"
	out := captureHealthStdout(t, func() {
		require.NoError(t, healthCmd.RunE(healthCmd, []string{"web"}))
	})
	assert.Contains(t, out, "web")
}

// TestProjectHealth_RunE_Embedded verifies that healthCmd.RunE dispatches to the
// embedded path when no server env vars are set.
func TestProjectHealth_RunE_Embedded(t *testing.T) {
	setupHealthEmbedded(t)

	// project doesn't exist → error expected (embedded path)
	err := healthCmd.RunE(healthCmd, []string{"no-such-project"})
	require.Error(t, err)
}

// TestProjectHealth_Embedded_ServiceInitError forces InitializeCoreService to
// fail by pointing the DB path at a directory (SQLite cannot open a directory).
func TestProjectHealth_Embedded_ServiceInitError(t *testing.T) {
	dir := t.TempDir()
	// Point the DB path at a sub-directory — SQLite will fail to open it.
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
	t.Cleanup(func() { healthLimit = 20; healthFormat = "table" })

	err := runHealthEmbedded(context.Background(), "any-project")
	require.Error(t, err, "expected error when storage cannot be opened")
}


func TestProjectHealth_Embedded_LongSecretName(t *testing.T) {
	setupHealthEmbedded(t)
	ctx := context.Background()

	createName = "delta"
	createDescription = ""
	createEnvs = "dev"
	require.NoError(t, runCreate(nil, nil))
	t.Cleanup(func() { createName, createDescription, createEnvs = "", "", "" })

	svc, err := common.InitializeCoreService()
	require.NoError(t, err)
	projects, err := svc.ListProjects(ctx)
	require.NoError(t, err)
	var deltaID uint
	for _, p := range projects {
		if p.Name == "delta" {
			deltaID = p.ID
		}
	}
	require.NotZero(t, deltaID)

	envs, err := svc.ListEnvironmentsByProject(ctx, deltaID)
	require.NoError(t, err)
	require.NotEmpty(t, envs)

	// A 35-character name will be truncated to "..." in the table output.
	longName := "this-is-a-very-long-secret-name-xyz"
	_, err = svc.CreateSecret(ctx, &core.CreateSecretRequest{
		Name:          longName,
		Value:         []byte("v"),
		ProjectID:     deltaID,
		EnvironmentID: envs[0].ID,
		Type:          "password",
		CreatedBy:     "test",
	})
	require.NoError(t, err)

	healthFormat = "table"
	out := captureHealthStdout(t, func() {
		require.NoError(t, runHealthEmbedded(ctx, "delta"))
	})
	// The name exceeds 30 chars so it should be truncated with "...".
	assert.Contains(t, out, "...")
}

// ── Mock storage helpers for error-path coverage ───────────────────────────

// healthErrorStorage embeds a nil coreStorage.Storage and implements only the
// two methods called by the runHealthEmbedded path: ListProjects (succeeds,
// returning a project named "err-proj") and ListSecrets (fails).
type healthErrorStorage struct {
	coreStorage.Storage
	projectName string
	projectID   uint
	listErr     error
}

func (s *healthErrorStorage) ListProjects(_ context.Context) ([]*models.Project, error) {
	return []*models.Project{{ID: s.projectID, Name: s.projectName}}, nil
}

func (s *healthErrorStorage) ListSecrets(_ context.Context, _ *coreStorage.SecretFilter) ([]*models.SecretNode, int64, error) {
	return nil, 0, s.listErr
}

// TestPrintHealthJSON_MarshalError exercises lines 191-193 in printHealthJSON
// by swapping jsonMarshalFn to a failing implementation.
func TestPrintHealthJSON_MarshalError(t *testing.T) {
	savedMarshal := jsonMarshalFn
	t.Cleanup(func() { jsonMarshalFn = savedMarshal })

	injErr := errors.New("marshal failed")
	jsonMarshalFn = func(_ any) ([]byte, error) { return nil, injErr }

	err := printHealthJSON(&healthSummary{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to marshal health summary")
}

// TestRunHealthEmbedded_HealthSummaryError exercises lines 137-139 in
// runHealthEmbedded: LookupProjectIDByName succeeds (finds the project) but
// GetProjectHealthSummary fails because ListSecrets returns an error. The
// function must propagate it as "failed to compute project health: …".
func TestRunHealthEmbedded_HealthSummaryError(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(func() {
		healthLimit = 20
		healthFormat = "table"
		coreServiceInit = common.InitializeCoreService
	})

	injErr := errors.New("storage unavailable")
	coreServiceInit = func() (*core.KeyorixCore, error) {
		return core.NewKeyorixCore(&healthErrorStorage{
			projectName: "err-proj",
			projectID:   42,
			listErr:     injErr,
		}), nil
	}

	err := runHealthEmbedded(context.Background(), "err-proj")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to compute project health")
}
