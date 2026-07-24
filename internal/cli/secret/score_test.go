package secret

import (
	"bytes"
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

// scoreSetup creates a test HTTP server driven by handler and points the CLI at
// it via env vars. It returns the RemoteClient and a cleanup function.
func scoreSetup(t *testing.T, handler http.HandlerFunc) (*common.RemoteClient, func()) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	t.Setenv("KEYORIX_PROJECT", "")
	// Reset package-level flag vars so tests don't bleed into each other.
	t.Cleanup(func() {
		scoreProject = ""
		scoreEnv = 0
	})
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)
	return rc, srv.Close
}

// captureScoreOutput captures both stdout and stderr produced by fn.
func captureScoreOutput(t *testing.T, fn func()) (stdout, stderr string) {
	t.Helper()

	// Capture stdout.
	origOut := os.Stdout
	rOut, wOut, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = wOut

	// Capture stderr.
	origErr := os.Stderr
	rErr, wErr, err2 := os.Pipe()
	require.NoError(t, err2)
	os.Stderr = wErr

	defer func() {
		os.Stdout = origOut
		os.Stderr = origErr
	}()

	fn()

	require.NoError(t, wOut.Close())
	require.NoError(t, wErr.Close())

	outBytes, _ := io.ReadAll(rOut)
	errBytes, _ := io.ReadAll(rErr)

	var buf bytes.Buffer
	buf.Write(outBytes)
	stdout = buf.String()
	stderr = string(errBytes)
	return
}

// highRiskHandler serves:
//   - GET /api/v1/secrets?...  → list with one secret named "prod-db"
//   - GET /api/v1/secrets/5/risk → high-risk score
func highRiskHandler(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/api/v1/secrets":
		_, _ = w.Write([]byte(`{"success":true,"data":{"secrets":[{"ID":5,"Name":"prod-db"}],"total":1,"page":1,"page_size":500,"total_pages":1}}`))
	case "/api/v1/secrets/5/risk":
		_, _ = w.Write([]byte(`{"success":true,"data":{"secret_id":5,"secret_name":"prod-db","score":85,"band":"high","factors":[{"key":"rotation","label":"Rotation age","score":100,"weight":0.3,"detail":"Last created 400 day(s) ago (never rotated)"},{"key":"expiry","label":"Expiry","score":100,"weight":0.3,"detail":"Expired 10 day(s) ago"},{"key":"usage","label":"Usage","score":80,"weight":0.2,"detail":"No reads in the last 30 days"},{"key":"exposure","label":"Exposure","score":10,"weight":0.2,"detail":"Only the owner has access"}],"degraded":false}}`))
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func TestSecretScore_Remote_HighRisk(t *testing.T) {
	rc, done := scoreSetup(t, highRiskHandler)
	defer done()

	var runErr error
	stdout, stderr := captureScoreOutput(t, func() {
		runErr = runScoreRemote(t.Context(), rc, "prod-db")
	})
	require.NoError(t, runErr)

	// Output should show the secret name, score, and band.
	assert.Contains(t, stdout, "prod-db")
	assert.Contains(t, stdout, "85/100")
	assert.Contains(t, stdout, "HIGH")
	assert.Contains(t, stdout, "Factors:")
	assert.Contains(t, stdout, "rotation")

	// HIGH risk warning must go to stderr.
	assert.Contains(t, stderr, "HIGH risk")
	assert.Contains(t, stderr, "Consider rotating")
}

// lowRiskHandler serves a low-risk score for secret "jwt-key" (id=3).
func lowRiskHandler(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/api/v1/secrets":
		_, _ = w.Write([]byte(`{"success":true,"data":{"secrets":[{"ID":3,"Name":"jwt-key"}],"total":1,"page":1,"page_size":500,"total_pages":1}}`))
	case "/api/v1/secrets/3/risk":
		_, _ = w.Write([]byte(`{"success":true,"data":{"secret_id":3,"secret_name":"jwt-key","score":12,"band":"low","factors":[{"key":"rotation","label":"Rotation age","score":10,"weight":0.3,"detail":"Last rotated 5 day(s) ago"},{"key":"expiry","label":"Expiry","score":10,"weight":0.3,"detail":"Expires in 200 day(s)"},{"key":"usage","label":"Usage","score":10,"weight":0.2,"detail":"12 reads in the last 30 days"},{"key":"exposure","label":"Exposure","score":10,"weight":0.2,"detail":"Only the owner has access"}],"degraded":false}}`))
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func TestSecretScore_Remote_LowRisk(t *testing.T) {
	rc, done := scoreSetup(t, lowRiskHandler)
	defer done()

	var runErr error
	stdout, stderr := captureScoreOutput(t, func() {
		runErr = runScoreRemote(t.Context(), rc, "jwt-key")
	})
	require.NoError(t, runErr)

	assert.Contains(t, stdout, "jwt-key")
	assert.Contains(t, stdout, "12/100")
	assert.Contains(t, stdout, "LOW")

	// No HIGH-risk warning for a low-risk secret.
	assert.NotContains(t, stderr, "HIGH risk")
}

// notFoundHandler responds to all requests with 404.
func notFoundHandler(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/api/v1/secrets":
		// Return an empty list so name resolution fails gracefully.
		_, _ = w.Write([]byte(`{"success":true,"data":{"secrets":[],"total":0,"page":1,"page_size":500,"total_pages":1}}`))
	default:
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"success":false,"error":"NotFound","message":"not found","code":404}`))
	}
}

func TestSecretScore_Remote_NotFound(t *testing.T) {
	rc, done := scoreSetup(t, notFoundHandler)
	defer done()

	err := runScoreRemote(t.Context(), rc, "ghost-secret")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// ── Additional remote error / branch coverage ──────────────────────────────

// TestSecretScore_Remote_ListError verifies that when the secrets list endpoint
// returns a non-2xx status, runScoreRemote returns a "failed to list secrets" error.
func TestSecretScore_Remote_ListError(t *testing.T) {
	rc, done := scoreSetup(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"success":false,"error":"DBError","message":"db down","code":500}`))
	})
	defer done()

	err := runScoreRemote(t.Context(), rc, "any-secret")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list secrets")
}

// TestSecretScore_Remote_RiskEndpointError verifies that when the risk endpoint
// returns a non-2xx status, runScoreRemote returns a "failed to get risk score" error.
func TestSecretScore_Remote_RiskEndpointError(t *testing.T) {
	rc, done := scoreSetup(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/secrets":
			_, _ = w.Write([]byte(`{"success":true,"data":{"secrets":[{"ID":5,"Name":"my-secret"}],"total":1,"page":1,"page_size":500,"total_pages":1}}`))
		default:
			// Risk endpoint returns error.
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"success":false,"error":"InternalError","message":"score failed","code":500}`))
		}
	})
	defer done()

	err := runScoreRemote(t.Context(), rc, "my-secret")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get risk score")
}

// TestSecretScore_Remote_WithProjectFilter exercises the project-name resolution
// branch of resolveSecretIDByName (scoreProject != "").
func TestSecretScore_Remote_WithProjectFilter(t *testing.T) {
	rc, done := scoreSetup(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/projects":
			_, _ = w.Write([]byte(`{"success":true,"data":{"projects":[{"id":3,"name":"myproject"}]}}`))
		case "/api/v1/secrets":
			_, _ = w.Write([]byte(`{"success":true,"data":{"secrets":[{"ID":9,"Name":"proj-secret"}],"total":1,"page":1,"page_size":500,"total_pages":1}}`))
		default:
			// risk endpoint
			_, _ = w.Write([]byte(`{"success":true,"data":{"secret_id":9,"secret_name":"proj-secret","score":20,"band":"low","factors":[],"degraded":false}}`))
		}
	})
	defer done()

	scoreProject = "myproject"
	var runErr error
	stdout, _ := captureScoreOutput(t, func() {
		runErr = runScoreRemote(t.Context(), rc, "proj-secret")
	})
	require.NoError(t, runErr)
	assert.Contains(t, stdout, "proj-secret")
}

// TestSecretScore_Remote_WithProjectFilter_ProjectNotFound exercises the error
// path when the specified project does not exist in the remote list.
func TestSecretScore_Remote_WithProjectFilter_ProjectNotFound(t *testing.T) {
	rc, done := scoreSetup(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/projects":
			_, _ = w.Write([]byte(`{"success":true,"data":{"projects":[]}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	defer done()

	scoreProject = "ghost-project"
	err := runScoreRemote(t.Context(), rc, "any-secret")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// TestSecretScore_Remote_WithEnvFilter exercises the env-ID filter branch of
// resolveSecretIDByName (scoreEnv != 0).
func TestSecretScore_Remote_WithEnvFilter(t *testing.T) {
	rc, done := scoreSetup(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/secrets":
			_, _ = w.Write([]byte(`{"success":true,"data":{"secrets":[{"ID":11,"Name":"env-secret"}],"total":1,"page":1,"page_size":500,"total_pages":1}}`))
		default:
			_, _ = w.Write([]byte(`{"success":true,"data":{"secret_id":11,"secret_name":"env-secret","score":5,"band":"low","factors":[],"degraded":false}}`))
		}
	})
	defer done()

	scoreEnv = 2
	var runErr error
	stdout, _ := captureScoreOutput(t, func() {
		runErr = runScoreRemote(t.Context(), rc, "env-secret")
	})
	require.NoError(t, runErr)
	assert.Contains(t, stdout, "env-secret")
}

// TestSecretScore_Remote_DegradedScore exercises the printRiskScore degraded
// branch (score marked as degraded → warning on stderr).
func TestSecretScore_Remote_DegradedScore(t *testing.T) {
	rc, done := scoreSetup(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/secrets":
			_, _ = w.Write([]byte(`{"success":true,"data":{"secrets":[{"ID":7,"Name":"degraded-secret"}],"total":1,"page":1,"page_size":500,"total_pages":1}}`))
		default:
			// degraded=true in the risk result
			_, _ = w.Write([]byte(`{"success":true,"data":{"secret_id":7,"secret_name":"degraded-secret","score":50,"band":"medium","factors":[],"degraded":true}}`))
		}
	})
	defer done()

	var runErr error
	stdout, _ := captureScoreOutput(t, func() {
		runErr = runScoreRemote(t.Context(), rc, "degraded-secret")
	})
	require.NoError(t, runErr)
	assert.Contains(t, stdout, "exposure data incomplete")
}

// TestSecretScore_RunE_Remote exercises scoreCmd.RunE in remote mode (covers the
// cobra dispatch path for runScore).
func TestSecretScore_RunE_Remote(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(highRiskHandler))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	t.Setenv("KEYORIX_PROJECT", "")
	t.Cleanup(func() { scoreProject = ""; scoreEnv = 0 })

	_, _ = captureScoreOutput(t, func() {
		require.NoError(t, scoreCmd.RunE(scoreCmd, []string{"prod-db"}))
	})
}

// TestSecretScore_RunE_Embedded exercises scoreCmd.RunE in embedded mode
// (covers the other branch of the cobra dispatch function runScore).
func TestSecretScore_RunE_Embedded(t *testing.T) {
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
	t.Cleanup(func() { scoreProject = ""; scoreEnv = 0 })

	// Embedded mode, secret not found → error.
	err := scoreCmd.RunE(scoreCmd, []string{"no-such-secret"})
	require.Error(t, err)
}

// ── Embedded mode ──────────────────────────────────────────────────────────

// setupScoreEmbedded configures an isolated SQLite database for embedded score tests.
func setupScoreEmbedded(t *testing.T) {
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
	t.Cleanup(func() { scoreProject = ""; scoreEnv = 0 })
}

// TestSecretScore_Embedded_NotFound verifies that runScoreEmbedded returns a
// "not found" error when the named secret doesn't exist.
func TestSecretScore_Embedded_NotFound(t *testing.T) {
	setupScoreEmbedded(t)
	err := runScoreEmbedded(context.Background(), "no-such-secret")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// TestSecretScore_Embedded_WithEnvFilter exercises the scoreEnv != 0 branch in
// runScoreEmbedded.
func TestSecretScore_Embedded_WithEnvFilter(t *testing.T) {
	setupScoreEmbedded(t)
	// Set scoreEnv to a non-zero value — the secret won't be found in that env.
	scoreEnv = 99
	err := runScoreEmbedded(context.Background(), "any-secret")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// TestSecretScore_Embedded_Found verifies the happy path of runScoreEmbedded
// when a matching secret exists. It exercises the secret-found loop body,
// ComputeSecretRiskScore, factor conversion, and printRiskScore.
func TestSecretScore_Embedded_Found(t *testing.T) {
	setupScoreEmbedded(t)
	ctx := context.Background()

	svc, err := common.InitializeCoreService()
	require.NoError(t, err)

	p, err := svc.CreateProject(ctx, "score-proj", "")
	require.NoError(t, err)

	env, err := svc.CreateEnvironment(ctx, p.ID, "dev")
	require.NoError(t, err)

	_, err = svc.CreateSecret(ctx, &core.CreateSecretRequest{
		Name:          "embedded-score-secret",
		Value:         []byte("secretvalue"),
		ProjectID:     p.ID,
		EnvironmentID: env.ID,
		Type:          "password",
		CreatedBy:     "test",
	})
	require.NoError(t, err)

	stdout, _ := captureScoreOutput(t, func() {
		runErr := runScoreEmbedded(ctx, "embedded-score-secret")
		require.NoError(t, runErr)
	})
	assert.Contains(t, stdout, "embedded-score-secret")
	assert.Contains(t, stdout, "/100")
}

// TestSecretScore_Embedded_WithProject exercises the projectName != "" branch in
// runScoreEmbedded by setting scoreProject to a non-empty value.
func TestSecretScore_Embedded_WithProject(t *testing.T) {
	setupScoreEmbedded(t)
	// Set scoreProject to a non-existent project → LookupProjectIDByName returns "not found"
	scoreProject = "no-such-project"
	err := runScoreEmbedded(context.Background(), "any-secret")
	require.Error(t, err)
}

// TestSecretScore_Embedded_WithProject_Found exercises the filter.ProjectID
// assignment path (line 153) in runScoreEmbedded. It sets scoreProject to a
// project that actually exists so LookupProjectIDByName succeeds and
// filter.ProjectID is assigned — but the named secret is not in that project,
// so runScoreEmbedded returns "not found".
func TestSecretScore_Embedded_WithProject_Found(t *testing.T) {
	setupScoreEmbedded(t)
	ctx := context.Background()

	// Create the project so the lookup succeeds.
	svc, err := common.InitializeCoreService()
	require.NoError(t, err)
	_, err = svc.CreateProject(ctx, "existing-project", "")
	require.NoError(t, err)

	// Set scoreProject to the project that now exists.
	scoreProject = "existing-project"
	// The secret does not exist in that project → "not found" error, but
	// line 153 (filter.ProjectID = &projectID) will have been executed.
	err = runScoreEmbedded(ctx, "no-such-secret-in-project")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// TestSecretScore_Embedded_ServiceInitError verifies the InitializeCoreService
// error path by pointing the DB at a directory.
func TestSecretScore_Embedded_ServiceInitError(t *testing.T) {
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
	t.Cleanup(func() { scoreProject = ""; scoreEnv = 0 })

	err := runScoreEmbedded(context.Background(), "any-secret")
	require.Error(t, err, "expected error when DB cannot be opened")
}

// ── Mock storage helpers for error-path coverage ───────────────────────────

// listSecretsErrStorage embeds a nil coreStorage.Storage and overrides only
// ListSecrets so that the embedded nil never gets called.
type listSecretsErrStorage struct {
	coreStorage.Storage
	err error
}

func (s *listSecretsErrStorage) ListSecrets(_ context.Context, _ *coreStorage.SecretFilter) ([]*models.SecretNode, int64, error) {
	return nil, 0, s.err
}

// getSecretErrStorage embeds a nil coreStorage.Storage, implements ListSecrets
// to return one fake secret, and overrides GetSecret to return an error. This
// causes ComputeSecretRiskScore to fail after the secret ID has been resolved.
type getSecretErrStorage struct {
	coreStorage.Storage
	secretName string
	err        error
}

func (s *getSecretErrStorage) ListSecrets(_ context.Context, _ *coreStorage.SecretFilter) ([]*models.SecretNode, int64, error) {
	return []*models.SecretNode{{ID: 77, Name: s.secretName}}, 1, nil
}

func (s *getSecretErrStorage) GetSecret(_ context.Context, _ uint) (*models.SecretNode, error) {
	return nil, s.err
}

// TestSecretScore_Embedded_ListSecretsError exercises lines 160-162 in
// runScoreEmbedded: when svc.ListSecrets returns an error the function must
// wrap it as "failed to list secrets: …".
func TestSecretScore_Embedded_ListSecretsError(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(func() {
		scoreProject = ""
		scoreEnv = 0
		coreServiceInit = common.InitializeCoreService
	})

	injErr := errors.New("storage exploded")
	coreServiceInit = func() (*core.KeyorixCore, error) {
		return core.NewKeyorixCore(&listSecretsErrStorage{err: injErr}), nil
	}

	err := runScoreEmbedded(context.Background(), "any-secret")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list secrets")
}

// TestSecretScore_Embedded_ComputeScoreError exercises lines 176-178 in
// runScoreEmbedded: when svc.ComputeSecretRiskScore returns an error (because
// GetSecret fails after ListSecrets found the ID) the function must wrap it as
// "failed to compute risk score: …".
func TestSecretScore_Embedded_ComputeScoreError(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(func() {
		scoreProject = ""
		scoreEnv = 0
		coreServiceInit = common.InitializeCoreService
	})

	injErr := errors.New("storage exploded")
	const secretName = "target-secret"
	coreServiceInit = func() (*core.KeyorixCore, error) {
		return core.NewKeyorixCore(&getSecretErrStorage{secretName: secretName, err: injErr}), nil
	}

	err := runScoreEmbedded(context.Background(), secretName)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to compute risk score")
}
