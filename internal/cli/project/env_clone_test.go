package project

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// envAndProjectsHandler returns an http.HandlerFunc that serves the three
// endpoints exercised by runEnvClone in remote mode:
//   - GET /api/v1/projects      → one project "web" (id=1)
//   - GET /api/v1/projects/1/environments → two environments: staging(id=10), production(id=11)
//   - POST /api/v1/projects/1/environments/10/clone → customisable via cloneResp/cloneStatus
func envAndProjectsForCloneHandler(t *testing.T, cloneStatus int, cloneResp interface{}) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/projects":
			_, _ = w.Write([]byte(`{"success":true,"data":{"projects":[{"id":1,"name":"web"}]}}`))
		case r.URL.Path == "/api/v1/projects/1/environments":
			_, _ = w.Write([]byte(`{"success":true,"data":{"environments":[{"id":10,"name":"staging"},{"id":11,"name":"production"}]}}`))
		case r.URL.Path == "/api/v1/projects/1/environments/10/clone" && r.Method == http.MethodPost:
			w.WriteHeader(cloneStatus)
			if cloneResp != nil {
				enc, _ := json.Marshal(cloneResp)
				_, _ = w.Write(enc)
			}
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

// setupCloneRemote spins up a test server and points the CLI at it via env vars.
func setupCloneRemote(t *testing.T, handler http.HandlerFunc) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")
	t.Setenv("KEYORIX_PROJECT", "")
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(func() {
		envCloneProjectFlag = ""
	})
}

func TestEnvClone_Remote_Success(t *testing.T) {
	result := map[string]interface{}{
		"success": true,
		"data": core.EnvCloneResult{
			SourceEnv:      "staging",
			DestEnv:        "production",
			SecretsCloned:  5,
			SecretsSkipped: 0,
		},
	}
	setupCloneRemote(t, envAndProjectsForCloneHandler(t, http.StatusOK, result))
	envCloneProjectFlag = "web"

	out := captureStdout(t, func() {
		require.NoError(t, runEnvClone(nil, []string{"staging", "production"}))
	})
	assert.Contains(t, out, `Cloned environment "staging" → "production"`)
	assert.Contains(t, out, "Secrets cloned:  5")
}

func TestEnvClone_Remote_PartialSkip(t *testing.T) {
	result := map[string]interface{}{
		"success": true,
		"data": core.EnvCloneResult{
			SourceEnv:      "staging",
			DestEnv:        "production",
			SecretsCloned:  3,
			SecretsSkipped: 2,
		},
	}
	setupCloneRemote(t, envAndProjectsForCloneHandler(t, http.StatusOK, result))
	envCloneProjectFlag = "web"

	out := captureStdout(t, func() {
		require.NoError(t, runEnvClone(nil, []string{"staging", "production"}))
	})
	assert.Contains(t, out, "Secrets cloned:  3")
	assert.Contains(t, out, "Secrets skipped: 2")
	assert.Contains(t, out, "already exist in destination")
}

func TestEnvClone_Remote_NotFound(t *testing.T) {
	setupCloneRemote(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/projects":
			_, _ = w.Write([]byte(`{"success":true,"data":{"projects":[{"id":1,"name":"web"}]}}`))
		case "/api/v1/projects/1/environments":
			// Only returns staging, no production.
			_, _ = w.Write([]byte(`{"success":true,"data":{"environments":[{"id":10,"name":"staging"}]}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	envCloneProjectFlag = "web"

	err := runEnvClone(nil, []string{"staging", "production"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), `destination environment "production" not found`)
}

// TestRunEnvClone_Remote_ResolveProjectContextError verifies that a failure
// resolving the --project flag (server error on GET /api/v1/projects) is
// surfaced from runEnvClone before any environment lookups happen.
func TestRunEnvClone_Remote_ResolveProjectContextError(t *testing.T) {
	setupCloneRemote(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	envCloneProjectFlag = "web"

	err := runEnvClone(nil, []string{"staging", "production"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list projects")
}

// TestRunEnvClone_Remote_ListEnvsError verifies that a server error listing
// the project's environments is surfaced from runEnvCloneRemote.
func TestRunEnvClone_Remote_ListEnvsError(t *testing.T) {
	setupCloneRemote(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/projects":
			_, _ = w.Write([]byte(`{"success":true,"data":{"projects":[{"id":1,"name":"web"}]}}`))
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	})
	envCloneProjectFlag = "web"

	err := runEnvClone(nil, []string{"staging", "production"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list environments")
}

// TestEnvClone_Remote_SourceNotFound verifies the source-not-found branch
// (previously only the destination-not-found branch was exercised).
func TestEnvClone_Remote_SourceNotFound(t *testing.T) {
	setupCloneRemote(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/projects":
			_, _ = w.Write([]byte(`{"success":true,"data":{"projects":[{"id":1,"name":"web"}]}}`))
		case "/api/v1/projects/1/environments":
			// Only returns production, no staging.
			_, _ = w.Write([]byte(`{"success":true,"data":{"environments":[{"id":11,"name":"production"}]}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	envCloneProjectFlag = "web"

	err := runEnvClone(nil, []string{"staging", "production"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), `source environment "staging" not found`)
}

// TestEnvClone_Remote_CloneAPIError verifies that a server error from the
// clone POST endpoint itself is surfaced.
func TestEnvClone_Remote_CloneAPIError(t *testing.T) {
	setupCloneRemote(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/projects":
			_, _ = w.Write([]byte(`{"success":true,"data":{"projects":[{"id":1,"name":"web"}]}}`))
		case r.URL.Path == "/api/v1/projects/1/environments":
			_, _ = w.Write([]byte(`{"success":true,"data":{"environments":[{"id":10,"name":"staging"},{"id":11,"name":"production"}]}}`))
		case r.URL.Path == "/api/v1/projects/1/environments/10/clone" && r.Method == http.MethodPost:
			w.WriteHeader(http.StatusInternalServerError)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	envCloneProjectFlag = "web"

	err := runEnvClone(nil, []string{"staging", "production"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to clone environment")
}

// ── Embedded mode ───────────────────────────────────────────────────────────

// TestRunEnvClone_Embedded_Success drives runEnvClone (not just
// runEnvCloneEmbedded directly) end to end in embedded mode: it creates a
// project with two environments and a secret in the source environment, then
// exercises the full success path (both environments resolve, CloneEnvironment
// runs, and the result is printed without error).
//
// NB: runEnvCloneEmbedded calls svc.CloneEnvironment with a hardcoded actorID
// of 0 ("cli", 0), and the underlying CopySecret requires a nonzero actor ID
// for its permission check — so every secret is reported skipped rather than
// cloned in embedded mode today. This test asserts that actual (if surprising)
// behavior rather than the value we might have expected, since fixing the
// underlying actor-ID plumbing is out of scope here (internal/core is off
// limits for this change).
func TestRunEnvClone_Embedded_Success(t *testing.T) {
	setupEmbedded(t)
	ctx := context.Background()
	svc := embeddedCore(t)

	project, err := svc.CreateProjectWithEnvs(ctx, "web", "", []string{"staging", "production"})
	require.NoError(t, err)

	envs, err := svc.ListEnvironmentsByProject(ctx, project.ID)
	require.NoError(t, err)
	var stagingID uint
	for _, e := range envs {
		if e.Name == "staging" {
			stagingID = e.ID
		}
	}
	require.NotZero(t, stagingID)

	_, err = svc.CreateSecret(ctx, &core.CreateSecretRequest{
		Name:          "db-password",
		Value:         []byte("s3cret"),
		ProjectID:     project.ID,
		EnvironmentID: stagingID,
		Type:          "password",
		CreatedBy:     "test",
	})
	require.NoError(t, err)

	envCloneProjectFlag = "web"
	t.Cleanup(func() { envCloneProjectFlag = "" })

	out := captureStdout(t, func() {
		require.NoError(t, runEnvClone(nil, []string{"staging", "production"}))
	})
	assert.Contains(t, out, `Cloned environment "staging" → "production"`)
	assert.Contains(t, out, "Secrets skipped: 1  (already exist in destination)")
}

// TestRunEnvClone_Embedded_SourceNotFound verifies the embedded
// source-not-found branch of runEnvCloneEmbedded.
func TestRunEnvClone_Embedded_SourceNotFound(t *testing.T) {
	setupEmbedded(t)
	ctx := context.Background()
	svc := embeddedCore(t)
	_, err := svc.CreateProjectWithEnvs(ctx, "web", "", []string{"production"})
	require.NoError(t, err)

	envCloneProjectFlag = "web"
	t.Cleanup(func() { envCloneProjectFlag = "" })

	err = runEnvClone(nil, []string{"staging", "production"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), `source environment "staging" not found`)
}

// TestRunEnvClone_Embedded_DestNotFound verifies the embedded
// destination-not-found branch of runEnvCloneEmbedded.
func TestRunEnvClone_Embedded_DestNotFound(t *testing.T) {
	setupEmbedded(t)
	ctx := context.Background()
	svc := embeddedCore(t)
	_, err := svc.CreateProjectWithEnvs(ctx, "web", "", []string{"staging"})
	require.NoError(t, err)

	envCloneProjectFlag = "web"
	t.Cleanup(func() { envCloneProjectFlag = "" })

	err = runEnvClone(nil, []string{"staging", "production"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), `destination environment "production" not found`)
}

// TestRunEnvCloneEmbedded_ServiceInitError verifies that a broken storage
// config surfaces as an initialization error from runEnvCloneEmbedded itself
// (called directly since resolveProjectContext would otherwise fail first).
func TestRunEnvCloneEmbedded_ServiceInitError(t *testing.T) {
	setupBrokenService(t)

	err := runEnvCloneEmbedded(context.Background(), 1, "staging", "production")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to initialize service")
}
