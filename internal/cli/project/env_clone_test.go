package project

import (
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
