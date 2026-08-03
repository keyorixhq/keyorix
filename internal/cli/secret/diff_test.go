// diff_test.go — remote httptest tests for the secret diff CLI command.
package secret

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── TestRunDiff_InvalidFromVersion ───────────────────────────────────────────

// TestRunDiff_InvalidFromVersion exercises the "from-version must be a positive
// integer" branch (args[1] is not a valid positive integer).
func TestRunDiff_InvalidFromVersion(t *testing.T) {
	err := runDiff(nil, []string{"my-secret", "notanumber", "2"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "from-version must be a positive integer")
}

// TestRunDiff_ZeroFromVersion exercises the <= 0 branch for from-version.
func TestRunDiff_ZeroFromVersion(t *testing.T) {
	err := runDiff(nil, []string{"my-secret", "0", "2"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "from-version must be a positive integer")
}

// ── TestRunDiff_InvalidToVersion ─────────────────────────────────────────────

// TestRunDiff_InvalidToVersion exercises the "to-version must be a positive
// integer" branch (args[2] is not a valid positive integer).
func TestRunDiff_InvalidToVersion(t *testing.T) {
	err := runDiff(nil, []string{"my-secret", "1", "notanumber"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "to-version must be a positive integer")
}

// TestRunDiff_ZeroToVersion exercises the <= 0 branch for to-version.
func TestRunDiff_ZeroToVersion(t *testing.T) {
	err := runDiff(nil, []string{"my-secret", "1", "0"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "to-version must be a positive integer")
}

// ── TestRunDiff_EmbeddedMode_NoID ────────────────────────────────────────────

// TestRunDiff_EmbeddedMode_NoID exercises the embedded-mode branch where
// --id is not set: NewRemoteClient returns ok=false and diffID==0.
func TestRunDiff_EmbeddedMode_NoID(t *testing.T) {
	// Ensure no remote client env vars are set.
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	// Ensure diffID is reset to zero (package-level var).
	prev := diffID
	diffID = 0
	defer func() { diffID = prev }()

	err := runDiff(nil, []string{"my-secret", "1", "2"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--id is required in embedded mode")
}

// ── TestRunDiff_RemoteMode ────────────────────────────────────────────────────

// TestRunDiff_RemoteMode exercises the remote-mode branch of runDiff: when
// KEYORIX_SERVER and KEYORIX_TOKEN are set, runDiff calls runDiffRemote.
func TestRunDiff_RemoteMode(t *testing.T) {
	const (
		sid  = uint(10)
		from = 1
		to   = 2
	)
	body := `{"data":{` +
		`"secret_id":10,` +
		`"secret_name":"my-secret",` +
		`"from_version":1,` +
		`"to_version":2,` +
		`"changes":[],` +
		`"acl_user_ids":null}}`

	_, done := diffStub(t, sid, from, to, body, http.StatusOK)
	defer done()

	// With env vars set, runDiff should delegate to runDiffRemote.
	err := runDiff(nil, []string{"my-secret", "1", "2"})
	assert.NoError(t, err)
}

// diffStub starts an httptest server that handles the by-name lookup and the
// diff endpoint. Returns a configured RemoteClient and a teardown function.
func diffStub(t *testing.T, secretID uint, fromV, toV int, diffBody string, diffStatus int) (*common.RemoteClient, func()) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		// by-name resolution
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/secrets/by-name":
			_, _ = w.Write([]byte(`{"data":{"id":` + jsonUint(secretID) + `,"name":"my-api-key"}}`))

		// diff endpoint
		case r.Method == http.MethodGet &&
			r.URL.Path == diffEndpointPath(secretID, fromV, toV):
			w.WriteHeader(diffStatus)
			if diffBody != "" {
				_, _ = w.Write([]byte(diffBody))
			}

		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"not found"}`))
		}
	}))
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-tok")
	rc, ok := common.NewRemoteClient()
	require.True(t, ok, "NewRemoteClient must succeed with env vars set")
	return rc, srv.Close
}

func diffEndpointPath(id uint, from, to int) string {
	return "/api/v1/secrets/" + jsonUint(id) + "/versions/" + jsonInt(from) + "/diff/" + jsonInt(to)
}

func jsonUint(v uint) string { b, _ := json.Marshal(v); return string(b) }
func jsonInt(v int) string   { b, _ := json.Marshal(v); return string(b) }

// ── TestSecretDiff_Remote_Changes ─────────────────────────────────────────────

func TestSecretDiff_Remote_Changes(t *testing.T) {
	const (
		sid  = uint(42)
		from = 1
		to   = 3
	)
	body := `{"data":{` +
		`"secret_id":42,` +
		`"secret_name":"my-api-key",` +
		`"from_version":1,` +
		`"to_version":3,` +
		`"changes":[{"field":"classification","old_value":"(unknown)","new_value":"confidential"},` +
		`{"field":"read_count_delta","old_value":"3","new_value":"47 (+44)"}],` +
		`"acl_user_ids":[7,8]}}`

	rc, done := diffStub(t, sid, from, to, body, http.StatusOK)
	defer done()

	err := runDiffRemote(rc, "my-api-key", from, to)
	assert.NoError(t, err)
}

// ── TestSecretDiff_Remote_NoChanges ──────────────────────────────────────────

func TestSecretDiff_Remote_NoChanges(t *testing.T) {
	const (
		sid  = uint(7)
		from = 2
		to   = 3
	)
	body := `{"data":{` +
		`"secret_id":7,` +
		`"secret_name":"db-pass",` +
		`"from_version":2,` +
		`"to_version":3,` +
		`"changes":[],` +
		`"acl_user_ids":null}}`

	rc, done := diffStub(t, sid, from, to, body, http.StatusOK)
	defer done()

	err := runDiffRemote(rc, "db-pass", from, to)
	assert.NoError(t, err)
}

// ── TestSecretDiff_Remote_InvalidVersion ─────────────────────────────────────

func TestSecretDiff_Remote_InvalidVersion(t *testing.T) {
	const (
		sid  = uint(5)
		from = 1
		to   = 99 // doesn't exist on the server
	)
	errBody := `{"error":"NotFound","message":"version not found","code":404}`

	rc, done := diffStub(t, sid, from, to, errBody, http.StatusNotFound)
	defer done()

	err := runDiffRemote(rc, "my-api-key", from, to)
	require.Error(t, err, "a 404 from the diff endpoint must surface as an error")
}

// ── TestSecretDiff_Remote_ByNameFails ────────────────────────────────────────

// TestSecretDiff_Remote_ByNameFails exercises the error branch when the
// by-name resolution endpoint returns 404 — runDiffRemote should surface the error.
func TestSecretDiff_Remote_ByNameFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"not found"}`))
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-tok")
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)

	err := runDiffRemote(rc, "no-such-secret", 1, 2)
	require.Error(t, err)
}

// ── TestBuildByNamePath ───────────────────────────────────────────────────────

// TestBuildByNamePath covers all three branches of buildByNamePath:
// name-only, name+project, and name+project+env.
func TestBuildByNamePath(t *testing.T) {
	t.Run("name_only", func(t *testing.T) {
		p := buildByNamePath("my-key", "", "")
		assert.Equal(t, "/api/v1/secrets/by-name?name=my-key", p)
	})
	t.Run("name_and_project", func(t *testing.T) {
		p := buildByNamePath("my-key", "prod", "")
		assert.Equal(t, "/api/v1/secrets/by-name?name=my-key&project=prod", p)
	})
	t.Run("name_project_and_env", func(t *testing.T) {
		p := buildByNamePath("my-key", "prod", "staging")
		assert.Equal(t, "/api/v1/secrets/by-name?name=my-key&project=prod&environment=staging", p)
	})
}

// ── TestRunDiff_EmbeddedMode_Success ─────────────────────────────────────────

// TestRunDiff_EmbeddedMode_Success exercises the embedded-mode success path:
// --id is set, InitializeStorage succeeds (via a minimal keyorix.yaml), and
// DiffSecretVersions returns successfully for two existing versions.
func TestRunDiff_EmbeddedMode_Success(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	cfgStr := "storage:\n  type: local\n  database:\n    path: ./secrets.db\n"
	if err := os.WriteFile("keyorix.yaml", []byte(cfgStr), 0o600); err != nil {
		t.Skip("could not write keyorix.yaml:", err)
	}

	svc, err := common.InitializeCoreService()
	if err != nil {
		t.Skip("embedded storage unavailable:", err)
	}

	ctx := context.Background()
	proj, err := svc.CreateProject(ctx, "diff-embedded-proj", "")
	if err != nil {
		t.Skip("CreateProject failed:", err)
	}
	envs, err := svc.ListEnvironmentsByProject(ctx, proj.ID)
	if err != nil || len(envs) == 0 {
		t.Skip("no envs available:", err)
	}

	secret, err := svc.CreateSecret(ctx, &core.CreateSecretRequest{
		Name:          "diff-embedded-secret",
		Value:         []byte("initial-value"),
		Type:          "generic",
		ProjectID:     proj.ID,
		EnvironmentID: envs[0].ID,
		CreatedBy:     "cli-test-diff",
	})
	if err != nil {
		t.Skip("CreateSecret failed:", err)
	}

	// Create a second version by updating the secret.
	if _, err := svc.UpdateSecret(ctx, &core.UpdateSecretRequest{
		ID:        secret.ID,
		Value:     []byte("updated-value"),
		UpdatedBy: "cli-test-diff",
	}); err != nil {
		t.Skip("UpdateSecret failed:", err)
	}

	prev := diffID
	diffID = secret.ID
	defer func() { diffID = prev }()

	// runDiff in embedded mode (no env vars set).
	err = runDiff(nil, []string{"ignored-in-embedded", "1", "2"})
	require.NoError(t, err)
}

// ── TestRunDiff_EmbeddedMode_StorageError ────────────────────────────────────

// TestRunDiff_EmbeddedMode_StorageError exercises the InitializeStorage error
// branch in runDiff embedded mode: no keyorix.yaml, so config.Load fails.
func TestRunDiff_EmbeddedMode_StorageError(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	// No keyorix.yaml written → InitializeStorage will fail to load config.

	prev := diffID
	diffID = 99 // non-zero so we pass the diffID==0 guard
	defer func() { diffID = prev }()

	err := runDiff(nil, []string{"my-secret", "1", "2"})
	require.Error(t, err)
}

// ── TestRunDiff_EmbeddedMode_DiffError ───────────────────────────────────────

// TestRunDiff_EmbeddedMode_DiffError exercises the DiffSecretVersions error
// branch in runDiff embedded mode: storage initializes successfully but the
// requested version doesn't exist → DiffSecretVersions returns an error.
func TestRunDiff_EmbeddedMode_DiffError(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	cfgStr := "storage:\n  type: local\n  database:\n    path: ./secrets.db\n"
	if err := os.WriteFile("keyorix.yaml", []byte(cfgStr), 0o600); err != nil {
		t.Skip("could not write keyorix.yaml:", err)
	}

	svc, err := common.InitializeCoreService()
	if err != nil {
		t.Skip("embedded storage unavailable:", err)
	}

	ctx := context.Background()
	proj, err := svc.CreateProject(ctx, "diff-err-proj", "")
	if err != nil {
		t.Skip("CreateProject failed:", err)
	}
	envs, err := svc.ListEnvironmentsByProject(ctx, proj.ID)
	if err != nil || len(envs) == 0 {
		t.Skip("no envs available:", err)
	}

	secret, err := svc.CreateSecret(ctx, &core.CreateSecretRequest{
		Name:          "diff-err-secret",
		Value:         []byte("v1-value"),
		Type:          "generic",
		ProjectID:     proj.ID,
		EnvironmentID: envs[0].ID,
		CreatedBy:     "cli-test-diff-err",
	})
	if err != nil {
		t.Skip("CreateSecret failed:", err)
	}

	// Set diffID to an existing secret but request version 99 which doesn't exist.
	prev := diffID
	diffID = secret.ID
	defer func() { diffID = prev }()

	// Version 99 doesn't exist → DiffSecretVersions returns an error.
	err = runDiff(nil, []string{"ignored", "1", "99"})
	require.Error(t, err)
}
