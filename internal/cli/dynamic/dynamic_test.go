package dynamic

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCommandWiring guards the cobra wiring: subcommands, aliases, and flags.
func TestCommandWiring(t *testing.T) {
	names := map[string]bool{}
	for _, sub := range DynamicSecretCmd.Commands() {
		names[sub.Name()] = true
	}
	for _, want := range []string{"list", "issue", "leases", "renew", "revoke", "revoke-all", "create"} {
		assert.True(t, names[want], "missing subcommand %q", want)
	}
	assert.Contains(t, DynamicSecretCmd.Aliases, "dyn")
	assert.NotNil(t, issueCmd.Flags().Lookup("ttl"))
	assert.NotNil(t, listCmd.Flags().Lookup("project-id"))
	for _, want := range []string{"name", "project-id", "backend", "creation-template", "default-ttl", "max-ttl"} {
		assert.NotNilf(t, createConfigCmd.Flags().Lookup(want), "create missing --%s flag", want)
	}
	assert.Nil(t, createConfigCmd.Flags().Lookup("admin-dsn"), "admin DSN must NOT be a flag (shell-history leak)")
}

// captureStdout runs fn with os.Stdout redirected and returns what it printed.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w
	fn()
	_ = w.Close()
	os.Stdout = old
	out, _ := io.ReadAll(r)
	return string(out)
}

// TestIssueAgainstMockServer drives `issue` against a stub API and checks it posts
// to the right path and prints the once-shown credential.
func TestIssueAgainstMockServer(t *testing.T) {
	var gotMethod, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		_, _ = w.Write([]byte(`{"data":{"lease_id":"lease-abc","username":"kx_dyn_x9","password":"s3cr3t-pw","expires_at":"2026-06-12T11:00:00Z"}}`))
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")
	flagTTL = 0

	out := captureStdout(t, func() {
		require.NoError(t, issueCmd.RunE(issueCmd, []string{"7"}))
	})

	assert.Equal(t, http.MethodPost, gotMethod)
	assert.Equal(t, "/api/v1/dynamic-secrets/configs/7/issue", gotPath)
	assert.Contains(t, out, "lease-abc")
	assert.Contains(t, out, "kx_dyn_x9")
	assert.Contains(t, out, "s3cr3t-pw")
}

// TestCreateConfigAgainstMockServer drives `create` against a stub API and checks
// it POSTs to /configs with the admin DSN sourced from the env var (never a flag).
func TestCreateConfigAgainstMockServer(t *testing.T) {
	var gotMethod, gotPath string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_, _ = w.Write([]byte(`{"data":{"id":42,"name":"app-db","backend_type":"postgres"}}`))
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")
	t.Setenv(adminDSNEnv, "postgres://admin:p@db:5432/app")
	cfgName, cfgProjectID, cfgEnvID, cfgBackend = "app-db", 1, 0, "postgres"
	cfgTemplate, cfgDefaultTTL, cfgMaxTTL = "GRANT SELECT TO {{name}};", 3600, 0

	out := captureStdout(t, func() {
		require.NoError(t, createConfigCmd.RunE(createConfigCmd, nil))
	})

	assert.Equal(t, http.MethodPost, gotMethod)
	assert.Equal(t, "/api/v1/dynamic-secrets/configs", gotPath)
	// The admin DSN is read from the env var (never a flag) and posted to the server.
	assert.Equal(t, "postgres://admin:p@db:5432/app", gotBody["admin_dsn"])
	assert.Equal(t, "app-db", gotBody["name"])
	assert.Equal(t, "postgres", gotBody["backend_type"])
	assert.Contains(t, out, "config #42")
}

// Required flags are validated before any network/credential I/O.
func TestCreateConfig_RequiresFlags(t *testing.T) {
	cfgName, cfgProjectID, cfgBackend = "", 0, ""
	err := createConfigCmd.RunE(createConfigCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "required")
}

func TestRevokeAllAgainstMockServer(t *testing.T) {
	var gotMethod, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		_, _ = w.Write([]byte(`{"data":{"config_id":7,"revoked":3,"failed":0}}`))
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")
	flagYes = true // skip the interactive confirmation
	t.Cleanup(func() { flagYes = false })

	out := captureStdout(t, func() {
		require.NoError(t, revokeAllCmd.RunE(revokeAllCmd, []string{"7"}))
	})
	assert.Equal(t, http.MethodPost, gotMethod)
	assert.Equal(t, "/api/v1/dynamic-secrets/configs/7/revoke-all", gotPath)
	assert.Contains(t, out, "revoked 3")
}

func TestIssueRejectsBadConfigID(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "http://127.0.0.1:0")
	t.Setenv("KEYORIX_TOKEN", "t")
	err := issueCmd.RunE(issueCmd, []string{"not-a-number"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid config id")
}
