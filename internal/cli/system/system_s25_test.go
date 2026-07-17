// system_s25_test.go — coverage sprint 25 for internal/cli/system.
// Targets:
//   - runValidate: warning-specific recommendation branches (lines 73-84):
//     "File permission checks are disabled" and "Encryption is disabled"
//   - runRemoteInit: d.User == nil username-fallback branch
//   - runRemoteInit: bootstrap token read from KEYORIX_BOOTSTRAP_TOKEN env var
//   - runRemoteInit: HTTP error response using "error" field (not "message")
//   - runRemoteInit: 200 OK with non-JSON body (json.Unmarshal failure)
//   - fetchSystemInfo / infoCmd display: empty features map (len == 0, block skipped)
package system

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── runValidate: warning recommendation branches ──────────────────────────────

// writeValidatableConfig writes a minimal keyorix.yaml to dir that satisfies
// startup.ValidateStartup with no encryption and no file-permission checking,
// producing two warnings ("File permission checks are disabled" and
// "Encryption is disabled") plus a database warning for the missing DB file.
// dbPath must be an absolute path to an existing file (or we accept the
// "Database file does not exist" warning path).
func writeValidatableConfig(t *testing.T, dir string, dbPath string) string {
	t.Helper()
	yaml := "storage:\n" +
		"  type: local\n" +
		"  database:\n" +
		"    path: " + dbPath + "\n" +
		"security:\n" +
		"  enable_file_permission_check: false\n"
	cfgPath := filepath.Join(dir, "validate-test.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(yaml), 0o600))
	return cfgPath
}

// TestRunValidate_WarningRecommendations exercises the for-loop inside
// runValidate that prints specific recommendation lines for known warning
// strings (lines 73-84 in validate.go): "File permission checks are disabled"
// and "Encryption is disabled". Both appear when security.enable_file_permission_check
// is false and storage.encryption.enabled is false (the default).
func TestRunValidate_WarningRecommendations(t *testing.T) {
	dir := t.TempDir()
	// Use a non-existent absolute path so validateDatabase adds its own warning
	// (database file does not exist) rather than returning an error.
	dbPath := filepath.Join(dir, "secrets.db")
	cfgPath := writeValidatableConfig(t, dir, dbPath)

	orig, origFix := configFile, fixIssues
	defer func() { configFile = orig; fixIssues = origFix }()
	configFile = cfgPath
	fixIssues = false

	out := captureStdout(t, func() {
		err := runValidate(validateCmd, nil)
		// The validation path succeeds (warnings are not errors here).
		require.NoError(t, err)
	})

	// Both warning-driven recommendations must be printed.
	assert.Contains(t, out, "Consider enabling file permission checks")
	assert.Contains(t, out, "Consider enabling encryption")
	// The trailing generic recommendations must also appear.
	assert.Contains(t, out, "keyorix system init --force")
}

// TestRunValidate_WarningRecommendationsWithExistingDB is the same as above
// but creates the DB file so validateDatabase opens it successfully (exercises
// the Open path rather than the "will be created" warning path).
func TestRunValidate_WarningRecommendationsWithExistingDB(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "secrets.db")
	require.NoError(t, os.WriteFile(dbPath, []byte{}, 0o600))
	cfgPath := writeValidatableConfig(t, dir, dbPath)

	orig, origFix := configFile, fixIssues
	defer func() { configFile = orig; fixIssues = origFix }()
	configFile = cfgPath
	fixIssues = false

	out := captureStdout(t, func() {
		err := runValidate(validateCmd, nil)
		require.NoError(t, err)
	})

	assert.Contains(t, out, "Consider enabling file permission checks")
	assert.Contains(t, out, "Consider enabling encryption")
}

// ── runRemoteInit: d.User == nil username-fallback ────────────────────────────

// TestRunRemoteInit_NilUserFallback verifies that when the server response
// omits the "user" object (d.User == nil), runRemoteInit falls back to using
// initAdminUsername as the displayed username rather than panicking or printing
// an empty string.
func TestRunRemoteInit_NilUserFallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// "user" is absent — d.User will be nil after Unmarshal.
		_, _ = w.Write([]byte(`{"success":true,"data":{` +
			`"already_initialized":false,` +
			`"project":"myproject",` +
			`"environments":["production"]` +
			`}}`))
	}))
	defer srv.Close()

	orig, origUser, origPW := initServer, initAdminUsername, initAdminPassword
	defer func() {
		initServer = orig
		initAdminUsername = origUser
		initAdminPassword = origPW
	}()
	initServer = srv.URL
	initAdminUsername = "bootstrap-admin"
	initAdminPassword = "not-admin" // avoid default-password warning

	out := captureStdout(t, func() {
		require.NoError(t, runRemoteInit())
	})

	assert.Contains(t, out, "bootstrap-admin")
	assert.Contains(t, out, "Keyorix initialised successfully")
}

// ── runRemoteInit: bootstrap token from env var ───────────────────────────────

// TestRunRemoteInit_BootstrapTokenFromEnv verifies that when initBootstrapToken
// is empty, the KEYORIX_BOOTSTRAP_TOKEN environment variable is read and the
// call proceeds (exercises the os.Getenv branch at line 231 in init.go).
func TestRunRemoteInit_BootstrapTokenFromEnv(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Already initialized — gives a clean early return without requiring a
		// fully-formed workspace in the response.
		_, _ = w.Write([]byte(`{"success":true,"data":{"already_initialized":true}}`))
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_BOOTSTRAP_TOKEN", "env-token-xyz")

	orig, origTok := initServer, initBootstrapToken
	defer func() {
		initServer = orig
		initBootstrapToken = origTok
	}()
	initServer = srv.URL
	initBootstrapToken = "" // force the env-var branch

	require.NoError(t, runRemoteInit())
}

// ── runRemoteInit: HTTP error with "error" field ──────────────────────────────

// TestRunRemoteInit_ServerHTTPErrorField exercises the branch where the error
// JSON body uses the "error" key instead of "message" (line 260 in init.go).
func TestRunRemoteInit_ServerHTTPErrorField(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"success":false,"error":"bootstrap token invalid"}`))
	}))
	defer srv.Close()

	orig := initServer
	defer func() { initServer = orig }()
	initServer = srv.URL

	err := runRemoteInit()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "initialisation failed")
	assert.Contains(t, err.Error(), "bootstrap token invalid")
}

// ── runRemoteInit: 200 OK with non-JSON body ──────────────────────────────────

// TestRunRemoteInit_BadJSONResponse exercises the json.Unmarshal error path at
// line 268 in init.go: server responds 200 with a body that is not valid JSON.
func TestRunRemoteInit_BadJSONResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`not json at all`))
	}))
	defer srv.Close()

	orig := initServer
	defer func() { initServer = orig }()
	initServer = srv.URL

	err := runRemoteInit()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected response from server")
}

// ── fetchSystemInfo / infoCmd: empty features map ────────────────────────────

// TestFetchSystemInfo_EmptyFeatures verifies that when the server response has
// no features (empty or absent map), fetchSystemInfo parses successfully and
// the features field is nil/empty — confirming the len(info.Features) == 0
// guard in infoCmd's RunE is exercised (features block is skipped).
func TestFetchSystemInfo_EmptyFeatures(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/system/info" {
			_, _ = w.Write([]byte(`{"data":{"version":"v1.0.0","git_commit":"deadbeef","go_version":"go1.26","os":"linux","arch":"amd64","uptime":"1h","environment":"test","features":{},"database":{"type":"sqlite","connected":true},"security":{"tls_enabled":false,"auth_enabled":true,"encryption_method":"AES-256-GCM","audit_enabled":false}}}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	rc, ok := common.NewRemoteClient()
	require.True(t, ok)

	info, err := fetchSystemInfo(context.Background(), rc)
	require.NoError(t, err)
	assert.Equal(t, "v1.0.0", info.Version)
	assert.Empty(t, info.Features, "empty features map should be parsed as empty, not nil")
}

// TestInfoCmd_SuccessNoFeatures exercises infoCmd.RunE with a response that
// has an empty features map, confirming the len(info.Features) > 0 block is
// skipped and no panic occurs.
func TestInfoCmd_SuccessNoFeatures(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/system/info" {
			_, _ = w.Write([]byte(`{"data":{"version":"v1.0.0","git_commit":"deadbeef","go_version":"go1.26","os":"linux","arch":"amd64","uptime":"1h","environment":"staging","features":{},"database":{"type":"sqlite","connected":false},"security":{"tls_enabled":false,"auth_enabled":false,"encryption_method":"none","audit_enabled":false}}}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	out := captureStdout(t, func() {
		err := infoCmd.RunE(infoCmd, nil)
		require.NoError(t, err)
	})

	assert.Contains(t, out, "v1.0.0")
	assert.NotContains(t, out, "Features:", "features block must be absent when map is empty")
}
