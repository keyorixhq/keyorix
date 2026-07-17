package dynamic

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// client() error propagation inside each command's RunE
// The `if err != nil { return err }` branch after client() inside each RunE
// is only reachable when no server is configured. These tests cover that path
// for every command that hasn't had it explicitly exercised yet.
// ---------------------------------------------------------------------------

// TestList_S23_NoServer verifies that listCmd propagates a client() error.
func TestList_S23_NoServer(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	flagProjectID, flagEnvID = 0, 0

	err := listCmd.RunE(listCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected to a server")
}

// TestLeases_S23_NoServer verifies that leasesCmd propagates a client() error.
func TestLeases_S23_NoServer(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	err := leasesCmd.RunE(leasesCmd, []string{"1"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected to a server")
}

// TestRenew_S23_NoServer verifies that renewCmd propagates a client() error.
func TestRenew_S23_NoServer(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	flagTTL = 0

	err := renewCmd.RunE(renewCmd, []string{"some-lease-id"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected to a server")
}

// TestRevoke_S23_NoServer verifies that revokeCmd propagates a client() error.
func TestRevoke_S23_NoServer(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	err := revokeCmd.RunE(revokeCmd, []string{"some-lease-id"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected to a server")
}

// TestRevokeAll_S23_NoServerAfterConfirm verifies that revokeAllCmd propagates
// a client() error even when the --yes flag is set (i.e. after the ID parse
// succeeds and the prompt is skipped).
func TestRevokeAll_S23_NoServerAfterConfirm(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	flagYes = true
	t.Cleanup(func() { flagYes = false })

	err := revokeAllCmd.RunE(revokeAllCmd, []string{"3"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected to a server")
}

// TestGetConfig_S23_NoServer verifies that getConfigCmd propagates a client() error.
func TestGetConfig_S23_NoServer(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	err := getConfigCmd.RunE(getConfigCmd, []string{"1"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected to a server")
}

// TestClassify_S23_NoServer verifies that classifyCmd propagates a client() error.
func TestClassify_S23_NoServer(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	flagLevel = "restricted"
	t.Cleanup(func() { flagLevel = "" })

	err := classifyCmd.RunE(classifyCmd, []string{"1"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected to a server")
}

// TestCreateConfig_S23_NoServerValidDSN verifies that createConfigCmd propagates
// a client() error when the admin DSN is present in the environment but no server
// is configured. This covers the `client()` failure branch inside createConfigCmd
// that can only be reached after readAdminDSN() succeeds.
func TestCreateConfig_S23_NoServerValidDSN(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	t.Setenv(adminDSNEnv, "postgres://admin:pw@db/app")
	cfgName, cfgProjectID, cfgBackend = "mydb", 1, "postgres"

	err := createConfigCmd.RunE(createConfigCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected to a server")
}

// ---------------------------------------------------------------------------
// issueCmd — partial credential fields (username without password, vice versa)
// ---------------------------------------------------------------------------

// TestIssue_S23_UsernameOnlyNoPassword verifies that when the response carries a
// username but an empty password, only the username line is printed.
func TestIssue_S23_UsernameOnlyNoPassword(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"lease_id":"l-pg","username":"kx_dyn_u1","password":"","expires_at":"2026-09-01T00:00:00Z"}}`))
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	flagTTL = 0

	out := captureStdout(t, func() {
		require.NoError(t, issueCmd.RunE(issueCmd, []string{"1"}))
	})
	assert.Contains(t, out, "username:")
	assert.Contains(t, out, "kx_dyn_u1")
	assert.NotContains(t, out, "password:")
}

// TestIssue_S23_PasswordOnlyNoUsername verifies that when the response carries a
// password but an empty username, only the password line is printed.
func TestIssue_S23_PasswordOnlyNoUsername(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"lease_id":"l-redis","username":"","password":"s3cr3t","expires_at":"2026-09-01T00:00:00Z"}}`))
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	flagTTL = 0

	out := captureStdout(t, func() {
		require.NoError(t, issueCmd.RunE(issueCmd, []string{"2"}))
	})
	assert.NotContains(t, out, "username:")
	assert.Contains(t, out, "password:")
	assert.Contains(t, out, "s3cr3t")
}

// ---------------------------------------------------------------------------
// issueCmd — no-server path
// ---------------------------------------------------------------------------

// TestIssue_S23_NoServer verifies that issueCmd propagates a client() error.
func TestIssue_S23_NoServer(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	flagTTL = 0

	err := issueCmd.RunE(issueCmd, []string{"1"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected to a server")
}

// ---------------------------------------------------------------------------
// renewCmd — output format (lease ID and new expiry appear in printed line)
// ---------------------------------------------------------------------------

// TestRenew_S23_OutputFormat verifies that the renewal success line contains both
// the lease ID and the new expiry from the server response.
func TestRenew_S23_OutputFormat(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"lease_id":"lease-99","expires_at":"2026-12-31T23:59:59Z"}}`))
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	flagTTL = 0

	out := captureStdout(t, func() {
		require.NoError(t, renewCmd.RunE(renewCmd, []string{"lease-99"}))
	})
	assert.Contains(t, out, "lease-99")
	assert.Contains(t, out, "renewed")
	assert.Contains(t, out, "2026-12-31T23:59:59Z")
}

// ---------------------------------------------------------------------------
// revokeAllCmd — non-"yes" answer at interactive prompt aborts without API call
// ---------------------------------------------------------------------------

// TestRevokeAll_S23_EmptyAnswerAborts verifies that an empty input at the
// confirmation prompt is treated as a rejection (neither "yes" nor any other
// non-empty word) and no API call is made.
func TestRevokeAll_S23_EmptyAnswerAborts(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	flagYes = false
	t.Cleanup(func() { flagYes = false })

	cmd := &cobra.Command{}
	cmd.SetIn(strings.NewReader("\n")) // empty line — EOF on the scanner
	out := captureStdout(t, func() {
		require.NoError(t, revokeAllCmd.RunE(cmd, []string{"10"}))
	})
	assert.Equal(t, 0, calls, "empty answer must not invoke the server")
	assert.Contains(t, out, "Aborted")
}

// TestRevokeAll_S23_ArbitraryWordAborts verifies that an arbitrary non-"yes"
// word aborts and does not call the API.
func TestRevokeAll_S23_ArbitraryWordAborts(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	flagYes = false
	t.Cleanup(func() { flagYes = false })

	cmd := &cobra.Command{}
	cmd.SetIn(strings.NewReader("maybe\n"))
	out := captureStdout(t, func() {
		require.NoError(t, revokeAllCmd.RunE(cmd, []string{"10"}))
	})
	assert.Equal(t, 0, calls, "non-yes answer must not invoke the server")
	assert.Contains(t, out, "Aborted")
}

// ---------------------------------------------------------------------------
// revokeAllCmd — confirmation prompt mentions the config ID
// ---------------------------------------------------------------------------

// TestRevokeAll_S23_PromptMentionsConfigID verifies that the interactive
// confirmation prompt shows the config ID so the operator knows what they are
// about to revoke.
func TestRevokeAll_S23_PromptMentionsConfigID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"config_id":42,"revoked":0,"failed":0}}`))
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	flagYes = false
	t.Cleanup(func() { flagYes = false })

	cmd := &cobra.Command{}
	cmd.SetIn(strings.NewReader("yes\n"))

	// Capture stdout to inspect the prompt text.
	out := captureStdout(t, func() {
		require.NoError(t, revokeAllCmd.RunE(cmd, []string{"42"}))
	})
	assert.Contains(t, out, "42")
}

// ---------------------------------------------------------------------------
// sortedKeys — single-entry map (boundary case)
// ---------------------------------------------------------------------------

// TestSortedKeys_S23_SingleEntry verifies that sortedKeys handles a one-element
// map correctly (no sort needed, but the function must still return the key).
func TestSortedKeys_S23_SingleEntry(t *testing.T) {
	result := sortedKeys(map[string]string{"alpha": "val"})
	require.Len(t, result, 1)
	assert.Equal(t, "alpha", result[0])
}

// ---------------------------------------------------------------------------
// listCmd — both project and env filters produce correct query-string ordering
// (sep transition: first filter uses "?", second uses "&")
// ---------------------------------------------------------------------------

// TestList_S23_BothFiltersQueryString verifies that when both flagProjectID and
// flagEnvID are set the resulting URL uses "?" before the first parameter and
// "&" before the second, in the correct order.
func TestList_S23_BothFiltersQueryString(t *testing.T) {
	var gotRawQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotRawQuery = r.URL.RawQuery
		_, _ = w.Write([]byte(`{"data":[]}`))
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	flagProjectID, flagEnvID = 11, 22

	require.NoError(t, listCmd.RunE(listCmd, nil))
	// project_id must come first, environment_id second, joined by "&".
	assert.Equal(t, "project_id=11&environment_id=22", gotRawQuery)
}

// ---------------------------------------------------------------------------
// createConfigCmd — success output format (both printed lines)
// ---------------------------------------------------------------------------

// TestCreateConfig_S23_SuccessOutputLines verifies that on a successful create
// the output contains the created config's ID, name, backend type, and the
// follow-up hint telling the user how to issue a credential.
func TestCreateConfig_S23_SuccessOutputLines(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"id":77,"name":"redis-cache","backend_type":"redis"}}`))
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	t.Setenv(adminDSNEnv, "redis://admin:pw@cache:6379/0")
	cfgName, cfgProjectID, cfgBackend = "redis-cache", 5, "redis"
	cfgEnvID, cfgTemplate, cfgDefaultTTL, cfgMaxTTL, cfgMaxActiveLease = 0, "", 0, 0, 0

	out := captureStdout(t, func() {
		require.NoError(t, createConfigCmd.RunE(createConfigCmd, nil))
	})
	assert.Contains(t, out, "#77")
	assert.Contains(t, out, "redis-cache")
	assert.Contains(t, out, "redis")
	assert.Contains(t, out, "77") // in the follow-up issue hint
	assert.Contains(t, out, "issue")
}

// ---------------------------------------------------------------------------
// readAdminDSN — valid env var returns exact trimmed value
// (supplement: multiple leading/trailing chars)
// ---------------------------------------------------------------------------

// TestReadAdminDSN_S23_ValidEnvReturned verifies that a clean value from the
// environment variable is returned unchanged (no trimming artifacts).
func TestReadAdminDSN_S23_ValidEnvReturned(t *testing.T) {
	t.Setenv(adminDSNEnv, "mongodb://root:secret@mongo:27017/admin")
	dsn, err := readAdminDSN()
	require.NoError(t, err)
	assert.Equal(t, "mongodb://root:secret@mongo:27017/admin", dsn)
}

// TestReadAdminDSN_S23_TabsAndNewlinesTrimmed verifies that tabs and newlines
// surrounding the DSN value are stripped by the TrimSpace call.
func TestReadAdminDSN_S23_TabsAndNewlinesTrimmed(t *testing.T) {
	t.Setenv(adminDSNEnv, "\t\n  mysql://root:pw@db/app \n\t")
	dsn, err := readAdminDSN()
	require.NoError(t, err)
	assert.Equal(t, "mysql://root:pw@db/app", dsn)
}
