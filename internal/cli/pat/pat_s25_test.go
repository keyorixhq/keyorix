// pat_s25_test.go — sprint-2.5 coverage: hygiene fetch error, exp+stale combined
// flag in table output, "never" last-used rendering, not-connected paths for
// create/list/revoke, describeScope with CIDRs combined with other fields, and
// list rendering with non-nil expires_at / last_used_at.
package pat

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHygieneCmd_FetchError verifies that a server-side error propagates out of
// hygieneCmd.RunE.
func TestHygieneCmd_FetchError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	hygieneDays = 0

	err := hygieneCmd.RunE(hygieneCmd, nil)
	require.Error(t, err)
}

// TestHygieneCmd_ExpiredAndStale verifies that a token flagged as both expired
// and stale renders the "exp,stale" label in the hygiene table and that a token
// with an empty last_used_at renders "never".
func TestHygieneCmd_ExpiredAndStale(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"tokens":[
			{"id":3,"name":"zombie","token_prefix":"kx_z","user_id":2,"last_used_at":"","expired":true,"stale":true}
		]}}`))
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	hygieneDays = 0

	out := captureStdout(t, func() {
		require.NoError(t, hygieneCmd.RunE(hygieneCmd, nil))
	})

	assert.Contains(t, out, "exp,stale", "combined flag label must appear in table")
	assert.Contains(t, out, "zombie")
	assert.Contains(t, out, "never", "empty last_used_at must render as never")
}

// TestCreateCmd_NotConnected verifies that createCmd.RunE returns an error when
// no server is configured and the name flag is valid (so validation passes).
func TestCreateCmd_NotConnected(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	flagName, flagProject, flagEnv, flagExpires, flagCIDRs, flagScopes = "ci", 0, 0, "", nil, nil

	err := createCmd.RunE(createCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

// TestListCmd_NotConnected verifies that listCmd.RunE returns an error when no
// server is configured.
func TestListCmd_NotConnected(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	err := listCmd.RunE(listCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

// TestRevokeCmd_NotConnected verifies that revokeCmd.RunE returns an error when
// a valid numeric ID is provided but no server is configured.
func TestRevokeCmd_NotConnected(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	err := revokeCmd.RunE(revokeCmd, []string{"42"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

// TestDescribeScope_CIDRsCombined verifies that a token with CIDRs together
// with an explicit scope and project renders all parts in order.
func TestDescribeScope_CIDRsCombined(t *testing.T) {
	result := describeScope(patView{
		ProjectScope: 1,
		Scopes:       []string{"secrets.read"},
		AllowedCIDRs: []string{"10.0.0.0/8"},
	})
	assert.Equal(t, "project=1 secrets.read from=10.0.0.0/8", result)
}

// TestListCmd_WithOptionalFields verifies that the list table renders non-nil
// expires_at and last_used_at values as compact dates (not "never").
func TestListCmd_WithOptionalFields(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":[{
			"id":1,"name":"full","token_prefix":"kx_full","revoked":false,
			"created_at":"2026-01-01T00:00:00Z",
			"expires_at":"2027-01-01T00:00:00Z",
			"last_used_at":"2026-06-15T12:00:00Z",
			"scopes":[],"project_scope":0,"environment_scope":0,"allowed_cidrs":null
		}]}`))
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	out := captureStdout(t, func() {
		require.NoError(t, listCmd.RunE(listCmd, nil))
	})

	assert.Contains(t, out, "2027-01-01", "expires_at rendered as compact date")
	assert.Contains(t, out, "2026-06-15", "last_used_at rendered as compact date")
	assert.Contains(t, out, "full access")
}
