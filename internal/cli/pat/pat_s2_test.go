// pat_s2_test.go — sprint-2 coverage for hygieneCmd.RunE (table and empty
// branches), normalizeExpiry RFC3339 invalid path, describeScope CIDRs-only,
// and client() error path.
package pat

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHygieneCmd_Empty verifies the "No stale or expired tokens" branch of
// hygieneCmd.RunE via a server that returns an empty list.
func TestHygieneCmd_Empty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/pat-hygiene", r.URL.Path)
		_, _ = w.Write([]byte(`{"data":{"tokens":[]}}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	hygieneDays = 0

	out := captureStdout(t, func() {
		require.NoError(t, hygieneCmd.RunE(hygieneCmd, nil))
	})
	assert.Contains(t, out, "No stale or expired tokens")
}

// TestHygieneCmd_WithResults verifies the table-rendering branch of
// hygieneCmd.RunE via a server that returns both a stale and an expired token.
func TestHygieneCmd_WithResults(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"tokens":[
			{"id":1,"name":"ci","token_prefix":"kx_ci","user_id":5,"last_used_at":"","expired":false,"stale":true},
			{"id":2,"name":"old","token_prefix":"kx_old","user_id":9,"last_used_at":"2026-01-01T00:00:00Z","expired":true,"stale":false}
		]}}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	hygieneDays = 0

	out := captureStdout(t, func() {
		require.NoError(t, hygieneCmd.RunE(hygieneCmd, nil))
	})
	assert.Contains(t, out, "ci")
	assert.Contains(t, out, "kx_ci")
	assert.Contains(t, out, "stale")
	assert.Contains(t, out, "old")
	assert.Contains(t, out, "expired")
}

// TestHygieneCmd_WithDays verifies that hygieneDays > 0 appends the query param.
func TestHygieneCmd_WithDays(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.RequestURI()
		_, _ = w.Write([]byte(`{"data":{"tokens":[]}}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	hygieneDays = 60
	t.Cleanup(func() { hygieneDays = 0 })

	out := captureStdout(t, func() {
		require.NoError(t, hygieneCmd.RunE(hygieneCmd, nil))
	})
	assert.Contains(t, gotPath, "days=60")
	assert.Contains(t, out, "No stale")
}

// TestHygieneCmd_NotConnected verifies that hygieneCmd returns an error when
// no server is configured (the client() helper path).
func TestHygieneCmd_NotConnected(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	err := hygieneCmd.RunE(hygieneCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

// TestNormalizeExpiry_InvalidRFC3339 verifies the "invalid --expires" error
// path when the value contains "T" but is not a valid RFC3339 timestamp.
func TestNormalizeExpiry_InvalidRFC3339(t *testing.T) {
	_, err := normalizeExpiry("2026-13-01T25:00:00Z")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid --expires")
}

// TestDescribeScope_CIDRsOnly verifies that a token with only AllowedCIDRs
// (no scopes, no project/env scope) renders just the "from=…" part.
func TestDescribeScope_CIDRsOnly(t *testing.T) {
	result := describeScope(patView{AllowedCIDRs: []string{"10.0.0.0/8", "192.168.0.0/16"}})
	assert.Equal(t, "from=10.0.0.0/8,192.168.0.0/16", result)
}

// TestClient_NotConnected verifies that the client() helper returns an error
// when KEYORIX_SERVER is not set (XDG_CONFIG_HOME points at an empty dir so
// there is no cli.yaml in client mode either).
func TestClient_NotConnected(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	_, err := client()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}
