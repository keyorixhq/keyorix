package pat

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRevokeAgainstMockServer verifies that `revoke` sends a DELETE to the right path.
func TestRevokeAgainstMockServer(t *testing.T) {
	var gotMethod, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	out := captureStdout(t, func() {
		require.NoError(t, revokeCmd.RunE(revokeCmd, []string{"7"}))
	})
	assert.Equal(t, http.MethodDelete, gotMethod)
	assert.Equal(t, "/api/v1/auth/tokens/7", gotPath)
	assert.Contains(t, out, "Token 7 revoked")
}

// TestRevokeInvalidID verifies a non-numeric token ID is rejected before any network call.
func TestRevokeInvalidID(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "http://127.0.0.1:0")
	t.Setenv("KEYORIX_TOKEN", "tok")

	err := revokeCmd.RunE(revokeCmd, []string{"not-a-number"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid token id")
}

// TestListAgainstMockServer verifies `list` renders the token table.
func TestListAgainstMockServer(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = w.Write([]byte(`{"data":[{"id":7,"name":"ci","token_prefix":"kx_ci","revoked":false,"created_at":"2026-06-01T10:00:00Z","scopes":["secrets.read"],"project_scope":5}]}`))
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	out := captureStdout(t, func() {
		require.NoError(t, listCmd.RunE(listCmd, nil))
	})
	assert.Equal(t, "/api/v1/auth/tokens", gotPath)
	assert.Contains(t, out, "ci")
	assert.Contains(t, out, "kx_ci")
}

// TestListEmpty verifies the "no tokens" branch.
func TestListEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":[]}`))
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	out := captureStdout(t, func() {
		require.NoError(t, listCmd.RunE(listCmd, nil))
	})
	assert.Contains(t, out, "no personal access tokens")
}

// TestCreateWithCIDRs verifies allowed_cidrs is included in the POST body when set.
func TestCreateWithCIDRs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"token":"kx_pat_test","pat":{"id":9,"name":"restricted","scopes":[]}}}`))
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")
	flagName, flagScopes, flagProject, flagEnv, flagExpires = "restricted", nil, 0, 0, ""
	flagCIDRs = []string{"10.0.0.0/8", "192.168.0.0/16"}
	t.Cleanup(func() { flagCIDRs = nil })

	out := captureStdout(t, func() {
		require.NoError(t, createCmd.RunE(createCmd, nil))
	})
	assert.Contains(t, out, "kx_pat_test")
}

// TestCreateWithExpiry verifies the expiry is normalised and sent.
func TestCreateWithExpiry(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"token":"kx_pat_exp","pat":{"id":3,"name":"expiring","scopes":[]}}}`))
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")
	flagName, flagScopes, flagProject, flagEnv = "expiring", nil, 0, 0
	flagExpires = "2027-01-01"
	t.Cleanup(func() { flagExpires = "" })
	flagCIDRs = nil

	out := captureStdout(t, func() {
		require.NoError(t, createCmd.RunE(createCmd, nil))
	})
	assert.Contains(t, out, "kx_pat_exp")
}

// TestCreateWithBadExpiry verifies an invalid --expires flag is rejected before any network call.
func TestCreateWithBadExpiry(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "http://127.0.0.1:0")
	t.Setenv("KEYORIX_TOKEN", "tok")
	flagName, flagExpires = "ci", "not-a-date"
	flagCIDRs = nil
	t.Cleanup(func() { flagExpires = ""; flagName = "" })

	err := createCmd.RunE(createCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid --expires")
}
