// pat_s3_test.go — sprint-3 coverage: the server-error branches of
// createCmd/listCmd/revokeCmd.RunE (the c.Post/c.Get/c.Delete err != nil path),
// which were previously only exercised indirectly for hygiene/list-expired but
// never for create/list/revoke.
package pat

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCreateCmd_ServerError verifies that a server-side error from the POST
// /api/v1/auth/tokens call propagates out of createCmd.RunE (the err != nil
// branch right after c.Post, distinct from the pre-flight validation errors
// already covered by TestCreate_Validation and TestCreateWithBadExpiry).
func TestCreateCmd_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")
	flagName, flagScopes, flagProject, flagEnv, flagExpires, flagCIDRs = "ci", nil, 0, 0, "", nil

	err := createCmd.RunE(createCmd, nil)
	require.Error(t, err)
}

// TestListCmd_ServerError verifies that a server-side error from the GET
// /api/v1/auth/tokens call propagates out of listCmd.RunE (the err != nil
// branch right after c.Get, distinct from TestListCmd_NotConnected which
// never reaches the network call).
func TestListCmd_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	err := listCmd.RunE(listCmd, nil)
	require.Error(t, err)
}

// TestRevokeCmd_ServerError verifies that a server-side error from the DELETE
// /api/v1/auth/tokens/{id} call propagates out of revokeCmd.RunE (the err !=
// nil branch right after c.Delete, distinct from TestRevokeInvalidID which
// never reaches the network call and TestRevokeCmd_NotConnected which never
// has a server to talk to).
func TestRevokeCmd_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	err := revokeCmd.RunE(revokeCmd, []string{"7"})
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "invalid token id", "must fail at the network call, not id parsing")
}

// The three tests below exercise the client()-error ("not connected") branch
// of listExpiredCmd/cleanupExpiredCmd/hygieneCmd.RunE. They set
// XDG_CONFIG_HOME to an empty temp dir (mirroring TestCreateCmd_NotConnected
// et al. in pat_s25_test.go) so the assertion is isolated from any real
// ~/.keyorix/cli.yaml on the machine running the test — without this
// isolation a stale local connect config makes client() succeed instead of
// erroring, and the test would try (and time out) reaching a real host.

// TestListExpiredCmd_NotConnected_Isolated verifies listExpiredCmd.RunE's
// client() error branch (expired.go's `if err != nil { return err }` right
// after `client()`) in an environment with no server configured at all.
func TestListExpiredCmd_NotConnected_Isolated(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	err := listExpiredCmd.RunE(listExpiredCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected to a server")
}

// TestCleanupExpiredCmd_NotConnected_Isolated verifies cleanupExpiredCmd.RunE's
// client() error branch in an environment with no server configured at all.
func TestCleanupExpiredCmd_NotConnected_Isolated(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	err := cleanupExpiredCmd.RunE(cleanupExpiredCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected to a server")
}

// TestHygieneCmd_NotConnected_Isolated verifies hygieneCmd.RunE's client()
// error branch in an environment with no server configured at all.
func TestHygieneCmd_NotConnected_Isolated(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	hygieneDays = 0

	err := hygieneCmd.RunE(hygieneCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected to a server")
}
