// init_flag_warning_test.go — verifies 'system init --server ... --admin-password'
// warns on stderr about ps/proc + shell-history exposure when the flag is explicitly
// passed on the command line, and (#G76) that leaving it unset no longer silently
// bootstraps the server with the well-known default password "admin" — it must be
// resolved (flag/env/prompt) BEFORE the server is ever contacted.
package system

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stderr
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stderr = w
	defer func() { os.Stderr = orig }()

	fn()

	require.NoError(t, w.Close())
	out, err := io.ReadAll(r)
	require.NoError(t, err)
	return string(out)
}

func remoteInitStub(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"data":{"already_initialized":true}}`))
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func resetInitFlags(t *testing.T) {
	t.Helper()
	origServer, origPassword := initServer, initAdminPassword
	t.Cleanup(func() {
		initServer, initAdminPassword = origServer, origPassword
		InitCmd.Flags().Lookup("admin-password").Changed = false
		InitCmd.Flags().Lookup("server").Changed = false
	})
}

func TestRunInit_AdminPasswordFlagWarnsWhenExplicitlySet(t *testing.T) {
	resetInitFlags(t)
	url := remoteInitStub(t)
	require.NoError(t, InitCmd.Flags().Set("server", url))
	require.NoError(t, InitCmd.Flags().Set("admin-password", "correct-horse-battery-staple"))

	out := captureStderr(t, func() {
		require.NoError(t, runInit(InitCmd, nil))
	})
	assert.Contains(t, out, "--admin-password")
	assert.Contains(t, out, "ps/proc")
}

// TestRunInit_AdminPasswordUnsetNeverContactsServer is #G76: --admin-password
// no longer defaults to "admin" — leaving it (and KEYORIX_ADMIN_PASSWORD)
// unset must fail BEFORE the server is ever POSTed to, not silently bootstrap
// a well-known admin/admin credential pair. Stdin isn't a TTY in a test
// binary, so the interactive-prompt fallback fails fast rather than hanging —
// exactly the "refuse rather than proceed" outcome this closes.
func TestRunInit_AdminPasswordUnsetNeverContactsServer(t *testing.T) {
	resetInitFlags(t)
	var contacted atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contacted.Store(true)
		_, _ = w.Write([]byte(`{"success":true,"data":{"already_initialized":true}}`))
	}))
	t.Cleanup(srv.Close)
	require.NoError(t, InitCmd.Flags().Set("server", srv.URL))
	// admin-password left unset (no default) and no env var.

	err := runInit(InitCmd, nil)
	require.Error(t, err, "an unresolvable admin password must refuse, not silently bootstrap with a default")
	assert.False(t, contacted.Load(), "the server must never be contacted until the admin password is actually resolved")
}

// KEYORIX_ADMIN_PASSWORD must be honoured silently (no warning, no prompt) —
// the safe alternative to the insecure --admin-password flag.
func TestRunInit_AdminPasswordEnvVarResolvesSilently(t *testing.T) {
	resetInitFlags(t)
	url := remoteInitStub(t)
	require.NoError(t, InitCmd.Flags().Set("server", url))
	t.Setenv("KEYORIX_ADMIN_PASSWORD", "correct-horse-battery-staple")

	out := captureStderr(t, func() {
		require.NoError(t, runInit(InitCmd, nil))
	})
	assert.NotContains(t, out, "--admin-password", "the env var path must not warn — no command-line exposure occurred")
	assert.NotContains(t, out, "Enter admin password", "the env var path must not prompt")
}
