// init_flag_warning_test.go — verifies 'system init --server ... --admin-password'
// warns on stderr about ps/proc + shell-history exposure when the flag is explicitly
// passed on the command line, and stays silent when it is left at its default.
package system

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
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

func TestRunInit_AdminPasswordFlagSilentWhenLeftAtDefault(t *testing.T) {
	resetInitFlags(t)
	url := remoteInitStub(t)
	require.NoError(t, InitCmd.Flags().Set("server", url))
	// admin-password left untouched (default "admin").

	out := captureStderr(t, func() {
		require.NoError(t, runInit(InitCmd, nil))
	})
	assert.NotContains(t, out, "--admin-password")
}
