// login_flag_warning_test.go — verifies 'auth login --api-key' warns on stderr about
// ps/proc + shell-history exposure when the flag is explicitly passed on the command
// line, and stays silent when the caller is prompted for it instead.
package auth

import (
	"io"
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

func TestRunLogin_APIKeyFlagWarnsWhenExplicitlySet(t *testing.T) {
	t.Chdir(t.TempDir()) // runLogin writes keyorix.yaml relative to cwd

	require.NoError(t, loginCmd.Flags().Set("api-key", "kx_api_secret"))
	require.NoError(t, loginCmd.Flags().Set("server", "https://keyorix.example.com"))
	t.Cleanup(func() {
		_ = loginCmd.Flags().Set("api-key", "")
		_ = loginCmd.Flags().Set("server", "")
		loginCmd.Flags().Lookup("api-key").Changed = false
		loginCmd.Flags().Lookup("server").Changed = false
	})

	out := captureStderr(t, func() {
		require.NoError(t, runLogin(loginCmd, nil))
	})
	assert.Contains(t, out, "--api-key")
	assert.Contains(t, out, "ps/proc")
	assert.Contains(t, out, "shell history")
}
