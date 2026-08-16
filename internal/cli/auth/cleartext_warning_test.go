// cleartext_warning_test.go — #G74: 'auth login' persists a real API key
// against a user-supplied server URL with no cleartext-transmission warning
// when that URL isn't HTTPS. Verifies the warning fires before the config is
// saved for a plaintext http:// server, and stays silent for https://.
package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func resetLoginFlags(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		_ = loginCmd.Flags().Set("api-key", "")
		_ = loginCmd.Flags().Set("server", "")
		loginCmd.Flags().Lookup("api-key").Changed = false
		loginCmd.Flags().Lookup("server").Changed = false
	})
}

func TestRunLogin_WarnsOnPlaintextHTTPServer(t *testing.T) {
	t.Chdir(t.TempDir()) // runLogin writes keyorix.yaml relative to cwd
	resetLoginFlags(t)

	require.NoError(t, loginCmd.Flags().Set("api-key", "kx_api_secret"))
	require.NoError(t, loginCmd.Flags().Set("server", "http://keyorix.example.com"))

	out := captureStderr(t, func() {
		require.NoError(t, runLogin(loginCmd, nil))
	})
	assert.Contains(t, out, "not HTTPS")
	assert.Contains(t, out, "cleartext")
	assert.Contains(t, out, "MITM-capturable")
}

func TestRunLogin_NoWarningOnHTTPSServer(t *testing.T) {
	t.Chdir(t.TempDir())
	resetLoginFlags(t)

	require.NoError(t, loginCmd.Flags().Set("api-key", "kx_api_secret"))
	require.NoError(t, loginCmd.Flags().Set("server", "https://keyorix.example.com"))

	out := captureStderr(t, func() {
		require.NoError(t, runLogin(loginCmd, nil))
	})
	assert.NotContains(t, out, "not HTTPS")
	assert.NotContains(t, out, "MITM-capturable")
}
