// cleartext_warning_test.go — #G74: 'config set-remote' persists a real API
// key against a user-supplied server URL with no cleartext-transmission
// warning when that URL isn't HTTPS. Verifies the warning fires before the
// config is saved for a plaintext http:// server, and stays silent for
// https://.
package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func resetSetRemoteFlags(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		_ = setRemoteCmd.Flags().Set("url", "")
		_ = setRemoteCmd.Flags().Set("api-key", "")
		setRemoteCmd.Flags().Lookup("url").Changed = false
		setRemoteCmd.Flags().Lookup("api-key").Changed = false
	})
}

func TestRunSetRemote_WarnsOnPlaintextHTTPServer(t *testing.T) {
	t.Chdir(t.TempDir()) // runSetRemote writes keyorix.yaml relative to cwd
	resetSetRemoteFlags(t)

	require.NoError(t, setRemoteCmd.Flags().Set("url", "http://keyorix.example.com"))
	require.NoError(t, setRemoteCmd.Flags().Set("api-key", "kx_api_secret"))

	out := captureStderr(t, func() {
		require.NoError(t, runSetRemote(setRemoteCmd, nil))
	})
	assert.Contains(t, out, "not HTTPS")
	assert.Contains(t, out, "cleartext")
	assert.Contains(t, out, "MITM-capturable")
}

func TestRunSetRemote_NoWarningOnHTTPSServer(t *testing.T) {
	t.Chdir(t.TempDir())
	resetSetRemoteFlags(t)

	require.NoError(t, setRemoteCmd.Flags().Set("url", "https://keyorix.example.com"))
	require.NoError(t, setRemoteCmd.Flags().Set("api-key", "kx_api_secret"))

	out := captureStderr(t, func() {
		require.NoError(t, runSetRemote(setRemoteCmd, nil))
	})
	assert.NotContains(t, out, "not HTTPS")
	assert.NotContains(t, out, "MITM-capturable")
}
