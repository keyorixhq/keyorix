package auth

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRunLogin_ExistingConfigParseError_LeavesFileUnchangedAndFails is #1644's
// exact reproduction: a config file with a security-relevant setting enabled
// (security.require_transport_tls: true) plus one unrelated typo elsewhere
// (tls_verfiy instead of tls_verify) fails config.Load's strict decode. Before
// the #1644 fix, runLogin treated ANY Load error as "no config file yet",
// silently built a fresh default *Config, and wrote it back — reverting
// require_transport_tls to its false zero value and discarding every other
// setting, with a plain "✅ Successfully authenticated" success message. This
// test asserts the fixed contract: the command fails clearly, and the file on
// disk is byte-for-byte unchanged.
func TestRunLogin_ExistingConfigParseError_LeavesFileUnchangedAndFails(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	original := "security:\n  require_transport_tls: true\nstorage:\n  type: remote\n  remote:\n    base_url: https://original-trusted-server.example.com:8443\n    api_key: sk-original-production-api-key-do-not-lose\n    timeout_seconds: 90\n    retry_attempts: 7\n    tls_verfiy: false\n"
	configPath := filepath.Join(dir, "keyorix.yaml")
	require.NoError(t, os.WriteFile(configPath, []byte(original), 0o600))

	t.Setenv("KEYORIX_API_KEY", "kx_new_key")
	require.NoError(t, loginCmd.Flags().Set("server", "https://new-server.example.com"))
	t.Cleanup(func() {
		_ = loginCmd.Flags().Set("server", "")
		loginCmd.Flags().Lookup("server").Changed = false
	})

	err := runLogin(loginCmd, nil)
	require.Error(t, err, "a config that exists but fails to parse must fail the command, not silently proceed")
	assert.Contains(t, err.Error(), "failed to load existing configuration")

	after, readErr := os.ReadFile(configPath)
	require.NoError(t, readErr)
	assert.Equal(t, original, string(after), "the file must be byte-for-byte unchanged when Load fails for a reason other than \"does not exist\"")
}
