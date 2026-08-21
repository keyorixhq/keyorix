// auth_apikey_seam_test.go — exercises the "API key is required" branch in
// runLogin (auth.go), which fires when resolveAPIKey returns an empty key
// with no error. The real common.ResolveAPIKey only returns "" via its
// interactive term.ReadPassword prompt, which itself requires a real
// terminal fd and errors (rather than returning "") on a pipe or other
// non-terminal stdin — so this branch is unreachable in a normal test
// process without a real PTY. resolveAPIKey is stubbed via its package-level
// var seam to drive this specific, otherwise-untestable branch directly.
package auth

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunLogin_EmptyAPIKeyFromResolver(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	require.NoError(t, loginCmd.Flags().Set("server", "https://keyorix.example.com"))
	t.Cleanup(func() {
		_ = loginCmd.Flags().Set("server", "")
		loginCmd.Flags().Lookup("server").Changed = false
	})

	orig := resolveAPIKey
	resolveAPIKey = func(*cobra.Command, bool) (string, error) { return "", nil }
	t.Cleanup(func() { resolveAPIKey = orig })

	err := runLogin(loginCmd, nil)
	require.Error(t, err)
	assert.Equal(t, "API key is required", err.Error())
}

// TestRunLogin_ResolveAPIKeyError verifies runLogin propagates a resolver
// error (e.g. the interactive prompt failing) rather than swallowing it.
func TestRunLogin_ResolveAPIKeyError(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	require.NoError(t, loginCmd.Flags().Set("server", "https://keyorix.example.com"))
	t.Cleanup(func() {
		_ = loginCmd.Flags().Set("server", "")
		loginCmd.Flags().Lookup("server").Changed = false
	})

	orig := resolveAPIKey
	sentinel := &keyResolveErr{"boom"}
	resolveAPIKey = func(*cobra.Command, bool) (string, error) { return "", sentinel }
	t.Cleanup(func() { resolveAPIKey = orig })

	err := runLogin(loginCmd, nil)
	require.Error(t, err)
	assert.Equal(t, sentinel, err)
}

type keyResolveErr struct{ msg string }

func (e *keyResolveErr) Error() string { return e.msg }
