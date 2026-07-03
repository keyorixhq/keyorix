package user

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestResolveInitialPassword_PrefersFlagThenEnv guards #357: `user create`'s
// initial password must be resolvable via KEYORIX_INITIAL_PASSWORD (not just
// the argv-visible --password flag), matching the argv-hygiene pattern
// `keyorix connect` established (resolveAPIKey/resolveConnectPassword).
func TestResolveInitialPassword_PrefersFlagThenEnv(t *testing.T) {
	origPassword := createPassword
	defer func() { createPassword = origPassword }()
	cmd := &cobra.Command{}

	t.Run("an explicit --password flag value is used (with a warning)", func(t *testing.T) {
		createPassword = "argv-pass"
		pw, err := resolveInitialPassword(cmd)
		require.NoError(t, err)
		assert.Equal(t, "argv-pass", pw)
	})

	t.Run("KEYORIX_INITIAL_PASSWORD is used when --password is empty", func(t *testing.T) {
		createPassword = ""
		t.Setenv("KEYORIX_INITIAL_PASSWORD", "env-pass")
		pw, err := resolveInitialPassword(cmd)
		require.NoError(t, err)
		assert.Equal(t, "env-pass", pw)
	})

	t.Run("--password takes priority over the env var when both are set", func(t *testing.T) {
		createPassword = "argv-pass"
		t.Setenv("KEYORIX_INITIAL_PASSWORD", "env-pass")
		pw, err := resolveInitialPassword(cmd)
		require.NoError(t, err)
		assert.Equal(t, "argv-pass", pw)
	})
}

// TestCreateCmd_PasswordFlagDocumentsSaferAlternative confirms the --password
// flag's help text still exists for backward compatibility but documents the
// safer KEYORIX_INITIAL_PASSWORD alternative.
func TestCreateCmd_PasswordFlagDocumentsSaferAlternative(t *testing.T) {
	f := createCmd.Flags().Lookup("password")
	require.NotNil(t, f)
	assert.Contains(t, f.Usage, "KEYORIX_INITIAL_PASSWORD")
}
