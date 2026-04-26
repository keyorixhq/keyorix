package share

import (
	"bytes"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

func TestShareCommandsExist(t *testing.T) {
	// Test that all expected commands are registered
	assert.NotNil(t, ShareCmd)
	assert.NotNil(t, createCmd)
	assert.NotNil(t, listCmd)
	assert.NotNil(t, updateCmd)
	assert.NotNil(t, revokeCmd)
	assert.NotNil(t, sharedSecretsCmd)
}

func TestShareCommandHelp(t *testing.T) {
	// Test that help text is generated correctly
	buf := new(bytes.Buffer)
	ShareCmd.SetOut(buf)
	ShareCmd.SetArgs([]string{"--help"})
	ShareCmd.Execute()

	output := buf.String()
	assert.Contains(t, output, "Commands for sharing secrets with other users and managing shared secrets.")
	assert.Contains(t, output, "create")
	assert.Contains(t, output, "list")
	assert.Contains(t, output, "update")
	assert.Contains(t, output, "revoke")
	assert.Contains(t, output, "shared-secrets")
}

func TestCreateCommandFlags(t *testing.T) {
	// Test that required flags are properly set
	cmd := &cobra.Command{}
	cmd.AddCommand(createCmd)

	// Reset flags to default values
	createSecretID = 0
	createRecipientID = 0
	createIsGroup = false
	createPermission = "read"

	// Test that flags exist and have correct defaults
	// Note: Cobra's MarkFlagRequired only validates when executed through root command

	// Check that the flags exist
	assert.NotNil(t, createCmd.Flags().Lookup("secret-id"))
	assert.NotNil(t, createCmd.Flags().Lookup("recipient-id"))
	assert.NotNil(t, createCmd.Flags().Lookup("permission"))
	assert.NotNil(t, createCmd.Flags().Lookup("is-group"))

	// Test flag defaults
	permissionFlag := createCmd.Flags().Lookup("permission")
	assert.Equal(t, "read", permissionFlag.DefValue)

	isGroupFlag := createCmd.Flags().Lookup("is-group")
	assert.Equal(t, "false", isGroupFlag.DefValue)
}

func TestUpdateCommandFlags(t *testing.T) {
	// Test that required flags are properly defined

	// Check that the flags exist
	assert.NotNil(t, updateCmd.Flags().Lookup("share-id"))
	assert.NotNil(t, updateCmd.Flags().Lookup("permission"))

	// Test flag defaults
	permissionFlag := updateCmd.Flags().Lookup("permission")
	assert.Equal(t, "", permissionFlag.DefValue)
}

func TestRevokeCommandFlags(t *testing.T) {
	// Test that required flags are properly defined

	// Check that the flags exist
	assert.NotNil(t, revokeCmd.Flags().Lookup("share-id"))
}
