package secret

import (
	"github.com/spf13/cobra"
)

// SecretCmd is the root command for secret operations
var SecretCmd = &cobra.Command{
	Use:   "secret",
	Short: "Manage secrets",
	Long:  "Commands for creating, reading, updating, and deleting secrets",
}

func init() {
	SecretCmd.AddCommand(createCmd)
	SecretCmd.AddCommand(getCmd)
	SecretCmd.AddCommand(listCmd)
	SecretCmd.AddCommand(updateCmd)
	SecretCmd.AddCommand(deleteCmd)
	SecretCmd.AddCommand(versionsCmd)
	SecretCmd.AddCommand(importCmd)
}
