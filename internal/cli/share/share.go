package share

import (
	"github.com/spf13/cobra"
)

// ShareCmd represents the share command
var ShareCmd = &cobra.Command{
	Use:   "share",
	Short: "Manage secret sharing",
	Long:  `Commands for sharing secrets with other users and managing shared secrets.`,
}

func init() {
	// Add subcommands
	ShareCmd.AddCommand(createCmd)
	ShareCmd.AddCommand(listCmd)
	ShareCmd.AddCommand(updateCmd)
	ShareCmd.AddCommand(revokeCmd)
	ShareCmd.AddCommand(sharedSecretsCmd)
}
