package user

import (
	"github.com/spf13/cobra"
)

// UserCmd is the root command for user operations.
var UserCmd = &cobra.Command{
	Use:   "user",
	Short: "Manage users",
	Long:  "Create, read, update, delete, and list users in the local database.",
}

func init() {
	UserCmd.AddCommand(createCmd)
	UserCmd.AddCommand(getCmd)
	UserCmd.AddCommand(updateCmd)
	UserCmd.AddCommand(deleteCmd)
	UserCmd.AddCommand(listCmd)
}
