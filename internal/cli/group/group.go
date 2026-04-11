package group

import (
	"github.com/spf13/cobra"
)

// GroupCmd is the root command for group operations.
var GroupCmd = &cobra.Command{
	Use:   "group",
	Short: "Manage groups",
	Long:  "Create, read, update, delete, list groups and manage membership.",
}

func init() {
	GroupCmd.AddCommand(createCmd)
	GroupCmd.AddCommand(getCmd)
	GroupCmd.AddCommand(updateCmd)
	GroupCmd.AddCommand(deleteCmd)
	GroupCmd.AddCommand(listCmd)
	GroupCmd.AddCommand(addMemberCmd)
	GroupCmd.AddCommand(removeMemberCmd)
	GroupCmd.AddCommand(membersCmd)
}
