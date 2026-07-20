package system

import (
	"github.com/spf13/cobra"
)

var SystemCmd = &cobra.Command{
	Use:   "system",
	Short: "System management commands",
}

func init() {
	SystemCmd.AddCommand(InitCmd)
	SystemCmd.AddCommand(auditCmd)
	SystemCmd.AddCommand(validateCmd)
	SystemCmd.AddCommand(infoCmd)
	SystemCmd.AddCommand(roleExpiryCheckCmd)
	SystemCmd.AddCommand(tokenExpiryCheckCmd)
}
