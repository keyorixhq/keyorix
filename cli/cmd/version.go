package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/keyorix/cli/internal/cliversion"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the CLI version and the API version it targets",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Printf("keyorix %s (targets API version %d)\n", cliversion.Version, cliversion.TargetAPIVersion)
		return nil
	},
}
