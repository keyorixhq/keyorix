package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/keyorixhq/keyorix/migrate/internal/migrateversion"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the keyorix-migrate version",
	RunE: func(cmd *cobra.Command, args []string) error {
		_, err := fmt.Fprintf(cmd.OutOrStdout(), "keyorix-migrate %s\n", migrateversion.Version)
		return err
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
