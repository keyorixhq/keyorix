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
		fmt.Printf("keyorix-migrate %s\n", migrateversion.Version)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
