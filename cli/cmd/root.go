package cmd

import (
	"github.com/spf13/cobra"

	"github.com/keyorixhq/keyorix/cli/internal/cliversion"
)

var rootCmd = &cobra.Command{
	Use:     "keyorix",
	Short:   "Keyorix CLI -- see ADR-108",
	Long:    `keyorix is the Keyorix CLI. It talks to a Keyorix server exclusively over the REST API; it has no local database mode. Host-side operations (config/keys/database setup, encryption key rotation) are "keyorix-server admin", a separate command.`,
	Version: cliversion.Version,
}

// Execute runs the root command. Called from main().
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(loginCmd)
	rootCmd.AddCommand(statusCmd)
	rootCmd.AddCommand(logoutCmd)
	rootCmd.AddCommand(mfaCmd)
	rootCmd.AddCommand(auditCmd)
	rootCmd.AddCommand(anomaliesCmd)
	rootCmd.AddCommand(notificationCmd)
	rootCmd.AddCommand(accessReviewCmd)
	rootCmd.AddCommand(requestCmd)
	rootCmd.AddCommand(projectCmd)
	rootCmd.AddCommand(userCmd)
}
