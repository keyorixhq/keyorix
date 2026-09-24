package cmd

import (
	"github.com/spf13/cobra"

	"github.com/keyorixhq/keyorix/cli/internal/cliversion"
)

var rootCmd = &cobra.Command{
	Use:     "keyorix-next",
	Short:   "Keyorix CLI (thin, REST-only preview) -- see ADR-108",
	Long:    `keyorix-next is the thin, network-only Keyorix CLI being built under ADR-108. It talks to a Keyorix server exclusively over the REST API; it has no local database mode. Use "keyorix" for everything not yet migrated here.`,
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
