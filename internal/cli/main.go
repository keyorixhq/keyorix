package cli

import (
	"fmt"
	"os"

	"github.com/keyorixhq/keyorix/internal/cli/auth"
	"github.com/keyorixhq/keyorix/internal/cli/config"
	"github.com/keyorixhq/keyorix/internal/cli/connect"
	"github.com/keyorixhq/keyorix/internal/cli/encryption"
	"github.com/keyorixhq/keyorix/internal/cli/rbac"
	"github.com/keyorixhq/keyorix/internal/cli/secret"
	"github.com/keyorixhq/keyorix/internal/cli/share"
	"github.com/keyorixhq/keyorix/internal/cli/status"
	"github.com/keyorixhq/keyorix/internal/cli/system"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "keyorix",
	Short: "Keyorix - A secure secret management tool",
	Long:  `Keyorix is a tool for securely storing, managing, and sharing secrets.`,
}

func init() {
	// Add all available commands
	rootCmd.AddCommand(secret.SecretCmd)
	rootCmd.AddCommand(share.ShareCmd)
	rootCmd.AddCommand(auth.AuthCmd)
	rootCmd.AddCommand(config.ConfigCmd)
	rootCmd.AddCommand(connect.ConnectCmd)
	rootCmd.AddCommand(encryption.EncryptionCmd)
	rootCmd.AddCommand(rbac.RbacCmd)
	rootCmd.AddCommand(status.StatusCmd)
	rootCmd.AddCommand(system.SystemCmd)
}

// Execute runs the root command
func Execute() {
	// Initialize i18n system for CLI
	if err := i18n.InitializeForTesting(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize i18n: %v\n", err)
		// Continue anyway - don't fail completely
	}

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}