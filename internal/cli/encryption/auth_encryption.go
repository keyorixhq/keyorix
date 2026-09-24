// auth_encryption.go — Cobra commands, init, and status/enable/rotate run funcs.
//
// For migration see auth_encryption_migrate.go.
// For validation see auth_encryption_validate.go.
// For DB open and stats see auth_encryption_stats.go.
//
// The actual logic lives in internal/encryptionops (docs/cli-split-inventory.md
// §7 PR 12), shared with the `keyorix-server admin encryption
// auth-encryption` subcommand tree.
package encryption

import (
	"fmt"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/encryptionops"
	"github.com/spf13/cobra"
)

// AuthEncryptionCmd represents the auth encryption command.
var AuthEncryptionCmd = &cobra.Command{
	Use:   "auth-encryption",
	Short: "Manage authentication data encryption",
	Long: `Manage encryption for authentication-related data including:
- API client secrets
- Session tokens
- API tokens
- Password reset tokens

This command allows you to enable encryption, check status, and rotate keys for authentication data.`,
}

var authStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show authentication encryption status",
	Long:  "Display the current status of authentication data encryption including enabled state and key version.",
	RunE:  runAuthEncryptionStatus,
}

var enableCmd = &cobra.Command{
	Use:   "enable",
	Short: "Enable authentication encryption",
	Long:  "Enable encryption for authentication data. This will encrypt new authentication tokens and secrets.",
	RunE:  runEnableAuthEncryption,
}

var authRotateCmd = &cobra.Command{
	Use:   "rotate",
	Short: "Rotate authentication encryption keys",
	Long:  "Rotate encryption keys for all authentication data. This will re-encrypt all stored tokens and secrets with new keys.",
	RunE:  runRotateAuthEncryption,
}

var migrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Migrate existing plaintext auth data to encrypted storage",
	Long:  "Migrate existing plaintext authentication data to encrypted storage. This is useful when enabling encryption on an existing system.",
	RunE:  runMigrateAuthData,
}

var authValidateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate authentication encryption setup",
	Long:  "Validate that authentication encryption is properly configured and all encrypted data can be decrypted.",
	RunE:  runValidateAuthEncryption,
}

func init() {
	AuthEncryptionCmd.AddCommand(authStatusCmd)
	AuthEncryptionCmd.AddCommand(enableCmd)
	AuthEncryptionCmd.AddCommand(authRotateCmd)
	AuthEncryptionCmd.AddCommand(migrateCmd)
	AuthEncryptionCmd.AddCommand(authValidateCmd)

	enableCmd.Flags().Bool("force", false, "Force enable encryption even if already enabled")
	authRotateCmd.Flags().Bool("confirm", false, "Confirm key rotation (required)")
	migrateCmd.Flags().Bool("dry-run", false, "Show what would be migrated without making changes")
	authValidateCmd.Flags().Bool("verbose", false, "Show detailed validation results")
}

func runAuthEncryptionStatus(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load("")
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}
	return authStatusWithConfig(cfg)
}

// authStatusWithConfig is a thin re-export of encryptionops.AuthStatusWithConfig
// — kept as a package-local name because this package's tests call it directly.
func authStatusWithConfig(cfg *config.Config) error {
	return encryptionops.AuthStatusWithConfig(cfg, common.PassphraseSource)
}

func runEnableAuthEncryption(cmd *cobra.Command, args []string) error {
	force, _ := cmd.Flags().GetBool("force")
	cfg, err := config.Load("")
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}
	return enableAuthEncryptionWithConfig(cfg, force)
}

// enableAuthEncryptionWithConfig is a thin re-export of
// encryptionops.EnableAuthEncryptionWithConfig — kept as a package-local name
// because this package's tests call it directly.
func enableAuthEncryptionWithConfig(cfg *config.Config, force bool) error {
	return encryptionops.EnableAuthEncryptionWithConfig(cfg, force, common.PassphraseSource)
}

func runRotateAuthEncryption(cmd *cobra.Command, args []string) error {
	confirm, _ := cmd.Flags().GetBool("confirm")
	// The --confirm gate is checked here, BEFORE config.Load, matching this
	// command's original control flow: an operator who forgot --confirm gets
	// that error immediately, not a possibly-unrelated config-load failure.
	// encryptionops.RotateAuthEncryptionWithConfig re-checks confirm too
	// (harmless — every caller must pass it a value either way), but relying
	// on that alone would reorder the two failure modes for this command.
	if !confirm {
		return fmt.Errorf("key rotation requires --confirm flag. This operation will re-encrypt all authentication data")
	}
	cfg, err := config.Load("")
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}
	return encryptionops.RotateAuthEncryptionWithConfig(cfg, confirm, common.PassphraseSource)
}
