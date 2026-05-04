// auth_encryption.go — Cobra commands, init, and status/enable/rotate run funcs.
//
// For migration see auth_encryption_migrate.go.
// For validation see auth_encryption_validate.go.
// For DB open and stats see auth_encryption_stats.go.
package encryption

import (
	"fmt"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/encryption"
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
	db, err := openDatabase(cfg)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	authEnc := encryption.NewAuthEncryption(&cfg.Storage.Encryption, ".", db)
	passphrase, _ := masterPassphrase()
	if err := authEnc.Initialize(passphrase); err != nil {
		return fmt.Errorf("failed to initialize auth encryption: %w", err)
	}
	status := authEnc.GetAuthEncryptionStatus()

	fmt.Println("🔐 Authentication Encryption Status")
	fmt.Println("=" + string(make([]rune, 35)))
	if status["enabled"].(bool) {
		fmt.Println("✅ Status: ENABLED")
	} else {
		fmt.Println("❌ Status: DISABLED")
	}
	if status["initialized"].(bool) {
		fmt.Println("✅ Initialized: YES")
		if keyVersion, ok := status["key_version"]; ok {
			fmt.Printf("🔑 Key Version: %s\n", keyVersion)
		}
	} else {
		fmt.Println("❌ Initialized: NO")
	}
	if err := showAuthEncryptionStats(db, status["enabled"].(bool)); err != nil {
		fmt.Printf("⚠️  Warning: Could not retrieve statistics: %v\n", err)
	}
	return nil
}

func runEnableAuthEncryption(cmd *cobra.Command, args []string) error {
	force, _ := cmd.Flags().GetBool("force")
	cfg, err := config.Load("")
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}
	if !cfg.Storage.Encryption.Enabled && !force {
		return fmt.Errorf("encryption is disabled in configuration. Enable it in config or use --force flag")
	}
	db, err := openDatabase(cfg)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	authEnc := encryption.NewAuthEncryption(&cfg.Storage.Encryption, ".", db)
	status := authEnc.GetAuthEncryptionStatus()
	if status["enabled"].(bool) && status["initialized"].(bool) && !force {
		fmt.Println("✅ Authentication encryption is already enabled")
		return nil
	}
	passphrase, _ := masterPassphrase()
	if err := authEnc.Initialize(passphrase); err != nil {
		return fmt.Errorf("failed to initialize auth encryption: %w", err)
	}
	fmt.Println("✅ Authentication encryption enabled successfully")
	fmt.Println("🔑 New authentication tokens will be encrypted")
	fmt.Println("💡 Use 'migrate' command to encrypt existing plaintext data")
	return nil
}

func runRotateAuthEncryption(cmd *cobra.Command, args []string) error {
	confirm, _ := cmd.Flags().GetBool("confirm")
	if !confirm {
		return fmt.Errorf("key rotation requires --confirm flag. This operation will re-encrypt all authentication data")
	}
	cfg, err := config.Load("")
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}
	db, err := openDatabase(cfg)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	authEnc := encryption.NewAuthEncryption(&cfg.Storage.Encryption, ".", db)
	passphrase, _ := masterPassphrase()
	if err := authEnc.Initialize(passphrase); err != nil {
		return fmt.Errorf("failed to initialize auth encryption: %w", err)
	}
	fmt.Println("🔄 Starting authentication encryption key rotation...")
	if err := authEnc.RotateAuthEncryption(); err != nil {
		return fmt.Errorf("failed to rotate auth encryption keys: %w", err)
	}
	fmt.Println("✅ Authentication encryption key rotation completed successfully")
	fmt.Println("🔑 All authentication data has been re-encrypted with new keys")
	return nil
}
