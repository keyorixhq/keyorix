// auth_encryption.go implements `keyorix-server admin encryption
// auth-encryption <cmd>` (ADR-108 §B3, PR 12): status/enable/rotate/migrate/
// validate for authentication-data encryption (API client secrets, session
// tokens, API tokens, password reset tokens), ported from
// internal/cli/encryption/auth_encryption*.go. Logic lives in
// internal/encryptionops, shared with the old CLI.
package admin

import (
	"fmt"

	"github.com/keyorixhq/keyorix/internal/encryptionops"
	"github.com/spf13/cobra"
)

var authEncryptionCmd = &cobra.Command{
	Use:   "auth-encryption",
	Short: "Manage authentication data encryption",
	Long: `Manage encryption for authentication-related data: API client secrets,
session tokens, API tokens, and password reset tokens. Distinct from the
DEK-rotation "rotate"/"validate" above, which operate on secret VALUES, not
auth credentials.`,
}

var authStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show authentication encryption status",
	Long:  "Display the current status of authentication data encryption. Read-only: does NOT take this tree's exclusive database-presence lock.",
	RunE:  runAuthStatus,
}

var (
	authEnableForce bool
)

var authEnableCmd = &cobra.Command{
	Use:   "enable",
	Short: "Enable authentication encryption",
	Long:  "Enable encryption for authentication data. Holds this tree's exclusive database-presence lock for its whole run.",
	RunE:  runAuthEnable,
}

var (
	authRotateConfirm bool
)

var authRotateCmd = &cobra.Command{
	Use:   "rotate",
	Short: "Rotate authentication encryption keys",
	Long: `Rotate encryption keys for all authentication data — a true DEK rotation
covering every DEK-encrypted table, not just auth-specific ones (see
internal/encryptionops.RotateAuthEncryptionWithConfig). Requires --confirm.
Holds this tree's exclusive database-presence lock for its whole run, in
addition to the key-directory exclusive lock taken internally.`,
	RunE: runAuthRotate,
}

var (
	authMigrateDryRun bool
)

var authMigrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Migrate existing plaintext auth data to encrypted storage",
	Long:  "Migrate existing plaintext authentication data to encrypted storage. Holds this tree's exclusive database-presence lock for its whole run.",
	RunE:  runAuthMigrate,
}

var (
	authValidateVerbose bool
)

var authValidateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate authentication encryption setup",
	Long:  "Validate that authentication encryption is properly configured and all encrypted data can be decrypted. Read-only: does NOT take this tree's exclusive database-presence lock.",
	RunE:  runAuthValidate,
}

func init() {
	authEncryptionCmd.AddCommand(authStatusCmd)
	authEncryptionCmd.AddCommand(authEnableCmd)
	authEncryptionCmd.AddCommand(authRotateCmd)
	authEncryptionCmd.AddCommand(authMigrateCmd)
	authEncryptionCmd.AddCommand(authValidateCmd)

	authEnableCmd.Flags().BoolVar(&authEnableForce, "force", false, "Force enable encryption even if already enabled")
	authRotateCmd.Flags().BoolVar(&authRotateConfirm, "confirm", false, "Confirm key rotation (required)")
	authMigrateCmd.Flags().BoolVar(&authMigrateDryRun, "dry-run", false, "Show what would be migrated without making changes")
	authValidateCmd.Flags().BoolVar(&authValidateVerbose, "verbose", false, "Show detailed validation results")
}

func runAuthStatus(cmd *cobra.Command, args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	return encryptionops.AuthStatusWithConfig(cfg, encPassphraseSource)
}

func runAuthEnable(cmd *cobra.Command, args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	lock, err := acquireDatabaseLock(cfg)
	if err != nil {
		return err
	}
	defer lock.Release() //nolint:errcheck
	if err := encryptionops.EnableAuthEncryptionWithConfig(cfg, authEnableForce, encPassphraseSource); err != nil {
		return err
	}
	recordAdminAction(cfg, "admin.encryption.auth_encryption_enable", "ran `keyorix-server admin encryption auth-encryption enable`", true)
	return nil
}

func runAuthRotate(cmd *cobra.Command, args []string) error {
	// The --confirm gate is checked here, BEFORE loadConfig/the database lock,
	// matching internal/cli/encryption's runRotateAuthEncryption: an operator
	// who forgot --confirm gets that error immediately, not a possibly-slow
	// config-load or lock-acquisition failure first. encryptionops.
	// RotateAuthEncryptionWithConfig re-checks confirm too (harmless), but
	// relying on that alone would reorder the two failure modes.
	if !authRotateConfirm {
		return fmt.Errorf("key rotation requires --confirm flag. This operation will re-encrypt all authentication data")
	}
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	lock, err := acquireDatabaseLock(cfg)
	if err != nil {
		return err
	}
	defer lock.Release() //nolint:errcheck
	if err := encryptionops.RotateAuthEncryptionWithConfig(cfg, authRotateConfirm, encPassphraseSource); err != nil {
		return err
	}
	recordAdminAction(cfg, "admin.encryption.auth_encryption_rotate", "ran `keyorix-server admin encryption auth-encryption rotate`", true)
	return nil
}

func runAuthMigrate(cmd *cobra.Command, args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	lock, err := acquireDatabaseLock(cfg)
	if err != nil {
		return err
	}
	defer lock.Release() //nolint:errcheck
	if err := encryptionops.MigrateAuthDataWithConfig(cfg, authMigrateDryRun, encPassphraseSource); err != nil {
		return err
	}
	if authMigrateDryRun {
		return nil
	}
	recordAdminAction(cfg, "admin.encryption.auth_encryption_migrate", "ran `keyorix-server admin encryption auth-encryption migrate`", true)
	return nil
}

func runAuthValidate(cmd *cobra.Command, args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	return encryptionops.ValidateAuthEncryptionWithConfig(cfg, authValidateVerbose, encPassphraseSource)
}
