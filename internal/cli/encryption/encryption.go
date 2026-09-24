package encryption

import (
	"fmt"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/crypto"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/encryptionops"
	"github.com/spf13/cobra"
	"gorm.io/gorm"
)

// masterPassphrase, wipeBytes, and printProviderStatus are thin re-exports of
// internal/encryptionops's equivalents (docs/cli-split-inventory.md §7 PR 12)
// — kept as package-local names because this package's tests call them
// directly. The actual logic lives exactly once, in encryptionops.
func masterPassphrase(cfg *config.Config) (string, error) {
	return encryptionops.MasterPassphrase(cfg, common.PassphraseSource)
}

func wipeBytes(b []byte) {
	crypto.WipeBytes(b)
}

func printProviderStatus(kp config.KeyProviderConfig) {
	encryptionops.PrintProviderStatus(kp)
}

// EncryptionCmd is the root command for encryption operations
var EncryptionCmd = &cobra.Command{
	Use:   "encryption",
	Short: "Manage encryption keys and settings",
	Long:  "Commands for managing encryption keys, rotating keys, and validating encryption setup",
}

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize encryption keys",
	Long:  "Generate new encryption keys (KEK and DEK) if they don't exist",
	RunE:  runInit,
}

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show encryption status",
	Long:  "Display current encryption configuration and key status",
	RunE:  runStatus,
}

var rotateCmd = &cobra.Command{
	Use:   "rotate",
	Short: "Rotate the data encryption key (DEK) with full re-encryption sweep",
	Long: `Rotate the data encryption key and re-encrypt every DEK-encrypted row in
the database within a single transaction (ADR-010).

This is a write-locking operation. Stop write traffic to the database before
running. Requires --confirm.

Pass --dry-run to preview which tables/rows a rotation would re-encrypt WITHOUT
making any changes to the database or the DEK — no --confirm needed for a dry run.`,
	RunE: runRotate,
}

var upgradeAADCmd = &cobra.Command{
	Use:   "upgrade-aad",
	Short: "Bind legacy auth-secret rows to per-row AAD, without rotating the DEK",
	Long: `Re-encrypt every legacy (pre-#94), no-AAD row in mfa_secrets,
dynamic_secret_configs, and dynamic_secret_leases under the CURRENT DEK, binding
each to Additional Authenticated Data derived from its own identity (user id / config
id / lease id). This closes a ciphertext-transplant exposure — without AAD, a
DB-write attacker could copy an encrypted blob from one row to another and have it
decrypt successfully under the wrong identity.

Unlike "rotate", this does NOT change the DEK — it is safe to run repeatedly and
does not require --confirm, though it does hold a write lock on these three tables
for the duration of the sweep (typically brief; they are not high-row-count tables).`,
	RunE: runUpgradeAAD,
}

var rotateConfirm bool
var rotateDryRun bool

func init() {
	EncryptionCmd.AddCommand(initCmd)
	EncryptionCmd.AddCommand(statusCmd)
	EncryptionCmd.AddCommand(rotateCmd)
	EncryptionCmd.AddCommand(upgradeAADCmd)
	EncryptionCmd.AddCommand(validateCmd)
	EncryptionCmd.AddCommand(fixPermsCmd)
	// AuthEncryptionCmd (status/enable/rotate/migrate/validate for the
	// authentication-data encryption subsystem — API client secrets, session
	// tokens, API tokens, password reset tokens) is defined in auth_encryption.go
	// but was never wired into the tree, leaving it dead code (#292). It is
	// distinct from the DEK-rotation `rotate`/`validate` above, which operate on
	// secret VALUES, not auth credentials.
	EncryptionCmd.AddCommand(AuthEncryptionCmd)

	rotateCmd.Flags().BoolVar(&rotateConfirm, "confirm", false,
		"required acknowledgement that the database will be write-locked during the sweep")
	rotateCmd.Flags().BoolVar(&rotateDryRun, "dry-run", false,
		"preview which tables/rows a rotation would re-encrypt, without making any changes to the database or the DEK (does not require --confirm)")
}

var validateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate encryption setup",
	Long:  "Check encryption configuration and key file permissions",
	RunE:  runValidate,
}

var fixPermsCmd = &cobra.Command{
	Use:   "fix-perms",
	Short: "Fix key file permissions",
	Long:  "Automatically fix permissions on encryption key files",
	RunE:  runFixPerms,
}

func loadConfig() (*config.Config, error) {
	cfg, err := config.Load("")
	if err != nil {
		return nil, fmt.Errorf("failed to load configuration: %w", err)
	}
	return cfg, nil
}

// The actual logic for every command below lives in internal/encryptionops
// (docs/cli-split-inventory.md §7 PR 12), shared with the
// `keyorix-server admin encryption` subcommand tree (server/admin) so the
// operations exist exactly once. Each run* function here does only two
// things: load config, and forward common.PassphraseSource (bound to this
// CLI's root persistent flags in internal/cli/main.go).

func runInit(cmd *cobra.Command, args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	return encryptionops.InitWithConfig(cfg, common.PassphraseSource)
}

func runStatus(cmd *cobra.Command, args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	return encryptionops.StatusWithConfig(cfg, common.PassphraseSource)
}

func runRotate(cmd *cobra.Command, args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	return encryptionops.RotateWithConfig(cfg, rotateConfirm, rotateDryRun, common.PassphraseSource)
}

func runUpgradeAAD(cmd *cobra.Command, args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	return encryptionops.UpgradeAADWithConfig(cfg, common.PassphraseSource)
}

func runValidate(cmd *cobra.Command, args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	return encryptionops.ValidateWithConfig(cfg, common.PassphraseSource)
}

func runFixPerms(cmd *cobra.Command, args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	return encryptionops.FixPermsWithConfig(cfg, common.PassphraseSource)
}

// rotateWithConfig, upgradeAADWithConfig, validateWithConfig,
// fixPermsWithConfig, and initLocalKeyOpService are thin re-exports of their
// internal/encryptionops equivalents — kept as package-local names because
// this package's tests call them directly.
func rotateWithConfig(cfg *config.Config, confirm, dryRun bool) error {
	return encryptionops.RotateWithConfig(cfg, confirm, dryRun, common.PassphraseSource)
}

func upgradeAADWithConfig(cfg *config.Config) error {
	return encryptionops.UpgradeAADWithConfig(cfg, common.PassphraseSource)
}

func validateWithConfig(cfg *config.Config) error {
	return encryptionops.ValidateWithConfig(cfg, common.PassphraseSource)
}

func fixPermsWithConfig(cfg *config.Config) error {
	return encryptionops.FixPermsWithConfig(cfg, common.PassphraseSource)
}

func initLocalKeyOpService(cfg *config.Config, baseDir, passphrase string, cleanPendingDEK bool) (*encryption.Service, error) {
	return encryptionops.InitLocalKeyOpService(cfg, baseDir, passphrase, cleanPendingDEK)
}

func dryRunRotation(cfg *config.Config) error {
	return encryptionops.DryRunRotation(cfg, common.PassphraseSource)
}

func closeDB(db *gorm.DB) {
	if db == nil {
		return
	}
	if sqlDB, err := db.DB(); err == nil {
		_ = sqlDB.Close()
	}
}
