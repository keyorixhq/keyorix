package encryption

import (
	"fmt"
	"os"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/storage"
	"github.com/spf13/cobra"
	"gorm.io/gorm"
)

// wipeBytes overwrites a byte slice with zeros. Mirrors
// internal/encryption's own unexported wipeBytes (not accessible from this
// package) for the few places this CLI package handles raw key material
// directly (rotate-kek's discarded evidence/audit-checkpoint key copies,
// shamir-split's generated KEK) rather than only through Service/AuthEncryption.
func wipeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// masterPassphrase reads the master passphrase from KEYORIX_MASTER_PASSWORD. It is
// required only for the default "password" key provider; with the file/env
// providers (ADR-038) the KEK comes from key material elsewhere, so it returns ""
// without error and Service.Initialize sources the KEK from the provider.
func masterPassphrase(cfg *config.Config) (string, error) {
	if t := cfg.Storage.Encryption.KeyProvider.Type; t != "" && t != "password" {
		return "", nil
	}
	p := os.Getenv("KEYORIX_MASTER_PASSWORD")
	if p == "" {
		return "", fmt.Errorf("KEYORIX_MASTER_PASSWORD environment variable is not set")
	}
	return p, nil
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

// initLocalKeyOpService constructs and initializes the encryption.Service for a
// short-lived, LOCAL key-management CLI operation — status/validate/fix-perms/
// upgrade-aad/init — and has it participate in the same cross-process lock
// coordination the server (held for its whole lifetime) and rotate/migrate-
// provider (held for the duration of their write) already use (#92/#195/#196).
// None of these commands rotate the DEK themselves, so they take the SHARED
// side of the lock: any number of them can run concurrently with each other,
// but every one is refused while a live server or an in-progress rotation/
// migrate-provider holds the lock exclusively — instead of silently reading
// (or, for upgrade-aad, writing under) a DEK that's concurrently being
// replaced. cleanPendingDEK matches upgrade-aad/rotate's existing convention of
// clearing a leftover dek.key.pending from an interrupted rotation before
// initializing. Callers must `defer service.Shutdown()` on success to release
// the lock.
func initLocalKeyOpService(cfg *config.Config, baseDir, passphrase string, cleanPendingDEK bool) (*encryption.Service, error) {
	service := encryption.NewService(&cfg.Storage.Encryption, baseDir)
	if cleanPendingDEK {
		service.CleanPendingDEK()
	}
	if err := service.Initialize(passphrase); err != nil {
		return nil, fmt.Errorf("failed to initialize encryption: %w", err)
	}
	if err := service.AcquireSharedKeyLock(); err != nil {
		service.Shutdown()
		return nil, fmt.Errorf("%w — a live server or an in-progress rotation/migrate-provider is using this key directory; stop it or wait for it to finish, then retry", err)
	}
	return service, nil
}

func runInit(cmd *cobra.Command, args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}

	if !cfg.Storage.Encryption.Enabled {
		fmt.Println("❌ Encryption is disabled in configuration")
		return nil
	}

	baseDir, _ := os.Getwd()
	passphrase, err := masterPassphrase(cfg)
	if err != nil {
		return err
	}

	fmt.Println("🔐 Initializing encryption...")
	service, err := initLocalKeyOpService(cfg, baseDir, passphrase, false)
	if err != nil {
		return err
	}
	defer service.Shutdown()

	fmt.Println("✅ Encryption initialized successfully")
	fmt.Printf("📋 Key version: %s\n", service.GetKeyVersion())
	return nil
}

func runStatus(cmd *cobra.Command, args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}

	fmt.Println("🔐 Encryption Status")
	fmt.Println("==================")
	fmt.Printf("Enabled: %v\n", cfg.Storage.Encryption.Enabled)
	fmt.Printf("DEK Path: %s\n", cfg.Storage.Encryption.DEKPath)
	fmt.Printf("Salt Path: %s\n", cfg.Storage.Encryption.SaltPath)

	if !cfg.Storage.Encryption.Enabled {
		return nil
	}

	baseDir, _ := os.Getwd()
	passphrase, err := masterPassphrase(cfg)
	if err != nil {
		fmt.Printf("⚠️  %v\n", err)
		return nil
	}

	service, err := initLocalKeyOpService(cfg, baseDir, passphrase, false)
	if err != nil {
		fmt.Printf("❌ %v\n", err)
		return nil
	}
	defer service.Shutdown()

	fmt.Printf("Initialized: ✅\n")
	fmt.Printf("Key Version: %s\n", service.GetKeyVersion())
	printProviderStatus(cfg.Storage.Encryption.KeyProvider)

	return nil
}

func printProviderStatus(kp config.KeyProviderConfig) {
	provType := kp.Type
	if provType == "" {
		provType = "password"
	}
	fmt.Printf("Key Provider: %s\n", provType)
	switch provType {
	case "password":
		fmt.Println("  (passphrase-derived KEK; use `keyorix encryption migrate-provider` to change)")
	case "file":
		fmt.Printf("  File: %s\n", kp.FilePath)
		if _, err := os.Stat(kp.FilePath); err == nil {
			fmt.Println("  Status: file accessible ✅")
		} else {
			fmt.Printf("  Status: file not accessible ❌ (%v)\n", err)
		}
	case "env":
		fmt.Printf("  Env var: %s\n", kp.EnvVar)
		if os.Getenv(kp.EnvVar) != "" {
			fmt.Println("  Status: env var set ✅")
		} else {
			fmt.Println("  Status: env var not set ❌")
		}
	case "exec":
		fmt.Printf("  Command: %v\n", kp.ExecCommand)
	case "shamir":
		fmt.Printf("  Share files: %d configured\n", len(kp.ShamirShareFiles))
	case "tpm":
		fmt.Printf("  TPM device: %s\n", kp.TPMDevice)
		fmt.Printf("  Wrapped key: %s\n", kp.WrappedKeyPath)
	case "aws-kms", "gcp-kms", "azure-kms":
		fmt.Printf("  KMS key: %s\n", kp.KMSKeyID)
		if kp.WrappedKeyPath != "" {
			fmt.Printf("  Wrapped key: %s\n", kp.WrappedKeyPath)
		}
		fmt.Println("  (connectivity not checked; verify credentials separately)")
	}
}

func runRotate(cmd *cobra.Command, args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	return rotateWithConfig(cfg, rotateConfirm, rotateDryRun)
}

// rotateWithConfig is the testable core of runRotate. It does no config loading
// and no flag parsing — callers pass explicit confirm/dryRun bools. Returns early
// (before any DB or encryption work) on the validation gates so tests don't
// need a real database or key files.
func rotateWithConfig(cfg *config.Config, confirm bool, dryRun bool) error {
	if !cfg.Storage.Encryption.Enabled {
		return fmt.Errorf("encryption is disabled in configuration")
	}

	if cfg.Storage.Type == "remote" {
		return fmt.Errorf("DEK rotation must run on the server host. Current storage type is 'remote' — connect to the server and run this command there")
	}

	if dryRun {
		return dryRunRotation(cfg)
	}

	if !confirm {
		return fmt.Errorf("this is a write-locking operation. Re-run with --confirm")
	}

	fmt.Println("⚠️  Rotating DEK and re-encrypting all DEK-encrypted rows. This holds a write lock on the database — stop write traffic before continuing.")

	baseDir, _ := os.Getwd()
	service := encryption.NewService(&cfg.Storage.Encryption, baseDir)

	passphrase, err := masterPassphrase(cfg)
	if err != nil {
		return err
	}
	service.CleanPendingDEK()
	if err := service.Initialize(passphrase); err != nil {
		return fmt.Errorf("failed to initialize encryption: %w", err)
	}
	defer service.Shutdown()

	// RotateDEKWithSweep needs a raw *gorm.DB so it can own the re-encryption
	// transaction (ADR-010), which the storage.Storage abstraction can't provide.
	// OpenGormDB honors cfg.Storage.Type and keeps the driver selection inside the
	// storage package rather than this CLI file (ADR-049). The remote-storage guard
	// above means this only reaches the local sqlite/postgres branches.
	db, err := storage.OpenGormDB(cfg)
	if err != nil {
		return fmt.Errorf("failed to open database for rotation: %w", err)
	}
	defer closeDB(db)

	fmt.Println("🔄 Rotating DEK with full re-encryption sweep...")
	result, err := service.RotateDEKWithSweep(passphrase, db)
	if err != nil {
		return fmt.Errorf("DEK rotation failed: %w", err)
	}

	fmt.Println("✅ DEK rotated successfully")
	fmt.Printf("📋 New key version: %s\n", service.GetKeyVersion())
	printSweepResult(result)
	return nil
}

// dryRunRotation previews what a real "rotate" would touch — table names and row
// counts — WITHOUT making any changes to the database or the DEK, and without
// requiring --confirm. It uses the SAME shared-key-lock local-CLI-op pattern as
// status/validate/fix-perms/upgrade-aad (refused only while a live server or an
// in-progress rotation/migrate-provider holds the key directory exclusively), not
// the exclusive lock a real rotation takes — a dry run never writes the DEK, so it
// does not need to exclude a live server the way an actual rotation does.
func dryRunRotation(cfg *config.Config) error {
	baseDir, _ := os.Getwd()
	passphrase, err := masterPassphrase(cfg)
	if err != nil {
		return err
	}

	service, err := initLocalKeyOpService(cfg, baseDir, passphrase, false)
	if err != nil {
		return err
	}
	defer service.Shutdown()

	db, err := storage.OpenGormDB(cfg)
	if err != nil {
		return fmt.Errorf("failed to open database for dry-run rotation preview: %w", err)
	}
	defer closeDB(db)

	fmt.Println("🔍 Dry run: previewing what a DEK rotation would re-encrypt — no changes will be made to the database or the DEK...")
	result, err := service.PreviewRotationSweep(db)
	if err != nil {
		return fmt.Errorf("dry-run rotation preview failed: %w", err)
	}

	fmt.Println("✅ Dry run complete — no changes were made")
	printSweepResult(result)
	return nil
}

// printSweepResult prints every field of a SweepResult — all 8 per-table "Swept"
// counts plus LegacyAADUpgraded — so an operator sees the FULL sweep outcome
// (real or previewed), not a partial one. Before this, the CLI printed no
// per-table detail from a rotation at all, and even the underlying service log
// line covered only 5 of these 8 fields — silently omitting mfa_secrets,
// dynamic_secret_configs, and dynamic_secret_leases, the exact three tables
// #422's sweep-gap fix added.
func printSweepResult(result *encryption.SweepResult) {
	fmt.Printf("📋 secret_versions: %d, sessions: %d, api_tokens: %d, api_clients: %d, password_resets: %d, mfa_secrets: %d, dynamic_secret_configs: %d, dynamic_secret_leases: %d (legacy AAD upgraded: %d)\n",
		result.SecretVersionsSwept, result.SessionsSwept, result.APITokensSwept, result.APIClientsSwept,
		result.AccountResetsSwept, result.MFASecretsSwept, result.DynamicSecretConfigsSwept, result.DynamicSecretLeasesSwept,
		result.LegacyAADUpgraded)
}

func runUpgradeAAD(cmd *cobra.Command, args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	return upgradeAADWithConfig(cfg)
}

// upgradeAADWithConfig is the testable core of runUpgradeAAD — no config loading, no
// flag parsing. Returns early (before any DB or encryption work) when encryption is
// disabled or storage is remote, so tests don't need a real database or key files.
func upgradeAADWithConfig(cfg *config.Config) error {
	if !cfg.Storage.Encryption.Enabled {
		return fmt.Errorf("encryption is disabled in configuration")
	}
	if cfg.Storage.Type == "remote" {
		return fmt.Errorf("AAD upgrade must run on the server host. Current storage type is 'remote' — connect to the server and run this command there")
	}

	baseDir, _ := os.Getwd()
	passphrase, err := masterPassphrase(cfg)
	if err != nil {
		return err
	}

	service, err := initLocalKeyOpService(cfg, baseDir, passphrase, true)
	if err != nil {
		return err
	}
	defer service.Shutdown()

	db, err := storage.OpenGormDB(cfg)
	if err != nil {
		return fmt.Errorf("failed to open database for AAD upgrade: %w", err)
	}
	defer closeDB(db)

	fmt.Println("🔄 Upgrading legacy auth-secret rows to per-row AAD...")
	result, err := service.UpgradeAuthAAD(db)
	if err != nil {
		return fmt.Errorf("AAD upgrade failed: %w", err)
	}

	fmt.Println("✅ AAD upgrade complete")
	fmt.Printf("📋 mfa_secrets: %d, dynamic_secret_configs: %d, dynamic_secret_leases: %d (legacy rows upgraded: %d)\n",
		result.MFASecretsSwept, result.DynamicSecretConfigsSwept, result.DynamicSecretLeasesSwept, result.LegacyAADUpgraded)
	return nil
}

func closeDB(db *gorm.DB) {
	if db == nil {
		return
	}
	if sqlDB, err := db.DB(); err == nil {
		_ = sqlDB.Close()
	}
}

func runValidate(cmd *cobra.Command, args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	return validateWithConfig(cfg)
}

// validateWithConfig is the testable core of runValidate.
func validateWithConfig(cfg *config.Config) error {
	if !cfg.Storage.Encryption.Enabled {
		fmt.Println("ℹ️  Encryption is disabled - nothing to validate")
		return nil
	}

	baseDir, _ := os.Getwd()

	fmt.Println("🔍 Validating encryption setup...")

	passphrase, err := masterPassphrase(cfg)
	if err != nil {
		return err
	}

	service, err := initLocalKeyOpService(cfg, baseDir, passphrase, false)
	if err != nil {
		fmt.Printf("❌ %v\n", err)
		return err
	}
	defer service.Shutdown()

	if err := service.ValidateKeyFiles(); err != nil {
		fmt.Printf("❌ Key file validation failed: %v\n", err)
		fmt.Println("💡 Run 'keyorix encryption fix-perms' to fix permissions")
		return err
	}

	fmt.Println("✅ Encryption setup is valid")
	return nil
}

func runFixPerms(cmd *cobra.Command, args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	return fixPermsWithConfig(cfg)
}

// fixPermsWithConfig is the testable core of runFixPerms.
func fixPermsWithConfig(cfg *config.Config) error {
	if !cfg.Storage.Encryption.Enabled {
		return fmt.Errorf("encryption is disabled in configuration")
	}

	baseDir, _ := os.Getwd()
	passphrase, err := masterPassphrase(cfg)
	if err != nil {
		return err
	}

	service, err := initLocalKeyOpService(cfg, baseDir, passphrase, false)
	if err != nil {
		return err
	}
	defer service.Shutdown()

	fmt.Println("🔧 Fixing key file permissions...")
	if err := service.FixKeyFilePermissions(); err != nil {
		return fmt.Errorf("failed to fix permissions: %w", err)
	}

	fmt.Println("✅ Key file permissions fixed")
	return nil
}
