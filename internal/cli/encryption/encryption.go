package encryption

import (
	"fmt"
	"os"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/spf13/cobra"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// masterPassphrase reads the master passphrase from KEYORIX_MASTER_PASSWORD.
// Returns an error if the variable is unset or empty.
func masterPassphrase() (string, error) {
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
running. Requires --confirm.`,
	RunE: runRotate,
}

var rotateConfirm bool

func init() {
	EncryptionCmd.AddCommand(initCmd)
	EncryptionCmd.AddCommand(statusCmd)
	EncryptionCmd.AddCommand(rotateCmd)
	EncryptionCmd.AddCommand(validateCmd)
	EncryptionCmd.AddCommand(fixPermsCmd)

	rotateCmd.Flags().BoolVar(&rotateConfirm, "confirm", false,
		"required acknowledgement that the database will be write-locked during the sweep")
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
	service := encryption.NewService(&cfg.Storage.Encryption, baseDir)

	passphrase, err := masterPassphrase()
	if err != nil {
		return err
	}

	fmt.Println("🔐 Initializing encryption...")
	if err := service.Initialize(passphrase); err != nil {
		return fmt.Errorf("failed to initialize encryption: %w", err)
	}

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
	fmt.Printf("Use KEK: %v\n", cfg.Storage.Encryption.UseKEK)
	fmt.Printf("KEK Path: %s\n", cfg.Storage.Encryption.KEKPath)
	fmt.Printf("DEK Path: %s\n", cfg.Storage.Encryption.DEKPath)

	if !cfg.Storage.Encryption.Enabled {
		return nil
	}

	baseDir, _ := os.Getwd()
	service := encryption.NewService(&cfg.Storage.Encryption, baseDir)

	passphrase, err := masterPassphrase()
	if err != nil {
		fmt.Printf("⚠️  %v\n", err)
		return nil
	}
	if err := service.Initialize(passphrase); err != nil {
		fmt.Printf("❌ Initialization failed: %v\n", err)
		return nil
	}

	fmt.Printf("Initialized: ✅\n")
	fmt.Printf("Key Version: %s\n", service.GetKeyVersion())

	return nil
}

func runRotate(cmd *cobra.Command, args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	return rotateWithConfig(cfg, rotateConfirm)
}

// rotateWithConfig is the testable core of runRotate. It does no config loading
// and no flag parsing — callers pass an explicit confirm bool. Returns early
// (before any DB or encryption work) on the validation gates so tests don't
// need a real database or key files.
func rotateWithConfig(cfg *config.Config, confirm bool) error {
	if !cfg.Storage.Encryption.Enabled {
		return fmt.Errorf("encryption is disabled in configuration")
	}

	if cfg.Storage.Type == "remote" {
		return fmt.Errorf("DEK rotation must run on the server host. Current storage type is 'remote' — connect to the server and run this command there")
	}

	if !confirm {
		return fmt.Errorf("this is a write-locking operation. Re-run with --confirm")
	}

	fmt.Println("⚠️  Rotating DEK and re-encrypting all DEK-encrypted rows. This holds a write lock on the database — stop write traffic before continuing.")

	baseDir, _ := os.Getwd()
	service := encryption.NewService(&cfg.Storage.Encryption, baseDir)

	passphrase, err := masterPassphrase()
	if err != nil {
		return err
	}
	service.CleanPendingDEK()
	if err := service.Initialize(passphrase); err != nil {
		return fmt.Errorf("failed to initialize encryption: %w", err)
	}
	defer service.Shutdown()

	db, err := openDBForRotation(cfg)
	if err != nil {
		return fmt.Errorf("failed to open database for rotation: %w", err)
	}
	defer closeDB(db)

	fmt.Println("🔄 Rotating DEK with full re-encryption sweep...")
	if err := service.RotateDEKWithSweep(passphrase, db); err != nil {
		return fmt.Errorf("DEK rotation failed: %w", err)
	}

	fmt.Println("✅ DEK rotated successfully")
	fmt.Printf("📋 New key version: %s\n", service.GetKeyVersion())
	return nil
}

// openDBForRotation opens a *gorm.DB connection that mirrors the connection
// logic in internal/storage/factory.go. We deliberately do not go through the
// storage abstraction — RotateDEKWithSweep needs a raw *gorm.DB so it can own
// the transaction. See the ADR-010 addendum for why this is a private CLI
// helper rather than an accessor on storage.LocalStorage.
func openDBForRotation(cfg *config.Config) (*gorm.DB, error) {
	switch cfg.Storage.Type {
	case "postgres", "postgresql":
		dsn := config.BuildPostgresDSN(&cfg.Storage.Database)
		if dsn == "" {
			return nil, fmt.Errorf("postgres storage requires a DSN or host/name/user fields")
		}
		db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
		if err != nil {
			return nil, fmt.Errorf("failed to connect to postgres: %w", err)
		}
		return applyDBPool(db, &cfg.Storage.Database)
	default:
		dbPath := cfg.Storage.Database.Path
		if dbPath == "" {
			dbPath = "./secrets.db"
		}
		db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
		if err != nil {
			return nil, fmt.Errorf("failed to connect to database: %w", err)
		}
		return applyDBPool(db, &cfg.Storage.Database)
	}
}

func applyDBPool(db *gorm.DB, dbCfg *config.DatabaseConfig) (*gorm.DB, error) {
	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("failed to get underlying sql.DB: %w", err)
	}
	if dbCfg.MaxOpenConns > 0 {
		sqlDB.SetMaxOpenConns(dbCfg.MaxOpenConns)
	}
	if dbCfg.MaxIdleConns > 0 {
		sqlDB.SetMaxIdleConns(dbCfg.MaxIdleConns)
	}
	if dbCfg.ConnMaxLifetimeMinutes > 0 {
		sqlDB.SetConnMaxLifetime(time.Duration(dbCfg.ConnMaxLifetimeMinutes) * time.Minute)
	}
	return db, nil
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

	if !cfg.Storage.Encryption.Enabled {
		fmt.Println("ℹ️  Encryption is disabled - nothing to validate")
		return nil
	}

	baseDir, _ := os.Getwd()
	service := encryption.NewService(&cfg.Storage.Encryption, baseDir)

	fmt.Println("🔍 Validating encryption setup...")

	passphrase, err := masterPassphrase()
	if err != nil {
		return err
	}
	if err := service.Initialize(passphrase); err != nil {
		fmt.Printf("❌ Initialization failed: %v\n", err)
		return err
	}

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

	if !cfg.Storage.Encryption.Enabled {
		return fmt.Errorf("encryption is disabled in configuration")
	}

	baseDir, _ := os.Getwd()
	service := encryption.NewService(&cfg.Storage.Encryption, baseDir)

	passphrase, err := masterPassphrase()
	if err != nil {
		return err
	}
	if err := service.Initialize(passphrase); err != nil {
		return fmt.Errorf("failed to initialize encryption: %w", err)
	}

	fmt.Println("🔧 Fixing key file permissions...")
	if err := service.FixKeyFilePermissions(); err != nil {
		return fmt.Errorf("failed to fix permissions: %w", err)
	}

	fmt.Println("✅ Key file permissions fixed")
	return nil
}
