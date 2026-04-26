package encryption

import (
	"fmt"
	"os"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/spf13/cobra"
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
	Short: "Rotate encryption keys",
	Long:  "Generate new encryption keys and update key version",
	RunE:  runRotate,
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

func init() {
	EncryptionCmd.AddCommand(initCmd)
	EncryptionCmd.AddCommand(statusCmd)
	EncryptionCmd.AddCommand(rotateCmd)
	EncryptionCmd.AddCommand(validateCmd)
	EncryptionCmd.AddCommand(fixPermsCmd)
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

	fmt.Println("🔄 Rotating DEK...")
	if err := service.RotateDEK(passphrase); err != nil {
		return fmt.Errorf("failed to rotate DEK: %w", err)
	}

	fmt.Println("✅ Keys rotated successfully")
	fmt.Printf("📋 New key version: %s\n", service.GetKeyVersion())
	fmt.Println("⚠️  Note: Existing secrets will need to be re-encrypted with the new keys")
	return nil
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
