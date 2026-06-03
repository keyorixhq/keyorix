package startup

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/securefiles"
)

const (
	statusFail = "❌"
	statusPass = "✅"
)

// ValidationResult contains the results of startup validation
type ValidationResult struct {
	ConfigValid   bool
	PermissionsOK bool
	EncryptionOK  bool
	DatabaseOK    bool
	Warnings      []string
	Errors        []string
}

// ValidateStartup performs comprehensive startup validation
func ValidateStartup(configPath string) (*ValidationResult, error) {
	result := &ValidationResult{
		ConfigValid:   false,
		PermissionsOK: false,
		EncryptionOK:  false,
		DatabaseOK:    false,
		Warnings:      []string{},
		Errors:        []string{},
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Failed to load config: %v", err))
		return result, fmt.Errorf("configuration validation failed: %w", err)
	}
	result.ConfigValid = true

	if cfg.Security.EnableFilePermissionCheck {
		if err := validateFilePermissions(cfg, result); err != nil {
			if !cfg.Security.AllowUnsafeFilePermissions {
				return result, fmt.Errorf("file permission validation failed: %w", err)
			}
			result.Warnings = append(result.Warnings, fmt.Sprintf("File permission issues detected but allowed: %v", err))
		} else {
			result.PermissionsOK = true
		}
	} else {
		result.PermissionsOK = true
		result.Warnings = append(result.Warnings, "File permission checks are disabled")
	}

	if cfg.Storage.Encryption.Enabled {
		if err := validateEncryption(cfg, result); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("Encryption validation failed: %v", err))
			return result, fmt.Errorf("encryption validation failed: %w", err)
		}
		result.EncryptionOK = true
	} else {
		result.EncryptionOK = true
		result.Warnings = append(result.Warnings, "Encryption is disabled")
	}

	if err := validateDatabase(cfg, result); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Database validation failed: %v", err))
		return result, fmt.Errorf("database validation failed: %w", err)
	}
	result.DatabaseOK = true

	return result, nil
}

func validateFilePermissions(cfg *config.Config, result *ValidationResult) error {
	var files []securefiles.FilePermSpec

	files = append(files, securefiles.FilePermSpec{
		Path: filepath.Clean("keyorix.yaml"),
		Mode: 0600,
	})

	if cfg.Storage.Encryption.Enabled {
		// The KEK is passphrase-derived and never on disk (ADR-004); the salt and
		// the wrapped DEK are the only key files to lock down.
		files = append(files,
			securefiles.FilePermSpec{Path: filepath.Clean(cfg.Storage.Encryption.SaltPath), Mode: 0600},
			securefiles.FilePermSpec{Path: filepath.Clean(cfg.Storage.Encryption.DEKPath), Mode: 0600},
		)
	}

	files = append(files, securefiles.FilePermSpec{
		Path: filepath.Clean(cfg.Storage.Database.Path),
		Mode: 0600,
	})

	if cfg.Server.HTTP.TLS.Enabled {
		files = append(files,
			securefiles.FilePermSpec{Path: filepath.Clean(cfg.Server.HTTP.TLS.CertFile), Mode: 0600},
			securefiles.FilePermSpec{Path: filepath.Clean(cfg.Server.HTTP.TLS.KeyFile), Mode: 0600},
		)
	}
	if cfg.Server.GRPC.TLS.Enabled {
		files = append(files,
			securefiles.FilePermSpec{Path: filepath.Clean(cfg.Server.GRPC.TLS.CertFile), Mode: 0600},
			securefiles.FilePermSpec{Path: filepath.Clean(cfg.Server.GRPC.TLS.KeyFile), Mode: 0600},
		)
	}

	if err := securefiles.FixFilePerms(files, cfg.Security.AutoFixFilePermissions); err != nil {
		return fmt.Errorf("file permission validation failed: %w", err)
	}

	if cfg.Security.AutoFixFilePermissions {
		result.Warnings = append(result.Warnings, "File permissions were automatically fixed")
	}

	return nil
}

// validateEncryption verifies the on-disk key material required by the ADR-004
// envelope scheme: the 32-byte KEK salt and the wrapped DEK. The KEK itself is
// derived from the master passphrase at runtime and never touches disk, so there
// is no KEK file to check. The DEK on disk is wrapped (AES-256-GCM: 12-byte nonce
// + 32-byte key + 16-byte tag = 60 bytes), not a bare 32-byte key.
func validateEncryption(cfg *config.Config, result *ValidationResult) error {
	enc := cfg.Storage.Encryption

	saltPath := resolveKeyPath(enc.SaltPath)
	if strings.Contains(saltPath, "..") {
		return fmt.Errorf("KEK salt path is unsafe: %s", saltPath)
	}
	saltInfo, err := os.Stat(saltPath)
	if err != nil {
		return fmt.Errorf("KEK salt file not found: %s", saltPath)
	}
	if saltInfo.Size() != 32 {
		return fmt.Errorf("KEK salt file %s has invalid size %d bytes (expected 32)", saltPath, saltInfo.Size())
	}

	dekPath := resolveKeyPath(enc.DEKPath)
	if strings.Contains(dekPath, "..") {
		return fmt.Errorf("DEK path is unsafe: %s", dekPath)
	}
	dekInfo, err := os.Stat(dekPath)
	if err != nil {
		return fmt.Errorf("wrapped DEK file not found: %s", dekPath)
	}
	const minWrappedDEKSize = 60 // 12-byte GCM nonce + 32-byte key + 16-byte tag
	if dekInfo.Size() < minWrappedDEKSize {
		return fmt.Errorf("wrapped DEK file %s is too small (%d bytes) to be a valid wrapped key", dekPath, dekInfo.Size())
	}
	return nil
}

// resolveKeyPath maps a configured key path to its on-disk location, mirroring
// the baseDir resolution the server uses at startup: absolute paths are used
// as-is, relative paths are resolved against the working directory.
func resolveKeyPath(p string) string {
	if filepath.IsAbs(p) {
		return filepath.Clean(p)
	}
	return filepath.Clean(filepath.Join(".", p))
}

func validateDatabase(cfg *config.Config, result *ValidationResult) error {
	dbPath := filepath.Clean(cfg.Storage.Database.Path)

	if strings.Contains(dbPath, "..") || !filepath.IsAbs(dbPath) {
		return fmt.Errorf("unsafe or relative database path: %s", dbPath)
	}

	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		result.Warnings = append(result.Warnings, fmt.Sprintf("Database file does not exist: %s (will be created on first use)", dbPath))
		return nil
	}

	file, err := os.Open(dbPath)
	if err != nil {
		return fmt.Errorf("cannot open database file %s: %w", dbPath, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("failed to close database file: %w", err)
	}

	return nil
}

func PrintValidationResult(result *ValidationResult) {
	fmt.Println("🔍 Startup Validation Results")
	fmt.Println("============================")

	printStatus := func(name string, ok bool) {
		if ok {
			fmt.Printf("%-13s: %s\n", name, statusPass)
		} else {
			fmt.Printf("%-13s: %s\n", name, statusFail)
		}
	}

	printStatus("Configuration", result.ConfigValid)
	printStatus("Permissions", result.PermissionsOK)
	printStatus("Encryption", result.EncryptionOK)
	printStatus("Database", result.DatabaseOK)

	if len(result.Warnings) > 0 {
		fmt.Println("\n⚠️  Warnings:")
		for _, w := range result.Warnings {
			fmt.Printf("   • %s\n", w)
		}
	}
	if len(result.Errors) > 0 {
		fmt.Println("\n❌ Errors:")
		for _, e := range result.Errors {
			fmt.Printf("   • %s\n", e)
		}
	}

	if result.ConfigValid && result.PermissionsOK && result.EncryptionOK && result.DatabaseOK {
		fmt.Println("\n🎉 All validations passed!")
	} else {
		fmt.Println("\n⚠️  Some validations failed. Please review the output above.")
	}
}
