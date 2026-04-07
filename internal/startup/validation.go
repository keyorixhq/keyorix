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
		files = append(files,
			securefiles.FilePermSpec{Path: filepath.Clean(cfg.Storage.Encryption.KEKPath), Mode: 0600},
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

func validateEncryption(cfg *config.Config, result *ValidationResult) error {
	for _, key := range []struct {
		Path string
		Name string
	}{
		{cfg.Storage.Encryption.KEKPath, "KEK"},
		{cfg.Storage.Encryption.DEKPath, "DEK"},
	} {
		path := filepath.Clean(key.Path)
		if strings.Contains(path, "..") || !filepath.IsAbs(path) {
			return fmt.Errorf("%s path is invalid or unsafe: %s", key.Name, path)
		}
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return fmt.Errorf("%s file not found: %s", key.Name, path)
		}
		if err := validateKeyFile(path, key.Name); err != nil {
			return err
		}
	}
	return nil
}

func validateKeyFile(path, keyType string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("cannot stat %s file %s: %w", keyType, path, err)
	}
	if info.Size() != 32 {
		return fmt.Errorf("%s file %s has invalid size %d bytes (expected 32)", keyType, path, info.Size())
	}
	return nil
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
