package startup

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/keyfiles"
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

// ValidateStartup performs comprehensive startup validation. forceAutoFix, when
// true, remediates file-permission issues regardless of the loaded config's
// Security.AutoFixFilePermissions setting — this is how a caller-supplied
// intent (e.g. an explicit CLI flag) takes effect without silently depending
// on a field read from the very config file being validated.
func ValidateStartup(configPath string, forceAutoFix bool) (*ValidationResult, error) {
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
	if err := cfg.Validate(); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Config schema validation failed: %v", err))
		return result, fmt.Errorf("configuration validation failed: %w", err)
	}
	result.ConfigValid = true

	if cfg.Security.EnableFilePermissionCheck {
		if err := validateFilePermissions(cfg, configPath, forceAutoFix, result); err != nil {
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

// SafeFilePermPath cleans path and rejects it if the cleaned form still
// contains a ".." segment. Unlike validateEncryption/validateDatabase (whose
// paths come from a small, fixed set of config fields dedicated to a single
// key/db file), the paths collected here span several independently-authored
// config fields (config path, key paths, TLS cert/key paths, db path) that
// FixFilePerms below will Lstat/Chmod/Chown — so every one of them is
// sanitized the same way before it is ever added to that list, closing off a
// config-driven path-traversal into chmod/chown of an unintended file.
func SafeFilePermPath(label, path string) (string, error) {
	clean := filepath.Clean(path)
	if strings.Contains(clean, "..") {
		return "", fmt.Errorf("%s path is unsafe (contains '..'): %s", label, path)
	}
	return clean, nil
}

func validateFilePermissions(cfg *config.Config, configPath string, forceAutoFix bool, result *ValidationResult) error { // NOSONAR -- cognitive complexity 27, suppress go:S3776
	var files []securefiles.FilePermSpec

	// Check the config file that was actually loaded, not a hardcoded "keyorix.yaml":
	// the loader resolves KEYORIX_CONFIG_PATH / an absolute path, so a fixed relative
	// name would silently stat a non-existent file and pass. Skip only when truly unknown.
	if cfgFile := strings.TrimSpace(configPath); cfgFile != "" {
		clean, err := SafeFilePermPath("config file", cfgFile)
		if err != nil {
			return err
		}
		files = append(files, securefiles.FilePermSpec{Path: clean, Mode: 0600})
	}

	if cfg.Storage.Encryption.Enabled {
		// The KEK salt and wrapped DEK (ADR-004) are always present; a TPM/cloud-KMS
		// key_provider (ADR-038/ADR-041) adds a separate wrapped-KEK blob, and a
		// shamir key_provider's share files are also key material -- see
		// internal/keyfiles.Registry, the single enumeration every key-permission
		// checker in this repo shares (this function used to hand-build a
		// salt+DEK-only list here, which is exactly how the wrapped-KEK blob went
		// unchecked for every TPM/KMS deployment).
		specs, err := keyfiles.Registry(&cfg.Storage.Encryption, ".")
		if err != nil {
			return err
		}
		files = append(files, specs...)
	}

	// Mirror Config.Validate()'s switch on Storage.Type: only "local"/"" storage has a
	// local database FILE to lock down. postgres/remote connect over the network (DSN or
	// host/name/user, or the remote client's own auth) and legitimately have an empty
	// Database.Path — appending it unconditionally would stat/chmod the current directory
	// (filepath.Clean("") == ".") instead of skipping the check.
	switch cfg.Storage.Type {
	case "remote", "postgres", "postgresql":
		// no local database file to check
	default: // "local", ""
		if cfg.Storage.Database.Path != "" {
			dbPath, err := SafeFilePermPath("database", cfg.Storage.Database.Path)
			if err != nil {
				return err
			}
			files = append(files, securefiles.FilePermSpec{
				Path: dbPath,
				Mode: 0600,
			})
		}
	}

	if cfg.Server.HTTP.TLS.Enabled {
		certPath, err := SafeFilePermPath("HTTP TLS cert", cfg.Server.HTTP.TLS.CertFile)
		if err != nil {
			return err
		}
		keyPath, err := SafeFilePermPath("HTTP TLS key", cfg.Server.HTTP.TLS.KeyFile)
		if err != nil {
			return err
		}
		files = append(files,
			securefiles.FilePermSpec{Path: certPath, Mode: 0600},
			securefiles.FilePermSpec{Path: keyPath, Mode: 0600},
		)
	}
	if cfg.Server.GRPC.TLS.Enabled {
		certPath, err := SafeFilePermPath("gRPC TLS cert", cfg.Server.GRPC.TLS.CertFile)
		if err != nil {
			return err
		}
		keyPath, err := SafeFilePermPath("gRPC TLS key", cfg.Server.GRPC.TLS.KeyFile)
		if err != nil {
			return err
		}
		files = append(files,
			securefiles.FilePermSpec{Path: certPath, Mode: 0600},
			securefiles.FilePermSpec{Path: keyPath, Mode: 0600},
		)
	}

	autoFix := cfg.Security.AutoFixFilePermissions || forceAutoFix
	if err := securefiles.FixFilePerms(files, autoFix); err != nil {
		return fmt.Errorf("file permission validation failed: %w", err)
	}

	if autoFix {
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
	// Mirror Config.Validate()'s switch on Storage.Type: only "local"/"" storage is a
	// local SQLite file reachable by stat/open. postgres/remote reach their backing store
	// over the network and are out of scope for a local-file reachability check here.
	switch cfg.Storage.Type {
	case "remote":
		result.Warnings = append(result.Warnings, "Database reachability check skipped: storage.type is \"remote\" (network client, not a local file)")
		return nil
	case "postgres", "postgresql":
		result.Warnings = append(result.Warnings, "Database reachability check skipped: storage.type is \"postgres\" (network connection, not a local file)")
		return nil
	}

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
