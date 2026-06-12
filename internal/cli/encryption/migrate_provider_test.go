package encryption

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/encryption"
)

func enabledLocalCfg() *config.Config {
	return &config.Config{
		Storage: config.StorageConfig{
			Type: "local",
			Encryption: config.EncryptionConfig{
				Enabled: true,
				DEKPath: "keys/dek.key",
			},
		},
	}
}

func TestMigrateProvider_RequiresConfirm(t *testing.T) {
	err := migrateProviderWithConfig(enabledLocalCfg(), migrateOpts{toType: "env", toEnvVar: "KEK"}, false)
	if err == nil || !strings.Contains(err.Error(), "--confirm") {
		t.Fatalf("expected --confirm gate, got: %v", err)
	}
}

func TestMigrateProvider_RejectsRemoteStorage(t *testing.T) {
	cfg := enabledLocalCfg()
	cfg.Storage.Type = "remote"
	err := migrateProviderWithConfig(cfg, migrateOpts{toType: "env", toEnvVar: "KEK"}, true)
	if err == nil || !strings.Contains(err.Error(), "server host") {
		t.Fatalf("expected remote-storage rejection, got: %v", err)
	}
}

func TestMigrateProvider_RejectsDisabledEncryption(t *testing.T) {
	cfg := enabledLocalCfg()
	cfg.Storage.Encryption.Enabled = false
	err := migrateProviderWithConfig(cfg, migrateOpts{toType: "env", toEnvVar: "KEK"}, true)
	if err == nil || !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("expected disabled-encryption rejection, got: %v", err)
	}
}

func TestMigrateProvider_RequiresToType(t *testing.T) {
	err := migrateProviderWithConfig(enabledLocalCfg(), migrateOpts{}, true)
	if err == nil || !strings.Contains(err.Error(), "--to-type") {
		t.Fatalf("expected --to-type requirement, got: %v", err)
	}
}

// TestMigrateProvider_EndToEnd_PasswordToEnv drives the full CLI core: it
// bootstraps a password-derived install, migrates the KEK to the env provider, and
// confirms the env provider unwraps the same DEK and a backup was kept — all
// without a database (encrypt/decrypt are key-only operations).
func TestMigrateProvider_EndToEnd_PasswordToEnv(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir) // migrateProviderWithConfig resolves key paths under cwd

	t.Setenv("KEYORIX_MASTER_PASSWORD", "Sup3r-Secret-Passphrase!")
	raw := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		t.Fatalf("gen kek: %v", err)
	}
	t.Setenv("KEYORIX_TARGET_KEK", hex.EncodeToString(raw))

	cfg := enabledLocalCfg()
	cfg.Storage.Encryption.DEKPath = "dek.key"
	cfg.Storage.Encryption.SaltPath = "kek.salt"

	opts := migrateOpts{toType: "env", toEnvVar: "KEYORIX_TARGET_KEK"}
	if err := migrateProviderWithConfig(cfg, opts, true); err != nil {
		t.Fatalf("migrate password → env: %v", err)
	}

	// A fresh service on the TARGET (env) provider must open the re-wrapped DEK and
	// round-trip a secret.
	tgt := cfg.Storage.Encryption
	tgt.KeyProvider = config.KeyProviderConfig{Type: "env", EnvVar: "KEYORIX_TARGET_KEK"}
	svc := encryption.NewService(&tgt, dir)
	if err := svc.Initialize(""); err != nil {
		t.Fatalf("open with env provider after migration: %v", err)
	}
	defer svc.Shutdown()
	ct, _, err := svc.EncryptSecret([]byte("hello"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	pt, err := svc.DecryptSecret(ct)
	if err != nil || string(pt) != "hello" {
		t.Fatalf("round-trip under env provider failed: pt=%q err=%v", pt, err)
	}

	// The previous wrapped DEK was backed up.
	matches, _ := filepath.Glob(filepath.Join(dir, "dek.key.migrate-backup.*"))
	if len(matches) == 0 {
		t.Fatalf("expected a dek.key.migrate-backup.* file")
	}
}

func TestTargetEncryptionConfig(t *testing.T) {
	cur := &config.EncryptionConfig{DEKPath: "keys/dek.key", SaltPath: "keys/kek.salt"}

	t.Run("kms requires key id", func(t *testing.T) {
		_, err := targetEncryptionConfig(cur, migrateOpts{toType: "aws-kms", toWrappedKeyPath: "keys/kek.kms"})
		if err == nil || !strings.Contains(err.Error(), "--to-kms-key-id") {
			t.Fatalf("expected kms key-id requirement, got: %v", err)
		}
	})

	t.Run("kms requires wrapped key path", func(t *testing.T) {
		_, err := targetEncryptionConfig(cur, migrateOpts{toType: "gcp-kms", toKMSKeyID: "k"})
		if err == nil || !strings.Contains(err.Error(), "--to-wrapped-key-path") {
			t.Fatalf("expected wrapped-key-path requirement, got: %v", err)
		}
	})

	t.Run("kms wrapped path must differ from dek", func(t *testing.T) {
		_, err := targetEncryptionConfig(cur, migrateOpts{toType: "azure-kms", toKMSKeyID: "k", toWrappedKeyPath: "keys/dek.key"})
		if err == nil || !strings.Contains(err.Error(), "must differ") {
			t.Fatalf("expected DEK-path collision rejection, got: %v", err)
		}
	})

	t.Run("kms ok preserves dek path", func(t *testing.T) {
		tgt, err := targetEncryptionConfig(cur, migrateOpts{toType: "azure-kms", toKMSKeyID: "https://v.vault.azure.net/keys/k", toWrappedKeyPath: "keys/kek.kms"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if tgt.DEKPath != cur.DEKPath {
			t.Fatalf("DEK path should be preserved, got %q", tgt.DEKPath)
		}
		if tgt.KeyProvider.Type != "azure-kms" || tgt.KeyProvider.WrappedKeyPath != "keys/kek.kms" {
			t.Fatalf("unexpected target provider: %+v", tgt.KeyProvider)
		}
	})

	t.Run("file requires path", func(t *testing.T) {
		_, err := targetEncryptionConfig(cur, migrateOpts{toType: "file"})
		if err == nil || !strings.Contains(err.Error(), "--to-file-path") {
			t.Fatalf("expected file-path requirement, got: %v", err)
		}
	})

	t.Run("env requires var", func(t *testing.T) {
		_, err := targetEncryptionConfig(cur, migrateOpts{toType: "env"})
		if err == nil || !strings.Contains(err.Error(), "--to-env-var") {
			t.Fatalf("expected env-var requirement, got: %v", err)
		}
	})

	t.Run("password overrides salt path", func(t *testing.T) {
		tgt, err := targetEncryptionConfig(cur, migrateOpts{toType: "password", toSaltPath: "keys/new.salt"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if tgt.SaltPath != "keys/new.salt" {
			t.Fatalf("expected salt path override, got %q", tgt.SaltPath)
		}
	})

	t.Run("unknown type", func(t *testing.T) {
		_, err := targetEncryptionConfig(cur, migrateOpts{toType: "bogus"})
		if err == nil || !strings.Contains(err.Error(), "unknown --to-type") {
			t.Fatalf("expected unknown-type error, got: %v", err)
		}
	})
}
