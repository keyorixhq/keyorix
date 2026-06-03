package startup

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
)

// writeFile writes n bytes to dir/name and returns the absolute path.
func writeKeyFile(t *testing.T, dir, name string, n int) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, make([]byte, n), 0600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

func encCfg(saltPath, dekPath string) *config.Config {
	cfg := &config.Config{}
	cfg.Storage.Encryption.Enabled = true
	cfg.Storage.Encryption.SaltPath = saltPath
	cfg.Storage.Encryption.DEKPath = dekPath
	return cfg
}

// A 32-byte salt and a wrapped DEK (>= 60 bytes) must validate. The wrapped DEK
// is never a bare 32-byte key, so the old size==32 assertion was a false failure.
func TestValidateEncryption_ValidSaltAndWrappedDEK(t *testing.T) {
	dir := t.TempDir()
	salt := writeKeyFile(t, dir, "kek.salt", 32)
	dek := writeKeyFile(t, dir, "dek.key", 60) // 12 nonce + 32 key + 16 tag

	if err := validateEncryption(encCfg(salt, dek), &ValidationResult{}); err != nil {
		t.Fatalf("expected valid config to pass, got: %v", err)
	}
}

func TestValidateEncryption_MissingSalt(t *testing.T) {
	dir := t.TempDir()
	dek := writeKeyFile(t, dir, "dek.key", 60)
	salt := filepath.Join(dir, "absent.salt")

	if err := validateEncryption(encCfg(salt, dek), &ValidationResult{}); err == nil {
		t.Fatal("expected error for missing salt file")
	}
}

func TestValidateEncryption_WrongSaltSize(t *testing.T) {
	dir := t.TempDir()
	salt := writeKeyFile(t, dir, "kek.salt", 16) // too short
	dek := writeKeyFile(t, dir, "dek.key", 60)

	if err := validateEncryption(encCfg(salt, dek), &ValidationResult{}); err == nil {
		t.Fatal("expected error for 16-byte salt (must be 32)")
	}
}

func TestValidateEncryption_DEKTooSmall(t *testing.T) {
	dir := t.TempDir()
	salt := writeKeyFile(t, dir, "kek.salt", 32)
	dek := writeKeyFile(t, dir, "dek.key", 32) // a bare key, not a wrapped one

	if err := validateEncryption(encCfg(salt, dek), &ValidationResult{}); err == nil {
		t.Fatal("expected error for 32-byte DEK (wrapped DEK is >= 60 bytes)")
	}
}

func TestResolveKeyPath(t *testing.T) {
	if got := resolveKeyPath("/app/keys/dek.key"); got != "/app/keys/dek.key" {
		t.Errorf("absolute path should pass through, got %q", got)
	}
	if got := resolveKeyPath("keys/dek.key"); got != filepath.Clean("keys/dek.key") {
		t.Errorf("relative path resolved unexpectedly: %q", got)
	}
}
