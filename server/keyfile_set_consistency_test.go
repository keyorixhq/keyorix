// keyfile_set_consistency_test.go -- ADR-112 (follow-up from #2400):
// server-level wiring for internal/keyfiles.VerifyKeySetConsistency. The
// check's own logic is covered in internal/keyfiles/consistency_test.go;
// these tests cover verifyKeyFileSetConsistency's config-gating and the
// real baseDir="." resolution server/main.go actually uses.
package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
)

// Encryption disabled entirely: no-op regardless of what's on disk.
func TestVerifyKeyFileSetConsistency_EncryptionDisabled_NoOp(t *testing.T) {
	cfg := &config.Config{}
	if err := verifyKeyFileSetConsistency(cfg); err != nil {
		t.Errorf("encryption disabled must be a no-op: %v", err)
	}
}

// Encryption enabled, neither file exists yet: a fresh install, must pass.
func TestVerifyKeyFileSetConsistency_FreshInstall_Passes(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	cfg := &config.Config{}
	cfg.Storage.Encryption.Enabled = true
	cfg.Storage.Encryption.SaltPath = "kek.salt"
	cfg.Storage.Encryption.DEKPath = "dek.key"
	if err := verifyKeyFileSetConsistency(cfg); err != nil {
		t.Errorf("fresh install (neither file exists) must pass: %v", err)
	}
}

// A partial set (salt present, DEK missing), resolved against the real
// baseDir="." this function hardcodes, must fail closed.
func TestVerifyKeyFileSetConsistency_PartialSet_FailsClosed(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.WriteFile(filepath.Join(dir, "kek.salt"), []byte("x"), 0600); err != nil {
		t.Fatalf("write salt: %v", err)
	}
	cfg := &config.Config{}
	cfg.Storage.Encryption.Enabled = true
	cfg.Storage.Encryption.SaltPath = "kek.salt"
	cfg.Storage.Encryption.DEKPath = "dek.key"
	if err := verifyKeyFileSetConsistency(cfg); err == nil {
		t.Error("a partial set (salt present, DEK missing) must fail closed")
	}
}

// A complete, same-generation set must pass.
func TestVerifyKeyFileSetConsistency_CompleteSet_Passes(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	now := time.Now()
	salt := filepath.Join(dir, "kek.salt")
	dek := filepath.Join(dir, "dek.key")
	if err := os.WriteFile(salt, []byte("x"), 0600); err != nil {
		t.Fatalf("write salt: %v", err)
	}
	if err := os.WriteFile(dek, []byte("y"), 0600); err != nil {
		t.Fatalf("write dek: %v", err)
	}
	if err := os.Chtimes(salt, now, now); err != nil {
		t.Fatalf("chtimes salt: %v", err)
	}
	if err := os.Chtimes(dek, now, now); err != nil {
		t.Fatalf("chtimes dek: %v", err)
	}
	cfg := &config.Config{}
	cfg.Storage.Encryption.Enabled = true
	cfg.Storage.Encryption.SaltPath = "kek.salt"
	cfg.Storage.Encryption.DEKPath = "dek.key"
	if err := verifyKeyFileSetConsistency(cfg); err != nil {
		t.Errorf("a complete, same-generation set must pass: %v", err)
	}
}
