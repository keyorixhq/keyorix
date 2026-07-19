package encryption

// rotate_kek_test.go — integration tests for the rotate-kek CLI command.
//
// Exercises rotateKEKWithConfig — the testable core of runRotateKEK — directly,
// using real temp key directories so the file I/O (read salt, write .pending
// files, atomic rename) is fully exercised without a running server or database.

import (
	"os"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/encryption"
)

// enabledLocalCfgKEK returns a minimal EncryptionConfig with encryption
// enabled and local storage, pointing at default relative key paths (resolved
// under the test's cwd / temp dir).
func enabledLocalCfgKEK() *config.Config {
	return &config.Config{
		Storage: config.StorageConfig{
			Type: "local",
			Encryption: config.EncryptionConfig{
				Enabled:  true,
				DEKPath:  "dek.key",
				SaltPath: "kek.salt",
			},
		},
	}
}

// TestRotateKEKCommand_RequiresConfirm verifies that missing --confirm causes
// an early error before any key-file work.
func TestRotateKEKCommand_RequiresConfirm(t *testing.T) {
	err := rotateKEKWithConfig(enabledLocalCfgKEK(), false /*confirm=false*/)
	if err == nil || !strings.Contains(err.Error(), "--confirm") {
		t.Fatalf("expected --confirm gate, got: %v", err)
	}
}

// TestRotateKEKCommand_RejectsDisabledEncryption verifies that the command
// returns an error when encryption is disabled in config.
func TestRotateKEKCommand_RejectsDisabledEncryption(t *testing.T) {
	cfg := enabledLocalCfgKEK()
	cfg.Storage.Encryption.Enabled = false
	err := rotateKEKWithConfig(cfg, true)
	if err == nil || !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("expected disabled-encryption rejection, got: %v", err)
	}
}

// TestRotateKEKCommand_RejectsRemoteStorage verifies that the command refuses
// to run when the storage type is "remote" (must run on the server host).
func TestRotateKEKCommand_RejectsRemoteStorage(t *testing.T) {
	cfg := enabledLocalCfgKEK()
	cfg.Storage.Type = "remote"
	err := rotateKEKWithConfig(cfg, true)
	if err == nil || !strings.Contains(err.Error(), "server host") {
		t.Fatalf("expected remote-storage rejection, got: %v", err)
	}
}

// TestRotateKEKCommand_RequiresNewPassphraseEnv verifies that missing
// KEYORIX_NEW_MASTER_PASSWORD causes an error.
func TestRotateKEKCommand_RequiresNewPassphraseEnv(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	t.Setenv("KEYORIX_MASTER_PASSWORD", "old-passphrase")
	t.Setenv("KEYORIX_NEW_MASTER_PASSWORD", "") // explicitly unset

	// We need actual key files so we get past the Initialize step; alternatively
	// we can init the keys first.
	cfg := enabledLocalCfgKEK()
	svc := encryption.NewService(&cfg.Storage.Encryption, dir)
	if err := svc.Initialize("old-passphrase"); err != nil {
		t.Fatalf("init: %v", err)
	}
	svc.Shutdown()

	err := rotateKEKWithConfig(cfg, true)
	if err == nil || !strings.Contains(err.Error(), "KEYORIX_NEW_MASTER_PASSWORD") {
		t.Fatalf("expected missing-env-var rejection, got: %v", err)
	}
}

// TestRotateKEKCommand_RejectsSamePassphrase verifies that using the same
// value for old and new passphrase is rejected.
func TestRotateKEKCommand_RejectsSamePassphrase(t *testing.T) {
	const pass = "same-old-same-new"
	dir := t.TempDir()
	t.Chdir(dir)

	t.Setenv("KEYORIX_MASTER_PASSWORD", pass)
	t.Setenv("KEYORIX_NEW_MASTER_PASSWORD", pass)

	cfg := enabledLocalCfgKEK()
	svc := encryption.NewService(&cfg.Storage.Encryption, dir)
	if err := svc.Initialize(pass); err != nil {
		t.Fatalf("init: %v", err)
	}
	svc.Shutdown()

	err := rotateKEKWithConfig(cfg, true)
	if err == nil || !strings.Contains(err.Error(), "differ") {
		t.Fatalf("expected same-passphrase rejection, got: %v", err)
	}
}

// TestRotateKEKCommand_Success_OldPassphraseNoLongerWorks is the full
// end-to-end CLI test:
//  1. Init keys with old passphrase.
//  2. Run rotate-kek via rotateKEKWithConfig.
//  3. Verify old passphrase is rejected.
//  4. Verify new passphrase opens the DEK (and can decrypt pre-rotation data).
func TestRotateKEKCommand_Success_OldPassphraseNoLongerWorks(t *testing.T) {
	const (
		oldPass = "e2e-old-master-passphrase-correct"
		newPass = "e2e-new-master-passphrase-different"
		secret  = "super-secret-value-to-survive-kek-rotation"
	)

	dir := t.TempDir()
	t.Chdir(dir) // rotateKEKWithConfig resolves key paths under cwd via os.Getwd()

	t.Setenv("KEYORIX_MASTER_PASSWORD", oldPass)
	t.Setenv("KEYORIX_NEW_MASTER_PASSWORD", newPass)

	cfg := enabledLocalCfgKEK()

	// 1. Init keys and encrypt a value.
	svc := encryption.NewService(&cfg.Storage.Encryption, dir)
	if err := svc.Initialize(oldPass); err != nil {
		t.Fatalf("init with old passphrase: %v", err)
	}
	ciphertext, _, err := svc.EncryptSecret([]byte(secret))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	svc.Shutdown()

	// 2. Run rotate-kek.
	if err := rotateKEKWithConfig(cfg, true); err != nil {
		t.Fatalf("rotateKEKWithConfig: %v", err)
	}

	// 3. Old passphrase must be rejected.
	svcOld := encryption.NewService(&cfg.Storage.Encryption, dir)
	if err := svcOld.Initialize(oldPass); err == nil {
		svcOld.Shutdown()
		t.Fatal("old passphrase still accepted after KEK rotation — expected failure")
	}

	// 4. New passphrase must work and decrypt the pre-rotation ciphertext.
	svcNew := encryption.NewService(&cfg.Storage.Encryption, dir)
	if err := svcNew.Initialize(newPass); err != nil {
		t.Fatalf("new passphrase rejected after KEK rotation: %v", err)
	}
	defer svcNew.Shutdown()

	plaintext, err := svcNew.DecryptSecret(ciphertext)
	if err != nil {
		t.Fatalf("decrypt pre-rotation ciphertext with new passphrase: %v", err)
	}
	if string(plaintext) != secret {
		t.Fatalf("plaintext mismatch: got %q want %q", plaintext, secret)
	}

	// Confirm no leftover pending files.
	if _, err := os.Stat("dek.key.pending"); !os.IsNotExist(err) {
		t.Errorf("dek.key.pending still exists after successful rotation")
	}
	if _, err := os.Stat("kek.salt.pending"); !os.IsNotExist(err) {
		t.Errorf("kek.salt.pending still exists after successful rotation")
	}
}
