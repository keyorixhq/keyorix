package encryption

// local_key_lock_test.go — end-to-end pin for #196: local, short-lived
// key-management CLI commands (status/validate/fix-perms/upgrade-aad/init)
// now participate in the same dek.lock coordination the server and
// RotateDEKWithSweep already use, via initLocalKeyOpService's
// AcquireSharedKeyLock call. Exercised here through validateWithConfig, the
// simplest of the wired commands (no database dependency).
//
// The unit-level lock-primitive tests (AcquireSharedKeyLock's own mutual-
// exclusion/refusal semantics) live in internal/encryption/exclusive_lock_test.go;
// this test proves the CLI entry point actually reaches that primitive and
// surfaces a clear, actionable error.

import (
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	enc "github.com/keyorixhq/keyorix/internal/encryption"
)

const localLockTestPassphrase = "local-key-lock-test-passphrase-123"

// newLocalLockTestConfig points cfg at a throwaway key directory (validateWithConfig
// resolves it from os.Getwd(), so the caller must t.Chdir into workDir first) and
// sets KEYORIX_MASTER_PASSWORD so masterPassphrase() succeeds.
func newLocalLockTestConfig(t *testing.T) *config.Config {
	t.Helper()
	t.Setenv("KEYORIX_MASTER_PASSWORD", localLockTestPassphrase)
	cfg := &config.Config{}
	cfg.Storage.Type = "local"
	cfg.Storage.Encryption = config.EncryptionConfig{
		Enabled:  true,
		DEKPath:  "dek.key",
		SaltPath: "kek.salt",
	}
	return cfg
}

// TestValidateWithConfig_RefusedWhileServerHoldsLock proves requirement (1):
// a local CLI operation (here, `keyorix encryption validate`) fails fast with
// a clear, actionable error when a live server (or, equally, an in-progress
// RotateDEKWithSweep — both hold the exact same exclusive dek.lock) already
// holds the key directory.
func TestValidateWithConfig_RefusedWhileServerHoldsLock(t *testing.T) {
	workDir := t.TempDir()
	t.Chdir(workDir)
	cfg := newLocalLockTestConfig(t)

	// Provision the key material once, up front (mirrors `keyorix encryption
	// init` having already run against this directory).
	setup := enc.NewService(&cfg.Storage.Encryption, workDir)
	if err := setup.Initialize(localLockTestPassphrase); err != nil {
		t.Fatalf("failed to provision key material: %v", err)
	}
	setup.Shutdown()

	// Simulate a live server (or an in-progress rotation sweep — both use
	// AcquireExclusiveKeyLock) holding the key directory exclusively.
	serverSvc := enc.NewService(&cfg.Storage.Encryption, workDir)
	if err := serverSvc.Initialize(localLockTestPassphrase); err != nil {
		t.Fatalf("failed to initialize simulated server: %v", err)
	}
	if err := serverSvc.AcquireExclusiveKeyLock(); err != nil {
		t.Fatalf("simulated server failed to acquire the exclusive key lock: %v", err)
	}
	defer serverSvc.Shutdown()

	err := validateWithConfig(cfg)
	if err == nil {
		t.Fatal("expected validate to be refused while a live server/rotation holds the exclusive key lock")
	}
	if !strings.Contains(err.Error(), "exclusively") {
		t.Errorf("expected a clear, actionable error mentioning the exclusive holder, got: %v", err)
	}
}

// TestValidateWithConfig_SucceedsWithNoServerOrRotationRunning is the
// non-regression control for requirement (2): ordinary, single-invocation CLI
// usage (the common case — no server running, no rotation in progress) must
// not be broken by requiring a lock that's never held in that scenario.
func TestValidateWithConfig_SucceedsWithNoServerOrRotationRunning(t *testing.T) {
	workDir := t.TempDir()
	t.Chdir(workDir)
	cfg := newLocalLockTestConfig(t)

	setup := enc.NewService(&cfg.Storage.Encryption, workDir)
	if err := setup.Initialize(localLockTestPassphrase); err != nil {
		t.Fatalf("failed to provision key material: %v", err)
	}
	setup.Shutdown()

	if err := validateWithConfig(cfg); err != nil {
		t.Fatalf("expected validate to succeed with no server/rotation running, got: %v", err)
	}
}
