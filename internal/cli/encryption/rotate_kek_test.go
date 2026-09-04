package encryption

// rotate_kek_test.go — integration tests for the rotate-kek CLI command.
//
// Exercises rotateKEKWithConfig — the testable core of runRotateKEK — directly,
// using real temp key directories so the file I/O (read salt, write .pending
// files, atomic rename) is fully exercised without a running server or database.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/crypto"
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

// TestRotateKEKCommand_NewPassphraseFDSource proves --new-passphrase-fd
// (ADR-099) reaches rotateKEKWithConfig end to end via a real file
// descriptor, winning over KEYORIX_NEW_MASTER_PASSWORD when both are set.
func TestRotateKEKCommand_NewPassphraseFDSource(t *testing.T) {
	const (
		oldPass = "fd-source-old-passphrase"
		newPass = "fd-sourced-new-passphrase"
	)

	dir := t.TempDir()
	t.Chdir(dir)

	cfg := enabledLocalCfgKEK()
	svc := encryption.NewService(&cfg.Storage.Encryption, dir)
	if err := svc.Initialize(oldPass); err != nil {
		t.Fatalf("provision key material: %v", err)
	}
	svc.Shutdown()

	t.Setenv("KEYORIX_MASTER_PASSWORD", oldPass)
	t.Setenv("KEYORIX_NEW_MASTER_PASSWORD", "wrong-passphrase-must-not-be-used")

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	go func() {
		_, _ = w.Write([]byte(newPass + "\n"))
		_ = w.Close()
	}()
	old := rotateKEKNewPassphraseSource
	rotateKEKNewPassphraseSource = crypto.PassphraseSource{FD: int(r.Fd()), FDSet: true}
	t.Cleanup(func() { rotateKEKNewPassphraseSource = old; _ = r.Close() })

	if err := rotateKEKWithConfig(cfg, true); err != nil {
		t.Fatalf("rotateKEKWithConfig: %v", err)
	}

	svcNew := encryption.NewService(&cfg.Storage.Encryption, dir)
	if err := svcNew.Initialize(newPass); err != nil {
		t.Fatalf("fd-sourced new passphrase rejected after rotation: %v", err)
	}
	svcNew.Shutdown()
}

// ── runRotateKEK: the thin cobra shim (config.Load + delegate) ──────────────
//
// The tests above all exercise rotateKEKWithConfig directly. runRotateKEK
// itself — config.Load("") via loadConfig(), then delegate to
// rotateKEKWithConfig — was entirely untested (0% coverage), so these two
// tests drive it via rotateKEKCmd.RunE, following the same
// KEYORIX_CONFIG_PATH-driven convention TestRunValidateAuthEncryption_
// ConfigLoadError (cli_encryption_s17_test.go) already established for the
// sibling *Cmd.RunE shims.

// TestRunRotateKEKCommand_ConfigLoadError verifies runRotateKEK's first error
// branch: loadConfig() fails when there is no keyorix.yaml discoverable, and
// the error is wrapped with "failed to load configuration".
func TestRunRotateKEKCommand_ConfigLoadError(t *testing.T) {
	t.Chdir(t.TempDir()) // no keyorix.yaml → config.Load("") returns an error
	t.Setenv("KEYORIX_CONFIG_PATH", "")

	err := rotateKEKCmd.RunE(rotateKEKCmd, nil)
	if err == nil {
		t.Fatal("expected config-load error, got nil")
	}
	if !strings.Contains(err.Error(), "failed to load configuration") {
		t.Errorf("expected 'failed to load configuration' in error, got: %v", err)
	}
}

// TestRunRotateKEKCommand_DelegatesToWithConfig verifies runRotateKEK's
// success branch: once loadConfig() succeeds, it must delegate straight to
// rotateKEKWithConfig(cfg, rotateKEKConfirm) rather than swallowing the
// config or silently no-op'ing. A config with encryption disabled makes
// rotateKEKWithConfig return a specific, recognizable error, proving the
// delegation actually happened (not just "config loaded, function returned
// nil for an unrelated reason").
func TestRunRotateKEKCommand_DelegatesToWithConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "keyorix.yaml")
	const yaml = `
storage:
  type: local
  encryption:
    enabled: false
`
	if err := os.WriteFile(cfgPath, []byte(yaml), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv("KEYORIX_CONFIG_PATH", cfgPath)

	old := rotateKEKConfirm
	rotateKEKConfirm = false
	t.Cleanup(func() { rotateKEKConfirm = old })

	err := rotateKEKCmd.RunE(rotateKEKCmd, nil)
	if err == nil || !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("expected rotateKEKWithConfig's disabled-encryption error to surface through runRotateKEK, got: %v", err)
	}
}

// ── rotateKEKWithConfig: remaining error branches ────────────────────────────

// TestRotateKEKCommand_RequiresMasterPassphraseEnv verifies that a missing
// KEYORIX_MASTER_PASSWORD (old passphrase) causes an error before any key
// file is touched, distinct from the already-covered missing-NEW-passphrase
// case.
func TestRotateKEKCommand_RequiresMasterPassphraseEnv(t *testing.T) {
	t.Setenv("KEYORIX_MASTER_PASSWORD", "")
	t.Setenv("KEYORIX_NEW_MASTER_PASSWORD", "irrelevant-new-pass")

	cfg := enabledLocalCfgKEK()
	err := rotateKEKWithConfig(cfg, true)
	if err == nil || !strings.Contains(err.Error(), "KEYORIX_MASTER_PASSWORD") {
		t.Fatalf("expected missing-old-passphrase rejection, got: %v", err)
	}
}

// TestRotateKEKCommand_WrongOldPassphraseRejected verifies that Initialize
// fails (and rotateKEKWithConfig surfaces a clear error) when
// KEYORIX_MASTER_PASSWORD does not match the passphrase the key material was
// actually provisioned with.
func TestRotateKEKCommand_WrongOldPassphraseRejected(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	cfg := enabledLocalCfgKEK()
	svc := encryption.NewService(&cfg.Storage.Encryption, dir)
	if err := svc.Initialize("the-real-old-passphrase"); err != nil {
		t.Fatalf("provision key material: %v", err)
	}
	svc.Shutdown()

	t.Setenv("KEYORIX_MASTER_PASSWORD", "not-the-real-passphrase")
	t.Setenv("KEYORIX_NEW_MASTER_PASSWORD", "some-new-passphrase")

	err := rotateKEKWithConfig(cfg, true)
	if err == nil || !strings.Contains(err.Error(), "failed to initialize encryption") {
		t.Fatalf("expected wrong-old-passphrase initialization failure, got: %v", err)
	}
}

// TestRotateKEKCommand_RefusedWhileLockHeld proves rotateKEKWithConfig fails
// fast, via AcquireExclusiveKeyLock, when another process (simulated here by
// a second Service instance) already holds the key directory — mirroring
// TestValidateWithConfig_RefusedWhileServerHoldsLock in local_key_lock_test.go.
func TestRotateKEKCommand_RefusedWhileLockHeld(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	const oldPass = "kek-lock-held-old-passphrase"
	cfg := enabledLocalCfgKEK()

	setup := encryption.NewService(&cfg.Storage.Encryption, dir)
	if err := setup.Initialize(oldPass); err != nil {
		t.Fatalf("provision key material: %v", err)
	}
	setup.Shutdown()

	// Simulate a live server (or an in-progress rotation) holding the key
	// directory exclusively.
	serverSvc := encryption.NewService(&cfg.Storage.Encryption, dir)
	if err := serverSvc.Initialize(oldPass); err != nil {
		t.Fatalf("simulated server init: %v", err)
	}
	if err := serverSvc.AcquireExclusiveKeyLock(); err != nil {
		t.Fatalf("simulated server failed to acquire the exclusive key lock: %v", err)
	}
	defer serverSvc.Shutdown()

	t.Setenv("KEYORIX_MASTER_PASSWORD", oldPass)
	t.Setenv("KEYORIX_NEW_MASTER_PASSWORD", "kek-lock-held-new-passphrase")

	err := rotateKEKWithConfig(cfg, true)
	if err == nil {
		t.Fatal("expected rotate-kek to be refused while a live server holds the exclusive key lock")
	}
	if !strings.Contains(err.Error(), "refusing to rotate KEK") {
		t.Errorf("expected a clear, actionable error mentioning the refusal, got: %v", err)
	}
}

// TestRotateKEKCommand_RotateFailsOnReadOnlyKeyDir drives service.
// RotateKEKPassphrase itself into an error, covering rotateKEKWithConfig's
// "KEK rotation failed: %w" wrap — the only branch of rotateKEKWithConfig none
// of the tests above reach. Once the key directory is made read-only,
// commitNewKEKFiles can't create kek.salt.pending (a brand-new directory
// entry, unlike dek.lock/dek.key/kek.salt which already exist and so only need
// read/write on the file itself, not the directory).
func TestRotateKEKCommand_RotateFailsOnReadOnlyKeyDir(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: a read-only directory doesn't block writes")
	}

	const (
		oldPass = "kek-readonly-dir-old-passphrase"
		newPass = "kek-readonly-dir-new-passphrase"
	)

	dir := t.TempDir()
	t.Chdir(dir)
	cfg := enabledLocalCfgKEK()

	setup := encryption.NewService(&cfg.Storage.Encryption, dir)
	if err := setup.Initialize(oldPass); err != nil {
		t.Fatalf("provision key material: %v", err)
	}
	// Pre-create dek.lock (acquire + release) so rotateKEKWithConfig's own
	// AcquireExclusiveKeyLock call — which opens it with O_CREATE — still
	// succeeds once the directory below is made read-only: opening an EXISTING
	// file only needs directory *search* (execute) permission, not write.
	if err := setup.AcquireExclusiveKeyLock(); err != nil {
		t.Fatalf("pre-provision dek.lock: %v", err)
	}
	setup.Shutdown()

	if err := os.Chmod(dir, 0555); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0755) })

	t.Setenv("KEYORIX_MASTER_PASSWORD", oldPass)
	t.Setenv("KEYORIX_NEW_MASTER_PASSWORD", newPass)

	err := rotateKEKWithConfig(cfg, true)
	if err == nil {
		t.Fatal("expected rotation to fail when the key directory is read-only")
	}
	if !strings.Contains(err.Error(), "KEK rotation failed") {
		t.Errorf("expected the RotateKEKPassphrase error to be wrapped as 'KEK rotation failed', got: %v", err)
	}
}
