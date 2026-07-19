package encryption

// keymanager_kek_rotation_test.go — unit tests for RotateKEKPassphrase.
//
// All tests use real temp directories (t.TempDir()) since the feature exercises
// file I/O: reading the current salt, writing .pending files, and atomically
// renaming them into place.

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
)

// newPassphraseService creates an initialized Service with a password provider
// in a fresh temp directory and returns both the service and the directory.
func newPassphraseService(t *testing.T, passphrase string) (*Service, string) {
	t.Helper()
	dir := t.TempDir()
	cfg := &config.EncryptionConfig{
		Enabled:  true,
		DEKPath:  "dek.key",
		SaltPath: "kek.salt",
	}
	svc := NewService(cfg, dir)
	if err := svc.Initialize(passphrase); err != nil {
		t.Fatalf("initialize service: %v", err)
	}
	return svc, dir
}

// TestRotateKEKPassphrase_SuccessChangesSalt verifies that after KEK rotation:
//  1. The salt file on disk is different from the original salt.
//  2. The old passphrase no longer unwraps the DEK (new KEK = new salt + new passphrase).
//  3. The new passphrase correctly unwraps the DEK from a fresh service.
func TestRotateKEKPassphrase_SuccessChangesSalt(t *testing.T) {
	const (
		oldPass = "old-correct-horse-battery-staple"
		newPass = "new-tr0ub4dor&3"
	)

	dir := t.TempDir()
	cfg := &config.EncryptionConfig{
		Enabled:  true,
		DEKPath:  "dek.key",
		SaltPath: "kek.salt",
	}
	svc := NewService(cfg, dir)
	if err := svc.Initialize(oldPass); err != nil {
		t.Fatalf("initialize: %v", err)
	}
	defer svc.Shutdown()

	// Capture the salt before rotation.
	saltBefore, err := os.ReadFile(filepath.Join(dir, "kek.salt"))
	if err != nil {
		t.Fatalf("read salt before: %v", err)
	}

	if err := svc.RotateKEKPassphrase(oldPass, newPass); err != nil {
		t.Fatalf("RotateKEKPassphrase: %v", err)
	}

	// Salt file must have changed.
	saltAfter, err := os.ReadFile(filepath.Join(dir, "kek.salt"))
	if err != nil {
		t.Fatalf("read salt after: %v", err)
	}
	if bytes.Equal(saltBefore, saltAfter) {
		t.Fatal("salt did not change after KEK rotation")
	}

	// Old passphrase must no longer unwrap the DEK.
	svcOld := NewService(cfg, dir)
	if err := svcOld.Initialize(oldPass); err == nil {
		svcOld.Shutdown()
		t.Fatal("old passphrase still unwraps DEK after KEK rotation — expected failure")
	}

	// New passphrase must successfully unwrap the DEK.
	svcNew := NewService(cfg, dir)
	if err := svcNew.Initialize(newPass); err != nil {
		t.Fatalf("new passphrase failed to open DEK after KEK rotation: %v", err)
	}
	defer svcNew.Shutdown()
}

// TestRotateKEKPassphrase_WrongOldPassphrase_Fails verifies that an incorrect
// old passphrase is rejected before any file is modified.
func TestRotateKEKPassphrase_WrongOldPassphrase_Fails(t *testing.T) {
	const correctPass = "correct-passphrase"
	svc, dir := newPassphraseService(t, correctPass)
	defer svc.Shutdown()

	saltBefore, _ := os.ReadFile(filepath.Join(dir, "kek.salt"))
	dekBefore, _ := os.ReadFile(filepath.Join(dir, "dek.key"))

	err := svc.RotateKEKPassphrase("wrong-passphrase", "new-passphrase")
	if err == nil {
		t.Fatal("expected error for wrong old passphrase, got nil")
	}

	// Neither file must have changed.
	saltAfter, _ := os.ReadFile(filepath.Join(dir, "kek.salt"))
	dekAfter, _ := os.ReadFile(filepath.Join(dir, "dek.key"))

	if !bytes.Equal(saltBefore, saltAfter) {
		t.Error("salt changed even though old passphrase was wrong")
	}
	if !bytes.Equal(dekBefore, dekAfter) {
		t.Error("dek.key changed even though old passphrase was wrong")
	}
}

// TestRotateKEKPassphrase_EmptyNewPassphrase_Fails verifies that an empty new
// passphrase is rejected immediately (input validation, no file access).
func TestRotateKEKPassphrase_EmptyNewPassphrase_Fails(t *testing.T) {
	svc, _ := newPassphraseService(t, "correct-passphrase")
	defer svc.Shutdown()

	if err := svc.RotateKEKPassphrase("correct-passphrase", ""); err == nil {
		t.Fatal("expected error for empty new passphrase, got nil")
	}
}

// TestRotateKEKPassphrase_EmptyOldPassphrase_Fails verifies that an empty old
// passphrase is rejected immediately.
func TestRotateKEKPassphrase_EmptyOldPassphrase_Fails(t *testing.T) {
	svc, _ := newPassphraseService(t, "correct-passphrase")
	defer svc.Shutdown()

	if err := svc.RotateKEKPassphrase("", "new-passphrase"); err == nil {
		t.Fatal("expected error for empty old passphrase, got nil")
	}
}

// TestRotateKEKPassphrase_SamePassphrase_Allowed verifies that rotating to the
// same passphrase is allowed (salt is regenerated, so the wrapping genuinely
// changes; this is a valid idempotency / re-salt operation).
func TestRotateKEKPassphrase_SamePassphrase_Allowed(t *testing.T) {
	const pass = "same-passphrase"
	svc, dir := newPassphraseService(t, pass)
	defer svc.Shutdown()

	saltBefore, _ := os.ReadFile(filepath.Join(dir, "kek.salt"))

	if err := svc.RotateKEKPassphrase(pass, pass); err != nil {
		t.Fatalf("same-passphrase KEK rotation failed: %v", err)
	}

	saltAfter, _ := os.ReadFile(filepath.Join(dir, "kek.salt"))
	// Salt must change even for same passphrase (fresh random salt).
	if bytes.Equal(saltBefore, saltAfter) {
		t.Error("salt did not change for same-passphrase rotation")
	}

	// Verify the passphrase still works after re-salting.
	cfg := &config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}
	svcNew := NewService(cfg, dir)
	if err := svcNew.Initialize(pass); err != nil {
		t.Fatalf("passphrase failed after same-passphrase rotation: %v", err)
	}
	defer svcNew.Shutdown()
}

// TestRotateKEKPassphrase_EvidenceKeyChanges verifies that the evidence-signing
// key fingerprint differs after KEK rotation (because it is KEK-derived).
func TestRotateKEKPassphrase_EvidenceKeyChanges(t *testing.T) {
	const (
		oldPass = "old-evidence-test-pass"
		newPass = "new-evidence-test-pass"
	)
	svc, _ := newPassphraseService(t, oldPass)
	defer svc.Shutdown()

	_, eskIDBefore, ok := svc.EvidenceSignKey()
	if !ok {
		t.Fatal("EvidenceSignKey unavailable before KEK rotation")
	}

	if err := svc.RotateKEKPassphrase(oldPass, newPass); err != nil {
		t.Fatalf("RotateKEKPassphrase: %v", err)
	}

	_, eskIDAfter, ok := svc.EvidenceSignKey()
	if !ok {
		t.Fatal("EvidenceSignKey unavailable after KEK rotation")
	}
	if eskIDBefore == eskIDAfter {
		t.Fatalf("evidence-signing key fingerprint did not change after KEK rotation: %q", eskIDAfter)
	}
}

// TestRotateKEKPassphrase_AuditCheckpointKeyChanges verifies that the
// audit-checkpoint key fingerprint differs after KEK rotation.
func TestRotateKEKPassphrase_AuditCheckpointKeyChanges(t *testing.T) {
	const (
		oldPass = "old-audit-test-pass"
		newPass = "new-audit-test-pass"
	)
	svc, _ := newPassphraseService(t, oldPass)
	defer svc.Shutdown()

	_, ackIDBefore, ok := svc.AuditCheckpointKey()
	if !ok {
		t.Fatal("AuditCheckpointKey unavailable before KEK rotation")
	}

	if err := svc.RotateKEKPassphrase(oldPass, newPass); err != nil {
		t.Fatalf("RotateKEKPassphrase: %v", err)
	}

	_, ackIDAfter, ok := svc.AuditCheckpointKey()
	if !ok {
		t.Fatal("AuditCheckpointKey unavailable after KEK rotation")
	}
	if ackIDBefore == ackIDAfter {
		t.Fatalf("audit-checkpoint key fingerprint did not change after KEK rotation: %q", ackIDAfter)
	}
}

// TestRotateKEKPassphrase_DEKValueUnchanged verifies that the plaintext DEK
// value is identical before and after KEK rotation: data encrypted before the
// rotation must still decrypt successfully after it.
func TestRotateKEKPassphrase_DEKValueUnchanged(t *testing.T) {
	const (
		oldPass  = "old-dek-unchanged-pass"
		newPass  = "new-dek-unchanged-pass"
		secret   = "plaintext-that-must-survive-kek-rotation"
	)

	dir := t.TempDir()
	cfg := &config.EncryptionConfig{
		Enabled:  true,
		DEKPath:  "dek.key",
		SaltPath: "kek.salt",
	}

	// Initialize and encrypt a value before rotation.
	svc := NewService(cfg, dir)
	if err := svc.Initialize(oldPass); err != nil {
		t.Fatalf("initialize: %v", err)
	}
	ciphertext, _, err := svc.EncryptSecret([]byte(secret))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// Capture DEK bytes before rotation.
	dekBefore := captureCurrentDEK(t, svc)

	if err := svc.RotateKEKPassphrase(oldPass, newPass); err != nil {
		svc.Shutdown()
		t.Fatalf("RotateKEKPassphrase: %v", err)
	}
	svc.Shutdown()

	// Open a fresh service with the new passphrase (simulates server restart).
	svcNew := NewService(cfg, dir)
	if err := svcNew.Initialize(newPass); err != nil {
		t.Fatalf("open with new passphrase: %v", err)
	}
	defer svcNew.Shutdown()

	// DEK value must be identical (re-derived from the on-disk key).
	dekAfter := captureCurrentDEK(t, svcNew)
	if !bytes.Equal(dekBefore, dekAfter) {
		t.Fatalf("DEK value changed across KEK rotation: before=%x after=%x", dekBefore, dekAfter)
	}

	// Pre-rotation ciphertext must still decrypt successfully.
	plaintext, err := svcNew.DecryptSecret(ciphertext)
	if err != nil {
		t.Fatalf("decrypt pre-rotation ciphertext with new passphrase: %v", err)
	}
	if string(plaintext) != secret {
		t.Fatalf("plaintext mismatch: got %q want %q", plaintext, secret)
	}
}

// TestRotateKEKPassphrase_RequiresInitializedManager verifies that calling
// RotateKEKPassphrase on an uninitialized KeyManager returns an error.
func TestRotateKEKPassphrase_RequiresInitializedManager(t *testing.T) {
	dir := t.TempDir()
	km := NewKeyManager(dir, "dek.key", "kek.salt")
	if err := km.RotateKEKPassphrase("old", "new"); err == nil {
		t.Fatal("expected error for uninitialized manager, got nil")
	}
}

// TestRotateKEKPassphrase_NoPendingFilesLeft verifies that no .pending files
// remain on disk after a successful rotation.
func TestRotateKEKPassphrase_NoPendingFilesLeft(t *testing.T) {
	const (
		oldPass = "old-pending-test"
		newPass = "new-pending-test"
	)
	svc, dir := newPassphraseService(t, oldPass)
	defer svc.Shutdown()

	if err := svc.RotateKEKPassphrase(oldPass, newPass); err != nil {
		t.Fatalf("RotateKEKPassphrase: %v", err)
	}

	// dek.key.pending must not exist.
	if _, err := os.Stat(filepath.Join(dir, "dek.key.pending")); !os.IsNotExist(err) {
		t.Errorf("dek.key.pending still exists after successful rotation (stat err: %v)", err)
	}
	// kek.salt.pending must not exist.
	if _, err := os.Stat(filepath.Join(dir, "kek.salt.pending")); !os.IsNotExist(err) {
		t.Errorf("kek.salt.pending still exists after successful rotation (stat err: %v)", err)
	}
}
