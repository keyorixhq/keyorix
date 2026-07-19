// coverage_test.go — targeted gap-fill tests for internal/encryption.
//
// Focus: uncovered branches in the following functions (reported by go tool cover):
//
//   - keymanager_rotation.go:28  RotateDEKWithSweep      (70.4%)
//   - keymanager_lifecycle.go:121 deriveEvidenceSignKey  (70.0%)
//   - keymanager_lifecycle.go:142 deriveAuditCheckpointKey (70.0%)
//   - keymanager_lifecycle.go:273 ensureWrappedDEKExists  (76.9%)
//   - keymanager_rotation.go:121 deleteBackupFiles        (77.8%)
//   - encryption.go:53           NewEncryptionService     (77.8%)
//   - encryption.go:93           GenerateRandomKey        (75.0%)
package encryption

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// ─── NewEncryptionService ─────────────────────────────────────────────────────

// TestNewEncryptionService_ValidKey verifies the happy path: a 32-byte key
// creates a working service that can round-trip plaintext through encrypt/decrypt.
func TestNewEncryptionService_ValidKey(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	svc, err := NewEncryptionService(key)
	if err != nil {
		t.Fatalf("NewEncryptionService(32-byte key) returned error: %v", err)
	}
	if svc == nil {
		t.Fatal("NewEncryptionService returned nil service")
	}
	// Sanity: can actually encrypt and decrypt.
	enc, err := svc.Encrypt([]byte("hello"), "v1")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	got, err := svc.Decrypt(enc)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, []byte("hello")) {
		t.Fatalf("round-trip mismatch: got %q", got)
	}
}

// TestNewEncryptionService_WrongSize verifies that keys that are not exactly 32
// bytes are rejected with an informative error (the existing test in
// encryption_test.go covers 16 bytes; this also checks 0, 31, and 33 to pin
// the size guard rather than just the AES key size).
func TestNewEncryptionService_WrongSize(t *testing.T) {
	for _, size := range []int{0, 1, 16, 24, 31, 33, 64} {
		_, err := NewEncryptionService(make([]byte, size))
		if err == nil {
			t.Errorf("NewEncryptionService(%d-byte key): expected error, got nil", size)
		}
	}
}

// ─── GenerateRandomKey ────────────────────────────────────────────────────────

// TestGenerateRandomKey_VariousSizes verifies that GenerateRandomKey honours the
// requested size for multiple sizes and that two calls for the same size yield
// different output.
func TestGenerateRandomKey_VariousSizes(t *testing.T) {
	for _, size := range []int{1, 16, 24, 32, 64} {
		key, err := GenerateRandomKey(size)
		if err != nil {
			t.Fatalf("GenerateRandomKey(%d): %v", size, err)
		}
		if len(key) != size {
			t.Errorf("GenerateRandomKey(%d): got length %d", size, len(key))
		}
	}
}

// TestGenerateRandomKey_TwoDifferentResults verifies the two-call uniqueness
// property for a key size of 32 (the main operational size).
func TestGenerateRandomKey_TwoDifferentResults(t *testing.T) {
	a, err := GenerateRandomKey(32)
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	b, err := GenerateRandomKey(32)
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("two calls to GenerateRandomKey(32) returned identical output")
	}
}

// ─── deriveEvidenceSignKey ────────────────────────────────────────────────────

// TestDeriveEvidenceSignKey_KeyAndIDHaveExpectedPrefixAndLength checks that
// the returned key is 32 bytes and the ID string has the "esk-" prefix and
// contains a hex string of 32 hex chars (16 bytes).
func TestDeriveEvidenceSignKey_KeyAndIDHaveExpectedPrefixAndLength(t *testing.T) {
	kek := make([]byte, 32)
	for i := range kek {
		kek[i] = byte(i + 7)
	}
	key, id, err := deriveEvidenceSignKey(kek)
	if err != nil {
		t.Fatalf("deriveEvidenceSignKey: %v", err)
	}
	if len(key) != 32 {
		t.Errorf("key length: got %d, want 32", len(key))
	}
	const prefix = "esk-"
	if len(id) < len(prefix)+32 {
		t.Errorf("id %q: want prefix %q followed by 32 hex chars", id, prefix)
	}
	if id[:len(prefix)] != prefix {
		t.Errorf("id %q: does not start with %q", id, prefix)
	}
}

// TestDeriveEvidenceSignKey_EmptyKEK verifies that deriving from an empty (zero-
// length) KEK still succeeds — HKDF-SHA256 is defined for any key material
// length, including zero, so this is a valid call. It is NOT an error path for
// the function itself; the caller (Initialize) is responsible for ensuring the
// KEK is a proper 32-byte value before passing it.
func TestDeriveEvidenceSignKey_EmptyKEK(t *testing.T) {
	// HKDF does not fail on empty key material; this covers the
	// "different KEK produces different output" property.
	key1, id1, err1 := deriveEvidenceSignKey([]byte{})
	key2, id2, err2 := deriveEvidenceSignKey(make([]byte, 32))
	if err1 != nil {
		t.Fatalf("empty KEK: %v", err1)
	}
	if err2 != nil {
		t.Fatalf("32-zero KEK: %v", err2)
	}
	if bytes.Equal(key1, key2) {
		t.Error("empty-KEK and zero-32-KEK produced the same signing key")
	}
	if id1 == id2 {
		t.Error("empty-KEK and zero-32-KEK produced the same signing key ID")
	}
}

// ─── deriveAuditCheckpointKey ─────────────────────────────────────────────────

// TestDeriveAuditCheckpointKey_KeyAndIDHaveExpectedPrefixAndLength mirrors the
// evidence-sign-key test, but for the audit-checkpoint derivation.
func TestDeriveAuditCheckpointKey_KeyAndIDHaveExpectedPrefixAndLength(t *testing.T) {
	kek := make([]byte, 32)
	for i := range kek {
		kek[i] = byte(i + 11)
	}
	key, id, err := deriveAuditCheckpointKey(kek)
	if err != nil {
		t.Fatalf("deriveAuditCheckpointKey: %v", err)
	}
	if len(key) != 32 {
		t.Errorf("key length: got %d, want 32", len(key))
	}
	const prefix = "ack-"
	if len(id) < len(prefix)+32 {
		t.Errorf("id %q: want prefix %q followed by 32 hex chars", id, prefix)
	}
	if id[:len(prefix)] != prefix {
		t.Errorf("id %q: does not start with %q", id, prefix)
	}
}

// TestDeriveAuditCheckpointKey_EmptyVsZeroKEK verifies domain separation for
// different KEK values (mirrors the evidence-sign-key variant).
func TestDeriveAuditCheckpointKey_EmptyVsZeroKEK(t *testing.T) {
	key1, id1, err1 := deriveAuditCheckpointKey([]byte{})
	key2, id2, err2 := deriveAuditCheckpointKey(make([]byte, 32))
	if err1 != nil {
		t.Fatalf("empty KEK: %v", err1)
	}
	if err2 != nil {
		t.Fatalf("32-zero KEK: %v", err2)
	}
	if bytes.Equal(key1, key2) {
		t.Error("empty-KEK and zero-32-KEK produced the same checkpoint key")
	}
	if id1 == id2 {
		t.Error("empty-KEK and zero-32-KEK produced the same checkpoint key ID")
	}
}

// ─── ensureWrappedDEKExists ───────────────────────────────────────────────────

// TestEnsureWrappedDEKExists_DEKAlreadyPresent verifies the "DEK file exists,
// skip" branch: Initialize on a manager whose key directory already contains a
// valid dek.key must succeed without overwriting it.
func TestEnsureWrappedDEKExists_DEKAlreadyPresent(t *testing.T) {
	dir := t.TempDir()
	km := NewKeyManager(dir, "dek.key", "kek.salt")
	if err := km.Initialize("passphrase-a"); err != nil {
		t.Fatalf("first Initialize: %v", err)
	}
	dekBefore, err := os.ReadFile(filepath.Join(dir, "dek.key"))
	if err != nil {
		t.Fatalf("read dek.key after first init: %v", err)
	}

	// Second Initialize with the SAME passphrase must reuse the existing DEK.
	km2 := NewKeyManager(dir, "dek.key", "kek.salt")
	if err := km2.Initialize("passphrase-a"); err != nil {
		t.Fatalf("second Initialize: %v", err)
	}
	dekAfter, err := os.ReadFile(filepath.Join(dir, "dek.key"))
	if err != nil {
		t.Fatalf("read dek.key after second init: %v", err)
	}
	if !bytes.Equal(dekBefore, dekAfter) {
		t.Fatal("dek.key was overwritten on second Initialize — ensureWrappedDEKExists must not regenerate an existing DEK")
	}
}

// TestEnsureWrappedDEKExists_CreatesNewDEKOnFirstRun verifies the "DEK file
// absent, create" branch: Initialize on a fresh temp directory generates and
// persists a wrapped DEK.
func TestEnsureWrappedDEKExists_CreatesNewDEKOnFirstRun(t *testing.T) {
	dir := t.TempDir()
	dekPath := filepath.Join(dir, "dek.key")

	if _, err := os.Stat(dekPath); !os.IsNotExist(err) {
		t.Fatal("precondition: dek.key must not exist before Initialize")
	}

	km := NewKeyManager(dir, "dek.key", "kek.salt")
	if err := km.Initialize("some-passphrase"); err != nil {
		t.Fatalf("Initialize: %v", err)
	}

	if _, err := os.Stat(dekPath); err != nil {
		t.Fatalf("dek.key not created by Initialize: %v", err)
	}
}

// TestEnsureWrappedDEKExists_WriteFailure verifies the write-failure branch of
// ensureWrappedDEKExists by making the key directory read-only AFTER the salt
// is written (Initialize first writes the salt, then the DEK) but BEFORE the
// DEK file is created. We achieve this by running two initializations: the
// first creates salt+DEK normally; then we remove the DEK file and make the
// directory read-only so the second attempt to write the DEK fails.
//
// Skip on Windows where chmod is not enforced for the owner.
func TestEnsureWrappedDEKExists_WriteFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chmod directory permissions not enforced on Windows")
	}
	if os.Getuid() == 0 {
		t.Skip("running as root bypasses permission checks")
	}

	dir := t.TempDir()

	// First: full successful Initialize so salt is on disk.
	km := NewKeyManager(dir, "dek.key", "kek.salt")
	if err := km.Initialize("passphrase"); err != nil {
		t.Fatalf("first Initialize: %v", err)
	}

	// Remove the DEK file but keep the salt, then lock the directory.
	dekPath := filepath.Join(dir, "dek.key")
	if err := os.Remove(dekPath); err != nil {
		t.Fatalf("remove dek.key: %v", err)
	}
	if err := os.Chmod(dir, 0555); err != nil {
		t.Fatalf("chmod dir: %v", err)
	}
	defer func() { _ = os.Chmod(dir, 0755) }()

	// Second Initialize must fail because it cannot write the new DEK.
	km2 := NewKeyManager(dir, "dek.key", "kek.salt")
	if err := km2.Initialize("passphrase"); err == nil {
		t.Fatal("expected Initialize to fail when DEK directory is read-only, but it succeeded")
	}
}

// ─── deleteBackupFiles ────────────────────────────────────────────────────────

// TestDeleteBackupFiles_EmptyDir verifies that deleteBackupFiles on a directory
// with no matching backup files does nothing and does not panic.
func TestDeleteBackupFiles_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	km := NewKeyManager(dir, "dek.key", "kek.salt")
	km.deleteBackupFiles() // must not panic or log an error
}

// TestDeleteBackupFiles_NonExistentDir verifies that deleteBackupFiles on a
// non-existent directory gracefully handles the glob pattern (filepath.Glob
// on a missing dir returns no matches, not an error, so this is a no-op).
func TestDeleteBackupFiles_NonExistentDir(t *testing.T) {
	km := NewKeyManager("/tmp/nonexistent-keyorix-dir-xyz", "dek.key", "kek.salt")
	km.deleteBackupFiles() // must not panic
}

// TestDeleteBackupFiles_RemovesBackupFilesSuccessfully verifies the happy
// path: existing dek.key.backup.* files are deleted.
func TestDeleteBackupFiles_RemovesBackupFilesSuccessfully(t *testing.T) {
	dir := t.TempDir()
	km := NewKeyManager(dir, "dek.key", "kek.salt")

	// Create matching backup files.
	for _, name := range []string{"dek.key.backup.111", "dek.key.backup.222"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("old-wrapped-dek"), 0600); err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
	}
	// A non-matching file must NOT be deleted.
	other := filepath.Join(dir, "dek.key.lock")
	if err := os.WriteFile(other, []byte("lock"), 0600); err != nil {
		t.Fatalf("create lock: %v", err)
	}

	km.deleteBackupFiles()

	for _, name := range []string{"dek.key.backup.111", "dek.key.backup.222"} {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Errorf("backup file %s should have been deleted", name)
		}
	}
	if _, err := os.Stat(other); err != nil {
		t.Errorf("non-matching file %s should NOT have been deleted: %v", other, err)
	}
}

// TestDeleteBackupFiles_RemoveFailureIsLogged verifies that a deletion error
// (here: a backup "file" is actually a directory that cannot be os.Remove'd)
// is handled gracefully — deleteBackupFiles logs the error but does not return
// or panic. The test checks that the caller is unaffected.
func TestDeleteBackupFiles_RemoveFailureIsLogged(t *testing.T) {
	dir := t.TempDir()
	km := NewKeyManager(dir, "dek.key", "kek.salt")

	// Create a directory where a backup file is expected — os.Remove on a
	// non-empty directory fails on Linux/macOS.
	badBackup := filepath.Join(dir, "dek.key.backup.999")
	if err := os.MkdirAll(filepath.Join(badBackup, "child"), 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	// Must not panic.
	km.deleteBackupFiles()
	// The directory should still exist (remove failed).
	if _, err := os.Stat(badBackup); err != nil {
		t.Errorf("expected the un-removable backup dir to still exist: %v", err)
	}
}

// ─── RotateDEKWithSweep (KeyManager level) ───────────────────────────────────

// TestKeyManager_RotateDEKWithSweep_NotInitialized verifies that calling
// RotateDEKWithSweep on an uninitialized KeyManager returns an error
// immediately (the km.currentDEK == nil guard, line 32-34).
func TestKeyManager_RotateDEKWithSweep_NotInitialized(t *testing.T) {
	dir := t.TempDir()
	km := NewKeyManager(dir, "dek.key", "kek.salt")
	err := km.RotateDEKWithSweep("any-passphrase", func(_, _ *EncryptionService, _ string) error {
		return nil
	})
	if err == nil {
		t.Fatal("expected error for uninitialized KeyManager, got nil")
	}
}

// TestKeyManager_RotateDEKWithSweep_SweepFnErrorCleanup verifies the sweep-failure
// branch: when sweepFn returns an error the pending DEK file is cleaned up,
// the in-memory currentDEK is unchanged, and the function returns an error.
func TestKeyManager_RotateDEKWithSweep_SweepFnErrorCleanup(t *testing.T) {
	dir := t.TempDir()
	km := NewKeyManager(dir, "dek.key", "kek.salt")
	if err := km.Initialize("passphrase"); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	dekBefore := km.GetDEK()

	sweepCalled := false
	err := km.RotateDEKWithSweep("passphrase", func(_, _ *EncryptionService, _ string) error {
		sweepCalled = true
		return os.ErrPermission // any non-nil error
	})
	if err == nil {
		t.Fatal("expected error when sweepFn fails, got nil")
	}
	if !sweepCalled {
		t.Fatal("sweepFn was never called")
	}
	// DEK must be unchanged.
	dekAfter := km.GetDEK()
	if !bytes.Equal(dekBefore, dekAfter) {
		t.Fatal("currentDEK changed despite sweep failure")
	}
	// pending file must be cleaned up.
	pending := filepath.Join(dir, "dek.key.pending")
	if _, err := os.Stat(pending); !os.IsNotExist(err) {
		t.Error("pending DEK file was not cleaned up after sweep failure")
	}
}

// TestKeyManager_RotateDEKWithSweep_LockFailure verifies the
// acquireExclusiveKeyLock failure branch (line 49-51): if the baseDir does not
// exist the lock file cannot be opened and RotateDEKWithSweep returns an error.
func TestKeyManager_RotateDEKWithSweep_LockFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission enforcement differs on Windows")
	}
	if os.Getuid() == 0 {
		t.Skip("running as root bypasses permission checks")
	}

	dir := t.TempDir()
	km := NewKeyManager(dir, "dek.key", "kek.salt")
	if err := km.Initialize("passphrase"); err != nil {
		t.Fatalf("Initialize: %v", err)
	}

	// Make the directory read-only so that the lock file cannot be created.
	if err := os.Chmod(dir, 0555); err != nil {
		t.Fatalf("chmod dir: %v", err)
	}
	defer func() { _ = os.Chmod(dir, 0755) }()

	// The existing lock file (if any) from Initialize won't block us from opening
	// it for reading, but a fresh lock file CAN'T be created. However the lock
	// file already exists from acquireExclusiveKeyLock during Initialize... let's
	// check if it was created then. The lock file is <dekPath>.lock.
	// Remove the existing lock file first so creation attempt will fail.
	lockPath := filepath.Join(dir, "dek.key.lock")
	_ = os.Remove(lockPath)

	err := km.RotateDEKWithSweep("passphrase", func(_, _ *EncryptionService, _ string) error {
		return nil
	})
	if err == nil {
		t.Fatal("expected error when lock file cannot be created, got nil")
	}
}

// TestKeyManager_RotateDEKWithSweep_WritePendingFailure verifies the
// SecureWriteFileSync failure branch (line 71-74): if the pending DEK file
// cannot be written the function returns an error and the original DEK is
// unchanged.
func TestKeyManager_RotateDEKWithSweep_WritePendingFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission enforcement differs on Windows")
	}
	if os.Getuid() == 0 {
		t.Skip("running as root bypasses permission checks")
	}

	dir := t.TempDir()
	km := NewKeyManager(dir, "dek.key", "kek.salt")
	if err := km.Initialize("passphrase"); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	dekBefore := km.GetDEK()

	// Make the directory read-only AFTER initialization — the existing files
	// (dek.key, kek.salt, dek.key.lock) are present but new writes will fail.
	if err := os.Chmod(dir, 0555); err != nil {
		t.Fatalf("chmod dir: %v", err)
	}
	defer func() { _ = os.Chmod(dir, 0755) }()

	// Remove the existing lock file so acquireExclusiveKeyLock also fails, OR
	// keep it so acquireExclusiveKeyLock succeeds (it's a read-open). The lock
	// file already exists so opening it for read/write might still succeed. If
	// acquireExclusiveKeyLock succeeds but SecureWriteFileSync fails, we hit the
	// target branch. Either way we expect an error.
	err := km.RotateDEKWithSweep("passphrase", func(_, _ *EncryptionService, _ string) error {
		return nil
	})
	if err == nil {
		t.Fatal("expected error when directory is read-only, got nil")
	}
	// DEK must be unchanged.
	dekAfter := km.GetDEK()
	if !bytes.Equal(dekBefore, dekAfter) {
		t.Fatal("currentDEK changed despite write failure")
	}
}

// TestKeyManager_RotateDEKWithSweep_HappyPath verifies the success path at the
// KeyManager level (rather than via Service.RotateDEKWithSweep): the DEK
// changes and the sweep function is called with different old/new services.
func TestKeyManager_RotateDEKWithSweep_HappyPath(t *testing.T) {
	dir := t.TempDir()
	km := NewKeyManager(dir, "dek.key", "kek.salt")
	if err := km.Initialize("passphrase"); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	dekBefore := km.GetDEK()

	var capturedOld, capturedNew *EncryptionService
	err := km.RotateDEKWithSweep("passphrase", func(old, new *EncryptionService, ver string) error {
		capturedOld = old
		capturedNew = new
		if ver == "" {
			return os.ErrInvalid // version must not be empty
		}
		return nil
	})
	if err != nil {
		t.Fatalf("RotateDEKWithSweep: %v", err)
	}
	if capturedOld == nil || capturedNew == nil {
		t.Fatal("sweepFn was not called with both services")
	}
	dekAfter := km.GetDEK()
	if bytes.Equal(dekBefore, dekAfter) {
		t.Fatal("DEK did not change after successful RotateDEKWithSweep")
	}
}

// TestKeyManager_RotateDEKWithSweep_BadPassphrase verifies that a wrong
// passphrase (when using passphrase-based KEK derivation) causes
// RotateDEKWithSweep to fail. With the PBKDF2-based derivation, deriveKEK
// always succeeds (it just produces a different KEK), so this test verifies
// that an empty passphrase on a manager that was initialized with a non-empty
// one causes the function to fail at the deriveKEK step (empty passphrase with
// no provider → error).
func TestKeyManager_RotateDEKWithSweep_EmptyPassphrase(t *testing.T) {
	dir := t.TempDir()
	km := NewKeyManager(dir, "dek.key", "kek.salt")
	if err := km.Initialize("passphrase"); err != nil {
		t.Fatalf("Initialize: %v", err)
	}

	// Empty passphrase with no key provider returns an error from deriveKEK.
	err := km.RotateDEKWithSweep("", func(_, _ *EncryptionService, _ string) error {
		return nil
	})
	if err == nil {
		t.Fatal("expected error for empty passphrase, got nil")
	}
}
