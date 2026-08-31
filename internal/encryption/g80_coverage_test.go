// g80_coverage_test.go — targeted gap-fill tests for internal/encryption (g80
// coverage-uplift round, baseline 89.1% statement coverage).
//
// Each section below names the specific function/branch it exercises, matching
// the convention already established in coverage_test.go.
package encryption

import (
	"bytes"
	"context"
	"crypto/aes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/crypto"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// skipIfRootOrWindows skips permission-based tests that don't work as root
// (bypasses permission checks) or on Windows (chmod not enforced the same way).
func skipIfRootOrWindows(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("permission enforcement differs on Windows")
	}
	if os.Getuid() == 0 {
		t.Skip("running as root bypasses permission checks")
	}
}

// ─── AuthEncryption.AcquireSharedKeyLock / Shutdown (auth_encryption.go) ──────

// TestAuthEncryption_AcquireSharedKeyLock_Disabled verifies the disabled-service
// no-op branch: with encryption disabled there is no DEK to guard, so the call
// must succeed without touching the filesystem.
func TestAuthEncryption_AcquireSharedKeyLock_Disabled(t *testing.T) {
	dir := t.TempDir()
	db, err := gorm.Open(sqlite.Open(filepath.Join(dir, "test.db")), &gorm.Config{})
	require.NoError(t, err)
	cfg := &config.EncryptionConfig{Enabled: false}
	ae := NewAuthEncryption(cfg, dir, db)
	require.NoError(t, ae.Initialize("unused"))

	require.NoError(t, ae.AcquireSharedKeyLock())
}

// TestAuthEncryption_AcquireSharedKeyLock_Enabled verifies the enabled branch
// delegates to the underlying Service and actually takes the OS lock — a second,
// independent AuthEncryption sharing the same key directory can still take a
// shared lock alongside it (shared locks don't exclude each other).
func TestAuthEncryption_AcquireSharedKeyLock_Enabled(t *testing.T) {
	dir := t.TempDir()
	db, err := gorm.Open(sqlite.Open(filepath.Join(dir, "test.db")), &gorm.Config{})
	require.NoError(t, err)
	cfg := &config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}
	ae := NewAuthEncryption(cfg, dir, db)
	require.NoError(t, ae.Initialize("g80-passphrase"))
	defer ae.Shutdown()

	require.NoError(t, ae.AcquireSharedKeyLock())

	// A concurrent exclusive lock attempt from a second Service sharing the same
	// key directory must now be refused — proving the shared lock was really taken
	// at the OS level, not just a no-op.
	other := NewService(cfg, dir)
	require.NoError(t, other.Initialize("g80-passphrase"))
	defer other.Shutdown()
	err = other.AcquireExclusiveKeyLock()
	assert.Error(t, err, "exclusive lock must be refused while AuthEncryption holds the shared lock")
}

// TestAuthEncryption_Shutdown_Disabled verifies Shutdown is safe to call on a
// disabled/never-really-initialized AuthEncryption (no underlying key material).
func TestAuthEncryption_Shutdown_Disabled(t *testing.T) {
	dir := t.TempDir()
	db, err := gorm.Open(sqlite.Open(filepath.Join(dir, "test.db")), &gorm.Config{})
	require.NoError(t, err)
	cfg := &config.EncryptionConfig{Enabled: false}
	ae := NewAuthEncryption(cfg, dir, db)
	require.NoError(t, ae.Initialize("unused"))

	ae.Shutdown() // must not panic
}

// TestAuthEncryption_Shutdown_ReleasesLock verifies Shutdown on an enabled,
// initialized AuthEncryption releases a previously-acquired shared lock: a
// second Service can then take the lock exclusively.
func TestAuthEncryption_Shutdown_ReleasesLock(t *testing.T) {
	dir := t.TempDir()
	db, err := gorm.Open(sqlite.Open(filepath.Join(dir, "test.db")), &gorm.Config{})
	require.NoError(t, err)
	cfg := &config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}
	ae := NewAuthEncryption(cfg, dir, db)
	require.NoError(t, ae.Initialize("g80-passphrase-2"))
	require.NoError(t, ae.AcquireSharedKeyLock())

	ae.Shutdown()

	other := NewService(cfg, dir)
	require.NoError(t, other.Initialize("g80-passphrase-2"))
	defer other.Shutdown()
	assert.NoError(t, other.AcquireExclusiveKeyLock(), "exclusive lock must succeed after AuthEncryption.Shutdown released the shared lock")
}

// TestAuthEncryption_APITokenAAD_BindsToRealOwner exercises EncryptAPIToken/
// DecryptAPIToken with a real (non-zero) owning userID — the AAD binds to the
// real owning user, so a wrong-user decrypt (see AUTH-CRYPTO-002) fails.
func TestAuthEncryption_APITokenAAD_BindsToRealOwner(t *testing.T) {
	dir := t.TempDir()
	db, err := gorm.Open(sqlite.Open(filepath.Join(dir, "test.db")), &gorm.Config{})
	require.NoError(t, err)

	cfg := &config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}
	ae := NewAuthEncryption(cfg, dir, db)
	require.NoError(t, ae.Initialize("g80-apitoken-userid-pass"))
	defer ae.Shutdown()

	enc, meta, err := ae.EncryptAPIToken("api-token-plain-owned", uint(7))
	require.NoError(t, err)

	retrieved, err := ae.DecryptAPIToken(enc, meta, uint(7))
	require.NoError(t, err)
	assert.Equal(t, "api-token-plain-owned", retrieved)

	// Decrypting with the wrong (zero) userID AAD must fail once the token was
	// encrypted with a real, non-zero owning userID.
	_, err = ae.DecryptAPIToken(enc, meta, 0)
	assert.Error(t, err, "decrypting with the wrong (zero) userID AAD must fail once the token was encrypted with a real, non-zero userID")
}

// ─── encryption.go: Decrypt — invalid base64 nonce (no rand mocking needed) ───

func TestDecrypt_InvalidBase64Nonce_Error(t *testing.T) {
	es, err := NewEncryptionService(make([]byte, 32))
	require.NoError(t, err)

	enc, err := es.Encrypt([]byte("payload"), "v1")
	require.NoError(t, err)
	enc.Metadata.Nonce = "not-valid-base64!!!"

	_, err = es.Decrypt(enc)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode nonce")
}

// TestDecryptWithAAD_InvalidBase64Nonce_Error mirrors the above for the AAD path
// (DecryptWithAAD has its own, separately-covered, base64-decode branch).
func TestDecryptWithAAD_InvalidBase64Nonce_Error(t *testing.T) {
	es, err := NewEncryptionService(make([]byte, 32))
	require.NoError(t, err)

	aad := []byte("aad")
	enc, err := es.EncryptWithAAD([]byte("payload"), "v1", aad)
	require.NoError(t, err)
	enc.Metadata.Nonce = "%%%not-base64%%%"

	_, err = es.DecryptWithAAD(enc, aad)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode nonce")
}

// ─── encryption.go: rand.Reader failure branches ──────────────────────────────
//
// NOTE: GenerateRandomKey's own error branch (encryption.go:128-130) is NOT
// covered here. It calls the crypto/rand.Read package function directly, and as
// of Go 1.24 (https://go.dev/issue/66821) that function is documented to never
// return an error — any failure crashes the process via runtime.fatal instead,
// even when crypto/rand.Reader has been swapped for a failing io.Reader. That
// makes the branch genuinely unreachable from a test in this Go toolchain, not
// merely hard to set up; forcing it would crash the whole test binary.

// TestEncryptionService_Encrypt_RandFailure_Error covers Encrypt's nonce-generation
// io.ReadFull(rand.Reader, ...) error branch (encryption.go:139).
func TestEncryptionService_Encrypt_RandFailure_Error(t *testing.T) {
	es, err := NewEncryptionService(make([]byte, 32))
	require.NoError(t, err)
	withFailingRand(t, func() {
		_, err := es.Encrypt([]byte("data"), "v1")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to generate nonce")
	})
}

// TestEncryptionService_EncryptWithAAD_RandFailure_Error covers EncryptWithAAD's
// nonce-generation error branch (encryption.go:247).
func TestEncryptionService_EncryptWithAAD_RandFailure_Error(t *testing.T) {
	es, err := NewEncryptionService(make([]byte, 32))
	require.NoError(t, err)
	withFailingRand(t, func() {
		_, err := es.EncryptWithAAD([]byte("data"), "v1", []byte("aad"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to generate nonce")
	})
}

// TestEncryptionService_EncryptChunked_StreamIDRandFailure_Error covers
// EncryptChunked's stream-ID generation error branch (encryption.go:302).
func TestEncryptionService_EncryptChunked_StreamIDRandFailure_Error(t *testing.T) {
	es, err := NewEncryptionService(make([]byte, 32))
	require.NoError(t, err)
	withFailingRand(t, func() {
		_, err := es.EncryptChunked([]byte("some data to chunk"), 4, "v1")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to generate chunk stream id")
	})
}

// TestEncryptionService_EncryptChunked_PerChunkEncryptFailure_Error covers the
// inner EncryptWithAAD-call error branch inside EncryptChunked's loop
// (encryption.go:318) — the 16-byte stream ID read succeeds, but the first
// chunk's nonce read (12 bytes, immediately after) fails.
func TestEncryptionService_EncryptChunked_PerChunkEncryptFailure_Error(t *testing.T) {
	es, err := NewEncryptionService(make([]byte, 32))
	require.NoError(t, err)
	withRandFailingAfter(t, 16, func() {
		_, err := es.EncryptChunked([]byte("some data to chunk into pieces"), 4, "v1")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to encrypt chunk 0")
	})
}

// ─── exclusive_lock.go: OpenFile failure branches ─────────────────────────────

// TestAcquireExclusiveKeyLock_OpenFileFailure_Error covers the os.OpenFile error
// branch (exclusive_lock.go:45) — a baseDir whose parent doesn't exist can't have
// the lock file created inside it.
func TestAcquireExclusiveKeyLock_OpenFileFailure_Error(t *testing.T) {
	badDir := filepath.Join(t.TempDir(), "does", "not", "exist")
	_, err := acquireExclusiveKeyLock(badDir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "open DEK lock file")
}

// TestAcquireSharedKeyLock_OpenFileFailure_Error mirrors the above for
// acquireSharedKeyLock (exclusive_lock.go:67).
func TestAcquireSharedKeyLock_OpenFileFailure_Error(t *testing.T) {
	badDir := filepath.Join(t.TempDir(), "does", "not", "exist")
	_, err := acquireSharedKeyLock(badDir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "open DEK lock file")
}

// ─── key_provider_downgrade.go: auditKeyProviderDowngrade ─────────────────────

// TestAuditKeyProviderDowngrade_NilSink_NoOp covers the sink==nil early-return
// branch (key_provider_downgrade.go:62): calling it before SetAuditSink must not
// panic and must simply do nothing.
func TestAuditKeyProviderDowngrade_NilSink_NoOp(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.EncryptionConfig{Enabled: false}
	svc := NewService(cfg, dir)

	// No SetAuditSink call — s.auditSink is nil.
	svc.auditKeyProviderDowngrade(crypto.FallbackDowngrade{
		Index:    1,
		Provider: "password",
	})
	// No panic == pass. Nothing else to assert since the branch is a pure no-op.
}

// TestAuditKeyProviderDowngrade_SinkError_Swallowed covers the sink-returns-error
// branch (key_provider_downgrade.go:75): the sink is still called (best-effort),
// but its error is only logged, never propagated or panicked on.
func TestAuditKeyProviderDowngrade_SinkError_Swallowed(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.EncryptionConfig{Enabled: false}
	svc := NewService(cfg, dir)

	called := false
	svc.SetAuditSink(func(_ context.Context, event *models.AuditEvent) error {
		called = true
		return fmt.Errorf("injected sink write failure")
	})

	svc.auditKeyProviderDowngrade(crypto.FallbackDowngrade{
		Index:    2,
		Provider: "env",
	})
	assert.True(t, called, "sink must still be called even though it will return an error")
}

// ─── service.go: wireKMSAuditSink — non-sinkable client branch ────────────────

// TestWireKMSAuditSink_NonKMSProvider_NoOp covers the type-assertion-fails branch
// (service.go:77): wireKMSAuditSink is called with any crypto.KeyProvider that is
// NOT a *crypto.KMSKeyProvider (e.g. the plain password provider every enabled
// test in this package already constructs) and must return without panicking.
func TestWireKMSAuditSink_NonKMSProvider_NoOp(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}
	svc := NewService(cfg, dir)
	provider := crypto.NewPasswordKeyProvider("pw", dir, "kek.salt")

	svc.wireKMSAuditSink(provider) // must not panic; provider is not *crypto.KMSKeyProvider
}

// ─── unwrapKey/wrapKey: bad-length KEK branches (no mocking needed) ───────────

func TestWrapKey_BadKEKLength_Error(t *testing.T) {
	_, err := wrapKey(make([]byte, 32), make([]byte, 15)) // AES needs 16/24/32
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create AES cipher")
}

func TestUnwrapKey_BadKEKLength_Error(t *testing.T) {
	_, err := unwrapKey(make([]byte, 40), make([]byte, 15))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create AES cipher")
}

// TestWrapKey_RandFailure_Error covers wrapKey's nonce-generation error branch
// (keymanager_lifecycle.go — the wrapKey helper's rand.Reader call).
func TestWrapKey_RandFailure_Error(t *testing.T) {
	withFailingRand(t, func() {
		_, err := wrapKey(make([]byte, 32), make([]byte, 32))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to generate nonce")
	})
}

// sanity: confirm AES block size assumption used above still holds (documents
// intent rather than testing stdlib, keeps the "why 15 bytes" self-evident).
func TestAESBlockSizeAssumption(t *testing.T) {
	assert.Equal(t, 16, aes.BlockSize)
}

// ─── keymanager_lifecycle.go: ensureSaltExists rand-failure branch ────────────

func TestEnsureSaltExists_RandFailure_Error(t *testing.T) {
	dir := t.TempDir()
	km := NewKeyManager(dir, "dek.key", "kek.salt")
	withFailingRand(t, func() {
		_, err := km.ensureSaltExists()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to generate salt")
	})
}

// TestEnsureSaltExists_WriteFailure_Error covers the salt-write failure branch:
// the salt directory is read-only, so persisting a freshly generated salt fails.
func TestEnsureSaltExists_WriteFailure_Error(t *testing.T) {
	skipIfRootOrWindows(t)
	dir := t.TempDir()
	km := NewKeyManager(dir, "dek.key", "kek.salt")
	require.NoError(t, os.Chmod(dir, 0555))
	defer func() { _ = os.Chmod(dir, 0755) }()

	_, err := km.ensureSaltExists()
	require.Error(t, err)
}

// ─── keymanager_lifecycle.go: ensureWrappedDEKExists — wrapKey failure ────────

// TestEnsureWrappedDEKExists_WrapKeyFailure_Error covers the wrapKey-error
// branch by supplying a bad-length KEK directly (aes.NewCipher fails, no rand
// mocking needed).
func TestEnsureWrappedDEKExists_WrapKeyFailure_Error(t *testing.T) {
	dir := t.TempDir()
	km := NewKeyManager(dir, "dek.key", "kek.salt")
	err := km.ensureWrappedDEKExists(make([]byte, 10)) // invalid AES key size
	require.Error(t, err)
}

// ─── keymanager_lifecycle.go: unwrapDEK — SafeReadFile failure ────────────────

func TestUnwrapDEK_ReadFailure_Error(t *testing.T) {
	dir := t.TempDir()
	km := NewKeyManager(dir, "dek.key", "kek.salt")
	// dek.key does not exist.
	_, err := km.unwrapDEK(make([]byte, 32))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read wrapped DEK")
}

// ─── keymanager_filelock.go / keymanager_rotation.go / keymanager_rewrap.go: ──
// ─── shared lock-file setup helper                                          ───

// createLockFileThenReadOnly pre-creates <baseDir>/<dekPath>.lock (so the
// exclusive flock acquisition, which only needs to open an EXISTING file, still
// succeeds) and then makes baseDir read-only, so any subsequent NEW file the
// caller tries to create there (a .pending write) fails. Returns a cleanup func
// that restores directory permissions.
func createLockFileThenReadOnly(t *testing.T, baseDir, dekPath string) func() {
	t.Helper()
	lockPath := filepath.Join(baseDir, dekPath+".lock")
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	require.NoError(t, err)
	require.NoError(t, f.Close())
	require.NoError(t, os.Chmod(baseDir, 0555))
	return func() { _ = os.Chmod(baseDir, 0755) }
}

// ─── keymanager_rotation.go: RotateDEKWithSweep remaining branches ────────────
//
// NOTE: the GenerateRandomKey error branch (keymanager_rotation.go:61-63) is not
// covered here for the same reason noted above: GenerateRandomKey calls
// crypto/rand.Read, which cannot return an error in this Go toolchain (Go 1.24+,
// https://go.dev/issue/66821) — it crashes the process on failure instead.

// TestRotateDEKWithSweep_WrapKeyFailure_Error covers the wrapKey error branch
// (keymanager_rotation.go:67) by installing a key provider that returns a
// bad-length KEK — deriveKEK for the provider path does not itself validate
// length, so wrapKey's aes.NewCipher call is what actually fails.
func TestRotateDEKWithSweep_WrapKeyFailure_Error(t *testing.T) {
	dir := t.TempDir()
	km := NewKeyManager(dir, "dek.key", "kek.salt")
	require.NoError(t, km.Initialize("passphrase"))
	km.SetKeyProvider(&mockKeyProvider{kek: make([]byte, 10)})

	err := km.RotateDEKWithSweep("unused-with-provider-set", func(_, _ *EncryptionService, _ string) error {
		t.Fatal("sweepFn must not be called when wrapKey fails")
		return nil
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to wrap new DEK")
}

// TestRotateDEKWithSweep_WritePendingFailure_ExactBranch covers the
// SecureWriteFileSync failure branch (keymanager_rotation.go:71) precisely: the
// lock file is pre-created (so lock acquisition itself succeeds) and only THEN
// is baseDir made read-only, so the failure is specifically the pending-DEK
// write, not the lock acquisition (unlike the pre-existing, similarly-named test
// in coverage_test.go, which — per its own on-disk behavior — actually hits the
// lock-acquisition branch instead, since it never pre-creates the lock file).
func TestRotateDEKWithSweep_WritePendingFailure_ExactBranch(t *testing.T) {
	skipIfRootOrWindows(t)
	dir := t.TempDir()
	km := NewKeyManager(dir, "dek.key", "kek.salt")
	require.NoError(t, km.Initialize("passphrase"))
	dekBefore := km.GetDEK()

	restore := createLockFileThenReadOnly(t, dir, "dek.key")
	defer restore()

	err := km.RotateDEKWithSweep("passphrase", func(_, _ *EncryptionService, _ string) error {
		t.Fatal("sweepFn must not be called when the pending DEK write fails")
		return nil
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to write pending DEK")
	assert.True(t, bytes.Equal(dekBefore, km.GetDEK()), "DEK must be unchanged on write failure")
}

// TestRotateDEKWithSweep_OldEncSvcCreationFailure_Error covers the
// NewEncryptionService(km.currentDEK) failure branch for the OLD DEK
// (keymanager_rotation.go:77) by directly corrupting the in-memory DEK to an
// invalid AES key length (accessible since this test lives in-package).
func TestRotateDEKWithSweep_OldEncSvcCreationFailure_Error(t *testing.T) {
	dir := t.TempDir()
	km := NewKeyManager(dir, "dek.key", "kek.salt")
	require.NoError(t, km.Initialize("passphrase"))
	km.currentDEK = make([]byte, 10) // corrupt: not a valid AES key size

	err := km.RotateDEKWithSweep("passphrase", func(_, _ *EncryptionService, _ string) error {
		t.Fatal("sweepFn must not be called when the old encryption service can't be created")
		return nil
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create old encryption service")
}

// TestRotateDEKWithSweep_RenameFailure_Error covers the os.Rename failure branch
// (keymanager_rotation.go:98) by replacing the active DEK path with a directory —
// RotateDEKWithSweep never reads dek.key's own content before promoting the
// pending file (unlike RewrapDEK/RotateKEKPassphrase, which do a staleness
// check), so this is reachable without corrupting any earlier step.
func TestRotateDEKWithSweep_RenameFailure_Error(t *testing.T) {
	dir := t.TempDir()
	km := NewKeyManager(dir, "dek.key", "kek.salt")
	require.NoError(t, km.Initialize("passphrase"))

	require.NoError(t, os.Remove(filepath.Join(dir, "dek.key")))
	require.NoError(t, os.Mkdir(filepath.Join(dir, "dek.key"), 0755))

	err := km.RotateDEKWithSweep("passphrase", func(_, _ *EncryptionService, _ string) error {
		return nil
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to promote pending DEK to active")
}

// TestDeleteBackupFiles_BadGlobPattern_Error covers the filepath.Glob error
// branch (keymanager_rotation.go:124): an unterminated "[" character in the glob
// pattern makes filepath.Glob return ErrBadPattern.
func TestDeleteBackupFiles_BadGlobPattern_Error(t *testing.T) {
	dir := t.TempDir()
	km := NewKeyManager(dir, "dek.key[", "kek.salt")
	km.deleteBackupFiles() // must not panic; the error is logged and swallowed
}

// ─── keymanager_kek_rotation.go: RotateKEKPassphrase remaining branches ───────

// TestRotateKEKPassphrase_LockFailure_Error covers the acquireExclusiveKeyLock
// failure branch (keymanager_kek_rotation.go:53): baseDir is read-only and the
// lock file does not exist yet, so it can't be created.
func TestRotateKEKPassphrase_LockFailure_Error(t *testing.T) {
	skipIfRootOrWindows(t)
	dir := t.TempDir()
	km := NewKeyManager(dir, "dek.key", "kek.salt")
	require.NoError(t, km.Initialize("passphrase"))

	require.NoError(t, os.Chmod(dir, 0555))
	defer func() { _ = os.Chmod(dir, 0755) }()

	err := km.RotateKEKPassphrase("passphrase", "new-passphrase")
	require.Error(t, err)
}

// TestRotateKEKPassphrase_ReadDEKFailure_Error covers the SafeReadFile(dekPath)
// failure branch (keymanager_kek_rotation.go:64): the lock file is pre-created
// so locking succeeds, then dek.key is removed entirely.
func TestRotateKEKPassphrase_ReadDEKFailure_Error(t *testing.T) {
	dir := t.TempDir()
	km := NewKeyManager(dir, "dek.key", "kek.salt")
	require.NoError(t, km.Initialize("passphrase"))
	require.NoError(t, os.Remove(filepath.Join(dir, "dek.key")))

	err := km.RotateKEKPassphrase("passphrase", "new-passphrase")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "re-read active DEK under lock")
}

// TestRotateKEKPassphrase_StaleDEKSnapshot_Error covers the on-disk-DEK-changed
// staleness branch (keymanager_kek_rotation.go:67): dek.key is overwritten with
// different (but still valid-length) bytes after Initialize, simulating a
// concurrent rotation from another process.
func TestRotateKEKPassphrase_StaleDEKSnapshot_Error(t *testing.T) {
	dir := t.TempDir()
	km := NewKeyManager(dir, "dek.key", "kek.salt")
	require.NoError(t, km.Initialize("passphrase"))

	stale := bytes.Repeat([]byte{0xAB}, 60)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "dek.key"), stale, 0600))

	err := km.RotateKEKPassphrase("passphrase", "new-passphrase")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "on-disk DEK changed since this process started")
}

// TestRotateKEKPassphrase_ReadSaltFailure_Error covers the salt-read failure
// branch (keymanager_kek_rotation.go:74).
func TestRotateKEKPassphrase_ReadSaltFailure_Error(t *testing.T) {
	dir := t.TempDir()
	km := NewKeyManager(dir, "dek.key", "kek.salt")
	require.NoError(t, km.Initialize("passphrase"))
	require.NoError(t, os.Remove(filepath.Join(dir, "kek.salt")))

	err := km.RotateKEKPassphrase("passphrase", "new-passphrase")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read current salt")
}

// TestRotateKEKPassphrase_InvalidSaltSize_Error covers the salt-size-validation
// branch (keymanager_kek_rotation.go:77).
func TestRotateKEKPassphrase_InvalidSaltSize_Error(t *testing.T) {
	dir := t.TempDir()
	km := NewKeyManager(dir, "dek.key", "kek.salt")
	require.NoError(t, km.Initialize("passphrase"))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "kek.salt"), []byte("too-short"), 0600))

	err := km.RotateKEKPassphrase("passphrase", "new-passphrase")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid current salt size")
}

// TestRotateKEKPassphrase_NewSaltRandFailure_Error covers the new-salt
// generation error branch (keymanager_kek_rotation.go:93).
func TestRotateKEKPassphrase_NewSaltRandFailure_Error(t *testing.T) {
	dir := t.TempDir()
	km := NewKeyManager(dir, "dek.key", "kek.salt")
	require.NoError(t, km.Initialize("passphrase"))

	withFailingRand(t, func() {
		err := km.RotateKEKPassphrase("passphrase", "new-passphrase")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "generate new salt")
	})
}

// TestRotateKEKPassphrase_WrapNewDEKFailure_Error covers the
// wrapKey(km.currentDEK, newKEK) error branch (keymanager_kek_rotation.go:103):
// the first 32 bytes of rand output (the new salt) succeed, but wrapKey's own
// 12-byte nonce read (which happens after) fails.
func TestRotateKEKPassphrase_WrapNewDEKFailure_Error(t *testing.T) {
	dir := t.TempDir()
	km := NewKeyManager(dir, "dek.key", "kek.salt")
	require.NoError(t, km.Initialize("passphrase"))

	withRandFailingAfter(t, 32, func() {
		err := km.RotateKEKPassphrase("passphrase", "new-passphrase")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "wrap DEK with new KEK")
	})
}

// TestRotateKEKPassphrase_CommitFailure_Error covers the commitNewKEKFiles error
// propagation branch (keymanager_kek_rotation.go:107) by pre-creating
// "kek.salt.pending" as a directory, so commitNewKEKFiles's first write fails.
func TestRotateKEKPassphrase_CommitFailure_Error(t *testing.T) {
	dir := t.TempDir()
	km := NewKeyManager(dir, "dek.key", "kek.salt")
	require.NoError(t, km.Initialize("passphrase"))
	require.NoError(t, os.Mkdir(filepath.Join(dir, "kek.salt.pending"), 0755))

	err := km.RotateKEKPassphrase("passphrase", "new-passphrase")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "write pending salt")
}

// ─── keymanager_kek_rotation.go: commitNewKEKFiles direct branch coverage ─────
//
// Called directly (unexported method, in-package) to reach branches that are
// impractical to set up through the full RotateKEKPassphrase flow, mirroring
// coverage_test.go's existing direct-call pattern for deleteBackupFiles.

func TestCommitNewKEKFiles_WriteSaltFailure_Error(t *testing.T) {
	dir := t.TempDir()
	km := NewKeyManager(dir, "dek.key", "kek.salt")
	require.NoError(t, os.Mkdir(filepath.Join(dir, "kek.salt.pending"), 0755))

	err := km.commitNewKEKFiles(make([]byte, 32), make([]byte, 48))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "write pending salt")
}

func TestCommitNewKEKFiles_WriteDEKFailure_Error(t *testing.T) {
	dir := t.TempDir()
	km := NewKeyManager(dir, "dek.key", "kek.salt")
	require.NoError(t, os.Mkdir(filepath.Join(dir, "dek.key.pending"), 0755))

	err := km.commitNewKEKFiles(make([]byte, 32), make([]byte, 48))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "write pending DEK")
	// The pending salt file written just before the DEK write failed must be
	// cleaned up, not left behind.
	_, statErr := os.Stat(filepath.Join(dir, "kek.salt.pending"))
	assert.True(t, os.IsNotExist(statErr), "pending salt file must be removed after a later write failure")
}

func TestCommitNewKEKFiles_RenameDEKFailure_Error(t *testing.T) {
	dir := t.TempDir()
	km := NewKeyManager(dir, "dek.key", "kek.salt")
	// dek.key exists as a directory, so renaming the pending file onto it fails.
	require.NoError(t, os.Mkdir(filepath.Join(dir, "dek.key"), 0755))

	err := km.commitNewKEKFiles(make([]byte, 32), make([]byte, 48))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "promote pending DEK to active")
	_, statErr := os.Stat(filepath.Join(dir, "dek.key.pending"))
	assert.True(t, os.IsNotExist(statErr), "pending DEK file must be removed after a rename failure")
	_, statErr = os.Stat(filepath.Join(dir, "kek.salt.pending"))
	assert.True(t, os.IsNotExist(statErr), "pending salt file must also be removed after a DEK-rename failure")
}

func TestCommitNewKEKFiles_RenameSaltFailure_Error(t *testing.T) {
	dir := t.TempDir()
	km := NewKeyManager(dir, "dek.key", "kek.salt")
	// kek.salt exists as a directory, so the DEK rename succeeds but the salt
	// rename fails.
	require.NoError(t, os.Mkdir(filepath.Join(dir, "kek.salt"), 0755))

	err := km.commitNewKEKFiles(make([]byte, 32), make([]byte, 48))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "promote pending salt to active")
	// The DEK rename already succeeded and must NOT have been rolled back.
	_, statErr := os.Stat(filepath.Join(dir, "dek.key"))
	assert.NoError(t, statErr, "the DEK rename must remain committed even though the salt rename failed")
}

func TestCommitNewKEKFiles_HappyPath(t *testing.T) {
	dir := t.TempDir()
	km := NewKeyManager(dir, "dek.key", "kek.salt")
	salt := bytes.Repeat([]byte{0x11}, 32)
	wrapped := bytes.Repeat([]byte{0x22}, 48)

	require.NoError(t, km.commitNewKEKFiles(salt, wrapped))

	gotSalt, err := os.ReadFile(filepath.Join(dir, "kek.salt"))
	require.NoError(t, err)
	assert.Equal(t, salt, gotSalt)
	gotDEK, err := os.ReadFile(filepath.Join(dir, "dek.key"))
	require.NoError(t, err)
	assert.Equal(t, wrapped, gotDEK)
}

// ─── keymanager_rewrap.go: RewrapDEK remaining branches ───────────────────────

func TestRewrapDEK_LockFailure_Error(t *testing.T) {
	skipIfRootOrWindows(t)
	dir := t.TempDir()
	km := NewKeyManager(dir, "dek.key", "kek.salt")
	require.NoError(t, km.Initialize("passphrase"))

	require.NoError(t, os.Chmod(dir, 0555))
	defer func() { _ = os.Chmod(dir, 0755) }()

	err := km.RewrapDEK(&mockKeyProvider{kek: make([]byte, 32)})
	require.Error(t, err)
}

// TestRewrapDEK_WrapKeyFailure_Error covers wrapKey's error branch inside
// RewrapDEK (keymanager_rewrap.go:80) via a rand.Reader failure — the new
// provider's KEK is a valid 32 bytes (passes the length check), so wrapKey
// itself must be what's reached and what fails.
func TestRewrapDEK_WrapKeyFailure_Error(t *testing.T) {
	dir := t.TempDir()
	km := NewKeyManager(dir, "dek.key", "kek.salt")
	require.NoError(t, km.Initialize("passphrase"))

	withFailingRand(t, func() {
		err := km.RewrapDEK(&mockKeyProvider{kek: make([]byte, 32)})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "wrap DEK with new KEK")
	})
}

// TestRewrapDEK_WritePendingFailure_Error covers the SecureWriteFileSync failure
// branch (keymanager_rewrap.go:90), using the same pre-create-lock-then-readonly
// technique as the RotateDEKWithSweep equivalent above.
func TestRewrapDEK_WritePendingFailure_Error(t *testing.T) {
	skipIfRootOrWindows(t)
	dir := t.TempDir()
	km := NewKeyManager(dir, "dek.key", "kek.salt")
	require.NoError(t, km.Initialize("passphrase"))

	restore := createLockFileThenReadOnly(t, dir, "dek.key")
	defer restore()

	err := km.RewrapDEK(&mockKeyProvider{kek: make([]byte, 32)})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "write pending DEK")
}

// ─── keymanager_kek_rotation_test.go coverage note ─────────────────────────────
// (RotateKEKPassphrase's happy path, wrong-passphrase, empty-passphrase, and
// same-passphrase cases are already covered by keymanager_kek_rotation_test.go;
// deriveEvidenceSignKey/deriveAuditCheckpointKey re-derivation failure branches
// inside RotateKEKPassphrase are not exercised here — HKDF-SHA256 does not fail
// for any 32-byte KEK input, making those branches practically unreachable
// without modifying the golang.org/x/crypto/hkdf package itself.)

// ─── g80SvcInit: shared helper for an initialized Service (service.go /       ──
// ─── service_rotation.go sections below)                                     ──

func g80SvcInit(t *testing.T, passphrase string) (*Service, string) {
	t.Helper()
	dir := t.TempDir()
	cfg := &config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}
	svc := NewService(cfg, dir)
	require.NoError(t, svc.Initialize(passphrase))
	return svc, dir
}

// ─── service.go: EncryptSecret / EncryptSecretWithAAD / EncryptLargeSecret ────
// ─── rand.Reader failure branches                                            ──

func TestService_EncryptSecret_RandFailure_Error(t *testing.T) {
	svc, _ := g80SvcInit(t, "g80-svc-encrypt-rand")
	defer svc.Shutdown()

	withFailingRand(t, func() {
		_, _, err := svc.EncryptSecret([]byte("plaintext"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to encrypt secret")
	})
}

func TestService_EncryptSecretWithAAD_RandFailure_Error(t *testing.T) {
	svc, _ := g80SvcInit(t, "g80-svc-encrypt-aad-rand")
	defer svc.Shutdown()

	withFailingRand(t, func() {
		_, _, err := svc.EncryptSecretWithAAD([]byte("plaintext"), []byte("aad"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to encrypt secret with AAD")
	})
}

func TestService_EncryptLargeSecret_RandFailure_Error(t *testing.T) {
	svc, _ := g80SvcInit(t, "g80-svc-encrypt-large-rand")
	defer svc.Shutdown()

	withFailingRand(t, func() {
		_, _, err := svc.EncryptLargeSecret([]byte("a large secret payload to chunk"), 1)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to encrypt chunked secret")
	})
}

// ─── service_rotation.go: RotateKEKPassphrase (Service level) ─────────────────

func TestServiceRotateKEKPassphrase_NotInitialized_Error(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.EncryptionConfig{Enabled: false}
	svc := NewService(cfg, dir)

	err := svc.RotateKEKPassphrase("old", "new")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not initialized")
}

// TestServiceRotateKEKPassphrase_LockFailure_Error covers the
// AcquireExclusiveKeyLock failure branch (service_rotation.go:229): baseDir is
// read-only and the Service-level lock file ("dek.lock", distinct from the
// KeyManager-level "dek.key.lock") does not exist yet, so it can't be created.
func TestServiceRotateKEKPassphrase_LockFailure_Error(t *testing.T) {
	skipIfRootOrWindows(t)
	svc, dir := g80SvcInit(t, "g80-svc-rotate-kek-lock")
	defer svc.Shutdown()

	require.NoError(t, os.Chmod(dir, 0555))
	defer func() { _ = os.Chmod(dir, 0755) }()

	err := svc.RotateKEKPassphrase("g80-svc-rotate-kek-lock", "new-passphrase")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "stop the running server before rotating")
}

// ─── service_rotation.go: PreviewRotationSweep / UpgradeAuthAAD — tx.Begin ────
// ─── error branches                                                          ──

// g80ClosedDB returns a *gorm.DB whose underlying *sql.DB has already been
// closed, so db.Begin() fails immediately — used to reach the tx.Begin()-error
// branches that a merely-empty database can't reach.
func g80ClosedDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "closed.db")), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())
	return db
}

func TestPreviewRotationSweep_TxBeginFailure_Error(t *testing.T) {
	svc, _ := g80SvcInit(t, "g80-preview-begin-fail")
	defer svc.Shutdown()

	_, err := svc.PreviewRotationSweep(g80ClosedDB(t))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to begin transaction")
}

func TestUpgradeAuthAAD_TxBeginFailure_Error(t *testing.T) {
	svc, _ := g80SvcInit(t, "g80-upgradeaad-begin-fail")
	defer svc.Shutdown()

	_, err := svc.UpgradeAuthAAD(g80ClosedDB(t))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to begin transaction")
}

// TestServiceRotateDEKWithSweep_TxBeginFailure_Error covers the tx.Begin()
// error branch inside RotateDEKWithSweep's own sweepFn (service_rotation.go:46)
// — reached only once a full, real key rotation gets underway (KeyManager-level
// RotateDEKWithSweep must succeed in generating and wrapping a new DEK before
// sweepFn ever runs), so this exercises the real rotation path up to the point
// where the caller-supplied *gorm.DB can't even start a transaction. The DEK
// must remain the OLD one since the sweep never got a chance to run.
func TestServiceRotateDEKWithSweep_TxBeginFailure_Error(t *testing.T) {
	svc, _ := g80SvcInit(t, "g80-svc-rotate-begin-fail")
	defer svc.Shutdown()
	keyVersionBefore := svc.GetKeyVersion()

	_, err := svc.RotateDEKWithSweep("g80-svc-rotate-begin-fail", g80ClosedDB(t))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "DEK rotation with sweep failed")
	assert.Equal(t, keyVersionBefore, svc.GetKeyVersion(), "key version must be unchanged when the sweep transaction can't even begin")
}

// ─── sweep.go: sweepSecretVersions — empty-value skip + re-encrypt failure ────
// ─── + Updates() DB error                                                    ──

func g80SweepDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "sweep.db")), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.SecretNode{}, &models.SecretVersion{}))
	return db
}

// TestSweepSecretVersions_SkipsEmptyEncryptedValue covers the
// `if len(version.EncryptedValue) == 0 { continue }` branch (sweep.go:161): a
// row with no ciphertext yet (e.g. a placeholder/reserved version) must be
// skipped, not treated as a decrypt failure, and must not count toward swept.
func TestSweepSecretVersions_SkipsEmptyEncryptedValue(t *testing.T) {
	db := g80SweepDB(t)
	es, err := NewEncryptionService(make([]byte, 32))
	require.NoError(t, err)

	node := &models.SecretNode{Name: "n-empty", ProjectID: 1, Type: "generic"}
	require.NoError(t, db.Create(node).Error)
	ver := &models.SecretVersion{SecretNodeID: node.ID, VersionNumber: 1, EncryptedValue: nil}
	require.NoError(t, db.Create(ver).Error)

	swept, legacy, err := sweepSecretVersions(db, es, es, "v2", false)
	require.NoError(t, err)
	assert.Equal(t, 0, swept, "a row with no encrypted value must be skipped, not swept")
	assert.Equal(t, 0, legacy)
}

// TestSweepSecretVersions_ReEncryptFailure covers the newSvc.EncryptWithAAD
// error branch (sweep.go:188): decrypt with oldSvc succeeds, but the
// re-encryption under newSvc fails.
func TestSweepSecretVersions_ReEncryptFailure(t *testing.T) {
	db := g80SweepDB(t)
	oldSvc, err := NewEncryptionService(make([]byte, 32))
	require.NoError(t, err)
	newSvc, err := NewEncryptionService(bytes.Repeat([]byte{0x9}, 32))
	require.NoError(t, err)

	node := &models.SecretNode{Name: "n-reenc", ProjectID: 2, Type: "generic"}
	require.NoError(t, db.Create(node).Error)
	aad := SecretAAD(node.ID, 2, 1)
	enc, err := oldSvc.EncryptWithAAD([]byte("secret-value"), "v1", aad)
	require.NoError(t, err)
	encBytes, err := SerializeEncryptedData(enc)
	require.NoError(t, err)
	ver := &models.SecretVersion{SecretNodeID: node.ID, VersionNumber: 1, EncryptedValue: encBytes}
	require.NoError(t, db.Create(ver).Error)

	withFailingRand(t, func() {
		_, _, err := sweepSecretVersions(db, oldSvc, newSvc, "v2", false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to re-encrypt secret_version")
	})
}

// TestSweepSecretVersions_UpdatesError covers the Updates() DB-error branch
// (sweep.go:207) via a read-only SQLite connection to a file that already
// contains the row (same technique as TestSweepAPITokens_UpdatesError_ReadOnly
// in encryption_s25_test.go).
func TestSweepSecretVersions_UpdatesError(t *testing.T) {
	es, err := NewEncryptionService(make([]byte, 32))
	require.NoError(t, err)

	dbFile := filepath.Join(t.TempDir(), "secretversion_ro.db")
	rwDB, err := gorm.Open(sqlite.Open(dbFile), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, rwDB.AutoMigrate(&models.SecretNode{}, &models.SecretVersion{}))

	node := &models.SecretNode{Name: "n-ro", ProjectID: 3, Type: "generic"}
	require.NoError(t, rwDB.Create(node).Error)
	aad := SecretAAD(node.ID, 3, 1)
	enc, err := es.EncryptWithAAD([]byte("secret-value"), "v1", aad)
	require.NoError(t, err)
	encBytes, err := SerializeEncryptedData(enc)
	require.NoError(t, err)
	ver := &models.SecretVersion{SecretNodeID: node.ID, VersionNumber: 1, EncryptedValue: encBytes}
	require.NoError(t, rwDB.Create(ver).Error)

	roDB, err := gorm.Open(sqlite.Open("file:"+dbFile+"?mode=ro"), &gorm.Config{})
	require.NoError(t, err)

	_, _, err = sweepSecretVersions(roDB, es, es, "v2", false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to update re-encrypted secret_version")
}

// ─── sweep_auth.go: sweepAPITokens — token.UserID != nil branch ───────────────

func TestSweepAPITokens_WithNonNilUserID(t *testing.T) {
	db := g80SweepDB(t)
	require.NoError(t, db.AutoMigrate(&models.APIToken{}))
	es, err := NewEncryptionService(make([]byte, 32))
	require.NoError(t, err)

	uid := uint(55)
	// APITokenAAD(55), matching the live write path (auth_encryption.go), so
	// this is the AAD-bound (non-legacy) case with a real owning user.
	enc, err := es.EncryptWithAAD([]byte("tok-val"), "v1", APITokenAAD(uid))
	require.NoError(t, err)
	encBytes, err := SerializeEncryptedData(enc)
	require.NoError(t, err)
	metaBytes, err := json.Marshal(enc.Metadata)
	require.NoError(t, err)
	row := &models.APIToken{
		UserID:         &uid,
		Token:          "h-userid-tok",
		EncryptedToken: encBytes,
		TokenMetadata:  models.JSON(metaBytes),
	}
	require.NoError(t, db.Create(row).Error)

	swept, legacy, err := sweepAPITokens(db, es, es, "v2", false)
	require.NoError(t, err)
	assert.Equal(t, 1, swept)
	assert.Equal(t, 0, legacy)

	// Confirm the re-encrypted row still round-trips under the real owning
	// user's AAD (proves tokenUserID was actually derived from *token.UserID,
	// not silently left at 0).
	var reloaded models.APIToken
	require.NoError(t, db.First(&reloaded, row.ID).Error)
	reEnc, err := DeserializeEncryptedData(reloaded.EncryptedToken)
	require.NoError(t, err)
	plain, err := es.DecryptWithAAD(reEnc, APITokenAAD(uid))
	require.NoError(t, err)
	assert.Equal(t, "tok-val", string(plain))
}

// ─── sweep_auth.go: re-encrypt failure branches (one per sweep function) ──────

func TestSweepAPITokens_ReEncryptFailure(t *testing.T) {
	db := g80SweepDB(t)
	require.NoError(t, db.AutoMigrate(&models.APIToken{}))
	oldSvc, newSvc := g80OldNewSvc(t)

	enc, err := oldSvc.EncryptWithAAD([]byte("tok-val"), "v1", APITokenAAD(0))
	require.NoError(t, err)
	encBytes, err := SerializeEncryptedData(enc)
	require.NoError(t, err)
	row := &models.APIToken{Token: "h-reenc-fail", EncryptedToken: encBytes}
	require.NoError(t, db.Create(row).Error)

	withFailingRand(t, func() {
		_, _, err := sweepAPITokens(db, oldSvc, newSvc, "v2", false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to re-encrypt api_token")
	})
}

func TestSweepAPIClients_ReEncryptFailure(t *testing.T) {
	db := g80SweepDB(t)
	require.NoError(t, db.AutoMigrate(&models.APIClient{}))
	oldSvc, newSvc := g80OldNewSvc(t)

	enc, err := oldSvc.Encrypt([]byte("client-secret-val"), "v1")
	require.NoError(t, err)
	encBytes, err := SerializeEncryptedData(enc)
	require.NoError(t, err)
	row := &models.APIClient{ClientID: "cl-reenc-fail", EncryptedClientSecret: encBytes}
	require.NoError(t, db.Create(row).Error)

	withFailingRand(t, func() {
		_, err := sweepAPIClients(db, oldSvc, newSvc, "v2", false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to re-encrypt api_client")
	})
}

func TestSweepMFASecrets_ReEncryptFailure(t *testing.T) {
	db := g80SweepDB(t)
	require.NoError(t, db.AutoMigrate(&models.MFASecret{}))
	oldSvc, newSvc := g80OldNewSvc(t)

	enc, err := oldSvc.EncryptWithAAD([]byte("totp-seed"), "v1", MFASecretAAD(9))
	require.NoError(t, err)
	encBytes, err := SerializeEncryptedData(enc)
	require.NoError(t, err)
	row := &models.MFASecret{UserID: 9, SecretEnc: encBytes}
	require.NoError(t, db.Create(row).Error)

	withFailingRand(t, func() {
		_, _, err := sweepMFASecrets(db, oldSvc, newSvc, "v2", false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to re-encrypt mfa_secret")
	})
}

func TestSweepDynamicSecretConfigs_ReEncryptFailure(t *testing.T) {
	db := g80SweepDB(t)
	require.NoError(t, db.AutoMigrate(&models.DynamicSecretConfig{}))
	oldSvc, newSvc := g80OldNewSvc(t)

	enc, err := oldSvc.EncryptWithAAD([]byte("admin-dsn"), "v1", DynamicSecretConfigAAD(1, 2, 3))
	require.NoError(t, err)
	encBytes, err := SerializeEncryptedData(enc)
	require.NoError(t, err)
	row := &models.DynamicSecretConfig{ProjectID: 2, EnvironmentID: 3, AdminDSNEnc: encBytes}
	require.NoError(t, db.Create(row).Error)

	withFailingRand(t, func() {
		_, _, err := sweepDynamicSecretConfigs(db, oldSvc, newSvc, "v2", false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to re-encrypt dynamic_secret_config")
	})
}

func TestSweepDynamicSecretLeases_ReEncryptFailure(t *testing.T) {
	db := g80SweepDB(t)
	require.NoError(t, db.AutoMigrate(&models.DynamicSecretLease{}))
	oldSvc, newSvc := g80OldNewSvc(t)

	enc, err := oldSvc.EncryptWithAAD([]byte("lease-cred"), "v1", DynamicSecretLeaseAAD("lease-1", 4))
	require.NoError(t, err)
	encBytes, err := SerializeEncryptedData(enc)
	require.NoError(t, err)
	row := &models.DynamicSecretLease{LeaseID: "lease-1", ConfigID: 4, CredentialEnc: encBytes}
	require.NoError(t, db.Create(row).Error)

	withFailingRand(t, func() {
		_, _, err := sweepDynamicSecretLeases(db, oldSvc, newSvc, "v2", false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to re-encrypt dynamic_secret_lease")
	})
}

func TestSweepPasswordResets_ReEncryptFailure(t *testing.T) {
	db := g80SweepDB(t)
	require.NoError(t, db.AutoMigrate(&models.PasswordReset{}))
	oldSvc, newSvc := g80OldNewSvc(t)

	enc, err := oldSvc.EncryptWithAAD([]byte("reset-token"), "v1", PasswordResetTokenAAD(11))
	require.NoError(t, err)
	encBytes, err := SerializeEncryptedData(enc)
	require.NoError(t, err)
	row := &models.PasswordReset{UserID: 11, EncryptedToken: encBytes}
	require.NoError(t, db.Create(row).Error)

	withFailingRand(t, func() {
		_, _, err := sweepPasswordResets(db, oldSvc, newSvc, "v2", false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to re-encrypt password_reset")
	})
}

// g80OldNewSvc returns two distinct, valid EncryptionServices to use as
// oldSvc/newSvc in a sweep — separate keys so a round-trip decrypt-then-
// re-encrypt is meaningful (not required for the re-encrypt-failure tests
// above, but keeps the helper generally reusable).
func g80OldNewSvc(t *testing.T) (*EncryptionService, *EncryptionService) {
	t.Helper()
	oldSvc, err := NewEncryptionService(make([]byte, 32))
	require.NoError(t, err)
	newSvc, err := NewEncryptionService(bytes.Repeat([]byte{0x5}, 32))
	require.NoError(t, err)
	return oldSvc, newSvc
}
