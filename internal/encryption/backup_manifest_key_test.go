package encryption

// backup_manifest_key_test.go mirrors audit_checkpoint_key_test.go's own
// tests exactly, for the backup-manifest signing key design-b3-backup-v2.md
// §5.2 requires: KEK-derived (not DEK-derived, so a DEK rotation doesn't
// invalidate an already-signed manifest), independently domain-separated
// from the audit-checkpoint key, wiped on shutdown alongside every other
// derived key here.

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBackupManifestKey_DerivedAndStable(t *testing.T) {
	svc, _ := newTestService(t, "test-passphrase-for-unit-tests")

	key, ver, ok := svc.BackupManifestKey()
	require.True(t, ok, "an enabled+initialised service must yield a manifest key")
	assert.Len(t, key, 32, "manifest key is 32 bytes")
	assert.NotEmpty(t, ver, "key version is reported")

	key2, ver2, ok2 := svc.BackupManifestKey()
	require.True(t, ok2)
	assert.True(t, bytes.Equal(key, key2), "derivation is stable for a fixed DEK")
	assert.Equal(t, ver, ver2)

	dek := svc.keyManager.GetDEK()
	assert.False(t, bytes.Equal(key, dek), "manifest key must be HKDF-derived, not the DEK itself")

	// Domain separation from the audit-checkpoint key (design §5.2's
	// explicit requirement): same KEK, different derived keys.
	checkpointKey, _, ok3 := svc.AuditCheckpointKey()
	require.True(t, ok3)
	assert.False(t, bytes.Equal(key, checkpointKey),
		"the manifest key must never equal the audit-checkpoint key derived from the same KEK")
}

func TestBackupManifestKey_UnavailableWhenDisabled(t *testing.T) {
	svc := NewService(&config.EncryptionConfig{Enabled: false}, t.TempDir())
	_, _, ok := svc.BackupManifestKey()
	assert.False(t, ok, "a disabled service has no signing key")

	svc2 := NewService(&config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}, t.TempDir())
	_, _, ok2 := svc2.BackupManifestKey()
	assert.False(t, ok2, "an uninitialised service has no DEK yet")
}

// TestBackupManifestKey_StableAcrossDEKRotation is the manifest-key analog
// of #502: a backup signed before a DEK rotation must stay verifiable
// after one, since key/version are BYTE-IDENTICAL across RotateDEKWithSweep
// even though the DEK itself changes.
func TestBackupManifestKey_StableAcrossDEKRotation(t *testing.T) {
	db := newTestDB(t)
	svc, _ := newTestService(t, "test-passphrase")

	keyBefore, verBefore, ok := svc.BackupManifestKey()
	if !ok {
		t.Fatal("BackupManifestKey unavailable before rotation")
	}
	if len(keyBefore) != 32 {
		t.Fatalf("expected a 32-byte key, got %d bytes", len(keyBefore))
	}

	dekBefore := captureCurrentDEK(t, svc)
	dekVerBefore := svc.GetKeyVersion()

	if _, err := svc.RotateDEKWithSweep("test-passphrase", db); err != nil {
		t.Fatalf("RotateDEKWithSweep failed: %v", err)
	}

	dekAfter := captureCurrentDEK(t, svc)
	if bytes.Equal(dekBefore, dekAfter) {
		t.Fatal("DEK did not change after rotation — test setup is broken")
	}
	if svc.GetKeyVersion() == dekVerBefore {
		t.Fatal("DEK key version did not change after rotation — test setup is broken")
	}

	keyAfter, verAfter, ok := svc.BackupManifestKey()
	if !ok {
		t.Fatal("BackupManifestKey unavailable after rotation")
	}
	if !bytes.Equal(keyBefore, keyAfter) {
		t.Fatalf("backup-manifest key changed across a DEK rotation: before=%x after=%x", keyBefore, keyAfter)
	}
	if verBefore != verAfter {
		t.Fatalf("backup-manifest key version changed across a DEK rotation: before=%q after=%q", verBefore, verAfter)
	}
}

// TestBackupManifestKey_ChangesAcrossKEKMigration is the negative
// counterpart: a genuine KEK change (KEK-provider migration) DOES change
// the manifest key -- correct, since it's KEK-derived, not a bug.
func TestBackupManifestKey_ChangesAcrossKEKMigration(t *testing.T) {
	dir := t.TempDir()
	oldKEK := filepath.Join(dir, "old.kek")
	newKEK := filepath.Join(dir, "new.kek")
	writeHexKEK(t, oldKEK)
	writeHexKEK(t, newKEK)

	km := NewKeyManager(dir, "dek.key", "kek.salt")
	km.SetKeyProvider(crypto.NewFileKeyProvider(oldKEK))
	if err := km.Initialize(""); err != nil {
		t.Fatalf("initialize old: %v", err)
	}
	keyBefore, verBefore, ok := km.GetBackupManifestKey()
	if !ok {
		t.Fatal("GetBackupManifestKey unavailable after initialize")
	}

	if err := km.RewrapDEK(crypto.NewFileKeyProvider(newKEK)); err != nil {
		t.Fatalf("rewrap: %v", err)
	}

	kmNew := NewKeyManager(dir, "dek.key", "kek.salt")
	kmNew.SetKeyProvider(crypto.NewFileKeyProvider(newKEK))
	if err := kmNew.Initialize(""); err != nil {
		t.Fatalf("initialize new: %v", err)
	}
	keyAfter, verAfter, ok := kmNew.GetBackupManifestKey()
	if !ok {
		t.Fatal("GetBackupManifestKey unavailable after re-initialize with new provider")
	}

	if bytes.Equal(keyBefore, keyAfter) {
		t.Fatal("backup-manifest key did NOT change across a KEK-provider migration — it should have")
	}
	if verBefore == verAfter {
		t.Fatalf("backup-manifest key version did NOT change across a KEK-provider migration — it should have (got %q both times)", verBefore)
	}
}

// TestBackupManifestKey_ChangesAcrossPassphraseRotation is RotateKEKPassphrase's
// own KEK-change path (distinct code path from RewrapDEK, see
// keymanager_kek_rotation.go) -- must re-derive the manifest key too, live,
// without needing a process restart the way RewrapDEK does.
func TestBackupManifestKey_ChangesAcrossPassphraseRotation(t *testing.T) {
	svc, _ := newTestService(t, "old-passphrase")
	keyBefore, verBefore, ok := svc.BackupManifestKey()
	require.True(t, ok)

	require.NoError(t, svc.keyManager.RotateKEKPassphrase("old-passphrase", "new-passphrase"))

	keyAfter, verAfter, ok := svc.BackupManifestKey()
	require.True(t, ok)
	assert.False(t, bytes.Equal(keyBefore, keyAfter), "manifest key must change after a passphrase (KEK) rotation")
	assert.NotEqual(t, verBefore, verAfter)
}

// TestBackupManifestKey_WipedOnShutdown mirrors
// TestAuditCheckpointKey_WipedOnShutdown's own memory-scan discipline: reach
// the unexported backing array directly and assert every byte is zero after
// Wipe(), not just that the getter reports unavailable (which a broken
// Wipe() that only nils the reference would also satisfy).
func TestBackupManifestKey_WipedOnShutdown(t *testing.T) {
	svc, _ := newTestService(t, "test-passphrase")
	if _, _, ok := svc.BackupManifestKey(); !ok {
		t.Fatal("BackupManifestKey unavailable before shutdown")
	}

	svc.keyManager.mu.RLock()
	keyRef := svc.keyManager.backupManifestKey
	svc.keyManager.mu.RUnlock()
	if allZeroBytes(keyRef) {
		t.Fatal("test setup bug: backup-manifest key was already all-zero before Wipe()")
	}

	svc.keyManager.Wipe()

	if !allZeroBytes(keyRef) {
		t.Fatal("backup-manifest key bytes were not wiped by Wipe() -- key remains live in process memory")
	}
	if _, _, ok := svc.keyManager.GetBackupManifestKey(); ok {
		t.Fatal("expected the backup-manifest key to be gone after Wipe()")
	}
}
