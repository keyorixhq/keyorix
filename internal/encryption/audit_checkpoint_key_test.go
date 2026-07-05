package encryption

// audit_checkpoint_key_test.go also carries the #502 regression tests: the
// audit-checkpoint signing key (used to sign/verify audit-chain checkpoints,
// ADR-029, see internal/core/audit_checkpoint.go) must be derived from the KEK,
// not the DEK, so a routine DEK rotation does not affect it — mirroring #268's
// fix for the evidence-signing key (evidence_sign_key_test.go). It should only
// change on a genuine KEK change (a KEK-provider migration, ADR-041).

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuditCheckpointKey_DerivedAndStable(t *testing.T) {
	svc, _ := newTestService(t, "test-passphrase-for-unit-tests")

	key, ver, ok := svc.AuditCheckpointKey()
	require.True(t, ok, "an enabled+initialised service must yield a checkpoint key")
	assert.Len(t, key, 32, "checkpoint key is 32 bytes")
	assert.NotEmpty(t, ver, "key version is reported")

	// Deterministic for the same DEK.
	key2, ver2, ok2 := svc.AuditCheckpointKey()
	require.True(t, ok2)
	assert.True(t, bytes.Equal(key, key2), "derivation is stable for a fixed DEK")
	assert.Equal(t, ver, ver2)

	// Domain separation: the checkpoint key is not the raw DEK.
	dek := svc.keyManager.GetDEK()
	assert.False(t, bytes.Equal(key, dek), "checkpoint key must be HKDF-derived, not the DEK itself")
}

func TestAuditCheckpointKey_UnavailableWhenDisabled(t *testing.T) {
	// Encryption disabled → no DEK → no checkpoint key.
	svc := NewService(&config.EncryptionConfig{Enabled: false}, t.TempDir())
	_, _, ok := svc.AuditCheckpointKey()
	assert.False(t, ok, "a disabled service has no signing key")

	// Enabled but not initialised → also unavailable.
	svc2 := NewService(&config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}, t.TempDir())
	_, _, ok2 := svc2.AuditCheckpointKey()
	assert.False(t, ok2, "an uninitialised service has no DEK yet")
}

// TestAuditCheckpointKey_StableAcrossDEKRotation is the core regression test for
// #502: signing key and version must be BYTE-IDENTICAL before and after a full
// RotateDEKWithSweep, even though the DEK itself (and its own key version)
// changes. This is what makes a checkpoint signed before a DEK rotation still
// verifiable after one — closing the false-tamper-alarm window a DEK-derived key
// used to open on every rotation.
func TestAuditCheckpointKey_StableAcrossDEKRotation(t *testing.T) {
	db := newTestDB(t)
	svc, _ := newTestService(t, "test-passphrase")

	keyBefore, verBefore, ok := svc.AuditCheckpointKey()
	if !ok {
		t.Fatal("AuditCheckpointKey unavailable before rotation")
	}
	if len(keyBefore) != 32 {
		t.Fatalf("expected a 32-byte key, got %d bytes", len(keyBefore))
	}

	dekBefore := captureCurrentDEK(t, svc)
	dekVerBefore := svc.GetKeyVersion()

	if _, err := svc.RotateDEKWithSweep("test-passphrase", db); err != nil {
		t.Fatalf("RotateDEKWithSweep failed: %v", err)
	}

	// Sanity: the DEK and its own version DID change (that's the whole point of
	// rotation) — otherwise this test would be vacuous.
	dekAfter := captureCurrentDEK(t, svc)
	if bytes.Equal(dekBefore, dekAfter) {
		t.Fatal("DEK did not change after rotation — test setup is broken")
	}
	if svc.GetKeyVersion() == dekVerBefore {
		t.Fatal("DEK key version did not change after rotation — test setup is broken")
	}

	keyAfter, verAfter, ok := svc.AuditCheckpointKey()
	if !ok {
		t.Fatal("AuditCheckpointKey unavailable after rotation")
	}
	if !bytes.Equal(keyBefore, keyAfter) {
		t.Fatalf("audit-checkpoint key changed across a DEK rotation: before=%x after=%x", keyBefore, keyAfter)
	}
	if verBefore != verAfter {
		t.Fatalf("audit-checkpoint key version changed across a DEK rotation: before=%q after=%q", verBefore, verAfter)
	}
}

// TestAuditCheckpointKey_ChangesAcrossKEKMigration proves the corresponding
// negative: a genuine KEK change (KEK-provider migration, ADR-041) DOES change
// the audit-checkpoint key and its version. This is expected and correctly
// reported by enforceAuditCheckpoint as a superseded key version needing
// re-baselining, not silently accepted and not reported as tampering — the same
// non-regression the #502 fix preserves (mirroring #268's evidence-key test).
func TestAuditCheckpointKey_ChangesAcrossKEKMigration(t *testing.T) {
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
	keyBefore, verBefore, ok := km.GetAuditCheckpointKey()
	if !ok {
		t.Fatal("GetAuditCheckpointKey unavailable after initialize")
	}

	if err := km.RewrapDEK(crypto.NewFileKeyProvider(newKEK)); err != nil {
		t.Fatalf("rewrap: %v", err)
	}

	// A fresh manager loading under the NEW provider (mirroring a server restart
	// after migrate-provider, since RewrapDEK itself doesn't live-update an
	// already-running process) must derive a DIFFERENT audit-checkpoint key/version.
	kmNew := NewKeyManager(dir, "dek.key", "kek.salt")
	kmNew.SetKeyProvider(crypto.NewFileKeyProvider(newKEK))
	if err := kmNew.Initialize(""); err != nil {
		t.Fatalf("initialize new: %v", err)
	}
	keyAfter, verAfter, ok := kmNew.GetAuditCheckpointKey()
	if !ok {
		t.Fatal("GetAuditCheckpointKey unavailable after re-initialize with new provider")
	}

	if bytes.Equal(keyBefore, keyAfter) {
		t.Fatal("audit-checkpoint key did NOT change across a KEK-provider migration — it should have")
	}
	if verBefore == verAfter {
		t.Fatalf("audit-checkpoint key version did NOT change across a KEK-provider migration — it should have (got %q both times)", verBefore)
	}
}

// TestAuditCheckpointKey_WipedOnShutdown proves Wipe() zeroes the
// audit-checkpoint key alongside the DEK, so neither lingers in memory after
// shutdown.
func TestAuditCheckpointKey_WipedOnShutdown(t *testing.T) {
	svc, _ := newTestService(t, "test-passphrase")
	if _, _, ok := svc.AuditCheckpointKey(); !ok {
		t.Fatal("AuditCheckpointKey unavailable before shutdown")
	}
	svc.keyManager.Wipe()
	if _, _, ok := svc.keyManager.GetAuditCheckpointKey(); ok {
		t.Fatal("expected the audit-checkpoint key to be gone after Wipe()")
	}
}
