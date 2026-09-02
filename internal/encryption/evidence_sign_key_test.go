package encryption

// evidence_sign_key_test.go — regression tests for #268: the evidence-signing key
// (used to sign exported compliance-evidence packs, see
// internal/core/evidence_signing.go) must be derived from the KEK, not the DEK, so
// a routine DEK rotation does not silently and permanently invalidate every
// previously-signed pack. It should only change on a genuine KEK change (a
// KEK-provider migration, ADR-041 — a far rarer, deliberate operator action).

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/crypto"
)

// TestEvidenceSignKey_StableAcrossDEKRotation is the core regression test for
// #268: signing key and version must be BYTE-IDENTICAL before and after a full
// RotateDEKWithSweep, even though the DEK itself (and its own key version) changes.
// This is what makes an evidence pack signed before a DEK rotation still verifiable
// after one.
func TestEvidenceSignKey_StableAcrossDEKRotation(t *testing.T) {
	db := newTestDB(t)
	svc, _ := newTestService(t, "test-passphrase")

	keyBefore, verBefore, ok := svc.EvidenceSignKey()
	if !ok {
		t.Fatal("EvidenceSignKey unavailable before rotation")
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

	keyAfter, verAfter, ok := svc.EvidenceSignKey()
	if !ok {
		t.Fatal("EvidenceSignKey unavailable after rotation")
	}
	if !bytes.Equal(keyBefore, keyAfter) {
		t.Fatalf("evidence-signing key changed across a DEK rotation: before=%x after=%x", keyBefore, keyAfter)
	}
	if verBefore != verAfter {
		t.Fatalf("evidence-signing key version changed across a DEK rotation: before=%q after=%q", verBefore, verAfter)
	}
}

// TestEvidenceSignKey_ChangesAcrossKEKMigration proves the corresponding negative:
// a genuine KEK change (KEK-provider migration, ADR-041) DOES change the
// evidence-signing key and its version. This is expected and correctly reported by
// VerifyEvidenceSignature as "superseded key version", not silently accepted and
// not reported as tampering — the same non-regression the #268 fix preserves.
func TestEvidenceSignKey_ChangesAcrossKEKMigration(t *testing.T) {
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
	keyBefore, verBefore, ok := km.GetEvidenceSignKey()
	if !ok {
		t.Fatal("GetEvidenceSignKey unavailable after initialize")
	}

	if err := km.RewrapDEK(crypto.NewFileKeyProvider(newKEK)); err != nil {
		t.Fatalf("rewrap: %v", err)
	}

	// A fresh manager loading under the NEW provider (mirroring a server restart
	// after migrate-provider, since RewrapDEK itself doesn't live-update an
	// already-running process) must derive a DIFFERENT evidence-signing key/version.
	kmNew := NewKeyManager(dir, "dek.key", "kek.salt")
	kmNew.SetKeyProvider(crypto.NewFileKeyProvider(newKEK))
	if err := kmNew.Initialize(""); err != nil {
		t.Fatalf("initialize new: %v", err)
	}
	keyAfter, verAfter, ok := kmNew.GetEvidenceSignKey()
	if !ok {
		t.Fatal("GetEvidenceSignKey unavailable after re-initialize with new provider")
	}

	if bytes.Equal(keyBefore, keyAfter) {
		t.Fatal("evidence-signing key did NOT change across a KEK-provider migration — it should have")
	}
	if verBefore == verAfter {
		t.Fatalf("evidence-signing key version did NOT change across a KEK-provider migration — it should have (got %q both times)", verBefore)
	}
}

// TestEvidenceSignKey_UnavailableWhenUninitialized mirrors the existing DEK/audit-
// checkpoint-key behavior: no KEK has been derived yet, so no signing key exists.
func TestEvidenceSignKey_UnavailableWhenUninitialized(t *testing.T) {
	dir := t.TempDir()
	km := NewKeyManager(dir, "dek.key", "kek.salt")
	if _, _, ok := km.GetEvidenceSignKey(); ok {
		t.Fatal("expected GetEvidenceSignKey to report unavailable before Initialize")
	}
}

// TestEvidenceSignKey_WipedOnShutdown proves Wipe() zeroes the evidence-signing
// key alongside the DEK, so neither lingers in memory after shutdown.
// GetEvidenceSignKey always returns a COPY (keymanager_io.go), so asserting
// ok=false on it afterward only proves the field reference was nilled -- a
// Wipe() that dropped its wipeBytes(km.evidenceSignKey) call but kept the
// nil-assignment would pass that check identically while leaving the real key
// bytes live in memory. This test instead reaches the unexported
// km.evidenceSignKey field directly (same package as keymanager_lifecycle.go)
// to capture the actual backing array before Wipe() and assert every byte is
// zero afterward -- the same memory-scan style
// TestServiceShutdown_WipesEncryptionServiceDEK (g62_dek_safety_test.go)
// already uses for the DEK, and TestAuditCheckpointKey_WipedOnShutdown
// (audit_checkpoint_key_test.go) now uses for its sibling key.
func TestEvidenceSignKey_WipedOnShutdown(t *testing.T) {
	svc, _ := newTestService(t, "test-passphrase")
	if _, _, ok := svc.EvidenceSignKey(); !ok {
		t.Fatal("EvidenceSignKey unavailable before shutdown")
	}

	svc.keyManager.mu.RLock()
	keyRef := svc.keyManager.evidenceSignKey // same backing array wipeBytes must zero in place
	svc.keyManager.mu.RUnlock()
	if allZeroBytes(keyRef) {
		t.Fatal("test setup bug: evidence-signing key was already all-zero before Wipe()")
	}

	svc.keyManager.Wipe()

	if !allZeroBytes(keyRef) {
		t.Fatal("evidence-signing key bytes were not wiped by Wipe() -- key remains live in process memory")
	}
	if _, _, ok := svc.keyManager.GetEvidenceSignKey(); ok {
		t.Fatal("expected the evidence-signing key to be gone after Wipe()")
	}
}
