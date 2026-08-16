package encryption

// g62_dek_safety_test.go — regression tests for G62: newer encryption-package
// code skipping the package's own established DEK-safety conventions.
//
//   - RewrapDEKWithProvider (the `migrate-provider` command's core function)
//     never acquired the cross-process exclusive key lock RotateDEKWithSweep/
//     RotateKEKPassphrase already require, so a concurrent migrate-provider run
//     could race a live server (or an in-progress rotation) on the same key
//     file. TestRewrapDEKWithProvider_RefusesWhileServerHoldsLock and its
//     positive-control sibling pin the fix.
//
//   - EncryptionService.dek (and the pre-rotation EncryptionService that
//     RotateDEKWithSweep discards once it's superseded) was never wiped via
//     wipeBytes on shutdown/replacement, unlike every other DEK-bearing
//     variable in this package. TestServiceShutdown_WipesEncryptionServiceDEK
//     and TestRotateDEKWithSweep_WipesSupersededEncryptionServiceDEK are
//     memory-scan-style tests proving no DEK bytes remain afterward.

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/crypto"
)

// allZeroBytes reports whether every byte in b is 0 — the wipeBytes
// post-condition. An empty/nil slice is trivially "all zero" (nothing left to
// leak), which is also what a slice looks like after being set to nil.
func allZeroBytes(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

// ─── member 1: RewrapDEKWithProvider must take the cross-process exclusive lock ───

// TestRewrapDEKWithProvider_RefusesWhileServerHoldsLock is the direct
// regression test for G62 member 1: migrate-provider (RewrapDEKWithProvider)
// must refuse to run while a live server (or an in-progress rotation — both
// hold the same exclusive dek.lock via AcquireExclusiveKeyLock) already holds
// the key directory, exactly like RotateDEKWithSweep already does
// (TestRotateDEKWithSweep_RefusesWhileServerHoldsLock in exclusive_lock_test.go).
func TestRewrapDEKWithProvider_RefusesWhileServerHoldsLock(t *testing.T) {
	serverSvc, dir := newTestService(t, lockTestPassphrase)
	if err := serverSvc.AcquireExclusiveKeyLock(); err != nil {
		t.Fatalf("server failed to acquire its own key lock: %v", err)
	}
	defer serverSvc.Shutdown()

	migrateSvc := newTestServiceAtDir(t, dir, lockTestPassphrase)
	defer migrateSvc.Shutdown()

	newKEKPath := filepath.Join(dir, "new.kek")
	writeHexKEK(t, newKEKPath)
	newProvider := crypto.NewFileKeyProvider(newKEKPath)

	err := migrateSvc.RewrapDEKWithProvider(newProvider)
	if err == nil {
		t.Fatal("expected RewrapDEKWithProvider to be refused while the server holds the key lock")
	}
	if !strings.Contains(err.Error(), "refusing to re-wrap") {
		t.Fatalf("expected a 'refusing to re-wrap' error, got: %v", err)
	}
}

// TestRewrapDEKWithProvider_SucceedsAfterServerLockReleased is the positive
// control: once the "server" shuts down (releasing the exclusive lock),
// RewrapDEKWithProvider proceeds normally — ordinary, single-process
// migrate-provider usage must not be broken by the new lock requirement.
func TestRewrapDEKWithProvider_SucceedsAfterServerLockReleased(t *testing.T) {
	serverSvc, dir := newTestService(t, lockTestPassphrase)
	if err := serverSvc.AcquireExclusiveKeyLock(); err != nil {
		t.Fatalf("server failed to acquire its own key lock: %v", err)
	}
	serverSvc.Shutdown() // releases the lock

	migrateSvc := newTestServiceAtDir(t, dir, lockTestPassphrase)
	defer migrateSvc.Shutdown()

	newKEKPath := filepath.Join(dir, "new.kek")
	writeHexKEK(t, newKEKPath)
	newProvider := crypto.NewFileKeyProvider(newKEKPath)

	if err := migrateSvc.RewrapDEKWithProvider(newProvider); err != nil {
		t.Fatalf("RewrapDEKWithProvider should succeed once the server's lock is released: %v", err)
	}
}

// TestRewrapDEKWithProvider_RefusedDuringConcurrentRotationSweep mirrors
// TestAcquireSharedKeyLock_RefusedWhileRotationSweepInProgress: an in-progress
// RotateDEKWithSweep holds the exact same exclusive dek.lock for the duration
// of its sweep, so a concurrent migrate-provider must be refused too, not just
// while a long-lived server is up.
func TestRewrapDEKWithProvider_RefusedDuringConcurrentRotationSweep(t *testing.T) {
	rotatingSvc, dir := newTestService(t, lockTestPassphrase)
	if err := rotatingSvc.AcquireExclusiveKeyLock(); err != nil {
		t.Fatalf("rotation failed to acquire the exclusive key lock: %v", err)
	}
	defer rotatingSvc.Shutdown()

	migrateSvc := newTestServiceAtDir(t, dir, lockTestPassphrase)
	defer migrateSvc.Shutdown()

	newKEKPath := filepath.Join(dir, "new.kek")
	writeHexKEK(t, newKEKPath)
	newProvider := crypto.NewFileKeyProvider(newKEKPath)

	err := migrateSvc.RewrapDEKWithProvider(newProvider)
	if err == nil {
		t.Fatal("expected RewrapDEKWithProvider to be refused while a rotation sweep holds the exclusive key lock")
	}
}

// ─── member 2: EncryptionService.dek must be wiped, not leaked in memory ───

// TestServiceShutdown_WipesEncryptionServiceDEK is the memory-scan-style
// regression test for G62 member 2: Service.Shutdown() called
// s.keyManager.Wipe() (which only zeroes km.currentDEK) but never wiped
// s.encryptionService.dek — a SEPARATE copy of the DEK bytes made via
// s.keyManager.GetDEK() in Initialize — leaving a live copy of the DEK in
// process memory after "shutdown". This captures a reference to the DEK
// backing array before Shutdown and asserts every byte is zero afterward.
func TestServiceShutdown_WipesEncryptionServiceDEK(t *testing.T) {
	svc, _ := newTestService(t, lockTestPassphrase)

	svc.mu.RLock()
	if svc.encryptionService == nil {
		svc.mu.RUnlock()
		t.Fatal("test setup bug: expected an initialized encryptionService before Shutdown")
	}
	dekRef := svc.encryptionService.dek // same backing array wipeBytes must zero in place
	svc.mu.RUnlock()

	if allZeroBytes(dekRef) {
		t.Fatal("test setup bug: DEK was already all-zero before Shutdown")
	}

	svc.Shutdown()

	if !allZeroBytes(dekRef) {
		t.Fatal("EncryptionService.dek was not wiped by Shutdown — DEK bytes remain live in process memory")
	}

	svc.mu.RLock()
	stillReferenced := svc.encryptionService != nil
	svc.mu.RUnlock()
	if stillReferenced {
		t.Error("expected Service.encryptionService to be cleared (nil) after Shutdown")
	}
}

// TestRotateDEKWithSweep_WipesSupersededEncryptionServiceDEK is the
// memory-scan-style regression test for the other half of G62 member 2: when
// RotateDEKWithSweep replaces s.encryptionService with a new one bound to the
// freshly-rotated DEK, the OLD EncryptionService (bound to the now-superseded
// DEK) becomes unreachable through s but its DEK-bytes copy was never wiped —
// unlike km.currentDEK, which the key-manager layer does wipe on the same
// rotation. This captures the pre-rotation DEK backing array and asserts it is
// zeroed once the rotation completes and the old EncryptionService is
// discarded.
func TestRotateDEKWithSweep_WipesSupersededEncryptionServiceDEK(t *testing.T) {
	svc, _ := newTestService(t, lockTestPassphrase)
	defer svc.Shutdown()

	svc.mu.RLock()
	oldDEKRef := svc.encryptionService.dek
	svc.mu.RUnlock()
	if allZeroBytes(oldDEKRef) {
		t.Fatal("test setup bug: DEK was already all-zero before rotation")
	}

	db := newTestDB(t)
	if _, err := svc.RotateDEKWithSweep(lockTestPassphrase, db); err != nil {
		t.Fatalf("RotateDEKWithSweep failed: %v", err)
	}

	if !allZeroBytes(oldDEKRef) {
		t.Fatal("the pre-rotation EncryptionService's DEK copy was not wiped after being superseded by RotateDEKWithSweep")
	}

	// Non-regression: the NEW encryption service (the one actually in use after
	// rotation) must still work — this fix must not have wiped the wrong slice.
	svc.mu.RLock()
	newDEKRef := svc.encryptionService.dek
	svc.mu.RUnlock()
	if allZeroBytes(newDEKRef) {
		t.Fatal("the post-rotation (live) EncryptionService's DEK was wiped too — encryption would now be broken")
	}
}
