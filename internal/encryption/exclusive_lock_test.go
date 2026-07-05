package encryption

// exclusive_lock_test.go — pins #92: DEK rotation must refuse to run while a live
// server (or another rotation) already holds the exclusive key lock, so the
// rotation CLI (a separate OS process) can never promote a new DEK to disk while
// the server still caches the old one in memory.

import (
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
)

const lockTestPassphrase = "test-passphrase-123"

// newTestServiceAtDir is newTestService but against a caller-supplied directory,
// so a second Service can be pointed at the SAME key material — simulating the
// rotation CLI (a separate process) sharing a key directory with a running server.
func newTestServiceAtDir(t *testing.T, dir, passphrase string) *Service {
	t.Helper()
	cfg := &config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}
	svc := NewService(cfg, dir)
	if err := svc.Initialize(passphrase); err != nil {
		t.Fatalf("failed to initialize service: %v", err)
	}
	return svc
}

// TestRotateDEKWithSweep_RefusesWhileServerHoldsLock is the core regression: a
// live server (simulated by a Service that has acquired the exclusive key lock,
// exactly as the real server does at startup) must block a concurrent rotation
// attempt against the same key directory.
func TestRotateDEKWithSweep_RefusesWhileServerHoldsLock(t *testing.T) {
	serverSvc, dir := newTestService(t, lockTestPassphrase)
	if err := serverSvc.AcquireExclusiveKeyLock(); err != nil {
		t.Fatalf("server failed to acquire its own key lock: %v", err)
	}
	defer serverSvc.Shutdown()

	db := newTestDB(t)
	rotSvc := newTestServiceAtDir(t, dir, lockTestPassphrase)
	defer rotSvc.Shutdown()

	_, err := rotSvc.RotateDEKWithSweep(lockTestPassphrase, db)
	if err == nil {
		t.Fatal("expected rotation to be refused while the server holds the key lock")
	}
	if !strings.Contains(err.Error(), "refusing to rotate") {
		t.Fatalf("expected a 'refusing to rotate' error, got: %v", err)
	}
}

// TestRotateDEKWithSweep_SucceedsAfterServerLockReleased is the positive control:
// once the "server" shuts down (releasing the lock), rotation proceeds normally.
func TestRotateDEKWithSweep_SucceedsAfterServerLockReleased(t *testing.T) {
	serverSvc, dir := newTestService(t, lockTestPassphrase)
	if err := serverSvc.AcquireExclusiveKeyLock(); err != nil {
		t.Fatalf("server failed to acquire its own key lock: %v", err)
	}
	serverSvc.Shutdown() // releases the lock

	db := newTestDB(t)
	rotSvc := newTestServiceAtDir(t, dir, lockTestPassphrase)
	defer rotSvc.Shutdown()

	if _, err := rotSvc.RotateDEKWithSweep(lockTestPassphrase, db); err != nil {
		t.Fatalf("rotation should succeed once the server's lock is released: %v", err)
	}
}

// TestAcquireExclusiveKeyLock_SecondServerRefused pins the server-startup side:
// a second server instance pointed at the same key directory must not start
// while the first is live.
func TestAcquireExclusiveKeyLock_SecondServerRefused(t *testing.T) {
	first, dir := newTestService(t, lockTestPassphrase)
	if err := first.AcquireExclusiveKeyLock(); err != nil {
		t.Fatalf("first server failed to acquire the key lock: %v", err)
	}
	defer first.Shutdown()

	second := newTestServiceAtDir(t, dir, lockTestPassphrase)
	defer second.Shutdown()
	if err := second.AcquireExclusiveKeyLock(); err == nil {
		t.Fatal("expected a second server instance to be refused the key lock")
	}
}

// The tests below pin #196: local, short-lived CLI commands (status/validate/
// fix-perms/upgrade-aad/init) now participate in the SAME dek.lock coordination
// via AcquireSharedKeyLock, so they can no longer read (or write under) a DEK
// that a live server or an in-progress rotation sweep is concurrently
// replacing — while still never contending with each other.

// TestAcquireSharedKeyLock_RefusedWhileServerHoldsLock proves requirement (1):
// a local CLI operation taking the shared lock must be refused, with a clear
// error, while a live server (simulated exactly as
// TestRotateDEKWithSweep_RefusesWhileServerHoldsLock does, by a Service that
// has acquired the exclusive lock) holds the key directory.
func TestAcquireSharedKeyLock_RefusedWhileServerHoldsLock(t *testing.T) {
	serverSvc, dir := newTestService(t, lockTestPassphrase)
	if err := serverSvc.AcquireExclusiveKeyLock(); err != nil {
		t.Fatalf("server failed to acquire its own key lock: %v", err)
	}
	defer serverSvc.Shutdown()

	cliSvc := newTestServiceAtDir(t, dir, lockTestPassphrase)
	defer cliSvc.Shutdown()

	err := cliSvc.AcquireSharedKeyLock()
	if err == nil {
		t.Fatal("expected the local CLI operation to be refused the shared lock while the server holds it exclusively")
	}
	if !strings.Contains(err.Error(), "exclusively") {
		t.Fatalf("expected an error explaining the key directory is held exclusively, got: %v", err)
	}
}

// TestAcquireSharedKeyLock_RefusedWhileRotationSweepInProgress proves the other
// half of requirement (1): the exact scenario in the bug report — a CLI
// command reading/writing key material while RotateDEKWithSweep is mid-flight
// on a different process. RotateDEKWithSweep holds the exclusive dek.lock for
// the duration of its sweep (AcquireExclusiveKeyLock, called at the top of
// RotateDEKWithSweep) — simulated here the same way, by a Service holding that
// same exclusive lock — so a concurrent local CLI operation must be refused.
func TestAcquireSharedKeyLock_RefusedWhileRotationSweepInProgress(t *testing.T) {
	rotatingSvc, dir := newTestService(t, lockTestPassphrase)
	if err := rotatingSvc.AcquireExclusiveKeyLock(); err != nil {
		t.Fatalf("rotation failed to acquire the exclusive key lock: %v", err)
	}
	defer rotatingSvc.Shutdown()

	cliSvc := newTestServiceAtDir(t, dir, lockTestPassphrase)
	defer cliSvc.Shutdown()

	err := cliSvc.AcquireSharedKeyLock()
	if err == nil {
		t.Fatal("expected the local CLI operation to be refused the shared lock while a rotation sweep holds it exclusively")
	}
	if !strings.Contains(err.Error(), "rotation") {
		t.Fatalf("expected the error to mention the in-progress rotation, got: %v", err)
	}
}

// TestAcquireSharedKeyLock_SucceedsWhenNoServerOrRotationHoldsLock is the
// non-regression control for requirement (2): ordinary CLI usage — no server
// running, no rotation in progress — must not be broken by requiring a lock
// that would never be granted in that scenario.
func TestAcquireSharedKeyLock_SucceedsWhenNoServerOrRotationHoldsLock(t *testing.T) {
	svc, _ := newTestService(t, lockTestPassphrase)
	defer svc.Shutdown()

	if err := svc.AcquireSharedKeyLock(); err != nil {
		t.Fatalf("expected the shared lock to be granted when nothing else holds it, got: %v", err)
	}
}

// TestAcquireSharedKeyLock_SucceedsAfterExclusiveLockReleased is the positive
// control mirroring TestRotateDEKWithSweep_SucceedsAfterServerLockReleased:
// once the server/rotation releases the exclusive lock, a local CLI operation
// against the same key directory proceeds normally.
func TestAcquireSharedKeyLock_SucceedsAfterExclusiveLockReleased(t *testing.T) {
	serverSvc, dir := newTestService(t, lockTestPassphrase)
	if err := serverSvc.AcquireExclusiveKeyLock(); err != nil {
		t.Fatalf("server failed to acquire its own key lock: %v", err)
	}
	serverSvc.Shutdown() // releases the lock

	cliSvc := newTestServiceAtDir(t, dir, lockTestPassphrase)
	defer cliSvc.Shutdown()

	if err := cliSvc.AcquireSharedKeyLock(); err != nil {
		t.Fatalf("shared lock should be granted once the exclusive holder's lock is released: %v", err)
	}
}

// TestAcquireSharedKeyLock_MultipleReadersDoNotBlockEachOther proves shared
// locks are, as the name implies, shared: several concurrent local CLI
// operations against the same key directory (e.g. two operators independently
// running `status`) must not contend with each other, unlike the exclusive
// lock the server/rotation use.
func TestAcquireSharedKeyLock_MultipleReadersDoNotBlockEachOther(t *testing.T) {
	first, dir := newTestService(t, lockTestPassphrase)
	defer first.Shutdown()
	if err := first.AcquireSharedKeyLock(); err != nil {
		t.Fatalf("first reader failed to acquire the shared lock: %v", err)
	}

	second := newTestServiceAtDir(t, dir, lockTestPassphrase)
	defer second.Shutdown()
	if err := second.AcquireSharedKeyLock(); err != nil {
		t.Fatalf("second concurrent reader should not be blocked by the first, got: %v", err)
	}
}
