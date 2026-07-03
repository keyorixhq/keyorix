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

	err := rotSvc.RotateDEKWithSweep(lockTestPassphrase, db)
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

	if err := rotSvc.RotateDEKWithSweep(lockTestPassphrase, db); err != nil {
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
