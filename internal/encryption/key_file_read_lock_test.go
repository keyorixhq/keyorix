package encryption

// key_file_read_lock_test.go — #2602: `admin backup`'s live-server path reads
// the key files and a database snapshot while holding the key-file REWRITE
// lock (<dek_path>.lock) in shared mode via Service.AcquireKeyFileReadLock.
// Its safety rests on two properties of that lock, pinned here:
//
//  1. It excludes every key-file rewriter: a rewriter's exclusive request
//     (acquireExclusiveKeyLock, taken by RotateDEKWithSweep,
//     RotateKEKPassphrase and RewrapDEK*) waits until the reader releases,
//     and a reader is refused while a rewriter holds it.
//  2. It does NOT conflict with a live server's dek.lock, which is the whole
//     point: the server holds dek.lock exclusively for its lifetime.

import (
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
)

func TestAcquireKeyFileReadLock_ExcludesKeyFileRewriters(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}

	release, err := NewService(cfg, dir).AcquireKeyFileReadLock()
	if err != nil {
		t.Fatalf("AcquireKeyFileReadLock: %v", err)
	}

	// A second reader coexists (shared mode).
	release2, err := NewService(cfg, dir).AcquireKeyFileReadLock()
	if err != nil {
		t.Fatalf("second concurrent AcquireKeyFileReadLock: %v", err)
	}
	release2()

	// A rewriter (a separate "process": its own KeyManager) must wait.
	acquired := make(chan *keyFileLock, 1)
	go func() {
		l, lerr := NewKeyManager(dir, "dek.key", "kek.salt").acquireExclusiveKeyLock()
		if lerr != nil {
			t.Errorf("rewriter acquireExclusiveKeyLock: %v", lerr)
			close(acquired)
			return
		}
		acquired <- l
	}()
	select {
	case <-acquired:
		t.Fatal("a key-file rewriter acquired the rewrite lock while a reader held it shared")
	case <-time.After(300 * time.Millisecond):
	}
	release()
	var rewriter *keyFileLock
	select {
	case rewriter = <-acquired:
	case <-time.After(5 * time.Second):
		t.Fatal("the rewriter never acquired the lock after the reader released it")
	}

	// While the rewriter holds it, a reader is refused (non-blocking).
	if rel, err := NewService(cfg, dir).AcquireKeyFileReadLock(); err == nil {
		rel()
		t.Fatal("AcquireKeyFileReadLock succeeded while a key-file rewriter held the rewrite lock")
	}
	rewriter.release()
}

func TestAcquireKeyFileReadLock_CoexistsWithLiveServerLock(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}

	server := NewService(cfg, dir)
	if err := server.AcquireExclusiveKeyLock(); err != nil {
		t.Fatalf("simulated live server AcquireExclusiveKeyLock: %v", err)
	}
	defer server.Shutdown()

	// Precondition: the live server really does hold dek.lock -- the backup's
	// old path (an exclusive dek.lock) is refused.
	if err := NewService(cfg, dir).AcquireExclusiveKeyLock(); err == nil {
		t.Fatal("precondition: a second exclusive dek.lock succeeded while the simulated server held it")
	}

	release, err := NewService(cfg, dir).AcquireKeyFileReadLock()
	if err != nil {
		t.Fatalf("AcquireKeyFileReadLock must not conflict with a live server's dek.lock: %v", err)
	}
	release()
}
