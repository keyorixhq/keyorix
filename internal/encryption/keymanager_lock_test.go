package encryption

// keymanager_lock_test.go — regression tests for #195: RewrapDEK never
// participated in the DEK-rotation exclusive-lock coordination, so it could
// race a concurrent RotateDEKWithSweep and permanently orphan the database's
// ciphertext.
//
// TestAcquireExclusiveKeyLock_MutualExclusion proves the lock primitive
// itself: many goroutines, each with its own KeyManager (simulating separate
// CLI processes), race to hold it and never overlap.
//
// TestRewrapAndRotate_ConcurrentRace_FinalDEKMatchesDB is the higher-value
// test: it runs the actual RotateDEKWithSweep and RewrapDEKWithProvider
// operations concurrently against a shared on-disk DEK and a shared
// database, and asserts the security property that matters — whichever one
// "wins" the race, the DEK left on disk once both finish is the one the
// database was actually re-encrypted under, never a stale, superseded one.

import (
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/crypto"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// TestAcquireExclusiveKeyLock_MutualExclusion proves the flock-based
// exclusive lock actually serialises concurrent holders. Each goroutine uses
// its OWN KeyManager instance pointed at the same key directory — mirroring
// two independently-invoked CLI processes racing for the same
// dek.key.lock — so nothing but the file lock itself can prevent overlap.
func TestAcquireExclusiveKeyLock_MutualExclusion(t *testing.T) {
	dir := t.TempDir()

	const goroutines = 16
	var (
		current int32
		maxSeen int32
		wg      sync.WaitGroup
	)

	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()

			km := NewKeyManager(dir, "dek.key", "kek.salt")
			lock, err := km.acquireExclusiveKeyLock()
			if err != nil {
				t.Errorf("acquireExclusiveKeyLock: %v", err)
				return
			}

			n := atomic.AddInt32(&current, 1)
			for {
				m := atomic.LoadInt32(&maxSeen)
				if n <= m || atomic.CompareAndSwapInt32(&maxSeen, m, n) {
					break
				}
			}
			// Hold the lock briefly to widen the window in which a broken
			// implementation would let a second holder in.
			time.Sleep(5 * time.Millisecond)
			atomic.AddInt32(&current, -1)

			lock.release()
		}()
	}
	wg.Wait()

	if got := atomic.LoadInt32(&maxSeen); got != 1 {
		t.Fatalf("exclusive lock allowed %d concurrent holders, want at most 1", got)
	}
}

// TestRewrapAndRotate_ConcurrentRace_FinalDEKMatchesDB is the direct
// regression test for #195. svcA and svcB are two SEPARATE Service/
// KeyManager instances — simulating the two independent CLI processes behind
// `keyorix encryption rotate --confirm` and `keyorix encryption
// migrate-provider --confirm` — both Initialized against the SAME on-disk
// DEK before racing: A rotates (generates a NEW DEK and re-encrypts the
// database under it), B re-wraps whatever DEK it already has in memory under
// a different KEK provider. Regardless of which the OS scheduler lets run
// first, dek.key on disk once both finish must unwrap to the DEK the
// database was last actually re-encrypted under.
func TestRewrapAndRotate_ConcurrentRace_FinalDEKMatchesDB(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.EncryptionConfig{
		Enabled:  true,
		DEKPath:  "dek.key",
		SaltPath: "kek.salt",
	}
	db := newTestDB(t)

	// Both "processes" start from the SAME current (password) provider —
	// exactly how rotate and migrate-provider both Initialize() against the
	// currently-configured provider before racing.
	svcA := NewService(cfg, dir)
	if err := svcA.Initialize("test-passphrase"); err != nil {
		t.Fatalf("init A (rotate side): %v", err)
	}
	svcB := NewService(cfg, dir)
	if err := svcB.Initialize("test-passphrase"); err != nil {
		t.Fatalf("init B (rewrap side): %v", err)
	}

	const projectID = uint(1)
	nodeID := seedSecretNode(t, db, projectID)
	versionID := seedSecretVersion(t, db, svcA, nodeID, projectID, 1, "top-secret-race-value")

	// Process B's migration target: a brand-new file-backed KEK provider,
	// distinct from the current password provider.
	newKEKPath := filepath.Join(dir, "new.kek")
	writeHexKEK(t, newKEKPath)
	newProvider := crypto.NewFileKeyProvider(newKEKPath)

	var wg sync.WaitGroup
	wg.Add(2)
	var rotateErr, rewrapErr error
	go func() {
		defer wg.Done()
		rotateErr = svcA.RotateDEKWithSweep("test-passphrase", db)
	}()
	go func() {
		defer wg.Done()
		rewrapErr = svcB.RewrapDEKWithProvider(newProvider)
	}()
	wg.Wait()

	// Rotate must always succeed — a concurrent rewrap attempt must never be
	// able to block or corrupt it.
	if rotateErr != nil {
		t.Fatalf("RotateDEKWithSweep failed under concurrent rewrap: %v", rotateErr)
	}
	// Rewrap either wins cleanly, or correctly detects that the DEK it holds
	// went stale under it and aborts rather than clobbering the rotated one.
	// Both are safe outcomes; the invariant checked below is what matters.
	t.Logf("concurrent RewrapDEKWithProvider result: %v", rewrapErr)

	// Fetch the row rotate's sweep re-encrypted and confirm svcA (which now
	// holds the freshly-rotated DEK) can still decrypt it — the DB and svcA's
	// in-memory DEK must agree.
	var v models.SecretVersion
	if err := db.First(&v, versionID).Error; err != nil {
		t.Fatalf("failed to fetch SecretVersion: %v", err)
	}
	aad := SecretAAD(nodeID, projectID, 1)
	plaintext, err := svcA.DecryptSecretWithAAD(v.EncryptedValue, aad)
	if err != nil {
		t.Fatalf("decrypt post-rotation row with svcA: %v", err)
	}
	if string(plaintext) != "top-secret-race-value" {
		t.Fatalf("unexpected plaintext after rotation: %q", plaintext)
	}

	// Now resolve whichever DEK is ACTUALLY on disk right now, independently
	// of which candidate provider wrapped it, and confirm it is byte-
	// identical to svcA's post-rotation in-memory DEK — i.e. the file left
	// behind is never the stale pre-rotation value.
	finalDEK := resolveFinalDEK(t, dir, cfg, "test-passphrase", newProvider)
	postRotateDEK := captureCurrentDEK(t, svcA)
	if string(finalDEK) != string(postRotateDEK) {
		t.Fatalf("on-disk DEK after the race does not match the DEK the database was re-encrypted under — ciphertext orphaned")
	}
}

// resolveFinalDEK unwraps whatever is currently on disk at
// dir/cfg.DEKPath using WHICHEVER of the two candidate providers — the
// original password provider (cfg/passphrase), or the rewrap target
// (newProvider) — actually succeeds, and returns the resulting raw DEK
// bytes. Exactly one candidate is expected to work: dek.key is wrapped
// under a single KEK at any moment, so only the matching provider can
// unwrap it.
func resolveFinalDEK(t *testing.T, dir string, cfg *config.EncryptionConfig, passphrase string, newProvider crypto.KeyProvider) []byte {
	t.Helper()

	kmOld := NewKeyManager(dir, cfg.DEKPath, cfg.SaltPath)
	kmOld.SetKeyProvider(crypto.NewPasswordKeyProvider(passphrase, dir, cfg.SaltPath))
	errOld := kmOld.Initialize(passphrase)

	kmNew := NewKeyManager(dir, cfg.DEKPath, cfg.SaltPath)
	kmNew.SetKeyProvider(newProvider)
	errNew := kmNew.Initialize("")

	switch {
	case errOld == nil && errNew != nil:
		return kmOld.GetDEK()
	case errNew == nil && errOld != nil:
		return kmNew.GetDEK()
	case errOld == nil && errNew == nil:
		t.Fatalf("both the old and new KEK providers unwrapped dek.key — expected exactly one to work")
	default:
		t.Fatalf("neither candidate provider could unwrap the final dek.key: old=%v new=%v", errOld, errNew)
	}
	return nil
}
