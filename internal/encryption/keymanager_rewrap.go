// keymanager_rewrap.go — KEK-provider migration: re-wrap the DEK under a new KEK
// without re-encrypting any data (ADR-041).
//
// Unlike RotateDEKWithSweep (which generates a NEW DEK and re-encrypts every row),
// RewrapDEK keeps the SAME DEK and only changes the key that wraps it on disk. The
// data path is untouched, so this is fast and holds no database lock — it is how an
// existing install moves between KEK providers (e.g. password → cloud KMS).
package encryption

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"github.com/keyorixhq/keyorix/internal/crypto"
	"github.com/keyorixhq/keyorix/internal/securefiles"
)

// RewrapDEK re-wraps the in-memory DEK with a KEK sourced from newProvider and
// atomically replaces the on-disk wrapped DEK (write-pending-then-rename). The DEK
// value is unchanged, so all existing ciphertext stays valid — only the wrapping
// key changes. The manager must already be Initialized (DEK in memory) with the
// CURRENT provider.
//
// newProvider.KEK() persists the new provider's own key material as a side effect
// (a fresh salt for password, a KMS-wrapped KEK blob for the kms providers); this
// happens before the DEK file is touched, so a failure here leaves the active DEK
// untouched and the old provider still working.
func (km *KeyManager) RewrapDEK(newProvider crypto.KeyProvider) error {
	km.mu.Lock()
	defer km.mu.Unlock()

	if km.currentDEK == nil {
		return fmt.Errorf("key manager not initialized — cannot re-wrap DEK")
	}
	if newProvider == nil {
		return fmt.Errorf("re-wrap DEK: new key provider must not be nil")
	}

	newKEK, err := newProvider.KEK()
	if err != nil {
		return fmt.Errorf("re-wrap DEK: derive KEK from %s provider: %w", newProvider.Name(), err)
	}
	defer wipeBytes(newKEK)
	if len(newKEK) != crypto.KEKSize {
		return fmt.Errorf("re-wrap DEK: %s provider returned a %d-byte KEK, expected %d", newProvider.Name(), len(newKEK), crypto.KEKSize)
	}

	// Crash-consistency checkpoint (nil in production): the new provider has now
	// persisted its own key material (e.g. a fresh salt), but the active dek.key is
	// still wrapped under the OLD KEK. See FuzzDEKRewrapCrashConsistency.
	rotationCheckpointHook("rewrap:after-provider-kek")

	// #195: acquire the cross-process exclusive DEK lock before touching
	// dek.key.pending at all, so this can never interleave with a concurrent
	// RotateDEKWithSweep (or another RewrapDEK) running in a different
	// process — both write to the same dek.key.pending → dek.key path.
	lock, err := km.acquireExclusiveKeyLock()
	if err != nil {
		return fmt.Errorf("re-wrap DEK: %w", err)
	}
	defer lock.release()

	// Mutual exclusion alone is not sufficient: km.currentDEK was captured
	// whenever this process's own Initialize() ran, which may be long before
	// this call and long before the lock above was even contended for. If a
	// concurrent RotateDEKWithSweep replaced dek.key with a NEW DEK (and
	// fully re-encrypted the database under it) in the meantime, our cached
	// currentDEK is now stale — re-wrapping and promoting it would silently
	// overwrite the freshly-rotated DEK with the superseded one, orphaning
	// every row the rotation just re-encrypted. Re-read the on-disk DEK
	// under the lock and compare it, byte-for-byte, against the snapshot
	// taken when currentDEK was set: any difference means another process
	// wrote dek.key since, so fail closed instead of clobbering it.
	onDisk, err := securefiles.SafeReadFile(km.baseDir, km.dekPath)
	if err != nil {
		return fmt.Errorf("re-wrap DEK: re-read active DEK under lock: %w", err)
	}
	if !bytes.Equal(onDisk, km.dekSnapshot) {
		return fmt.Errorf("re-wrap DEK: the on-disk DEK changed since this process started — a concurrent DEK rotation likely completed in the meantime, so the in-memory DEK here is stale. Aborting without writing to avoid discarding the newer key; re-run migrate-provider now that the rotation has finished")
	}

	wrapped, err := wrapKey(km.currentDEK, newKEK)
	if err != nil {
		return fmt.Errorf("re-wrap DEK: wrap DEK with new KEK: %w", err)
	}

	// Durability is load-bearing here: this is the one operation where the OLD
	// wrapping key is about to be retired, so the new wrapped DEK must be on disk
	// (not just in the page cache) before — and the rename durable after — we
	// declare success. A non-durable write that is lost to a power failure after
	// the operator retires the old KEK would orphan all ciphertext irreversibly.
	pendingDEKPath := km.dekPath + ".pending"
	if err := durableWriteSync(km.baseDir, pendingDEKPath, wrapped, 0600, "rewrap:write-dek-pending"); err != nil {
		return fmt.Errorf("re-wrap DEK: write pending DEK: %w", err)
	}
	// Crash-consistency checkpoint (nil in production): the new-wrapped DEK is durably
	// on disk as .pending, but the active dek.key is still the OLD wrapping.
	rotationCheckpointHook("rewrap:after-write-dek-pending")
	pendingPath := filepath.Join(km.baseDir, pendingDEKPath)
	activePath := filepath.Join(km.baseDir, km.dekPath)
	if err := durableRename(pendingPath, activePath, "rewrap:rename-dek"); err != nil {
		_ = os.Remove(pendingPath)
		return fmt.Errorf("re-wrap DEK: promote pending DEK to active: %w", err)
	}
	// Crash-consistency checkpoint (nil in production): the active dek.key is now the
	// NEW wrapping; only the directory fsync remains.
	rotationCheckpointHook("rewrap:after-rename-dek")
	if err := durableSyncDir(filepath.Dir(activePath), "rewrap:syncdir"); err != nil {
		return fmt.Errorf("re-wrap DEK: fsync key directory after promote: %w", err)
	}
	// Crash-consistency checkpoint (nil in production): the rewrap is fully durable.
	rotationCheckpointHook("rewrap:after-syncdir")
	km.dekSnapshot = append([]byte(nil), wrapped...)
	return nil
}
