// keymanager_rotation.go — DEK rotation with full re-encryption sweep (ADR-010).
//
// RotateDEKWithSweep, CleanPendingDEK, deleteBackupFiles.
// For initialisation see keymanager_lifecycle.go. For get/validate/wipe see keymanager_io.go.
package encryption

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/keyorixhq/keyorix/internal/securefiles"
)

// RotateDEKWithSweep performs a true DEK rotation with a full re-encryption sweep (ADR-010).
//
// Algorithm:
//  1. Derive KEK from passphrase + existing salt
//  2. Generate new random DEK
//  3. Wrap new DEK → write to keys/dek.key.pending
//  4. Call sweepFn(oldSvc, newSvc, newKeyVersion) — caller runs this inside a DB transaction
//  5. On sweep success: atomic rename pending → active, wipe old DEK, delete backup files
//  6. On any error: delete pending file, keep old DEK active
//
// Secret values NEVER leave the sweep function — transient in memory only.
func (km *KeyManager) RotateDEKWithSweep(passphrase string, sweepFn func(oldSvc, newSvc *EncryptionService, newKeyVersion string) error) error {
	km.mu.Lock()
	defer km.mu.Unlock()

	if km.currentDEK == nil {
		return fmt.Errorf("key manager not initialized — cannot rotate")
	}

	// #195: acquire the same cross-process exclusive DEK lock as RewrapDEK.
	// Prior to this fix RotateDEKWithSweep held no cross-process lock here at
	// all — a concurrent RewrapDEK/RewrapDEKWithProvider (`migrate-provider`)
	// racing this rotation could read the DEK being replaced here and, if its
	// rename landed after this one's, silently overwrite the
	// freshly-rotated (and now fully re-encrypted-into) DEK with the
	// superseded one. Both operations write to the same
	// dek.key.pending → dek.key path, so they must be mutually exclusive.
	// (Distinct from #92's server-vs-rotation lock in service.go's
	// AcquireExclusiveKeyLock/`dek.lock`, which guards a live server process
	// against rotation — that fix is merged; this one guards two
	// rotation-family CLI ops against each other.)
	lock, err := km.acquireExclusiveKeyLock()
	if err != nil {
		return fmt.Errorf("rotate DEK: %w", err)
	}
	defer lock.release()

	kek, err := km.deriveKEK(passphrase)
	if err != nil {
		return fmt.Errorf("failed to derive KEK for DEK rotation: %w", err)
	}
	defer wipeBytes(kek)

	newDEK, err := GenerateRandomKey(32)
	if err != nil {
		return fmt.Errorf("failed to generate new DEK: %w", err)
	}

	pendingDEKPath := km.dekPath + ".pending"
	wrapped, err := wrapKey(newDEK, kek)
	if err != nil {
		wipeBytes(newDEK)
		return fmt.Errorf("failed to wrap new DEK: %w", err)
	}
	if err := securefiles.SecureWriteFileSync(km.baseDir, pendingDEKPath, wrapped, 0600); err != nil {
		wipeBytes(newDEK)
		return fmt.Errorf("failed to write pending DEK: %w", err)
	}

	oldEncSvc, err := NewEncryptionService(km.currentDEK)
	if err != nil {
		wipeBytes(newDEK)
		_ = os.Remove(filepath.Join(km.baseDir, pendingDEKPath))
		return fmt.Errorf("failed to create old encryption service: %w", err)
	}
	newEncSvc, err := NewEncryptionService(newDEK)
	if err != nil {
		wipeBytes(newDEK)
		_ = os.Remove(filepath.Join(km.baseDir, pendingDEKPath))
		return fmt.Errorf("failed to create new encryption service: %w", err)
	}
	newKeyVersion := fmt.Sprintf("v%d", time.Now().Unix())

	if err := sweepFn(oldEncSvc, newEncSvc, newKeyVersion); err != nil {
		wipeBytes(newDEK)
		_ = os.Remove(filepath.Join(km.baseDir, pendingDEKPath))
		return fmt.Errorf("re-encryption sweep failed — old DEK remains active: %w", err)
	}

	activePath := filepath.Join(km.baseDir, km.dekPath)
	pendingPath := filepath.Join(km.baseDir, pendingDEKPath)
	if err := os.Rename(pendingPath, activePath); err != nil {
		wipeBytes(newDEK)
		_ = os.Remove(pendingPath)
		return fmt.Errorf("failed to promote pending DEK to active: %w", err)
	}
	// Make the rename durable before deleting the old-DEK backups below — else a
	// crash could lose the new DEK while the backups are already gone.
	if err := securefiles.SyncDir(filepath.Dir(activePath)); err != nil {
		wipeBytes(newDEK)
		return fmt.Errorf("failed to fsync key directory after promote: %w", err)
	}

	wipeBytes(km.currentDEK)
	km.currentDEK = newDEK
	km.dekSnapshot = append([]byte(nil), wrapped...)
	km.keyVersion = newKeyVersion
	km.deleteBackupFiles()

	fmt.Printf("✅ DEK rotated and full re-encryption sweep complete. New version: %s\n", km.keyVersion)
	return nil
}

// deleteBackupFiles removes all dek.key.backup.* files from old RotateDEK() calls.
func (km *KeyManager) deleteBackupFiles() {
	pattern := filepath.Join(km.baseDir, km.dekPath+".backup.*")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		log.Printf("[WARN] failed to glob backup DEK files: %v", err)
		return
	}
	for _, f := range matches {
		if err := os.Remove(f); err != nil {
			log.Printf("[WARN] failed to delete backup DEK file %s: %v", f, err)
		} else {
			log.Printf("[sweep] deleted backup DEK file: %s", f)
		}
	}
}

// CleanPendingDEK removes a leftover dek.key.pending file from a previously
// failed or interrupted rotation. Should be called at startup.
func (km *KeyManager) CleanPendingDEK() {
	pendingPath := filepath.Join(km.baseDir, km.dekPath+".pending")
	if _, err := os.Stat(pendingPath); err == nil {
		log.Printf("[WARN] found leftover pending DEK file %s — removing (previous rotation was interrupted)", pendingPath)
		_ = os.Remove(pendingPath)
	}
}
