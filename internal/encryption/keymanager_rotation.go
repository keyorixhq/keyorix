// keymanager_rotation.go — DEK rotation with full re-encryption sweep (ADR-010).
//
// RotateDEKWithSweep (preferred), RotateDEK (deprecated), CleanPendingDEK, deleteBackupFiles.
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

	if passphrase == "" {
		return fmt.Errorf("master passphrase must not be empty")
	}
	if km.currentDEK == nil {
		return fmt.Errorf("key manager not initialized — cannot rotate")
	}

	salt, err := securefiles.SafeReadFile(km.baseDir, km.saltPath)
	if err != nil {
		return fmt.Errorf("failed to read salt for DEK rotation: %w", err)
	}
	kek := GenerateKEK(passphrase, salt, 600000)
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
	if err := securefiles.SecureWriteFile(km.baseDir, pendingDEKPath, wrapped, 0600); err != nil {
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

	wipeBytes(km.currentDEK)
	km.currentDEK = newDEK
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

// RotateDEK generates a new DEK and writes it to disk without re-encrypting existing secrets.
//
// DEPRECATED: Use RotateDEKWithSweep instead. This method causes key proliferation —
// existing secrets remain encrypted with the old DEK and backup files accumulate.
// See ADR-010.
func (km *KeyManager) RotateDEK(passphrase string) error {
	km.mu.Lock()
	defer km.mu.Unlock()

	if passphrase == "" {
		return fmt.Errorf("master passphrase must not be empty")
	}

	salt, err := securefiles.SafeReadFile(km.baseDir, km.saltPath)
	if err != nil {
		return fmt.Errorf("failed to read salt for DEK rotation: %w", err)
	}
	kek := GenerateKEK(passphrase, salt, 600000)
	defer wipeBytes(kek)

	newDEK, err := GenerateRandomKey(32)
	if err != nil {
		return fmt.Errorf("failed to generate new DEK: %w", err)
	}

	oldDEKPath := fmt.Sprintf("%s.backup.%d", km.dekPath, time.Now().Unix())
	oldWrapped, err := securefiles.SafeReadFile(km.baseDir, km.dekPath)
	if err != nil {
		return fmt.Errorf("failed to read old DEK for backup: %w", err)
	}
	if err := securefiles.SecureWriteFile(km.baseDir, oldDEKPath, oldWrapped, 0600); err != nil {
		return fmt.Errorf("failed to backup old DEK: %w", err)
	}

	wrapped, err := wrapKey(newDEK, kek)
	if err != nil {
		return fmt.Errorf("failed to wrap new DEK: %w", err)
	}
	if err := securefiles.SecureWriteFile(km.baseDir, km.dekPath, wrapped, 0600); err != nil {
		return fmt.Errorf("failed to write new wrapped DEK: %w", err)
	}

	wipeBytes(km.currentDEK)
	km.currentDEK = newDEK
	km.keyVersion = fmt.Sprintf("v%d", time.Now().Unix())

	fmt.Printf("✅ DEK rotated successfully. New version: %s\n", km.keyVersion)
	return nil
}
