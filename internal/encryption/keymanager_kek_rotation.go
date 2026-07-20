// keymanager_kek_rotation.go — passphrase-only KEK rotation (rotate-kek).
//
// RotateKEKPassphrase re-wraps the current DEK under a new KEK derived from a
// new passphrase + a freshly generated salt, without touching the database or
// changing the DEK value. Evidence-signing and audit-checkpoint keys change
// because they are KEK-derived.
//
// Unlike RotateDEKWithSweep (new DEK, full re-encryption sweep) and
// RewrapDEK (new KEK provider, no passphrase), this operation stays entirely
// within the password/passphrase KEK provider and is the intended path for
// an operator who needs to rotate the master passphrase.
package encryption

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/keyorixhq/keyorix/internal/securefiles"
)

// RotateKEKPassphrase re-wraps the current DEK under a new KEK derived from
// newPassphrase + a freshly generated salt, without touching the database.
// The old passphrase must match what the manager was initialized with (verified
// by attempting an unwrap before any file is modified). Evidence-signing and
// audit-checkpoint keys change because they are KEK-derived.
//
// Both oldPassphrase and newPassphrase must be non-empty. The same value for
// both is allowed and simply re-derives the KEK with a new random salt.
//
// The manager must already be Initialized (currentDEK in memory).
func (km *KeyManager) RotateKEKPassphrase(oldPassphrase, newPassphrase string) error {
	km.mu.Lock()
	defer km.mu.Unlock()

	if km.currentDEK == nil {
		return fmt.Errorf("key manager not initialized — cannot rotate KEK")
	}
	if oldPassphrase == "" {
		return fmt.Errorf("rotate KEK: old passphrase must not be empty")
	}
	if newPassphrase == "" {
		return fmt.Errorf("rotate KEK: new passphrase must not be empty")
	}

	// Acquire the same cross-process exclusive DEK lock that RewrapDEK and
	// RotateDEKWithSweep use — we write to the same dek.key.pending → dek.key
	// path and must never interleave with a concurrent rotation.
	lock, err := km.acquireExclusiveKeyLock()
	if err != nil {
		return fmt.Errorf("rotate KEK: %w", err)
	}
	defer lock.release()

	// Re-read the on-disk wrapped DEK under the exclusive lock and compare it
	// against the snapshot taken when currentDEK was last set. If another
	// process rotated the DEK in the meantime, our in-memory currentDEK is now
	// stale — abort rather than overwriting the newer key (mirrors
	// RewrapDEK's staleness check, #195).
	onDisk, err := securefiles.SafeReadFile(km.baseDir, km.dekPath)
	if err != nil {
		return fmt.Errorf("rotate KEK: re-read active DEK under lock: %w", err)
	}
	if !bytes.Equal(onDisk, km.dekSnapshot) {
		return fmt.Errorf("rotate KEK: the on-disk DEK changed since this process started — a concurrent DEK rotation likely completed in the meantime; re-run rotate-kek now that the rotation has finished")
	}

	// Read the current salt from disk so we can derive the current KEK and
	// verify oldPassphrase is correct before touching any file.
	currentSalt, err := securefiles.SafeReadFile(km.baseDir, km.saltPath)
	if err != nil {
		return fmt.Errorf("rotate KEK: read current salt: %w", err)
	}
	if len(currentSalt) != 32 {
		return fmt.Errorf("rotate KEK: invalid current salt size: expected 32 bytes, got %d", len(currentSalt))
	}

	// Derive the current KEK from the old passphrase and verify it unwraps the
	// on-disk DEK. This confirms the passphrase is correct BEFORE modifying any
	// file — fail closed rather than writing an unwrappable DEK on disk.
	currentKEK := GenerateKEK(oldPassphrase, currentSalt, DefaultKEKIterations)
	defer wipeBytes(currentKEK)

	if _, err := unwrapKey(onDisk, currentKEK); err != nil {
		return fmt.Errorf("rotate KEK: old passphrase is incorrect — aborting without modifying any file: %w", err)
	}

	// Generate a fresh 32-byte salt for the new KEK.
	newSalt := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, newSalt); err != nil {
		return fmt.Errorf("rotate KEK: generate new salt: %w", err)
	}

	// Derive the new KEK from newPassphrase + newSalt.
	newKEK := GenerateKEK(newPassphrase, newSalt, DefaultKEKIterations)
	defer wipeBytes(newKEK)

	// Wrap the current (unchanged) DEK with the new KEK.
	newWrappedDEK, err := wrapKey(km.currentDEK, newKEK)
	if err != nil {
		return fmt.Errorf("rotate KEK: wrap DEK with new KEK: %w", err)
	}

	if err := km.commitNewKEKFiles(newSalt, newWrappedDEK); err != nil {
		return err
	}

	// Derive new evidence-signing and audit-checkpoint keys from the new KEK,
	// matching Initialize's derivation exactly, before wiping the new KEK.
	newESK, newESKID, err := deriveEvidenceSignKey(newKEK)
	if err != nil {
		return fmt.Errorf("rotate KEK: re-derive evidence-signing key: %w", err)
	}
	newACK, newACKID, err := deriveAuditCheckpointKey(newKEK)
	if err != nil {
		wipeBytes(newESK)
		return fmt.Errorf("rotate KEK: re-derive audit-checkpoint key: %w", err)
	}

	// Update in-memory state under the already-held mu.Lock.
	wipeBytes(km.evidenceSignKey)
	km.evidenceSignKey = newESK
	km.evidenceSignKeyID = newESKID

	wipeBytes(km.auditCheckpointKey)
	km.auditCheckpointKey = newACK
	km.auditCheckpointKeyID = newACKID

	km.dekSnapshot = append([]byte(nil), newWrappedDEK...)

	return nil
}

// commitNewKEKFiles writes newSalt and newWrappedDEK as pending files and then
// atomically renames them into place (DEK first, then salt). On any write/rename
// failure the original files are untouched. The pending DEK file is cleaned up on
// partial failure so the next retry starts clean.
//
// Ordering: DEK is renamed before salt so that a crash between the two renames
// leaves the new DEK (wrapped under the new KEK + new salt) with the old salt still
// on disk. The pending salt file allows the operator to complete the rename manually.
func (km *KeyManager) commitNewKEKFiles(newSalt, newWrappedDEK []byte) error {
	pendingSaltPath := km.saltPath + ".pending"
	if err := securefiles.SecureWriteFileSync(km.baseDir, pendingSaltPath, newSalt, 0600); err != nil {
		return fmt.Errorf("rotate KEK: write pending salt: %w", err)
	}
	pendingDEKPath := km.dekPath + ".pending"
	if err := securefiles.SecureWriteFileSync(km.baseDir, pendingDEKPath, newWrappedDEK, 0600); err != nil {
		_ = os.Remove(filepath.Join(km.baseDir, pendingSaltPath))
		return fmt.Errorf("rotate KEK: write pending DEK: %w", err)
	}
	pendingDEKFull := filepath.Join(km.baseDir, pendingDEKPath)
	activeDEKFull := filepath.Join(km.baseDir, km.dekPath)
	if err := os.Rename(pendingDEKFull, activeDEKFull); err != nil {
		_ = os.Remove(filepath.Join(km.baseDir, pendingSaltPath))
		_ = os.Remove(pendingDEKFull)
		return fmt.Errorf("rotate KEK: promote pending DEK to active: %w", err)
	}
	_ = securefiles.SyncDir(filepath.Dir(activeDEKFull)) // best-effort
	pendingSaltFull := filepath.Join(km.baseDir, pendingSaltPath)
	activeSaltFull := filepath.Join(km.baseDir, km.saltPath)
	if err := os.Rename(pendingSaltFull, activeSaltFull); err != nil {
		return fmt.Errorf("rotate KEK: promote pending salt to active (DEK rename already succeeded — manually rename %s to %s to complete): %w", pendingSaltPath, km.saltPath, err)
	}
	_ = securefiles.SyncDir(filepath.Dir(activeSaltFull)) // best-effort
	return nil
}
