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
	if err := durableWriteSync(km.baseDir, pendingSaltPath, newSalt, 0600, "kek:write-salt-pending"); err != nil {
		return fmt.Errorf("rotate KEK: write pending salt: %w", err)
	}
	rotationCheckpointHook("kek:after-write-salt-pending")
	pendingDEKPath := km.dekPath + ".pending"
	if err := durableWriteSync(km.baseDir, pendingDEKPath, newWrappedDEK, 0600, "kek:write-dek-pending"); err != nil {
		_ = os.Remove(filepath.Join(km.baseDir, pendingSaltPath))
		return fmt.Errorf("rotate KEK: write pending DEK: %w", err)
	}
	rotationCheckpointHook("kek:after-write-dek-pending")
	pendingDEKFull := filepath.Join(km.baseDir, pendingDEKPath)
	activeDEKFull := filepath.Join(km.baseDir, km.dekPath)
	if err := durableRename(pendingDEKFull, activeDEKFull, "kek:rename-dek"); err != nil {
		// Do not assume the rename didn't happen: an error here can be reported
		// AFTER the rename actually applied (e.g. an NFS lost-reply/retransmit
		// ambiguity — see docs/findings/2026-09-19-FINDING-kek-rotation-rename-dek-cleanup-dataloss.md).
		// Verify the ACTUAL on-disk state before deciding whether kek.salt.pending
		// — the only recovery material for the hazard window below — is safe to
		// delete. A prior version of this code deleted it unconditionally here,
		// which orphaned the DEK permanently whenever the rename had, in fact,
		// already succeeded. A LATER version of this code fixed that but still
		// treated "could not confirm the rename succeeded" (e.g. a read/stat
		// error verifying the outcome) as equivalent to "confirmed it did not" —
		// which is unsound whenever the SAME transient condition that made the
		// rename report a spurious error also disrupts the verification read
		// (the identical class of NFS blip can plausibly hit both). Classify
		// into three outcomes instead of two, and fail-safe (delete nothing) on
		// genuine uncertainty rather than treating uncertainty as "safe to
		// clean up."
		switch classifyDEKRename(km.baseDir, km.dekPath, pendingDEKFull, km.dekSnapshot, newWrappedDEK) {
		case dekRenameNotApplied:
			_ = os.Remove(filepath.Join(km.baseDir, pendingSaltPath))
			_ = os.Remove(pendingDEKFull)
			return fmt.Errorf("rotate KEK: promote pending DEK to active: %w", err)
		case dekRenameUnknown:
			return fmt.Errorf("rotate KEK: promote pending DEK to active: outcome could not be confirmed (the rename reported an error, but whether it actually applied is unknown — no pending files were removed; re-run rotate-kek, or inspect %s and %s manually before proceeding): %w", pendingDEKPath, pendingSaltPath, err)
		case dekRenameApplied:
			// The rename actually applied despite the reported error: fall
			// through and complete the rotation exactly as the success path
			// would (same as what a genuine kek:after-rename-dek crash-recovery
			// would reach) — kek.salt.pending must survive for the salt rename
			// below, or for an operator to apply manually if that also fails.
		}
	}
	// Surfaced, not discarded: an un-fsynced directory entry after a rename is
	// not guaranteed durable across a power loss (the classic "rename without
	// fsync(dir)" hazard — see
	// docs/findings/2026-09-19-DRAFT-ISSUE-kek-rotation-syncdir-discarded.md).
	// Fail the rotation here, before attempting the salt rename below, rather
	// than building a second durability step on top of an unconfirmed one.
	if err := durableSyncDir(filepath.Dir(activeDEKFull), "kek:syncdir-dek"); err != nil {
		return fmt.Errorf("rotate KEK: fsync key directory after promoting DEK (the DEK rename itself succeeded — its durability is unconfirmed; retry rotate-kek, or manually fsync the key directory, before completing the salt rename): %w", err)
	}
	// Hazard window: dek.key is now the new-wrapped DEK (KEK from the NEW salt),
	// but kek.salt on disk is still the OLD salt — recovery here needs the
	// leftover kek.salt.pending. Crash-consistency tests interrupt exactly here.
	rotationCheckpointHook("kek:after-rename-dek")
	pendingSaltFull := filepath.Join(km.baseDir, pendingSaltPath)
	activeSaltFull := filepath.Join(km.baseDir, km.saltPath)
	if err := durableRename(pendingSaltFull, activeSaltFull, "kek:rename-salt"); err != nil {
		return fmt.Errorf("rotate KEK: promote pending salt to active (DEK rename already succeeded — manually rename %s to %s to complete): %w", pendingSaltPath, km.saltPath, err)
	}
	// Surfaced, not discarded — see the kek:syncdir-dek comment above. This is
	// the LAST step: the rename itself already fully applied the rotation on
	// disk, so a failure here means only its durability is unconfirmed, not
	// that the rotation didn't happen.
	if err := durableSyncDir(filepath.Dir(activeSaltFull), "kek:syncdir-salt"); err != nil {
		return fmt.Errorf("rotate KEK: fsync key directory after promoting salt (the rotation itself already fully applied on disk — its durability is unconfirmed; retry to confirm): %w", err)
	}
	rotationCheckpointHook("kek:after-rename-salt")
	return nil
}

// dekRenameOutcome classifies what a rename-dek error actually means on
// disk, after durableRename has already reported that error. Three-way, not
// boolean: an earlier version of this classification collapsed "confirmed
// not applied" and "could not confirm either way" into a single false value,
// which is unsound — the transient condition that made the rename report a
// spurious error in the first place (e.g. an NFS lost-reply ambiguity) can
// plausibly ALSO disrupt the verification read/stat itself, and treating
// that as "safe to clean up" reopens the exact permanent-data-loss path this
// whole verify-before-cleanup mechanism exists to close.
type dekRenameOutcome int

const (
	// dekRenameNotApplied: the rename's source file still exists. A rename
	// atomically moves its source — if it's still there, the rename
	// definitively did not happen. Safe to clean up exactly as before this
	// fix existed.
	dekRenameNotApplied dekRenameOutcome = iota
	// dekRenameApplied: the source is confirmed gone AND the active DEK file
	// holds exactly the bytes this call tried to promote. The rename
	// definitively did happen despite the reported error.
	dekRenameApplied
	// dekRenameUnknown: neither of the above could be confirmed — a stat or
	// read error verifying the outcome, or the active content matching
	// neither the old nor the new wrapped DEK. The caller MUST treat this as
	// "cannot rule out success": deleting kek.salt.pending here risks
	// exactly the data loss this fix exists to prevent, so nothing gets
	// deleted and the caller must fail loudly instead.
	dekRenameUnknown
)

// classifyDEKRename determines which of the three outcomes above applies.
// pendingDEKFull is the rename's source path (baseDir/dekPath+".pending");
// oldWrapped/newWrapped are the wrapped-DEK bytes active before/after this
// rotation (the caller's km.dekSnapshot, and the value this call tried to
// promote, respectively).
//
// Deliberately read-and-compare, not a size/mtime heuristic: a stat-only
// check on the DESTINATION cannot distinguish genuinely new content from old
// content of coincidentally the same size, and mtimes are not a reliable
// durability signal either. The SOURCE check, by contrast, is a plain
// existence stat — rename's atomicity guarantee makes that sufficient on its
// own for the NotApplied direction, no content comparison needed.
func classifyDEKRename(baseDir, dekPath, pendingDEKFull string, oldWrapped, newWrapped []byte) dekRenameOutcome {
	// Test-only seam (nil in production): lets a test simulate the SAME class
	// of transient failure that made the rename itself report a spurious
	// error ALSO disrupting this verification — e.g. one NFS blip affecting
	// both the RENAME and the follow-up GETATTR/READ. See
	// FuzzFaultInjectedOperations's combined rename-dek+verification-failure
	// case, which exists specifically to prove this path fails safe (deletes
	// nothing) rather than fail open.
	if fileFaultHook != nil {
		if fileFaultHook("kek:verify-rename-dek") != nil {
			return dekRenameUnknown
		}
	}
	if _, err := os.Stat(pendingDEKFull); err == nil { // #nosec G304 -- fixed internal key-directory path
		return dekRenameNotApplied
	} else if !os.IsNotExist(err) {
		return dekRenameUnknown // couldn't even confirm the source is gone
	}
	got, err := securefiles.SafeReadFile(baseDir, dekPath)
	if err != nil {
		return dekRenameUnknown
	}
	if bytes.Equal(got, newWrapped) {
		return dekRenameApplied
	}
	if bytes.Equal(got, oldWrapped) {
		// Source vanished but the active content is still old — inconsistent
		// with either a genuine successful rename (would show new content) or
		// a genuine no-op (the source would still be there); cannot be
		// trusted either way.
		return dekRenameUnknown
	}
	return dekRenameUnknown // matches neither old nor new
}
