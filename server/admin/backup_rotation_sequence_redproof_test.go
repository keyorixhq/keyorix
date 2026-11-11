// backup_rotation_sequence_redproof_test.go (C2, task 4): red/green proofs that
// the sequence fuzzer's oracles actually fire on a planted defect and stay
// silent on a matched control. A green oracle nobody has watched fail is not a
// guard (CLAUDE.md).
//
// Two planted defects, each paired with a silent control:
//   - "a backup that silently drops .pending": the clean-host-decrypt oracle
//     must catch the undecryptable archive it produces; the real (refusing)
//     backup is the control.
//   - "a restore that accepts a mixed-generation key set": ReconcileKeySet (the
//     guard restore relies on) must refuse the mixed set; a coherent set is the
//     control.
//
// Default CI (SQLite).
package admin

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/i18n"
)

// runBackupHere runs the real admin backup from the host's key dir and returns
// (archivePath, err). archivePath exists only on success.
func (h *seqHost) runBackupHere() (string, error) {
	chdirTest(h.t, h.dir)
	configPathFlag = h.writeConfig(h.dir, h.dbPathOrDSN)
	archive := filepath.Join(h.t.TempDir(), "redproof-backup.tar.gz")
	backupOutput = archive
	backupExclusive = !h.pg
	_, err := captureStdout(h.t, func() error { return runAdminBackup(nil, nil) })
	return archive, err
}

// TestSeqRedProof_BackupDroppingPending proves the contract oracle (a successful
// backup must restore+decrypt on a clean host) catches a backup that silently
// drops the DEK .pending file in state B.
func TestSeqRedProof_BackupDroppingPending(t *testing.T) {
	resetBackupRestoreFlags(t)
	require.NoError(t, i18n.InitializeForTesting())

	t.Run("control_real_backup_refuses_in_state_B", func(t *testing.T) {
		resetBackupRestoreFlags(t)
		h := newSeqHost(t, false, "")
		t.Setenv("KEYORIX_MASTER_PASSWORD", h.pass)
		h.opKillAtSeam(0) // state B: dek.key.pending present
		require.True(t, h.pendingPresent(), "state B must leave dek.key.pending")
		archive, err := h.runBackupHere()
		require.Error(t, err, "the real backup must refuse while dek.key.pending exists")
		_, statErr := os.Stat(archive)
		require.True(t, os.IsNotExist(statErr), "a refused backup must write no archive")
	})

	t.Run("plant_backup_drops_pending_produces_undecryptable_archive", func(t *testing.T) {
		resetBackupRestoreFlags(t)
		h := newSeqHost(t, false, "")
		t.Setenv("KEYORIX_MASTER_PASSWORD", h.pass)
		h.opKillAtSeam(0) // state B: dek.key.pending is the ONLY copy of the new DEK
		require.True(t, h.pendingPresent())

		// PLANT the defect: a backup that silently drops the .pending file and
		// proceeds. The active dek.key is still the OLD one; the DB rows are under
		// the NEW DEK (lost with the dropped pending).
		require.NoError(t, os.Remove(filepath.Join(h.dir, "dek.key.pending")))
		require.False(t, h.pendingPresent(), "defect: pending dropped")
		archive, err := h.runBackupHere()
		require.NoError(t, err, "with .pending dropped the backup is no longer refused (the defect)")
		fi, statErr := os.Stat(archive)
		require.NoError(t, statErr)
		require.Greater(t, fi.Size(), int64(0))

		// RED PROOF: the oracle catches it -- the archive restores but does NOT
		// decrypt on a clean host.
		restoreOK, decrypts := h.cleanHostTry(archive)
		require.False(t, decrypts,
			"oracle failed to catch a backup that dropped .pending: the archive decrypted")
		t.Logf("planted defect caught: restoreOK=%v decrypts=%v (undecryptable archive)", restoreOK, decrypts)
	})

	t.Run("green_control_coherent_backup_decrypts", func(t *testing.T) {
		resetBackupRestoreFlags(t)
		h := newSeqHost(t, false, "")
		t.Setenv("KEYORIX_MASTER_PASSWORD", h.pass)
		h.opRotateDEK() // coherent rotation, no interruption
		archive, err := h.runBackupHere()
		require.NoError(t, err)
		restoreOK, decrypts := h.cleanHostTry(archive)
		require.True(t, restoreOK && decrypts,
			"silent control: a coherent backup must restore and decrypt on a clean host")
	})
}

// TestSeqRedProof_RestoreMixedGeneration proves the mixed-generation guard
// (ReconcileKeySet, which restore relies on to reject an incoherent key set)
// fires on a planted mixed-generation set and is silent on a coherent one.
func TestSeqRedProof_RestoreMixedGeneration(t *testing.T) {
	resetBackupRestoreFlags(t)
	require.NoError(t, i18n.InitializeForTesting())
	h := newSeqHost(t, false, "")
	t.Setenv("KEYORIX_MASTER_PASSWORD", h.pass)

	active := filepath.Join(h.dir, "dek.key")

	// Rotate once: records generation 2 in the manifest, dek.key = gen2.
	h.opRotateDEK()
	gen2DEK, err := os.ReadFile(active)
	require.NoError(t, err)
	// Rotate again: generation 3, dek.key = gen3, manifest = gen3.
	h.opRotateDEK()

	// GREEN control: the coherent gen-3 set must reconcile without error.
	ctl := encryption.NewService(h.encCfg(), h.dir)
	require.NoError(t, ctl.AcquireExclusiveKeyLock())
	require.NoError(t, ctl.ReconcileKeySet(), "a coherent key set must reconcile")
	ctl.Shutdown()

	// PLANT the defect: overwrite dek.key with the gen-2 wrapped DEK while the
	// manifest still records gen-3 -- the mixed-generation set a defective
	// restore (one that wrote key files from two different backups) would leave.
	require.NoError(t, os.WriteFile(active, gen2DEK, 0o600))

	// RED proof: ReconcileKeySet must refuse the mixed-generation set.
	plant := encryption.NewService(h.encCfg(), h.dir)
	require.NoError(t, plant.AcquireExclusiveKeyLock())
	defer plant.Shutdown()
	err = plant.ReconcileKeySet()
	require.Error(t, err, "the mixed-generation guard must refuse a dek.key from a different generation")
	require.Contains(t, err.Error(), "generation",
		"the refusal must name the generation mismatch")
}
