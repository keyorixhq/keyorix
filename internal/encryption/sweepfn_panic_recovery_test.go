package encryption

// sweepfn_panic_recovery_test.go — deterministic regression test for
// docs/findings/2026-09-20-FINDING-sweepfn-panic-recovery-swallows-failure.md.
//
// Before the fix (service_rotation.go's sweepFn had an unnamed error return),
// a panic anywhere between tx.Begin() and tx.Commit() inside sweepFn was
// caught by its own defer/recover, which rolled the transaction back
// correctly but then let sweepFn return nil (the zero value) to its caller.
// KeyManager.RotateDEKWithSweep saw err == nil and proceeded to promote the
// new DEK, wipe the old one, and delete its backups — total, unconditional
// data loss for every row the (rolled-back) sweep was supposed to
// re-encrypt.
//
// This test injects a genuine panic (not a returned error) via a GORM
// Before-Update callback — the same technique
// fault_injected_operations_fuzz_test.go's armSQLFault already uses for
// error injection, here used for a panic instead — on the real
// Service.RotateDEKWithSweep, and asserts the fix's contract: a panicked
// sweep must surface as an error, and the rotation must not have promoted
// the new DEK, wiped the old one, deleted backups, or left any row altered.

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestRotateDEKWithSweep_PanicMidSweepDoesNotPromoteOrWipe(t *testing.T) {
	db := newTestDB(t)
	svc, dir := newTestService(t, "test-passphrase")

	const projectID = uint(7)
	nodeID := seedSecretNode(t, db, projectID)
	versionID := seedSecretVersion(t, db, svc, nodeID, projectID, 1, "sensitive-data")

	oldDEK := captureCurrentDEK(t, svc)

	var before models.SecretVersion
	require.NoError(t, db.First(&before, versionID).Error)
	originalEncrypted := append([]byte(nil), before.EncryptedValue...)

	// Arm a fault that panics (not returns an error) the first time the sweep
	// issues its per-row UPDATE against secret_versions — i.e. while sweepFn's
	// own transaction is open. Matched on Statement.Model (set by
	// tx.Model(&models.SecretVersion{}) in sweepSecretVersions), not
	// Statement.Dest (the map passed to Updates()).
	const hookName = "panic-mid-sweep"
	fired := false
	db.Callback().Update().Before("gorm:before_update").Register(hookName, func(d *gorm.DB) {
		if fired {
			return // once only — a real panic happens once, not on every statement after
		}
		if _, ok := d.Statement.Model.(*models.SecretVersion); ok {
			fired = true
			panic("sweepfn_panic_recovery_test: simulated mid-sweep panic (not a returned error)")
		}
	})
	defer db.Callback().Update().Remove(hookName)

	result, err := svc.RotateDEKWithSweep("test-passphrase", db)

	require.Error(t, err, "REGRESSION: a panic mid-sweep must surface as an error, not report success")
	require.Nil(t, result)
	require.Contains(t, err.Error(), "panicked")

	// The new DEK must NOT have been promoted — the active DEK must still be
	// the original one.
	currentDEK := captureCurrentDEK(t, svc)
	require.Equal(t, oldDEK, currentDEK, "the old DEK must remain active after a panicked sweep")

	// No pending file should remain — KeyManager.RotateDEKWithSweep's existing
	// error-handling path (unaffected by this fix) removes it once sweepFn
	// correctly reports failure.
	_, statErr := os.Stat(filepath.Join(dir, "dek.key.pending"))
	require.True(t, os.IsNotExist(statErr), "dek.key.pending must not remain after a panicked sweep")

	// The row must be untouched — the sweep's transaction was rolled back.
	var after models.SecretVersion
	require.NoError(t, db.First(&after, versionID).Error)
	require.Equal(t, originalEncrypted, after.EncryptedValue, "ATOMICITY: row was re-encrypted despite the panicked sweep")

	// And it must still decrypt correctly under the (unchanged) active service.
	aad := SecretAAD(nodeID, projectID, 1)
	pt, err := svc.DecryptSecretWithAAD(after.EncryptedValue, aad)
	require.NoError(t, err)
	require.Equal(t, "sensitive-data", string(pt))
}
