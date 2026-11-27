package admin

// restore_sqlite_dek_epoch_boot_test.go -- SQLITE-DEK-EPOCH-1 restore decision.
//
// The boot guard now verifies the DEK epoch on SQLite too
// (INV-ENCRYPTION-sqlite-dek-epoch-at-boot). A restore must not be broken by it:
// `admin restore` installs the archive's database image (which carries its own
// dek.epoch row, if any) together with the archive's key files, so the restored
// epoch always names the restored DEK. This drives a real SQLite restore
// round-trip and then boots the epoch guard the way the server does, asserting
// the restored database boots under the restored key set and self-seeds its
// epoch to the restored DEK (the archive here predates the boot guard, so it has
// no epoch row -- the self-seed-after-probe path, no dek.key format change).

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage"
)

func TestAdminRestore_SQLite_RestoredDatabaseBootsUnderRestoredKeys(t *testing.T) {
	resetBackupRestoreFlags(t)
	require.NoError(t, i18n.InitializeForTesting())
	t.Setenv("KEYORIX_MASTER_PASSWORD", populatedTargetPassphrase)

	// Back up a populated SQLite deployment and restore it over a different,
	// also-populated target. After this, the target's database image and key
	// files are both the source's -- one consistent set.
	archive, dstCfg, _, _, _ := populatedSQLiteRestoreCase(t)
	out, err := runReplacingRestore(t, archive)
	require.NoError(t, err, "a legitimate SQLite restore must succeed; output:\n%s", out)

	// Boot the epoch guard the way the server does, against the restored
	// database with the restored key set. It must be accepted (not refused with
	// ErrDEKEpochMismatch): the restored keys are the DEK the restored rows are
	// under.
	db, err := storage.OpenGormDB(dstCfg)
	require.NoError(t, err)
	defer closeGormDB(db)
	svc := encryption.NewService(&dstCfg.Storage.Encryption, ".")
	require.NoError(t, svc.Initialize(populatedTargetPassphrase))
	defer svc.Shutdown()

	err = svc.StartDEKEpochGuard(db, nil)
	require.NoError(t, err, "a restored SQLite database must boot under its restored key set")
	require.NotErrorIs(t, err, encryption.ErrDEKEpochMismatch)

	// The restored archive predates the boot guard, so it carries no epoch row;
	// the boot self-seeds it to the restored DEK's fingerprint.
	fp, err := svc.DEKFingerprint()
	require.NoError(t, err)
	var epoch string
	require.NoError(t, db.Raw(`SELECT value FROM system_metadata WHERE "key" = ?`,
		encryption.DEKEpochMetadataKey).Scan(&epoch).Error)
	require.Equal(t, fp, epoch, "the restored database's epoch must be the restored DEK's fingerprint")

	// Single node: boot-time check only, no watcher.
	require.False(t, svc.DEKEpochGuardRunning(), "SQLite must not start a watcher")
}
