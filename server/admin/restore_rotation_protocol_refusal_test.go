// restore_rotation_protocol_refusal_test.go: `admin restore` onto a target
// whose database records a DEK rotation protocol newer than this binary's
// (KEY-ROTATION-TAILS-NOV-1 item 3). The restore must refuse before it stages
// anything, even with --overwrite-existing --replace-existing-data
// --allow-rollback: the key files, the key-set manifest and the database are
// byte-identical afterwards and nothing is moved aside.
//
// Not t.Parallel(): package-level cobra flag vars and chdir.
package admin

import (
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// recordFutureRotationProtocol writes a rotation protocol no binary implements
// yet, as a newer server would.
func recordFutureRotationProtocol(t *testing.T, db *gorm.DB) {
	t.Helper()
	require.NoError(t, db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "key"}},
		DoUpdates: clause.AssignmentColumns([]string{"value"}),
	}).Create(&models.SystemMetadata{Key: encryption.DEKRotationProtocolKey, Value: strconv.Itoa(999), UpdatedAt: time.Now().UTC()}).Error)
}

func runReplacingRestore(t *testing.T, archive string) (string, error) {
	t.Helper()
	restoreInput = archive
	restoreOverwriteExisting = true
	restoreReplaceExistingData = true
	restoreAllowRollback = true
	restoreMaxEntryBytes, restoreMaxTotalBytes = 0, 0
	return captureStdout(t, func() error { return runAdminRestore(nil, nil) })
}

func TestAdminRestore_SQLite_TargetRecordsNewerRotationProtocol_Refused(t *testing.T) {
	resetBackupRestoreFlags(t)
	require.NoError(t, i18n.InitializeForTesting())
	t.Setenv("KEYORIX_MASTER_PASSWORD", populatedTargetPassphrase)

	archive, dstCfg, _, tgt, dbPath := populatedSQLiteRestoreCase(t)
	db, err := storage.OpenGormDB(dstCfg)
	require.NoError(t, err)
	recordFutureRotationProtocol(t, db)
	closeGormDB(db)
	oldKeys, oldManifest, oldDBSum := readKeyFiles(t, tgt.dir), readKeySetManifest(t, tgt.dir), fileSHA256(t, dbPath)

	out, err := runReplacingRestore(t, archive)
	require.ErrorIs(t, err, encryption.ErrRotationProtocolTooOld, "output was:\n%s", out)
	require.Contains(t, err.Error(), "admin restore", "the refusal must say which command to run with the servers' version")
	require.NotContains(t, out, "Running migrations", "the refusal must come before anything is built")
	require.Equal(t, oldKeys, readKeyFiles(t, tgt.dir), "a refused restore must leave the key files byte-identical")
	require.Equal(t, oldManifest, readKeySetManifest(t, tgt.dir), "a refused restore must leave the key-set manifest byte-identical")
	require.Equal(t, oldDBSum, fileSHA256(t, dbPath), "a refused restore must leave the database file byte-identical")
	requireNoAsideFiles(t, tgt.dir)
}

// The same target at this binary's own protocol restores (the guard does not
// refuse an equal protocol).
func TestAdminRestore_SQLite_TargetRecordsSameRotationProtocol_Restores(t *testing.T) {
	resetBackupRestoreFlags(t)
	require.NoError(t, i18n.InitializeForTesting())
	t.Setenv("KEYORIX_MASTER_PASSWORD", populatedTargetPassphrase)

	archive, dstCfg, _, _, _ := populatedSQLiteRestoreCase(t)
	db, err := storage.OpenGormDB(dstCfg)
	require.NoError(t, err)
	svc := encryption.NewService(&dstCfg.Storage.Encryption, ".")
	require.NoError(t, svc.Initialize(populatedTargetPassphrase))
	require.NoError(t, svc.StartDEKEpochGuard(db, nil), "a SQLite start records this binary's protocol")
	svc.Shutdown()
	closeGormDB(db)

	out, err := runReplacingRestore(t, archive)
	require.NoError(t, err, "output was:\n%s", out)
}

func TestAdminRestore_Postgres_TargetRecordsNewerRotationProtocol_Refused(t *testing.T) {
	resetBackupRestoreFlags(t)
	require.NoError(t, i18n.InitializeForTesting())
	t.Setenv("KEYORIX_MASTER_PASSWORD", populatedTargetPassphrase)

	base := pgAdminTestDSN(t)
	srcDSN := pgAdminIsolatedDatabaseDSN(t, base)
	dstDSN := pgAdminIsolatedDatabaseDSN(t, base)
	archive, _, _ := backupPostgresSource(t, srcDSN)

	dstDir := t.TempDir()
	chdirTest(t, dstDir)
	initTargetKeys(t, dstDir)
	configPathFlag = writePostgresBackupRestoreTestConfig(t, dstDir, dstDSN)
	dstCfg, err := loadConfig()
	require.NoError(t, err)
	st, err := createStorageClosedAtCleanup(t, dstCfg)
	require.NoError(t, err)
	closeTestStorage(st)
	raw := pgAdminRawOpen(t, dstDSN)
	seedDeploymentRows(t, raw, dstDir, "dst")
	recordFutureRotationProtocol(t, raw)
	oldKeys, oldManifest, oldDB := readKeyFiles(t, dstDir), readKeySetManifest(t, dstDir), pgTableFingerprint(t, dstDSN)

	out, err := runReplacingRestore(t, archive)
	require.ErrorIs(t, err, encryption.ErrRotationProtocolTooOld, "output was:\n%s", out)
	require.NotContains(t, out, "Running migrations", "the refusal must come before the target is migrated")
	require.Equal(t, oldKeys, readKeyFiles(t, dstDir), "a refused restore must leave the key files byte-identical")
	require.Equal(t, oldManifest, readKeySetManifest(t, dstDir), "a refused restore must leave the key-set manifest byte-identical")
	require.Equal(t, oldDB, pgTableFingerprint(t, dstDSN), "a refused restore must leave every table unchanged")
	requireNoAsideFiles(t, dstDir)
}
