// restore_populated_refusal_test.go: `admin restore --overwrite-existing` onto
// a target that holds a working deployment, without --replace-existing-data
// (KEY-ROTATION-SAFETY-1 item 1, MIGRATE-VERIFY-1 (b)). The restore must refuse
// before it stages anything: the key files, the key-set manifest and the
// database are byte-identical afterwards, nothing is moved aside, and the
// target still boots and decrypts its own secret.
//
// Uses only what main already had before the guard, so it runs red against
// the pre-fix tree (there --overwrite-existing alone replaced the target).
//
// Not t.Parallel(): package-level cobra flag vars and chdir.
package admin

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage"
)

// populatedSQLiteRestoreCase builds a SQLite source deployment and its backup
// archive, then a populated SQLite target (own keys, own rows, fully
// checkpointed) and chdirs into it.
func populatedSQLiteRestoreCase(t *testing.T) (archive string, dstCfg *config.Config, src, tgt populatedTarget, dbPath string) {
	t.Helper()
	srcDir := t.TempDir()
	chdirTest(t, srcDir)
	initTargetKeys(t, srcDir)
	configPathFlag = writeBackupRestoreTestConfig(t, srcDir, filepath.Join(srcDir, "secrets.db"))
	srcCfg, err := loadConfig()
	require.NoError(t, err)
	srcSt, err := storage.NewStorageFactory().CreateStorage(srcCfg)
	require.NoError(t, err)
	srcDB, err := storage.OpenGormDB(srcCfg)
	require.NoError(t, err)
	src = seedDeploymentRows(t, srcDB, srcDir, "src")
	closeGormDB(srcDB)
	closeTestStorage(srcSt)
	archive = filepath.Join(t.TempDir(), "src-backup.tar.gz")
	backupOutput = archive
	out, err := captureStdout(t, func() error { return runAdminBackup(nil, nil) })
	require.NoError(t, err, "output was:\n%s", out)

	dstDir := t.TempDir()
	chdirTest(t, dstDir)
	initTargetKeys(t, dstDir)
	dbPath = filepath.Join(dstDir, "secrets.db")
	configPathFlag = writeBackupRestoreTestConfig(t, dstDir, dbPath)
	dstCfg, err = loadConfig()
	require.NoError(t, err)
	dstSt, err := storage.NewStorageFactory().CreateStorage(dstCfg)
	require.NoError(t, err)
	dstDB, err := storage.OpenGormDB(dstCfg)
	require.NoError(t, err)
	tgt = seedDeploymentRows(t, dstDB, dstDir, "dst")
	closeGormDB(dstDB)
	closeTestStorage(dstSt)
	return archive, dstCfg, src, tgt, dbPath
}

func TestAdminRestore_SQLite_OverwriteExisting_PopulatedTarget_RefusedKeysByteIdentical(t *testing.T) {
	resetBackupRestoreFlags(t)
	require.NoError(t, i18n.InitializeForTesting())
	t.Setenv("KEYORIX_MASTER_PASSWORD", populatedTargetPassphrase)

	archive, dstCfg, _, tgt, dbPath := populatedSQLiteRestoreCase(t)
	oldKeys, oldManifest, oldDBSum := readKeyFiles(t, tgt.dir), readKeySetManifest(t, tgt.dir), fileSHA256(t, dbPath)

	restoreInput = archive
	restoreOverwriteExisting = true
	restoreMaxEntryBytes, restoreMaxTotalBytes = 0, 0
	out, err := captureStdout(t, func() error { return runAdminRestore(nil, nil) })
	require.Error(t, err, "--overwrite-existing alone must not replace a target that holds data; output was:\n%s", out)
	require.Contains(t, err.Error(), "--replace-existing-data", "the refusal must name the flag that replaces data")
	require.Contains(t, err.Error(), "secret_versions", "the refusal must name the tables that hold data")
	require.NotContains(t, out, "Running migrations", "the refusal must come before anything is built")
	require.Equal(t, oldKeys, readKeyFiles(t, tgt.dir), "a refused restore must leave the key files byte-identical")
	require.Equal(t, oldManifest, readKeySetManifest(t, tgt.dir), "a refused restore must leave the key-set manifest byte-identical")
	require.Equal(t, oldDBSum, fileSHA256(t, dbPath), "a refused restore must leave the database file byte-identical")
	requireNoAsideFiles(t, tgt.dir)
	requireTargetUsable(t, dstCfg, tgt, "dst")
}

func TestAdminRestore_Postgres_OverwriteExisting_PopulatedTarget_RefusedKeysByteIdentical(t *testing.T) {
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
	st, err := storage.NewStorageFactory().CreateStorage(dstCfg)
	require.NoError(t, err)
	closeTestStorage(st)
	tgt := seedDeploymentRows(t, pgAdminRawOpen(t, dstDSN), dstDir, "dst")
	oldKeys, oldManifest, oldDB := readKeyFiles(t, dstDir), readKeySetManifest(t, dstDir), pgTableFingerprint(t, dstDSN)

	restoreInput = archive
	restoreOverwriteExisting = true
	restoreMaxEntryBytes, restoreMaxTotalBytes = 0, 0
	out, err := captureStdout(t, func() error { return runAdminRestore(nil, nil) })
	require.Error(t, err, "--overwrite-existing alone must not replace a target that holds data; output was:\n%s", out)
	require.Contains(t, err.Error(), "--replace-existing-data", "the refusal must name the flag that replaces data")
	require.Contains(t, err.Error(), "secret_versions", "the refusal must name the tables that hold data")
	require.NotContains(t, out, "Running migrations", "the refusal must come before the target is migrated")
	require.Equal(t, oldKeys, readKeyFiles(t, dstDir), "a refused restore must leave the key files byte-identical")
	require.Equal(t, oldManifest, readKeySetManifest(t, dstDir), "a refused restore must leave the key-set manifest byte-identical")
	require.Equal(t, oldDB, pgTableFingerprint(t, dstDSN), "a refused restore must leave every table unchanged")
	requireNoAsideFiles(t, dstDir)
	requireTargetUsable(t, dstCfg, tgt, "dst")
}
