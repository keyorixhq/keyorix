// restore_populated_target_test.go: `admin restore` onto a target that
// already holds a working deployment (its own database rows, its own key files
// and their key-set manifest, #2900), from RESTORE-POPULATED-PG-1 (#3618),
// rebuilt on the restore journal (#3583) by RESTORE-JOURNAL-DECIDE-1. Whatever
// happens, the target must end as a consistent database+keys+manifest triple:
// either the restore completes (the archive's rows, the archive's keys, a
// manifest recording them) or it fails and all three are left byte-identical
// and usable. Where these overlap restore_overwrite_atomicity_test.go, the
// difference is the oracle: these decrypt a secret with the key files at the
// config's paths and fingerprint every table, instead of comparing names.
//
// Not t.Parallel(): package-level cobra flag vars, the step hook and chdir.
package admin

import (
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/keyfiles"
	"github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

const populatedTargetPassphrase = "test-passphrase-1234"

var populatedTargetKeyFiles = []string{"dek.key", "kek.salt"}

// populatedTarget is one deployment: a directory holding its config and key
// files, and the ciphertext of one secret its own keys encrypted.
type populatedTarget struct {
	dir        string
	secretID   uint
	ciphertext []byte
}

// closeTestStorage releases the pools a CreateStorage call opened, so a
// SQLite file is checkpointed and a Postgres database can be dropped.
func closeTestStorage(st any) {
	if c, ok := st.(io.Closer); ok {
		_ = c.Close()
	}
}

func initTargetKeys(t *testing.T, dir string) {
	t.Helper()
	encCfg := &config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}
	require.NoError(t, encryption.NewService(encCfg, dir).Initialize(populatedTargetPassphrase))
}

// seedDeploymentRows writes a user, a project, an environment and one secret
// whose version is encrypted with dir's own key files. Primary keys start at
// 1 on a fresh database, so a source and a target seeded this way collide.
func seedDeploymentRows(t *testing.T, db *gorm.DB, dir, label string) populatedTarget {
	t.Helper()
	user := models.User{Username: label + "-user", UsernameFolded: label + "-user", Email: label + "@example.test", IsActive: true}
	require.NoError(t, db.Create(&user).Error)
	project := models.Project{Name: label + "-proj"}
	require.NoError(t, db.Create(&project).Error)
	env := models.Environment{ProjectID: project.ID, Name: "prod"}
	require.NoError(t, db.Create(&env).Error)
	node := models.SecretNode{ProjectID: project.ID, EnvironmentID: env.ID, Name: label + "-secret", OwnerID: user.ID, IsSecret: true}
	require.NoError(t, db.Create(&node).Error)

	svc := encryption.NewService(&config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}, dir)
	require.NoError(t, svc.Initialize(populatedTargetPassphrase))
	ct, _, err := svc.EncryptSecret([]byte(label + "-plaintext"))
	require.NoError(t, err)
	require.NoError(t, db.Create(&models.SecretVersion{SecretNodeID: node.ID, VersionNumber: 1, EncryptedValue: ct}).Error)
	return populatedTarget{dir: dir, secretID: node.ID, ciphertext: ct}
}

func readKeyFiles(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	for _, name := range populatedTargetKeyFiles {
		b, err := os.ReadFile(filepath.Join(dir, name))
		require.NoError(t, err)
		out[name] = b
	}
	return out
}

// requireNoAsideFiles asserts nothing in dir was renamed aside: a restore
// that left the target untouched has nothing to roll back.
func requireNoAsideFiles(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	for _, e := range entries {
		require.NotContains(t, e.Name(), ".pre-restore-", "a failed restore must not have moved %q aside", e.Name())
		require.NotContains(t, e.Name(), ".restoring-", "a failed restore must not leave a staged temp file %q", e.Name())
	}
}

// requireTargetUsable re-opens the target the way the server boots it
// (migrating storage, then the encryption service from the key files at the
// config's paths) and decrypts the secret its own keys wrote.
func requireTargetUsable(t *testing.T, cfg *config.Config, tgt populatedTarget, label string) {
	t.Helper()
	st, err := storage.NewStorageFactory().CreateStorage(cfg)
	require.NoError(t, err, "the target must still start after a failed restore")
	t.Cleanup(func() { closeTestStorage(st) })
	db, err := storage.OpenGormDB(cfg)
	require.NoError(t, err)
	defer closeGormDB(db)

	var v models.SecretVersion
	require.NoError(t, db.Where("secret_node_id = ?", tgt.secretID).First(&v).Error)
	require.Equal(t, tgt.ciphertext, v.EncryptedValue, "the old secret version must still be in the database")

	svc := encryption.NewService(&cfg.Storage.Encryption, tgt.dir)
	require.NoError(t, svc.Initialize(populatedTargetPassphrase), "the old key files must still unwrap")
	pt, err := svc.DecryptSecret(v.EncryptedValue)
	require.NoError(t, err, "the old database and the key files at the config's paths must be a matching pair")
	require.Equal(t, label+"-plaintext", string(pt))
}

// pgTableFingerprint returns, for every table in the public schema, its row
// count and an md5 over its rows in a stable order: equal fingerprints mean
// the database content is unchanged.
func pgTableFingerprint(t *testing.T, dsn string) map[string]string {
	t.Helper()
	db := pgAdminRawOpen(t, dsn)
	var tables []string
	require.NoError(t, db.Raw(`SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' AND table_type = 'BASE TABLE' ORDER BY table_name`).Scan(&tables).Error)
	out := make(map[string]string, len(tables))
	for _, tbl := range tables {
		var row struct {
			N   int64
			Sum sql.NullString
		}
		q := fmt.Sprintf(`SELECT COUNT(*) AS n, md5(string_agg(t::text, E'\n' ORDER BY t::text)) AS sum FROM %s t`, quoteIdentPG(tbl))
		require.NoError(t, db.Raw(q).Scan(&row).Error, "fingerprint %s", tbl)
		out[tbl] = fmt.Sprintf("%d:%s", row.N, row.Sum.String)
	}
	return out
}

func fileSHA256(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path) // #nosec G304 -- test-owned temp path
	require.NoError(t, err)
	return fmt.Sprintf("%x", sha256.Sum256(b))
}

// failRestoreBeforeCommit fails the restore at its "loaded" step: on
// PostgreSQL inside the load transaction (every row loaded, sequences resynced,
// token written, not yet committed), on SQLite once the staged database is
// complete and before the journal makes it the commit point.
func failRestoreBeforeCommit(t *testing.T) error {
	t.Helper()
	injected := errors.New("injected load failure before commit")
	orig := restoreStepHook
	t.Cleanup(func() { restoreStepHook = orig })
	restoreStepHook = func(step string) error {
		if step == "loaded" {
			return injected
		}
		return nil
	}
	return injected
}

// requireManifestRecords asserts dir's key-set manifest records exactly keys
// as written by a restore, and the boot-time key-set check accepts the set.
func requireManifestRecords(t *testing.T, cfg *config.Config, dir string, keys map[string][]byte) {
	t.Helper()
	m, err := keyfiles.LoadManifest(filepath.Join(dir, keyfiles.ManifestFileName))
	require.NoError(t, err)
	require.Nil(t, m.Next)
	for name, data := range keys {
		require.Equal(t, keyfiles.HashBytes(data), m.Files[name].SHA256, name)
		require.Equal(t, keyfiles.OpRestore, m.Files[name].Operation, name)
	}
	require.NoError(t, keyfiles.VerifyKeySetConsistency(&cfg.Storage.Encryption, "."))
}

// backupPostgresSource builds a source deployment on srcDSN (its own keys,
// rows whose primary keys collide with any other freshly-seeded deployment)
// and returns the path of an `admin backup` archive of it.
func backupPostgresSource(t *testing.T, srcDSN string) (archive string, srcKeys map[string][]byte, src populatedTarget) {
	t.Helper()
	srcDir := t.TempDir()
	chdirTest(t, srcDir)
	initTargetKeys(t, srcDir)
	configPathFlag = writePostgresBackupRestoreTestConfig(t, srcDir, srcDSN)
	srcCfg, err := loadConfig()
	require.NoError(t, err)
	st, err := storage.NewStorageFactory().CreateStorage(srcCfg)
	require.NoError(t, err)
	t.Cleanup(func() { closeTestStorage(st) })
	src = seedDeploymentRows(t, pgAdminRawOpen(t, srcDSN), srcDir, "src")

	archive = filepath.Join(t.TempDir(), "src-backup.tar.gz")
	backupOutput = archive
	backupExclusive = false
	out, err := captureStdout(t, func() error { return runAdminBackup(nil, nil) })
	require.NoError(t, err, "output was:\n%s", out)
	return archive, readKeyFiles(t, srcDir), src
}

// TestAdminRestore_Postgres_OverwriteExisting_PopulatedTarget_ReplacesAllThree
// is #3618's finding on the reconciled code: a PostgreSQL target that already
// holds rows with the archive's primary keys, restored with
// --overwrite-existing. On main since #3583 that flag empties the target's
// tables inside the load transaction, so the restore completes: the archive's
// rows, the archive's key files at the config's paths (the archive's secret
// decrypts with them) and a manifest recording those key files. The replaced
// key files and manifest are kept aside; the replaced ROWS are not (only a
// backup of the target keeps them -- see SELF_HOSTING.md §5).
func TestAdminRestore_Postgres_OverwriteExisting_PopulatedTarget_ReplacesAllThree(t *testing.T) {
	resetBackupRestoreFlags(t)
	require.NoError(t, i18n.InitializeForTesting())
	t.Setenv("KEYORIX_MASTER_PASSWORD", populatedTargetPassphrase)

	base := pgAdminTestDSN(t)
	srcDSN := pgAdminIsolatedDatabaseDSN(t, base)
	dstDSN := pgAdminIsolatedDatabaseDSN(t, base)
	archive, srcKeys, src := backupPostgresSource(t, srcDSN)

	dstDir := t.TempDir()
	chdirTest(t, dstDir)
	initTargetKeys(t, dstDir)
	configPathFlag = writePostgresBackupRestoreTestConfig(t, dstDir, dstDSN)
	dstCfg, err := loadConfig()
	require.NoError(t, err)
	st, err := storage.NewStorageFactory().CreateStorage(dstCfg)
	require.NoError(t, err)
	closeTestStorage(st)
	seedDeploymentRows(t, pgAdminRawOpen(t, dstDSN), dstDir, "dst")
	oldManifest := readKeySetManifest(t, dstDir)

	restoreInput = archive
	restoreOverwriteExisting = true
	restoreMaxEntryBytes, restoreMaxTotalBytes = 0, 0
	out, err := captureStdout(t, func() error { return runAdminRestore(nil, nil) })
	require.NoError(t, err, "output was:\n%s", out)
	require.Equal(t, srcKeys, readKeyFiles(t, dstDir), "a completed restore must install the archive's key files")
	var users []models.User
	require.NoError(t, pgAdminRawOpen(t, dstDSN).Find(&users).Error)
	require.Len(t, users, 1)
	require.Equal(t, "src-user", users[0].Username, "a completed restore must hold the archive's rows only")
	src.dir = dstDir
	requireTargetUsable(t, dstCfg, src, "src")
	requireManifestRecords(t, dstCfg, dstDir, srcKeys)
	aside, err := filepath.Glob(filepath.Join(dstDir, keyfiles.ManifestFileName+".pre-restore-*"))
	require.NoError(t, err)
	require.Len(t, aside, 1)
	got, err := os.ReadFile(aside[0]) // #nosec G304 -- t.TempDir() path
	require.NoError(t, err)
	require.Equal(t, oldManifest, got, "the replaced manifest is kept aside with the key files it recorded")
}

// TestAdminRestore_Postgres_PopulatedTarget_WithoutOverwrite_RefusedBeforeStaging
// is the refused populated-PostgreSQL restore and the key-set manifest: the
// refusal (refuseNonEmptyPostgresTarget, the checks stage) comes before the
// target is migrated and before any key file or manifest is staged, so the key
// files, the manifest and every table are byte-identical afterwards and the
// target still boots and decrypts its own secret.
func TestAdminRestore_Postgres_PopulatedTarget_WithoutOverwrite_RefusedBeforeStaging(t *testing.T) {
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
	restoreOverwriteExisting = false
	restoreMaxEntryBytes, restoreMaxTotalBytes = 0, 0
	out, err := captureStdout(t, func() error { return runAdminRestore(nil, nil) })
	require.Error(t, err)
	require.Contains(t, err.Error(), "target Postgres database already has")
	require.NotContains(t, out, "Running migrations", "the refusal must come before the target is migrated")
	require.Equal(t, oldKeys, readKeyFiles(t, dstDir))
	require.Equal(t, oldManifest, readKeySetManifest(t, dstDir), "a refused restore must not touch the key-set manifest")
	require.Equal(t, oldDB, pgTableFingerprint(t, dstDSN))
	requireNoAsideFiles(t, dstDir)
	requireTargetUsable(t, dstCfg, tgt, "dst")
}

// TestAdminRestore_Postgres_OverwriteExisting_EmptySchema_Succeeds is the
// re-run case --overwrite-existing exists for on Postgres: an interrupted
// restore's leftovers (an empty, migrated schema and a key set) are replaced,
// and the old key files are kept aside.
func TestAdminRestore_Postgres_OverwriteExisting_EmptySchema_Succeeds(t *testing.T) {
	resetBackupRestoreFlags(t)
	require.NoError(t, i18n.InitializeForTesting())
	t.Setenv("KEYORIX_MASTER_PASSWORD", populatedTargetPassphrase)

	base := pgAdminTestDSN(t)
	srcDSN := pgAdminIsolatedDatabaseDSN(t, base)
	dstDSN := pgAdminIsolatedDatabaseDSN(t, base)
	archive, srcKeys, _ := backupPostgresSource(t, srcDSN)

	dstDir := t.TempDir()
	chdirTest(t, dstDir)
	initTargetKeys(t, dstDir)
	oldKeys := readKeyFiles(t, dstDir)
	configPathFlag = writePostgresBackupRestoreTestConfig(t, dstDir, dstDSN)
	dstCfg, err := loadConfig()
	require.NoError(t, err)
	st, err := storage.NewStorageFactory().CreateStorage(dstCfg)
	require.NoError(t, err)
	closeTestStorage(st)

	restoreInput = archive
	restoreOverwriteExisting = true
	restoreMaxEntryBytes, restoreMaxTotalBytes = 0, 0
	out, err := captureStdout(t, func() error { return runAdminRestore(nil, nil) })
	require.NoError(t, err, "output was:\n%s", out)
	require.Contains(t, out, "verify-audit on the restored database: VALID")
	require.Equal(t, srcKeys, readKeyFiles(t, dstDir))
	requireManifestRecords(t, dstCfg, dstDir, srcKeys)

	entries, err := os.ReadDir(dstDir)
	require.NoError(t, err)
	aside := map[string][]byte{}
	for _, e := range entries {
		for _, name := range populatedTargetKeyFiles {
			if strings.HasPrefix(e.Name(), name+".pre-restore-") {
				b, rerr := os.ReadFile(filepath.Join(dstDir, e.Name()))
				require.NoError(t, rerr)
				aside[name] = b
			}
		}
	}
	require.Equal(t, oldKeys, aside, "the replaced key files must be kept aside as *.pre-restore-<ts>")
}

// TestAdminRestore_Postgres_OverwriteExisting_LoadFailure_LeavesKeyFiles
// fails the load at its last point (every row inserted, transaction not yet
// committed) on an otherwise loadable target: the key files must not have been
// touched.
func TestAdminRestore_Postgres_OverwriteExisting_LoadFailure_LeavesKeyFiles(t *testing.T) {
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
	oldKeys, oldManifest := readKeyFiles(t, dstDir), readKeySetManifest(t, dstDir)
	configPathFlag = writePostgresBackupRestoreTestConfig(t, dstDir, dstDSN)
	dstCfg, err := loadConfig()
	require.NoError(t, err)
	st, err := storage.NewStorageFactory().CreateStorage(dstCfg)
	require.NoError(t, err)
	closeTestStorage(st)
	oldDB := pgTableFingerprint(t, dstDSN)

	injected := failRestoreBeforeCommit(t)
	restoreInput = archive
	restoreOverwriteExisting = true
	restoreMaxEntryBytes, restoreMaxTotalBytes = 0, 0
	out, err := captureStdout(t, func() error { return runAdminRestore(nil, nil) })
	require.ErrorIs(t, err, injected, "output was:\n%s", out)
	require.Equal(t, oldKeys, readKeyFiles(t, dstDir), "a failed load must leave the old key files byte-identical")
	require.Equal(t, oldManifest, readKeySetManifest(t, dstDir), "a failed load must leave the key-set manifest byte-identical")
	require.Equal(t, oldDB, pgTableFingerprint(t, dstDSN), "a failed load must leave no rows behind")
	requireNoAsideFiles(t, dstDir)
}

// TestAdminRestore_SQLite_OverwriteExisting_LoadFailure_LeavesOldDatabase is
// the SQLite counterpart: the restore loads into a staged database file beside
// the live one, so a failed load must leave the live file, the old key files
// and the manifest alone.
func TestAdminRestore_SQLite_OverwriteExisting_LoadFailure_LeavesOldDatabase(t *testing.T) {
	resetBackupRestoreFlags(t)
	require.NoError(t, i18n.InitializeForTesting())
	t.Setenv("KEYORIX_MASTER_PASSWORD", populatedTargetPassphrase)

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
	seedDeploymentRows(t, srcDB, srcDir, "src")
	closeGormDB(srcDB)
	closeTestStorage(srcSt)
	archive := filepath.Join(t.TempDir(), "src-backup.tar.gz")
	backupOutput = archive
	out, err := captureStdout(t, func() error { return runAdminBackup(nil, nil) })
	require.NoError(t, err, "output was:\n%s", out)

	dstDir := t.TempDir()
	chdirTest(t, dstDir)
	initTargetKeys(t, dstDir)
	dbPath := filepath.Join(dstDir, "secrets.db")
	configPathFlag = writeBackupRestoreTestConfig(t, dstDir, dbPath)
	dstCfg, err := loadConfig()
	require.NoError(t, err)
	dstSt, err := storage.NewStorageFactory().CreateStorage(dstCfg)
	require.NoError(t, err)
	dstDB, err := storage.OpenGormDB(dstCfg)
	require.NoError(t, err)
	tgt := seedDeploymentRows(t, dstDB, dstDir, "dst")
	closeGormDB(dstDB)
	closeTestStorage(dstSt)
	for _, suffix := range []string{"-wal", "-shm"} {
		_, statErr := os.Stat(dbPath + suffix)
		require.True(t, os.IsNotExist(statErr), "the seeded target must be fully checkpointed before it is fingerprinted")
	}
	oldKeys, oldManifest := readKeyFiles(t, dstDir), readKeySetManifest(t, dstDir)
	oldDBSum := fileSHA256(t, dbPath)

	injected := failRestoreBeforeCommit(t)
	restoreInput = archive
	restoreOverwriteExisting = true
	restoreMaxEntryBytes, restoreMaxTotalBytes = 0, 0
	out, err = captureStdout(t, func() error { return runAdminRestore(nil, nil) })
	require.ErrorIs(t, err, injected, "output was:\n%s", out)
	require.Equal(t, oldKeys, readKeyFiles(t, dstDir), "a failed load must leave the old key files byte-identical")
	require.Equal(t, oldManifest, readKeySetManifest(t, dstDir), "a failed load must leave the key-set manifest byte-identical")
	require.Equal(t, oldDBSum, fileSHA256(t, dbPath), "a failed load must leave the old database file byte-identical")
	requireNoAsideFiles(t, dstDir)
	requireTargetUsable(t, dstCfg, tgt, "dst")
}
