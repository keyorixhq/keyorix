package admin

// #4105 on PostgreSQL (pg-gated, KEYORIX_TEST_PG_DSN): the key-file side is the
// same as on SQLite; what differs is the lock the refusal's audit write runs
// under (the live backup's shared presence lock) and the database.

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage"
)

func TestClearStaleSaltPending_Postgres_RefusalAuditedThenCleared(t *testing.T) {
	resetBackupRestoreFlags(t)
	require.NoError(t, i18n.InitializeForTesting())
	t.Setenv("KEYORIX_MASTER_PASSWORD", "test-passphrase-1234")
	dsn := pgAdminIsolatedDatabaseDSN(t, pgAdminTestDSN(t))
	dir := t.TempDir()
	chdirTest(t, dir)
	require.NoError(t, encryption.NewService(&config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}, dir).Initialize("test-passphrase-1234"))
	configPathFlag = writePostgresBackupRestoreTestConfig(t, dir, dsn)
	cfg, err := loadConfig()
	require.NoError(t, err)
	_, err = storage.NewStorageFactory().CreateStorage(cfg)
	require.NoError(t, err)
	oldExclusive := backupExclusive
	backupExclusive = false // the default live backup, under the presence lock
	t.Cleanup(func() { backupExclusive = oldExclusive })

	planted := plantStagingFiles(t, testSaltPending)
	recoverLikeBoot(t)
	active := keyFilesSnapshot(t, planted)

	stderr := requireRefusedAndUntouched(t, planted)
	require.Contains(t, stderr, "This refusal was recorded to the audit chain ("+backupRefusedEventType+")")
	evs := auditEventsNamed(t, backupRefusedEventType)
	require.Len(t, evs, 1)
	require.False(t, *evs[0].Success)

	// With a DEK staging file beside it the command refuses and leaves both.
	withDEK := plantStagingFiles(t, testDEKPending)
	code, out, cerr := runClearStaleSalt(t)
	require.NotZero(t, code, "stdout:\n%s\nstderr:\n%s", out, cerr)
	require.Contains(t, cerr, testDEKPending+" is present")
	requireFilesUnchanged(t, keyFilesSnapshot(t, withDEK), "refused with a DEK staging file")
	require.NoError(t, os.Remove(testDEKPending)) // test fixture cleanup: it holds random bytes, no DEK

	code, out, cerr = runClearStaleSalt(t)
	require.Zero(t, code, "stdout:\n%s\nstderr:\n%s", out, cerr)
	require.Contains(t, out, "removed "+testSaltPending)
	require.NoFileExists(t, testSaltPending)
	require.Len(t, auditEventsNamed(t, clearStaleSaltEventType), 1)
	delete(active, testSaltPending)
	requireFilesUnchanged(t, active, "clear-stale-salt-pending")

	code, stderr = runBackupCommand(t, filepath.Join(t.TempDir(), "after.tar.gz"))
	require.Zero(t, code, "stderr:\n%s", stderr)
}
