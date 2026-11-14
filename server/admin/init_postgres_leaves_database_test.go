package admin

// #3523: `admin init` for a PostgreSQL deployment creates no SQLite file and
// leaves the PostgreSQL database alone until `admin migrate` (it used to open
// storage for its own audit event, which migrated the whole schema). Its
// closing hints are the last thing it prints, after anything init itself
// creates.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/storage"
)

// runInitIn runs `admin init <args>` in dir (the process moves into it) and
// returns its exit code and stdout. init's flags are package globals that
// cobra does not reset between Execute calls.
func runInitIn(t *testing.T, dir string, args ...string) (int, string) {
	t.Helper()
	chdirTest(t, dir)
	prevConfig, prevType := configPathFlag, initStorageType
	t.Cleanup(func() { configPathFlag, initStorageType = prevConfig, prevType })
	initStorageType = ""
	var code int
	out, _ := captureStdout(t, func() error {
		code = Execute(append([]string{"init", "--config", "keyorix.yaml"}, args...)) // init writes relative paths only
		return nil
	})
	return code, out
}

// requireNoSQLiteFiles fails on any keyorix.db* file (database, -wal, -shm,
// .migration.lock, .server.lock) anywhere under dir.
func requireNoSQLiteFiles(t *testing.T, dir string) {
	t.Helper()
	require.NoError(t, filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		require.False(t, strings.HasPrefix(d.Name(), "keyorix.db"), "init created SQLite file %s for a PostgreSQL deployment", p)
		return nil
	}))
}

func TestAdminInit_StorageTypePostgres_EmptyDirCreatesNoSQLiteFiles(t *testing.T) {
	dir := t.TempDir()
	code, out := runInitIn(t, dir, "--storage-type", "postgres")
	require.Zero(t, code, "output:\n%s", out)
	requireNoSQLiteFiles(t, dir)
	require.FileExists(t, filepath.Join(dir, "keyorix.yaml"))
}

// The closing hints come last: nothing init does (its own audit event opens
// the SQLite database and creates keyorix.db-wal/-shm) is printed after them,
// and the PostgreSQL hint names every SQLite file to delete.
func TestAdminInit_SQLite_ClosingHintsComeLast(t *testing.T) {
	dir := t.TempDir()
	code, out := runInitIn(t, dir)
	require.Zero(t, code, "output:\n%s", out)

	audit := strings.Index(out, "ran `keyorix-server admin init`")
	hint := strings.Index(out, "Using PostgreSQL instead?")
	next := strings.Index(out, "Next, in this order")
	require.True(t, audit >= 0 && hint >= 0 && next >= 0, "output:\n%s", out)
	require.Less(t, audit, hint, "the audit line (which creates the WAL files) must come before the closing hint:\n%s", out)
	require.Less(t, hint, next, "output:\n%s", out)
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	require.Contains(t, lines[len(lines)-1], "admin audit", "the next-steps block is the last output:\n%s", out)
	require.Contains(t, out, "keyorix.db-wal")
}

// PostgreSQL with a DSN: init finishes, writes no SQLite file and creates no
// table. `admin migrate` creates the schema.
func TestAdminInit_PostgresConfig_LeavesDatabaseUntilMigrate(t *testing.T) {
	dsn := pgAdminIsolatedDatabaseDSN(t, pgAdminTestDSN(t))
	dir := t.TempDir()
	writePostgresBackupRestoreTestConfig(t, dir, dsn)
	t.Setenv("KEYORIX_MASTER_PASSWORD", "test-passphrase-1234")

	code, out := runInitIn(t, dir)
	require.Zero(t, code, "output:\n%s", out)
	requireNoSQLiteFiles(t, dir)
	require.Contains(t, out, "admin migrate")

	var tables int64
	require.NoError(t, pgAdminRawOpen(t, dsn).Raw(
		"SELECT count(*) FROM information_schema.tables WHERE table_schema = current_schema()").Scan(&tables).Error)
	require.Zero(t, tables, "init must leave the PostgreSQL database alone until admin migrate; output:\n%s", out)
}

// Control: on a PostgreSQL database that already has its schema, init still
// records itself in the audit chain, as before.
func TestAdminInit_PostgresMigratedDatabase_StillAudited(t *testing.T) {
	dsn := pgAdminIsolatedDatabaseDSN(t, pgAdminTestDSN(t))
	dir := t.TempDir()
	cfgPath := writePostgresBackupRestoreTestConfig(t, dir, dsn)
	t.Setenv("KEYORIX_MASTER_PASSWORD", "test-passphrase-1234")
	cfg, err := config.Load(cfgPath)
	require.NoError(t, err)
	_, err = storage.NewStorageFactory().CreateStorage(cfg) // what `admin migrate` does
	require.NoError(t, err)

	code, out := runInitIn(t, dir)
	require.Zero(t, code, "output:\n%s", out)
	var events int64
	require.NoError(t, pgAdminRawOpen(t, dsn).Raw(
		"SELECT count(*) FROM audit_events WHERE event_type = 'admin.init'").Scan(&events).Error)
	require.EqualValues(t, 1, events, "output:\n%s", out)
}
