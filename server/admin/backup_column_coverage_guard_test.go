package admin

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/backupfmt"
	"github.com/keyorixhq/keyorix/internal/guardrules"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage"
)

// backupUnmappedColumns lists the database columns of a backed-up table that
// the backup writer deliberately does not archive, keyed "table.column", each
// with the reason. The literal is empty on purpose: one entry is one test file,
// backup_unmapped_column_<table>_<column>_test.go, whose init() calls
// registerBackupUnmappedColumn (CLAUDE.md "Test registry tables"). Valid
// reasons are a column that is derived, regenerated at server start, or legacy
// and encrypted at restore; "nobody needed it" is not one.
var backupUnmappedColumns = map[string]string{}

func registerBackupUnmappedColumn(table, column, reason string) {
	key := table + "." + column
	if reason == "" {
		panic("backupUnmappedColumns: " + key + " has no reason")
	}
	if _, dup := backupUnmappedColumns[key]; dup {
		panic("backupUnmappedColumns: duplicate entry " + key)
	}
	backupUnmappedColumns[key] = reason
}

// unmappedBackupColumns returns, sorted, every "table.column" that exists in
// db's tables but is not among the columns the backup writer maps for that
// table. The mapped set is read from the manifest a real backupfmt.WriteBackup
// of db produces (TableEntry.Columns), not recomputed here, so it is exactly
// what the archive records.
func unmappedBackupColumns(t testing.TB, db *gorm.DB) []string {
	t.Helper()
	manifest, err := backupfmt.WriteBackup(db, storage.CurrentSchemaEpoch(), "", make([]byte, 32), nil, nil, io.Discard)
	require.NoError(t, err)
	var out []string
	for _, te := range manifest.Tables {
		cols, err := db.Migrator().ColumnTypes(te.Name)
		require.NoError(t, err, "columns of %s", te.Name)
		for _, c := range cols {
			if !slices.Contains(te.Columns, c.Name()) {
				out = append(out, te.Name+"."+c.Name())
			}
		}
	}
	sort.Strings(out)
	return out
}

// TestEveryBackedUpColumnIsMappedOrAllowlisted fails when a migration adds a
// column the backup silently ignores (the class behind ABT-1 item 1: a
// legacy notification_channels.url value dropped by the writer). It checks
// every table the backup writer covers, on three schemas: a freshly migrated
// SQLite database, a freshly migrated PostgreSQL database (pg-gated), and the
// database a v0.95.3 binary left behind (the fixture #3807 added, restored),
// which still carries columns the current model dropped. A column found on
// any of them that the writer does not map must have a
// backupUnmappedColumns entry, and an entry no checked schema still shows is
// stale and fails too, so the allowlist cannot outlive its column.
//
// What it does NOT catch:
//   - a table missing from the backup's registry altogether (that is
//     backupfmt's table-coverage checks, not this one);
//   - a column that exists only in a database upgraded from a release that is
//     not among the checked schemas (v0.95.0 and every other tag): the
//     in-place check scripts/release-qa/backup_inplace_upgrade_check.sh covers
//     one old tag at a time, this test covers v0.95.3;
//   - a mapped column whose VALUE is mangled or truncated on the way in or out
//     (the round-trip tests own that);
//   - an allowlisted column that starts holding data worth keeping; the entry's
//     reason is a claim, and only the legacy URL column has a runtime check
//     (INV-ADMIN-backup-refuses-unmigrated-legacy-url).
func TestEveryBackedUpColumnIsMappedOrAllowlisted(t *testing.T) {
	g := guardrules.Rollout(t)
	seen := map[string]bool{}
	check := func(t *testing.T, label string, db *gorm.DB) {
		for _, col := range unmappedBackupColumns(t, db) {
			seen[col] = true
			if _, ok := backupUnmappedColumns[col]; !ok {
				g.Errorf("%s: column %s is in the migrated schema but the backup writer does not map it, so a backup silently drops it. "+
					"Map it in the model, or add backup_unmapped_column_<table>_<column>_test.go registering it with the reason it is safe to leave out", label, col)
			}
		}
	}

	// Subtests, so each schema's chdir (the fixture path is resolved from the
	// package directory) is undone before the next one starts.
	t.Run("fresh SQLite", func(t *testing.T) { check(t, "fresh SQLite", freshMigratedSQLite(t)) })
	if dsn := os.Getenv("KEYORIX_TEST_PG_DSN"); dsn != "" {
		t.Run("fresh PostgreSQL", func(t *testing.T) { check(t, "fresh PostgreSQL", freshMigratedPostgres(t, dsn)) })
	}
	t.Run("v0.95.3 fixture restored", func(t *testing.T) { check(t, "v0.95.3 fixture restored", v0953RestoredDatabase(t)) })

	for key := range backupUnmappedColumns {
		if !seen[key] {
			g.Errorf("backupUnmappedColumns entry %s matches no column in any checked schema: delete its backup_unmapped_column_* file", key)
		}
	}
}

// TestBackupColumnGuard_RedOnAColumnAddedByAMigration proves the guard's check
// goes red: a column added to a backed-up table is reported unless allowlisted.
// It adds one to a fresh schema, which is what a migration that forgot the
// backup does.
func TestBackupColumnGuard_RedOnAColumnAddedByAMigration(t *testing.T) {
	db := freshMigratedSQLite(t)
	require.NotContains(t, unmappedBackupColumns(t, db), "secret_nodes.backup_guard_probe",
		"premise: the probe column is not there yet")
	require.NoError(t, db.Exec("ALTER TABLE secret_nodes ADD COLUMN backup_guard_probe TEXT").Error)
	found := unmappedBackupColumns(t, db)
	require.Contains(t, found, "secret_nodes.backup_guard_probe")
	_, allowlisted := backupUnmappedColumns["secret_nodes.backup_guard_probe"]
	require.False(t, allowlisted, "the probe must be reported, not excused")
}

// freshMigratedSQLite returns a database migrated by the storage factory, the
// same way a first server start migrates it.
func freshMigratedSQLite(t *testing.T) *gorm.DB {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	resetBackupRestoreFlags(t)
	dir := t.TempDir()
	chdirTest(t, dir)
	cfgPath := filepath.Join(dir, "keyorix.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(fmt.Sprintf("storage:\n  type: local\n  database:\n    path: %s\n", filepath.Join(dir, "secrets.db"))), 0o600))
	configPathFlag = cfgPath
	return migratedGormDB(t)
}

func freshMigratedPostgres(t *testing.T, base string) *gorm.DB {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	resetBackupRestoreFlags(t)
	dir := t.TempDir()
	chdirTest(t, dir)
	cfgPath := filepath.Join(dir, "keyorix.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(fmt.Sprintf("storage:\n  type: postgres\n  database:\n    dsn: %q\n", pgAdminIsolatedDatabaseDSN(t, base))), 0o600))
	configPathFlag = cfgPath
	return migratedGormDB(t)
}

// v0953RestoredDatabase restores the v0.95.3 fixture and opens the result: a
// schema with the columns that release created, including notification_channels.url.
func v0953RestoredDatabase(t *testing.T) *gorm.DB {
	t.Helper()
	setupV0953ArchiveRestore(t, func(dir string) string {
		return fmt.Sprintf("  type: local\n  database:\n    path: %s\n", filepath.Join(dir, "secrets.db"))
	})
	t.Setenv("KEYORIX_MASTER_PASSWORD", v0953FixturePassphrase)
	out, err := captureStdout(t, func() error { return runAdminRestore(nil, nil) })
	require.NoError(t, err, "restore of the v0.95.3 fixture:\n%s", out)
	cfg, err := loadConfig()
	require.NoError(t, err)
	gdb, err := storage.OpenGormDB(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { closeGormDB(gdb) })
	return gdb
}

func migratedGormDB(t *testing.T) *gorm.DB {
	t.Helper()
	cfg, err := loadConfig()
	require.NoError(t, err)
	_, err = storage.NewStorageFactory().CreateStorage(cfg) // creates and migrates
	require.NoError(t, err)
	gdb, err := storage.OpenGormDB(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { closeGormDB(gdb) })
	return gdb
}
