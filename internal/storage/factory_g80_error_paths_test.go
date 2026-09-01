// factory_g80_error_paths_test.go — targeted coverage for genuinely-reachable
// error branches left uncovered by the earlier s2x coverage sweeps:
//
//   - every ensure*Index helper's CREATE UNIQUE INDEX failure path (as opposed
//     to the pre-flight warnIfDuplicatesExist failure path the s25 sweep's
//     "NoTableError" tests actually exercise — see the doc comment on
//     seedIndexNameOnDummyTable below for why those are different branches);
//   - applyPoolSettings' db.DB() failure branch;
//   - acquireSQLiteMigrationLock's os.OpenFile failure branch;
//   - migrateDatabase's shared `exec` closure error-wrapping branch, and the
//     first ALTER TABLE call site that uses it.
package storage

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
)

// ---------------------------------------------------------------------------
// ensure*Index — CREATE INDEX failure path (distinct from the pre-flight
// warnIfDuplicatesExist failure path)
// ---------------------------------------------------------------------------

// seedIndexNameOnDummyTable creates an unrelated table and an index named
// idxName on it. Every ensure*Index helper in factory.go first checks
// indexExists(db, idxName) and, only when that's false, runs the
// warnIfDuplicatesExist pre-flight scan before its own CREATE UNIQUE INDEX
// statement. Seeding an index of the same name on a throwaway table makes
// indexExists report true, which skips the pre-flight scan entirely and
// drives straight into the helper's own `db.Exec(sqlCreateUniqueIdx + ...)`
// call — which then genuinely fails, because the target table the statement
// actually names was never created. Confirmed against SQLite directly: a
// `CREATE UNIQUE INDEX IF NOT EXISTS <existing-name> ON <missing-table> (...)`
// still parses and validates the referenced table (raising "no such table")
// even though the "IF NOT EXISTS" name check would otherwise short-circuit —
// SQLite resolves the table reference before deciding whether to skip.
func seedIndexNameOnDummyTable(t *testing.T, db *gorm.DB, idxName string) {
	t.Helper()
	dummyTable := idxName + "_dummy"
	require.NoError(t, db.Exec("CREATE TABLE "+dummyTable+" (id INTEGER PRIMARY KEY)").Error)
	require.NoError(t, db.Exec("CREATE INDEX "+idxName+" ON "+dummyTable+" (id)").Error)
}

func TestEnsureIndexHelpers_CreateIndexFailsWhenTargetTableMissing(t *testing.T) {
	cases := []struct {
		name        string
		idxName     string
		fn          func(*gorm.DB) error
		errContains string
	}{
		{"ShareRecordUniqueIndex", "uniq_share_records_active", ensureShareRecordUniqueIndex, "failed to create partial share_records unique index"},
		{"SecretNodeNameIndex", "uniq_secret_nodes_project_env_name_active", ensureSecretNodeNameIndex, "failed to create secret_nodes unique-name index"},
		{"SecretVersionIndex", "uniq_secret_versions_node_version", ensureSecretVersionIndex, "failed to create secret_versions unique index"},
		{"DynamicSecretConfigNameIndex", "uniq_dynamic_secret_configs_project_env_name", ensureDynamicSecretConfigNameIndex, "failed to create dynamic_secret_configs unique index"},
		// GroupNameIndex/UserNameIndex/UserEmailIndex are deliberately NOT in this
		// table-driven case list (#1642): each of those three now runs
		// backfillFoldedColumn BEFORE the indexExists(idxName) short-circuit this
		// helper relies on, so seeding the index name on a dummy table (with the
		// real target table absent) makes backfillFoldedColumn's own "no such
		// table" read fail FIRST -- a different branch than the CREATE INDEX
		// failure this test is named for. Worse, the CREATE-INDEX-itself-fails
		// branch these three used to exercise this way is no longer reachable by
		// ANY variant of this technique: giving backfillFoldedColumn a real
		// target table (so it succeeds) means CREATE UNIQUE INDEX IF NOT EXISTS
		// also finds its target table valid -- and then the "IF NOT EXISTS" name
		// match (the same seeded name that skips warnIfDuplicatesExist) ALSO
		// short-circuits the CREATE itself before SQLite ever evaluates the real
		// duplicate data, so no error surfaces (confirmed empirically). The
		// reachable failure mode for these three is now backfillFoldedColumn's
		// own "no such table" error when the table is genuinely absent --
		// already covered by TestEnsureGroupNameIndex_S25_NoTableError /
		// TestEnsureUserNameIndex_S25_NoTableError /
		// TestEnsureUserEmailIndex_S25_NoTableError in storage_s25_test.go
		// (their generic `Contains(err.Error(), "groups"/"users")` assertions
		// still hold against the new backfill error text).
		{"ProjectMembershipIndex", "uniq_project_memberships_active", ensureProjectMembershipIndex, "failed to create partial project_memberships index"},
		{"BreakGlassActiveIndex", "uniq_break_glass_active_project_user", ensureBreakGlassActiveIndex, "failed to create partial break_glass_activations active index"},
		{"UserExternalIDIndex", "uniq_users_external_id_active", ensureUserExternalIDIndex, "failed to create partial users external_id index"},
		{"ProjectNameIndex", "uniq_projects_name_active", ensureProjectNameIndex, "failed to create partial projects name index"},
		{"LegalHoldActiveIndex", "uniq_legal_holds_active", ensureLegalHoldActiveIndex, "failed to create partial legal_holds active index"},
		{"ReminderNotificationDedupIndex", "uniq_notifications_unread_reminder", ensureReminderNotificationDedupIndex, "failed to create partial notifications reminder-dedup index"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), tc.name+"-collision.db"))
			require.NoError(t, err)
			seedIndexNameOnDummyTable(t, db, tc.idxName)

			err = tc.fn(db)
			require.Error(t, err, "%s must return an error when its CREATE INDEX statement itself fails (target table missing)", tc.name)
			assert.Contains(t, err.Error(), tc.errContains)
			// Must be the CREATE INDEX wrapper message, not the pre-flight
			// warnIfDuplicatesExist error (which is skipped here since the
			// index name already "exists") — confirms the right branch fired.
			assert.NotContains(t, err.Error(), "pre-existing group(s) of rows already share a value")
		})
	}
}

// ---------------------------------------------------------------------------
// applyPoolSettings — db.DB() failure branch
// ---------------------------------------------------------------------------

// TestApplyPoolSettings_ReturnsError_WhenConnPoolInvalid verifies that
// applyPoolSettings propagates db.DB()'s error instead of panicking when
// handed a *gorm.DB with a non-nil Config but no ConnPool set (as would occur
// if a future refactor ever passed a *gorm.DB through before a real Open —
// this pins the current fail-loud contract). gorm.DB embeds *Config, and
// ConnPool itself lives on Config, not DB — a fully zero-value &gorm.DB{}
// (nil embedded *Config) panics on field promotion before ever reaching
// db.DB()'s own nil-handling, so Config must be non-nil here to exercise
// db.DB()'s actual ErrInvalidDB fallback rather than an unrelated crash.
func TestApplyPoolSettings_ReturnsError_WhenConnPoolInvalid(t *testing.T) {
	db := &gorm.DB{Config: &gorm.Config{}}
	err := applyPoolSettings(db, &config.DatabaseConfig{})
	require.Error(t, err, "applyPoolSettings must surface a db.DB() failure rather than panic")
	assert.Contains(t, err.Error(), "failed to get underlying sql.DB")
}

// ---------------------------------------------------------------------------
// acquireSQLiteMigrationLock — os.OpenFile failure branch
// ---------------------------------------------------------------------------

// TestAcquireSQLiteMigrationLock_OpenFileFails_WhenParentDirMissing verifies
// that acquireSQLiteMigrationLock surfaces an actionable error (rather than a
// bare os.PathError or a panic) when the lock sidecar file cannot even be
// opened — here because its parent directory does not exist.
func TestAcquireSQLiteMigrationLock_OpenFileFails_WhenParentDirMissing(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "no-such-subdir", "secrets.db")

	lock, err := acquireSQLiteMigrationLock(dbPath)
	require.Error(t, err, "acquireSQLiteMigrationLock must surface the OpenFile error")
	assert.Nil(t, lock)
	assert.Contains(t, err.Error(), "open SQLite migration lock file")
}

// ---------------------------------------------------------------------------
// migrateDatabase — shared `exec` closure error-wrapping branch
// ---------------------------------------------------------------------------

// TestMigrateDatabase_WrapsRawExecFailure exercises migrateDatabase's shared
// `exec` closure error path via its very first call site (the secret_nodes
// last_rotated_at ALTER). columnExists's pragma_table_info lookup is a
// case-SENSITIVE string comparison, but SQLite itself treats column names as
// case-INSENSITIVE for duplicate detection — so pre-creating the column under
// a different case defeats the `!columnExists(...)` guard (it reports the
// column absent) while the ALTER TABLE this triggers still genuinely fails
// with "duplicate column name". This is a real (if narrow) gap in
// columnExists's case-sensitivity, exercised here as a legitimate way to
// reach the exec closure's error-wrapping branch and confirm migrateDatabase
// propagates the failure instead of silently continuing.
func TestMigrateDatabase_WrapsRawExecFailure(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "migrate-exec-fail.db"))
	require.NoError(t, err)

	require.NoError(t, db.Exec(`CREATE TABLE secret_nodes (id INTEGER PRIMARY KEY, Last_Rotated_At TIMESTAMP)`).Error)
	require.False(t, columnExists(db, "secret_nodes", "last_rotated_at"),
		"columnExists must miss the case-variant column (case-sensitive lookup) so the ALTER is attempted")

	err = (&DefaultStorageFactory{}).migrateDatabase(db)
	require.Error(t, err, "migrateDatabase must propagate the wrapped ALTER TABLE failure")
	assert.Contains(t, err.Error(), "migration failed")
	assert.Contains(t, err.Error(), "duplicate column name")
}

// ---------------------------------------------------------------------------
// rebuildRolePKSQLite — CREATE TABLE failure branch
// ---------------------------------------------------------------------------

// TestRebuildRolePKSQLite_CreateTableFails_WhenScratchTableAlreadyExists
// verifies that rebuildRolePKSQLite propagates a wrapped error when its own
// `CREATE TABLE <table>_new` statement fails, by pre-creating that exact
// scratch table out of band so the name collides.
func TestRebuildRolePKSQLite_CreateTableFails_WhenScratchTableAlreadyExists(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "pk-rebuild-collision.db"))
	require.NoError(t, err)

	require.NoError(t, db.Exec(`CREATE TABLE user_roles (
		user_id INTEGER NOT NULL,
		role_id INTEGER NOT NULL,
		PRIMARY KEY (user_id, role_id)
	)`).Error)
	// Collides with the scratch table rebuildRolePKSQLite itself tries to create.
	require.NoError(t, db.Exec(`CREATE TABLE user_roles_new (id INTEGER)`).Error)

	err = rebuildRolePKSQLite(db, "user_roles", "user_id", "user_id, role_id, project_id, environment_id")
	require.Error(t, err, "rebuildRolePKSQLite must propagate a CREATE TABLE failure on the scratch table")
	assert.Contains(t, err.Error(), "create user_roles_new")
}
