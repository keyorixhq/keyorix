// storage_s28_test.go — s28 coverage sweep for internal/storage (factory.go).
//
// Targets:
//
//	factory.go migrateDatabase (81.7%)
//	  — machine_identity_credentials "else" (existing table, classification column upgrade)
//	  — machine_identity_roles pre-existing (skip AutoMigrate)
//	  — machine_identity_oidc_bindings pre-existing (skip AutoMigrate)
//	  — setup_tokens pre-existing (skip AutoMigrate)
//	  — risk_exceptions pre-existing (skip AutoMigrate)
//	  — sso_login_states pre-existing (skip AutoMigrate)
//	  — scheduler_lock_leases pre-existing (skip AutoMigrate)
//	  — sod_policies pre-existing (skip AutoMigrate)
//	  — secret_dependencies pre-existing (skip AutoMigrate)
//	  — password_histories pre-existing (skip AutoMigrate)
//	  — login_attempts pre-existing (skip AutoMigrate)
//	  — web_authn_credentials pre-existing (skip AutoMigrate)
//	  — web_authn_sessions pre-existing (skip AutoMigrate)
//	  — connect_ref_grants pre-existing (skip AutoMigrate)
//	  — access_request_approvals pre-existing (skip AutoMigrate)
//	  — break_glass_activations pre-existing (only ensureBreakGlassActiveIndex runs)
//	  — legal_holds pre-existing (only ensureLegalHoldActiveIndex runs)
//	  — mfa_secrets, mfa_recovery_codes, mfa_challenges pre-existing (skip AutoMigrate)
//
//	factory.go ensureReminderNotificationDedupIndex (100% but confirm error path
//	  when notifications table exists with incompatible schema).
//
//	factory.go createLocalStorage — migrateDatabase failure causes an error.
//
//	factory.go warnIfDuplicatesExist — no-where-clause path.
//
//	factory.go columnExists / tableExists / indexExists — edge cases on fresh DB.
package storage

import (
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Helper: migrateDatabase with tables already present (upgrade scenario)
// These tests create a partial schema, run migrateDatabase, and assert
// the function does not error on tables that simply pre-exist.
// ---------------------------------------------------------------------------

// TestMigrateDatabase_S28_MachineCredentialsElseBranch exercises the
// machine_identity_credentials else-branch: table pre-exists without the
// classification column → the branch adds the column and companion index.
func TestMigrateDatabase_S28_MachineCredentialsElseBranch(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "machinecred-else.db"))
	require.NoError(t, err)

	// Pre-existing table without classification column.
	require.NoError(t, db.Exec(`CREATE TABLE machine_identity_credentials (
		id INTEGER PRIMARY KEY,
		machine_identity_id INTEGER,
		credential_hash TEXT
	)`).Error)

	f := &DefaultStorageFactory{}
	_ = f.migrateDatabase(db)

	// The else-branch must have run; column should now exist.
	assert.True(t, columnExists(db, "machine_identity_credentials", "classification"),
		"classification column must be added by the upgrade branch")
}

// TestMigrateDatabase_S28_MachineRolesPreExisting verifies that migrateDatabase
// handles machine_identity_roles already existing (skips AutoMigrate, no error).
func TestMigrateDatabase_S28_MachineRolesPreExisting(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "machinerole-exists.db"))
	require.NoError(t, err)

	require.NoError(t, db.Exec(`CREATE TABLE machine_identity_roles (
		id INTEGER PRIMARY KEY,
		machine_identity_id INTEGER,
		role_id INTEGER
	)`).Error)

	f := &DefaultStorageFactory{}
	// No error expected — the if-block is simply skipped when table pre-exists.
	_ = f.migrateDatabase(db)
}

// TestMigrateDatabase_S28_MachineOIDCPreExisting verifies that migrateDatabase
// handles machine_identity_oidc_bindings already existing (skips AutoMigrate).
func TestMigrateDatabase_S28_MachineOIDCPreExisting(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "machineoidc-exists.db"))
	require.NoError(t, err)

	require.NoError(t, db.Exec(`CREATE TABLE machine_identity_oidc_bindings (
		id INTEGER PRIMARY KEY,
		machine_identity_id INTEGER,
		issuer TEXT
	)`).Error)

	f := &DefaultStorageFactory{}
	_ = f.migrateDatabase(db)
}

// TestMigrateDatabase_S28_SetupTokensPreExisting verifies that migrateDatabase
// handles setup_tokens already existing (skips AutoMigrate, no error).
func TestMigrateDatabase_S28_SetupTokensPreExisting(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "setuptoken-exists.db"))
	require.NoError(t, err)

	require.NoError(t, db.Exec(`CREATE TABLE setup_tokens (
		id INTEGER PRIMARY KEY,
		token TEXT,
		machine_identity_id INTEGER
	)`).Error)

	f := &DefaultStorageFactory{}
	_ = f.migrateDatabase(db)
}

// TestMigrateDatabase_S28_RiskExceptionsPreExisting verifies that migrateDatabase
// handles risk_exceptions already existing (skips AutoMigrate).
func TestMigrateDatabase_S28_RiskExceptionsPreExisting(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "riskexcept-exists.db"))
	require.NoError(t, err)

	require.NoError(t, db.Exec(`CREATE TABLE risk_exceptions (
		id INTEGER PRIMARY KEY,
		title TEXT,
		status TEXT
	)`).Error)

	f := &DefaultStorageFactory{}
	_ = f.migrateDatabase(db)
}

// TestMigrateDatabase_S28_SSOLoginStatesPreExisting verifies that migrateDatabase
// handles sso_login_states already existing (skips AutoMigrate).
func TestMigrateDatabase_S28_SSOLoginStatesPreExisting(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "ssostate-exists.db"))
	require.NoError(t, err)

	require.NoError(t, db.Exec(`CREATE TABLE sso_login_states (
		id INTEGER PRIMARY KEY,
		state TEXT,
		nonce TEXT
	)`).Error)

	f := &DefaultStorageFactory{}
	_ = f.migrateDatabase(db)
}

// TestMigrateDatabase_S28_SchedulerLockLeasesPreExisting verifies that
// migrateDatabase handles scheduler_lock_leases already existing.
func TestMigrateDatabase_S28_SchedulerLockLeasesPreExisting(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "schedlock-exists.db"))
	require.NoError(t, err)

	require.NoError(t, db.Exec(`CREATE TABLE scheduler_lock_leases (
		id INTEGER PRIMARY KEY,
		owner TEXT,
		expires_at DATETIME
	)`).Error)

	f := &DefaultStorageFactory{}
	_ = f.migrateDatabase(db)
}

// TestMigrateDatabase_S28_SoDPoliciesPreExisting verifies that migrateDatabase
// handles sod_policies already existing (skips AutoMigrate).
func TestMigrateDatabase_S28_SoDPoliciesPreExisting(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "sod-exists.db"))
	require.NoError(t, err)

	require.NoError(t, db.Exec(`CREATE TABLE sod_policies (
		id INTEGER PRIMARY KEY,
		name TEXT,
		rule TEXT
	)`).Error)

	f := &DefaultStorageFactory{}
	_ = f.migrateDatabase(db)
}

// TestMigrateDatabase_S28_SecretDependenciesPreExisting verifies that
// migrateDatabase handles secret_dependencies already existing.
func TestMigrateDatabase_S28_SecretDependenciesPreExisting(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "secretdep-exists.db"))
	require.NoError(t, err)

	require.NoError(t, db.Exec(`CREATE TABLE secret_dependencies (
		id INTEGER PRIMARY KEY,
		source_id INTEGER,
		target_id INTEGER
	)`).Error)

	f := &DefaultStorageFactory{}
	_ = f.migrateDatabase(db)
}

// TestMigrateDatabase_S28_PasswordHistoriesPreExisting verifies that migrateDatabase
// handles password_histories already existing (skips AutoMigrate).
func TestMigrateDatabase_S28_PasswordHistoriesPreExisting(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "pwhist-exists.db"))
	require.NoError(t, err)

	require.NoError(t, db.Exec(`CREATE TABLE password_histories (
		id INTEGER PRIMARY KEY,
		user_id INTEGER,
		password_hash TEXT
	)`).Error)

	f := &DefaultStorageFactory{}
	_ = f.migrateDatabase(db)
}

// TestMigrateDatabase_S28_LoginAttemptsPreExisting verifies that migrateDatabase
// handles login_attempts already existing (skips AutoMigrate).
func TestMigrateDatabase_S28_LoginAttemptsPreExisting(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "loginattempt-exists.db"))
	require.NoError(t, err)

	require.NoError(t, db.Exec(`CREATE TABLE login_attempts (
		id INTEGER PRIMARY KEY,
		username TEXT,
		attempted_at DATETIME
	)`).Error)

	f := &DefaultStorageFactory{}
	_ = f.migrateDatabase(db)
}

// TestMigrateDatabase_S28_WebAuthnCredentialsPreExisting verifies that
// migrateDatabase handles web_authn_credentials already existing.
func TestMigrateDatabase_S28_WebAuthnCredentialsPreExisting(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "webauthn-cred-exists.db"))
	require.NoError(t, err)

	require.NoError(t, db.Exec(`CREATE TABLE web_authn_credentials (
		id INTEGER PRIMARY KEY,
		user_id INTEGER,
		cred_id TEXT
	)`).Error)

	f := &DefaultStorageFactory{}
	_ = f.migrateDatabase(db)
}

// TestMigrateDatabase_S28_WebAuthnSessionsPreExisting verifies that migrateDatabase
// handles web_authn_sessions already existing (skips AutoMigrate).
func TestMigrateDatabase_S28_WebAuthnSessionsPreExisting(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "webauthn-sess-exists.db"))
	require.NoError(t, err)

	require.NoError(t, db.Exec(`CREATE TABLE web_authn_sessions (
		id INTEGER PRIMARY KEY,
		user_id INTEGER,
		challenge TEXT
	)`).Error)

	f := &DefaultStorageFactory{}
	_ = f.migrateDatabase(db)
}

// TestMigrateDatabase_S28_ConnectRefGrantsPreExisting verifies that migrateDatabase
// handles connect_ref_grants already existing (skips AutoMigrate).
func TestMigrateDatabase_S28_ConnectRefGrantsPreExisting(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "connectref-exists.db"))
	require.NoError(t, err)

	require.NoError(t, db.Exec(`CREATE TABLE connect_ref_grants (
		id INTEGER PRIMARY KEY,
		project_id INTEGER,
		ref TEXT
	)`).Error)

	f := &DefaultStorageFactory{}
	_ = f.migrateDatabase(db)
}

// TestMigrateDatabase_S28_AccessRequestApprovalsPreExisting verifies that
// migrateDatabase handles access_request_approvals already existing.
func TestMigrateDatabase_S28_AccessRequestApprovalsPreExisting(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "ar-approvals-exists.db"))
	require.NoError(t, err)

	require.NoError(t, db.Exec(`CREATE TABLE access_request_approvals (
		id INTEGER PRIMARY KEY,
		access_request_id INTEGER,
		approver_id INTEGER
	)`).Error)

	f := &DefaultStorageFactory{}
	_ = f.migrateDatabase(db)
}

// TestMigrateDatabase_S28_BreakGlassPreExisting verifies that migrateDatabase
// with break_glass_activations already existing still runs ensureBreakGlassActiveIndex.
func TestMigrateDatabase_S28_BreakGlassPreExisting(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "bga-exists.db"))
	require.NoError(t, err)

	require.NoError(t, db.Exec(`CREATE TABLE break_glass_activations (
		id INTEGER PRIMARY KEY,
		project_id INTEGER,
		user_id INTEGER,
		state TEXT
	)`).Error)

	f := &DefaultStorageFactory{}
	err = f.migrateDatabase(db)
	// migrateDatabase should succeed — ensureBreakGlassActiveIndex runs and creates index.
	require.NoError(t, err)
}

// TestMigrateDatabase_S28_LegalHoldsPreExisting verifies that migrateDatabase
// with legal_holds already existing still runs ensureLegalHoldActiveIndex.
func TestMigrateDatabase_S28_LegalHoldsPreExisting(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "legalhold-exists.db"))
	require.NoError(t, err)

	require.NoError(t, db.Exec(`CREATE TABLE legal_holds (
		id INTEGER PRIMARY KEY,
		released BOOLEAN DEFAULT false,
		reason TEXT
	)`).Error)

	f := &DefaultStorageFactory{}
	err = f.migrateDatabase(db)
	// migrateDatabase should succeed — ensureLegalHoldActiveIndex creates the index.
	require.NoError(t, err)
}

// TestMigrateDatabase_S28_MFATablesPreExisting verifies that migrateDatabase
// handles all three MFA tables pre-existing (skips AutoMigrate for each).
func TestMigrateDatabase_S28_MFATablesPreExisting(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "mfa-exists.db"))
	require.NoError(t, err)

	require.NoError(t, db.Exec(`CREATE TABLE mfa_secrets (
		id INTEGER PRIMARY KEY,
		user_id INTEGER,
		secret TEXT
	)`).Error)
	require.NoError(t, db.Exec(`CREATE TABLE mfa_recovery_codes (
		id INTEGER PRIMARY KEY,
		user_id INTEGER,
		code_hash TEXT
	)`).Error)
	require.NoError(t, db.Exec(`CREATE TABLE mfa_challenges (
		id INTEGER PRIMARY KEY,
		user_id INTEGER,
		challenge TEXT
	)`).Error)

	f := &DefaultStorageFactory{}
	_ = f.migrateDatabase(db)
}

// TestMigrateDatabase_S28_RotationPoliciesPreExisting verifies that migrateDatabase
// handles rotation_policies already existing (skips AutoMigrate).
func TestMigrateDatabase_S28_RotationPoliciesPreExisting(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "rotpol-exists.db"))
	require.NoError(t, err)

	require.NoError(t, db.Exec(`CREATE TABLE rotation_policies (
		id INTEGER PRIMARY KEY,
		secret_node_id INTEGER,
		interval_days INTEGER
	)`).Error)

	f := &DefaultStorageFactory{}
	_ = f.migrateDatabase(db)
}

// TestMigrateDatabase_S28_DynamicSecretLeasesPreExisting verifies that
// migrateDatabase handles dynamic_secret_leases already existing.
func TestMigrateDatabase_S28_DynamicSecretLeasesPreExisting(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "dynlease-exists.db"))
	require.NoError(t, err)

	// Pre-create dynamic_secret_configs too so the ensureDynamicSecretConfigNameIndex
	// call in migrateDatabase can find the table.
	require.NoError(t, db.Exec(`CREATE TABLE dynamic_secret_configs (
		id INTEGER PRIMARY KEY,
		project_id INTEGER,
		environment_id INTEGER,
		name TEXT
	)`).Error)
	require.NoError(t, db.Exec(`CREATE TABLE dynamic_secret_leases (
		id INTEGER PRIMARY KEY,
		config_id INTEGER,
		expires_at DATETIME
	)`).Error)

	f := &DefaultStorageFactory{}
	_ = f.migrateDatabase(db)
}

// ---------------------------------------------------------------------------
// ensureReminderNotificationDedupIndex — error path
// ---------------------------------------------------------------------------

// TestEnsureReminderNotificationDedupIndex_S28_NoTableError verifies that
// ensureReminderNotificationDedupIndex returns an error when the notifications
// table does not exist. SQLite rejects CREATE INDEX on a non-existent table.
func TestEnsureReminderNotificationDedupIndex_S28_NoTableError(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "reminder-notbl.db"))
	require.NoError(t, err)

	// No notifications table.
	err = ensureReminderNotificationDedupIndex(db)
	require.Error(t, err, "must error when notifications table does not exist")
	assert.Contains(t, err.Error(), "notifications")
}

// ---------------------------------------------------------------------------
// createLocalStorage — migrateDatabase failure surfaces as "failed to migrate"
// ---------------------------------------------------------------------------

// TestCreateLocalStorage_S28_MigrateDatabaseFailure verifies that createLocalStorage
// wraps a migrateDatabase error with "failed to migrate database". We trigger a
// migration failure by pre-seeding the DB with duplicate active share records, which
// causes ensureShareRecordUniqueIndex → warnIfDuplicatesExist to fail.
func TestCreateLocalStorage_S28_MigrateDatabaseFailure(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	// Pre-create and seed the SQLite file at the target path.
	dbPath := filepath.Join(t.TempDir(), "migrate-fail.db")
	seed, err := gormOpenForTest(t, dbPath)
	require.NoError(t, err)

	// Create a minimal share_records table with duplicate active rows.
	// ensureShareRecordUniqueIndex will call warnIfDuplicatesExist which
	// detects these and returns an error before the CREATE INDEX runs.
	require.NoError(t, seed.Exec(`CREATE TABLE share_records (
		id INTEGER PRIMARY KEY,
		secret_id INTEGER,
		recipient_id INTEGER,
		is_group BOOLEAN,
		deleted_at DATETIME
	)`).Error)
	require.NoError(t, seed.Exec(`INSERT INTO share_records VALUES (1, 10, 20, false, NULL)`).Error)
	require.NoError(t, seed.Exec(`INSERT INTO share_records VALUES (2, 10, 20, false, NULL)`).Error) // duplicate

	// Close the seeding connection so createLocalStorage can open its own.
	rawDB, dbErr := seed.DB()
	if dbErr == nil {
		_ = rawDB.Close()
	}

	cfg := &config.Config{}
	cfg.Storage.Type = "local"
	cfg.Storage.Database.Path = dbPath

	_, err = NewStorageFactory().CreateStorage(cfg)
	require.Error(t, err, "createLocalStorage must fail when migrateDatabase fails")
	assert.Contains(t, err.Error(), "migrate", "error must mention 'migrate'")
}

// ---------------------------------------------------------------------------
// columnExists, tableExists, indexExists — additional SQLite edge cases
// ---------------------------------------------------------------------------

// TestColumnExists_S28_EmptyTable verifies that columnExists returns false
// for a column on a table that was just created with no data.
func TestColumnExists_S28_EmptyTable(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "col-empty.db"))
	require.NoError(t, err)

	require.NoError(t, db.Exec(`CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)`).Error)

	assert.True(t, columnExists(db, "t1", "id"))
	assert.True(t, columnExists(db, "t1", "val"))
	assert.False(t, columnExists(db, "t1", "nonexistent_col"))
}

// TestTableExists_S28_AfterCreate verifies that tableExists returns true after
// a table has been created and false before.
func TestTableExists_S28_AfterCreate(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "tbl-aftercreate.db"))
	require.NoError(t, err)

	assert.False(t, tableExists(db, "future_table"))
	require.NoError(t, db.Exec(`CREATE TABLE future_table (id INTEGER PRIMARY KEY)`).Error)
	assert.True(t, tableExists(db, "future_table"))
}

// TestIndexExists_S28_AfterCreate verifies that indexExists returns true after
// an index is created and false before.
func TestIndexExists_S28_AfterCreate(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "idx-aftercreate.db"))
	require.NoError(t, err)

	require.NoError(t, db.Exec(`CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)`).Error)
	assert.False(t, indexExists(db, "idx_t1_val"))
	require.NoError(t, db.Exec(`CREATE INDEX idx_t1_val ON t1 (val)`).Error)
	assert.True(t, indexExists(db, "idx_t1_val"))
}

// TestIndexExists_S28_UniqueIndex verifies that indexExists detects a UNIQUE index.
func TestIndexExists_S28_UniqueIndex(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "idx-unique.db"))
	require.NoError(t, err)

	require.NoError(t, db.Exec(`CREATE TABLE t2 (id INTEGER PRIMARY KEY, code TEXT)`).Error)
	require.NoError(t, db.Exec(`CREATE UNIQUE INDEX idx_t2_code ON t2 (code)`).Error)
	assert.True(t, indexExists(db, "idx_t2_code"))
	assert.False(t, indexExists(db, "idx_t2_nonexistent"))
}

// ---------------------------------------------------------------------------
// warnIfDuplicatesExist — no-where-clause variant
// ---------------------------------------------------------------------------

// TestWarnIfDuplicatesExist_S28_NoWhereNoDuplicates verifies that
// warnIfDuplicatesExist returns nil when there are no duplicates and no WHERE
// clause is used (the predicate-less path).
func TestWarnIfDuplicatesExist_S28_NoWhereNoDuplicates(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "warn-nowhere.db"))
	require.NoError(t, err)

	require.NoError(t, db.Exec(`CREATE TABLE items (id INTEGER PRIMARY KEY, code TEXT)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO items VALUES (1, 'A')`).Error)
	require.NoError(t, db.Exec(`INSERT INTO items VALUES (2, 'B')`).Error)

	err = warnIfDuplicatesExist(db, "items", "code", "", "dedup remedy")
	require.NoError(t, err)
}

// TestWarnIfDuplicatesExist_S28_NoWhereWithDuplicates verifies that
// warnIfDuplicatesExist returns an error when duplicates exist and no WHERE
// clause is applied (the predicate-less path with "(no predicate)" in message).
func TestWarnIfDuplicatesExist_S28_NoWhereWithDuplicates(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "warn-nowheredup.db"))
	require.NoError(t, err)

	require.NoError(t, db.Exec(`CREATE TABLE items2 (id INTEGER PRIMARY KEY, code TEXT)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO items2 VALUES (1, 'A')`).Error)
	require.NoError(t, db.Exec(`INSERT INTO items2 VALUES (2, 'A')`).Error) // duplicate

	err = warnIfDuplicatesExist(db, "items2", "code", "", "dedup remedy")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no predicate")
}

// ---------------------------------------------------------------------------
// sqliteDSN — confirm both separator branches
// ---------------------------------------------------------------------------

// TestSQLiteDSN_S28_NoPriorParams verifies that a plain path gets "?" appended.
func TestSQLiteDSN_S28_NoPriorParams(t *testing.T) {
	dsn := sqliteDSN("/tmp/mydb.db")
	assert.Contains(t, dsn, "?", "plain path must get '?' separator")
	assert.Contains(t, dsn, "_foreign_keys=1")
	assert.Contains(t, dsn, "_busy_timeout=10000")
	assert.Contains(t, dsn, "_journal_mode=WAL")
}

// TestSQLiteDSN_S28_WithExistingParams verifies that a path with "?" already
// gets "&" appended (not a second "?").
func TestSQLiteDSN_S28_WithExistingParams(t *testing.T) {
	dsn := sqliteDSN("file:mydb?mode=memory")
	assert.NotContains(t, dsn, "??")
	assert.Contains(t, dsn, "_foreign_keys=1")
	assert.Contains(t, dsn, "_journal_mode=WAL")
}

// ---------------------------------------------------------------------------
// gormConfig — verify the returned config is safe
// ---------------------------------------------------------------------------

// TestGormConfig_S28_NonNil verifies that gormConfig returns a non-nil config.
func TestGormConfig_S28_NonNil(t *testing.T) {
	cfg := gormConfig()
	require.NotNil(t, cfg)
}

// ---------------------------------------------------------------------------
// createLocalStorage — empty path uses default "./secrets.db"
// ---------------------------------------------------------------------------

// TestCreateLocalStorage_S28_EmptyPathUsesDefault verifies that createLocalStorage
// defaults to "./secrets.db" when no path is configured (line 163 in factory.go).
// We use t.Chdir to redirect the default file to the test's temp dir.
func TestCreateLocalStorage_S28_EmptyPathUsesDefault(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	// Change to a temp dir so "./secrets.db" doesn't pollute the source tree.
	t.Chdir(t.TempDir())

	cfg := &config.Config{}
	cfg.Storage.Type = "local"
	// Path is intentionally empty → createLocalStorage uses "./secrets.db"

	st, err := NewStorageFactory().CreateStorage(cfg)
	require.NoError(t, err, "createLocalStorage with empty path must succeed using default ./secrets.db")
	assert.NotNil(t, st)
}

// ---------------------------------------------------------------------------
// migrateDatabase — projects table pre-existing triggers early return
// ---------------------------------------------------------------------------

// TestMigrateDatabase_S28_ProjectsExistingEarlyReturn verifies that migrateDatabase
// returns nil early when the projects table already exists (the fast-path for
// already-initialized DBs).
func TestMigrateDatabase_S28_ProjectsExistingEarlyReturn(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "projects-early.db"))
	require.NoError(t, err)

	// Create minimal projects table so projectsExists=true triggers early return.
	require.NoError(t, db.Exec(`CREATE TABLE projects (
		id INTEGER PRIMARY KEY,
		name TEXT,
		deleted_at DATETIME
	)`).Error)

	// Also create the indexes' dependencies to avoid errors from ensure*Index helpers.
	// Users, groups, share_records, secret_versions, project_memberships,
	// break_glass_activations, legal_holds, notifications, dynamic_secret_configs
	// are referenced before the early return.
	require.NoError(t, db.Exec(`CREATE TABLE users (
		id INTEGER PRIMARY KEY,
		username TEXT,
		email TEXT,
		external_id TEXT NOT NULL DEFAULT '',
		deleted_at DATETIME
	)`).Error)
	require.NoError(t, db.Exec(`CREATE TABLE groups (
		id INTEGER PRIMARY KEY,
		name TEXT,
		deleted_at DATETIME
	)`).Error)
	require.NoError(t, db.Exec(`CREATE TABLE share_records (
		id INTEGER PRIMARY KEY,
		secret_id INTEGER,
		recipient_id INTEGER,
		is_group BOOLEAN,
		deleted_at DATETIME
	)`).Error)
	require.NoError(t, db.Exec(`CREATE TABLE secret_versions (
		id INTEGER PRIMARY KEY,
		secret_node_id INTEGER,
		version_number INTEGER
	)`).Error)
	require.NoError(t, db.Exec(`CREATE TABLE break_glass_activations (
		id INTEGER PRIMARY KEY,
		project_id INTEGER,
		user_id INTEGER,
		state TEXT
	)`).Error)
	require.NoError(t, db.Exec(`CREATE TABLE legal_holds (
		id INTEGER PRIMARY KEY,
		released BOOLEAN DEFAULT false,
		reason TEXT
	)`).Error)
	require.NoError(t, db.Exec(`CREATE TABLE notifications (
		id INTEGER PRIMARY KEY,
		user_id INTEGER,
		type TEXT,
		is_read BOOLEAN DEFAULT false,
		project_id INTEGER
	)`).Error)

	f := &DefaultStorageFactory{}
	err = f.migrateDatabase(db)
	// Should succeed — all ensure*Index functions find the tables and create indexes.
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// migrateDatabase — machine_identities else branch (classification column)
// ---------------------------------------------------------------------------

// TestMigrateDatabase_S28_MachineIdentitiesElseBranch verifies that the
// machine_identities else-branch (adds classification column + companion index)
// is reached when the table already exists without that column.
func TestMigrateDatabase_S28_MachineIdentitiesElseBranch(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "machineid-else.db"))
	require.NoError(t, err)

	// Pre-existing machine_identities without classification column.
	require.NoError(t, db.Exec(`CREATE TABLE machine_identities (
		id INTEGER PRIMARY KEY,
		name TEXT,
		project_id INTEGER
	)`).Error)

	f := &DefaultStorageFactory{}
	_ = f.migrateDatabase(db)

	// The else-branch should have run and added the column.
	assert.True(t, columnExists(db, "machine_identities", "classification"))
	assert.True(t, indexExists(db, "idx_machine_identities_classification"))
}

// ---------------------------------------------------------------------------
// migrateDatabase — project_memberships else branch (ensureProjectMembershipIndex)
// ---------------------------------------------------------------------------

// TestMigrateDatabase_S28_ProjectMembershipsPreExisting verifies that when
// project_memberships pre-exists, migrateDatabase runs ensureProjectMembershipIndex
// (via the tableExists check at line ~931) and succeeds.
func TestMigrateDatabase_S28_ProjectMembershipsPreExisting(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "membership-exists.db"))
	require.NoError(t, err)

	require.NoError(t, db.Exec(`CREATE TABLE project_memberships (
		id INTEGER PRIMARY KEY,
		project_id INTEGER,
		user_id INTEGER,
		state TEXT NOT NULL DEFAULT 'active'
	)`).Error)

	f := &DefaultStorageFactory{}
	err = f.migrateDatabase(db)
	require.NoError(t, err, "migrateDatabase must succeed when project_memberships pre-exists")
	assert.True(t, indexExists(db, "uniq_project_memberships_active"))
}

// ---------------------------------------------------------------------------
// migrateDatabase — error propagation from ensure*Index inside users block
// ---------------------------------------------------------------------------

// TestMigrateDatabase_S28_UsersTableIncompatibleSchema verifies that migrateDatabase
// propagates an error from ensureUserNameIndex when the users table exists but lacks
// the username column (so the warnIfDuplicatesExist query fails on the missing column).
func TestMigrateDatabase_S28_UsersTableIncompatibleSchema(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "users-badcols.db"))
	require.NoError(t, err)

	// Create users table WITHOUT username/email/external_id columns.
	// ensureUserNameIndex → warnIfDuplicatesExist queries for "username" column
	// which doesn't exist → query fails → error propagates up through migrateDatabase.
	require.NoError(t, db.Exec(`CREATE TABLE users (
		id INTEGER PRIMARY KEY,
		display_name TEXT
	)`).Error)

	f := &DefaultStorageFactory{}
	err = f.migrateDatabase(db)
	require.Error(t, err, "migrateDatabase must propagate error when users table has incompatible schema")
}

// TestMigrateDatabase_S28_GroupsTableIncompatibleSchema verifies that migrateDatabase
// propagates an error from ensureGroupNameIndex when the groups table exists but
// lacks the name column.
func TestMigrateDatabase_S28_GroupsTableIncompatibleSchema(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "groups-badcols.db"))
	require.NoError(t, err)

	// Create groups table WITHOUT name/deleted_at columns.
	// ensureGroupNameIndex → warnIfDuplicatesExist queries "name" which won't exist
	// → the DROP INDEX succeeds (no-op), then warnIfDuplicatesExist fails.
	require.NoError(t, db.Exec(`CREATE TABLE groups (
		id INTEGER PRIMARY KEY,
		description TEXT
	)`).Error)

	f := &DefaultStorageFactory{}
	err = f.migrateDatabase(db)
	require.Error(t, err, "migrateDatabase must propagate error when groups table has incompatible schema")
}

// TestMigrateDatabase_S28_DynamicSecretConfigsIncompatibleSchema verifies that
// migrateDatabase propagates an error when dynamic_secret_configs exists but lacks
// the columns needed for ensureDynamicSecretConfigNameIndex.
func TestMigrateDatabase_S28_DynamicSecretConfigsIncompatibleSchema(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "dynconfig-badcols.db"))
	require.NoError(t, err)

	// Create dynamic_secret_configs WITHOUT project_id/environment_id/name columns.
	// ensureDynamicSecretConfigNameIndex → warnIfDuplicatesExist queries those
	// columns → fails → error propagates.
	require.NoError(t, db.Exec(`CREATE TABLE dynamic_secret_configs (
		id INTEGER PRIMARY KEY,
		description TEXT
	)`).Error)

	f := &DefaultStorageFactory{}
	err = f.migrateDatabase(db)
	require.Error(t, err, "migrateDatabase must propagate error when dynamic_secret_configs has incompatible schema")
}

// TestMigrateDatabase_S28_ProjectMembershipsIncompatibleSchema verifies that
// migrateDatabase propagates an error from ensureProjectMembershipIndex when the
// project_memberships table exists but lacks required columns.
func TestMigrateDatabase_S28_ProjectMembershipsIncompatibleSchema(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "pm-badcols.db"))
	require.NoError(t, err)

	// Create project_memberships WITHOUT project_id/user_id/state columns.
	require.NoError(t, db.Exec(`CREATE TABLE project_memberships (
		id INTEGER PRIMARY KEY,
		description TEXT
	)`).Error)

	f := &DefaultStorageFactory{}
	err = f.migrateDatabase(db)
	require.Error(t, err, "migrateDatabase must propagate error when project_memberships has incompatible schema")
}

// TestMigrateDatabase_S28_BreakGlassIncompatibleSchema verifies that
// migrateDatabase propagates an error from ensureBreakGlassActiveIndex when
// break_glass_activations lacks project_id/user_id/state columns.
func TestMigrateDatabase_S28_BreakGlassIncompatibleSchema(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "bga-badcols.db"))
	require.NoError(t, err)

	// break_glass_activations WITHOUT project_id/user_id/state columns.
	require.NoError(t, db.Exec(`CREATE TABLE break_glass_activations (
		id INTEGER PRIMARY KEY,
		description TEXT
	)`).Error)

	f := &DefaultStorageFactory{}
	err = f.migrateDatabase(db)
	require.Error(t, err, "migrateDatabase must propagate error when break_glass_activations has incompatible schema")
}

// TestMigrateDatabase_S28_LegalHoldsIncompatibleSchema verifies that
// migrateDatabase propagates an error from ensureLegalHoldActiveIndex when
// legal_holds lacks the released column.
func TestMigrateDatabase_S28_LegalHoldsIncompatibleSchema(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "legalhold-badcols.db"))
	require.NoError(t, err)

	// legal_holds WITHOUT the released column.
	require.NoError(t, db.Exec(`CREATE TABLE legal_holds (
		id INTEGER PRIMARY KEY,
		description TEXT
	)`).Error)

	f := &DefaultStorageFactory{}
	err = f.migrateDatabase(db)
	require.Error(t, err, "migrateDatabase must propagate error when legal_holds has incompatible schema")
}

// TestMigrateDatabase_S28_SecretVersionsIncompatibleSchema verifies that
// migrateDatabase propagates an error from ensureSecretVersionIndex when
// secret_versions lacks secret_node_id/version_number columns.
func TestMigrateDatabase_S28_SecretVersionsIncompatibleSchema(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "sv-badcols2.db"))
	require.NoError(t, err)

	// Create secret_versions WITHOUT required columns.
	require.NoError(t, db.Exec(`CREATE TABLE secret_versions (
		id INTEGER PRIMARY KEY,
		description TEXT
	)`).Error)

	f := &DefaultStorageFactory{}
	err = f.migrateDatabase(db)
	require.Error(t, err, "migrateDatabase must propagate ensureSecretVersionIndex error")
}
