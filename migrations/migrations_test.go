// Package migrations contains regression tests for the legacy, manual-only
// migrations/*.sql files described in migrations/README.md. These files are
// not exercised by any other automated harness (they're applied, if at all,
// via scripts/run_migrations.sh + the external golang-migrate CLI) — this
// test applies the raw SQL directly against a real SQLite database using the
// same modernc.org/sqlite driver used elsewhere in the codebase (ADR-048,
// indirectly via internal/storage/sqlitedialect), so no new test-only
// dependency is introduced.
//
// It covers backlog finding #203 and its round-140 follow-up: five
// destructive down-migrations (002_rbac_enhancements, 004_add_auth_encryption,
// 005_secret_sharing, 007_rotation_policies, 008_scope_user_group_roles) used
// to DROP (or, for 008, silently strip scoping from) security-relevant data
// with no export step. Each now copies the about-to-be-dropped data into a
// same-database backup table before the DROP/column-drop. These tests prove
// (1) real data present before rollback survives in the backup location
// afterward, and (2) the down-migration still performs its original
// structural change (the original column/table is genuinely gone), so the
// fix doesn't silently turn the down-migration into a no-op. 005's tests
// additionally pin a deliberate scope decision: secret_nodes.owner_id is kept
// (it's core ownership tracking used well beyond the sharing feature), only
// the sharing-specific is_shared column is dropped — see the down-migration's
// own comment for the investigation.
package migrations

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite" // registers the "sqlite" driver with database/sql
)

// openTestDB opens a fresh, file-backed (not shared in-memory) SQLite
// database unique to this test, and applies 001_init.sql to establish the
// baseline schema every later migration builds on.
func openTestDB(t *testing.T) *sql.DB {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), "migrations-test.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open sqlite db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	// A single connection avoids any cross-connection SQLite locking
	// surprises for this short-lived, single-goroutine test DB.
	db.SetMaxOpenConns(1)

	execSQLFile(t, db, "001_init.sql")
	return db
}

func execSQLFile(t *testing.T, db *sql.DB, name string) {
	t.Helper()

	content, err := os.ReadFile(filepath.Join(".", name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	if _, err := db.Exec(string(content)); err != nil {
		t.Fatalf("exec %s: %v", name, err)
	}
}

func tableExists(t *testing.T, db *sql.DB, table string) bool {
	t.Helper()

	var name string
	err := db.QueryRow(
		`SELECT name FROM sqlite_master WHERE type='table' AND name=?`, table,
	).Scan(&name)
	if err == sql.ErrNoRows {
		return false
	}
	if err != nil {
		t.Fatalf("check table %s exists: %v", table, err)
	}
	return true
}

func columnExists(t *testing.T, db *sql.DB, table, column string) bool {
	t.Helper()

	rows, err := db.Query(`PRAGMA table_info(` + table + `)`)
	if err != nil {
		t.Fatalf("PRAGMA table_info(%s): %v", table, err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var (
			cid       int
			name      string
			ctype     sql.NullString
			notnull   int
			dfltValue sql.NullString
			pk        int
		)
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dfltValue, &pk); err != nil {
			t.Fatalf("scan table_info row: %v", err)
		}
		if name == column {
			return true
		}
	}
	return false
}

// TestRBACAuditLogDownMigration_PreservesAuditTrail pins #203: rolling back
// migration 002 must not silently destroy the RBAC audit trail.
func TestRBACAuditLogDownMigration_PreservesAuditTrail(t *testing.T) {
	db := openTestDB(t)
	execSQLFile(t, db, "002_rbac_enhancements.up.sql")

	if _, err := db.Exec(
		`INSERT INTO rbac_audit_log (action, actor_user_id, target_user_id, role_id, namespace_id, details)
		 VALUES ('ASSIGN_ROLE', 1, 2, 3, 1, '{"note":"pin-203"}')`,
	); err != nil {
		t.Fatalf("seed rbac_audit_log: %v", err)
	}

	execSQLFile(t, db, "002_rbac_enhancements.down.sql")

	// Non-regression: the down-migration must still actually drop the table.
	if tableExists(t, db, "rbac_audit_log") {
		t.Fatal("rbac_audit_log still exists after down-migration; down-migration is a no-op")
	}

	// Regression fix: the row must survive in the backup table.
	var action string
	var details string
	err := db.QueryRow(
		`SELECT action, details FROM rbac_audit_log_backup WHERE action = 'ASSIGN_ROLE'`,
	).Scan(&action, &details)
	if err != nil {
		t.Fatalf("query rbac_audit_log_backup: %v", err)
	}
	if details != `{"note":"pin-203"}` {
		t.Fatalf("rbac_audit_log_backup.details = %q, want the seeded details preserved", details)
	}
}

// TestAuthEncryptionDownMigration_PreservesEncryptedColumns pins #203: rolling
// back migration 004 must not silently destroy encrypted credential material.
func TestAuthEncryptionDownMigration_PreservesEncryptedColumns(t *testing.T) {
	db := openTestDB(t)
	execSQLFile(t, db, "004_add_auth_encryption.up.sql")

	if _, err := db.Exec(
		`INSERT INTO users (username, email, password_hash) VALUES ('alice', 'alice@example.com', 'x')`,
	); err != nil {
		t.Fatalf("seed users: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO api_clients (name, client_id, client_secret, encrypted_client_secret, client_secret_metadata)
		 VALUES ('client1', 'cid1', 'plain', X'DEADBEEF', '{"alg":"AES-256-GCM","kv":1}')`,
	); err != nil {
		t.Fatalf("seed api_clients: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO sessions (user_id, session_token, encrypted_session_token, session_token_metadata)
		 VALUES (1, 'tok1', X'CAFEBABE', '{"alg":"AES-256-GCM","kv":1}')`,
	); err != nil {
		t.Fatalf("seed sessions: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO api_tokens (client_id, token, encrypted_token, token_metadata)
		 VALUES (1, 'atok1', X'FEEDFACE', '{"alg":"AES-256-GCM","kv":1}')`,
	); err != nil {
		t.Fatalf("seed api_tokens: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO password_resets (user_id, token, encrypted_token, token_metadata)
		 VALUES (1, 'ptok1', X'B16B00B5', '{"alg":"AES-256-GCM","kv":1}')`,
	); err != nil {
		t.Fatalf("seed password_resets: %v", err)
	}

	execSQLFile(t, db, "004_add_auth_encryption.down.sql")

	// Non-regression: the encrypted_* / *_metadata columns must genuinely be
	// gone from their original tables.
	for _, tc := range []struct{ table, column string }{
		{"api_clients", "encrypted_client_secret"},
		{"api_clients", "client_secret_metadata"},
		{"sessions", "encrypted_session_token"},
		{"sessions", "session_token_metadata"},
		{"api_tokens", "encrypted_token"},
		{"api_tokens", "token_metadata"},
		{"password_resets", "encrypted_token"},
		{"password_resets", "token_metadata"},
	} {
		if columnExists(t, db, tc.table, tc.column) {
			t.Fatalf("%s.%s still exists after down-migration; down-migration is a no-op", tc.table, tc.column)
		}
	}

	// Regression fix: every dropped column's value must survive in the
	// shared backup table, keyed by source table/row id/column name.
	wantRows := map[string]string{
		"api_clients|encrypted_client_secret": string([]byte{0xDE, 0xAD, 0xBE, 0xEF}),
		"api_clients|client_secret_metadata":  `{"alg":"AES-256-GCM","kv":1}`,
		"sessions|encrypted_session_token":    string([]byte{0xCA, 0xFE, 0xBA, 0xBE}),
		"sessions|session_token_metadata":     `{"alg":"AES-256-GCM","kv":1}`,
		"api_tokens|encrypted_token":          string([]byte{0xFE, 0xED, 0xFA, 0xCE}),
		"api_tokens|token_metadata":           `{"alg":"AES-256-GCM","kv":1}`,
		"password_resets|encrypted_token":     string([]byte{0xB1, 0x6B, 0x00, 0xB5}),
		"password_resets|token_metadata":      `{"alg":"AES-256-GCM","kv":1}`,
	}
	for key, want := range wantRows {
		var table, column string
		splitKV(key, &table, &column)
		var got []byte
		err := db.QueryRow(
			`SELECT column_value FROM auth_encryption_columns_backup
			 WHERE source_table = ? AND column_name = ? AND source_id = 1`,
			table, column,
		).Scan(&got)
		if err != nil {
			t.Fatalf("query auth_encryption_columns_backup for %s.%s: %v", table, column, err)
		}
		if string(got) != want {
			t.Fatalf("auth_encryption_columns_backup %s.%s = %q, want %q", table, column, got, want)
		}
	}
}

func splitKV(key string, table, column *string) {
	for i := range key {
		if key[i] == '|' {
			*table = key[:i]
			*column = key[i+1:]
			return
		}
	}
	*table = key
}

// TestShareRecordsDownMigration_PreservesShareHistory pins #203: rolling back
// migration 005 must not silently destroy share/access-grant history.
func TestShareRecordsDownMigration_PreservesShareHistory(t *testing.T) {
	db := openTestDB(t)
	execSQLFile(t, db, "005_secret_sharing.up.sql")

	if _, err := db.Exec(
		`INSERT INTO users (username, email, password_hash) VALUES ('owner1', 'owner1@example.com', 'x')`,
	); err != nil {
		t.Fatalf("seed users (owner): %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO users (username, email, password_hash) VALUES ('recipient1', 'recipient1@example.com', 'x')`,
	); err != nil {
		t.Fatalf("seed users (recipient): %v", err)
	}
	if _, err := db.Exec(`INSERT INTO namespaces (name) VALUES ('ns1')`); err != nil {
		t.Fatalf("seed namespaces: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO zones (name) VALUES ('zone1')`); err != nil {
		t.Fatalf("seed zones: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO environments (name) VALUES ('env1')`); err != nil {
		t.Fatalf("seed environments: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO secret_nodes (namespace_id, zone_id, environment_id, name, is_secret, type, created_by)
		 VALUES (1, 1, 1, 's1', 1, 'secret', 'owner1')`,
	); err != nil {
		t.Fatalf("seed secret_nodes: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO share_records (secret_id, owner_id, recipient_id, is_group, permission, created_at, updated_at)
		 VALUES (1, 1, 2, 0, 'read', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`,
	); err != nil {
		t.Fatalf("seed share_records: %v", err)
	}

	execSQLFile(t, db, "005_secret_sharing.down.sql")

	// Non-regression: the down-migration must still actually drop the table.
	if tableExists(t, db, "share_records") {
		t.Fatal("share_records still exists after down-migration; down-migration is a no-op")
	}

	// Regression fix: the share record must survive in the backup table.
	var ownerID, recipientID int
	var permission string
	err := db.QueryRow(
		`SELECT owner_id, recipient_id, permission FROM share_records_backup WHERE secret_id = 1`,
	).Scan(&ownerID, &recipientID, &permission)
	if err != nil {
		t.Fatalf("query share_records_backup: %v", err)
	}
	if ownerID != 1 || recipientID != 2 || permission != "read" {
		t.Fatalf("share_records_backup row = (owner=%d, recipient=%d, permission=%q), want (1, 2, \"read\")",
			ownerID, recipientID, permission)
	}
}

// TestSecretNodesDownMigration_KeepsOwnerIDDropsIsShared pins the fix to
// 005_secret_sharing.down.sql's previously-stubbed secret_nodes column
// removal (see the file's own comment for the investigation: owner_id is
// core ownership-tracking infrastructure used far beyond the "sharing"
// feature — permissions.go's CheckSecretPermission, secret_ownership.go's
// TransferSecretOwnership, access reviews, blast-radius/risk analysis, and
// the inventory report all key off it — so only is_shared, which is
// sharing-specific and fully recomputable from share_records, is dropped.
func TestSecretNodesDownMigration_KeepsOwnerIDDropsIsShared(t *testing.T) {
	db := openTestDB(t)
	execSQLFile(t, db, "005_secret_sharing.up.sql")

	if _, err := db.Exec(
		`INSERT INTO users (username, email, password_hash) VALUES ('owner1', 'owner1@example.com', 'x')`,
	); err != nil {
		t.Fatalf("seed users: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO namespaces (name) VALUES ('ns1')`); err != nil {
		t.Fatalf("seed namespaces: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO zones (name) VALUES ('zone1')`); err != nil {
		t.Fatalf("seed zones: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO environments (name) VALUES ('env1')`); err != nil {
		t.Fatalf("seed environments: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO secret_nodes (namespace_id, zone_id, environment_id, name, is_secret, type, created_by, owner_id, is_shared)
		 VALUES (1, 1, 1, 's1', 1, 'secret', 'owner1', 1, 1)`,
	); err != nil {
		t.Fatalf("seed secret_nodes: %v", err)
	}

	execSQLFile(t, db, "005_secret_sharing.down.sql")

	// Non-regression: is_shared is sharing-specific and genuinely dropped.
	if columnExists(t, db, "secret_nodes", "is_shared") {
		t.Fatal("secret_nodes.is_shared still exists after down-migration; the stub was never implemented")
	}

	// Regression fix, deliberate scope decision: owner_id is NOT dropped
	// (it's core ownership tracking, not sharing-specific) and its data must
	// survive the table rebuild intact.
	if !columnExists(t, db, "secret_nodes", "owner_id") {
		t.Fatal("secret_nodes.owner_id was dropped; it is core ownership tracking and must be preserved")
	}
	var ownerID int
	if err := db.QueryRow(`SELECT owner_id FROM secret_nodes WHERE id = 1`).Scan(&ownerID); err != nil {
		t.Fatalf("query secret_nodes.owner_id: %v", err)
	}
	if ownerID != 1 {
		t.Fatalf("secret_nodes.owner_id = %d, want 1 (preserved across the table rebuild)", ownerID)
	}

	// The owner_id index must survive the rebuild too, since the column did.
	if !tableExists(t, db, "secret_nodes") {
		t.Fatal("secret_nodes table itself must still exist (only is_shared should be removed)")
	}
	var idxName string
	err := db.QueryRow(
		`SELECT name FROM sqlite_master WHERE type='index' AND name='idx_secret_nodes_owner_id'`,
	).Scan(&idxName)
	if err != nil {
		t.Fatalf("idx_secret_nodes_owner_id missing after rebuild: %v", err)
	}
}

// TestSecretNodesDownMigration_ReapplyingUpFailsLoudlyOnPreservedOwnerID
// documents an accepted, intentional consequence of keeping owner_id (see
// the test above and the comment in 005_secret_sharing.down.sql): because
// owner_id is deliberately NOT dropped, 005_secret_sharing.up.sql's
// `ALTER TABLE secret_nodes ADD COLUMN owner_id ...` can no longer be
// cleanly replayed after a down-migration — it now fails loudly with a
// duplicate-column error instead of silently succeeding. That's the correct
// trade-off (a loud, immediate failure beats silently duplicating or
// losing ownership data), but it means down-then-up is no longer fully
// symmetric for this migration; this test pins that as expected, not a
// regression to "fix" by reintroducing the drop.
func TestSecretNodesDownMigration_ReapplyingUpFailsLoudlyOnPreservedOwnerID(t *testing.T) {
	db := openTestDB(t)
	execSQLFile(t, db, "005_secret_sharing.up.sql")
	execSQLFile(t, db, "005_secret_sharing.down.sql")

	content, err := os.ReadFile(filepath.Join(".", "005_secret_sharing.up.sql"))
	if err != nil {
		t.Fatalf("read 005_secret_sharing.up.sql: %v", err)
	}
	_, execErr := db.Exec(string(content))
	if execErr == nil {
		t.Fatal("expected re-applying 005's up-migration to fail on the already-present owner_id column, got nil error")
	}
}

// TestRotationPoliciesDownMigration_PreservesComplianceData pins the fix to
// 007_rotation_policies.down.sql: rolling back must not silently destroy
// rotation-policy/compliance data (which secrets require rotation, alert
// thresholds, created_by accountability).
//
// 007_rotation_policies.up.sql uses PostgreSQL-only syntax (SERIAL, NOW())
// that modernc.org/sqlite's driver cannot execute (see migrations/README.md:
// these files are "dialect-inconsistent by construction" and "were never
// executed end-to-end as a single unit against one database engine"), so
// this test seeds the table directly with SQLite-compatible DDL matching the
// up-migration's column set, rather than executing the up file.
func TestRotationPoliciesDownMigration_PreservesComplianceData(t *testing.T) {
	db := openTestDB(t)

	if _, err := db.Exec(`CREATE TABLE rotation_policies (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		description TEXT,
		scope TEXT NOT NULL DEFAULT 'environment',
		project_id INTEGER,
		environment_id INTEGER,
		interval_days INTEGER NOT NULL,
		alert_days_before INTEGER NOT NULL DEFAULT 7,
		notify_on_breach BOOLEAN NOT NULL DEFAULT 1,
		is_active BOOLEAN NOT NULL DEFAULT 1,
		created_by TEXT NOT NULL,
		created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
		deleted_at TIMESTAMP
	)`); err != nil {
		t.Fatalf("seed rotation_policies schema: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO rotation_policies (name, description, scope, interval_days, alert_days_before, notify_on_breach, is_active, created_by)
		 VALUES ('db-creds-90d', 'rotate DB creds quarterly', 'environment', 90, 14, 1, 1, 'alice')`,
	); err != nil {
		t.Fatalf("seed rotation_policies row: %v", err)
	}

	execSQLFile(t, db, "007_rotation_policies.down.sql")

	// Non-regression: the down-migration must still actually drop the table.
	if tableExists(t, db, "rotation_policies") {
		t.Fatal("rotation_policies still exists after down-migration; down-migration is a no-op")
	}

	// Regression fix: the row must survive in the backup table.
	var name, createdBy string
	var intervalDays int
	err := db.QueryRow(
		`SELECT name, interval_days, created_by FROM rotation_policies_backup WHERE name = 'db-creds-90d'`,
	).Scan(&name, &intervalDays, &createdBy)
	if err != nil {
		t.Fatalf("query rotation_policies_backup: %v", err)
	}
	if intervalDays != 90 || createdBy != "alice" {
		t.Fatalf("rotation_policies_backup row = (interval_days=%d, created_by=%q), want (90, \"alice\")",
			intervalDays, createdBy)
	}
}

// TestScopeUserGroupRolesDownMigration_PreservesEnvironmentScoping pins the
// fix to 008_scope_user_group_roles.down.sql: dropping environment_id must
// not silently widen every previously environment-scoped role/group binding
// to "all environments" (environment_id=0, per 008's up-migration and
// internal/core/access_review.go's EnvironmentID doc comment) on a future
// down-then-up cycle. The row itself (and its environment_id value) must
// survive in a backup table, and the live table's other columns/rows must be
// untouched by the column drop.
func TestScopeUserGroupRolesDownMigration_PreservesEnvironmentScoping(t *testing.T) {
	db := openTestDB(t)
	execSQLFile(t, db, "002_rbac_enhancements.up.sql")
	execSQLFile(t, db, "006_rename_namespace_to_project.up.sql")
	execSQLFile(t, db, "008_scope_user_group_roles.up.sql")

	if _, err := db.Exec(`INSERT INTO users (username, email, password_hash) VALUES ('alice', 'alice@example.com', 'x')`); err != nil {
		t.Fatalf("seed users: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO roles (name) VALUES ('admin')`); err != nil {
		t.Fatalf("seed roles: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO groups (name) VALUES ('g1')`); err != nil {
		t.Fatalf("seed groups: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO projects (name) VALUES ('proj1')`); err != nil {
		t.Fatalf("seed projects: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO user_roles (user_id, role_id, project_id, environment_id) VALUES (1, 1, 1, 7)`,
	); err != nil {
		t.Fatalf("seed user_roles: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO group_roles (group_id, role_id, project_id, environment_id) VALUES (1, 1, 1, 7)`,
	); err != nil {
		t.Fatalf("seed group_roles: %v", err)
	}

	execSQLFile(t, db, "008_scope_user_group_roles.down.sql")

	// Non-regression: the down-migration must still actually drop the column.
	if columnExists(t, db, "user_roles", "environment_id") {
		t.Fatal("user_roles.environment_id still exists after down-migration; down-migration is a no-op")
	}
	if columnExists(t, db, "group_roles", "environment_id") {
		t.Fatal("group_roles.environment_id still exists after down-migration; down-migration is a no-op")
	}

	// The row itself (minus environment_id) must survive the column drop.
	var projectID int
	if err := db.QueryRow(`SELECT project_id FROM user_roles WHERE user_id = 1 AND role_id = 1`).Scan(&projectID); err != nil {
		t.Fatalf("user_roles row missing after down-migration: %v", err)
	}
	if projectID != 1 {
		t.Fatalf("user_roles.project_id = %d, want 1 (untouched by the environment_id drop)", projectID)
	}

	// Regression fix: environment_id must survive in the backup tables.
	var envID int
	err := db.QueryRow(
		`SELECT environment_id FROM user_roles_backup WHERE user_id = 1 AND role_id = 1 AND project_id = 1`,
	).Scan(&envID)
	if err != nil {
		t.Fatalf("query user_roles_backup: %v", err)
	}
	if envID != 7 {
		t.Fatalf("user_roles_backup.environment_id = %d, want 7", envID)
	}

	err = db.QueryRow(
		`SELECT environment_id FROM group_roles_backup WHERE group_id = 1 AND role_id = 1 AND project_id = 1`,
	).Scan(&envID)
	if err != nil {
		t.Fatalf("query group_roles_backup: %v", err)
	}
	if envID != 7 {
		t.Fatalf("group_roles_backup.environment_id = %d, want 7", envID)
	}
}
