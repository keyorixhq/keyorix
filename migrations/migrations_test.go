// Package migrations contains regression tests for the legacy, manual-only
// migrations/*.sql files described in migrations/README.md. These files are
// not exercised by any other automated harness (they're applied, if at all,
// via scripts/run_migrations.sh + the external golang-migrate CLI) — this
// test applies the raw SQL directly against a real SQLite database using the
// same mattn/go-sqlite3 driver already used elsewhere in the codebase
// (indirectly, via gorm.io/driver/sqlite), so no new test-only dependency is
// introduced.
//
// It covers backlog finding #203: three destructive down-migrations
// (002_rbac_enhancements, 004_add_auth_encryption, 005_secret_sharing) used
// to DROP security-relevant data with no export step. Each now copies the
// about-to-be-dropped data into a same-database backup table before the
// DROP. These tests prove (1) real data present before rollback survives in
// the backup location afterward, and (2) the down-migration still performs
// its original structural change (the original column/table is genuinely
// gone), so the fix doesn't silently turn the down-migration into a no-op.
package migrations

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	_ "github.com/mattn/go-sqlite3" // registers the sqlite3 driver with database/sql
)

// openTestDB opens a fresh, file-backed (not shared in-memory) SQLite
// database unique to this test, and applies 001_init.sql to establish the
// baseline schema every later migration builds on.
func openTestDB(t *testing.T) *sql.DB {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), "migrations-test.db")
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("open sqlite3 db: %v", err)
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
