package main

// admin_verify_audit_postgres_test.go is the Postgres-gated counterpart to
// admin_verify_audit_integration_test.go — same `verify-audit --pg-dsn`
// subprocess pattern, against a real Postgres database instead of SQLite.
// Gated on KEYORIX_TEST_PG_DSN (skips, not fails, when unset), reusing
// adminPgTestDSN/adminPgIsolatedDatabaseDSN from
// admin_integration_postgres_test.go for per-test database isolation.

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/auditverify"
)

// setupVerifyAuditPostgresDB writes a postgres-backed config, derives the
// KEK, and migrates the schema — mirroring
// admin_integration_postgres_test.go's TestAdminWorkflow_Postgres setup
// (storage.database.path is treated as a local SQLite file to create even
// under storage.type: postgres, a pre-existing gap out of scope here — skip
// `admin init` for the same reason that test does).
func setupVerifyAuditPostgresDB(t *testing.T, bin, dsn string) (dir string, env []string) {
	t.Helper()
	dir = t.TempDir()
	env = append(baseEnv(dir), "KEYORIX_MASTER_PASSWORD=test-passphrase-verify-audit-pg")

	configContent := fmt.Sprintf(`storage:
  type: postgres
  database:
    dsn: %q
  encryption:
    enabled: true
    dek_path: keys/dek.key
    salt_path: keys/kek.salt
server:
  http:
    enabled: true
    port: "8080"
  grpc:
    enabled: false
`, dsn)
	if err := os.WriteFile(filepath.Join(dir, "keyorix.yaml"), []byte(configContent), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "keys"), 0750); err != nil {
		t.Fatalf("create keys dir: %v", err)
	}

	if out, err := runAdmin(t, bin, dir, env, "diagnose", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin diagnose (KEK derivation) failed: %v\n%s", err, out)
	}
	if out, err := runAdmin(t, bin, dir, env, "migrate", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin migrate failed: %v\n%s", err, out)
	}
	return dir, env
}

// seedAuditChainPG mirrors seedAuditChain but over a Postgres connection
// (driver "pgx", already registered process-wide via this file's import of
// internal/auditverify, which blank-imports jackc/pgx/v5/stdlib).
func seedAuditChainPG(t *testing.T, dsn string, n int) (chainedEvents int64, headID uint64, headHash string) {
	t.Helper()
	sqlDB, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	defer func() { _ = sqlDB.Close() }()

	var existingCount int64
	if err := sqlDB.QueryRow("SELECT COUNT(*) FROM audit_events").Scan(&existingCount); err != nil {
		t.Fatalf("count existing audit_events: %v", err)
	}
	prevHash := auditverify.GenesisHash
	if existingCount > 0 {
		if err := sqlDB.QueryRow("SELECT entry_hash FROM audit_events ORDER BY id DESC LIMIT 1").Scan(&prevHash); err != nil {
			t.Fatalf("read existing chain head: %v", err)
		}
	}

	tr := true
	base := time.Now().UTC().Truncate(time.Second)
	for i := 1; i <= n; i++ {
		row := &auditverify.AuditEventRow{
			EventType:   "secret.read",
			IPAddress:   "10.0.0.1",
			Description: fmt.Sprintf("seeded event %d", i),
			Success:     &tr,
			EventTime:   base.Add(time.Duration(i) * time.Second),
			ActorType:   "user",
		}
		entryHash := auditverify.ComputeEntryHash(row, prevHash)
		var id uint64
		err := sqlDB.QueryRow(`INSERT INTO audit_events
			(event_type, ip_address, description, success, event_time, diff, impersonation, actor_type, prev_hash, entry_hash)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING id`,
			row.EventType, row.IPAddress, row.Description, tr, row.EventTime, "", false, row.ActorType, prevHash, entryHash,
		).Scan(&id)
		if err != nil {
			t.Fatalf("insert audit_events row %d: %v", i, err)
		}
		headID, headHash = id, entryHash
		prevHash = entryHash
	}
	return existingCount + int64(n), headID, headHash
}

func TestVerifyAudit_Postgres_ValidChain_ExitZero(t *testing.T) {
	base := adminPgTestDSN(t)
	dsn := adminPgIsolatedDatabaseDSN(t, base)

	bin := buildServerBinary(t)
	dir, env := setupVerifyAuditPostgresDB(t, bin, dsn)
	wantChained, _, _ := seedAuditChainPG(t, dsn, 10)

	out, code := verifyAuditExitCode(t, bin, dir, env, "--pg-dsn", dsn)
	if code != 0 {
		t.Fatalf("expected exit 0 for a clean chain, got %d:\n%s", code, out)
	}
	wantLine := fmt.Sprintf("chained events:   %d", wantChained)
	if !strings.Contains(out, wantLine) {
		t.Errorf("expected report to contain %q, got:\n%s", wantLine, out)
	}
}

func TestVerifyAudit_Postgres_TamperedRow_ExitOne(t *testing.T) {
	base := adminPgTestDSN(t)
	dsn := adminPgIsolatedDatabaseDSN(t, base)

	bin := buildServerBinary(t)
	dir, env := setupVerifyAuditPostgresDB(t, bin, dsn)
	_, headID, _ := seedAuditChainPG(t, dsn, 5)

	sqlDB, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	if _, err := sqlDB.Exec("UPDATE audit_events SET description = 'tampered' WHERE id = $1", headID); err != nil {
		t.Fatalf("tamper row: %v", err)
	}
	_ = sqlDB.Close()

	out, code := verifyAuditExitCode(t, bin, dir, env, "--pg-dsn", dsn)
	if code != 1 {
		t.Fatalf("expected exit 1 for a tampered chain, got %d:\n%s", code, out)
	}
	if !strings.Contains(out, "BROKEN") {
		t.Errorf("expected report to say BROKEN, got:\n%s", out)
	}
}
