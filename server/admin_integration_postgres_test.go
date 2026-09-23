package main

// admin_integration_postgres_test.go covers the same `keyorix-server admin`
// workflow as admin_integration_test.go's TestAdminWorkflow_SQLite, but
// against a real PostgreSQL backend -- gated on KEYORIX_TEST_PG_DSN, per
// this repo's standing convention (see e.g.
// internal/storage/postgres_pk_rebuild_helpers_test.go's pgTestDSN). Skips
// (not fails) when unset.

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var adminPGDBCounter int64

func adminPgTestDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("KEYORIX_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("KEYORIX_TEST_PG_DSN not set — skipping Postgres admin-command integration test")
	}
	return dsn
}

// adminPgIsolatedDatabaseDSN creates a fresh, empty database on the real
// Postgres server at base, dropped on test cleanup, and returns a DSN
// pointing at it -- mirrors internal/storage's own
// pgIsolatedDatabaseDSN, so each test's migration/audit-chain state is
// genuinely isolated rather than racing other tests sharing one database.
func adminPgIsolatedDatabaseDSN(t *testing.T, base string) string {
	t.Helper()
	n := atomic.AddInt64(&adminPGDBCounter, 1)
	dbName := fmt.Sprintf("admin_pr11_%d_%d", os.Getpid(), n)

	admin, err := gorm.Open(postgres.Open(base), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	require.NoError(t, err)
	adminSQL, err := admin.DB()
	require.NoError(t, err)
	t.Cleanup(func() { _ = adminSQL.Close() })

	require.NoError(t, admin.Exec(fmt.Sprintf("CREATE DATABASE %s", dbName)).Error)
	t.Cleanup(func() {
		// Terminate any lingering connections (the admin commands under test
		// each open and close their own) before dropping, or DROP DATABASE
		// fails with "database is being accessed by other users".
		_ = admin.Exec(fmt.Sprintf(
			"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '%s' AND pid <> pg_backend_pid()", dbName,
		)).Error
		_ = admin.Exec(fmt.Sprintf("DROP DATABASE IF EXISTS %s", dbName)).Error
	})

	return replaceAdminDBName(base, dbName)
}

// replaceAdminDBName swaps the dbname= field in a libpq-style "key=value ..."
// DSN -- identical to internal/storage/postgres_pk_rebuild_helpers_test.go's
// own replaceDBName; KEYORIX_TEST_PG_DSN is always this form, never a
// "postgres://" URL, so the two helpers can and should agree.
func replaceAdminDBName(dsn, newName string) string {
	fields := strings.Fields(dsn)
	out := make([]string, 0, len(fields)+1)
	found := false
	for _, f := range fields {
		if strings.HasPrefix(f, "dbname=") {
			out = append(out, "dbname="+newName)
			found = true
			continue
		}
		out = append(out, f)
	}
	if !found {
		out = append(out, "dbname="+newName)
	}
	return strings.Join(out, " ")
}

func TestAdminWorkflow_Postgres(t *testing.T) {
	base := adminPgTestDSN(t)
	dsn := adminPgIsolatedDatabaseDSN(t, base)

	bin := buildServerBinary(t)
	dir := t.TempDir()
	env := append(baseEnv(dir), "KEYORIX_MASTER_PASSWORD=test-passphrase-postgres")

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
	// `admin init` (which normally creates this) also unconditionally treats
	// storage.database.path as a local SQLite file to create -- a
	// pre-existing gap in the ported-near-verbatim CLI logic, out of scope
	// here since storage.type is postgres. Create the key directory directly
	// instead of routing through `admin init` for this Postgres config.
	if err := os.MkdirAll(filepath.Join(dir, "keys"), 0750); err != nil {
		t.Fatalf("create keys dir: %v", err)
	}

	// First diagnose derives the KEK (first-boot key derivation) against a
	// not-yet-migrated database -- migration state is expected to WARN here,
	// not pass; see TestAdminDiagnose_UnmigratedDatabase for that behavior
	// covered directly against SQLite.
	out, err := runAdmin(t, bin, dir, env, "diagnose", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("admin diagnose (first-boot key derivation) failed: %v\n%s", err, out)
	}
	for _, want := range []string{"[ OK ] config parse", "[ OK ] KEK/passphrase access", "[ OK ] database open"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected diagnose output to contain %q, got:\n%s", want, out)
		}
	}
	if !strings.Contains(out, "[WARN] migration state") {
		t.Errorf("expected diagnose to WARN on the not-yet-migrated database, got:\n%s", out)
	}

	out, err = runAdmin(t, bin, dir, env, "migrate", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("admin migrate failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "migrated successfully") {
		t.Errorf("expected migrate to report success, got:\n%s", out)
	}

	// Idempotency: re-running migrate against an already-migrated Postgres
	// database must still succeed (mirrors the SQLite workflow test).
	out, err = runAdmin(t, bin, dir, env, "migrate", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("second admin migrate (idempotency check) failed: %v\n%s", err, out)
	}

	// A fresh diagnose after migrate must now report every check passing.
	out, err = runAdmin(t, bin, dir, env, "diagnose", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("admin diagnose after migrate failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "[ OK ] migration state") {
		t.Errorf("expected diagnose to report migration state OK after `admin migrate`, got:\n%s", out)
	}
}

func TestAdminGuard_Postgres_RefusesWhileServerRunning(t *testing.T) {
	base := adminPgTestDSN(t)
	dsn := adminPgIsolatedDatabaseDSN(t, base)

	bin := buildServerBinary(t)
	dir := t.TempDir()
	env := append(baseEnv(dir), "KEYORIX_MASTER_PASSWORD=test-passphrase-pg-guard")

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
    port: "8081"
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
		t.Fatalf("admin diagnose (key derivation) failed: %v\n%s", err, out)
	}
	if out, err := runAdmin(t, bin, dir, env, "migrate", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin migrate failed: %v\n%s", err, out)
	}

	serverEnv := append(baseEnv(dir), "KEYORIX_MASTER_PASSWORD=test-passphrase-pg-guard", "KEYORIX_CONFIG_PATH=./keyorix.yaml")
	serverCmd := exec.Command(bin)
	serverCmd.Dir = dir
	serverCmd.Env = serverEnv
	logFile, err := os.Create(filepath.Join(dir, "server.log"))
	if err != nil {
		t.Fatalf("create server log: %v", err)
	}
	defer logFile.Close() //nolint:errcheck
	serverCmd.Stdout = logFile
	serverCmd.Stderr = logFile
	if err := serverCmd.Start(); err != nil {
		t.Fatalf("start server: %v", err)
	}
	t.Cleanup(func() {
		_ = serverCmd.Process.Kill()
		_, _ = serverCmd.Process.Wait()
	})

	cfg, err := adminConfigForProbe(filepath.Join(dir, "keyorix.yaml"))
	if err != nil {
		t.Fatalf("load config for probe: %v", err)
	}
	running := waitForPresence(t, cfg, 30)
	if !running {
		logBytes, _ := os.ReadFile(filepath.Join(dir, "server.log"))
		t.Fatalf("expected the server to acquire the presence lock within the deadline; server log:\n%s", logBytes)
	}

	out, err := runAdmin(t, bin, dir, env, "migrate", "--config", "./keyorix.yaml")
	if err == nil || !strings.Contains(out, "admin commands must not run concurrently") {
		logBytes, _ := os.ReadFile(filepath.Join(dir, "server.log"))
		t.Fatalf("expected admin migrate to refuse while the server is running, got (err=%v):\n%s\nserver log:\n%s", err, out, logBytes)
	}
}
