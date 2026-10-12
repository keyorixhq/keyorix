package main

// fast_audit_mode_postgres_e2e_test.go — the in-effect path, end to end
// against the real built binary on a real PostgreSQL cluster.
//
// Coordinator review of #2828 asked for this "optional if cheap". It is the
// only test that drives the three operator-visible surfaces of the IN EFFECT
// state together, on one real boot: the start-up WARNING, the posture report,
// and the start-up audit event landing in the real hash chain. Everything else
// covering the in-effect path does so a layer down (the SET LOCAL mechanism in
// internal/storage/store, the posture computation in internal/startup), where
// the surfaces cannot disagree with each other because they are not all
// present.
//
// Why its sibling file covers only the SQLite refusal: this package's harness
// generates a SQLite config via `admin init`, and the mode is PostgreSQL-only,
// so the in-effect boot needs a config this test writes by hand plus a real
// cluster. DSN-gated, so it skips cleanly wherever KEYORIX_TEST_PG_DSN is
// absent — same convention as internal/storage/store's pg-gated tests, and the
// `core` CI leg is what actually runs it.

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/testutil/pgdsn"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// writePostgresFastAuditConfig writes a server config pointed at schema on the
// pg-gated cluster, with the fast audit mode set. Its own schema, created and
// dropped around the test, so a full AutoMigrate cannot collide with another
// test's tables in the same database.
func writePostgresFastAuditConfig(t *testing.T, dir, baseDSN, schema string) string {
	t.Helper()

	admin, err := gorm.Open(postgres.Open(baseDSN), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatalf("open pg admin connection: %v", err)
	}
	if err := admin.Exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE").Error; err != nil {
		t.Fatalf("drop schema: %v", err)
	}
	if err := admin.Exec("CREATE SCHEMA " + schema).Error; err != nil {
		t.Fatalf("create schema: %v", err)
	}
	t.Cleanup(func() {
		_ = admin.Exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE").Error
		if sqlDB, derr := admin.DB(); derr == nil {
			_ = sqlDB.Close()
		}
	})

	cfg := fmt.Sprintf(`environment: production

server:
  http:
    enabled: true
    port: "8099"
  grpc:
    enabled: false

storage:
  type: postgres
  database:
    dsn: %q
    insecure_audit_skip_durable_sync: true
  encryption:
    enabled: true
    dek_path: "keys/dek.key"
    salt_path: "keys/kek.salt"

security:
  enable_file_permission_check: false
  require_transport_tls: false
`, pgdsn.PGSearchPathDSN(baseDSN, schema))

	// `admin init` would create this for the SQLite flow; this config is
	// hand-written, so the key directory has to be made here or the encryption
	// provider cannot take its DEK lock.
	if err := os.MkdirAll(filepath.Join(dir, "keys"), 0o700); err != nil {
		t.Fatalf("create keys dir: %v", err)
	}

	path := filepath.Join(dir, "keyorix.yaml")
	if err := os.WriteFile(path, []byte(cfg), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

// TestFastAuditMode_PostgresInEffectEndToEnd boots the real binary on a real
// PostgreSQL cluster with the mode on and asserts all three operator-visible
// surfaces agree that it is IN EFFECT.
func TestFastAuditMode_PostgresInEffectEndToEnd(t *testing.T) {
	baseDSN := os.Getenv("KEYORIX_TEST_PG_DSN")
	if baseDSN == "" {
		t.Skip("KEYORIX_TEST_PG_DSN not set -- the in-effect path is PostgreSQL-only and needs a real cluster")
	}

	bin := buildServerBinary(t)
	dir := t.TempDir()
	env := append(baseEnv(dir),
		"KEYORIX_MASTER_PASSWORD=test-passphrase-fast-audit-pg-e2e",
		"KEYORIX_CONFIG_PATH=./keyorix.yaml",
	)
	writePostgresFastAuditConfig(t, dir, baseDSN, "fastaudit_pg_e2e")

	// `diagnose` creates the encryption key files and validates the config, so
	// it doubles as the proof that Postgres + the setting is ACCEPTED -- the
	// exact combination its SQLite sibling refuses.
	diagOut, err := runAdmin(t, bin, dir, env, "diagnose", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("admin diagnose failed on a POSTGRES config with the fast audit mode set -- this is the one "+
			"supported backend and must be accepted: %v\n%s", err, diagOut)
	}
	if out, merr := runAdmin(t, bin, dir, env, "migrate", "--config", "./keyorix.yaml"); merr != nil {
		t.Fatalf("admin migrate failed: %v\n%s", merr, out)
	}

	// Surface 1: the start-up WARNING, from a real boot. The server is expected
	// to come up and keep running, so it is started and then killed -- unlike
	// the SQLite case, where exiting IS the expected behaviour.
	serverLog := runServerExpectingItToStayUp(t, bin, dir, env, "8099")
	if !strings.Contains(serverLog, "insecure_audit_skip_durable_sync is ENABLED") {
		t.Errorf("the server did not print the IN EFFECT start-up warning. ADR-112 §1 requires a warning at "+
			"EVERY start. Server log:\n%s", serverLog)
	}
	// Match the ignored wording's OWN distinctive phrase, not the bare word
	// "IGNORED": an unrelated trusted_proxies warning in this same log says
	// "X-Forwarded-For/X-Real-IP are being IGNORED", which made the first
	// version of this assertion fire on a correct boot.
	if strings.Contains(serverLog, "is set but IGNORED") {
		t.Errorf("the server printed the IGNORED wording on a backend where the mode IS in effect -- the two "+
			"wordings have been crossed, which would tell an operator their durability is intact when it is "+
			"not. Server log:\n%s", serverLog)
	}
	if strings.Contains(serverLog, "Audit durability is UNCHANGED") {
		t.Errorf("the server claimed audit durability is UNCHANGED on a backend where the mode IS in effect. "+
			"Server log:\n%s", serverLog)
	}

	// Surface 2: the posture report, via the real `admin validate`.
	validateOut, err := runAdmin(t, bin, dir, env, "validate", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("admin validate failed: %v\n%s", err, validateOut)
	}
	if !strings.Contains(validateOut, "Durable audit sync is DISABLED") {
		t.Errorf("`admin validate` did not report the fast audit mode as a posture deviation on a backend "+
			"where it is in effect. Output:\n%s", validateOut)
	}

	// Surface 3: the start-up audit event, read straight off Postgres rather
	// than through any Keyorix API.
	db, err := gorm.Open(postgres.Open(pgdsn.PGSearchPathDSN(baseDSN, "fastaudit_pg_e2e")),
		&gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatalf("open db for verification: %v", err)
	}
	defer func() {
		if sqlDB, derr := db.DB(); derr == nil {
			_ = sqlDB.Close()
		}
	}()
	var events []models.AuditEvent
	if err := db.Where("event_type = ?", fastAuditStartupEventType).Find(&events).Error; err != nil {
		t.Fatalf("query startup audit events: %v", err)
	}
	if len(events) == 0 {
		t.Fatalf("no %s audit event after a real boot with the mode in effect. ADR-112 §1 requires the "+
			"tamper-evident chain itself to carry a record of the weakened window.", fastAuditStartupEventType)
	}
	for _, e := range events {
		if e.ActorType != "system" {
			t.Errorf("the startup event's ActorType is %q, want \"system\": it is an unattended boot-time "+
				"event with no human or machine actor", e.ActorType)
		}
		if e.UserID != nil {
			t.Errorf("the startup event carries a UserID (%v); it must not -- there is no acting identity at "+
				"boot", *e.UserID)
		}
	}

	// And the chain this weakened mode wrote still verifies.
	verifyOut, err := runAdmin(t, bin, dir, env, "verify-audit", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("`admin verify-audit` failed against a Postgres database written with the fast audit mode "+
			"in effect: %v\n%s", err, verifyOut)
	}
	if !strings.Contains(verifyOut, "VALID") {
		t.Errorf("expected a VALID verdict from verify-audit, got:\n%s", verifyOut)
	}
	t.Logf("verify-audit:\n%s", verifyOut)
}

// runServerExpectingItToStayUp starts the built binary as a real server,
// waits for it to accept connections, then kills it and returns its log.
//
// The mirror image of runServerExpectingExit in the sibling file, and the
// distinction matters: on the supported backend the server must COME UP, so a
// process that dies here is the failure. Asserting "it stayed up" is what
// stops this test from passing on a boot that crashed immediately after
// printing the warning.
func runServerExpectingItToStayUp(t *testing.T, bin, dir string, env []string, port string) string {
	t.Helper()
	logPath := filepath.Join(dir, "pg-e2e-server.log")
	logFile, err := os.Create(logPath) //nolint:gosec // test-generated path under t.TempDir()
	if err != nil {
		t.Fatalf("create server log: %v", err)
	}
	defer func() { _ = logFile.Close() }()

	cmd := exec.Command(bin) //nolint:gosec // bin is this suite's own freshly built binary
	cmd.Dir = dir
	cmd.Env = env
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		t.Fatalf("start server: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()

	base := "http://localhost:" + port
	deadline := time.Now().Add(30 * time.Second)
	up := false
	for time.Now().Before(deadline) {
		resp, gerr := http.Get(base + "/health") //nolint:noctx // test-local liveness poll
		if gerr == nil {
			_ = resp.Body.Close()
			up = true
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	raw, _ := os.ReadFile(logPath) //nolint:gosec // test-generated path
	if !up {
		t.Fatalf("the server never became reachable on port %s. On PostgreSQL the fast audit mode is "+
			"SUPPORTED, so the server must come up -- a refusal here would mean the SQLite guard is "+
			"rejecting Postgres too. Server log:\n%s", port, raw)
	}
	return string(raw)
}
