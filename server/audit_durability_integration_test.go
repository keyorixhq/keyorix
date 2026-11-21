package main

// audit_durability_integration_test.go — ADR-112 Amendment 3
// (storage.database.audit_durability, docs/specs/fast-audit-mode.md) driven
// the way an operator drives it: the real built binary, a real config file
// edit, real `admin` commands.
//
// This harness's `admin init` generates a SQLite config, so what it exercises
// end-to-end is the SQLite side: standard (by name or through the deprecated
// alias) boots with SQLite's meaning (Amendment 7), and a default install runs
// strict and says so in one INFO line. The PostgreSQL side (standard by default) is
// audit_durability_postgres_e2e_test.go, pg-gated.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// legacyFastAuditStartupEventType is Amendment 1's per-start event, removed by
// Amendment 3 (the settings diff replaces it). Tests assert it is never written.
const legacyFastAuditStartupEventType = "admin.audit_durable_sync_skipped_at_startup"

// addDatabaseLineToConfig edits the generated config's storage.database block
// to add line. Editing the YAML file is the ONLY way to set audit durability
// (internal/config/audit_durability_reachability_test.go keeps it that way),
// so the test does it the way an operator would.
func addDatabaseLineToConfig(t *testing.T, cfgPath, line string) {
	t.Helper()
	raw, err := os.ReadFile(cfgPath) //nolint:gosec // test-generated path under t.TempDir()
	if err != nil {
		t.Fatalf("read generated config: %v", err)
	}
	// `admin init` writes storage.database.path; anchor on it so the new key
	// lands inside the same mapping rather than guessing at indentation.
	lines := strings.Split(string(raw), "\n")
	var out []string
	injected := false
	for _, l := range lines {
		out = append(out, l)
		trimmed := strings.TrimSpace(l)
		if !injected && strings.HasPrefix(trimmed, "path:") && strings.HasPrefix(l, "    ") {
			indent := l[:len(l)-len(strings.TrimLeft(l, " "))]
			out = append(out, indent+line)
			injected = true
		}
	}
	if !injected {
		t.Fatalf("failed to inject %q into the generated config (no storage.database.path anchor line found). "+
			"Config was:\n%s", line, raw)
	}
	if err := os.WriteFile(cfgPath, []byte(strings.Join(out, "\n")), 0600); err != nil {
		t.Fatalf("write edited config: %v", err)
	}
}

func legacyFastAuditStartupEventCount(t *testing.T, dbPath string) int {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatalf("open db for verification: %v", err)
	}
	defer func() {
		if sqlDB, derr := db.DB(); derr == nil {
			_ = sqlDB.Close()
		}
	}()
	var events []models.AuditEvent
	if err := db.Where("event_type = ?", legacyFastAuditStartupEventType).Find(&events).Error; err != nil {
		t.Fatalf("query startup audit events: %v", err)
	}
	return len(events)
}

// TestAuditDurability_SQLiteStandardBootsEndToEnd: since ADR-112 Amendment 7
// SQLite accepts standard (read audits on a dedicated synchronous=NORMAL
// connection). By name or through the deprecated alias, the real binary boots,
// says which level is in effect with SQLite's meaning (never PostgreSQL's
// ~600 ms), logs that the read-audit connection is open, admin validate
// reports it, and the chain verifies. Until Amendment 7 this config refused
// to start.
func TestAuditDurability_SQLiteStandardBootsEndToEnd(t *testing.T) {
	bin := buildServerBinary(t)
	for i, line := range []string{"audit_durability: standard", "insecure_audit_skip_durable_sync: true"} {
		t.Run(line, func(t *testing.T) {
			dir := t.TempDir()
			env := append(baseEnv(dir), "KEYORIX_MASTER_PASSWORD=test-passphrase-audit-durability-sqlite-standard")

			if out, err := runAdmin(t, bin, dir, env, "init", "--dev", "--config", "./keyorix.yaml"); err != nil {
				t.Fatalf("admin init failed: %v\n%s", err, out)
			}
			addDatabaseLineToConfig(t, filepath.Join(dir, "keyorix.yaml"), line)
			adminEncryptionInit(t, bin, dir, env)
			if out, err := runAdmin(t, bin, dir, env, "migrate", "--config", "./keyorix.yaml"); err != nil {
				t.Fatalf("admin migrate failed: %v\n%s", err, out)
			}

			bootstrapAdminViaHTTP(t, bin, dir, env, pinFreeHTTPPort(t, dir),
				"sqlitestd", fmt.Sprintf("sqlite-standard-%d@example.com", i), "InitialPassw0rd!")

			serverLog, err := os.ReadFile(filepath.Join(dir, "bootstrap-server.log")) //nolint:gosec // test-generated path
			if err != nil {
				t.Fatalf("read server log: %v", err)
			}
			for _, want := range []string{
				"INFO: audit durability: standard (committed before every disclosure; secret mutations and their audit rows are synced to disk",
				"successful secret-read audits commit on a dedicated synchronous=NORMAL connection; every other transaction stays synchronous=FULL",
			} {
				if !strings.Contains(string(serverLog), want) {
					t.Errorf("a SQLite boot at standard must log %q. Server log was:\n%s", want, serverLog)
				}
			}
			if strings.Contains(string(serverLog), "600 ms") {
				t.Errorf("the SQLite standard line must not claim PostgreSQL's ~600 ms bound. Server log was:\n%s", serverLog)
			}

			validateOut, err := runAdmin(t, bin, dir, env, "validate", "--config", "./keyorix.yaml")
			if err != nil {
				t.Fatalf("admin validate failed: %v\n%s", err, validateOut)
			}
			if !strings.Contains(validateOut, "Audit durability: standard (committed before every disclosure; secret mutations") {
				t.Errorf("`admin validate` must report the effective SQLite level. Output:\n%s", validateOut)
			}

			verifyOut, err := runAdmin(t, bin, dir, env, "verify-audit", "--config", "./keyorix.yaml")
			if err != nil {
				t.Fatalf("`admin verify-audit` failed: %v\n%s", err, verifyOut)
			}
			if !strings.Contains(verifyOut, "VALID") {
				t.Errorf("expected a VALID verdict from verify-audit, got:\n%s", verifyOut)
			}
		})
	}
}

// TestAuditDurability_SQLiteDefaultBootIsStrict: a default SQLite install runs
// strict and says so in one INFO line; admin validate reports the level and no
// deviation; no per-start event is written; the chain verifies.
func TestAuditDurability_SQLiteDefaultBootIsStrict(t *testing.T) {
	bin := buildServerBinary(t)
	dir := t.TempDir()
	env := append(baseEnv(dir), "KEYORIX_MASTER_PASSWORD=test-passphrase-audit-durability-default")

	if out, err := runAdmin(t, bin, dir, env, "init", "--dev", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin init failed: %v\n%s", err, out)
	}
	adminEncryptionInit(t, bin, dir, env)
	// Deliberately NO config edit: this is what `admin init` generates.
	if out, err := runAdmin(t, bin, dir, env, "diagnose", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin diagnose failed: %v\n%s", err, out)
	}
	if out, err := runAdmin(t, bin, dir, env, "migrate", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin migrate failed: %v\n%s", err, out)
	}

	bootstrapAdminViaHTTP(t, bin, dir, env, pinFreeHTTPPort(t, dir), "defaultadmin", "fast-audit-default@example.com", "InitialPassw0rd!")

	// After the boot: the encryption key files are created on first server
	// start, not by `admin init`, so a pre-boot `validate` fails its own
	// key-file permission check for reasons unrelated to this setting.
	validateOut, err := runAdmin(t, bin, dir, env, "validate", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("admin validate failed: %v\n%s", err, validateOut)
	}
	if !strings.Contains(validateOut, "Audit durability: strict (committed and synced to disk") {
		t.Errorf("`admin validate` must report the effective audit durability level. Output:\n%s", validateOut)
	}
	if strings.Contains(validateOut, "insecure_audit_skip_durable_sync") {
		t.Errorf("a DEFAULT install mentioned the deprecated key in its validate output. Output:\n%s", validateOut)
	}

	serverLog, err := os.ReadFile(filepath.Join(dir, "bootstrap-server.log")) //nolint:gosec // test-generated path
	if err != nil {
		t.Fatalf("read server log: %v", err)
	}
	if !strings.Contains(string(serverLog), "INFO: audit durability: strict (committed and synced to disk before every disclosure") {
		t.Errorf("a SQLite boot must log the INFO line for strict. Server log was:\n%s", serverLog)
	}
	if strings.Contains(string(serverLog), "insecure_audit_skip_durable_sync") {
		t.Errorf("a default boot mentioned the deprecated insecure_audit_skip_durable_sync key. Server log was:\n%s", serverLog)
	}

	if n := legacyFastAuditStartupEventCount(t, filepath.Join(dir, "keyorix.db")); n != 0 {
		t.Fatalf("a default boot wrote %d %s audit event(s); expected 0", n, legacyFastAuditStartupEventType)
	}

	// The default install's chain must still verify — the baseline this whole
	// setting chooses between.
	verifyOut, err := runAdmin(t, bin, dir, env, "verify-audit", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("`admin verify-audit` failed on a default install: %v\n%s", err, verifyOut)
	}
	if !strings.Contains(verifyOut, "VALID") {
		t.Errorf("expected a VALID verdict from verify-audit on a default install, got:\n%s", verifyOut)
	}
}
