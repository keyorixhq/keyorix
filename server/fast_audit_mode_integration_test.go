package main

// fast_audit_mode_integration_test.go — ADR-112 Amendment 1 / FASTAUDIT-1
// (docs/specs/fast-audit-mode.md) driven the way an operator drives it: the
// real built binary, a real config file edit, a real boot, and the real
// `keyorix-server admin verify-audit` command.
//
// Reuses this package's existing harness (buildServerBinary/runAdmin/baseEnv
// from admin_integration_test.go, bootstrapAdminViaHTTP from
// admin_recover_admin_integration_test.go) and deliberately mirrors
// TestAdminRecoverAdmin_KeylessMode_SQLite's structure: this is the same
// category of setting (a config-file-only security opt-out that must be loud,
// audited, and surfaced), so it earns the same end-to-end treatment.
//
// What it covers that a unit test cannot: that the setting actually reaches
// the running server from a YAML file, that the warning really is printed to
// the server's own output on a real boot, that the audit event really lands in
// the real database through the real audit path, and that `verify-audit` — the
// customer-facing offline verification command, not VerifyAuditChain called
// directly — passes against a database written in fast mode.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

const fastAuditStartupEventType = "admin.audit_durable_sync_skipped_at_startup"

// enableFastAuditModeInConfig edits the generated config's storage.database
// block to set insecure_audit_skip_durable_sync: true. Editing the YAML file
// is the ONLY legitimate way to set this field — see
// internal/config/insecure_audit_skip_durable_sync_reachability_test.go for
// the guard that keeps it that way — so the test has to do it the same way an
// operator would, rather than reaching into a config struct.
func enableFastAuditModeInConfig(t *testing.T, cfgPath string) {
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
	for _, line := range lines {
		out = append(out, line)
		trimmed := strings.TrimSpace(line)
		if !injected && strings.HasPrefix(trimmed, "path:") && strings.HasPrefix(line, "    ") {
			indent := line[:len(line)-len(strings.TrimLeft(line, " "))]
			out = append(out, indent+"insecure_audit_skip_durable_sync: true")
			injected = true
		}
	}
	if !injected {
		t.Fatalf("failed to inject insecure_audit_skip_durable_sync into the generated config "+
			"(no storage.database.path anchor line found). Config was:\n%s", raw)
	}
	if err := os.WriteFile(cfgPath, []byte(strings.Join(out, "\n")), 0600); err != nil {
		t.Fatalf("write edited config: %v", err)
	}
}

func fastAuditStartupEventCount(t *testing.T, dbPath string) int {
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
	if err := db.Where("event_type = ?", fastAuditStartupEventType).Find(&events).Error; err != nil {
		t.Fatalf("query startup audit events: %v", err)
	}
	return len(events)
}

// TestFastAuditMode_LoudAuditedAndVerifiableEndToEnd is the on case: a real
// boot with the setting enabled must warn, audit, and still produce a database
// whose chain `verify-audit` accepts.
func TestFastAuditMode_LoudAuditedAndVerifiableEndToEnd(t *testing.T) {
	bin := buildServerBinary(t)
	dir := t.TempDir()
	env := append(baseEnv(dir), "KEYORIX_MASTER_PASSWORD=test-passphrase-fast-audit-mode")

	if out, err := runAdmin(t, bin, dir, env, "init", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin init failed: %v\n%s", err, out)
	}
	cfgPath := filepath.Join(dir, "keyorix.yaml")
	enableFastAuditModeInConfig(t, cfgPath)

	// `diagnose` is what creates the encryption key files (keys/kek.salt,
	// keys/dek.key); without it the server refuses to start on its own
	// file-permission startup validation. Same ordering
	// TestAdminRecoverAdmin_KeylessMode_SQLite uses.
	if out, err := runAdmin(t, bin, dir, env, "diagnose", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin diagnose failed: %v\n%s", err, out)
	}
	if out, err := runAdmin(t, bin, dir, env, "migrate", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin migrate failed: %v\n%s", err, out)
	}

	// A real boot, which is what produces the warning and the audit event.
	bootstrapAdminViaHTTP(t, bin, dir, env, "8080", "fastauditadmin", "fast-audit-e2e@example.com", "InitialPassw0rd!")

	// `admin validate` is the posture surface (ADR-112 Amendment 1): the
	// deviation has to be visible to an operator who runs it. Asserted on the
	// real command's real output, not on ValidateStartup's return value.
	//
	// Run AFTER the first boot on purpose: the encryption key files
	// (keys/kek.salt, keys/dek.key) are created on first server start, not by
	// `admin init`, so a pre-boot `validate` fails its own key-file
	// permission check for reasons that have nothing to do with this setting.
	validateOut, err := runAdmin(t, bin, dir, env, "validate", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("admin validate failed: %v\n%s", err, validateOut)
	}
	if !strings.Contains(validateOut, "insecure_audit_skip_durable_sync") {
		t.Errorf("`admin validate` did not report the fast audit mode as a posture deviation. "+
			"ADR-112 Amendment 1 requires it in the posture surface; an operator running this command has "+
			"to be told. Output was:\n%s", validateOut)
	}

	serverLog, err := os.ReadFile(filepath.Join(dir, "bootstrap-server.log")) //nolint:gosec // test-generated path
	if err != nil {
		t.Fatalf("read server log: %v", err)
	}
	logText := string(serverLog)
	if !strings.Contains(logText, "insecure_audit_skip_durable_sync is ENABLED") {
		t.Errorf("the server did not print the fast-audit-mode startup WARNING naming the setting. "+
			"ADR-112 §1 requires a warning at EVERY start. Server log was:\n%s", logText)
	}
	// The SQLite-specific scope caveat is the one way this setting is broader
	// than its name, and this is a SQLite deployment, so it must be in the
	// warning an operator actually sees -- not only in the docs.
	if !strings.Contains(logText, "DATABASE-WIDE, NOT AUDIT-ONLY") {
		t.Errorf("the startup warning on a SQLite backend must say the relaxation is database-wide, not "+
			"audit-only (PRAGMA synchronous is per-connection and the pool is shared). Server log was:\n%s", logText)
	}

	if n := fastAuditStartupEventCount(t, filepath.Join(dir, "keyorix.db")); n != 1 {
		t.Fatalf("expected exactly 1 %s audit event after one boot, got %d -- ADR-112 §1 requires the "+
			"tamper-evident chain itself to carry a record of the weaker mode, at every start",
			fastAuditStartupEventType, n)
	}

	// The requirement in the brief's own words: "verify-audit must pass".
	// Run the real command against the real database written in fast mode.
	verifyOut, err := runAdmin(t, bin, dir, env, "verify-audit", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("`admin verify-audit` failed against a database written with the fast audit mode on: %v\n%s\n"+
			"Lost tail entries are permitted in this mode; a chain verify-audit rejects is not.", err, verifyOut)
	}
	t.Logf("verify-audit output:\n%s", verifyOut)
}

// TestFastAuditMode_DefaultBootIsSilentAndDurable is the off case, and it is
// the half that stops the on case from passing for the wrong reason: a default
// install must print no such warning, write no such audit event, and report no
// such posture deviation. Without this, a change that emitted the warning
// unconditionally would leave the test above green while making every
// deployment look deviant.
func TestFastAuditMode_DefaultBootIsSilentAndDurable(t *testing.T) {
	bin := buildServerBinary(t)
	dir := t.TempDir()
	env := append(baseEnv(dir), "KEYORIX_MASTER_PASSWORD=test-passphrase-fast-audit-default")

	if out, err := runAdmin(t, bin, dir, env, "init", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin init failed: %v\n%s", err, out)
	}
	// Deliberately NO config edit: this is what `admin init` generates.
	// `diagnose` is what creates the encryption key files (keys/kek.salt,
	// keys/dek.key); without it the server refuses to start on its own
	// file-permission startup validation. Same ordering
	// TestAdminRecoverAdmin_KeylessMode_SQLite uses.
	if out, err := runAdmin(t, bin, dir, env, "diagnose", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin diagnose failed: %v\n%s", err, out)
	}
	if out, err := runAdmin(t, bin, dir, env, "migrate", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin migrate failed: %v\n%s", err, out)
	}

	bootstrapAdminViaHTTP(t, bin, dir, env, "8080", "defaultadmin", "fast-audit-default@example.com", "InitialPassw0rd!")

	// After the boot, for the same key-file reason as the on case above.
	validateOut, err := runAdmin(t, bin, dir, env, "validate", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("admin validate failed: %v\n%s", err, validateOut)
	}
	if strings.Contains(validateOut, "insecure_audit_skip_durable_sync") {
		t.Errorf("a DEFAULT install reported the fast audit mode as a posture deviation. ADR-112 §4's gate "+
			"is that the posture report shows zero deviations on the default configuration. Output:\n%s", validateOut)
	}

	serverLog, err := os.ReadFile(filepath.Join(dir, "bootstrap-server.log")) //nolint:gosec // test-generated path
	if err != nil {
		t.Fatalf("read server log: %v", err)
	}
	if strings.Contains(string(serverLog), "insecure_audit_skip_durable_sync is ENABLED") {
		t.Errorf("a default boot printed the fast-audit-mode warning. The default must be durable AND "+
			"silent about a setting nobody enabled. Server log was:\n%s", serverLog)
	}

	if n := fastAuditStartupEventCount(t, filepath.Join(dir, "keyorix.db")); n != 0 {
		t.Fatalf("a default boot wrote %d %s audit event(s); expected 0", n, fastAuditStartupEventType)
	}
}
