// adr112_secure_defaults_test.go -- ADR-112 (secure-by-default baseline, item 1):
// security.enable_file_permission_check and security.require_mfa now default to
// the secure state (config.Load resolves an absent key to true). An existing
// deployment that relied on the pre-ADR-112 implicit-false default gets a grace
// period instead of an instant behavior change on upgrade -- these tests cover
// that grace-period logic in enforceKeyFilePermissions, runStartupValidation,
// and logWarnOnImplicitRequireMFADefault.
package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
)

// ── enforceKeyFilePermissions: ImplicitDefault grace period ──────────────────

// A deployment that never explicitly set enable_file_permission_check (it is
// failing closed only because of the ADR-112 secure default) must WARN, not
// refuse to start, on a pre-existing world-readable key file -- the exact
// scenario an unattended upgrade must not turn into an outage.
func TestEnforceKeyFilePermissions_ImplicitDefault_WarnsInsteadOfFailingClosed(t *testing.T) {
	dir := t.TempDir()
	dek := filepath.Join(dir, "dek.json")
	if err := os.WriteFile(dek, []byte("{}"), 0o644); err != nil { // world-readable
		t.Fatalf("write dek: %v", err)
	}

	cfg := &config.Config{
		Storage: config.StorageConfig{
			Encryption: config.EncryptionConfig{Enabled: true, DEKPath: dek},
		},
		Security: config.SecurityConfig{
			EnableFilePermissionCheck:                true,
			EnableFilePermissionCheckImplicitDefault: true, // as config.Load sets it for an absent key
		},
	}

	logged := captureLogs(func() {
		if err := enforceKeyFilePermissions(cfg); err != nil {
			t.Errorf("expected the ADR-112 grace period to warn, not fail closed: %v", err)
		}
	})
	if !strings.Contains(logged, "ADR-112") {
		t.Errorf("expected a grace-period warning naming ADR-112, got: %q", logged)
	}
}

// RED proof for the test above: a deployment that explicitly set
// enable_file_permission_check (today's existing opt-in behavior,
// ImplicitDefault=false) must keep failing closed exactly as before --
// confirming the grace period never masks a deliberate, explicit choice. This
// is also TestEnforceKeyFilePermissions_InsecureFile_FailClosed's exact
// scenario (hand-built Config{EnableFilePermissionCheck: true}, which leaves
// ImplicitDefault at Go's false zero value) passing unmodified.
func TestEnforceKeyFilePermissions_ExplicitTrue_StillFailsClosed(t *testing.T) {
	dir := t.TempDir()
	dek := filepath.Join(dir, "dek.json")
	if err := os.WriteFile(dek, []byte("{}"), 0o644); err != nil {
		t.Fatalf("write dek: %v", err)
	}

	cfg := &config.Config{
		Storage: config.StorageConfig{
			Encryption: config.EncryptionConfig{Enabled: true, DEKPath: dek},
		},
		Security: config.SecurityConfig{
			EnableFilePermissionCheck: true,
			// EnableFilePermissionCheckImplicitDefault left at its zero value (false):
			// this is what every hand-built Config{EnableFilePermissionCheck: true}
			// looks like, so the grace period must never trigger for it.
		},
	}

	if err := enforceKeyFilePermissions(cfg); err == nil {
		t.Error("expected an explicit enable_file_permission_check=true to still fail closed")
	}
}

// ── runStartupValidation: ImplicitDefault grace period ────────────────────────

// writeADR112StartupConfig writes a config file through config.Load so the
// real explicit/implicit tracking machinery is exercised, with a world-
// readable DEK -- a real, reportable startup-validation problem -- and
// returns the loaded *config.Config. explicitCheck controls whether
// enable_file_permission_check is written into the YAML at all.
func writeADR112StartupConfig(t *testing.T, explicitCheck bool) *config.Config {
	t.Helper()
	dir := t.TempDir()
	dek := filepath.Join(dir, "dek.key")
	salt := filepath.Join(dir, "kek.salt")
	dbPath := filepath.Join(dir, "keyorix.db")
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.WriteFile(dek, make([]byte, 60), 0o644))  // world-readable wrapped DEK
	must(os.WriteFile(salt, make([]byte, 32), 0o600)) // clean salt
	must(os.WriteFile(dbPath, []byte("sqlite"), 0o600))

	securityBlock := ""
	if explicitCheck {
		securityBlock = "security:\n  enable_file_permission_check: true\n"
	}
	configPath := filepath.Join(dir, "keyorix.yaml")
	content := "storage:\n" +
		"  type: local\n" +
		"  database:\n" +
		"    path: " + dbPath + "\n" +
		"  encryption:\n" +
		"    enabled: true\n" +
		"    dek_path: " + dek + "\n" +
		"    salt_path: " + salt + "\n" +
		securityBlock
	must(os.WriteFile(configPath, []byte(content), 0600))

	t.Setenv("KEYORIX_CONFIG_PATH", configPath)
	cfg, err := config.Load(configPath)
	must(err)
	return cfg
}

// A config file that never set enable_file_permission_check (ADR-112 implicit
// secure default) must continue booting, with a warning, when
// ValidateStartup finds a real problem -- the upgrade-safety half of ADR-112's
// grace period.
func TestRunStartupValidation_ImplicitDefault_WarnsInsteadOfFailingClosed(t *testing.T) {
	cfg := writeADR112StartupConfig(t, false)
	if !cfg.Security.EnableFilePermissionCheckImplicitDefault {
		t.Fatal("test premise broken: expected an absent key to resolve as an implicit default")
	}

	logged := captureLogs(func() {
		if err := runStartupValidation(cfg); err != nil {
			t.Errorf("expected the ADR-112 grace period to warn, not refuse to start: %v", err)
		}
	})
	if !strings.Contains(logged, "ADR-112") {
		t.Errorf("expected a grace-period warning naming ADR-112, got: %q", logged)
	}
}

// RED proof: the same real problem, with enable_file_permission_check set
// explicitly (today's existing opt-in behavior), must still refuse to start --
// confirming the grace period never masks a deliberate, explicit choice.
func TestRunStartupValidation_ExplicitTrue_StillFailsClosed(t *testing.T) {
	cfg := writeADR112StartupConfig(t, true)
	if cfg.Security.EnableFilePermissionCheckImplicitDefault {
		t.Fatal("test premise broken: expected an explicitly-set key to NOT resolve as an implicit default")
	}

	if err := runStartupValidation(cfg); err == nil {
		t.Error("expected an explicit enable_file_permission_check=true to still refuse to start")
	}
}

// ── logWarnOnImplicitRequireMFADefault ────────────────────────────────────────

func TestLogWarnOnImplicitRequireMFADefault_WarnsOnlyForTheImplicitDefault(t *testing.T) {
	cases := []struct {
		name            string
		requireMFA      bool
		implicitDefault bool
		wantWarning     bool
	}{
		{"off entirely", false, false, false},
		{"off entirely even if implicit flag set", false, true, false},
		{"explicitly on", true, false, false},
		{"on via the ADR-112 implicit default", true, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{Security: config.SecurityConfig{
				RequireMFA:                tc.requireMFA,
				RequireMFAImplicitDefault: tc.implicitDefault,
			}}
			logged := captureLogs(func() { logWarnOnImplicitRequireMFADefault(cfg) })
			gotWarning := strings.Contains(logged, "require_mfa")
			if gotWarning != tc.wantWarning {
				t.Errorf("wantWarning=%v, logged=%q", tc.wantWarning, logged)
			}
		})
	}
}
