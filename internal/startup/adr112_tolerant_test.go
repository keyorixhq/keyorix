package startup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// adr112FirstBootConfig writes a config whose key material and SQLite database do
// not exist yet: a fresh install the moment before its first boot generates them.
func adr112FirstBootConfig(t *testing.T) (configPath, dek, salt, dbPath string) {
	t.Helper()
	dir := t.TempDir()
	dek = filepath.Join(dir, "dek.key")
	salt = filepath.Join(dir, "kek.salt")
	dbPath = filepath.Join(dir, "keyorix.db")
	configPath = filepath.Join(dir, "keyorix.yaml")
	writeConfig(t, configPath, "storage:\n"+
		"  type: local\n"+
		"  database:\n"+
		"    path: "+dbPath+"\n"+
		"  encryption:\n"+
		"    enabled: true\n"+
		"    dek_path: "+dek+"\n"+
		"    salt_path: "+salt+"\n")
	if err := os.Chmod(configPath, 0o600); err != nil {
		t.Fatal(err)
	}
	return configPath, dek, salt, dbPath
}

// ADR-112 enforces the file-permission check on a fresh install from its first
// start, so the server's tolerant validation must not fail on the files the
// same boot is about to create (key material, the local database).
func TestValidateStartupTolerant_FirstBoot_SkipsNotYetCreatedFiles(t *testing.T) {
	configPath, _, _, _ := adr112FirstBootConfig(t)
	if _, err := ValidateStartupTolerant(configPath, false); err != nil {
		t.Fatalf("expected a fresh install's first boot to pass tolerant validation: %v", err)
	}
}

// The strict ValidateStartup (admin validate, an explicit
// enable_file_permission_check: true) keeps reporting the missing files.
func TestValidateStartup_Strict_FirstBoot_StillFails(t *testing.T) {
	configPath, _, _, _ := adr112FirstBootConfig(t)
	if _, err := ValidateStartup(configPath, false); err == nil {
		t.Fatal("expected strict validation to report missing key material")
	}
}

// Tolerance covers only "nothing generated yet": once a key file exists, the
// whole key set is audited, so a world-readable salt is still refused.
func TestValidateStartupTolerant_PresentKeyFile_StillAudited(t *testing.T) {
	configPath, dek, salt, _ := adr112FirstBootConfig(t)
	if err := os.WriteFile(salt, make([]byte, 32), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dek, make([]byte, 60), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateStartupTolerant(configPath, false); err == nil {
		t.Fatal("expected a world-readable KEK salt to fail tolerant validation")
	}
}

// The config file is an orchestrator-mounted input (Kubernetes ConfigMap: root-owned
// 0644; docker-compose bind mount: the host owner). On the implicit default a
// mismatch warns, naming the file, the mismatch and the fix (Andrei, 2026-10-10:
// "keys strict, mounts warn"); the strict audit stays for an explicit true.
func TestValidateStartupTolerant_WorldReadableConfig_WarnsWithFileMismatchAndFix(t *testing.T) {
	configPath, _, _, _ := adr112FirstBootConfig(t)
	if err := os.Chmod(configPath, 0o644); err != nil {
		t.Fatal(err)
	}
	result, err := ValidateStartupTolerant(configPath, false)
	if err != nil {
		t.Fatalf("expected a world-readable config file to warn on the implicit default, got %v", err)
	}
	var found string
	for _, w := range result.Warnings {
		if strings.Contains(w, configPath) {
			found = w
		}
	}
	for _, want := range []string{"config file", configPath, "mode 0644, expected 0600", "Fix: chmod 600", "defaultMode 0400"} {
		if !strings.Contains(found, want) {
			t.Errorf("warning missing %q: %q", want, found)
		}
	}
}

func TestValidateStartup_ExplicitTrue_WorldReadableConfig_StillFails(t *testing.T) {
	configPath, _, _, _ := adr112FirstBootConfig(t)
	f, err := os.OpenFile(configPath, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("security:\n  enable_file_permission_check: true\n"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(configPath, 0o644); err != nil {
		t.Fatal(err)
	}
	// Even through the tolerant entry point: the loaded config writes the key itself.
	if _, err := ValidateStartupTolerant(configPath, false); err == nil {
		t.Fatal("expected an explicit enable_file_permission_check: true to refuse a world-readable config file")
	}
}

// The database is the server's own file: a world-readable one stays a refusal on
// the implicit default.
func TestValidateStartupTolerant_WorldReadableDatabase_StillFails(t *testing.T) {
	configPath, _, _, dbPath := adr112FirstBootConfig(t)
	if err := os.WriteFile(dbPath, []byte("sqlite"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateStartupTolerant(configPath, false); err == nil {
		t.Fatal("expected a world-readable database file to fail tolerant validation")
	}
}
