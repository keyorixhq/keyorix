package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
)

// writeStartupTestConfig writes a self-consistent local-storage + encryption config
// (a config file, a wrapped DEK, a KEK salt, and a SQLite DB file) to dir and returns
// its path. The permission modes of each file, and whether the permission check is
// turned on, are parameterized so callers can exercise both the "clean" and
// "world-readable key material" cases end to end (config file on disk -> config.Load
// -> runStartupValidation), exactly as server/main.go's real startup sequence does.
func writeStartupTestConfig(t *testing.T, dir string, enableCheck bool, dekMode, saltMode, dbMode os.FileMode) string {
	t.Helper()

	dek := filepath.Join(dir, "dek.key")
	salt := filepath.Join(dir, "kek.salt")
	dbPath := filepath.Join(dir, "keyorix.db")

	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.WriteFile(dek, make([]byte, 60), dekMode))    // wrapped DEK: 12+32+16 bytes
	must(os.WriteFile(salt, make([]byte, 32), saltMode))  // KEK salt: 32 bytes
	must(os.WriteFile(dbPath, []byte("sqlite"), dbMode))

	configPath := filepath.Join(dir, "keyorix.yaml")
	yamlContent := fmt.Sprintf(`
storage:
  type: local
  database:
    path: %q
  encryption:
    enabled: true
    dek_path: %q
    salt_path: %q
security:
  enable_file_permission_check: %v
  allow_unsafe_file_permissions: false
`, dbPath, dek, salt, enableCheck)
	must(os.WriteFile(configPath, []byte(yamlContent), 0600))
	return configPath
}

// loadStartupTestConfig points KEYORIX_CONFIG_PATH at configPath (mirroring how
// config.LoadConfig/config.ResolvedPath resolve the default path in server/main.go)
// and loads it, so runStartupValidation's internal re-load via
// startup.ValidateStartup sees the exact same file.
func loadStartupTestConfig(t *testing.T, configPath string) *config.Config {
	t.Helper()
	t.Setenv("KEYORIX_CONFIG_PATH", configPath)
	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("failed to load test config: %v", err)
	}
	return cfg
}

// #330: with security.enable_file_permission_check set (as the documented production
// template does), a world-readable DEK must refuse to start — this is meant to be the
// sole automated backstop for exactly this condition, and must not silently no-op.
func TestRunStartupValidation_EnabledCatchesWorldReadableDEK(t *testing.T) {
	dir := t.TempDir()
	configPath := writeStartupTestConfig(t, dir, true, 0644, 0600, 0600)
	cfg := loadStartupTestConfig(t, configPath)

	if err := runStartupValidation(cfg); err == nil {
		t.Fatal("expected startup validation to refuse to start with a world-readable DEK")
	}
}

// The same world-readable DEK must NOT block startup when the check is left at its
// default (disabled) — confirming this wiring cannot regress an existing deployment
// that hasn't opted in to the flag.
func TestRunStartupValidation_DisabledIsANoOp(t *testing.T) {
	dir := t.TempDir()
	configPath := writeStartupTestConfig(t, dir, false, 0644, 0644, 0644)
	cfg := loadStartupTestConfig(t, configPath)

	if err := runStartupValidation(cfg); err != nil {
		t.Fatalf("startup validation must be a no-op when the flag is disabled: %v", err)
	}
}

// A correctly-permissioned setup with the check enabled must pass cleanly.
func TestRunStartupValidation_EnabledPassesOnCleanSetup(t *testing.T) {
	dir := t.TempDir()
	configPath := writeStartupTestConfig(t, dir, true, 0600, 0600, 0600)
	cfg := loadStartupTestConfig(t, configPath)

	if err := runStartupValidation(cfg); err != nil {
		t.Fatalf("expected a clean 0600 setup to pass: %v", err)
	}
}

// A completely zero-value config (the shape most local/dev/CI configs take: the flag
// defaults to false in Go/YAML) must never touch the filesystem or fail, regardless of
// what encryption/database paths would otherwise be configured — the safety property
// this wiring relies on to avoid regressing normal server startup.
func TestRunStartupValidation_ZeroValueConfigIsANoOp(t *testing.T) {
	if err := runStartupValidation(&config.Config{}); err != nil {
		t.Fatalf("zero-value config must not fail startup validation: %v", err)
	}
}
