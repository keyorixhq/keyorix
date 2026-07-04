package startup

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
)

// writeFile writes n bytes to dir/name and returns the absolute path.
func writeKeyFile(t *testing.T, dir, name string, n int) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, make([]byte, n), 0600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

func encCfg(saltPath, dekPath string) *config.Config {
	cfg := &config.Config{}
	cfg.Storage.Encryption.Enabled = true
	cfg.Storage.Encryption.SaltPath = saltPath
	cfg.Storage.Encryption.DEKPath = dekPath
	return cfg
}

// A 32-byte salt and a wrapped DEK (>= 60 bytes) must validate. The wrapped DEK
// is never a bare 32-byte key, so the old size==32 assertion was a false failure.
func TestValidateEncryption_ValidSaltAndWrappedDEK(t *testing.T) {
	dir := t.TempDir()
	salt := writeKeyFile(t, dir, "kek.salt", 32)
	dek := writeKeyFile(t, dir, "dek.key", 60) // 12 nonce + 32 key + 16 tag

	if err := validateEncryption(encCfg(salt, dek), &ValidationResult{}); err != nil {
		t.Fatalf("expected valid config to pass, got: %v", err)
	}
}

func TestValidateEncryption_MissingSalt(t *testing.T) {
	dir := t.TempDir()
	dek := writeKeyFile(t, dir, "dek.key", 60)
	salt := filepath.Join(dir, "absent.salt")

	if err := validateEncryption(encCfg(salt, dek), &ValidationResult{}); err == nil {
		t.Fatal("expected error for missing salt file")
	}
}

func TestValidateEncryption_WrongSaltSize(t *testing.T) {
	dir := t.TempDir()
	salt := writeKeyFile(t, dir, "kek.salt", 16) // too short
	dek := writeKeyFile(t, dir, "dek.key", 60)

	if err := validateEncryption(encCfg(salt, dek), &ValidationResult{}); err == nil {
		t.Fatal("expected error for 16-byte salt (must be 32)")
	}
}

func TestValidateEncryption_DEKTooSmall(t *testing.T) {
	dir := t.TempDir()
	salt := writeKeyFile(t, dir, "kek.salt", 32)
	dek := writeKeyFile(t, dir, "dek.key", 32) // a bare key, not a wrapped one

	if err := validateEncryption(encCfg(salt, dek), &ValidationResult{}); err == nil {
		t.Fatal("expected error for 32-byte DEK (wrapped DEK is >= 60 bytes)")
	}
}

func TestResolveKeyPath(t *testing.T) {
	if got := resolveKeyPath("/app/keys/dek.key"); got != "/app/keys/dek.key" {
		t.Errorf("absolute path should pass through, got %q", got)
	}
	if got := resolveKeyPath("keys/dek.key"); got != filepath.Clean("keys/dek.key") {
		t.Errorf("relative path resolved unexpectedly: %q", got)
	}
}

// #331 regression: validateFilePermissions must check the config file that was
// actually passed in (and loaded via config.Load), not a hardcoded "keyorix.yaml" in
// the process's working directory. A 0600 file at an arbitrary custom path must pass;
// if the old hardcoded-name bug were still present, it would try to Lstat a
// "keyorix.yaml" that doesn't exist in this package's test directory and fail instead.
func TestValidateFilePermissions_UsesActualConfigPath(t *testing.T) {
	if _, err := os.Lstat("keyorix.yaml"); err == nil {
		t.Skip("a keyorix.yaml exists in the test working directory; this test cannot distinguish the bug from the fix")
	}

	dir := t.TempDir()
	configPath := filepath.Join(dir, "custom-config-name.yml")
	if err := os.WriteFile(configPath, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{} // no encryption/DB path configured — isolates the config-file check
	if err := validateFilePermissions(cfg, configPath, false, &ValidationResult{}); err != nil {
		t.Fatalf("expected the real 0600 config path to pass, got: %v", err)
	}
}

// #332 regression: validateFilePermissions must not treat a postgres/remote deployment's
// (legitimately empty) Storage.Database.Path as a local file to lock down — that would
// resolve to "." (the current directory) and either warn on or attempt to chmod it.
func TestValidateFilePermissions_SkipsDatabasePathForNonLocalStorage(t *testing.T) {
	for _, typ := range []string{"postgres", "postgresql", "remote"} {
		cfg := &config.Config{}
		cfg.Storage.Type = typ
		// Database.Path intentionally left empty, as it legitimately is for these types.
		if err := validateFilePermissions(cfg, "", false, &ValidationResult{}); err != nil {
			t.Errorf("storage.type=%q must not check a local database file, got: %v", typ, err)
		}
	}
}

// #229: validateFilePermissions must reject a ".."-traversal segment in every path it
// collects — the config file path, key paths, database path, and TLS cert/key paths are
// all sourced from a config file that may itself be attacker-influenced (e.g. a custom
// --config pointed at a maliciously-crafted file). Unlike this file's sibling functions
// (validateEncryption, validateDatabase), validateFilePermissions previously only
// filepath.Clean()'d these paths with no traversal check before handing them to
// securefiles.FixFilePerms, which will Lstat/Chmod/Chown whatever path it's given.
func TestValidateFilePermissions_RejectsPathTraversal(t *testing.T) {
	dir := t.TempDir()
	// A relative path that filepath.Clean cannot fully resolve (it climbs above
	// where it started), so the cleaned form still contains "..". filepath.Join
	// would clean this away, so it's built by hand to keep the traversal intact.
	outside := "sub/../../outside-target"

	t.Run("config path", func(t *testing.T) {
		cfg := &config.Config{}
		if err := validateFilePermissions(cfg, outside, false, &ValidationResult{}); err == nil {
			t.Fatal("expected error for a config path containing '..'")
		}
	})

	t.Run("encryption salt path", func(t *testing.T) {
		cfg := encCfg(outside, filepath.Join(dir, "dek.key"))
		if err := validateFilePermissions(cfg, "", false, &ValidationResult{}); err == nil {
			t.Fatal("expected error for a KEK salt path containing '..'")
		}
	})

	t.Run("encryption dek path", func(t *testing.T) {
		cfg := encCfg(filepath.Join(dir, "kek.salt"), outside)
		if err := validateFilePermissions(cfg, "", false, &ValidationResult{}); err == nil {
			t.Fatal("expected error for a DEK path containing '..'")
		}
	})

	t.Run("database path", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.Storage.Database.Path = outside
		if err := validateFilePermissions(cfg, "", false, &ValidationResult{}); err == nil {
			t.Fatal("expected error for a database path containing '..'")
		}
	})

	t.Run("http tls cert/key path", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.Server.HTTP.TLS.Enabled = true
		cfg.Server.HTTP.TLS.CertFile = outside
		cfg.Server.HTTP.TLS.KeyFile = filepath.Join(dir, "server.key")
		if err := validateFilePermissions(cfg, "", false, &ValidationResult{}); err == nil {
			t.Fatal("expected error for an HTTP TLS cert path containing '..'")
		}
	})

	t.Run("grpc tls cert/key path", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.Server.GRPC.TLS.Enabled = true
		cfg.Server.GRPC.TLS.CertFile = filepath.Join(dir, "server.crt")
		cfg.Server.GRPC.TLS.KeyFile = outside
		if err := validateFilePermissions(cfg, "", false, &ValidationResult{}); err == nil {
			t.Fatal("expected error for a gRPC TLS key path containing '..'")
		}
	})
}

// #229: forceAutoFix must actually drive remediation independent of the config's
// Security.AutoFixFilePermissions field — this is what makes `keyorix system validate
// --fix` do what an operator expects instead of silently depending on a field read from
// the config file being validated.
func TestValidateFilePermissions_ForceAutoFixOverridesConfig(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "cfg.yaml")
	// 0644 is wrong (want 0600); this exercises the fix path.
	if err := os.WriteFile(configPath, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{} // AutoFixFilePermissions left false/zero-value
	result := &ValidationResult{}
	if err := validateFilePermissions(cfg, configPath, true, result); err != nil {
		t.Fatalf("expected forceAutoFix to remediate the bad mode, got: %v", err)
	}

	info, err := os.Stat(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("expected mode to be fixed to 0600, got %o", info.Mode().Perm())
	}
}

// #332 regression: validateDatabase must mirror Config.Validate()'s switch on
// Storage.Type — postgres/remote deployments reach their store over the network and
// must not be false-failed by a local-file reachability check.
func TestValidateDatabase_SkipsLocalCheckForNonLocalStorage(t *testing.T) {
	for _, typ := range []string{"postgres", "postgresql", "remote"} {
		cfg := &config.Config{}
		cfg.Storage.Type = typ
		result := &ValidationResult{}
		if err := validateDatabase(cfg, result); err != nil {
			t.Errorf("storage.type=%q must not require a local database file, got: %v", typ, err)
		}
	}
}

// Local/sqlite storage is unaffected by the #332 fix: an unsafe (relative) path is
// still rejected.
func TestValidateDatabase_LocalStorageStillValidatesPath(t *testing.T) {
	cfg := &config.Config{}
	cfg.Storage.Database.Path = "relative.db"
	if err := validateDatabase(cfg, &ValidationResult{}); err == nil {
		t.Fatal("expected error for a relative local database path")
	}
}
