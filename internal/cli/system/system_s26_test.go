// system_s26_test.go — coverage sprint 26 for internal/cli/system.
// Targets the wrapped-error branches in runInit that weren't reachable through
// the existing "selective component" tests (which use a template config that
// makes every downstream step succeed), plus a couple of always-0%
// helper/branch spots:
//   - runInit: generateConfigFile() error branch (init.go:101-103)
//   - runInit: config.Load() error branch (init.go:106-108)
//   - runInit: initializeEncryption() error branch (init.go:111-113), and
//     initializeEncryption's own DEK-dir/salt-dir MkdirAll failure branches
//   - runInit: initializeDatabase() error branch (init.go:117-119), and
//     initializeDatabase's own MkdirAll failure branch (distinct from the
//     already-covered ".." rejection)
//   - runInit: initializeLogging() error branch (init.go:123-125), and
//     initializeLogging's own OpenFile failure branch
//   - generateConfigFile: MkdirAll failure and SecureWriteFileSync failure
//     branches (init.go:150-152, 154-156)
//   - refuseInitRedirect (init.go, 0% covered): the http.Client CheckRedirect
//     guard is never invoked in-process (no test server issues a 3xx), so it
//     needs a direct unit test
//   - runAuditNoExit: the spec.path == "" skip branch (audit.go:66-67) — hit
//     when a config has no encryption paths configured at all
package system

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ──────────────────────────── refuseInitRedirect ───────────────────────────

// TestRefuseInitRedirect exercises the CheckRedirect guard directly: it must
// always return a non-nil error naming the redirect target, since runRemoteInit
// relies on it never letting the credential-carrying POST follow a 3xx.
func TestRefuseInitRedirect(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "http://internal.example.invalid/imds", nil)
	require.NoError(t, err)

	rerr := refuseInitRedirect(req, nil)
	require.Error(t, rerr)
	assert.Contains(t, rerr.Error(), "refusing to follow redirect")
	assert.Contains(t, rerr.Error(), "internal.example.invalid")
}

// ──────────────────────────── runInit wrapped-error branches ───────────────

// TestRunInit_GenerateConfigFileErrorPropagates exercises init.go:101-103: when
// generateConfigFile fails (no template file present, and the config doesn't
// already exist so the "already exists" skip can't short-circuit first),
// runInit must wrap and return that error rather than continuing.
func TestRunInit_GenerateConfigFileErrorPropagates(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir) // deliberately no keyorix_template.yaml here

	restore := saveInitFlags(t)
	defer restore()
	configPath = "keyorix.yaml"
	force = true
	initAll = true
	initServer = ""

	err := runInit(InitCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to generate config file")
}

// TestRunInit_ConfigLoadErrorPropagates exercises init.go:106-108: the
// template is written successfully but contains a field config.Load's
// KnownFields(true) decoder rejects, so config.Load fails on the freshly
// generated file and runInit must wrap that error.
func TestRunInit_ConfigLoadErrorPropagates(t *testing.T) {
	dir := t.TempDir()
	badTemplate := "storage:\n  type: local\n  totally_unrecognized_field: true\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "keyorix_template.yaml"), []byte(badTemplate), 0600))
	t.Chdir(dir)

	restore := saveInitFlags(t)
	defer restore()
	configPath = "keyorix.yaml"
	force = false
	initAll = true
	initServer = ""

	err := runInit(InitCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load config")
}

// TestRunInit_InitializeEncryptionErrorPropagates exercises init.go:111-113
// (and, inside initializeEncryption itself, the DEK-dir MkdirAll failure
// branch): the generated config's dek_path/salt_path sit under a path
// component that's already an existing regular file, so MkdirAll fails with
// ENOTDIR and runInit must wrap that error.
func TestRunInit_InitializeEncryptionErrorPropagates(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	require.NoError(t, os.WriteFile(blocker, []byte("not a directory"), 0600))

	template := fmt.Sprintf("storage:\n  type: local\n  encryption:\n    dek_path: %s/dek.bin\n    salt_path: %s/salt.bin\n", blocker, blocker)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "keyorix_template.yaml"), []byte(template), 0600))
	t.Chdir(dir)

	restore := saveInitFlags(t)
	defer restore()
	configPath = "keyorix.yaml"
	force = false
	initAll = true
	initEncryption = true
	initDatabase = false
	initLogging = false
	initServer = ""

	err := runInit(InitCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to initialize encryption")
}

// TestRunInit_DatabasePathTraversal_RejectedAtConfigLoad exercises the same
// "../escapes.db" traversal TestRunInit_InitializeDatabaseErrorPropagates
// used to catch inside initializeDatabase (init.go's own "invalid path for
// database" check) -- #1636 moved that rejection into config.Load() itself
// (resolveConfigRelativePath, internal/config/config.go), since
// initializeDatabase's check only ever ran on this CLI path, never on the
// server's own boot path (createLocalStorage had no such check at all).
// runInit now fails at the "failed to load config" step, before
// initializeDatabase is ever reached -- initializeDatabase's own check is
// still in place as defense-in-depth for a hand-constructed *config.Config
// that didn't go through Load(), but is no longer what this test exercises.
func TestRunInit_DatabasePathTraversal_RejectedAtConfigLoad(t *testing.T) {
	dir := t.TempDir()
	template := "storage:\n  type: local\n  database:\n    path: ../escapes.db\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "keyorix_template.yaml"), []byte(template), 0600))
	t.Chdir(dir)

	restore := saveInitFlags(t)
	defer restore()
	configPath = "keyorix.yaml"
	force = false
	initAll = true
	initEncryption = false
	initDatabase = true
	initLogging = false
	initServer = ""

	err := runInit(InitCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load config")
	assert.Contains(t, err.Error(), "..")
}

// TestRunInit_InitializeLoggingErrorPropagates exercises init.go:123-125 (and,
// inside initializeLogging itself, the OpenFile non-IsExist failure branch):
// the config already exists (so generateConfigFile takes the no-write skip
// path) and the working directory is read-only, so initializeLogging's
// os.OpenFile(O_CREATE) for keyorix.log fails with permission denied — a
// non-IsExist error — and runInit must wrap it.
func TestRunInit_InitializeLoggingErrorPropagates(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "keyorix.yaml"), []byte(minimalTemplate), 0600))
	t.Chdir(dir)

	restore := saveInitFlags(t)
	defer restore()
	configPath = "keyorix.yaml" // already exists: generateConfigFile takes the no-write branch
	force = false
	initAll = true
	initEncryption = false
	initDatabase = false
	initLogging = true
	initServer = ""

	require.NoError(t, os.Chmod(dir, 0500)) // read+execute only: blocks creating keyorix.log
	t.Cleanup(func() { _ = os.Chmod(dir, 0750) })

	err := runInit(InitCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to initialize logging")
}

// ──────────────────────────── generateConfigFile own error branches ────────

// TestGenerateConfigFile_MkdirAllFails exercises init.go:150-152: configPath's
// parent directory can't be created because a path component ("blocker") is
// already an existing regular file, not a directory.
func TestGenerateConfigFile_MkdirAllFails(t *testing.T) {
	dir := setupInitDir(t) // template present, cwd = dir

	blocker := filepath.Join(dir, "blocker")
	require.NoError(t, os.WriteFile(blocker, []byte("x"), 0600))

	restore := saveInitFlags(t)
	defer restore()
	configPath = filepath.Join("blocker", "sub", "keyorix.yaml")
	force = true

	out := captureStdout(t, func() {
		err := generateConfigFile()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to create config directory")
	})
	assert.Contains(t, out, "Generating config file")
}

// TestGenerateConfigFile_WriteFails exercises init.go:154-156:
// SecureWriteFileSync fails because configPath names an existing directory,
// not a writable regular-file target.
func TestGenerateConfigFile_WriteFails(t *testing.T) {
	dir := setupInitDir(t) // template present, cwd = dir
	require.NoError(t, os.Mkdir(filepath.Join(dir, "existing-dir"), 0750))

	restore := saveInitFlags(t)
	defer restore()
	configPath = "existing-dir"
	force = true

	out := captureStdout(t, func() {
		err := generateConfigFile()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to write config file")
	})
	assert.Contains(t, out, "Generating config file")
}

// ──────────────────────────── initializeDatabase own error branch ──────────

// TestInitializeDatabase_MkdirAllFails exercises init.go:167-169: the database
// directory can't be created because a path component is an existing regular
// file — distinct from the already-covered ".." rejection branch.
func TestInitializeDatabase_MkdirAllFails(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	require.NoError(t, os.WriteFile(blocker, []byte("x"), 0600))
	dbPath := filepath.Join(blocker, "sub", "secrets.db")

	cfg := &config.Config{
		Storage: config.StorageConfig{
			Database: config.DatabaseConfig{Path: dbPath},
		},
	}
	err := initializeDatabase(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create database directory")
}

// TestInitializeDatabase_OpenFileFailsNotExist exercises init.go:177-179: the
// database directory already exists but is read-only, so os.OpenFile's
// O_CREATE fails with permission-denied — a non-IsExist error distinct from
// the "file already exists" ok-path.
func TestInitializeDatabase_OpenFileFailsNotExist(t *testing.T) {
	dir := t.TempDir()
	subDir := filepath.Join(dir, "dbdir")
	require.NoError(t, os.Mkdir(subDir, 0750))
	dbPath := filepath.Join(subDir, "secrets.db")

	require.NoError(t, os.Chmod(subDir, 0500)) // read+execute only, no write
	t.Cleanup(func() { _ = os.Chmod(subDir, 0750) })

	cfg := &config.Config{
		Storage: config.StorageConfig{
			Database: config.DatabaseConfig{Path: dbPath},
		},
	}
	err := initializeDatabase(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create database file")
}

// ──────────────────────────── initializeEncryption own error branches ──────

// TestInitializeEncryption_SaltDirMkdirAllFails exercises init.go:191-193 (the
// salt-dir MkdirAll failure), distinct from the DEK-dir failure already
// covered via TestRunInit_InitializeEncryptionErrorPropagates: the DEK
// directory can be created fine, but the salt directory's parent is an
// existing regular file.
func TestInitializeEncryption_SaltDirMkdirAllFails(t *testing.T) {
	dir := t.TempDir()
	dekPath := filepath.Join(dir, "dek-dir", "dek.bin")

	blocker := filepath.Join(dir, "blocker")
	require.NoError(t, os.WriteFile(blocker, []byte("x"), 0600))
	saltPath := filepath.Join(blocker, "sub", "salt.bin")

	cfg := &config.Config{
		Storage: config.StorageConfig{
			Encryption: config.EncryptionConfig{DEKPath: dekPath, SaltPath: saltPath},
		},
	}
	err := initializeEncryption(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create salt directory")

	// The DEK directory must have been created successfully before the salt
	// failure was hit, confirming this test exercises the SECOND MkdirAll,
	// not a repeat of the DEK-dir failure branch.
	_, statErr := os.Stat(filepath.Dir(dekPath))
	require.NoError(t, statErr, "DEK directory should have been created before the salt MkdirAll failed")
}

// ──────────────────────────── runAuditNoExit: empty key-path skip ──────────

// TestRunAuditNoExit_SkipsUnconfiguredKeyPaths exercises audit.go:66-67: when
// a config has no storage.encryption.salt_path/dek_path configured (both are
// the empty string), the per-spec loop must `continue` rather than trying to
// stat an empty path — the audit should still pass, checking only the config
// file's own permissions.
func TestRunAuditNoExit_SkipsUnconfiguredKeyPaths(t *testing.T) {
	resetAuditConfigFile(t)
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "no-encryption-paths.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte("storage:\n  type: local\n"), 0600))
	auditConfigFile = cfgPath

	var failed bool
	out := captureStdout(t, func() {
		failed = runAuditNoExit()
	})

	assert.False(t, failed, "audit must pass when no salt/DEK paths are configured at all")
	assert.Contains(t, out, "Audit passed")
}
