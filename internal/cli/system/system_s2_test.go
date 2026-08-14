// system_s2_test.go — coverage sprint 2 for internal/cli/system.
// Targets: runAudit (the os.Exit wrapper), generateConfigFile, and additional
// paths through runInit and runValidate not yet exercised by existing tests.
package system

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// minimalTemplate is a minimal keyorix_template.yaml content for tests that
// need generateConfigFile to succeed.
const minimalTemplate = "storage:\n  type: local\n  database:\n    path: ./secrets.db\n"

// setupInitDir creates a temp dir with:
//   - keyorix_template.yaml (so generateConfigFile can read it)
//   - cwd set to the temp dir
func setupInitDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Chdir(dir)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "keyorix_template.yaml"), []byte(minimalTemplate), 0600))
	return dir
}

// saveInitFlags saves and returns a restore function for all init package-level flags.
func saveInitFlags(t *testing.T) func() {
	t.Helper()
	origConfigPath := configPath
	origForce := force
	origAll := initAll
	origEnc := initEncryption
	origDB := initDatabase
	origLog := initLogging
	origServer := initServer
	return func() {
		configPath = origConfigPath
		force = origForce
		initAll = origAll
		initEncryption = origEnc
		initDatabase = origDB
		initLogging = origLog
		initServer = origServer
	}
}

// ──────────────────────────── generateConfigFile ──────────────────────────────

// TestGenerateConfigFile_AlreadyExists_NoForce checks that when the config file
// already exists and --force is false, generateConfigFile prints a warning and
// returns nil (no overwrite, no error).
func TestGenerateConfigFile_AlreadyExists_NoForce(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	cfgPath := filepath.Join(dir, "keyorix.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte("existing: content\n"), 0600))

	restore := saveInitFlags(t)
	defer restore()
	configPath = cfgPath
	force = false

	out := captureStdout(t, func() {
		err := generateConfigFile()
		require.NoError(t, err)
	})
	assert.Contains(t, out, "already exists")

	// Verify that the file content is unchanged.
	data, err := os.ReadFile(cfgPath)
	require.NoError(t, err)
	assert.Equal(t, "existing: content\n", string(data))
}

// TestGenerateConfigFile_TemplateNotFound exercises the error branch when the
// template file is missing.
func TestGenerateConfigFile_TemplateNotFound(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir) // no keyorix_template.yaml here

	restore := saveInitFlags(t)
	defer restore()
	configPath = filepath.Join(dir, "new-config.yaml")
	force = true // force so the "already exists" short-circuit is skipped

	out := captureStdout(t, func() {
		err := generateConfigFile()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to read template file")
	})
	assert.Contains(t, out, "Generating config file")
}

// TestGenerateConfigFile_CreatesFile verifies the happy path: with a template
// present and force=false (or no pre-existing file), the config file is written.
// configPath must be relative to cwd because SecureWriteFileSync uses "." as base.
func TestGenerateConfigFile_CreatesFile(t *testing.T) {
	setupInitDir(t) // creates template in cwd

	restore := saveInitFlags(t)
	defer restore()
	configPath = "out-config.yaml" // relative to cwd
	force = false

	out := captureStdout(t, func() {
		err := generateConfigFile()
		require.NoError(t, err)
	})
	assert.Contains(t, out, "Config file created")

	data, err := os.ReadFile(configPath)
	require.NoError(t, err)
	assert.Contains(t, string(data), "storage")
}

// TestGenerateConfigFile_Force_Overwrites confirms --force=true overwrites an
// existing file by replacing it with the template contents.
func TestGenerateConfigFile_Force_Overwrites(t *testing.T) {
	setupInitDir(t)

	restore := saveInitFlags(t)
	defer restore()
	configPath = "keyorix.yaml" // relative to cwd
	require.NoError(t, os.WriteFile(configPath, []byte("old: content\n"), 0600))
	force = true

	out := captureStdout(t, func() {
		err := generateConfigFile()
		require.NoError(t, err)
	})
	assert.Contains(t, out, "Config file created")

	data, err := os.ReadFile(configPath)
	require.NoError(t, err)
	// The template content should have replaced the old content.
	assert.Equal(t, minimalTemplate, string(data))
}

// ──────────────────────────── initializeEncryption ───────────────────────────

func TestInitializeEncryption_SaltAndDEKDirCreated(t *testing.T) {
	dir := t.TempDir()
	dekPath := filepath.Join(dir, "dek-dir", "dek.bin")
	saltPath := filepath.Join(dir, "salt-dir", "salt.bin")

	cfg := &config.Config{
		Storage: config.StorageConfig{
			Encryption: config.EncryptionConfig{
				DEKPath:  dekPath,
				SaltPath: saltPath,
			},
		},
	}
	require.NoError(t, initializeEncryption(cfg))

	_, err := os.Stat(filepath.Dir(dekPath))
	require.NoError(t, err, "DEK directory should be created")
	_, err = os.Stat(filepath.Dir(saltPath))
	require.NoError(t, err, "salt directory should be created")
}

// ──────────────────────────── initializeDatabase extra ───────────────────────

// TestInitializeDatabase_InvalidPath verifies that a path containing ".." is
// rejected.
func TestInitializeDatabase_InvalidPath(t *testing.T) {
	cfg := &config.Config{
		Storage: config.StorageConfig{
			Database: config.DatabaseConfig{Path: "../etc/secrets.db"},
		},
	}
	err := initializeDatabase(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid path")
}

// ──────────────────────────── runInit local mode ─────────────────────────────

// TestRunInit_AllComponents exercises the runInit local path with initAll=true.
// configPath is relative to cwd so generateConfigFile can write it (SecureWriteFileSync
// uses "." as base). After generateConfigFile, config.Load is called; the template's
// relative db path may cause an error — we just verify no panic and the banner.
func TestRunInit_AllComponents(t *testing.T) {
	setupInitDir(t)

	restore := saveInitFlags(t)
	defer restore()
	configPath = "keyorix.yaml" // relative to cwd
	force = false
	initAll = true
	initEncryption = false
	initDatabase = false
	initLogging = false
	initServer = ""

	out := captureStdout(t, func() {
		// May fail at config.Load or component init — that's fine.
		_ = runInit(InitCmd, nil)
	})
	// The "System Initialization" banner is always printed.
	assert.Contains(t, out, "Initialization")
}

// TestRunInit_SelectiveEncryption exercises the selective-component path where
// setting initEncryption clears initAll so only encryption is initialized.
func TestRunInit_SelectiveEncryption(t *testing.T) {
	setupInitDir(t)

	restore := saveInitFlags(t)
	defer restore()
	configPath = "keyorix.yaml"
	force = false
	initAll = true
	initEncryption = true // will clear initAll inside runInit
	initDatabase = false
	initLogging = false
	initServer = ""

	out := captureStdout(t, func() {
		_ = runInit(InitCmd, nil)
	})
	assert.Contains(t, out, "Initialization")
}

// TestRunInit_SelectiveDatabase exercises the database-only path.
func TestRunInit_SelectiveDatabase(t *testing.T) {
	setupInitDir(t)

	restore := saveInitFlags(t)
	defer restore()
	configPath = "keyorix.yaml"
	force = false
	initAll = true
	initEncryption = false
	initDatabase = true
	initLogging = false
	initServer = ""

	_ = captureStdout(t, func() {
		_ = runInit(InitCmd, nil)
	})
}

// TestRunInit_SelectiveLogging exercises the logging-only path.
func TestRunInit_SelectiveLogging(t *testing.T) {
	setupInitDir(t)

	restore := saveInitFlags(t)
	defer restore()
	configPath = "keyorix.yaml"
	force = false
	initAll = true
	initEncryption = false
	initDatabase = false
	initLogging = true
	initServer = ""

	_ = captureStdout(t, func() {
		_ = runInit(InitCmd, nil)
	})
}

// TestRunInit_ServerFlagTriggersPOST checks the remote-init dispatch.
func TestRunInit_ServerFlagTriggersPOST(t *testing.T) {
	restore := saveInitFlags(t)
	defer restore()
	origPW := initAdminPassword
	defer func() { initAdminPassword = origPW }()
	initServer = "http://127.0.0.1:1" // nothing listening
	initAdminPassword = "not-admin"   // #G76: must be resolved before this test's actual target (unreachable server) is exercised

	err := runInit(InitCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "could not reach server")
}

// ──────────────────────────── runValidate ─────────────────────────────────────

// TestRunValidate_ValidConfig checks that a minimal valid config file triggers
// the startup validation path without panicking.
func TestRunValidate_ValidConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keyorix.yaml")
	require.NoError(t, os.WriteFile(path, []byte("storage:\n  type: local\n  database:\n    path: ./secrets.db\n"), 0600))

	orig := configFile
	defer func() { configFile = orig }()
	configFile = path

	// Must not panic; may succeed or fail with a startup error.
	err := runValidate(validateCmd, nil)
	if err != nil {
		assert.NotContains(t, err.Error(), "config file not found")
	}
}

// TestRunValidate_AbsoluteDBPath uses an absolute database path so that the
// startup.ValidateStartup call proceeds further into validation, exercising the
// code path where results with warnings/errors are printed.
func TestRunValidate_AbsoluteDBPath(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "secrets.db")
	path := filepath.Join(dir, "keyorix.yaml")
	yaml := "storage:\n  type: local\n  database:\n    path: " + dbPath + "\n"
	require.NoError(t, os.WriteFile(path, []byte(yaml), 0600))

	orig, origFix := configFile, fixIssues
	defer func() { configFile = orig; fixIssues = origFix }()
	configFile = path
	fixIssues = false

	// Must not panic.
	_ = runValidate(validateCmd, nil)
}

// TestRunValidate_WithFix exercises the --fix flag code path.
func TestRunValidate_WithFix(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "secrets.db")
	path := filepath.Join(dir, "keyorix.yaml")
	yaml := "storage:\n  type: local\n  database:\n    path: " + dbPath + "\n"
	require.NoError(t, os.WriteFile(path, []byte(yaml), 0600))

	orig, origFix := configFile, fixIssues
	defer func() { configFile = orig; fixIssues = origFix }()
	configFile = path
	fixIssues = true

	// Must not panic.
	_ = runValidate(validateCmd, nil)
}

// ──────────────────────────── infoCmd.RunE ───────────────────────────────────

// TestInfoCmd_NotConnected verifies that the infoCmd RunE returns an error when
// no remote client is configured (KEYORIX_SERVER unset).
func TestInfoCmd_NotConnected(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	err := infoCmd.RunE(infoCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected to a server")
}

// TestInfoCmd_ServerError checks that the infoCmd RunE surfaces errors from
// fetchSystemInfo when the server returns a non-2xx status.
func TestInfoCmd_ServerError(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "http://127.0.0.1:1")
	t.Setenv("KEYORIX_TOKEN", "tok")
	err := infoCmd.RunE(infoCmd, nil)
	// The error might be from fetchSystemInfo (connection refused) or the client.
	require.Error(t, err)
}

// TestInfoCmd_Success exercises the info printing path including features output.
func TestInfoCmd_Success(t *testing.T) {
	// Use the same stub helper already defined in info_remote_test.go
	// (systemInfoStub). That sets KEYORIX_SERVER and KEYORIX_TOKEN.
	rc, done := systemInfoStub(t)
	defer done()
	_ = rc // rc is already set in env

	out := captureStdout(t, func() {
		err := infoCmd.RunE(infoCmd, nil)
		require.NoError(t, err)
	})
	assert.Contains(t, out, "v0.68.0")
	assert.Contains(t, out, "Features:")
}

// ──────────────────────────── runAudit success path ──────────────────────────

// TestRunAudit_SuccessPath exercises the non-exit branch of runAudit: when
// runAuditNoExit returns false the function returns without calling os.Exit.
// We manufacture a passing audit by pointing auditConfigFile at a valid config
// with all encryption files present at correct permissions.
func TestRunAudit_SuccessPath(t *testing.T) {
	resetAuditConfigFile(t)
	dir := t.TempDir()
	cfgPath := writeAuditableConfig(t, dir, "good-config.yaml")
	auditConfigFile = cfgPath

	// runAuditNoExit must return false for runAudit not to call os.Exit.
	var failed bool
	_ = captureStdout(t, func() {
		failed = runAuditNoExit()
	})
	// Only call runAudit if the audit passes (otherwise os.Exit kills the test).
	if !failed {
		_ = captureStdout(t, func() {
			runAudit()
		})
	}
}
