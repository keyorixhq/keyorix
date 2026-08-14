package startup

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSafeFilePermPath_CleanAbsolute validates that a safe absolute path is
// returned unchanged (after Clean).
func TestSafeFilePermPath_CleanAbsolute(t *testing.T) {
	got, err := SafeFilePermPath("label", "/app/keys/dek.key")
	require.NoError(t, err)
	assert.Equal(t, "/app/keys/dek.key", got)
}

// TestSafeFilePermPath_RejectsTraversal validates that paths with ".." are
// rejected after filepath.Clean.
func TestSafeFilePermPath_RejectsTraversal(t *testing.T) {
	_, err := SafeFilePermPath("test", "sub/../../outside")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "..")
}

// TestSafeFilePermPath_RejectsParentDirOnly validates that ".." alone is
// rejected.
func TestSafeFilePermPath_RejectsParentDirOnly(t *testing.T) {
	_, err := SafeFilePermPath("label", "..")
	require.Error(t, err)
}

// TestSafeFilePermPath_SafeRelative validates that a safe relative path without
// traversal is allowed.
func TestSafeFilePermPath_SafeRelative(t *testing.T) {
	got, err := SafeFilePermPath("label", "keys/dek.key")
	require.NoError(t, err)
	assert.Equal(t, filepath.Clean("keys/dek.key"), got)
}

// TestValidateEncryption_UnsafeSaltPath validates that a ".." in the salt path
// is caught by validateEncryption's own traversal check.
func TestValidateEncryption_UnsafeSaltPath(t *testing.T) {
	cfg := encCfg("../../outside/salt", "/tmp/dek")
	err := validateEncryption(cfg, &ValidationResult{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsafe")
}

// TestValidateEncryption_UnsafeDEKPath validates that a ".." in the DEK path
// is caught by validateEncryption's own traversal check.
func TestValidateEncryption_UnsafeDEKPath(t *testing.T) {
	dir := t.TempDir()
	salt := writeKeyFile(t, dir, "kek.salt", 32)
	cfg := encCfg(salt, "../../outside/dek.key")
	err := validateEncryption(cfg, &ValidationResult{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsafe")
}

// TestValidateEncryption_MissingDEK validates that a missing DEK file is
// detected.
func TestValidateEncryption_MissingDEK(t *testing.T) {
	dir := t.TempDir()
	salt := writeKeyFile(t, dir, "kek.salt", 32)
	dek := filepath.Join(dir, "absent.dek")

	err := validateEncryption(encCfg(salt, dek), &ValidationResult{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "DEK")
}

// TestValidateDatabase_LocalPathMustBeAbsolute validates that a relative
// database path is rejected for local storage.
func TestValidateDatabase_LocalPathMustBeAbsolute(t *testing.T) {
	cfg := &config.Config{}
	cfg.Storage.Type = "local"
	cfg.Storage.Database.Path = "relative/secrets.db"
	err := validateDatabase(cfg, &ValidationResult{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "relative")
}

// TestValidateDatabase_LocalPathWithTraversal validates that a RELATIVE path
// with ".." is rejected for local storage. Note: an absolute path like
// /app/../../etc/secrets.db cleans to /etc/secrets.db (still absolute), which
// passes the check — only paths that are relative (not absolute) after Clean
// are caught by the is-abs guard here.
func TestValidateDatabase_LocalPathWithTraversal(t *testing.T) {
	cfg := &config.Config{}
	// A relative path with ".." remains relative after Clean.
	cfg.Storage.Database.Path = "../relative.db"
	err := validateDatabase(cfg, &ValidationResult{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "relative")
}

// TestValidateDatabase_ExistingFile validates that an existing, readable file is
// accepted.
func TestValidateDatabase_ExistingFile(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "secrets.db")
	require.NoError(t, os.WriteFile(dbPath, []byte("SQLite data"), 0600))

	cfg := &config.Config{}
	cfg.Storage.Database.Path = dbPath
	result := &ValidationResult{}
	err := validateDatabase(cfg, result)
	require.NoError(t, err)
}

// TestValidateDatabase_NonExistentFileIsWarning validates that a missing DB file
// produces a warning (not an error) — it will be created on first use.
func TestValidateDatabase_NonExistentFileIsWarning(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{}
	cfg.Storage.Database.Path = filepath.Join(dir, "not-yet-created.db")
	result := &ValidationResult{}
	err := validateDatabase(cfg, result)
	require.NoError(t, err)
	assert.NotEmpty(t, result.Warnings, "a missing DB file should produce a warning")
}

// TestValidateDatabase_RemoteStorageSkip validates the "remote" path skips the
// local-file check and adds a warning.
func TestValidateDatabase_RemoteStorageSkip(t *testing.T) {
	cfg := &config.Config{}
	cfg.Storage.Type = "remote"
	result := &ValidationResult{}
	err := validateDatabase(cfg, result)
	require.NoError(t, err)
	assert.NotEmpty(t, result.Warnings)
}

// TestValidateDatabase_PostgresSkip validates the "postgres" path skips the
// local-file check and adds a warning.
func TestValidateDatabase_PostgresSkip(t *testing.T) {
	for _, typ := range []string{"postgres", "postgresql"} {
		cfg := &config.Config{}
		cfg.Storage.Type = typ
		result := &ValidationResult{}
		err := validateDatabase(cfg, result)
		require.NoErrorf(t, err, "storage.type=%q must not require a local DB file", typ)
		assert.NotEmptyf(t, result.Warnings, "storage.type=%q should add a skip warning", typ)
	}
}

// TestResolveKeyPath_Absolute validates that absolute paths are returned as-is.
func TestResolveKeyPath_Absolute(t *testing.T) {
	got := resolveKeyPath("/etc/keys/dek.key")
	assert.Equal(t, "/etc/keys/dek.key", got)
}

// TestResolveKeyPath_Relative validates that relative paths are resolved against
// ".".
func TestResolveKeyPath_Relative(t *testing.T) {
	got := resolveKeyPath("keys/dek.key")
	assert.Equal(t, filepath.Clean("keys/dek.key"), got)
}

// TestResolveKeyPath_Dot validates that "." resolves to ".".
func TestResolveKeyPath_Dot(t *testing.T) {
	got := resolveKeyPath(".")
	assert.Equal(t, ".", got)
}

// TestValidateFilePermissions_EncryptionPathsChecked validates that when
// encryption is enabled, the salt and DEK paths are added to the check list.
// We use existing files with correct permissions so the check passes.
func TestValidateFilePermissions_EncryptionPathsChecked(t *testing.T) {
	dir := t.TempDir()
	salt := writeKeyFile(t, dir, "kek.salt", 32)
	dek := writeKeyFile(t, dir, "dek.key", 60)

	cfg := &config.Config{}
	cfg.Storage.Encryption.Enabled = true
	cfg.Storage.Encryption.SaltPath = salt
	cfg.Storage.Encryption.DEKPath = dek

	result := &ValidationResult{}
	err := validateFilePermissions(cfg, "", false, result)
	require.NoError(t, err)
}

// TestValidateFilePermissions_TLSGRPCPathsChecked validates that when gRPC TLS
// is enabled, cert and key paths are included.
func TestValidateFilePermissions_TLSGRPCPathsChecked(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "server.crt")
	key := filepath.Join(dir, "server.key")
	require.NoError(t, os.WriteFile(cert, []byte("cert"), 0600))
	require.NoError(t, os.WriteFile(key, []byte("key"), 0600))

	cfg := &config.Config{}
	cfg.Server.GRPC.TLS.Enabled = true
	cfg.Server.GRPC.TLS.CertFile = cert
	cfg.Server.GRPC.TLS.KeyFile = key

	result := &ValidationResult{}
	err := validateFilePermissions(cfg, "", false, result)
	require.NoError(t, err)
}

// TestValidateFilePermissions_TLSHTTPPathsChecked validates that when HTTP TLS
// is enabled, cert and key paths are included.
func TestValidateFilePermissions_TLSHTTPPathsChecked(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "http.crt")
	key := filepath.Join(dir, "http.key")
	require.NoError(t, os.WriteFile(cert, []byte("cert"), 0600))
	require.NoError(t, os.WriteFile(key, []byte("key"), 0600))

	cfg := &config.Config{}
	cfg.Server.HTTP.TLS.Enabled = true
	cfg.Server.HTTP.TLS.CertFile = cert
	cfg.Server.HTTP.TLS.KeyFile = key

	result := &ValidationResult{}
	err := validateFilePermissions(cfg, "", false, result)
	require.NoError(t, err)
}

// TestValidateFilePermissions_DatabasePathIncluded validates that when storage
// type is local and a non-empty database path is given, it is included in the
// permission check.
func TestValidateFilePermissions_DatabasePathIncluded(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "secrets.db")
	require.NoError(t, os.WriteFile(dbPath, []byte("data"), 0600))

	cfg := &config.Config{}
	cfg.Storage.Type = "local"
	cfg.Storage.Database.Path = dbPath

	result := &ValidationResult{}
	err := validateFilePermissions(cfg, "", false, result)
	require.NoError(t, err)
}

// TestPrintValidationResult_AllPass exercises the print function with a fully
// passing result (smoke test — no panic, no assertions on stdout).
func TestPrintValidationResult_AllPass(t *testing.T) {
	result := &ValidationResult{
		ConfigValid:   true,
		PermissionsOK: true,
		EncryptionOK:  true,
		DatabaseOK:    true,
	}
	// Must not panic.
	PrintValidationResult(result)
}

// TestPrintValidationResult_WithWarningsAndErrors exercises the print function
// with a failing result that has both warnings and errors.
func TestPrintValidationResult_WithWarningsAndErrors(t *testing.T) {
	result := &ValidationResult{
		ConfigValid:   false,
		PermissionsOK: false,
		EncryptionOK:  false,
		DatabaseOK:    false,
		Warnings:      []string{"file permission check disabled"},
		Errors:        []string{"failed to load config: file not found"},
	}
	// Must not panic.
	PrintValidationResult(result)
}
