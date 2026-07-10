// system_remote_test.go — additional coverage for the system package RunE bodies.
package system

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ──────────────────────────── runRemoteInit ────────────────────────────────

// TestRunRemoteInit_Success exercises the success path of runRemoteInit,
// covering the "new workspace" branch (not already initialized).
func TestRunRemoteInit_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/system/init", r.URL.Path)
		_, _ = w.Write([]byte(`{"success":true,"data":{` +
			`"already_initialized":false,` +
			`"user":{"id":1,"username":"admin","email":"admin@example.com"},` +
			`"project":"default",` +
			`"environments":["development","staging","production"]` +
			`}}`))
	}))
	defer srv.Close()

	orig := initServer
	defer func() { initServer = orig }()
	initServer = srv.URL

	out := captureStdout(t, func() {
		require.NoError(t, runRemoteInit())
	})
	assert.Contains(t, out, "Keyorix initialised successfully")
	assert.Contains(t, out, "development, staging, production")
}

// TestRunRemoteInit_AlreadyInitialized covers the d.AlreadyInitialized == true branch.
func TestRunRemoteInit_AlreadyInitialized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"data":{"already_initialized":true}}`))
	}))
	defer srv.Close()

	orig := initServer
	defer func() { initServer = orig }()
	initServer = srv.URL

	// Already covered by init_flag_warning_test; confirm no error returned.
	require.NoError(t, runRemoteInit())
}

// TestRunRemoteInit_ServerHTTPError exercises the HTTP >= 400 branch.
func TestRunRemoteInit_ServerHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"success":false,"message":"system already bootstrapped"}`))
	}))
	defer srv.Close()

	orig := initServer
	defer func() { initServer = orig }()
	initServer = srv.URL

	err := runRemoteInit()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "initialisation failed")
	assert.Contains(t, err.Error(), "system already bootstrapped")
}

// TestRunRemoteInit_ServerUnreachable exercises the connection-failed branch.
func TestRunRemoteInit_ServerUnreachable(t *testing.T) {
	orig := initServer
	defer func() { initServer = orig }()
	initServer = "http://127.0.0.1:1" // port 1: nothing listening

	err := runRemoteInit()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "could not reach server")
}

// TestRunRemoteInit_DefaultPasswordWarning verifies that the default-password
// warning is printed when --admin-password is left at the "admin" default.
func TestRunRemoteInit_DefaultPasswordWarning(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"data":{` +
			`"already_initialized":false,"user":{"id":1,"username":"admin","email":"admin@example.com"},` +
			`"project":"default","environments":[]` +
			`}}`))
	}))
	defer srv.Close()

	origServer, origPW := initServer, initAdminPassword
	defer func() { initServer = origServer; initAdminPassword = origPW }()
	initServer = srv.URL
	initAdminPassword = "admin" // matches the warning condition

	out := captureStdout(t, func() {
		require.NoError(t, runRemoteInit())
	})
	assert.Contains(t, out, "WARNING: You are using the default password")
}

// TestRunRemoteInit_EmptyEnvList exercises the fallback when the server
// returns an empty environments list ("development, staging, production").
func TestRunRemoteInit_EmptyEnvList(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"data":{` +
			`"already_initialized":false,"user":{"id":1,"username":"admin","email":"admin@example.com"},` +
			`"project":"myproj","environments":[]` +
			`}}`))
	}))
	defer srv.Close()

	origServer, origPW := initServer, initAdminPassword
	defer func() { initServer = origServer; initAdminPassword = origPW }()
	initServer = srv.URL
	initAdminPassword = "not-admin" // skip the default-password warning branch

	out := captureStdout(t, func() {
		require.NoError(t, runRemoteInit())
	})
	// The fallback env list is shown when server returns an empty slice.
	assert.Contains(t, out, "development, staging, production")
	assert.Contains(t, out, "myproj")
}

// ──────────────────────────── initializeDatabase ───────────────────────────

// TestInitializeDatabase_CreatesFile covers the "database doesn't exist yet" branch.
func TestInitializeDatabase_CreatesFile(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "secrets.db")

	cfg := &config.Config{
		Storage: config.StorageConfig{
			Database: config.DatabaseConfig{Path: dbPath},
		},
	}
	require.NoError(t, initializeDatabase(cfg))

	// The file must have been created.
	_, err := os.Stat(dbPath)
	require.NoError(t, err, "initializeDatabase should create the DB file when it doesn't exist")
}

// TestInitializeDatabase_ExistingFileIsOK confirms that calling initializeDatabase
// when the file already exists is a no-op (doesn't error).
func TestInitializeDatabase_ExistingFileIsOK(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "existing.db")

	// Pre-create the file.
	require.NoError(t, os.WriteFile(dbPath, []byte{}, 0600))

	cfg := &config.Config{
		Storage: config.StorageConfig{
			Database: config.DatabaseConfig{Path: dbPath},
		},
	}
	require.NoError(t, initializeDatabase(cfg))
}

// ──────────────────────────── initializeLogging ────────────────────────────

// TestInitializeLogging_CreatesLogFile covers the "log file doesn't exist" branch.
func TestInitializeLogging_CreatesLogFile(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	require.NoError(t, initializeLogging())
	// keyorix.log should have been created in the temp dir.
	_, err := os.Stat(filepath.Join(dir, "keyorix.log"))
	require.NoError(t, err, "initializeLogging should create keyorix.log")
}

// TestInitializeLogging_ExistingLogIsOK confirms that initializeLogging with an
// existing log file is a no-op.
func TestInitializeLogging_ExistingLogIsOK(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "keyorix.log"), []byte("existing"), 0600))
	require.NoError(t, initializeLogging())
}

// ──────────────────────────── initializeEncryption ─────────────────────────

// TestInitializeEncryption_CreatesDirectories exercises initializeEncryption:
// it should create the DEK and salt directories if they don't exist.
func TestInitializeEncryption_CreatesDirectories(t *testing.T) {
	dir := t.TempDir()
	dekPath := filepath.Join(dir, "keys", "dek.bin")
	saltPath := filepath.Join(dir, "keys", "salt.bin")

	cfg := &config.Config{
		Storage: config.StorageConfig{
			Encryption: config.EncryptionConfig{
				DEKPath:  dekPath,
				SaltPath: saltPath,
			},
		},
	}
	require.NoError(t, initializeEncryption(cfg))

	// Both key directories must exist.
	_, err := os.Stat(filepath.Dir(dekPath))
	require.NoError(t, err, "DEK directory should be created")
	_, err = os.Stat(filepath.Dir(saltPath))
	require.NoError(t, err, "salt directory should be created")
}
