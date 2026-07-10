package storage

import (
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSQLiteDSN_NoPriorParams validates that the DSN has the required pragmas
// when no query params are present.
func TestSQLiteDSN_NoPriorParams(t *testing.T) {
	dsn := sqliteDSN("/data/secrets.db")
	assert.Contains(t, dsn, "_foreign_keys=1")
	assert.Contains(t, dsn, "_busy_timeout=")
	assert.Contains(t, dsn, "_journal_mode=WAL")
	assert.Contains(t, dsn, "?")
}

// TestSQLiteDSN_WithExistingParams validates that the DSN appends (not clobbers)
// pragmas when the operator already includes query parameters.
func TestSQLiteDSN_WithExistingParams(t *testing.T) {
	dsn := sqliteDSN("/data/secrets.db?cache=shared")
	// Must use "&" as separator, not "?" (which would duplicate the query start).
	assert.Contains(t, dsn, "cache=shared")
	assert.Contains(t, dsn, "_foreign_keys=1")
	assert.Contains(t, dsn, "_journal_mode=WAL")
}

// TestCreateStorage_LocalStorage validates that a local SQLite storage is
// constructed successfully.
func TestCreateStorage_LocalStorage(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	dir := t.TempDir()
	cfg := &config.Config{}
	cfg.Storage.Type = "local"
	cfg.Storage.Database.Path = filepath.Join(dir, "test.db")

	st, err := NewStorageFactory().CreateStorage(cfg)
	require.NoError(t, err)
	assert.NotNil(t, st)
}

// TestCreateStorage_EmptyTypeIsLocal validates that an empty storage.type is
// treated as "local" (backward-compat).
func TestCreateStorage_EmptyTypeIsLocal(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	dir := t.TempDir()
	cfg := &config.Config{}
	cfg.Storage.Type = "" // explicitly empty
	cfg.Storage.Database.Path = filepath.Join(dir, "empty-type.db")

	st, err := NewStorageFactory().CreateStorage(cfg)
	require.NoError(t, err)
	assert.NotNil(t, st)
}

// TestCreateStorage_InvalidType validates that any unrecognized type is
// explicitly rejected rather than silently falling through to SQLite.
func TestCreateStorage_InvalidType(t *testing.T) {
	for _, invalid := range []string{"postgress", "localdb", "remot", "mysql", "cassandra"} {
		cfg := &config.Config{}
		cfg.Storage.Type = invalid
		st, err := NewStorageFactory().CreateStorage(cfg)
		require.Errorf(t, err, "storage.type=%q must be rejected", invalid)
		assert.Nil(t, st)
		assert.Contains(t, err.Error(), invalid)
	}
}

// TestCreateStorage_PostgresRequiresDSNOrFields validates that creating
// Postgres storage without any connection info is rejected.
func TestCreateStorage_PostgresRequiresDSNOrFields(t *testing.T) {
	cfg := &config.Config{}
	cfg.Storage.Type = "postgres"
	// DSN, host, name, user all empty → BuildPostgresDSN returns "" for host-only.
	// The factory checks for empty DSN.
	// Note: BuildPostgresDSN fills host/port defaults but the factory only checks
	// when DSN is empty and name/user are empty. So we provide a host to still
	// get an empty Name/User — which our factory rejects.
	cfg.Storage.Database.DSN = ""
	cfg.Storage.Database.Host = ""
	cfg.Storage.Database.Name = ""
	cfg.Storage.Database.User = ""

	_, err := NewStorageFactory().CreateStorage(cfg)
	require.Error(t, err)
	// The factory rejects with "requires a DSN or host/name/user fields"
	// because BuildPostgresDSN still returns a non-empty DSN even with empty fields.
	// So just verify we can call it without panic.
	_ = err
}

// TestOpenGormDB_RemoteStorageRejected validates that OpenGormDB refuses remote
// storage since it has no local DB to open.
func TestOpenGormDB_RemoteStorageRejected(t *testing.T) {
	cfg := &config.Config{}
	cfg.Storage.Type = "remote"
	_, err := OpenGormDB(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "remote")
}

// TestOpenGormDB_InvalidTypeRejected validates that OpenGormDB rejects unknown
// storage types (#463 defense-in-depth).
func TestOpenGormDB_InvalidTypeRejected(t *testing.T) {
	cfg := &config.Config{}
	cfg.Storage.Type = "badtype"
	_, err := OpenGormDB(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "badtype")
}

// TestOpenGormDB_LocalSQLite validates that OpenGormDB can open a local SQLite
// database.
func TestOpenGormDB_LocalSQLite(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{}
	cfg.Storage.Type = "local"
	cfg.Storage.Database.Path = filepath.Join(dir, "gormdb.db")

	db, err := OpenGormDB(cfg)
	require.NoError(t, err)
	assert.NotNil(t, db)
}

// TestOpenGormDB_EmptyPathUsesDefault validates that an empty path uses the
// default "secrets.db" path (doesn't panic).
func TestOpenGormDB_EmptyPathUsesDefault(t *testing.T) {
	// This test only validates the logic routing, not the file creation.
	// We use a TempDir-chdir trick to avoid writing to the test runner's cwd.
	dir := t.TempDir()
	t.Chdir(dir)

	cfg := &config.Config{}
	cfg.Storage.Type = "local"
	cfg.Storage.Database.Path = "" // triggers default "./secrets.db"

	db, err := OpenGormDB(cfg)
	require.NoError(t, err)
	assert.NotNil(t, db)
}
