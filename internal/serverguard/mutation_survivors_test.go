package serverguard

// MUTANT-SEC-3: effects a gremlins mutant of serverguard.go left unchanged.

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
)

func TestSQLiteLockPath_ExactSpellings(t *testing.T) {
	for _, tc := range []struct {
		name, db, want string
		real           bool
	}{
		{"empty path uses the default database", "", "./secrets.db" + serverLockSuffix, true},
		{"plain path", "/data/secrets.db", "/data/secrets.db" + serverLockSuffix, true},
		{"query is not part of the file", "/data/secrets.db?mode=ro", "/data/secrets.db" + serverLockSuffix, true},
		{"memory database", ":memory:", "", false},
		{"memory by query", "file:x.db?mode=memory&mode2=x", "", false},
		{"mode=memory in a directory name is a real file", "/data/mode=memory/secrets.db", "/data/mode=memory/secrets.db" + serverLockSuffix, true},
		{"file: with an absolute path", "file:/data/secrets.db", "/data/secrets.db" + serverLockSuffix, true},
		{"file: with an empty authority", "file:///data/secrets.db", "/data/secrets.db" + serverLockSuffix, true},
		{"file: with the localhost authority", "file://localhost/data/secrets.db", "/data/secrets.db" + serverLockSuffix, true},
		{"file: with percent-encoding", "file:/data/my%20secrets.db", "/data/my secrets.db" + serverLockSuffix, true},
		{"file: with a fragment", "file:/data/secrets.db#frag", "/data/secrets.db" + serverLockSuffix, true},
		{"file: relative", "file:secrets.db", "secrets.db" + serverLockSuffix, true},
		{"file: with another authority is left alone", "file://otherhost/data/secrets.db", "//otherhost/data/secrets.db" + serverLockSuffix, true},
		{"file: with nothing after it", "file:", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{}
			cfg.Storage.Database.Path = tc.db
			got, real := sqliteLockPath(cfg)
			assert.Equal(t, tc.want, got)
			assert.Equal(t, tc.real, real)
		})
	}
}

// check() on a sidecar that still names the file it holds must leave the held
// file alone: no re-open, no warning.
func TestSidecarWatchCheck_IntactSidecarIsLeftAlone(t *testing.T) {
	_, lockPath := sqliteGuardCfg(t)
	f, err := lockSidecar(lockPath, 1) // syscall.LOCK_SH
	require.NoError(t, err)
	t.Cleanup(func() { _ = f.Close() })
	w := &sidecarWatch{path: lockPath, f: f}

	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	require.NoError(t, w.check())
	assert.Same(t, f, w.f, "an intact sidecar keeps the same open file")
	assert.NotContains(t, buf.String(), "was deleted or replaced")

	// Deleted: the watch re-creates the file and holds the new one.
	require.NoError(t, os.Remove(lockPath))
	require.NoError(t, w.check())
	assert.NotSame(t, f, w.f, "a deleted sidecar is re-opened")
	_, statErr := os.Stat(lockPath)
	require.NoError(t, statErr, "the file is back")
	assert.True(t, strings.Contains(buf.String(), "was deleted or replaced"), buf.String())
	_ = w.f.Close()
}

// An unreachable PostgreSQL server is a clear connect error from the presence
// guard's own connection, not a nil connection.
func TestPgConn_UnreachableServerIsAnError(t *testing.T) {
	cfg := &config.Config{}
	cfg.Storage.Type = "postgres"
	cfg.Storage.Database.DSN = "postgres://nobody@127.0.0.1:1/nodb?sslmode=disable&connect_timeout=2"
	db, conn, err := pgConn(cfg)
	require.Error(t, err)
	assert.Nil(t, db)
	assert.Nil(t, conn)
	assert.Contains(t, err.Error(), "connect to postgres for server-presence check")
}

func TestPgConn_UnresolvableConfigIsAnErrorBeforeAnyConnection(t *testing.T) {
	cfg := &config.Config{}
	cfg.Storage.Type = "postgres"
	cfg.Storage.Database.DSN = "://not a dsn"
	db, conn, err := pgConn(cfg)
	require.Error(t, err)
	assert.Nil(t, db)
	assert.Nil(t, conn)
	assert.NotContains(t, err.Error(), "connect to postgres for server-presence check")
}

// openLockFile creates the lock file's missing parent directories (private),
// and works for a bare file name in the working directory.
func TestOpenLockFile_CreatesMissingParentDirectories(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a", "b", "secrets.db"+serverLockSuffix)
	f, err := openLockFile(path)
	require.NoError(t, err)
	require.NoError(t, f.Close())
	fi, err := os.Stat(filepath.Dir(path))
	require.NoError(t, err)
	assert.True(t, fi.IsDir())
	assert.Equal(t, os.FileMode(0o750), fi.Mode().Perm()&0o750)
	assert.Zero(t, fi.Mode().Perm()&0o007, "no access for others")
}

func TestOpenLockFile_BareNameUsesTheWorkingDirectory(t *testing.T) {
	t.Chdir(t.TempDir())
	f, err := openLockFile("secrets.db" + serverLockSuffix)
	require.NoError(t, err)
	require.NoError(t, f.Close())
	_, err = os.Stat("secrets.db" + serverLockSuffix)
	require.NoError(t, err)
}
