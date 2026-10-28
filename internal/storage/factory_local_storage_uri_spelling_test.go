package storage

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/sqlitepath"
)

// STARTUP-GUARD-TAILS-1 item 3: SQLite opens a "file:" URI as the database
// at its path, and the server lock sidecar already resolves it that way
// (serverguard's TestSQLiteURISpellings_MeetOnTheSameLock, whose spelling
// table this test shares). localStorageDBFile and the migration lock took the
// raw string: "file:/data/secrets.db" pre-created a junk relative
// "file:/data/..." tree, the real database was born at the process umask
// until tightenExistingLocalStorageFiles corrected it after Open, and a
// process on the URI and one on the plain path took different migration
// locks on one database.

// uriSpellingDir is a fresh working directory with a space and a literal "%"
// (no hex digits after it) in its name, and the canonical database path in it.
func uriSpellingDir(t *testing.T) (dir, canonical string) {
	t.Helper()
	dir = filepath.Join(t.TempDir(), "my data 100%")
	require.NoError(t, os.MkdirAll(dir, 0o700))
	t.Chdir(dir)
	return dir, filepath.Join(dir, "secrets.db")
}

// requireNoURIJunk fails if anything named after the raw "file:" string was
// created under dir.
func requireNoURIJunk(t *testing.T, dir, spelling string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	for _, e := range entries {
		require.False(t, strings.HasPrefix(e.Name(), "file:"), "%q created %q in the working directory", spelling, e.Name())
	}
}

func TestLocalStorageDBFile_URISpellingsPreCreateTheRealDatabase(t *testing.T) {
	_, probe := uriSpellingDir(t)
	for i := range sqlitepath.URISpellings(probe) {
		dir, canonical := uriSpellingDir(t)
		spelling := sqlitepath.URISpellings(canonical)[i]
		t.Run(strings.ReplaceAll(spelling, dir, "<dir>"), func(t *testing.T) {
			got, real := localStorageDBFile(spelling)
			require.True(t, real)
			abs, err := filepath.Abs(got)
			require.NoError(t, err)
			require.Equal(t, canonical, abs)

			withUmask(t, 0o000, func() {
				require.NoError(t, prepareLocalStorageFile(spelling))
			})
			assertMode(t, canonical, 0o600)
			requireNoURIJunk(t, dir, spelling)

			// The URI and the plain path are one database: they take one lock.
			held, err := acquireSQLiteMigrationLock(canonical)
			require.NoError(t, err)
			require.NotNil(t, held)
			second, err := acquireSQLiteMigrationLock(spelling)
			if err == nil {
				second.release()
			}
			held.release()
			require.Error(t, err, "a process on %q took the migration lock while one on the plain path held it", spelling)
			requireNoURIJunk(t, dir, spelling)
		})
	}
}

func TestCreateLocalStorage_URISpelling_BornSecureWithNoJunk(t *testing.T) {
	dir, canonical := uriSpellingDir(t)
	spelling := "file:" + strings.ReplaceAll(canonical, " ", "%20") + "?_busy_timeout=5000"
	cfg := &config.Config{Storage: config.StorageConfig{Database: config.DatabaseConfig{Path: spelling}}}
	var s any
	withUmask(t, 0o022, func() {
		var err error
		s, err = (&DefaultStorageFactory{}).createLocalStorage(cfg)
		require.NoError(t, err)
	})
	if closer, ok := s.(interface{ Close() error }); ok {
		defer func() { _ = closer.Close() }()
	}
	assertMode(t, canonical, 0o600)
	requireNoURIJunk(t, dir, spelling)
}

func TestLocalStorageDBFile_OnlyTheQueryMarksInMemory(t *testing.T) {
	for _, mem := range sqlitepath.InMemorySpellings {
		_, real := localStorageDBFile(mem)
		require.False(t, real, "%q is in-memory", mem)
	}
	p := filepath.Join(t.TempDir(), "mode=memory", "secrets.db")
	got, real := localStorageDBFile(p)
	require.True(t, real, "a real database under a directory named mode=memory")
	require.Equal(t, p, got)
}
