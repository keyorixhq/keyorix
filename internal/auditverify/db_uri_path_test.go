package auditverify

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// REVIEW-AUDITVERIFY-KEYFILES-1: verify-audit --db (and a configured SQLite
// path) holding a byte SQLite's URI parser interprets must open exactly that
// file, read-only, and create nothing beside it.
func TestOpenSQLiteReadOnly_PathWithURICharacters(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"a?b.db", "c#d.db", "e%41f.db", "g.db?_pragma=journal_mode(delete)&x=", "h.db?mode=rwc"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			seed := filepath.Join(dir, "seed")
			w, err := sql.Open("sqlite", seed)
			require.NoError(t, err)
			_, err = w.Exec(`CREATE TABLE seeded(x)`)
			require.NoError(t, err)
			require.NoError(t, w.Close())
			data, err := os.ReadFile(seed)
			require.NoError(t, err)
			require.NoError(t, os.Remove(seed))
			path := filepath.Join(dir, name)
			require.NoError(t, os.WriteFile(path, data, 0o600))

			db, err := OpenSQLiteReadOnly(path)
			require.NoError(t, err)
			defer func() { _ = db.Close() }()
			var n int
			require.NoError(t, db.sql.QueryRow(`SELECT count(*) FROM sqlite_master WHERE name = 'seeded'`).Scan(&n))
			assert.Equal(t, 1, n, "opened a different file than the one named")
			_, err = db.sql.Exec(`CREATE TABLE written(x)`)
			assert.Error(t, err, "the artifact must be opened read-only")

			ents, err := os.ReadDir(dir)
			require.NoError(t, err)
			require.Len(t, ents, 1, "nothing may be created beside the artifact")
		})
	}
}
