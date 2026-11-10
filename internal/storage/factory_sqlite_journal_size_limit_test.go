package storage

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestSqliteDSN_JournalSizeLimit pins the fdatasync documentation's promise
// ("Committing with fdatasync" in docs/CONFIGURATION.md): the DSN builder does
// not set journal_size_limit, because a limit makes SQLite truncate the WAL after
// a checkpoint, so commits extend the file again and storage.database.fdatasync
// loses most of its gain. An operator who supplies their own value keeps it.
func TestSqliteDSN_JournalSizeLimit(t *testing.T) {
	t.Run("not set by default", func(t *testing.T) {
		for _, path := range []string{"/tmp/foo.db", "file:mydb?mode=memory"} {
			dsn := sqliteDSN(path)
			assert.NotContains(t, strings.ToLower(dsn), "journal_size_limit", "DSN for %q must not set a journal size limit: %s", path, dsn)
		}
	})
	t.Run("operator-supplied value passes through untouched", func(t *testing.T) {
		const supplied = "_pragma=journal_size_limit(67108864)"
		dsn := sqliteDSN("/tmp/foo.db?" + supplied)
		assert.Equal(t, 1, strings.Count(dsn, "journal_size_limit"), "the operator's value must appear exactly once: %s", dsn)
		assert.True(t, strings.HasPrefix(dsn, "/tmp/foo.db?"+supplied+"&"), "the operator's parameter must stay verbatim and first: %s", dsn)
	})
}
