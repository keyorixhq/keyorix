package storage

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func setsJournalSizeLimit(dsn string) bool {
	return strings.Contains(strings.ToLower(dsn), "journal_size_limit")
}

// TestSqliteDSN_JournalSizeLimit pins the fdatasync documentation's promise
// ("Committing with fdatasync" in docs/CONFIGURATION.md): the DSN builder does
// not set journal_size_limit, because a limit makes SQLite truncate the WAL after
// a checkpoint, so commits extend the file again and storage.database.fdatasync
// loses most of its gain. An operator who supplies their own value keeps it.
func TestSqliteDSN_JournalSizeLimit(t *testing.T) {
	t.Run("not set by default", func(t *testing.T) {
		for _, path := range []string{"/tmp/foo.db", "file:mydb?mode=memory"} {
			dsn := sqliteDSN(path)
			assert.False(t, setsJournalSizeLimit(dsn), "DSN for %q must not set a journal size limit: %s", path, dsn)
		}
	})
	// The pin is green on main by design; this proves the same predicate goes
	// red on a DSN that does set the limit, using a literal instead of editing
	// production code.
	t.Run("detector flags a DSN that sets the limit", func(t *testing.T) {
		wrong := "/tmp/foo.db?_pragma=busy_timeout(5000)&_pragma=journal_size_limit(67108864)"
		assert.True(t, setsJournalSizeLimit(wrong), "a DSN with journal_size_limit must be flagged: %s", wrong)
	})
	t.Run("operator-supplied value passes through untouched", func(t *testing.T) {
		const supplied = "_pragma=journal_size_limit(67108864)"
		dsn := sqliteDSN("/tmp/foo.db?" + supplied)
		assert.Equal(t, 1, strings.Count(dsn, "journal_size_limit"), "the operator's value must appear exactly once: %s", dsn)
		assert.True(t, strings.HasPrefix(dsn, "/tmp/foo.db?"+supplied+"&"), "the operator's parameter must stay verbatim and first: %s", dsn)
	})
}
