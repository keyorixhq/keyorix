package storage

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBackfillBlankAccountState_BackfillsBlankNullAndWhitespace covers all
// three shapes a "legacy unset" account_state can take -- empty string, SQL
// NULL, and whitespace-only (a value that would pass a naive `= ”` check but
// still normalizes to blank under strings.TrimSpace, and reads as blank to
// NormalizeAccountState's own switch since it's not any recognized state
// string either) -- plus a genuinely-set control row that must be left alone.
func TestBackfillBlankAccountState_BackfillsBlankNullAndWhitespace(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "account-state-blank-null-ws.db"))
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE users (id INTEGER PRIMARY KEY, account_state TEXT, deleted_at DATETIME)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO users VALUES (1, '', NULL)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO users VALUES (2, NULL, NULL)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO users VALUES (3, '   ', NULL)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO users VALUES (4, 'suspended', NULL)`).Error)

	require.NoError(t, backfillBlankAccountState(db))

	type row struct {
		ID           uint
		AccountState string
	}
	var rows []row
	require.NoError(t, db.Table("users").Order("id").Find(&rows).Error)
	require.Len(t, rows, 4)
	assert.Equal(t, "active", rows[0].AccountState, "empty string must be backfilled")
	assert.Equal(t, "active", rows[1].AccountState, "NULL must be backfilled")
	assert.Equal(t, "active", rows[2].AccountState, "whitespace-only must be backfilled")
	assert.Equal(t, "suspended", rows[3].AccountState, "an already-set state must be left completely alone")
}

// TestBackfillBlankAccountState_ExcludesSoftDeletedRows: a soft-deleted user's
// blank account_state is not a live login-eligibility landmine (DeleteUser
// already blocks login independently via deleted_at), so it's intentionally
// left alone rather than rewritten -- matches the deleted_at-scoping every
// other backfill* helper in this file uses.
func TestBackfillBlankAccountState_ExcludesSoftDeletedRows(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "account-state-softdeleted.db"))
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE users (id INTEGER PRIMARY KEY, account_state TEXT, deleted_at DATETIME)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO users VALUES (1, '', '2026-01-01 00:00:00')`).Error)

	require.NoError(t, backfillBlankAccountState(db))

	var state string
	require.NoError(t, db.Table("users").Select("account_state").Where("id = 1").Scan(&state).Error)
	assert.Equal(t, "", state, "a soft-deleted row's account_state is not touched")
}

// TestBackfillBlankAccountState_NoOpWhenNothingBlank proves the idempotency
// every other backfill* helper in this package guarantees: re-running finds
// nothing to do and touches nothing.
func TestBackfillBlankAccountState_NoOpWhenNothingBlank(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "account-state-noop.db"))
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE users (id INTEGER PRIMARY KEY, account_state TEXT, deleted_at DATETIME)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO users VALUES (1, 'active', NULL)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO users VALUES (2, 'pending_first_login', NULL)`).Error)

	require.NoError(t, backfillBlankAccountState(db))

	var state1, state2 string
	require.NoError(t, db.Table("users").Select("account_state").Where("id = 1").Scan(&state1).Error)
	require.NoError(t, db.Table("users").Select("account_state").Where("id = 2").Scan(&state2).Error)
	assert.Equal(t, "active", state1)
	assert.Equal(t, "pending_first_login", state2)
}

// TestGuardAccountStateNotBlank_NoOpOnSQLite: the CHECK constraint is
// Postgres-only (see the function's own doc for why) -- on SQLite this must
// be a clean no-op, not an error, since every local/dev/test database in
// this repo runs on SQLite.
func TestGuardAccountStateNotBlank_NoOpOnSQLite(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "account-state-guard-sqlite.db"))
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE users (id INTEGER PRIMARY KEY, account_state TEXT)`).Error)
	require.NoError(t, guardAccountStateNotBlank(db))
	// A blank write must still succeed on SQLite -- confirms no constraint
	// was (incorrectly) applied here.
	require.NoError(t, db.Exec(`INSERT INTO users VALUES (1, '')`).Error)
}
