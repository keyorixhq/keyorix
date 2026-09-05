package storage

// account_state_backfill_postgres_test.go — the real-Postgres counterpart to
// account_state_backfill_test.go's TestGuardAccountStateValid_NoOpOnSQLite:
// proves the CHECK constraint actually rejects blank and non-canonical writes
// on the one dialect it's meant to protect. Skips (KEYORIX_TEST_PG_DSN unset)
// when no real Postgres server is available, same convention as
// factory_rbac_pk_rebuild_postgres_test.go.

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGuardAccountStateValid_Postgres_RejectsBlankAndGarbageWrites(t *testing.T) {
	base := pgTestDSN(t)
	db := pgRawOpen(t, pgIsolatedDatabaseDSN(t, base))

	require.NoError(t, db.Exec(`CREATE TABLE users (id INTEGER PRIMARY KEY, account_state TEXT)`).Error)
	require.NoError(t, guardAccountStateValid(db))

	// Every canonical value still succeeds.
	for i, v := range ValidAccountStateSQLValues {
		require.NoError(t, db.Exec(`INSERT INTO users VALUES (?, ?)`, i+1, v).Error, "canonical value %q must be accepted", v)
	}

	// An empty-string write is refused at the database.
	err := db.Exec(`INSERT INTO users VALUES (100, '')`).Error
	require.Error(t, err, "an empty account_state must be refused by the CHECK constraint")
	assert.Contains(t, err.Error(), "chk_users_account_state_valid")

	// A whitespace-only write is ALSO refused (not a member of the enum list).
	err = db.Exec(`INSERT INTO users VALUES (101, '   ')`).Error
	require.Error(t, err, "a whitespace-only account_state must also be refused")

	// A non-blank but non-canonical (garbage/typo) value is refused too --
	// the entire reason for the enum allow-list over a plain non-empty check.
	err = db.Exec(`INSERT INTO users VALUES (102, 'Active')`).Error
	require.Error(t, err, "a non-canonical value (wrong casing) must be refused")
	err = db.Exec(`INSERT INTO users VALUES (103, 'deleted')`).Error
	require.Error(t, err, "a non-canonical value (made-up state) must be refused")

	// Re-applying the guard on a database that already has the constraint is
	// a no-op, not an error (idempotent, matching every other ensure*/guard*
	// migration helper in this package).
	require.NoError(t, guardAccountStateValid(db))
}

// TestGuardAccountStateValid_Postgres_ReplacesSupersededConstraint proves the
// upgrade path from the first version of this constraint
// (chk_users_account_state_not_blank, a plain non-empty check) to the current
// enum allow-list: a database that already has the old constraint (and no
// data that would violate the new one) gets it dropped and replaced, not left
// in place alongside the new one.
func TestGuardAccountStateValid_Postgres_ReplacesSupersededConstraint(t *testing.T) {
	base := pgTestDSN(t)
	db := pgRawOpen(t, pgIsolatedDatabaseDSN(t, base))

	require.NoError(t, db.Exec(`CREATE TABLE users (id INTEGER PRIMARY KEY, account_state TEXT)`).Error)
	require.NoError(t, db.Exec(`ALTER TABLE users ADD CONSTRAINT chk_users_account_state_not_blank CHECK (btrim(account_state) <> '')`).Error)
	require.NoError(t, db.Exec(`INSERT INTO users VALUES (1, 'active')`).Error)

	require.NoError(t, guardAccountStateValid(db))

	var oldExists bool
	require.NoError(t, db.Raw(
		"SELECT EXISTS (SELECT 1 FROM information_schema.table_constraints WHERE constraint_name = 'chk_users_account_state_not_blank' AND table_name = 'users')",
	).Scan(&oldExists).Error)
	assert.False(t, oldExists, "the superseded constraint must be dropped, not left in place")

	// The new constraint governs writes now -- a value that would have passed
	// the old one is refused.
	err := db.Exec(`INSERT INTO users VALUES (2, 'another-garbage-value')`).Error
	require.Error(t, err, "the new enum constraint must govern writes after the upgrade")
	assert.Contains(t, err.Error(), "chk_users_account_state_valid")
}

// TestGuardAccountStateValid_Postgres_FailsLoudlyOnPreexistingGarbageRow
// covers the case the previous test deliberately avoids: an existing row
// already holds a non-blank, non-canonical value (a typo or some unrelated
// historical bug -- backfillBlankAccountState only ever fixes BLANK rows, so
// this is untouched by it) when the enum constraint is first added. Postgres
// refuses the ADD CONSTRAINT outright; this proves the resulting error names
// the offending row/value instead of surfacing Postgres's own generic
// "violated by some row" message, which names nothing an operator could act
// on. This failure is intentional and fatal (migrateDatabase's caller aborts
// server startup on it) -- better a clearly-diagnosable refusal to start than
// silently leaving the schema-level guarantee unenforced.
func TestGuardAccountStateValid_Postgres_FailsLoudlyOnPreexistingGarbageRow(t *testing.T) {
	base := pgTestDSN(t)
	db := pgRawOpen(t, pgIsolatedDatabaseDSN(t, base))

	require.NoError(t, db.Exec(`CREATE TABLE users (id INTEGER PRIMARY KEY, account_state TEXT)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO users VALUES (1, 'active')`).Error)
	require.NoError(t, db.Exec(`INSERT INTO users VALUES (42, 'some-garbage-value')`).Error)

	err := guardAccountStateValid(db)
	require.Error(t, err, "a pre-existing non-canonical row must fail the constraint add, not be silently ignored")
	assert.Contains(t, err.Error(), "user 42")
	assert.Contains(t, err.Error(), "some-garbage-value")
	assert.Contains(t, err.Error(), "administrator")
}
