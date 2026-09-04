package storage

// account_state_backfill_postgres_test.go — the real-Postgres counterpart to
// account_state_backfill_test.go's TestGuardAccountStateNotBlank_NoOpOnSQLite:
// proves the CHECK constraint actually rejects a blank write on the one
// dialect it's meant to protect. Skips (KEYORIX_TEST_PG_DSN unset) when no
// real Postgres server is available, same convention as
// factory_rbac_pk_rebuild_postgres_test.go.

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGuardAccountStateNotBlank_Postgres_RejectsBlankWrite(t *testing.T) {
	base := pgTestDSN(t)
	db := pgRawOpen(t, pgIsolatedDatabaseDSN(t, base))

	require.NoError(t, db.Exec(`CREATE TABLE users (id INTEGER PRIMARY KEY, account_state TEXT)`).Error)
	require.NoError(t, guardAccountStateNotBlank(db))

	// A non-blank write still succeeds.
	require.NoError(t, db.Exec(`INSERT INTO users VALUES (1, 'active')`).Error)

	// An empty-string write is refused at the database.
	err := db.Exec(`INSERT INTO users VALUES (2, '')`).Error
	require.Error(t, err, "an empty account_state must be refused by the CHECK constraint")
	assert.Contains(t, err.Error(), "chk_users_account_state_not_blank")

	// A whitespace-only write is ALSO refused (the constraint uses btrim,
	// matching backfillBlankAccountState's own strings.TrimSpace definition
	// of "blank").
	err = db.Exec(`INSERT INTO users VALUES (3, '   ')`).Error
	require.Error(t, err, "a whitespace-only account_state must also be refused")

	// Re-applying the guard on a database that already has the constraint is
	// a no-op, not an error (idempotent, matching every other ensure*/guard*
	// migration helper in this package).
	require.NoError(t, guardAccountStateNotBlank(db))
}
