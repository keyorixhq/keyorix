package storage

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// nfcCafe/nfdCafe reproduce #1642's exact live-demonstrated collision: two
// byte-different, visually-identical representations of "cafe" + acute
// accent, built from actual combining-character bytes (not a typed/pasted
// glyph, which risks silent editor/tool re-normalization to NFC).
var (
	nfcCafe = "café"   // e-acute precomposed (U+00E9), 5 bytes UTF-8
	nfdCafe = "café" // e (U+0065) + combining acute accent (U+0301), 6 bytes UTF-8
)

// TestBackfillFoldedColumn_RefusesOnCollision pins the user's explicit design
// requirement for #1642's migration: a backfill that discovers two existing
// rows normalize to the same identity must refuse outright (write NOTHING)
// and name every colliding row, never auto-resolve by merging or dropping
// one — silently merging two identities is the worst possible outcome of a
// normalization migration.
func TestBackfillFoldedColumn_RefusesOnCollision(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "backfill-collision.db"))
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, username_folded TEXT, deleted_at DATETIME)`).Error)

	// Two independent colliding pairs in one pass: a pure case collision
	// ("Admin"/"admin") and an NFC/NFD collision (the café pair).
	require.NoError(t, db.Exec(`INSERT INTO users VALUES (1, 'Admin', '', NULL)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO users VALUES (2, 'admin', '', NULL)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO users VALUES (3, ?, '', NULL)`, nfcCafe).Error)
	require.NoError(t, db.Exec(`INSERT INTO users VALUES (4, ?, '', NULL)`, nfdCafe).Error)
	// A non-colliding row must be unaffected by the refusal.
	require.NoError(t, db.Exec(`INSERT INTO users VALUES (5, 'bob', '', NULL)`).Error)

	err = backfillFoldedColumn(db, "users", "id", "username", "username_folded", "", foldIdentity)
	require.Error(t, err, "two colliding row groups must refuse the entire backfill")
	assert.Contains(t, err.Error(), "admin", "error must name the colliding folded value")
	assert.Contains(t, err.Error(), "cannot backfill users.username_folded")

	// Nothing was written -- not even the non-colliding row -- since the
	// collision check runs before any write.
	var stillEmpty int64
	require.NoError(t, db.Table("users").Where("username_folded = ''").Count(&stillEmpty).Error)
	assert.Equal(t, int64(5), stillEmpty, "no row may be written once a collision is found, including non-colliding ones")
}

// TestBackfillFoldedColumn_HappyPathBackfillsDistinctRows verifies the
// non-collision path: every row with a genuinely distinct folded identity
// gets its username_folded populated, and re-running is a no-op (only rows
// with an empty/NULL folded column are re-examined).
func TestBackfillFoldedColumn_HappyPathBackfillsDistinctRows(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "backfill-happy.db"))
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, username_folded TEXT, deleted_at DATETIME)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO users VALUES (1, 'Alice', '', NULL)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO users VALUES (2, 'Bob', '', NULL)`).Error)

	require.NoError(t, backfillFoldedColumn(db, "users", "id", "username", "username_folded", "", foldIdentity))

	var got1, got2 string
	require.NoError(t, db.Table("users").Where("id = 1").Select("username_folded").Scan(&got1).Error)
	require.NoError(t, db.Table("users").Where("id = 2").Select("username_folded").Scan(&got2).Error)
	assert.Equal(t, "alice", got1)
	assert.Equal(t, "bob", got2)

	// Manually corrupt row 1's folded value, then re-run: since it's no
	// longer empty, the backfill must leave it untouched (only empty/NULL
	// rows are re-examined) -- proving the "only if empty" skip works.
	require.NoError(t, db.Exec(`UPDATE users SET username_folded = 'manually-set' WHERE id = 1`).Error)
	require.NoError(t, backfillFoldedColumn(db, "users", "id", "username", "username_folded", "", foldIdentity))
	var afterRerun string
	require.NoError(t, db.Table("users").Where("id = 1").Select("username_folded").Scan(&afterRerun).Error)
	assert.Equal(t, "manually-set", afterRerun, "a non-empty folded column must not be recomputed")
}

// TestNormalizeColumnInPlace_RefusesOnCollision mirrors the FoldedColumn
// collision-refusal test above, for the in-place NFC-only normalizer used by
// secret_nodes.name (no separate folded column -- see normalize_backfill.go).
func TestNormalizeColumnInPlace_RefusesOnCollision(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "normalize-collision.db"))
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE secret_nodes (id INTEGER PRIMARY KEY, name TEXT, deleted_at DATETIME)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO secret_nodes VALUES (1, ?, NULL)`, nfcCafe).Error)
	require.NoError(t, db.Exec(`INSERT INTO secret_nodes VALUES (2, ?, NULL)`, nfdCafe).Error)

	err = normalizeColumnInPlace(db, "secret_nodes", "id", "name", "", normalizeAddress)
	require.Error(t, err, "two rows normalizing to the same NFC form must refuse the entire pass")
	assert.Contains(t, err.Error(), "cannot normalize secret_nodes.name")

	// Case is NOT folded for addresses -- "PROD_KEY" and "prod_key" must stay
	// distinct, so normalizing must NOT report them as colliding.
	db2, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "normalize-case.db"))
	require.NoError(t, err)
	require.NoError(t, db2.Exec(`CREATE TABLE secret_nodes (id INTEGER PRIMARY KEY, name TEXT, deleted_at DATETIME)`).Error)
	require.NoError(t, db2.Exec(`INSERT INTO secret_nodes VALUES (1, 'PROD_KEY', NULL)`).Error)
	require.NoError(t, db2.Exec(`INSERT INTO secret_nodes VALUES (2, 'prod_key', NULL)`).Error)
	require.NoError(t, normalizeColumnInPlace(db2, "secret_nodes", "id", "name", "", normalizeAddress),
		"case-distinct secret names must not be treated as colliding")
}
