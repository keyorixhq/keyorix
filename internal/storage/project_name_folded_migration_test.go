package storage

// project_name_folded_migration_test.go: ensureProjectNameIndex moves project-name
// uniqueness from SQL LOWER(name) to the Go-folded projects.name_folded column, so
// SQLite and PostgreSQL accept the same set of names. The upgrade must stop, with
// an error naming the clashing projects, when two live projects fold to the same
// name, and must not change a row in that case. The same table runs on SQLite
// always and on PostgreSQL when KEYORIX_TEST_PG_DSN is set.

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

const legacyProjectsDDL = `CREATE TABLE projects (
	id          INTEGER PRIMARY KEY,
	name        TEXT NOT NULL,
	description TEXT,
	require_mfa BOOLEAN DEFAULT false,
	created_at  TIMESTAMP,
	updated_at  TIMESTAMP,
	deleted_at  TIMESTAMP
)`

// legacyProjectsDB returns db holding the pre-name_folded schema: projects with the
// LOWER(name) partial unique index as first shipped.
func legacyProjectsDB(t *testing.T, db *gorm.DB) {
	t.Helper()
	require.NoError(t, db.Exec(legacyProjectsDDL).Error)
	require.NoError(t, db.Exec(
		"CREATE UNIQUE INDEX uniq_projects_name_active ON projects (LOWER(name)) WHERE deleted_at IS NULL AND name <> ''").Error)
}

func runProjectNameFoldedMigration(t *testing.T, db *gorm.DB) {
	t.Helper()
	legacyProjectsDB(t, db)
	ins := func(id int, name string, deleted bool) {
		del := "NULL"
		if deleted {
			del = "CURRENT_TIMESTAMP"
		}
		require.NoError(t, db.Exec("INSERT INTO projects (id, name, deleted_at) VALUES (?, ?, "+del+")", id, name).Error)
	}

	// Clean data: distinct names, a soft-deleted pair sharing a name (legitimate),
	// a decomposed name, and a legacy blank name.
	ins(1, "Payments", false)
	ins(2, "Zoë", false) // stored decomposed
	ins(3, "ÄÖ", true)
	ins(4, "äö", true)
	ins(5, "", false)

	require.NoError(t, ensureProjectNameIndex(db))
	require.NoError(t, ensureProjectNameIndex(db), "idempotent")

	var folded []struct {
		ID         int
		NameFolded string
	}
	require.NoError(t, db.Raw("SELECT id, name_folded FROM projects ORDER BY id").Scan(&folded).Error)
	want := map[int]string{1: "payments", 2: "zoë", 3: "äö", 4: "äö", 5: ""}
	for _, r := range folded {
		assert.Equal(t, want[r.ID], r.NameFolded, "name_folded of project %d", r.ID)
	}
	assert.Contains(t, indexDefinition(db, "uniq_projects_name_active"), "name_folded",
		"the legacy LOWER(name) index must be replaced")

	// The new index enforces the same fold on both backends.
	for _, clash := range []string{"PAYMENTS", "payments", "ZOË"} {
		err := db.Exec("INSERT INTO projects (id, name, name_folded) VALUES (100, ?, ?)", clash, foldForTest(clash)).Error
		require.Error(t, err, "%q must collide with a live project", clash)
	}
	// A soft-deleted name is free again.
	require.NoError(t, db.Exec("INSERT INTO projects (id, name, name_folded) VALUES (101, 'ÄÖ', 'äö')").Error)
	// ...and now a second live one with the same fold is refused (the Unicode case
	// that SQLite's ASCII-only LOWER() used to let through).
	require.Error(t, db.Exec("INSERT INTO projects (id, name, name_folded) VALUES (102, 'äö', 'äö')").Error)
}

func foldForTest(s string) string {
	switch s {
	case "PAYMENTS", "payments":
		return "payments"
	case "ZOË":
		return "zoë"
	}
	return s
}

func runProjectNameFoldedCollision(t *testing.T, db *gorm.DB) {
	t.Helper()
	legacyProjectsDB(t, db)
	// The legacy ASCII-only index (SQLite) lets these two through; on PostgreSQL
	// the legacy index would already have refused the second, so drop it first to
	// model "created before the validator existed / restored from a dump".
	require.NoError(t, db.Exec("DROP INDEX uniq_projects_name_active").Error)
	require.NoError(t, db.Exec("INSERT INTO projects (id, name) VALUES (1, 'ÄÖ'), (2, 'äö'), (3, 'Other')").Error)
	require.NoError(t, db.Exec(
		"CREATE UNIQUE INDEX uniq_projects_name_active ON projects (name) WHERE deleted_at IS NULL AND name <> ''").Error)

	err := ensureProjectNameIndex(db)
	require.Error(t, err, "two live projects folding to one name must stop the upgrade")
	assert.Contains(t, err.Error(), "projects")
	assert.Contains(t, err.Error(), "äö", "the error names the folded value")
	assert.Contains(t, err.Error(), "[1 2]", "the error names the project ids")
	assert.Contains(t, err.Error(), "UPDATE projects SET name", "the error says what to do")

	// Nothing was renamed, merged, deleted or backfilled.
	var names []string
	require.NoError(t, db.Raw("SELECT name FROM projects ORDER BY id").Scan(&names).Error)
	assert.Equal(t, []string{"ÄÖ", "äö", "Other"}, names)
	var filled int64
	require.NoError(t, db.Raw("SELECT COUNT(*) FROM projects WHERE name_folded <> ''").Scan(&filled).Error)
	assert.Zero(t, filled, "no row may be backfilled when the migration refuses")
	assert.NotContains(t, indexDefinition(db, "uniq_projects_name_active"), "name_folded")

	// After the operator renames one, the upgrade goes through.
	require.NoError(t, db.Exec("UPDATE projects SET name = 'ÄÖ renamed' WHERE id = 1").Error)
	require.NoError(t, ensureProjectNameIndex(db))
	assert.Contains(t, indexDefinition(db, "uniq_projects_name_active"), "name_folded")
}

func TestEnsureProjectNameIndex_FoldedMigration_SQLite(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "proj-folded.db"))
	require.NoError(t, err)
	runProjectNameFoldedMigration(t, db)
}

func TestEnsureProjectNameIndex_FoldedCollisionRefused_SQLite(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "proj-folded-collide.db"))
	require.NoError(t, err)
	runProjectNameFoldedCollision(t, db)
}

func TestEnsureProjectNameIndex_FoldedMigration_Postgres(t *testing.T) {
	db := pgRawOpen(t, pgIsolatedDatabaseDSN(t, pgTestDSN(t)))
	runProjectNameFoldedMigration(t, db)
}

func TestEnsureProjectNameIndex_FoldedCollisionRefused_Postgres(t *testing.T) {
	db := pgRawOpen(t, pgIsolatedDatabaseDSN(t, pgTestDSN(t)))
	runProjectNameFoldedCollision(t, db)
}
