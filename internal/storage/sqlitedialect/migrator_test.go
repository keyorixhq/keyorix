package sqlite

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type migratorTestModel struct {
	ID    uint   `gorm:"primaryKey"`
	Name  string `gorm:"uniqueIndex:idx_migrator_name"`
	Email string
	Score int `gorm:"check:chk_migrator_score,score >= 0"`
}

type constraintTestModel struct {
	ID   uint   `gorm:"primaryKey"`
	Slug string `gorm:"unique"`
}

// likeEscapeTestModel's constraint name deliberately contains no '_' — the adversarial
// query in TestMigrator_HasConstraint_EscapesLikeWildcards below supplies '_' characters
// instead, in the exact positions this model's real 'X's sit, to prove they're no longer
// treated as SQL LIKE wildcards.
type likeEscapeTestModel struct {
	ID    uint `gorm:"primaryKey"`
	Score int  `gorm:"check:chkXaXscore,score >= 0"`
}

func TestMigrator_HasTable(t *testing.T) {
	db := openTestDB(t)
	require.NoError(t, db.AutoMigrate(&migratorTestModel{}))
	m := db.Migrator()

	assert.True(t, m.HasTable(&migratorTestModel{}))
	assert.False(t, m.HasTable("does_not_exist"))
}

func TestMigrator_HasColumnAndDropColumn(t *testing.T) {
	db := openTestDB(t)
	require.NoError(t, db.AutoMigrate(&migratorTestModel{}))
	m := db.Migrator()

	assert.True(t, m.HasColumn(&migratorTestModel{}, "Email"))
	assert.False(t, m.HasColumn(&migratorTestModel{}, "DoesNotExist"))

	require.NoError(t, m.DropColumn(&migratorTestModel{}, "Email"))
	assert.False(t, m.HasColumn(&migratorTestModel{}, "Email"))
}

// TestMigrator_DropColumn_NonexistentColumnErrors is #G54: before the fix,
// DropColumn reported success for a column name that was never actually
// present in the table's DDL — removeColumn's bool signaling "not found" was
// discarded, so a caller relying on DropColumn to actually remove a
// deprecated or insecure column got no indication the drop silently no-op'd.
func TestMigrator_DropColumn_NonexistentColumnErrors(t *testing.T) {
	db := openTestDB(t)
	require.NoError(t, db.AutoMigrate(&migratorTestModel{}))
	m := db.Migrator()

	err := m.DropColumn(&migratorTestModel{}, "DoesNotExist")
	require.Error(t, err, "dropping a column that was never in the table must report failure, not silent success")
	assert.Contains(t, err.Error(), "not found")
}

func TestMigrator_IndexLifecycle(t *testing.T) {
	db := openTestDB(t)
	require.NoError(t, db.AutoMigrate(&migratorTestModel{}))
	m := db.Migrator()

	require.True(t, m.HasIndex(&migratorTestModel{}, "idx_migrator_name"))

	indexes, err := m.GetIndexes(&migratorTestModel{})
	require.NoError(t, err)
	found := false
	for _, idx := range indexes {
		if idx.Name() == "idx_migrator_name" {
			found = true
		}
	}
	assert.True(t, found, "GetIndexes should report the declared unique index")

	require.NoError(t, m.DropIndex(&migratorTestModel{}, "idx_migrator_name"))
	assert.False(t, m.HasIndex(&migratorTestModel{}, "idx_migrator_name"))

	require.NoError(t, m.CreateIndex(&migratorTestModel{}, "idx_migrator_name"))
	assert.True(t, m.HasIndex(&migratorTestModel{}, "idx_migrator_name"))

	require.NoError(t, m.RenameIndex(&migratorTestModel{}, "idx_migrator_name", "idx_migrator_name_v2"))
	assert.False(t, m.HasIndex(&migratorTestModel{}, "idx_migrator_name"))
	assert.True(t, m.HasIndex(&migratorTestModel{}, "idx_migrator_name_v2"))
}

func TestMigrator_HasConstraint(t *testing.T) {
	db := openTestDB(t)
	require.NoError(t, db.AutoMigrate(&migratorTestModel{}))
	m := db.Migrator()

	assert.True(t, m.HasConstraint(&migratorTestModel{}, "chk_migrator_score"))
	assert.False(t, m.HasConstraint(&migratorTestModel{}, "chk_does_not_exist"))

	require.NoError(t, m.DropConstraint(&migratorTestModel{}, "chk_migrator_score"))
	assert.False(t, m.HasConstraint(&migratorTestModel{}, "chk_migrator_score"))

	require.NoError(t, m.CreateConstraint(&migratorTestModel{}, "chk_migrator_score"))
	assert.True(t, m.HasConstraint(&migratorTestModel{}, "chk_migrator_score"))
}

// TestMigrator_HasConstraint_EscapesLikeWildcards is #G46: HasConstraint spliced the
// queried constraint name unescaped into a SQL LIKE pattern, so '_' (which is EXTREMELY
// common in real constraint names — GORM's own default FK-naming convention is
// "fk_<table>_<column>") was interpreted as a single-character wildcard instead of a
// literal underscore. A query for "chk_a_score" must not incorrectly match a
// differently-named constraint like "chkXaXscore" just because '_' happens to wildcard
// onto 'X' in that position.
func TestMigrator_HasConstraint_EscapesLikeWildcards(t *testing.T) {
	db := openTestDB(t)
	require.NoError(t, db.AutoMigrate(&likeEscapeTestModel{}))
	m := db.Migrator()

	assert.True(t, m.HasConstraint(&likeEscapeTestModel{}, "chkXaXscore"), "the real constraint name must still match itself")
	assert.False(t, m.HasConstraint(&likeEscapeTestModel{}, "chk_a_score"),
		"a queried name containing '_' must be matched literally, not as a LIKE wildcard — chk_a_score must not incorrectly match chkXaXscore")
}

func TestMigrator_ConstraintLifecycle(t *testing.T) {
	db := openTestDB(t)
	require.NoError(t, db.AutoMigrate(&constraintTestModel{}))
	m := db.Migrator()

	var createSQL string
	require.NoError(t, db.Raw(
		"SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?", "constraint_test_models",
	).Row().Scan(&createSQL))
	constraintName := extractConstraintName(t, createSQL)

	require.True(t, m.HasConstraint(&constraintTestModel{}, constraintName))

	require.NoError(t, m.DropConstraint(&constraintTestModel{}, constraintName))
	assert.False(t, m.HasConstraint(&constraintTestModel{}, constraintName))

	require.NoError(t, m.CreateConstraint(&constraintTestModel{}, constraintName))
	assert.True(t, m.HasConstraint(&constraintTestModel{}, constraintName))
}

// extractConstraintName pulls the name out of the single `CONSTRAINT <name>
// UNIQUE (...)` clause GORM generates for a `gorm:"unique"` field, so the test
// doesn't have to hardcode GORM's constraint-naming convention.
func extractConstraintName(t *testing.T, createSQL string) string {
	t.Helper()
	const marker = "CONSTRAINT "
	idx := strings.Index(createSQL, marker)
	require.NotEqual(t, -1, idx, "expected a CONSTRAINT clause in: %s", createSQL)
	rest := createSQL[idx+len(marker):]
	end := strings.IndexAny(rest, " \t")
	require.NotEqual(t, -1, end)
	return strings.Trim(rest[:end], "`\"")
}

func TestMigrator_AlterColumn(t *testing.T) {
	db := openTestDB(t)
	require.NoError(t, db.AutoMigrate(&migratorTestModel{}))
	m := db.Migrator()

	require.NoError(t, m.AlterColumn(&migratorTestModel{}, "Name"))
	assert.True(t, m.HasColumn(&migratorTestModel{}, "Name"))

	require.NoError(t, db.Create(&migratorTestModel{Name: "still-works", Score: 1}).Error)
}

// TestMigrator_AlterColumn_NilSchemaReturnsErrorNotPanic guards against a
// nil-pointer panic in AlterColumn. Upstream gorm.io/driver/sqlite checks
// stmt.Schema != nil before calling stmt.Schema.LookUpField; this fork's
// AlterColumn was missing that guard. Every AutoMigrate call site in
// internal/storage/factory.go passes a concrete struct pointer, so stmt.Schema
// is always resolved in practice today — but AlterColumn is also reachable
// directly via db.Migrator().AlterColumn(...), and passing a bare table-name
// string (a value GORM can't resolve a schema for) must return a normal
// error instead of crashing the process handling migrations.
func TestMigrator_AlterColumn_NilSchemaReturnsErrorNotPanic(t *testing.T) {
	db := openTestDB(t)
	require.NoError(t, db.AutoMigrate(&migratorTestModel{}))
	m := db.Migrator()

	assert.NotPanics(t, func() {
		err := m.AlterColumn("migrator_test_models", "Name")
		require.Error(t, err, "AlterColumn with a schema-less value must return an error, not panic")
		assert.Contains(t, err.Error(), "schema")
	})
}

func TestMigrator_DropColumn_NilSchemaReturnsErrorNotPanic(t *testing.T) {
	db := openTestDB(t)
	require.NoError(t, db.AutoMigrate(&migratorTestModel{}))
	m := db.Migrator()

	assert.NotPanics(t, func() {
		err := m.DropColumn("migrator_test_models", "Name")
		require.Error(t, err, "DropColumn with a schema-less value must return an error, not panic")
		assert.Contains(t, err.Error(), "schema")
	})
}

func TestMigrator_ColumnTypesAndTablesAndCurrentDatabase(t *testing.T) {
	db := openTestDB(t)
	require.NoError(t, db.AutoMigrate(&migratorTestModel{}))
	m := db.Migrator()

	columnTypes, err := m.ColumnTypes(&migratorTestModel{})
	require.NoError(t, err)
	names := make(map[string]bool)
	for _, ct := range columnTypes {
		names[ct.Name()] = true
	}
	assert.True(t, names["name"])
	assert.True(t, names["email"])

	tables, err := m.GetTables()
	require.NoError(t, err)
	assert.Contains(t, tables, "migrator_test_models")

	assert.NotEmpty(t, m.CurrentDatabase())
}
