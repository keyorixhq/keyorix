package sqlite

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/schema"
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

// TestMigrator_RunWithoutForeignKey_TogglesPragma exercises the enabled==1
// branch: when foreign_keys is already ON, RunWithoutForeignKey must turn it
// OFF for the duration of fc and restore it afterward.
func TestMigrator_RunWithoutForeignKey_TogglesPragma(t *testing.T) {
	db := openTestDB(t)
	require.NoError(t, db.Exec("PRAGMA foreign_keys = ON").Error)

	var enabledDuring int
	m, ok := db.Migrator().(Migrator)
	require.True(t, ok)

	called := false
	err := m.RunWithoutForeignKey(func() error {
		called = true
		require.NoError(t, db.Raw("PRAGMA foreign_keys").Row().Scan(&enabledDuring))
		return nil
	})
	require.NoError(t, err)
	assert.True(t, called)
	assert.Equal(t, 0, enabledDuring, "foreign_keys should be OFF while fc runs")

	var enabledAfter int
	require.NoError(t, db.Raw("PRAGMA foreign_keys").Row().Scan(&enabledAfter))
	assert.Equal(t, 1, enabledAfter, "foreign_keys should be restored to ON afterward")
}

// TestMigrator_AlterColumn_UnknownFieldErrors exercises AlterColumn's final
// "field not found in schema" branch.
func TestMigrator_AlterColumn_UnknownFieldErrors(t *testing.T) {
	db := openTestDB(t)
	require.NoError(t, db.AutoMigrate(&migratorTestModel{}))
	m := db.Migrator()

	err := m.AlterColumn(&migratorTestModel{}, "NoSuchField")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to alter field")
}

// TestMigrator_AlterColumn_RebuildsInlineUniqueConstraint exercises
// AlterColumn's "old-style inline UNIQUE column" branch: a table created by
// hand with `... UNIQUE` inline (rather than a `CONSTRAINT ... UNIQUE`
// clause, which is what this dialector's own CreateConstraint/AutoMigrate
// generates) must still have its unique constraint carried forward as a
// proper constraint when the column is altered, given a schema that declares
// the field unique.
func TestMigrator_AlterColumn_RebuildsInlineUniqueConstraint(t *testing.T) {
	db := openTestDB(t)
	type inlineUniqueModel struct {
		ID   uint   `gorm:"primaryKey"`
		Code string `gorm:"unique"`
	}
	require.NoError(t, db.Exec(
		"CREATE TABLE inline_unique_models (id integer primary key autoincrement, code varchar(10) UNIQUE)",
	).Error)
	m := db.Migrator()

	require.NoError(t, m.AlterColumn(&inlineUniqueModel{}, "Code"))

	require.NoError(t, db.Create(&inlineUniqueModel{Code: "a"}).Error)
	err := db.Create(&inlineUniqueModel{Code: "a"}).Error
	require.Error(t, err, "the unique constraint must have survived AlterColumn's table rebuild")
}

// TestMigrator_ColumnTypes_NonexistentTableErrors exercises ColumnTypes' Rows()
// error branch: querying column types for a model whose table was never
// created must return an error, not a panic or an empty success.
func TestMigrator_ColumnTypes_NonexistentTableErrors(t *testing.T) {
	db := openTestDB(t)
	type neverMigratedModel struct {
		ID   uint `gorm:"primaryKey"`
		Name string
	}
	m := db.Migrator()

	_, err := m.ColumnTypes(&neverMigratedModel{})
	require.Error(t, err)
}

// TestMigrator_ColumnTypes_CorruptDDLErrors exercises ColumnTypes'
// parseDDL-error branch by corrupting the table's stored CREATE TABLE SQL
// directly in sqlite_master (SQLite's writable_schema escape hatch), so
// parseDDL is handed a string it cannot make sense of.
func TestMigrator_ColumnTypes_CorruptDDLErrors(t *testing.T) {
	db := openTestDB(t)
	require.NoError(t, db.AutoMigrate(&migratorTestModel{}))
	require.NoError(t, db.Exec("PRAGMA writable_schema = ON").Error)
	require.NoError(t, db.Exec(
		"UPDATE sqlite_master SET sql = 'not valid ddl' WHERE type = 'table' AND name = ?",
		"migrator_test_models",
	).Error)
	t.Cleanup(func() {
		_ = db.Exec("PRAGMA writable_schema = OFF").Error
	})

	m := db.Migrator()
	_, err := m.ColumnTypes(&migratorTestModel{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid DDL")
}

// TestMigrator_CreateConstraint_UnknownNameIsNoOp exercises both
// CreateConstraint's "constraint == nil" branch and recreateTable's
// "createDDL == nil" early-return branch: asking to create a constraint by a
// name GORM's schema doesn't recognize must be a harmless no-op, not an
// error and not a table rebuild.
func TestMigrator_CreateConstraint_UnknownNameIsNoOp(t *testing.T) {
	db := openTestDB(t)
	require.NoError(t, db.AutoMigrate(&migratorTestModel{}))
	m := db.Migrator()

	require.NoError(t, m.CreateConstraint(&migratorTestModel{}, "totally_unknown_constraint_name"))
	assert.False(t, m.HasConstraint(&migratorTestModel{}, "totally_unknown_constraint_name"))
}

// TestMigrator_BuildIndexOptions_ExpressionCollateSort exercises all three
// optional-suffix branches of BuildIndexOptions directly against manually
// built IndexOptions, independent of whatever GORM's own tag parser produces
// for this SQLite dialect.
func TestMigrator_BuildIndexOptions_ExpressionCollateSort(t *testing.T) {
	db := openTestDB(t)
	require.NoError(t, db.AutoMigrate(&migratorTestModel{}))
	m, ok := db.Migrator().(Migrator)
	require.True(t, ok)

	var results []migratorTestModel
	stmt := db.Session(&gorm.Session{DryRun: true}).Find(&results).Statement

	opts := []schema.IndexOption{
		{Field: &schema.Field{DBName: "name"}, Expression: "LOWER(name)"},
		{Field: &schema.Field{DBName: "email"}, Collate: "NOCASE"},
		{Field: &schema.Field{DBName: "score"}, Sort: "desc"},
	}
	built := m.BuildIndexOptions(opts, stmt)
	require.Len(t, built, 3)

	assert.Equal(t, clause.Expr{SQL: "LOWER(name)"}, built[0], "Expression must override the quoted column name")
	assert.Equal(t, clause.Expr{SQL: "`email` COLLATE NOCASE"}, built[1])
	assert.Equal(t, clause.Expr{SQL: "`score` desc"}, built[2])
}

// TestMigrator_CreateIndex_WithWhereClause exercises CreateIndex/
// BuildIndexOptions' idx.Where branch via a real partial index, which SQLite
// supports natively.
func TestMigrator_CreateIndex_WithWhereClause(t *testing.T) {
	db := openTestDB(t)
	type whereIndexModel struct {
		ID    uint `gorm:"primaryKey"`
		Score int  `gorm:"index:idx_where_score,where:score > 0"`
	}
	require.NoError(t, db.AutoMigrate(&whereIndexModel{}))
	m := db.Migrator()

	assert.True(t, m.HasIndex(&whereIndexModel{}, "idx_where_score"))

	var indexSQL string
	require.NoError(t, db.Raw(
		"SELECT sql FROM sqlite_master WHERE type = 'index' AND name = ?", "idx_where_score",
	).Row().Scan(&indexSQL))
	assert.Contains(t, indexSQL, "WHERE score > 0")
}

// TestMigrator_CreateIndex_TypeOptionIsUnsupportedBySQLite exercises
// CreateIndex/BuildIndexOptions' idx.Type branch. SQLite has no "USING type"
// index syntax, so building an index with a Type tag must surface as an
// error from the underlying Exec, not succeed silently or panic.
func TestMigrator_CreateIndex_TypeOptionIsUnsupportedBySQLite(t *testing.T) {
	db := openTestDB(t)
	type typedIndexModel struct {
		ID    uint `gorm:"primaryKey"`
		Score int  `gorm:"index:idx_typed_score,type:btree"`
	}
	require.NoError(t, db.Exec(
		"CREATE TABLE typed_index_models (id integer primary key autoincrement, score integer)",
	).Error)
	m := db.Migrator()

	err := m.CreateIndex(&typedIndexModel{}, "idx_typed_score")
	require.Error(t, err, "SQLite doesn't support CREATE INDEX ... USING <type>")
}

// TestMigrator_CreateIndex_UnknownNameErrors exercises CreateIndex's final
// "failed to create index" fallback branch.
func TestMigrator_CreateIndex_UnknownNameErrors(t *testing.T) {
	db := openTestDB(t)
	require.NoError(t, db.AutoMigrate(&migratorTestModel{}))
	m := db.Migrator()

	err := m.CreateIndex(&migratorTestModel{}, "no_such_index")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create index")
}

// TestMigrator_RenameIndex_UnknownNameErrors exercises RenameIndex's
// "failed to find index" fallback branch.
func TestMigrator_RenameIndex_UnknownNameErrors(t *testing.T) {
	db := openTestDB(t)
	require.NoError(t, db.AutoMigrate(&migratorTestModel{}))
	m := db.Migrator()

	err := m.RenameIndex(&migratorTestModel{}, "no_such_index", "new_name")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to find index")
}

// TestMigrator_GetIndexes_SkipsUniqueConstraintBackedIndex exercises
// GetIndexes' "origin == u" skip branch: the automatic index SQLite creates
// to back a UNIQUE constraint must not be reported by GetIndexes.
func TestMigrator_GetIndexes_SkipsUniqueConstraintBackedIndex(t *testing.T) {
	db := openTestDB(t)
	require.NoError(t, db.AutoMigrate(&constraintTestModel{}))
	m := db.Migrator()

	indexes, err := m.GetIndexes(&constraintTestModel{})
	require.NoError(t, err)
	for _, idx := range indexes {
		assert.NotContains(t, strings.ToLower(idx.Name()), "sqlite_autoindex", "the UNIQUE-constraint-backed autoindex must be filtered out")
	}
}

// TestMigrator_DropColumn_NeverMigratedTableErrors exercises recreateTable's
// parseDDL-error branch reached through getRawDDL returning an empty string
// for a table that was never created.
func TestMigrator_DropColumn_NeverMigratedTableErrors(t *testing.T) {
	db := openTestDB(t)
	type neverMigratedModel struct {
		ID   uint `gorm:"primaryKey"`
		Name string
	}
	m := db.Migrator()

	err := m.DropColumn(&neverMigratedModel{}, "Name")
	require.Error(t, err)
}

// TestMigrator_DropColumn_SkipsIndexReferencingDroppedColumn exercises
// recreateTable's aux-DDL-replay "no such column" skip branch: an index that
// only covers the column being dropped can't be recreated on the rebuilt
// table, and that must be silently tolerated rather than aborting the drop.
func TestMigrator_DropColumn_SkipsIndexReferencingDroppedColumn(t *testing.T) {
	db := openTestDB(t)
	require.NoError(t, db.AutoMigrate(&migratorTestModel{}))
	m := db.Migrator()
	require.True(t, m.HasIndex(&migratorTestModel{}, "idx_migrator_name"))

	require.NoError(t, m.DropColumn(&migratorTestModel{}, "Name"))
	assert.False(t, m.HasIndex(&migratorTestModel{}, "idx_migrator_name"), "an index over the dropped column can't survive and must be silently skipped")
	assert.False(t, m.HasColumn(&migratorTestModel{}, "Name"))
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
