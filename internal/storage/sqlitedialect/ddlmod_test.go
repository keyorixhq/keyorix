package sqlite

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParseDDL_EscapedQuoteInBody exercises the "skip escaped quote" branch in
// parseDDL's bracket/comma scanner: a doubled quote character inside a quoted
// identifier must not be treated as the identifier's closing quote, and the
// comma that follows the quoted identifier must still be recognized as a
// top-level field separator.
func TestParseDDL_EscapedQuoteInBody(t *testing.T) {
	d, err := parseDDL(`CREATE TABLE "foo" ("na""me" TEXT, "id" INTEGER)`)
	require.NoError(t, err)
	require.Len(t, d.fields, 2)
	assert.Contains(t, d.fields[0], `"na""me"`, "the escaped quote must remain part of the same field, not split it")
	assert.Contains(t, d.fields[1], `"id"`)
}

// TestParseDDL_UnbalancedExtraClosingParen exercises the bracketLevel<0 guard:
// a stray ')' with no matching '(' inside the DDL body must be rejected as
// invalid rather than silently accepted.
func TestParseDDL_UnbalancedExtraClosingParen(t *testing.T) {
	_, err := parseDDL("CREATE TABLE foo (id INTEGER))")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unbalanced brackets")
}

// TestParseDDL_UnbalancedUnclosedParen exercises the trailing bracketLevel!=0
// guard: an open '(' inside the body (e.g. a truncated data-type length spec)
// that never closes must be rejected.
func TestParseDDL_UnbalancedUnclosedParen(t *testing.T) {
	_, err := parseDDL("CREATE TABLE foo (id INTEGER(5)")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unbalanced brackets")
}

// TestParseDDL_ForeignKeyFieldSkipped exercises the FOREIGN KEY prefix branch:
// a FOREIGN KEY table constraint field must not be turned into a bogus column.
func TestParseDDL_ForeignKeyFieldSkipped(t *testing.T) {
	d, err := parseDDL("CREATE TABLE foo (id INTEGER, FOREIGN KEY (id) REFERENCES bar(id))")
	require.NoError(t, err)
	require.Len(t, d.columns, 1)
	assert.Equal(t, "id", d.columns[0].NameValue.String)
}

// TestParseDDL_CompositePrimaryKeyMarksColumns exercises the table-level
// PRIMARY KEY(...) branch: every column named in the composite key must have
// its PrimaryKeyValue flagged, not just the first.
func TestParseDDL_CompositePrimaryKeyMarksColumns(t *testing.T) {
	d, err := parseDDL("CREATE TABLE foo (id INTEGER, name TEXT, PRIMARY KEY (id, name))")
	require.NoError(t, err)
	require.Len(t, d.columns, 2)
	for _, c := range d.columns {
		assert.True(t, c.PrimaryKeyValue.Bool, "column %q should be marked primary key by the composite PRIMARY KEY clause", c.NameValue.String)
	}
}

// TestParseDDL_InlineColumnModifiers exercises the inline NOT NULL / NULL /
// UNIQUE / DEFAULT / sized-data-type branches of the per-column parser.
func TestParseDDL_InlineColumnModifiers(t *testing.T) {
	d, err := parseDDL("CREATE TABLE foo (id INTEGER NOT NULL, name TEXT NULL, email TEXT UNIQUE, age INTEGER DEFAULT 5, code VARCHAR(255))")
	require.NoError(t, err)
	require.Len(t, d.columns, 5)

	byName := make(map[string]int)
	for i, c := range d.columns {
		byName[c.NameValue.String] = i
	}

	idCol := d.columns[byName["id"]]
	assert.False(t, idCol.NullableValue.Bool, "id has NOT NULL")

	nameCol := d.columns[byName["name"]]
	assert.True(t, nameCol.NullableValue.Bool, "name has explicit NULL")

	emailCol := d.columns[byName["email"]]
	assert.True(t, emailCol.UniqueValue.Bool, "email has inline UNIQUE")

	ageCol := d.columns[byName["age"]]
	require.True(t, ageCol.DefaultValueValue.Valid)
	assert.Equal(t, "5", ageCol.DefaultValueValue.String)

	codeCol := d.columns[byName["code"]]
	assert.Equal(t, "VARCHAR", codeCol.DataTypeValue.String)
	require.True(t, codeCol.LengthValue.Valid)
	assert.Equal(t, int64(255), codeCol.LengthValue.Int64)
}

// TestParseDDL_IndexStatementIgnored exercises the indexRegexp branch: a
// CREATE INDEX statement passed alongside a CREATE TABLE statement must be
// recognized and skipped, not reported as an invalid-DDL error.
func TestParseDDL_IndexStatementIgnored(t *testing.T) {
	d, err := parseDDL(
		"CREATE TABLE foo (id INTEGER)",
		"CREATE UNIQUE INDEX idx_foo_id ON foo (id)",
	)
	require.NoError(t, err)
	require.Len(t, d.columns, 1)
}

// TestParseDDL_TotallyInvalidStatement exercises the final else branch: a
// string that matches neither the CREATE TABLE nor CREATE INDEX pattern must
// be rejected as invalid DDL.
func TestParseDDL_TotallyInvalidStatement(t *testing.T) {
	_, err := parseDDL("this is not sql")
	require.Error(t, err)
	assert.Equal(t, "invalid DDL", err.Error())
}

// TestDDLCompile_NoFields exercises the empty-fields branch of compile(): with
// no fields at all, compile must fall back to head+suffix rather than
// emitting an empty "()" field list.
func TestDDLCompile_NoFields(t *testing.T) {
	d := &ddl{head: "CREATE TABLE `foo`", suffix: " WITHOUT ROWID"}
	assert.Equal(t, "CREATE TABLE `foo` WITHOUT ROWID", d.compile())
}

// TestDDLRenameTable_SourceNotFound exercises renameTable's error branch: if
// the source table name can't be located in the DDL head, renaming must fail
// loudly instead of silently leaving the head unchanged.
func TestDDLRenameTable_SourceNotFound(t *testing.T) {
	d := &ddl{head: "CREATE TABLE `foo`"}
	err := d.renameTable("bar", "does_not_exist")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to look up tablename")
}

// TestDDLAddConstraint_ReplacesExisting exercises addConstraint's match branch:
// calling addConstraint twice with the same constraint name must replace the
// existing field in place rather than appending a duplicate.
func TestDDLAddConstraint_ReplacesExisting(t *testing.T) {
	d := &ddl{fields: []string{"id INTEGER"}}

	d.addConstraint("fk_1", "CONSTRAINT `fk_1` FOREIGN KEY (a) REFERENCES b(id)")
	require.Len(t, d.fields, 2, "first call with a new name should append")

	d.addConstraint("fk_1", "CONSTRAINT `fk_1` FOREIGN KEY (a) REFERENCES c(id)")
	require.Len(t, d.fields, 2, "second call with the same name should replace, not append")
	assert.Equal(t, "CONSTRAINT `fk_1` FOREIGN KEY (a) REFERENCES c(id)", d.fields[1])
}

// TestDDLRemoveConstraint_NotFound exercises removeConstraint's not-found
// return path.
func TestDDLRemoveConstraint_NotFound(t *testing.T) {
	d := &ddl{fields: []string{"id INTEGER"}}
	assert.False(t, d.removeConstraint("does_not_exist"))
}

// TestDDLGetColumns_SkipsTopLevelUnique exercises getColumns' uniqueRegexp
// branch: a standalone table-level "UNIQUE (...)" field must not be reported
// as a column.
func TestDDLGetColumns_SkipsTopLevelUnique(t *testing.T) {
	d := &ddl{fields: []string{"id INTEGER", "name TEXT", "UNIQUE (id, name)"}}
	cols := d.getColumns()
	assert.Equal(t, []string{"`id`", "`name`"}, cols)
}
