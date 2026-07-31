package sqlite

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/schema"
)

func openTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	return db
}

func TestOpenAndNew(t *testing.T) {
	d := Open("file::memory:")
	dialector, ok := d.(*Dialector)
	require.True(t, ok)
	assert.Equal(t, "file::memory:", dialector.DSN)
	assert.Equal(t, "sqlite", dialector.Name())

	d2 := New(Config{DSN: "file::memory:", DriverName: "sqlite"})
	dialector2, ok := d2.(*Dialector)
	require.True(t, ok)
	assert.Equal(t, "sqlite", dialector2.DriverName)
	assert.Equal(t, "file::memory:", dialector2.DSN)
}

func TestInitialize_RealDB(t *testing.T) {
	db := openTestDB(t)

	var version string
	require.NoError(t, db.Raw("select sqlite_version()").Row().Scan(&version))
	assert.NotEmpty(t, version)
}

func TestDataTypeOf(t *testing.T) {
	d := Dialector{}

	cases := []struct {
		name  string
		field *schema.Field
		want  string
	}{
		{"bool", &schema.Field{DataType: schema.Bool}, "numeric"},
		{"int autoincrement", &schema.Field{DataType: schema.Int, AutoIncrement: true}, "integer PRIMARY KEY AUTOINCREMENT"},
		{"int plain", &schema.Field{DataType: schema.Int}, "integer"},
		{"uint plain", &schema.Field{DataType: schema.Uint}, "integer"},
		{"float", &schema.Field{DataType: schema.Float}, "real"},
		{"string", &schema.Field{DataType: schema.String}, "text"},
		{"time default", &schema.Field{DataType: schema.Time}, "datetime"},
		{"time with TYPE tag", &schema.Field{DataType: schema.Time, TagSettings: map[string]string{"TYPE": "date"}}, "date"},
		{"bytes", &schema.Field{DataType: schema.Bytes}, "blob"},
		{"unknown falls back to raw DataType", &schema.Field{DataType: schema.DataType("custom")}, "custom"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, d.DataTypeOf(tc.field))
		})
	}
}

func TestDefaultValueOf(t *testing.T) {
	d := Dialector{}
	assert.Equal(t, clause.Expr{SQL: "NULL"}, d.DefaultValueOf(&schema.Field{AutoIncrement: true}))
	assert.Equal(t, clause.Expr{SQL: "DEFAULT"}, d.DefaultValueOf(&schema.Field{AutoIncrement: false}))
}

func TestQuoteTo(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{"simple identifier", "users", "`users`"},
		{"qualified identifier", "users.name", "`users`.`name`"},
		{"identifier with embedded backtick", "a`b", "`a``b`"},
	}

	d := Dialector{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var w strings.Builder
			d.QuoteTo(&w, tc.input)
			assert.Equal(t, tc.want, w.String())
		})
	}
}

func TestBindVarTo(t *testing.T) {
	d := Dialector{}
	var w strings.Builder
	d.BindVarTo(&w, nil, nil)
	assert.Equal(t, "?", w.String())
}

func TestExplain(t *testing.T) {
	d := Dialector{}
	got := d.Explain("SELECT * FROM x WHERE y = ?", "z")
	assert.NotContains(t, got, "?")
	assert.Contains(t, got, "z")
}

func TestSavePointAndRollbackTo(t *testing.T) {
	db := openTestDB(t)
	type spModel struct {
		ID   uint `gorm:"primaryKey"`
		Name string
	}
	require.NoError(t, db.AutoMigrate(&spModel{}))

	err := db.Transaction(func(tx *gorm.DB) error {
		require.NoError(t, tx.Create(&spModel{Name: "before-savepoint"}).Error)
		require.NoError(t, tx.SavePoint("sp1").Error)
		require.NoError(t, tx.Create(&spModel{Name: "after-savepoint"}).Error)
		require.NoError(t, tx.RollbackTo("sp1").Error)
		return nil
	})
	require.NoError(t, err)

	var count int64
	require.NoError(t, db.Model(&spModel{}).Count(&count).Error)
	assert.Equal(t, int64(1), count, "the row created after the savepoint should have been rolled back")
}

func TestClauseBuilders_ViaGeneratedSQL(t *testing.T) {
	db := openTestDB(t)
	type clauseModel struct {
		ID   uint `gorm:"primaryKey"`
		Name string
	}
	require.NoError(t, db.AutoMigrate(&clauseModel{}))

	insertSQL := db.Session(&gorm.Session{DryRun: true}).Create(&clauseModel{Name: "x"}).Statement.SQL.String()
	assert.Contains(t, insertSQL, "INSERT INTO")
	assert.Contains(t, insertSQL, "`clause_models`")

	var results []clauseModel
	limitSQL := db.Session(&gorm.Session{DryRun: true}).Limit(5).Offset(10).Find(&results).Statement.SQL.String()
	assert.Contains(t, limitSQL, "LIMIT 5")
	assert.Contains(t, limitSQL, "OFFSET 10")

	lockSQL := db.Session(&gorm.Session{DryRun: true}).Clauses(clause.Locking{Strength: "UPDATE"}).Find(&results).Statement.SQL.String()
	assert.NotContains(t, lockSQL, "FOR UPDATE", "SQLite does not support row-level locking; the FOR clause must be a no-op")
}

func TestTranslate_DuplicateKey(t *testing.T) {
	db, err := gorm.Open(Open(":memory:"), &gorm.Config{TranslateError: true})
	require.NoError(t, err)

	type uniqueModel struct {
		ID   uint   `gorm:"primaryKey"`
		Name string `gorm:"uniqueIndex"`
	}
	require.NoError(t, db.AutoMigrate(&uniqueModel{}))
	require.NoError(t, db.Create(&uniqueModel{Name: "dup"}).Error)

	err = db.Create(&uniqueModel{Name: "dup"}).Error
	require.Error(t, err)
	assert.ErrorIs(t, err, gorm.ErrDuplicatedKey)
}

func TestTranslate_UnrelatedError(t *testing.T) {
	d := Dialector{}
	original := errors.New("some unrelated error")
	assert.Equal(t, original, d.Translate(original))
}

func TestMigrator_DropTable(t *testing.T) {
	db := openTestDB(t)
	type dropTableModel struct {
		ID uint `gorm:"primaryKey"`
	}
	require.NoError(t, db.AutoMigrate(&dropTableModel{}))
	m := db.Migrator()

	require.True(t, m.HasTable(&dropTableModel{}))
	require.NoError(t, m.DropTable(&dropTableModel{}))
	assert.False(t, m.HasTable(&dropTableModel{}))
}

func TestCompareVersion(t *testing.T) {
	cases := []struct {
		v1, v2 string
		want   int
	}{
		{"3.35.0", "3.35.0", 0},
		{"3.36.0", "3.35.0", 1},
		{"3.34.0", "3.35.0", -1},
		{"3.35.1", "3.35.0", 1},
		{"3.5.0", "3.35.0", -1},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, compareVersion(tc.v1, tc.v2), "compareVersion(%q, %q)", tc.v1, tc.v2)
	}
}
