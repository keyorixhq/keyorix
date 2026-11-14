package sqllogicfuzz

import (
	"testing"

	"gorm.io/gorm"
)

// safeShapes are GORM query builders that pass the user value v strictly as a
// bind parameter. For every one of them, the prepared-statement text must be
// identical whatever v is, and v must never appear in the SQL text.
var safeShapes = []struct {
	name  string
	build func(tx *gorm.DB, v string) *gorm.DB
}{
	{"where-eq", func(tx *gorm.DB, v string) *gorm.DB { return tx.Where("c = ?", v) }},
	{"where-two-params", func(tx *gorm.DB, v string) *gorm.DB { return tx.Where("d = ? OR c = ?", v, v) }},
	{"where-map", func(tx *gorm.DB, v string) *gorm.DB { return tx.Where(map[string]any{"c": v}) }},
	{"where-in", func(tx *gorm.DB, v string) *gorm.DB { return tx.Where("c IN ?", []string{v, "y"}) }},
	{"where-not", func(tx *gorm.DB, v string) *gorm.DB { return tx.Not("c = ?", v) }},
}

// FuzzGormInjectionStructure asserts the injection-structure invariant: a value
// supplied to a parametrised GORM builder never changes the statement
// structure. It renders each safe shape with the fuzzer's hostile string via
// DryRun and compares the SQL text to the same shape with a benign value.
//
// This is the oracle in its GREEN direction (the shapes are safe by
// construction, so it must stay green). Its RED proof — that the oracle
// actually fires on an interpolating shape — lives in redproof_test.go.
func FuzzGormInjectionStructure(f *testing.F) {
	f.Add("' OR '1'='1")
	f.Add("1; DROP TABLE t; --")
	f.Add("\\'; DELETE FROM t WHERE ''='")
	f.Add("x) UNION SELECT password FROM users --")
	f.Add("名前\x00; --")

	db := newSQLiteMem(f)
	if err := createTable(db, "t", false); err != nil {
		f.Fatalf("create table: %v", err)
	}

	f.Fuzz(func(t *testing.T, hostile string) {
		for _, sh := range safeShapes {
			stable, detail := StructureStable(db, sh.build, hostile)
			if !stable {
				t.Fatalf("shape %q: statement structure changed under value %q\n%s",
					sh.name, hostile, detail)
			}
		}
	})
}
