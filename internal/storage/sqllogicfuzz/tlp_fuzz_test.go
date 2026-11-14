package sqllogicfuzz

import "testing"

// FuzzTLP exercises the Ternary Logic Partitioning oracle on the production
// modernc-SQLite dialector. For each input it builds a random table and a
// random bounded-depth predicate, then asserts
//
//	rows(T) == rows(p) ⊎ rows(¬p) ⊎ rows(p IS NULL)
//
// A failure means SQLite's three-valued WHERE evaluation lost or duplicated a
// row — a logic bug in the engine or in how GORM rendered the predicate.
func FuzzTLP(f *testing.F) {
	f.Add([]byte{1, 2, 3, 4, 5, 6, 7, 8})
	f.Add([]byte{0xff, 0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80})
	f.Add([]byte("tlp-seed-nulls-and-arith"))

	f.Fuzz(func(t *testing.T, data []byte) {
		s := newStream(data)
		rows := GenRows(s, 16)
		pred := GenPredicate(s, 3, false)

		db := newSQLiteMem(t)
		if err := createTable(db, "t", false); err != nil {
			t.Fatalf("create table: %v", err)
		}
		if err := InsertRows(db, "t", rows); err != nil {
			t.Fatalf("insert: %v", err)
		}

		res, err := CheckTLP(db, "t", pred)
		if err != nil {
			// A malformed predicate that the engine rejects is not a logic
			// mismatch; ignore it (the typed generator should not produce
			// these, but padding past the input can).
			t.Skipf("predicate error: %v", err)
		}
		if !res.Ok() {
			t.Fatalf("TLP mismatch: %s\n all=%v p=%v !p=%v pNull=%v",
				res.Mismatch, res.All, res.PTrue, res.PFalse, res.PNull)
		}
	})
}
