package sqllogicfuzz

import "testing"

// FuzzNoREC exercises the NoREC oracle on the production modernc-SQLite
// dialector: the number of rows satisfying p computed by an optimisable
// `COUNT(*) ... WHERE p` must equal the number computed by an un-optimisable
// `SUM(CASE WHEN p THEN 1 ELSE 0 END)` over a derived table. A disagreement is
// an optimiser logic bug (the WHERE path and the projection path diverged).
func FuzzNoREC(f *testing.F) {
	f.Add([]byte{3, 1, 4, 1, 5, 9, 2, 6})
	f.Add([]byte{0x7f, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09})
	f.Add([]byte("norec-seed-and-or-not"))

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

		opt, unopt, err := CheckNoREC(db, "t", pred)
		if err != nil {
			t.Skipf("predicate error: %v", err)
		}
		if opt != unopt {
			t.Fatalf("NoREC mismatch: optimised COUNT=%d unoptimised SUM=%d predicate=%q",
				opt, unopt, pred.SQL)
		}
	})
}
