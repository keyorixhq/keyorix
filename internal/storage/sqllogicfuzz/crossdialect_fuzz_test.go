package sqllogicfuzz

import "testing"

// FuzzCrossDialect runs the same GORM query over a defined common subset on
// modernc-SQLite and on PostgreSQL and asserts the returned row-id sets are
// equal. It skips cleanly when KEYORIX_TEST_PG_DSN is unset.
//
// Common subset (what IS compared):
//   - column types: integer (a,b,e; b nullable) and ASCII text (c,d; d nullable)
//   - numeric comparisons = <> < <= > >= and arithmetic + - * (bounded, no overflow)
//   - text comparisons = and <> only
//   - logical AND/OR/NOT and IS [NOT] NULL
//
// Known, deliberately-excluded differences (NOT compared):
//   - result ORDER (compared as sets)
//   - NULL ordering in ORDER BY (no ORDER BY)
//   - text ordering/collation (< <= > >= on text excluded; SQLite BINARY vs
//     PostgreSQL locale collation legitimately differ)
//   - LIKE case/escape semantics (excluded)
//   - integer division / modulo and divide-by-zero (SQLite returns NULL,
//     PostgreSQL raises; excluded)
//   - boolean type representation (e is an integer 0/1 in both engines)
func FuzzCrossDialect(f *testing.F) {
	f.Add([]byte{2, 4, 6, 8, 10, 12, 14, 16})
	f.Add([]byte("xdialect-seed-null-is-null"))
	f.Add([]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa})

	pg, ok := pgSetup(f)
	if !ok {
		f.Skip("KEYORIX_TEST_PG_DSN unset: cross-dialect oracle skipped")
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		s := newStream(data)
		rows := GenRows(s, 14)
		pred := GenPredicate(s, 3, true) // common subset

		// SQLite side
		lite := newSQLiteMem(t)
		if err := createTable(lite, "t", false); err != nil {
			t.Fatalf("sqlite create: %v", err)
		}
		if err := InsertRows(lite, "t", rows); err != nil {
			t.Fatalf("sqlite insert: %v", err)
		}

		// PostgreSQL side, isolated per-iteration table
		tbl := nextTable()
		if err := createTable(pg, tbl, true); err != nil {
			t.Fatalf("pg create: %v", err)
		}
		defer dropTable(pg, tbl)
		if err := InsertRows(pg, tbl, rows); err != nil {
			t.Fatalf("pg insert: %v", err)
		}

		liteIDs, errLite := SelectIDs(lite, "t", pred.SQL, pred.Args)
		pgIDs, errPG := SelectIDs(pg, tbl, pred.SQL, pred.Args)

		switch {
		case errLite != nil && errPG != nil:
			// Both engines reject the predicate: not a differential finding.
			t.Skipf("both engines error: sqlite=%v pg=%v", errLite, errPG)
		case errLite != nil || errPG != nil:
			t.Fatalf("one-sided error for predicate %q: sqlite=%v pg=%v",
				pred.SQL, errLite, errPG)
		case !equalInt64(liteIDs, pgIDs):
			t.Fatalf("cross-dialect mismatch for predicate %q:\n sqlite=%v\n pg=%v\n rows=%+v",
				pred.SQL, liteIDs, pgIDs, rows)
		}
	})
}
