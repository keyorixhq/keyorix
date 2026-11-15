package sqllogicfuzz

import (
	"fmt"
	"testing"

	"gorm.io/gorm"
)

// ptr is a small helper for nullable column literals.
func ptrInt(v int64) *int64 { return &v }

// seedWithNulls inserts a fixed set of rows: some with b NULL, some b>0, some
// b<=0, so predicates over b have a non-empty TRUE / FALSE / NULL partition.
func seedWithNulls(t *testing.T, db *gorm.DB, table string) {
	t.Helper()
	rows := []Row{
		{ID: 1, A: 5, B: ptrInt(3), C: "a", E: 1},  // b>0  -> TRUE
		{ID: 2, A: 5, B: ptrInt(-3), C: "a", E: 0}, // b<=0 -> FALSE
		{ID: 3, A: 5, B: nil, C: "a", E: 1},        // b NULL -> NULL
		{ID: 4, A: 5, B: ptrInt(7), C: "b", E: 0},  // b>0  -> TRUE
		{ID: 5, A: 5, B: nil, C: "b", E: 1},        // b NULL -> NULL
	}
	if err := InsertRows(db, table, rows); err != nil {
		t.Fatalf("seed: %v", err)
	}
}

// --- TLP -------------------------------------------------------------------

// TestTLP_RedGreen proves the TLP oracle is load-bearing: a partition that
// omits the `p IS NULL` third set (a plausible two-valued-logic bug) fails to
// cover all rows when NULLs are present, while the real three-way oracle holds.
func TestTLP_RedGreen(t *testing.T) {
	db := newSQLiteMem(t)
	if err := createTable(db, "t", false); err != nil {
		t.Fatal(err)
	}
	seedWithNulls(t, db, "t")
	pred := Frag{SQL: "b > ?", Args: []any{int64(0)}}

	// GREEN: the production three-way oracle holds.
	res, err := CheckTLP(db, "t", pred)
	if err != nil {
		t.Fatalf("CheckTLP error: %v", err)
	}
	if !res.Ok() {
		t.Fatalf("GREEN failed: production TLP should hold, got %s", res.Mismatch)
	}

	// RED: a two-way partition (TRUE ∪ FALSE only) drops the NULL rows, so the
	// union is strictly smaller than the full table — the defect the oracle's
	// third partition exists to catch.
	pTrue, _ := SelectIDs(db, "t", pred.SQL, pred.Args)
	pFalse, _ := SelectIDs(db, "t", "NOT ("+pred.SQL+")", pred.Args)
	twoWay := append(append([]int64{}, pTrue...), pFalse...)
	if len(twoWay) == len(res.All) {
		t.Fatalf("RED failed: two-way partition unexpectedly covered all rows (no NULLs in fixture?)")
	}
	if len(res.PNull) == 0 {
		t.Fatalf("RED failed: fixture produced no NULL partition, red proof is vacuous")
	}
	t.Logf("RED ok: two-way union covers %d of %d rows; %d NULL rows dropped",
		len(twoWay), len(res.All), len(res.PNull))
}

// --- NoREC -----------------------------------------------------------------

// TestNoREC_RedGreen proves the NoREC oracle catches a NULL-mishandling
// optimiser bug: an unoptimised form that counts `p IS NULL OR p` (treating
// NULL as TRUE) overcounts versus WHERE p, while the correct CASE form agrees.
func TestNoREC_RedGreen(t *testing.T) {
	db := newSQLiteMem(t)
	if err := createTable(db, "t", false); err != nil {
		t.Fatal(err)
	}
	seedWithNulls(t, db, "t")
	pred := Frag{SQL: "b > ?", Args: []any{int64(0)}}

	// GREEN: production oracle agrees.
	opt, unopt, err := CheckNoREC(db, "t", pred)
	if err != nil {
		t.Fatalf("CheckNoREC error: %v", err)
	}
	if opt != unopt {
		t.Fatalf("GREEN failed: production NoREC should agree, got opt=%d unopt=%d", opt, unopt)
	}

	// RED: a buggy unoptimised form that folds NULL into TRUE overcounts.
	var buggy int64
	raw := fmt.Sprintf(
		"SELECT COALESCE(SUM(CASE WHEN (%[1]s) IS NULL OR (%[1]s) THEN 1 ELSE 0 END),0) FROM (SELECT * FROM t) AS s",
		pred.SQL)
	if err := db.Raw(raw, pred.Args[0], pred.Args[0]).Scan(&buggy).Error; err != nil {
		t.Fatalf("buggy query error: %v", err)
	}
	if buggy == opt {
		t.Fatalf("RED failed: NULL-as-TRUE form did not overcount (opt=%d buggy=%d); fixture lacks NULLs?",
			opt, buggy)
	}
	t.Logf("RED ok: optimised=%d, NULL-as-TRUE buggy=%d (overcount by %d NULL rows)", opt, buggy, buggy-opt)
}

// --- Injection-structure ---------------------------------------------------

// TestInjectionStructure_RedGreen proves the structure oracle fires on an
// interpolating builder and stays green on the parametrised ones.
func TestInjectionStructure_RedGreen(t *testing.T) {
	db := newSQLiteMem(t)
	if err := createTable(db, "t", false); err != nil {
		t.Fatal(err)
	}
	const hostile = "a' OR '1'='1"

	// GREEN: every safe shape is stable.
	for _, sh := range safeShapes {
		if stable, detail := StructureStable(db, sh.build, hostile); !stable {
			t.Fatalf("GREEN failed: safe shape %q reported unstable: %s", sh.name, detail)
		}
	}

	// RED: raw interpolation into WHERE changes the statement structure.
	whereInterp := func(tx *gorm.DB, v string) *gorm.DB {
		return tx.Where(fmt.Sprintf("c = '%s'", v)) //nolint:gosec // deliberate defect for the red proof
	}
	if stable, _ := StructureStable(db, whereInterp, hostile); stable {
		t.Fatalf("RED failed: interpolated WHERE reported stable (oracle did not fire)")
	}

	// RED: a raw ORDER BY built from the user value also changes structure.
	orderInterp := func(tx *gorm.DB, v string) *gorm.DB {
		return tx.Order(v) //nolint:gosec // deliberate defect for the red proof
	}
	if stable, _ := StructureStable(db, orderInterp, hostile); stable {
		t.Fatalf("RED failed: interpolated ORDER BY reported stable (oracle did not fire)")
	}
	t.Log("RED ok: interpolated WHERE and ORDER BY both detected as structure-changing")
}

// --- Cross-dialect ---------------------------------------------------------

// TestCrossDialect_RedGreen proves the cross-dialect oracle distinguishes a
// genuine known difference (divide-by-zero: SQLite yields NULL, PostgreSQL
// raises) from an in-subset query that must agree. Skips without a DSN.
func TestCrossDialect_RedGreen(t *testing.T) {
	pg, ok := pgSetup(t)
	if !ok {
		t.Skip("KEYORIX_TEST_PG_DSN unset")
	}
	lite := newSQLiteMem(t)
	if err := createTable(lite, "t", false); err != nil {
		t.Fatal(err)
	}
	tbl := nextTable()
	if err := createTable(pg, tbl, true); err != nil {
		t.Fatal(err)
	}
	defer dropTable(pg, tbl)

	rows := []Row{
		{ID: 1, A: 1, B: ptrInt(1), C: "a", E: 1},
		{ID: 2, A: 2, B: ptrInt(2), C: "b", E: 0},
	}
	if err := InsertRows(lite, "t", rows); err != nil {
		t.Fatal(err)
	}
	if err := InsertRows(pg, tbl, rows); err != nil {
		t.Fatal(err)
	}

	// GREEN: an in-subset predicate agrees on both engines.
	good := Frag{SQL: "a >= ? AND c <> ?", Args: []any{int64(1), "z"}}
	liteIDs, errL := SelectIDs(lite, "t", good.SQL, good.Args)
	pgIDs, errP := SelectIDs(pg, tbl, good.SQL, good.Args)
	if errL != nil || errP != nil {
		t.Fatalf("GREEN errored: sqlite=%v pg=%v", errL, errP)
	}
	if !equalInt64(liteIDs, pgIDs) {
		t.Fatalf("GREEN failed: in-subset predicate disagreed sqlite=%v pg=%v", liteIDs, pgIDs)
	}

	// RED: divide-by-zero is outside the common subset — SQLite returns NULL
	// (no rows match), PostgreSQL raises. The oracle must observe a divergence
	// (here, a one-sided error), classified EXPECTED-DIFFERENCE.
	bad := Frag{SQL: "a / (a - a) = ?", Args: []any{int64(1)}}
	_, errLbad := SelectIDs(lite, "t", bad.SQL, bad.Args)
	_, errPbad := SelectIDs(pg, tbl, bad.SQL, bad.Args)
	if errLbad == nil && errPbad == nil {
		t.Fatalf("RED failed: divide-by-zero produced no divergence (sqlite and pg both ok)")
	}
	t.Logf("RED ok: divide-by-zero diverges — sqlite err=%v, pg err=%v", errLbad, errPbad)
}
