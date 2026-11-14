// Package sqllogicfuzz is a SQLancer-style logic-bug fuzzing harness for the
// GORM data layer (task SQ1). It does not touch production code: it builds its
// own small, type-disciplined schema and random-predicate generator and drives
// GORM exactly as a safe dynamic-filter builder would — column names and
// operators form the statement structure, every literal is a bind parameter.
//
// It implements four metamorphic / differential oracles as separate Fuzz
// targets (see *_fuzz_test.go):
//
//   - TLP   (Ternary Logic Partitioning): rows(T) == rows(p) ⊎ rows(¬p) ⊎ rows(p IS NULL)
//   - NoREC (Non-optimising Reference Engine Construction): COUNT(*) WHERE p
//     equals SUM(CASE WHEN p THEN 1 ELSE 0 END) over an un-optimisable scan.
//   - Cross-dialect equality: the same GORM query over a defined common subset
//     returns the same row-id set on modernc SQLite and PostgreSQL.
//   - Injection-structure invariance: a value passed as a bind parameter never
//     changes the prepared-statement text (DryRun SQL identical, value absent).
//
// What each oracle does NOT verify is documented on each oracle function. All oracles compare row-id *sets* (sorted), so result
// ORDER, collation-dependent ORDER BY, and NULL ordering are deliberately out
// of scope — they are known, legitimate cross-engine differences.
package sqllogicfuzz

import (
	"fmt"
	"slices"

	"gorm.io/gorm"
)

// ---------------------------------------------------------------------------
// Schema
//
// One table, six columns, chosen for identical semantics across SQLite and
// PostgreSQL within the common subset:
//
//	id  integer primary key   (generated, 1..N)
//	a   integer  NOT NULL
//	b   integer  NULL
//	c   text     NOT NULL      (ASCII lowercase only)
//	d   text     NULL          (ASCII lowercase only)
//	e   integer  NOT NULL      (0/1 "boolean" stored as integer in BOTH engines)
//
// e is a 0/1 integer in both engines on purpose: a real BOOLEAN column type
// diverges (SQLite stores 0/1, PostgreSQL has a true boolean type), which is a
// representation difference, not a logic bug — keeping e integer removes it
// from the common subset so the cross-dialect oracle tests logic, not typing.
// ---------------------------------------------------------------------------

// columns usable as leaves in the generator. b and d are the nullable ones.
var (
	numCols  = []string{"a", "b", "e"}
	textCols = []string{"c", "d"}
)

const tableCreateSQLite = `CREATE TABLE %s (
	id INTEGER PRIMARY KEY,
	a INTEGER NOT NULL,
	b INTEGER,
	c TEXT NOT NULL,
	d TEXT,
	e INTEGER NOT NULL
)`

const tableCreatePostgres = `CREATE TABLE %s (
	id BIGINT PRIMARY KEY,
	a BIGINT NOT NULL,
	b BIGINT,
	c TEXT NOT NULL,
	d TEXT,
	e BIGINT NOT NULL
)`

// Row is one generated tuple. Nullable columns use pointers (nil => SQL NULL).
type Row struct {
	ID int64
	A  int64
	B  *int64
	C  string
	D  *string
	E  int64
}

// ---------------------------------------------------------------------------
// Deterministic byte stream: the fuzzer's []byte drives every choice, so a
// corpus entry replays identically.
// ---------------------------------------------------------------------------

type stream struct {
	b   []byte
	pos int
}

func newStream(b []byte) *stream { return &stream{b: b} }

func (s *stream) byte() byte {
	if s.pos >= len(s.b) {
		// Deterministic padding once input is exhausted; keeps generation
		// bounded and total without panicking on short inputs.
		s.pos++
		return byte(s.pos * 31)
	}
	v := s.b[s.pos]
	s.pos++
	return v
}

// intn returns a value in [0,n). n must be > 0.
func (s *stream) intn(n int) int {
	if n <= 1 {
		return 0
	}
	return int(s.byte()) % n
}

// smallInt returns an int64 in [-lim, lim].
func (s *stream) smallInt(lim int) int64 {
	v := int(s.byte())%(2*lim+1) - lim
	return int64(v)
}

// bool returns a coin flip.
func (s *stream) bool() bool { return s.byte()&1 == 1 }

// ---------------------------------------------------------------------------
// Random data generator
// ---------------------------------------------------------------------------

var textAlphabet = []string{"", "a", "b", "c", "ab", "ba", "cc", "abc"}

// GenRows produces 1..maxRows rows. Values are small so arithmetic in the
// common subset cannot overflow a 64-bit integer (|value| stays well under
// 2^62 even through multiplication at the generator's bounded depth).
func GenRows(s *stream, maxRows int) []Row {
	n := 1 + s.intn(maxRows)
	rows := make([]Row, n)
	for i := range rows {
		r := Row{ID: int64(i + 1)}
		r.A = s.smallInt(30)
		if s.intn(4) != 0 { // ~75% populated
			v := s.smallInt(30)
			r.B = &v
		}
		r.C = textAlphabet[s.intn(len(textAlphabet))]
		if s.intn(4) != 0 {
			v := textAlphabet[s.intn(len(textAlphabet))]
			r.D = &v
		}
		r.E = int64(s.intn(2))
		rows[i] = r
	}
	return rows
}

// ---------------------------------------------------------------------------
// Typed predicate generator (bounded depth).
//
// A predicate is rendered to a parametrised SQL fragment: column names and
// operators are structure, every literal is a `?` bind parameter. This mirrors
// how a safe application assembles a dynamic WHERE from a validated column
// whitelist — it never interpolates a user value into SQL.
// ---------------------------------------------------------------------------

// Gen holds generation options.
type Gen struct {
	s        *stream
	maxDepth int
	// commonSubset restricts operators to the SQLite∩PostgreSQL logic subset
	// (no text ordering comparisons, no LIKE, no division/modulo). Used by the
	// cross-dialect oracle; the single-engine oracles (TLP/NoREC) leave it off.
	commonSubset bool
}

// Frag is a rendered SQL fragment plus its bind arguments.
type Frag struct {
	SQL  string
	Args []any
}

// GenPredicate builds a boolean predicate fragment.
func GenPredicate(s *stream, maxDepth int, commonSubset bool) Frag {
	g := &Gen{s: s, maxDepth: maxDepth, commonSubset: commonSubset}
	return g.boolExpr(0)
}

func (g *Gen) boolExpr(depth int) Frag {
	if depth >= g.maxDepth {
		return g.boolLeaf()
	}
	switch g.s.intn(6) {
	case 0, 1:
		return g.boolLeaf()
	case 2: // AND
		l, r := g.boolExpr(depth+1), g.boolExpr(depth+1)
		return Frag{"(" + l.SQL + ") AND (" + r.SQL + ")", append(l.Args, r.Args...)}
	case 3: // OR
		l, r := g.boolExpr(depth+1), g.boolExpr(depth+1)
		return Frag{"(" + l.SQL + ") OR (" + r.SQL + ")", append(l.Args, r.Args...)}
	case 4: // NOT
		l := g.boolExpr(depth + 1)
		return Frag{"NOT (" + l.SQL + ")", l.Args}
	default: // IS [NOT] NULL over a scalar
		e := g.scalar(depth + 1)
		op := " IS NULL"
		if g.s.bool() {
			op = " IS NOT NULL"
		}
		return Frag{"(" + e.SQL + ")" + op, e.Args}
	}
}

// boolLeaf is a comparison or the e flag.
//
// In commonSubset mode the LEFT operand of every comparison is column-rooted,
// so a bind parameter on the right is always compared against (or combined
// with) a typed column. This matters for PostgreSQL: it resolves an untyped
// bind parameter's type bottom-up from its operands, so `? + ?` or `? = ?`
// (two untyped parameters) is "operator is not unique / could not determine
// data type" — a parameter-type-inference rule, not a logic difference, and a
// shape Keyorix never produces (parameters are always bound against a typed
// column). Keeping a column on the left removes that degenerate shape without
// weakening the logic oracle. SQLite (untyped) is unaffected either way.
func (g *Gen) boolLeaf() Frag {
	switch g.s.intn(3) {
	case 0: // numeric comparison
		var l Frag
		if g.commonSubset {
			l = g.numColExpr(g.maxDepth)
		} else {
			l = g.numExpr(g.maxDepth)
		}
		r := g.numExpr(g.maxDepth)
		op := g.cmpOp(true)
		return Frag{l.SQL + op + r.SQL, append(l.Args, r.Args...)}
	case 1: // text comparison
		var l Frag
		if g.commonSubset {
			l = Frag{textCols[g.s.intn(len(textCols))], nil} // column-rooted left
		} else {
			l = g.textExpr()
		}
		r := g.textExpr()
		op := g.cmpOp(false)
		return Frag{l.SQL + op + r.SQL, append(l.Args, r.Args...)}
	default: // the e flag
		return Frag{"e = ?", []any{int64(g.s.intn(2))}}
	}
}

// scalar returns a numeric or text scalar (used under IS NULL). In commonSubset
// mode it is column-rooted so the parameter types are inferable in PostgreSQL.
func (g *Gen) scalar(depth int) Frag {
	if g.s.bool() {
		if g.commonSubset {
			return g.numColExpr(depth)
		}
		return g.numExpr(depth)
	}
	if g.commonSubset {
		return Frag{textCols[g.s.intn(len(textCols))], nil}
	}
	return g.textExpr()
}

// numColExpr builds a numeric expression whose left operand is always a column,
// so every bind parameter it contains is combined with a typed value.
func (g *Gen) numColExpr(depth int) Frag {
	col := Frag{numCols[g.s.intn(len(numCols))], nil}
	if depth <= 0 || g.s.intn(2) == 0 {
		return col
	}
	r := g.numExpr(depth - 1)
	ops := []string{" + ", " - ", " * "}
	op := ops[g.s.intn(len(ops))]
	return Frag{"(" + col.SQL + op + r.SQL + ")", r.Args}
}

func (g *Gen) cmpOp(numeric bool) string {
	if numeric {
		ops := []string{" = ", " <> ", " < ", " <= ", " > ", " >= "}
		return ops[g.s.intn(len(ops))]
	}
	// text
	if g.commonSubset {
		ops := []string{" = ", " <> "} // ordering comparisons are collation-dependent
		return ops[g.s.intn(len(ops))]
	}
	ops := []string{" = ", " <> ", " < ", " <= ", " > ", " >= "}
	return ops[g.s.intn(len(ops))]
}

func (g *Gen) numExpr(depth int) Frag {
	if depth <= 0 || g.s.intn(2) == 0 {
		// leaf: a column or a constant
		if g.s.bool() {
			return Frag{numCols[g.s.intn(len(numCols))], nil}
		}
		return Frag{"?", []any{g.s.smallInt(20)}}
	}
	// In commonSubset mode keep the left operand column-rooted so no arithmetic
	// node is `? op ?` (two untyped parameters) — see boolLeaf for why.
	var l Frag
	if g.commonSubset {
		l = g.numColExpr(depth - 1)
	} else {
		l = g.numExpr(depth - 1)
	}
	r := g.numExpr(depth - 1)
	ops := []string{" + ", " - ", " * "} // no / or % (divide-by-zero diverges)
	op := ops[g.s.intn(len(ops))]
	return Frag{"(" + l.SQL + op + r.SQL + ")", append(l.Args, r.Args...)}
}

func (g *Gen) textExpr() Frag {
	if g.s.bool() {
		return Frag{textCols[g.s.intn(len(textCols))], nil}
	}
	return Frag{"?", []any{textAlphabet[g.s.intn(len(textAlphabet))]}}
}

// ---------------------------------------------------------------------------
// GORM execution helpers. Row-id sets are the comparison currency everywhere.
// ---------------------------------------------------------------------------

// InsertRows bulk-inserts rows into the named table via parametrised GORM Exec.
func InsertRows(db *gorm.DB, table string, rows []Row) error {
	for _, r := range rows {
		var b any
		if r.B != nil {
			b = *r.B
		}
		var d any
		if r.D != nil {
			d = *r.D
		}
		sql := fmt.Sprintf("INSERT INTO %s (id,a,b,c,d,e) VALUES (?,?,?,?,?,?)", table)
		if err := db.Exec(sql, r.ID, r.A, b, r.C, d, r.E).Error; err != nil {
			return err
		}
	}
	return nil
}

// SelectIDs runs SELECT id FROM table [WHERE where] and returns a sorted slice.
// An empty where selects all rows. This exercises GORM clause building
// (.Table().Where().Pluck()), which is the construction path under test.
func SelectIDs(db *gorm.DB, table, where string, args []any) ([]int64, error) {
	var ids []int64
	tx := db.Table(table)
	if where != "" {
		tx = tx.Where(where, args...)
	}
	if err := tx.Pluck("id", &ids).Error; err != nil {
		return nil, err
	}
	slices.Sort(ids)
	return ids, nil
}

// ---------------------------------------------------------------------------
// Oracle: TLP
// ---------------------------------------------------------------------------

// TLPResult reports the outcome of one TLP check.
type TLPResult struct {
	All, PTrue, PFalse, PNull []int64
	// Mismatch is non-empty when the partition failed.
	Mismatch string
}

// Ok reports whether the partition held.
func (r TLPResult) Ok() bool { return r.Mismatch == "" }

// CheckTLP runs the Ternary Logic Partitioning oracle over one predicate.
//
// Oracle: every row of T lands in exactly one of {p TRUE, p FALSE, p NULL}.
// So sort(ids(p) ⊎ ids(¬p) ⊎ ids(p IS NULL)) == sort(ids(T)), with the three
// sets pairwise disjoint.
//
// Does NOT verify: result ordering, column values (only row-id membership),
// query performance, or any predicate the generator cannot express (LIKE,
// subqueries, aggregates, window functions, JOINs). A predicate that errors on
// the engine is surfaced as an error, not a logic mismatch.
func CheckTLP(db *gorm.DB, table string, p Frag) (TLPResult, error) {
	var res TLPResult
	var err error
	if res.All, err = SelectIDs(db, table, "", nil); err != nil {
		return res, err
	}
	if res.PTrue, err = SelectIDs(db, table, p.SQL, p.Args); err != nil {
		return res, fmt.Errorf("p: %w", err)
	}
	if res.PFalse, err = SelectIDs(db, table, "NOT ("+p.SQL+")", p.Args); err != nil {
		return res, fmt.Errorf("not p: %w", err)
	}
	if res.PNull, err = SelectIDs(db, table, "("+p.SQL+") IS NULL", p.Args); err != nil {
		return res, fmt.Errorf("p is null: %w", err)
	}
	union := append(append(append([]int64{}, res.PTrue...), res.PFalse...), res.PNull...)
	slices.Sort(union)
	// disjointness: union length must equal distinct count must equal len(All)
	if dup := firstDup(union); dup != nil {
		res.Mismatch = fmt.Sprintf("partitions overlap at id %d (predicate %q)", *dup, p.SQL)
		return res, nil
	}
	if !equalInt64(union, res.All) {
		res.Mismatch = fmt.Sprintf("union %v != all %v (predicate %q)", union, res.All, p.SQL)
	}
	return res, nil
}

// ---------------------------------------------------------------------------
// Oracle: NoREC
// ---------------------------------------------------------------------------

// CheckNoREC runs the NoREC oracle over one predicate.
//
//	optimised:   SELECT COUNT(*) FROM t WHERE p
//	unoptimised: SELECT SUM(CASE WHEN p THEN 1 ELSE 0 END) FROM (SELECT * FROM t) s
//
// The predicate is pushed into a projection the engine cannot answer from an
// index, so an optimiser bug that mis-evaluates the WHERE form shows up as a
// count disagreement. Both forms count only rows where p is TRUE (NULL and
// FALSE fall into ELSE 0), matching WHERE's three-valued logic.
//
// Does NOT verify: which rows (only their count), ordering, or anything the
// predicate grammar cannot express. Returns the two counts and whether they
// agree.
func CheckNoREC(db *gorm.DB, table string, p Frag) (optimised, unoptimised int64, err error) {
	// optimised, built through GORM's clause builder
	if err = db.Table(table).Where(p.SQL, p.Args...).Count(&optimised).Error; err != nil {
		return 0, 0, fmt.Errorf("optimised: %w", err)
	}
	// unoptimised; the predicate appears inside CASE in a derived table
	raw := fmt.Sprintf(
		"SELECT COALESCE(SUM(CASE WHEN (%s) THEN 1 ELSE 0 END),0) FROM (SELECT * FROM %s) AS s",
		p.SQL, table)
	if err = db.Raw(raw, p.Args...).Scan(&unoptimised).Error; err != nil {
		return 0, 0, fmt.Errorf("unoptimised: %w", err)
	}
	return optimised, unoptimised, nil
}

// ---------------------------------------------------------------------------
// Oracle: injection-structure invariance (DryRun)
// ---------------------------------------------------------------------------

// DryRunSQL renders the SQL GORM would emit for build, without executing it.
func DryRunSQL(db *gorm.DB, build func(*gorm.DB) *gorm.DB) (sql string, vars []any) {
	sess := db.Session(&gorm.Session{DryRun: true})
	var dst []Row
	tx := build(sess.Table("t")).Find(&dst)
	return tx.Statement.SQL.String(), tx.Statement.Vars
}

// StructureStable reports whether substituting a hostile value for a benign one
// leaves the prepared-statement text byte-identical AND the hostile value is
// carried as a bound parameter (present in Vars). A false result means the
// value changed the statement structure — i.e. it was interpolated, not bound.
//
// The structure check compares the hostile SQL against a benign-value baseline:
// any interpolation changes the text relative to that baseline, which is the
// sound test. (An earlier "hostile value must not be a substring of the SQL"
// heuristic was removed — it false-positives whenever a short hostile value
// coincides with a structural SQL token such as a column name, e.g. the value
// " c" matching "WHERE c", even though the value is correctly bound. The
// baseline comparison already catches real interpolation, so the substring
// check added only false positives.)
//
// Does NOT verify: that the value is safe at execution time on a specific
// driver, runtime escaping, or any construction path not exercised by buildFn.
// It verifies two things: structure invariance under value substitution, and
// that the value is actually bound as a parameter.
func StructureStable(db *gorm.DB, buildFn func(tx *gorm.DB, v string) *gorm.DB, hostile string) (stable bool, detail string) {
	const benign = "keyorix-benign-sentinel"
	sqlB, _ := DryRunSQL(db, func(tx *gorm.DB) *gorm.DB { return buildFn(tx, benign) })
	sqlH, varsH := DryRunSQL(db, func(tx *gorm.DB) *gorm.DB { return buildFn(tx, hostile) })
	if sqlB != sqlH {
		return false, fmt.Sprintf("SQL changed:\n benign=%q\n hostile=%q", sqlB, sqlH)
	}
	if !varsContains(varsH, hostile) {
		return false, fmt.Sprintf("hostile value %q not carried as a bound parameter (vars=%v)", hostile, varsH)
	}
	return true, ""
}

// varsContains reports whether v appears among the bound parameters (GORM
// flattens slice args, e.g. IN ?, into Vars).
func varsContains(vars []any, v string) bool {
	for _, a := range vars {
		if s, ok := a.(string); ok && s == v {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// small helpers
// ---------------------------------------------------------------------------

func equalInt64(a, b []int64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func firstDup(sorted []int64) *int64 {
	for i := 1; i < len(sorted); i++ {
		if sorted[i] == sorted[i-1] {
			return &sorted[i]
		}
	}
	return nil
}
