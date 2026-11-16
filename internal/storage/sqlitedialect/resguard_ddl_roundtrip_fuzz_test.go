package sqlite

// SP1 target: the SQLite DDL parser (parseDDL) + printer (ddl.compile) as a
// PARSE/PRINT ROUND-TRIP and a DIFFERENTIAL-vs-real-engine target.
//
// Reachability: the GORM SQLite migrator (migrator.go) reads a table's CREATE
// TABLE text straight out of sqlite_master ("SELECT sql FROM sqlite_master …"),
// parses it with parseDDL, mutates the parsed ddl (AlterColumn/DropColumn/
// AddConstraint via a table rebuild) and compiles it back with ddl.compile to
// run against the live database. The parsed text is therefore PERSISTED schema
// DDL, and a parse/compile disagreement would corrupt a real table during a
// migration — a live, reachable path on the SQLite backend.
//
// Two oracles, both REAL (not just "doesn't panic"):
//
//  1. ROUND-TRIP / idempotence (every input, pure). For an input that parseDDL
//     accepts as a CREATE TABLE, compile()'s output must (a) re-parse without
//     error, (b) preserve the parsed column metadata exactly, and (c) be a fixed
//     point of compile∘parse (compiling the re-parse yields the identical
//     string). This is the migrator's actual contract: whatever compile emits
//     must parse back to the same schema on the next migration pass.
//
//  2. DIFFERENTIAL vs the real modernc SQLite engine (sampled inputs only, to
//     keep exec/s up). If the engine accepts the ORIGINAL input as a CREATE
//     TABLE, it must also accept compile()'s normalised output, and PRAGMA
//     table_info must list the same column names in the same order. This checks
//     the parser/printer's model against the ground-truth SQL engine, not just
//     against itself.
//
// Resource angle (why resguard): parseDDL is regex-heavy and builds the body a
// rune at a time with `buf += string(c)` (ddlmod.go) — an O(n^2) shape on a
// large body. The alloc/malloc budget (per-byte slope) is a bounded-work oracle:
// a DDL whose parse allocates super-linearly in its length fails. Only the
// parser is metered; the engine differential runs outside Measure so its cost
// never pollutes the parser budget. Meters enabled: alloc_bytes, mallocs
// (sampled, fatal), cpu_ns/wall_ns (advisory). No disk/net/sleep/db seam is used
// by parseDDL, so those meters are not wired.
//
// What this target does NOT verify: it does not check that parseDDL's column
// model matches SQLite's semantics for inputs the engine REJECTS (the
// differential is gated on the engine accepting the original — parseDDL is
// deliberately lenient); it compares only column *names/order* from the engine,
// not affinity/constraints/defaults (those are compared only in the pure
// column-metadata digest, which is the parser's own view); the engine
// differential runs on sampled inputs only, so an engine-divergence on an
// unsampled input is seen only if that input also tripped SlowWall; it does not
// exercise the migrator's mutate step (renameTable/addConstraint) — only
// parse→print. No production code is modified.

import (
	"database/sql"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
	"github.com/keyorixhq/keyorix/internal/fuzzutil/resguard"
)

const ddlPilotBudgetPath = "testdata/resguard-sqlite-ddl.json"

// ddlSeeds are valid CREATE TABLE statements of varied size/shape, including one
// deliberately long column list so the alloc per-byte slope is calibrated
// against a realistically-large (but benign) schema, not only tiny ones.
func ddlSeeds() []string {
	seeds := []string{
		"CREATE TABLE users (id integer PRIMARY KEY, name text NOT NULL)",
		"CREATE TABLE `t` (`a` INTEGER, `b` TEXT DEFAULT 'x', `c` REAL)",
		`CREATE TABLE "quoted" (id INTEGER NOT NULL UNIQUE, email VARCHAR(255))`,
		"CREATE TABLE kv (k text PRIMARY KEY, v blob, CONSTRAINT `uq` UNIQUE (k))",
		"CREATE TABLE opt (a int, b int) WITHOUT ROWID",
		"CREATE TABLE strictt (a INTEGER, b TEXT) STRICT",
		"CREATE TABLE fk (id integer, parent integer, FOREIGN KEY(parent) REFERENCES fk(id))",
		"CREATE TABLE chk (n integer, CHECK (n > 0))",
		"CREATE TABLE multi (a int, b int, c int, PRIMARY KEY (a, b))",
		"CREATE TABLE defs (a int DEFAULT 1, s text DEFAULT 'hi', g int GENERATED ALWAYS AS (a+1))",
	}
	// One wide table: 40 columns -> a long body, so the per-byte slope floor
	// reflects a legitimately-large schema.
	var b strings.Builder
	b.WriteString("CREATE TABLE wide (")
	for i := range 40 {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "col%d integer DEFAULT %d", i, i)
	}
	b.WriteString(")")
	seeds = append(seeds, b.String())
	return seeds
}

// isTableDDL reports whether d is a CREATE TABLE ddl with a parsed column list —
// the only shape parseDDL actually models (index DDL parses to an empty ddl, and
// a bare `CREATE TABLE t AS SELECT …` has no column list). The round-trip oracle
// is scoped to this shape; anything else is a parseDDL non-result and skipped.
func isTableDDL(d *ddl) bool {
	if d == nil || len(d.fields) == 0 {
		return false
	}
	return strings.HasPrefix(strings.ToUpper(strings.TrimSpace(d.head)), "CREATE TABLE")
}

// colDigest is a deterministic, comparable rendering of a ddl's parsed column
// metadata — the migrator-relevant parser output. Equality across a round-trip
// means compile preserved every column's name/type/flags/default/length.
func colDigest(d *ddl) string {
	var b strings.Builder
	for _, c := range d.columns {
		fmt.Fprintf(&b, "name=%q type=%q coltype=%q pk=%s uniq=%s null=%s def=%q(%v) len=%d(%v)|",
			c.NameValue.String, c.DataTypeValue.String, c.ColumnTypeValue.String,
			nb(c.PrimaryKeyValue), nb(c.UniqueValue), nb(c.NullableValue),
			c.DefaultValueValue.String, c.DefaultValueValue.Valid,
			c.LengthValue.Int64, c.LengthValue.Valid)
	}
	return b.String()
}

func nb(v sql.NullBool) string {
	if !v.Valid {
		return "?"
	}
	if v.Bool {
		return "T"
	}
	return "F"
}

// roundTripViolation runs the parse/compile round-trip oracle on an
// already-parsed table ddl d1, using the supplied recompile function (the real
// (*ddl).compile for the fuzz target; a deliberately-broken copy for the RED
// proof). It returns a non-empty description of the first violation, or "" when
// the round-trip holds. This is the single assertion both the fuzzer and the
// red/green test drive, so the guard is exercised by the same code it protects.
func roundTripViolation(d1 *ddl, recompile func(*ddl) string) string {
	n1 := recompile(d1)
	d2, err := parseDDL(n1)
	if err != nil {
		return fmt.Sprintf("recompiled DDL does not re-parse: %v\n  recompiled=%q", err, n1)
	}
	if !isTableDDL(d2) {
		return fmt.Sprintf("recompiled DDL no longer parses as a CREATE TABLE\n  recompiled=%q", n1)
	}
	if g1, g2 := colDigest(d1), colDigest(d2); g1 != g2 {
		return fmt.Sprintf("column metadata changed across round-trip:\n  before=%s\n  after =%s\n  recompiled=%q", g1, g2, n1)
	}
	if n2 := recompile(d2); n1 != n2 {
		return fmt.Sprintf("compile is not idempotent:\n  n1=%q\n  n2=%q", n1, n2)
	}
	return ""
}

// realCompile is the production printer as a plain function value.
func realCompile(d *ddl) string { return d.compile() }

// engineColumnsFor runs ddl on a fresh in-memory modernc SQLite engine and
// returns the single created table's column names in definition order. ok is
// false when the engine REJECTS the DDL or it did not create exactly one table
// (a multi-statement or no-table input). This is both the reachability GATE
// (the migrator only ever parses DDL the engine itself stored in sqlite_master,
// so parseDDL's leniency on engine-INVALID input is out of scope) and the
// ground truth for the differential oracle.
func engineColumnsFor(ddl string) ([]string, bool) {
	db, err := sql.Open(DriverName, ":memory:")
	if err != nil {
		return nil, false
	}
	defer func() { _ = db.Close() }()
	if _, err := db.Exec(ddl); err != nil {
		return nil, false
	}
	return singleTableColumns(db)
}

// singleTableColumns returns the column names (definition order) of the single
// table in db, and false if there is not exactly one table (so a multi-statement
// or no-table input is skipped, never a false positive).
func singleTableColumns(db *sql.DB) ([]string, bool) {
	rows, err := db.Query("SELECT name FROM sqlite_master WHERE type='table'")
	if err != nil {
		return nil, false
	}
	var tables []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			_ = rows.Close()
			return nil, false
		}
		tables = append(tables, n)
	}
	_ = rows.Close()
	if len(tables) != 1 {
		return nil, false
	}
	// #nosec G202 -- table name comes from sqlite_master of our own :memory: DB.
	pr, err := db.Query("PRAGMA table_info(" + quoteIdent(tables[0]) + ")")
	if err != nil {
		return nil, false
	}
	defer func() { _ = pr.Close() }()
	var cols []string
	for pr.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt sql.NullString
		if err := pr.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return nil, false
		}
		cols = append(cols, name)
	}
	return cols, true
}

func quoteIdent(s string) string { return `"` + strings.ReplaceAll(s, `"`, `""`) + `"` }

// FuzzSqliteDDLRoundTrip drives both oracles, scoped to the migrator's real
// domain: DDL the SQLite engine accepts (what sqlite_master stores). parseDDL is
// metered by resguard (bounded-work on alloc).
func FuzzSqliteDDLRoundTrip(f *testing.F) {
	for _, s := range ddlSeeds() {
		f.Add(s)
	}
	// A few non-table / malformed seeds so the corpus exercises the fail-closed
	// path (parseDDL errors -> skipped, never a failure).
	f.Add("CREATE INDEX idx ON t (a)")
	f.Add("not ddl at all")
	f.Add("CREATE TABLE t (a int")

	probe := resguard.New(f, resguard.Options{SampleEvery: 32})
	budget, err := resguard.LoadBudget(ddlPilotBudgetPath)
	haveBudget := err == nil
	if !haveBudget {
		f.Logf("no committed budget at %s (run TestResguardSqliteDDLCalibrate with RESGUARD_CALIBRATE=1); metering without a ceiling", ddlPilotBudgetPath)
	} else {
		// alloc_bytes/mallocs are per-input ReadMemStats DELTAS around parseDDL
		// (via complexity.Measure) — truly attributable to this input. live_heap
		// (also calibrated, kept in the JSON for reference) is the whole-process
		// HeapAlloc after a GC, which the go-fuzz engine's own growing corpus
		// inflates over a long run — not a single input's fault. Enforce only the
		// attributable meters, per the RSG2 KeepOnly discipline. cpu_ns/wall_ns
		// stay advisory in meterDescs and never fail alone.
		budget.KeepOnly("alloc_bytes", "mallocs")
	}

	f.Fuzz(func(t *testing.T, s string) {
		var d1 *ddl
		var perr error
		cost := probe.Measure(len(s), func() {
			fuzzutil.Guard(t.Fatalf, "parseDDL", func() {
				d1, perr = parseDDL(s)
			})
		})
		resguard.FeedCoverage(cost)
		if haveBudget {
			budget.Check(t.Fatalf, cost)
		}

		if perr != nil || !isTableDDL(d1) {
			return // fail-closed / non-table: parseDDL models only CREATE TABLE
		}

		// Reachability GATE 0: valid UTF-8. parseDDL converts its input to []rune
		// (ddlmod.go: `[]rune(ddlBody)`), which maps every invalid-UTF-8 byte to
		// U+FFFD — so the GORM ddlmod parser is NOT byte-preserving on non-UTF-8
		// identifiers (a `\xff` in a column name comes back as the 3-byte
		// replacement char, and the recompiled DDL creates a differently-named
		// column). Keyorix schema identifiers are always ASCII and sqlite_master
		// stores exactly the DDL SQLite accepted, so non-UTF-8 DDL is never parsed
		// by any live caller. That lossiness is a documented third-party quirk
		// (SP1 report, EXPECTED-DIFFERENCE), out of this oracle's reachable scope.
		if !utf8.ValidString(s) {
			return
		}

		// Reachability GATE: the migrator parses only engine-stored DDL. If the
		// real engine rejects the original (parseDDL is deliberately lenient) or
		// it is not a single-table statement, the round-trip property is not
		// required — skip, never a false positive. Wrapped in Guard so a
		// pathological DDL cannot hang the worker inside the engine.
		var origCols []string
		var engineValid bool
		fuzzutil.Guard(t.Fatalf, "sqlite-engine-gate", func() {
			origCols, engineValid = engineColumnsFor(s)
		})
		if !engineValid {
			return
		}

		// Oracle 1 (pure): compile's output must re-parse, preserve the parsed
		// column metadata (type/flags/default/length — richer than the engine's
		// column-name view), and be an idempotent fixed point of compile∘parse.
		if v := roundTripViolation(d1, realCompile); v != "" {
			t.Fatalf("ROUND-TRIP violated (engine-valid input):\n  input=%q\n  %s", s, v)
		}

		// Oracle 2 (differential): the recompiled DDL must also be engine-valid
		// and yield the same column names in the same order.
		recompiled := d1.compile()
		var reCols []string
		var reValid bool
		fuzzutil.Guard(t.Fatalf, "sqlite-engine-differential", func() {
			reCols, reValid = engineColumnsFor(recompiled)
		})
		if !reValid {
			t.Fatalf("DIFFERENTIAL: engine accepts original but recompiled DDL is rejected / not a single table:\n  original  =%q\n  recompiled=%q", s, recompiled)
		}
		if !slices.Equal(origCols, reCols) {
			t.Fatalf("DIFFERENTIAL: engine column set differs after recompile:\n  original   cols=%v\n  recompiled cols=%v\n  original  =%q\n  recompiled=%q", origCols, reCols, s, recompiled)
		}
	})
}

// --- calibration -----------------------------------------------------------

func calibrateSqliteDDL(tb testing.TB) resguard.Budget {
	tb.Helper()
	var costs []resguard.Cost
	for _, s := range ddlSeeds() {
		// SampleEvery:1 so every seed contributes an alloc/malloc sample.
		p := resguard.New(tb, resguard.Options{SampleEvery: 1})
		var d *ddl
		var e error
		c := p.Measure(len(s), func() { d, e = parseDDL(s) })
		if e != nil {
			tb.Fatalf("seed should parse: %q: %v", s, e)
		}
		_ = d
		costs = append(costs, c)
	}
	// alloc_bytes/mallocs stay on the per-byte slope (the right model for a
	// parser: cost scales with input length; only super-linear growth fails).
	return resguard.Calibrate("sqlite_ddl_roundtrip", costs, resguard.DefaultFactor)
}

// TestResguardSqliteDDLCalibrate regenerates the committed budget under
// RESGUARD_CALIBRATE=1; otherwise it asserts calibration produced an alloc
// budget. Deterministic (the seeds are fixed).
func TestResguardSqliteDDLCalibrate(t *testing.T) {
	b := calibrateSqliteDDL(t)
	if _, ok := b.Meters["alloc_bytes"]; !ok {
		t.Fatalf("alloc_bytes should be calibrated; meters=%v", b.Summary())
	}
	if os.Getenv("RESGUARD_CALIBRATE") == "1" {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := b.WriteJSON(ddlPilotBudgetPath); err != nil {
			t.Fatalf("write budget: %v", err)
		}
		t.Logf("wrote %s: %s", ddlPilotBudgetPath, b.Summary())
	}
}

// --- red/green proof -------------------------------------------------------

// brokenCompile is a deliberately-defective copy of ddl.compile that joins the
// column fields with a SPACE instead of a comma — a plausible printer bug. It
// exists ONLY in this test to prove the round-trip oracle is load-bearing (a
// guard nobody has watched fail is not a guard); production compile is unchanged.
func brokenCompile(d *ddl) string {
	if len(d.fields) == 0 {
		return d.head + d.suffix
	}
	return fmt.Sprintf("%s (%s)%s", d.head, strings.Join(d.fields, " "), d.suffix)
}

// TestResguardSqliteDDLRoundTripRedGreen is the committed red/green proof.
//   - GREEN: every benign seed round-trips under the REAL compile (oracle returns "").
//   - RED: the same seeds under brokenCompile (fields joined by space) violate the
//     oracle — the recompiled DDL merges columns, so the column-metadata digest
//     changes (or the DDL fails to re-parse). The guard fires.
func TestResguardSqliteDDLRoundTripRedGreen(t *testing.T) {
	multiColSeeds := []string{
		"CREATE TABLE users (id integer PRIMARY KEY, name text NOT NULL)",
		"CREATE TABLE `t` (`a` INTEGER, `b` TEXT DEFAULT 'x', `c` REAL)",
		`CREATE TABLE "quoted" (id INTEGER NOT NULL UNIQUE, email VARCHAR(255))`,
	}
	for _, s := range multiColSeeds {
		d1, err := parseDDL(s)
		if err != nil || !isTableDDL(d1) {
			t.Fatalf("seed must parse as a table: %q (err=%v)", s, err)
		}
		if len(d1.columns) < 2 {
			t.Fatalf("red/green seed must have >=2 columns: %q", s)
		}
		// GREEN
		if v := roundTripViolation(d1, realCompile); v != "" {
			t.Fatalf("GREEN failed — real compile should round-trip %q:\n  %s", s, v)
		}
		// RED
		if v := roundTripViolation(d1, brokenCompile); v == "" {
			t.Fatalf("RED failed — brokenCompile should have violated the round-trip for %q but the oracle was silent", s)
		}
	}
}

// TestResguardSqliteDDLDifferentialSmoke is a GREEN smoke of oracle #2: the
// benign seeds that the real engine accepts must round-trip through the engine
// with an identical column set. (The RED side of the differential is implicit:
// brokenCompile's space-joined output changes the column set, which the same
// column comparison would reject — covered by the round-trip red/green above,
// which fires before the engine is ever reached.)
func TestResguardSqliteDDLDifferentialSmoke(t *testing.T) {
	var ran int
	for _, s := range ddlSeeds() {
		d1, err := parseDDL(s)
		if err != nil || !isTableDDL(d1) {
			continue
		}
		origCols, ok := engineColumnsFor(s)
		if !ok {
			continue // seed not engine-valid-single-table; out of the oracle's domain
		}
		ran++
		reCols, reValid := engineColumnsFor(d1.compile())
		if !reValid {
			t.Fatalf("GREEN differential failed: recompiled seed rejected by engine: %q", s)
		}
		if !slices.Equal(origCols, reCols) {
			t.Fatalf("GREEN differential failed: column set changed for seed %q:\n  orig=%v re=%v", s, origCols, reCols)
		}
	}
	if ran == 0 {
		t.Fatal("differential smoke exercised 0 engine-accepted seeds — the oracle never ran")
	}
	t.Logf("differential smoke: %d seeds exercised through the real engine", ran)
}
