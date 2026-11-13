// schema_parity_guard_test.go -- the fresh-install vs upgrade schema-diff guard
// (STORE-PARITY-TAILS-1).
//
// A fresh install builds the schema with AutoMigrate; an upgrade runs the
// explicit migrate_*.go steps on a database written by an older release and then
// the same AutoMigrate tail. Anything AutoMigrate creates that no explicit step
// backfills exists only on fresh installs (the break-glass reviewed_by index,
// #4091, was exactly that). This guard builds both databases and compares
//
//   - tables
//   - columns: type, nullability, default
//   - indexes: name, columns, uniqueness (and the partial predicate)
//   - triggers: name, table, definition
//
// on SQLite and on PostgreSQL. The upgrade side starts from the oldest release
// the upgrade guide supports (spOldestSupported, v0.93.0), replayed from the
// committed snapshot under testdata/upgrade-snapshots{,-pg}, and boots through
// the real CreateStorage path.
//
// Every difference that is intentional goes in spAllowlist with a reason. An
// allowlist entry that no longer matches a difference fails the test too, so the
// list cannot rot into a blanket ignore.
//
// What this does NOT check: row data, sequences, functions, foreign-key and
// check constraints (the PostgreSQL fuzzer compares constraints,
// upgrade_pg_fuzz_test.go), and any source newer than the oldest supported one.
// The Postgres half skips without KEYORIX_TEST_PG_DSN.
package storage

import (
	"database/sql"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/i18n"
)

// spOldestSupported is the oldest release the upgrade guide (docs/UPGRADING.md
// section 3) starts a supported upgrade from.
const spOldestSupported = "v0.93.0"

// spShape is the comparable shape of one database. Every map is keyed so that a
// key means the same object on both backends.
type spShape struct {
	tables   map[string]string // table -> ""
	columns  map[string]string // table.column -> type|notnull|default
	indexes  map[string]string // table.index -> columns|unique|partial predicate
	triggers map[string]string // table.trigger -> definition
}

func (s *spShape) kinds() map[string]map[string]string {
	return map[string]map[string]string{
		"tables": s.tables, "columns": s.columns, "indexes": s.indexes, "triggers": s.triggers,
	}
}

// spAllowlist holds the known intentional differences between an upgraded and a
// fresh database. A key is "kind:key" (see spShape), optionally prefixed with
// "sqlite|" or "postgres|" to apply to one backend. The value is why the
// difference is expected, or the issue that tracks it.
var spAllowlist = map[string]string{
	// migrate_users.go adds the column NOT NULL DEFAULT false with a safe backfill;
	// the model (models.go MFAEnrolmentRequired, no not-null gorm tag) makes a fresh
	// install nullable. Already recorded for a fresh install in the committed
	// schema-epoch snapshots (testdata/schema_epoch/epoch-*.txt) and in
	// pgSchemaIgnored. Stricter on upgrade, every row has a value either way.
	"columns:users.mfa_enrolment_required": "EXPECTED: upgrade adds NOT NULL DEFAULT false, fresh AutoMigrate leaves it nullable; every row defaulted",
}

// spDiff returns one line per difference not covered by the allowlist, plus one
// per allowlist entry that matched nothing for this backend.
func spDiff(backend string, upgraded, fresh *spShape) []string {
	var out []string
	used := map[string]bool{}
	allowed := func(kind, key string) bool {
		for _, k := range []string{kind + ":" + key, backend + "|" + kind + ":" + key} {
			if _, ok := spAllowlist[k]; ok {
				used[k] = true
				return true
			}
		}
		return false
	}
	gk, wk := upgraded.kinds(), fresh.kinds()
	for _, kind := range []string{"tables", "columns", "indexes", "triggers"} {
		keys := map[string]bool{}
		for k := range gk[kind] {
			keys[k] = true
		}
		for k := range wk[kind] {
			keys[k] = true
		}
		for _, k := range slices.Sorted(maps.Keys(keys)) {
			g, gok := gk[kind][k]
			w, wok := wk[kind][k]
			if gok && wok && g == w {
				continue
			}
			if allowed(kind, k) {
				continue
			}
			switch {
			case gok && !wok:
				out = append(out, fmt.Sprintf("%s %s only on the upgraded database: %s", kind, k, g))
			case wok && !gok:
				out = append(out, fmt.Sprintf("%s %s missing on the upgraded database (fresh has: %s)", kind, k, w))
			default:
				out = append(out, fmt.Sprintf("%s %s differs: upgraded %s, fresh %s", kind, k, g, w))
			}
		}
	}
	for _, k := range slices.Sorted(maps.Keys(spAllowlist)) {
		if used[k] || (strings.Contains(k, "|") && !strings.HasPrefix(k, backend+"|")) {
			continue
		}
		out = append(out, "stale allowlist entry "+k+": it matches no difference any more, delete it ("+spAllowlist[k]+")")
	}
	return out
}

// ---- SQLite ----

// spSQLiteAffinity reduces a declared column type to the type affinity SQLite
// derives from it (https://www.sqlite.org/datatype3.html section 3.1). SQLite
// stores whatever spelling the DDL used, and AutoMigrate (integer, numeric) and
// the explicit ALTER TABLE ADD COLUMN steps (bigint, boolean) spell the same
// affinity differently; the affinity is what governs stored values, so that is
// what is compared.
func spSQLiteAffinity(declared string) string {
	t := strings.ToUpper(declared)
	switch {
	case strings.Contains(t, "INT"):
		return "integer"
	case strings.Contains(t, "CHAR"), strings.Contains(t, "CLOB"), strings.Contains(t, "TEXT"):
		return "text"
	case t == "", strings.Contains(t, "BLOB"):
		return "blob"
	case strings.Contains(t, "REAL"), strings.Contains(t, "FLOA"), strings.Contains(t, "DOUB"):
		return "real"
	default:
		return "numeric"
	}
}

func spReadSQLite(db *sql.DB) (*spShape, error) {
	s := &spShape{tables: map[string]string{}, columns: map[string]string{}, indexes: map[string]string{}, triggers: map[string]string{}}
	rows, err := db.Query(`SELECT type, name, tbl_name, COALESCE(sql,'') FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'`)
	if err != nil {
		return nil, err
	}
	type obj struct{ typ, name, tbl, sql string }
	var objs []obj
	for rows.Next() {
		var o obj
		if err := rows.Scan(&o.typ, &o.name, &o.tbl, &o.sql); err != nil {
			_ = rows.Close()
			return nil, err
		}
		objs = append(objs, o)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	_ = rows.Close()
	for _, o := range objs {
		switch o.typ {
		case "table":
			s.tables[o.name] = ""
			cols, err := db.Query(fmt.Sprintf("PRAGMA table_info(%q)", o.name))
			if err != nil {
				return nil, err
			}
			for cols.Next() {
				var cid, notnull, pk int
				var name, typ string
				var dflt sql.NullString
				if err := cols.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil {
					_ = cols.Close()
					return nil, err
				}
				s.columns[o.name+"."+name] = fmt.Sprintf("%s|notnull=%t|default=%s", spSQLiteAffinity(typ), notnull == 1, dflt.String)
			}
			if err := cols.Err(); err != nil {
				return nil, err
			}
			_ = cols.Close()
		case "trigger":
			s.triggers[o.tbl+"."+o.name] = strings.Join(strings.Fields(o.sql), " ")
		}
	}
	for _, o := range objs {
		if o.typ != "table" {
			continue
		}
		idxs, err := db.Query(fmt.Sprintf("PRAGMA index_list(%q)", o.name))
		if err != nil {
			return nil, err
		}
		type ix struct {
			name, origin string
			unique       int
		}
		var list []ix
		for idxs.Next() {
			var seq, partial int
			var i ix
			if err := idxs.Scan(&seq, &i.name, &i.unique, &i.origin, &partial); err != nil {
				_ = idxs.Close()
				return nil, err
			}
			list = append(list, i)
		}
		if err := idxs.Err(); err != nil {
			return nil, err
		}
		_ = idxs.Close()
		for _, i := range list {
			ic, err := db.Query(fmt.Sprintf("PRAGMA index_info(%q)", i.name))
			if err != nil {
				return nil, err
			}
			var cols []string
			for ic.Next() {
				var seqno, cid int
				var name sql.NullString
				if err := ic.Scan(&seqno, &cid, &name); err != nil {
					_ = ic.Close()
					return nil, err
				}
				cols = append(cols, name.String)
			}
			if err := ic.Err(); err != nil {
				return nil, err
			}
			_ = ic.Close()
			pred := ""
			for _, o := range objs {
				if o.typ == "index" && o.name == i.name {
					if at := strings.Index(strings.ToUpper(o.sql), " WHERE "); at >= 0 {
						pred = strings.Join(strings.Fields(o.sql[at+len(" WHERE "):]), " ")
					}
				}
			}
			key := o.name + "." + i.name
			if i.origin != "c" { // pk/unique-constraint autoindexes carry a generated name
				key = o.name + ".(" + i.origin + ")" + strings.Join(cols, ",")
			}
			s.indexes[key] = fmt.Sprintf("cols=%s|unique=%t|where=%s", strings.Join(cols, ","), i.unique == 1, pred)
		}
	}
	return s, nil
}

// spBuildSQLite returns the shape of a fresh SQLite install and of the oldest
// supported release after the real boot-time migration. mutate, when set, edits
// the upgraded database after migration (calibration only).
func spBuildSQLite(t *testing.T, mutate func(db *sql.DB)) (upgraded, fresh *spShape) {
	t.Helper()
	if err := i18n.InitializeForTesting(); err != nil {
		t.Fatalf("initializing i18n: %v", err)
	}
	dir := t.TempDir()

	freshPath := filepath.Join(dir, "fresh.db")
	st, err := NewStorageFactory().CreateStorage(ugLocalConfig(freshPath))
	if err != nil {
		t.Fatalf("fresh CreateStorage: %v", err)
	}
	_ = ugCloseStorage(st)
	fresh = spReadSQLiteFile(t, freshPath)

	tpl, err := ugLoadTemplate(spOldestSupported)
	if err != nil {
		t.Fatalf("loading %s snapshot: %v", spOldestSupported, err)
	}
	upPath := filepath.Join(dir, "upgraded.db")
	if err := ugCopyFile(tpl.dbFile, upPath); err != nil {
		t.Fatalf("copying template: %v", err)
	}
	st, err = NewStorageFactory().CreateStorage(ugLocalConfig(upPath))
	if err != nil {
		t.Fatalf("upgrading from %s: %v", spOldestSupported, err)
	}
	_ = ugCloseStorage(st)
	if mutate != nil {
		db, err := sql.Open("sqlite", upPath)
		if err != nil {
			t.Fatalf("opening upgraded db: %v", err)
		}
		mutate(db)
		_ = db.Close()
	}
	return spReadSQLiteFile(t, upPath), fresh
}

func spReadSQLiteFile(t *testing.T, path string) *spShape {
	t.Helper()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("database file: %v", err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("opening %s: %v", path, err)
	}
	defer func() { _ = db.Close() }()
	s, err := spReadSQLite(db)
	if err != nil {
		t.Fatalf("reading schema: %v", err)
	}
	return s
}

// ---- PostgreSQL ----

const spPGIndexesQ = `SELECT t.relname, i.relname, idx.indisunique, idx.indisvalid,
	COALESCE(pg_get_expr(idx.indpred, idx.indrelid), ''),
	COALESCE((SELECT string_agg(pg_get_indexdef(idx.indexrelid, k, true), ',' ORDER BY k) FROM generate_series(1, idx.indnkeyatts::int) k), '')
	FROM pg_index idx JOIN pg_class i ON i.oid = idx.indexrelid JOIN pg_class t ON t.oid = idx.indrelid
	JOIN pg_namespace n ON n.oid = t.relnamespace
	WHERE n.nspname = current_schema() AND t.relkind = 'r' ORDER BY 1, 2`

func spReadPG(db *sql.DB) (*spShape, error) {
	s := &spShape{tables: map[string]string{}, columns: map[string]string{}, indexes: map[string]string{}, triggers: map[string]string{}}
	tabs, err := pgQueryRows(db, pgTablesQ, 1)
	if err != nil {
		return nil, err
	}
	for _, r := range tabs {
		s.tables[r[0]] = ""
	}
	cols, err := pgQueryRows(db, pgColumnsQ, 5)
	if err != nil {
		return nil, err
	}
	for _, r := range cols {
		s.columns[r[0]+"."+r[1]] = fmt.Sprintf("%s|notnull=%t|default=%s", r[2], r[3] == "true" || r[3] == "t", r[4])
	}
	idx, err := pgQueryRows(db, spPGIndexesQ, 6)
	if err != nil {
		return nil, err
	}
	for _, r := range idx {
		s.indexes[r[0]+"."+r[1]] = fmt.Sprintf("cols=%s|unique=%t|valid=%t|where=%s", r[5], r[2] == "true" || r[2] == "t", r[3] == "true" || r[3] == "t", r[4])
	}
	trg, err := pgQueryRows(db, pgTriggersQ, 3)
	if err != nil {
		return nil, err
	}
	for _, r := range trg {
		s.triggers[r[1]+"."+r[0]] = strings.Join(strings.Fields(r[2]), " ")
	}
	return s, nil
}

func spBuildPG(t *testing.T, mutate func(db *sql.DB)) (upgraded, fresh *spShape) {
	t.Helper()
	base := pgTestDSN(t)
	if err := i18n.InitializeForTesting(); err != nil {
		t.Fatalf("initializing i18n: %v", err)
	}

	_, freshDSN := pgCreateDatabase(t, base)
	st, err := NewStorageFactory().CreateStorage(pgLocalConfig(freshDSN))
	if err != nil {
		t.Fatalf("fresh CreateStorage: %s", redactDSN(err))
	}
	_ = ugCloseStorage(st)
	fresh = spReadPGDSN(t, freshDSN)

	tpl, err := pgLoadTemplate(spOldestSupported)
	if err != nil {
		t.Fatalf("loading %s snapshot: %v", spOldestSupported, err)
	}
	_, upDSN := pgCreateDatabase(t, base)
	raw := pgOpenRaw(t, upDSN)
	if _, err := raw.Exec(strings.ReplaceAll(tpl.script, pgStmtSep, ";\n")); err != nil {
		_ = raw.Close()
		t.Fatalf("replaying %s snapshot: %s", spOldestSupported, redactDSN(err))
	}
	_ = raw.Close()
	st, err = NewStorageFactory().CreateStorage(pgLocalConfig(upDSN))
	if err != nil {
		t.Fatalf("upgrading from %s: %s", spOldestSupported, redactDSN(err))
	}
	_ = ugCloseStorage(st)
	if mutate != nil {
		db := pgOpenRaw(t, upDSN)
		mutate(db)
		_ = db.Close()
	}
	return spReadPGDSN(t, upDSN), fresh
}

func spReadPGDSN(t *testing.T, dsn string) *spShape {
	t.Helper()
	db := pgOpenRaw(t, dsn)
	defer func() { _ = db.Close() }()
	s, err := spReadPG(db)
	if err != nil {
		t.Fatalf("reading schema: %s", redactDSN(err))
	}
	return s
}

// ---- the guard and its calibration ----

func TestSchemaParity_FreshVsUpgrade_SQLite(t *testing.T) {
	up, fresh := spBuildSQLite(t, nil)
	for _, d := range spDiff("sqlite", up, fresh) {
		t.Errorf("fresh install and upgrade from %s differ: %s", spOldestSupported, d)
	}
}

func TestSchemaParity_FreshVsUpgrade_Postgres(t *testing.T) {
	up, fresh := spBuildPG(t, nil)
	for _, d := range spDiff("postgres", up, fresh) {
		t.Errorf("fresh install and upgrade from %s differ: %s", spOldestSupported, d)
	}
}

// The calibration plants the two drifts the guard exists for, on the real
// upgraded database, and requires the guard to name them. A guard nobody has
// watched fail is not a guard.
func TestSchemaParity_Calibration_SQLite(t *testing.T) {
	up, fresh := spBuildSQLite(t, func(db *sql.DB) {
		for _, stmt := range []string{
			"DROP INDEX idx_break_glass_activations_reviewed_by",
			"ALTER TABLE break_glass_activations DROP COLUMN role_name",
			"ALTER TABLE break_glass_activations ADD COLUMN role_name BLOB",
		} {
			if _, err := db.Exec(stmt); err != nil {
				t.Fatalf("planting drift (%s): %v", stmt, err)
			}
		}
	})
	spRequireDiffs(t, spDiff("sqlite", up, fresh),
		"indexes break_glass_activations.idx_break_glass_activations_reviewed_by missing on the upgraded database",
		"columns break_glass_activations.role_name differs")
}

func TestSchemaParity_Calibration_Postgres(t *testing.T) {
	up, fresh := spBuildPG(t, func(db *sql.DB) {
		for _, stmt := range []string{
			"DROP INDEX idx_break_glass_activations_reviewed_by",
			"ALTER TABLE break_glass_activations ALTER COLUMN role_name TYPE varchar(10)",
		} {
			if _, err := db.Exec(stmt); err != nil {
				t.Fatalf("planting drift (%s): %s", stmt, redactDSN(err))
			}
		}
	})
	spRequireDiffs(t, spDiff("postgres", up, fresh),
		"indexes break_glass_activations.idx_break_glass_activations_reviewed_by missing on the upgraded database",
		"columns break_glass_activations.role_name differs")
}

// A stale allowlist entry must fail, and so must an unlisted difference; a
// listed one must pass. Pure shape-level checks, no database.
func TestSchemaParity_AllowlistSemantics(t *testing.T) {
	saved := spAllowlist
	spAllowlist = map[string]string{}
	defer func() { spAllowlist = saved }()
	mk := func(col string) *spShape {
		return &spShape{tables: map[string]string{"t": ""}, columns: map[string]string{"t.c": col}, indexes: map[string]string{}, triggers: map[string]string{}}
	}
	if d := spDiff("sqlite", mk("text"), mk("text")); len(d) != 0 {
		t.Fatalf("identical shapes reported: %v", d)
	}
	if d := spDiff("sqlite", mk("text"), mk("blob")); len(d) != 1 || !strings.Contains(d[0], "columns t.c differs") {
		t.Fatalf("unlisted difference not reported exactly once: %v", d)
	}
	spAllowlist["columns:t.c"] = "test"
	spAllowlist["postgres|columns:t.gone"] = "test"
	if d := spDiff("sqlite", mk("text"), mk("blob")); len(d) != 0 {
		t.Fatalf("listed difference still reported (and another backend's entry must not be): %v", d)
	}
	if d := spDiff("sqlite", mk("text"), mk("text")); len(d) != 1 || !strings.Contains(d[0], "stale allowlist entry columns:t.c") {
		t.Fatalf("stale entry not reported: %v", d)
	}
}

func spRequireDiffs(t *testing.T, got []string, wantSubstrings ...string) {
	t.Helper()
	for _, want := range wantSubstrings {
		found := false
		for _, g := range got {
			if strings.Contains(g, want) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("guard did not report %q; reported: %v", want, got)
		}
	}
}
