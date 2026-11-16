package store_test

// GM1 — gorm identifier / clause handling.
//
// These harnesses attack every place Keyorix feeds a caller- or tenant-influenced
// string to gorm through one of its list-query builders (ListSecrets, ListUsers,
// GetAuditLogs). The three builders between them consume Search, Username, Email,
// Type, Classification, CreatedBy, Action(s), Resource, IPAddress, RequestID,
// ActorUsername, ResourceType and the project/tenant scope — every free-text knob
// a list API forwards from an HTTP query string or a gRPC request.
//
// Oracle FuzzGormListSQLShape (this file): build the query in gorm DryRun on the
// SQLite dialect and (when $KEYORIX_TEST_PG_DSN is set) the PostgreSQL dialect,
// capture the PARAMETERISED SQL and its bind vars straight off db.Statement (not
// the logger, which inlines vars), and assert three sound properties plus one
// differential:
//
//   INJ   — a unique marker prefixed onto every caller string never appears in the
//           emitted SQL text; it must travel as a bind var. If any caller byte
//           reaches the statement text the builder interpolated an identifier or a
//           clause instead of binding it. (soundness: a self-consistency law —
//           parameterised SQL cannot carry its arguments in the statement body.)
//   SHAPE — the emitted SQL is a single statement: no ';' outside a string literal,
//           so a stacked "…; DROP TABLE…" cannot have been assembled.
//   TENANT— whenever a project/tenant scope was requested the project predicate is
//           present in the SQL and its id is a bind var, so the WHERE that confines
//           the result to one tenant can never be the thing that was interpolated
//           away.
//   DIFF  — the SQLite and PostgreSQL statements reduce to the SAME structural
//           skeleton (ordered keyword sequence + JOIN/WHERE/placeholder counts).
//           The legitimate SQLite↔PG differences are abstracted by the skeleton and
//           enumerated in gorm_identifier_EXPECTED_DIFFERENCE.md; a NEW divergence
//           (an extra JOIN, a dropped WHERE, a stacked statement, a differing bind
//           count) is what fails.
//
// RED/GREEN: TestGormIdentifierOracle_RedGreen below plants a deliberately
// vulnerable builder (interpolated Order / interpolated WHERE / dropped tenant
// predicate) and shows each check fires on it while staying green on the real
// builders. No production file is edited.
//
// What these oracles do NOT verify is stated in the report and in
// gorm_identifier_EXPECTED_DIFFERENCE.md.

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	storage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// kqzMarker is a token that occurs in no column name, keyword or dialect function
// of the schema. It is prefixed onto every caller-supplied string the harness
// feeds a builder; if it surfaces in the emitted SQL text the value was
// interpolated rather than bound.
const kqzMarker = "kqzmark7"

// sqlCapture records the parameterised SQL and bind vars of every statement gorm
// builds on a DryRun session. It reads db.Statement directly (an After callback),
// not the logger — the logger's Explain inlines the vars, which would defeat the
// whole INJ check.
type sqlCapture struct {
	stmts []capturedStmt
}

type capturedStmt struct {
	sql  string
	vars []any
}

func (c *sqlCapture) reset() { c.stmts = c.stmts[:0] }

func (c *sqlCapture) hook(db *gorm.DB) {
	if db.Statement == nil {
		return
	}
	s := db.Statement.SQL.String()
	if s == "" {
		return
	}
	vars := make([]any, len(db.Statement.Vars))
	copy(vars, db.Statement.Vars)
	c.stmts = append(c.stmts, capturedStmt{sql: s, vars: vars})
}

// newDryRunStore opens a DryRun gorm.DB on the given dialector, wires the capture
// hook into the query/row/raw callbacks, and returns a LocalStorage over it. No
// schema migration is needed: DryRun builds SQL from the model structs and never
// touches a table.
func newDryRunStore(t testing.TB, dialector gorm.Dialector, cap *sqlCapture) *store.LocalStorage {
	t.Helper()
	db, err := gorm.Open(dialector, &gorm.Config{
		DryRun:      true,
		QueryFields: true, // matches production gormConfig()
	})
	if err != nil {
		t.Fatalf("open %s dryrun: %v", dialector.Name(), err)
	}
	hook := func(d *gorm.DB) { cap.hook(d) }
	_ = db.Callback().Query().After("gorm:query").Register("kqz:capture", hook)
	_ = db.Callback().Row().After("gorm:row").Register("kqz:capture", hook)
	_ = db.Callback().Raw().After("gorm:raw").Register("kqz:capture", hook)
	return store.NewLocalStorage(db)
}

// --- the three builders under test, each driven from one fuzz payload ---------

func runSecretsBuilder(ctx context.Context, ls *store.LocalStorage, payload string, sel uint16) {
	f := &storage.SecretFilter{
		Type:           ptr(payload),
		CreatedBy:      ptr(payload),
		Classification: ptr(payload), // never == "unclassified" (marker prefix), so the bound branch
		Search:         ptr(payload),
		Page:           1,
		PageSize:       25,
	}
	if sel&1 != 0 {
		var pid uint = 7
		f.ProjectID = &pid
	}
	if sel&2 != 0 {
		var eid uint = 9
		f.EnvironmentID = &eid
	}
	if sel&4 != 0 {
		f.FolderOnly = true
	}
	if sel&8 != 0 {
		f.IncludeDeleted = true
	}
	if sel&16 != 0 {
		f.DeletedOnly = true
	}
	_, _, _ = ls.ListSecrets(ctx, f)
}

func runUsersBuilder(ctx context.Context, ls *store.LocalStorage, payload string, sel uint16) {
	f := &storage.UserFilter{
		Search:   ptr(payload),
		Username: ptr(payload),
		Email:    ptr(payload),
		Page:     1,
		PageSize: 25,
	}
	if sel&1 != 0 {
		f.IncludeDeleted = true
	}
	_, _, _ = ls.ListUsers(ctx, f)
}

func runAuditBuilder(ctx context.Context, ls *store.LocalStorage, payload string, sel uint16) {
	f := &storage.AuditFilter{
		Action:        ptr(payload),
		Resource:      ptr(payload),
		IPAddress:     ptr(payload),
		RequestID:     ptr(payload),
		ActorUsername: ptr(payload),
		ResourceType:  ptr(payload),
		Page:          1,
		PageSize:      25,
	}
	if sel&1 != 0 {
		var pid uint = 7
		f.ProjectID = &pid
	}
	if sel&2 != 0 {
		f.Actions = []string{payload, payload + "b"}
	}
	if sel&4 != 0 {
		f.ExcludeSystemJobEvents = true
	}
	_, _, _ = ls.GetAuditLogs(ctx, f)
}

func ptr[T any](v T) *T { return &v }

// --- the checks (return error so they are unit-testable in the red/green proof) -

// checkInjection: the marker must never reach the SQL text.
//
// The marker is a contiguous prefix of every caller string the harness feeds a
// builder, so ANY interpolation of that string into the statement body — an
// `Order(term)`, a `Where("x = '"+term+"'")`, a `Table`/`Joins`/`Select`
// built from it — copies the marker into the SQL text verbatim. The check is
// therefore sound for the realistic interpolation patterns without needing a
// second "hostile tail" scan (an earlier backstop that searched for the hostile
// SUFFIX was removed: it false-positived whenever the fuzzer picked a payload
// tail that is itself a common SQL token such as `SELECT`, which legitimately
// appears in `SELECT count(*)` — a harness bug, not an injection). A sink that
// strips exactly the marker prefix before interpolating is not a code pattern
// that occurs; if that ever became a concern, flank the payload with the marker
// on both sides rather than re-introducing a substring scan of the hostile text.
func checkInjection(backend string, stmts []capturedStmt, payload string) error {
	for _, s := range stmts {
		if strings.Contains(s.sql, kqzMarker) {
			return fmt.Errorf("[%s] INJECTION: caller marker %q reached SQL text (identifier/clause interpolated, not bound):\n  SQL: %s\n  payload=%q",
				backend, kqzMarker, s.sql, payload)
		}
	}
	return nil
}

// checkSingleStatement: no ';' outside a single-quoted string literal.
func checkSingleStatement(backend string, stmts []capturedStmt) error {
	for _, s := range stmts {
		if hasBareSemicolon(s.sql) {
			return fmt.Errorf("[%s] STACKED STATEMENT: a ';' appears outside a string literal:\n  SQL: %s", backend, s.sql)
		}
	}
	return nil
}

// hasBareSemicolon reports whether sql contains a ';' that is not inside a
// '...' string literal. gorm never emits a trailing ';', so any ';' at all is a
// red flag, but we still skip quoted ones to be precise.
func hasBareSemicolon(sql string) bool {
	inStr := false
	for i := 0; i < len(sql); i++ {
		switch sql[i] {
		case '\'':
			// handle doubled '' escape
			if inStr && i+1 < len(sql) && sql[i+1] == '\'' {
				i++
				continue
			}
			inStr = !inStr
		case ';':
			if !inStr {
				return true
			}
		}
	}
	return false
}

// checkTenant: when a project scope was requested, the project predicate must be
// present and the project id must be a bind var (not a literal in the text).
var (
	// tenantPredicateRe matches project_id used as a PREDICATE (project_id = …),
	// not project_id appearing as a selected/quoted column in the field list.
	tenantPredicateRe = regexp.MustCompile(`project_id\s*=`)
	tenantLiteralRe   = regexp.MustCompile(`project_id\s*=\s*7\b`)
)

func checkTenant(backend string, stmts []capturedStmt, wantTenant bool, tenantID uint) error {
	if !wantTenant {
		return nil
	}
	found := false
	for _, s := range stmts {
		if tenantPredicateRe.MatchString(s.sql) {
			found = true
			// the id must not be interpolated as a bare number next to project_id
			if tenantLiteralRe.MatchString(s.sql) {
				return fmt.Errorf("[%s] TENANT: project id interpolated as a literal, not bound:\n  SQL: %s", backend, s.sql)
			}
		}
	}
	if !found {
		return fmt.Errorf("[%s] TENANT: project scope requested (id=%d) but no project_id predicate was emitted:\n  stmts=%v", backend, tenantID, sqls(stmts))
	}
	return nil
}

func sqls(stmts []capturedStmt) []string {
	out := make([]string, len(stmts))
	for i, s := range stmts {
		out[i] = s.sql
	}
	return out
}

// --- differential skeleton ----------------------------------------------------

// skeleton reduces a parameterised SQL statement to its structural shape: the
// ordered sequence of the clause/connective keywords we track, plus the count of
// bind placeholders. Everything a dialect legitimately differs on — the ?/$n
// placeholder token, "/` identifier quoting, the keyorix_fold vs translate/LOWER/
// normalize fold expression, IN(SELECT) vs =ANY(ARRAY(SELECT)), GLOB vs LIKE, and
// the differently-escaped bind VALUES — lives inside a predicate and is abstracted
// away here (see gorm_identifier_EXPECTED_DIFFERENCE.md). A divergence in this
// skeleton is therefore a NEW class: an added/removed JOIN or WHERE, a stacked
// statement, or a differing number of bound arguments.
type skeleton struct {
	keywords string
	binds    int
}

var (
	placeholderRe = regexp.MustCompile(`\$\d+|\?`)
	keywordRe     = regexp.MustCompile(`(?i)\b(select|from|join|where|group by|order by|having|limit|offset|union|and|or)\b`)
	// EXPECTED-DIFFERENCE class "limit-offset-literal": gorm's SQLite dialector
	// inlines LIMIT/OFFSET as integer literals (LIMIT 25) while its PostgreSQL
	// dialector binds them (LIMIT $7). The value is a clamped integer from
	// clampPageSize/clampPage — never caller text — so this is a pure dialect
	// formatting difference, not a shape difference. Fold both forms to one token
	// before counting binds so the count is comparable across backends.
	limitOffsetLiteralRe = regexp.MustCompile(`(?i)\b(limit|offset)\s+\d+`)
)

func skeletonOf(sql string) skeleton {
	normalised := limitOffsetLiteralRe.ReplaceAllString(sql, "$1 ?")
	binds := len(placeholderRe.FindAllString(normalised, -1))
	kws := keywordRe.FindAllString(strings.ToLower(sql), -1)
	return skeleton{keywords: strings.Join(kws, " "), binds: binds}
}

// checkDifferential: the SQLite and PG statements, pairwise in emission order,
// reduce to the same skeleton.
func checkDifferential(sqliteStmts, pgStmts []capturedStmt, payload string, sel uint16) error {
	if len(sqliteStmts) != len(pgStmts) {
		return fmt.Errorf("DIFF: backend statement COUNT differs: sqlite=%d pg=%d (payload=%q sel=%d)\n  sqlite=%v\n  pg=%v",
			len(sqliteStmts), len(pgStmts), payload, sel, sqls(sqliteStmts), sqls(pgStmts))
	}
	for i := range sqliteStmts {
		sk := skeletonOf(sqliteStmts[i].sql)
		pk := skeletonOf(pgStmts[i].sql)
		if sk.keywords != pk.keywords {
			return fmt.Errorf("DIFF: NEW structural divergence in statement %d (payload=%q sel=%d)\n  sqlite keywords: %s\n  pg keywords:     %s\n  sqlite: %s\n  pg: %s",
				i, payload, sel, sk.keywords, pk.keywords, sqliteStmts[i].sql, pgStmts[i].sql)
		}
		if sk.binds != pk.binds {
			return fmt.Errorf("DIFF: NEW bind-count divergence in statement %d: sqlite=%d pg=%d (payload=%q sel=%d)\n  sqlite: %s\n  pg: %s",
				i, sk.binds, pk.binds, payload, sel, sqliteStmts[i].sql, pgStmts[i].sql)
		}
	}
	return nil
}

// --- the fuzz target ----------------------------------------------------------

func FuzzGormListSQLShape(f *testing.F) {
	f.Add("", uint16(0))
	f.Add("admin", uint16(1))
	f.Add("'; DROP TABLE secret_nodes;--", uint16(1))
	f.Add("name) UNION SELECT password FROM users--", uint16(3))
	f.Add("%_\\", uint16(2))
	f.Add("sys", uint16(7))          // audit "system" substring branch
	f.Add("unclassified", uint16(1)) // marker prefix keeps it off the sentinel branch
	f.Add("\" OR \"1\"=\"1", uint16(5))
	f.Add("项目", uint16(1)) // non-ASCII fold path
	f.Add("name ASC, (SELECT 1)", uint16(1))

	sqliteCap := &sqlCapture{}
	sqliteLS := newDryRunStore(f, sqlite.Open(":memory:"), sqliteCap)

	pgDSN := os.Getenv("KEYORIX_TEST_PG_DSN")
	var pgCap *sqlCapture
	var pgLS *store.LocalStorage
	if pgDSN != "" {
		pgCap = &sqlCapture{}
		pdb, err := gorm.Open(postgres.Open(pgDSN), &gorm.Config{DryRun: true, QueryFields: true})
		if err != nil {
			f.Fatalf("open pg dryrun: %v", err)
		}
		hook := func(d *gorm.DB) { pgCap.hook(d) }
		_ = pdb.Callback().Query().After("gorm:query").Register("kqz:capture", hook)
		_ = pdb.Callback().Row().After("gorm:row").Register("kqz:capture", hook)
		_ = pdb.Callback().Raw().After("gorm:raw").Register("kqz:capture", hook)
		pgLS = store.NewLocalStorage(pdb)
	}

	type builder struct {
		name string
		run  func(context.Context, *store.LocalStorage, string, uint16)
	}
	builders := []builder{
		{"secrets", runSecretsBuilder},
		{"users", runUsersBuilder},
		{"audit", runAuditBuilder},
	}

	f.Fuzz(func(t *testing.T, raw string, sel uint16) {
		if len(raw) > 4096 {
			raw = raw[:4096]
		}
		payload := kqzMarker + raw
		ctx := context.Background()
		wantTenant := sel&1 != 0

		for _, b := range builders {
			// secrets+audit honour ProjectID on sel bit 0; users has no project scope.
			tenant := wantTenant && b.name != "users"

			sqliteCap.reset()
			b.run(ctx, sqliteLS, payload, sel)
			sqliteStmts := append([]capturedStmt(nil), sqliteCap.stmts...)
			must(t, checkInjection("sqlite:"+b.name, sqliteStmts, payload))
			must(t, checkSingleStatement("sqlite:"+b.name, sqliteStmts))
			must(t, checkTenant("sqlite:"+b.name, sqliteStmts, tenant, 7))
			if len(sqliteStmts) == 0 {
				t.Fatalf("sqlite:%s produced no SQL (builder never ran?)", b.name)
			}

			if pgLS != nil {
				pgCap.reset()
				b.run(ctx, pgLS, payload, sel)
				pgStmts := append([]capturedStmt(nil), pgCap.stmts...)
				must(t, checkInjection("pg:"+b.name, pgStmts, payload))
				must(t, checkSingleStatement("pg:"+b.name, pgStmts))
				must(t, checkTenant("pg:"+b.name, pgStmts, tenant, 7))
				must(t, checkDifferential(sqliteStmts, pgStmts, payload, sel))
			}
		}
	})
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// --- RED/GREEN proof ----------------------------------------------------------

// vulnerableSecretsSQL builds the SQL a NAIVE ListSecrets would emit if it
// interpolated caller input into a clause instead of binding it. It exists only
// to prove the oracle's checks fire on a real injection; no production code does
// this.
func vulnerableSecretsSQL(ls *store.LocalStorage, sortBy, search string, dropTenant bool) []capturedStmt {
	// Interpolated ORDER BY and an interpolated WHERE — the exact mistakes the
	// oracle hunts for.
	q := ls.DB().Model(&models.SecretNode{})
	if !dropTenant {
		q = q.Where("secret_nodes.project_id = ?", 7)
	}
	q = q.Where("secret_nodes.name = '" + search + "'"). // fmt-style interpolation
								Order(sortBy) // interpolated identifier
	var out []*models.SecretNode
	_ = q.Find(&out).Error
	return []capturedStmt{{sql: q.Statement.SQL.String(), vars: q.Statement.Vars}}
}

func TestGormIdentifierOracle_RedGreen(t *testing.T) {
	cap := &sqlCapture{}
	ls := newDryRunStore(t, sqlite.Open(":memory:"), cap)
	payload := kqzMarker + "'; DROP TABLE secret_nodes;--"

	// GREEN: the REAL builder binds everything — every check passes.
	cap.reset()
	runSecretsBuilder(context.Background(), ls, payload, 1)
	real := append([]capturedStmt(nil), cap.stmts...)
	if err := checkInjection("real", real, payload); err != nil {
		t.Fatalf("real builder must be injection-free, got: %v", err)
	}
	if err := checkSingleStatement("real", real); err != nil {
		t.Fatalf("real builder must be single-statement, got: %v", err)
	}
	if err := checkTenant("real", real, true, 7); err != nil {
		t.Fatalf("real builder must carry the tenant predicate, got: %v", err)
	}

	// RED 1: interpolated ORDER BY / WHERE → the marker reaches the SQL text.
	bad := vulnerableSecretsSQL(ls, payload, payload, false)
	if err := checkInjection("vuln", bad, payload); err == nil {
		t.Fatalf("checkInjection FAILED to fire on interpolated clause: %s", bad[0].sql)
	}

	// RED 2: a stacked statement survives into the text.
	stacked := []capturedStmt{{sql: "SELECT * FROM secret_nodes WHERE name = 'x'; DROP TABLE users"}}
	if err := checkSingleStatement("vuln", stacked); err == nil {
		t.Fatalf("checkSingleStatement FAILED to fire on a stacked statement")
	}

	// RED 3: tenant predicate dropped → no project_id in any statement.
	noTenant := vulnerableSecretsSQL(ls, "secret_nodes.id ASC", "x", true)
	if err := checkTenant("vuln", noTenant, true, 7); err == nil {
		t.Fatalf("checkTenant FAILED to fire when the project predicate was dropped: %s", noTenant[0].sql)
	}

	// RED 4: a cross-backend structural divergence (extra JOIN on one side).
	skA := []capturedStmt{{sql: "SELECT id FROM t WHERE a = ? LIMIT 25"}}
	skB := []capturedStmt{{sql: "SELECT id FROM t JOIN u ON u.id = t.u WHERE a = $1 LIMIT $2"}}
	if err := checkDifferential(skA, skB, "p", 0); err == nil {
		t.Fatalf("checkDifferential FAILED to fire on an extra JOIN")
	}

	// GREEN differential: the known SQLite(LIMIT literal) vs PG(LIMIT bound)
	// difference is an EXPECTED-DIFFERENCE class and must NOT fire.
	okA := []capturedStmt{{sql: "SELECT id FROM t WHERE a = ? LIMIT 25"}}
	okB := []capturedStmt{{sql: "SELECT id FROM t WHERE a = $1 LIMIT $2"}}
	if err := checkDifferential(okA, okB, "p", 0); err != nil {
		t.Fatalf("checkDifferential fired on the expected LIMIT literal/bind difference: %v", err)
	}
}
