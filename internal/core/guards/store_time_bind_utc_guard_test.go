// store_time_bind_utc_guard_test.go -- TZ-RESIDUE-1 item 4 (#3914).
//
// The class: a store reader binds a time.Time that carries the HOST zone against a time column
// that holds UTC text. On the production SQLite dialect (modernc) a bound time is rendered in the
// zone it carries and SQLite orders the text by wall clock, so west of UTC an overdue row drops out
// of the result and east of UTC a not-yet-due row is included (#3914: break-glass
// ListUnreviewedBreakGlassActivationsBefore, #3913: RestoreProject). PostgreSQL compares instants,
// so only SQLite deployments see it. The repo's convention is that the store normalises the bound
// value itself (`cutoff.UTC()`), whatever zone the core caller computed it in.
//
// What it recognises (the enumeration, stated so a reviewer can check it):
//   - a call `<x>.Where|Or|Not|Having|Raw|Joins|Exec(query, args...)` in a non-test file of
//     internal/storage/store whose first argument resolves to a string: a literal, a package-level
//     string const of the package, or a `+` concatenation of those;
//   - in that string, a comparison `<column> <|<=|>|>= ?` or `<column> BETWEEN ? AND ?` where the
//     last dotted segment of <column> names a time column (ends in _at, _time, _date, or is
//     expiration / expires);
//   - the bound argument for that placeholder (the n-th `?` of the string maps to args[n]) must be
//     traceably UTC with the same textual per-function tracing as client_time_utc_guard_test.go
//     (tracesToUTC): a call chain ending in `.UTC()`, or an identifier the function assigns from
//     one (`cutoff = cutoff.UTC()`, `now := time.Now().UTC()`).
//
// What it does NOT catch:
//   - a placeholder whose argument it cannot map: a spread `args...` or a query built with a
//     non-constant string; these are counted and logged, never silently dropped;
//   - equality (`created_at = ?`), structs/maps as conditions, and GORM's own `Update("col", t)`
//     writes (the writers are covered by the UTC-WRITES guards);
//   - a helper that returns a UTC value other than the ones in storeUTCPreservingHelpers: it is a
//     hit until an exception row says why it is safe. rbacEffectiveNow is listed because it returns
//     either its argument or an earlier value of the same kind (a watermark of past arguments), so
//     it is UTC exactly when its argument is;
//   - data flow: tracing is textual, so a `.UTC()` on a different variable of the same name in
//     another branch satisfies it;
//   - packages other than internal/storage/store.
// Wrong-reason exemptions are checked too: an exception that no longer matches a hit fails.
//
// Report-only on its first day (docs/guard-rollout.d/TestEveryStoreTimeBindIsUTC.tsv).

package guards

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/guardrules"
	"github.com/keyorixhq/keyorix/internal/testutil/srcpath"
)

// storeTimeBindExceptions: "file.go:Func:column" -> why the bind is safe. Filled by
// registerStoreTimeBindException from init() in store_time_bind_utc_exception_<slug>_test.go (one
// row per file; there is none while the table is empty).
var storeTimeBindExceptions = map[string]string{}

func registerStoreTimeBindException(key, reason string) {
	if _, dup := storeTimeBindExceptions[key]; dup {
		panic("duplicate store-time-bind exception " + key)
	}
	storeTimeBindExceptions[key] = reason
}

func TestRegisterStoreTimeBindException_RejectsADuplicateKey(t *testing.T) {
	const key = "local_probe:Probe:created_at" // a synthetic key; not a file name
	registerStoreTimeBindException(key, "first")
	t.Cleanup(func() { delete(storeTimeBindExceptions, key) })
	defer func() {
		if r := recover(); r != "duplicate store-time-bind exception "+key {
			t.Fatalf("want the duplicate panic, got %v", r)
		}
	}()
	registerStoreTimeBindException(key, "second")
}

// storeTimeBind is one time comparison of a query string and what is bound to it.
type storeTimeBind struct {
	File, Func, Column string
	Line               int
	UTC                bool
	Mapped             bool // false: the argument could not be mapped to the placeholder
}

func (b storeTimeBind) key() string { return b.File + ":" + b.Func + ":" + b.Column }

var storeTimeQueryMethods = map[string]bool{"Where": true, "Or": true, "Not": true, "Having": true, "Raw": true, "Joins": true, "Exec": true}

// storeTimeCmpRE: a comparison of a (possibly qualified) column with a placeholder.
var storeTimeCmpRE = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_.]*)\s*(?:<=|>=|<|>)\s*\?|([A-Za-z_][A-Za-z0-9_.]*)\s+(?i:between)\s+\?\s+(?i:and)\s+\?`)

func isTimeColumn(col string) bool {
	if i := strings.LastIndex(col, "."); i >= 0 {
		col = col[i+1:]
	}
	col = strings.ToLower(col)
	return strings.HasSuffix(col, "_at") || strings.HasSuffix(col, "_time") || strings.HasSuffix(col, "_date") ||
		col == "expiration" || col == "expires"
}

// timeComparisons returns, for each time comparison in query, its column and the placeholder
// indexes (0-based, counting every `?` of the string) it binds.
func timeComparisons(query string) (cols []string, idxs [][]int) {
	for _, m := range storeTimeCmpRE.FindAllStringSubmatchIndex(query, -1) {
		col, between := "", false
		if m[2] >= 0 {
			col = query[m[2]:m[3]]
		} else {
			col, between = query[m[4]:m[5]], true
		}
		if !isTimeColumn(col) {
			continue
		}
		// The first placeholder this match binds is the first `?` at or after the column.
		first := strings.Count(query[:m[1]], "?") - 1
		if between {
			first = strings.Count(query[:m[1]], "?") - 2
		}
		ids := []int{first}
		if between {
			ids = append(ids, first+1)
		}
		cols = append(cols, col)
		idxs = append(idxs, ids)
	}
	return cols, idxs
}

// constString resolves e to a string: a literal, a package-level string const, or a + of those.
func constString(e ast.Expr, consts map[string]string) (string, bool) {
	switch x := e.(type) {
	case *ast.BasicLit:
		if x.Kind != token.STRING {
			return "", false
		}
		s, err := strconv.Unquote(x.Value)
		return s, err == nil
	case *ast.Ident:
		s, ok := consts[x.Name]
		return s, ok
	case *ast.ParenExpr:
		return constString(x.X, consts)
	case *ast.BinaryExpr:
		if x.Op != token.ADD {
			return "", false
		}
		l, ok1 := constString(x.X, consts)
		r, ok2 := constString(x.Y, consts)
		return l + r, ok1 && ok2
	}
	return "", false
}

// packageStringConsts collects the package-level string consts of files, resolving consts that
// refer to earlier ones.
func packageStringConsts(files []*ast.File) map[string]string {
	consts := map[string]string{}
	for changed := true; changed; {
		changed = false
		for _, f := range files {
			for _, d := range f.Decls {
				gd, ok := d.(*ast.GenDecl)
				if !ok || gd.Tok != token.CONST {
					continue
				}
				for _, spec := range gd.Specs {
					vs := spec.(*ast.ValueSpec)
					for i, name := range vs.Names {
						if _, done := consts[name.Name]; done || i >= len(vs.Values) {
							continue
						}
						if s, ok := constString(vs.Values[i], consts); ok {
							consts[name.Name] = s
							changed = true
						}
					}
				}
			}
		}
	}
	return consts
}

// storeUTCPreservingHelpers return their (first) argument or an earlier argument of an earlier
// call, so the result is UTC exactly when the argument is.
var storeUTCPreservingHelpers = map[string]bool{"rbacEffectiveNow": true}

// chainIsUTC reports whether e is a time expression that is UTC by construction: a call chain with
// `.UTC()` anywhere along its receivers where only zone-preserving methods (Add, AddDate, Truncate,
// Round) follow it (`time.Now().UTC().Add(-d)`), or `time.Date(..., time.UTC)`.
func chainIsUTC(e ast.Expr) bool {
	for {
		call, ok := stripExpr(e).(*ast.CallExpr)
		if !ok {
			return false
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return false
		}
		switch sel.Sel.Name {
		case "UTC":
			return true
		case "Add", "AddDate", "Truncate", "Round":
			e = sel.X
		case "Date":
			pkg, ok := sel.X.(*ast.Ident)
			if !ok || pkg.Name != "time" || len(call.Args) == 0 {
				return false
			}
			loc, ok := call.Args[len(call.Args)-1].(*ast.SelectorExpr)
			lp, _ := loc.X.(*ast.Ident)
			return ok && lp != nil && lp.Name == "time" && loc.Sel.Name == "UTC"
		default:
			return false
		}
	}
}

// storeBindIsUTC is tracesToUTC that also accepts chainIsUTC values and sees through a
// UTC-preserving helper call, directly or through a local assigned from one
// (`now := ls.rbacEffectiveNow(time.Now().UTC())`, `cutoff := time.Now().UTC().Add(-d)`).
func storeBindIsUTC(expr ast.Expr, body *ast.BlockStmt) bool {
	return storeBindIsUTCDepth(expr, body, 0)
}

func storeBindIsUTCDepth(expr ast.Expr, body *ast.BlockStmt, depth int) bool {
	if depth > 4 {
		return false
	}
	if chainIsUTC(expr) || tracesToUTC(expr, body, 0) {
		return true
	}
	if arg, ok := preservingHelperArg(expr); ok {
		return storeBindIsUTCDepth(arg, body, depth+1)
	}
	id, ok := stripExpr(expr).(*ast.Ident)
	if !ok {
		return false
	}
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok || len(as.Lhs) != len(as.Rhs) {
			return !found
		}
		for i, lhs := range as.Lhs {
			l, ok := lhs.(*ast.Ident)
			if !ok || l.Name != id.Name {
				continue
			}
			if rhsID, ok := stripExpr(as.Rhs[i]).(*ast.Ident); ok && rhsID.Name == id.Name {
				continue
			}
			if storeBindIsUTCDepth(as.Rhs[i], body, depth+1) {
				found = true
			}
		}
		return !found
	})
	return found
}

func preservingHelperArg(e ast.Expr) (ast.Expr, bool) {
	call, ok := stripExpr(e).(*ast.CallExpr)
	if !ok || len(call.Args) == 0 {
		return nil, false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || !storeUTCPreservingHelpers[sel.Sel.Name] {
		return nil, false
	}
	return call.Args[0], true
}

func scanStoreTimeBinds(fset *token.FileSet, f *ast.File, file string, consts map[string]string) []storeTimeBind {
	var out []storeTimeBind
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || !storeTimeQueryMethods[sel.Sel.Name] {
				return true
			}
			query, ok := constString(call.Args[0], consts)
			if !ok {
				return true
			}
			cols, idxs := timeComparisons(query)
			for i, col := range cols {
				for _, ph := range idxs[i] {
					b := storeTimeBind{File: file, Func: fn.Name.Name, Column: col, Line: fset.Position(call.Pos()).Line}
					if call.Ellipsis == token.NoPos && 1+ph < len(call.Args) {
						b.Mapped = true
						b.UTC = storeBindIsUTC(call.Args[1+ph], fn.Body)
					}
					out = append(out, b)
				}
			}
			return true
		})
	}
	return out
}

func scanStoreTimeBindsInSource(t testing.TB, src string) []storeTimeBind {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "calibration_input", src, 0) // a synthetic name; not a file
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return scanStoreTimeBinds(fset, f, "calibration_input", packageStringConsts([]*ast.File{f}))
}

// The planted shapes. Each unsafe one must be found and each safe one must not be: "a guard nobody
// has watched fail is not a guard", and one that always fails is as useless.
func TestStoreTimeBindScanner_Calibration(t *testing.T) {
	for name, src := range map[string]string{
		"param as given":     "package s\nfunc f(cutoff time.Time) {\n\tdb.Where(\"created_at <= ?\", cutoff)\n}",
		"core clock":         "package s\nfunc f() {\n\tdb.Where(\"expires_at < ?\", time.Now())\n}",
		"qualified column":   "package s\nfunc f(since time.Time) {\n\tdb.Joins(\"JOIN x ON x.id = l.x\").Where(\"l.access_time >= ?\", since)\n}",
		"const query":        "package s\nconst q = \"deleted_at IS NOT NULL AND deleted_at < ?\"\nfunc f(b time.Time) {\n\tdb.Where(q, b)\n}",
		"second placeholder": "package s\nfunc f(id uint, t time.Time) {\n\tdb.Where(\"project_id = ? AND last_used_at < ?\", id, t)\n}",
		"raw exec":           "package s\nfunc f(id uint, t time.Time) {\n\ttx.Exec(\"UPDATE x SET y = NULL WHERE id = ? AND deleted_at >= ?\", id, t)\n}",
		"local clock offset": "package s\nfunc f(d time.Duration) {\n\tcut := time.Now().Add(-d)\n\tdb.Where(\"created_at < ?\", cut)\n}",
		"helper on a param":  "package s\nfunc f(t time.Time) {\n\tdb.Where(\"expires_at > ?\", ls.rbacEffectiveNow(t))\n}",
		"between":            "package s\nfunc f(a, b time.Time) {\n\tdb.Where(\"event_time BETWEEN ? AND ?\", a, b)\n}",
	} {
		got := scanStoreTimeBindsInSource(t, src)
		if len(got) == 0 {
			t.Errorf("%s: want a bind, got none", name)
			continue
		}
		for _, b := range got {
			if b.UTC || !b.Mapped {
				t.Errorf("%s: want a mapped non-UTC bind, got %+v", name, b)
			}
		}
	}

	for name, src := range map[string]string{
		"inline UTC":         "package s\nfunc f(c time.Time) {\n\tdb.Where(\"created_at <= ?\", c.UTC())\n}",
		"reassigned":         "package s\nfunc f(cutoff time.Time) {\n\tcutoff = cutoff.UTC()\n\tdb.Where(\"created_at <= ?\", cutoff)\n}",
		"now UTC":            "package s\nfunc f() {\n\tnow := time.Now().UTC()\n\tdb.Where(\"expires_at < ?\", now)\n}",
		"derived from UTC":   "package s\nfunc f(s time.Duration) {\n\tnow := time.Now().UTC()\n\tcut := now.Add(-s)\n\tdb.Where(\"expires_at < ?\", cut)\n}",
		"only id compared":   "package s\nfunc f(id uint) {\n\tdb.Where(\"id > ?\", id)\n}",
		"non-time column":    "package s\nfunc f(n int) {\n\tdb.Where(\"read_count < ?\", n)\n}",
		"is-null no bind":    "package s\nfunc f() {\n\tdb.Where(\"deleted_at IS NULL\")\n}",
		"second placeholder": "package s\nfunc f(id uint, t time.Time) {\n\tdb.Where(\"project_id = ? AND last_used_at < ?\", id, t.UTC())\n}",
		"UTC then Add":       "package s\nfunc f(d time.Duration) {\n\tcut := time.Now().UTC().Add(-d)\n\tdb.Where(\"created_at < ?\", cut)\n}",
		"time.Date in UTC":   "package s\nfunc f(y int) {\n\tm := time.Date(y, 1, 1, 0, 0, 0, 0, time.UTC)\n\tdb.Where(\"snapshot_date < ?\", m)\n}",
		"helper on UTC":      "package s\nfunc f() {\n\tdb.Where(\"expires_at > ?\", ls.rbacEffectiveNow(time.Now().UTC()))\n}",
		"local from helper":  "package s\nfunc f() {\n\tnow := ls.rbacEffectiveNow(time.Now().UTC())\n\tdb.Where(\"expires_at > ?\", now)\n}",
	} {
		for _, b := range scanStoreTimeBindsInSource(t, src) {
			if !b.UTC || !b.Mapped {
				t.Errorf("%s: want only UTC-traced binds, got %+v", name, b)
			}
		}
	}

	// A spread cannot be mapped: it must be reported as unmapped, not skipped.
	got := scanStoreTimeBindsInSource(t, "package s\nfunc f(a []any) {\n\tdb.Where(\"created_at < ?\", a...)\n}")
	if len(got) != 1 || got[0].Mapped {
		t.Errorf("spread: want one unmapped bind, got %+v", got)
	}
}

func storeSourceFiles(t testing.TB) (paths []string) {
	t.Helper()
	dir := filepath.Join(srcpath.RepoRoot(), "internal", "storage", "store")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		paths = append(paths, filepath.Join(dir, e.Name()))
	}
	return paths
}

func TestEveryStoreTimeBindIsUTC(t *testing.T) {
	g := guardrules.Rollout(t)
	fset := token.NewFileSet()
	var files []*ast.File
	var names []string
	for _, path := range storeSourceFiles(t) {
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		files = append(files, f)
		names = append(names, filepath.Base(path))
	}
	consts := packageStringConsts(files)

	var all, hits, unmapped []storeTimeBind
	for i, f := range files {
		for _, b := range scanStoreTimeBinds(fset, f, names[i], consts) {
			all = append(all, b)
			switch {
			case !b.Mapped:
				unmapped = append(unmapped, b)
			case !b.UTC:
				hits = append(hits, b)
			}
		}
	}
	// A floor, so a scanner that silently matches nothing fails loudly: the store has well over
	// fifty time comparisons today.
	if len(all) < 40 {
		g.Fatalf("scanner found only %d time comparisons in internal/storage/store; it has stopped matching", len(all))
	}
	for _, b := range unmapped {
		t.Logf("UNMAPPED (not checked): %s:%d in %s binds %s through a spread or an unmappable argument", b.File, b.Line, b.Func, b.Column)
	}

	used := map[string]bool{}
	var msgs []string
	for _, b := range hits {
		if _, ok := storeTimeBindExceptions[b.key()]; ok {
			used[b.key()] = true
			continue
		}
		msgs = append(msgs, fmt.Sprintf("%s:%d in %s binds %s without .UTC()", b.File, b.Line, b.Func, b.Column))
	}
	sort.Strings(msgs)
	for _, m := range msgs {
		g.Errorf("%s: on SQLite a bound time is compared as text in the zone it carries, so a host-zone value mis-orders against the UTC column. "+
			"Normalise in the store (`x = x.UTC()`, or bind `x.UTC()`), or add a store_time_bind_utc_exception_<slug>_test.go "+
			"registerStoreTimeBindException row with the reason it is safe", m)
	}
	for key, why := range storeTimeBindExceptions {
		if !used[key] {
			g.Errorf("exception %q (%s) matches no hit any more: delete its file", key, why)
		}
	}
}
