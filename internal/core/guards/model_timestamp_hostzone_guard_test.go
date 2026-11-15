// model_timestamp_hostzone_guard_test.go -- HOSTZONE-TIME-NOV-1 item 3, the CreatedAt / UpdatedAt
// half of the UTC-write guards (client_time_utc_guard_test.go covers the expiry fields,
// utc_time_write_forms_guard_test.go the expiry / last-used / last-seen assignments and columns).
//
// The class: non-test code stamps a persisted model's CreatedAt or UpdatedAt with the HOST-zone
// clock (`UpdatedAt: time.Now()`, `x.UpdatedAt = time.Now()`, or a local `now := time.Now()` handed
// to one). GORM's NowFunc is UTC (internal/storage gormConfig), but it stamps only a ZERO field, so
// an explicit host-zone value is stored as given (TestNowFuncDoesNotCoverExplicitCreatedAt): on
// SQLite as text carrying the host offset ("2026-11-01 21:00:00 +0900 JST m=+0.01"), which does not
// order against the UTC values every other writer stores; on Postgres it is an instant (timestamptz)
// and harmless.
//
// What it recognises (the enumeration, stated so a reviewer can check it), in every non-test .go
// file under internal/ and server/ (testutil, testdata and generated protobuf excluded):
//   - a keyed field of a composite literal: `T{UpdatedAt: expr}`;
//   - an assignment `x.UpdatedAt = expr` whose left side is a selector;
//
// for the field names CreatedAt and UpdatedAt. A value is a finding when its call chain starts at
// `time.Now()` (directly, through `.Round(0)` / `.Add(d)`, or through a local identifier the same
// function assigns from such a chain) and is not traceably UTC (tracesToUTC: a chain ending in
// `.UTC()`, at most 4 hops).
//
// What it does NOT catch (each is a real gap, not a promise):
//   - a clock the function receives (`now time.Time` parameter, `c.now()` injected clock, a package
//     variable such as server's adr112Now): the origin is not in the function, so the value is not
//     provably host-zone. Those sites are normalised at their write by hand
//     (TestHostZoneTimestampSitesStoreUTC_* drive them);
//   - column-name writes (`Update("updated_at", ...)`, `Updates(map...)`): internal/storage/store's
//     TestEveryStoreTimeColumnWriteIsUTC covers those, the rest of the tree is not covered;
//   - other timestamp fields (DetectedAt, IssuedAt, ...), generated protobuf code, code outside the
//     root module (cli/, operator/);
//   - data flow: tracing is textual and per function.
//
// An exception that no longer matches any hit fails too.
//
// Report-only on its first day (docs/guard-rollout.d/TestEveryModelTimestampStampIsUTC.tsv).

package guards

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/guardrules"
	"github.com/keyorixhq/keyorix/internal/testutil/srcpath"
)

// modelTimestampExceptions: "dir/file.go:Func:Field" (path relative to the repo root) -> why the
// stamp is safe. Filled by registerModelTimestampException from init() in
// model_timestamp_hostzone_exceptions_test.go, one row each.
var modelTimestampExceptions = map[string]string{}

func registerModelTimestampException(key, reason string) {
	if _, dup := modelTimestampExceptions[key]; dup {
		panic("duplicate model-timestamp UTC exception " + key)
	}
	modelTimestampExceptions[key] = reason
}

func isModelStampField(name string) bool { return name == "CreatedAt" || name == "UpdatedAt" }

type modelStamp struct {
	File, Func, Field, Form string
	Line                    int
}

func (s modelStamp) key() string { return s.File + ":" + s.Func + ":" + s.Field }

// isTimeNowCall reports whether e is a call of time.Now().
func isTimeNowCall(e ast.Expr) bool {
	call, ok := stripExpr(e).(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Now" {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && id.Name == "time"
}

// startsAtTimeNow reports whether the call chain of e begins at time.Now(), directly or through a
// local identifier of body assigned from such a chain (at most 4 hops).
func startsAtTimeNow(e ast.Expr, body *ast.BlockStmt, depth int) bool {
	if isTimeNowCall(e) {
		return true
	}
	// Walk down a method chain: time.Now().Round(0).Add(d) -> time.Now().Round(0) -> time.Now().
	switch x := stripExpr(e).(type) {
	case *ast.CallExpr:
		if sel, ok := x.Fun.(*ast.SelectorExpr); ok {
			// A chain that passes through .UTC() no longer carries the host zone
			// (time.Now().UTC().Add(d)); tracesToUTC only sees a trailing .UTC().
			if sel.Sel.Name == "UTC" {
				return false
			}
			return startsAtTimeNow(sel.X, body, depth)
		}
		return false
	case *ast.SelectorExpr:
		return startsAtTimeNow(x.X, body, depth)
	case *ast.Ident:
		if depth > 4 {
			return false
		}
		found := false
		ast.Inspect(body, func(n ast.Node) bool {
			as, ok := n.(*ast.AssignStmt)
			if !ok || len(as.Lhs) != len(as.Rhs) {
				return !found
			}
			for i, lhs := range as.Lhs {
				if id, ok := lhs.(*ast.Ident); ok && id.Name == x.Name && startsAtTimeNow(as.Rhs[i], body, depth+1) {
					found = true
				}
			}
			return !found
		})
		return found
	}
	return false
}

// scanModelStamps returns every CreatedAt / UpdatedAt stamp in f whose value is a host-zone
// time.Now() derivative that is not traceably UTC.
func scanModelStamps(fset *token.FileSet, f *ast.File, file string) []modelStamp {
	var out []modelStamp
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		check := func(pos token.Pos, field, form string, val ast.Expr) {
			if startsAtTimeNow(val, fn.Body, 0) && !tracesToUTC(val, fn.Body, 0) {
				out = append(out, modelStamp{File: file, Func: fn.Name.Name, Field: field, Form: form, Line: fset.Position(pos).Line})
			}
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.KeyValueExpr:
				if id, ok := x.Key.(*ast.Ident); ok && isModelStampField(id.Name) {
					check(x.Pos(), id.Name, "keyed field", x.Value)
				}
			case *ast.AssignStmt:
				if x.Tok != token.ASSIGN || len(x.Lhs) != len(x.Rhs) {
					return true
				}
				for i, lhs := range x.Lhs {
					if sel, ok := lhs.(*ast.SelectorExpr); ok && isModelStampField(sel.Sel.Name) {
						check(sel.Pos(), sel.Sel.Name, "assignment", x.Rhs[i])
					}
				}
			}
			return true
		})
	}
	return out
}

func scanModelStampsInSource(t testing.TB, file, src string) []modelStamp {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, src, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
	return scanModelStamps(fset, f, file)
}

// modelStampSources lists the non-test .go files under internal/ and server/ as paths relative to
// the repo root (slash-separated).
func modelStampSources(t testing.TB) (root string, rels []string) {
	t.Helper()
	root = srcpath.RepoRoot()
	for _, top := range []string{"internal", "server"} {
		err := filepath.WalkDir(filepath.Join(root, top), func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if d.Name() == "testutil" || d.Name() == "testdata" || d.Name() == "node_modules" {
					return filepath.SkipDir
				}
				return nil
			}
			name := d.Name()
			if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") || strings.HasSuffix(name, ".pb.go") {
				return nil
			}
			rel, err := filepath.Rel(root, p)
			if err != nil {
				return err
			}
			rels = append(rels, filepath.ToSlash(rel))
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	sort.Strings(rels)
	return root, rels
}

// Planted shapes, red then green: "a guard nobody has watched fail is not a guard".
func TestModelStampScanner_Calibration(t *testing.T) {
	// Red: each of these stamps a model with the host-zone clock and must be reported once.
	for name, src := range map[string]string{
		"keyed literal":           "package p\nfunc f() {\n\t_ = &models.T{UpdatedAt: time.Now()}\n}",
		"keyed CreatedAt":         "package p\nfunc f() {\n\t_ = models.T{CreatedAt: time.Now()}\n}",
		"assignment":              "package p\nfunc f(m *models.T) {\n\tm.UpdatedAt = time.Now()\n}",
		"through a local":         "package p\nfunc f(m *models.T) {\n\tnow := time.Now()\n\tm.UpdatedAt = now\n}",
		"Round(0) keeps the zone": "package p\nfunc f(m *models.T) {\n\tm.UpdatedAt = time.Now().Round(0)\n}",
		"Add keeps the zone":      "package p\nfunc f(m *models.T) {\n\tm.CreatedAt = time.Now().Add(-time.Hour)\n}",
		"local, then Truncate":    "package p\nfunc f() {\n\tnow := time.Now().Truncate(time.Second)\n\t_ = models.T{UpdatedAt: now}\n}",
	} {
		if got := scanModelStampsInSource(t, "calibration_input", src); len(got) != 1 {
			t.Errorf("%s: want one host-zone stamp, got %+v", name, got)
		}
	}

	// Green: these are UTC, or not a host-zone origin, or not a guarded field.
	for name, src := range map[string]string{
		"inline UTC":                "package p\nfunc f(m *models.T) {\n\tm.UpdatedAt = time.Now().UTC()\n}",
		"keyed UTC":                 "package p\nfunc f() {\n\t_ = &models.T{CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}\n}",
		"local assigned UTC":        "package p\nfunc f(m *models.T) {\n\tnow := time.Now().UTC()\n\tm.UpdatedAt = now\n}",
		"local normalised later":    "package p\nfunc f(m *models.T) {\n\tnow := time.Now()\n\tnow = now.UTC()\n\tm.UpdatedAt = now\n}",
		"UTC then Add":              "package p\nfunc f(m *models.T) {\n\tm.CreatedAt = time.Now().UTC().Add(-time.Hour)\n}",
		"injected clock is unknown": "package p\nfunc f(m *models.T, c *C) {\n\tm.UpdatedAt = c.now()\n}",
		"parameter is unknown":      "package p\nfunc f(m *models.T, now time.Time) {\n\tm.UpdatedAt = now\n}",
		"other field":               "package p\nfunc f(m *models.T) {\n\tm.DetectedAt = time.Now()\n}",
		"zero value":                "package p\nfunc f(m *models.T) {\n\tm.UpdatedAt = time.Time{}\n}",
		"define, not assign":        "package p\nfunc f() {\n\tupdatedAt := time.Now()\n\t_ = updatedAt\n}",
	} {
		if got := scanModelStampsInSource(t, "calibration_input", src); len(got) != 0 {
			t.Errorf("%s: want no finding, got %+v", name, got)
		}
	}
}

func TestRegisterModelTimestampException_RejectsADuplicateKey(t *testing.T) {
	const key = "internal/core/secrets.go:Probe:UpdatedAt"
	registerModelTimestampException(key, "first")
	t.Cleanup(func() { delete(modelTimestampExceptions, key) })
	defer func() {
		if r := recover(); r != "duplicate model-timestamp UTC exception "+key {
			t.Errorf("want the duplicate-key panic, got %v", r)
		}
		if modelTimestampExceptions[key] != "first" {
			t.Errorf("duplicate overwrote the first reason: %q", modelTimestampExceptions[key])
		}
	}()
	registerModelTimestampException(key, "second")
}

func TestEveryModelTimestampStampIsUTC(t *testing.T) {
	g := guardrules.Rollout(t)
	root, rels := modelStampSources(t)
	// A floor, so a walker that silently lists nothing fails loudly.
	if len(rels) < 500 {
		g.Fatalf("only %d non-test source files under internal/ and server/: wrong root %s", len(rels), root)
	}

	used := map[string]bool{}
	var msgs []string
	for _, rel := range rels {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, filepath.Join(root, filepath.FromSlash(rel)), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", rel, err)
		}
		for _, s := range scanModelStamps(fset, f, rel) {
			if _, ok := modelTimestampExceptions[s.key()]; ok {
				used[s.key()] = true
				continue
			}
			msgs = append(msgs, fmt.Sprintf("%s:%d in %s stamps %s from the host-zone clock (%s) without .UTC()", s.File, s.Line, s.Func, s.Field, s.Form))
		}
	}
	sort.Strings(msgs)
	for _, m := range msgs {
		g.Errorf("%s: GORM's NowFunc is UTC but stamps only a zero field, so an explicit host-zone value is stored as given: on SQLite as text "+
			"with the host offset that does not order against the UTC values every other writer stores. Write `time.Now().UTC()` "+
			"(or `now := time.Now().UTC()`), or add a model_timestamp_hostzone_exceptions_test.go registerModelTimestampException row "+
			"with the reason the stamp is safe", m)
	}
	for key, why := range modelTimestampExceptions {
		if !used[key] {
			g.Errorf("exception %q (%s) matches no hit any more: delete its row", key, why)
		}
	}
}
