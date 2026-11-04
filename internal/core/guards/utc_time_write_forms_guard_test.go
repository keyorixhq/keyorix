// utc_time_write_forms_guard_test.go -- GUARD-PROMOTE-2 item 3, the widening of
// TestEveryUnhookedExpiryWriteInCoreIsUTC (client_time_utc_guard_test.go).
//
// That guard reads only keyed fields of a models.T composite literal. The same class
// (a time with a non-UTC zone reaches an SQLite column, where it is stored as text that
// neither scans back nor orders against the UTC "now" bound) also gets in through writes
// that guard cannot see. This one covers them, in the core family
// (srcpath.CoreFamilyGoFiles), for the fields and columns it names:
//
//   - FIELDS: a name ending in ExpiresAt, Expiration, LastUsedAt or LastSeenAt.
//   - COLUMNS: expires_at (or a *_expires_at name), expiration, last_used_at, last_seen_at.
//
// What it recognises (the enumeration, stated so a reviewer can check it):
//   - an assignment `x.F = expr` whose left side is a selector with a guarded field name;
//   - a call `.UpdateColumn("col", expr)` or `.Update("col", expr)` with a guarded literal column;
//   - a call `.Updates(map[...]...{"col": expr})` or `.UpdateColumns(map...)` with a guarded
//     literal key.
//
// A write is accepted when expr is nil (a NULL, not a time) or is traceably UTC by the same rule
// as the sibling guard (tracesToUTC: a call chain ending in `.UTC()`, or an identifier the same
// function assigns from such a chain, at most 4 hops).
//
// Unlike the keyed-literal guard, a BeforeSave hook is NOT accepted as protection here: gorm
// runs no hook on UpdateColumn and does not copy a hook's assignment into an Updates(map), and
// an assignment's receiver type is unknown to a shape-based scan, so a hooked field of another
// model would hide an unhooked one.
//
// What it does NOT catch:
//   - a map or column name built at runtime (a variable key, a Sprintf'd column), a map passed
//     in as a variable, and `Updates(models.T{F: v})` struct literals (the sibling guard covers
//     the expiry fields of those, not last_used_at / last_seen_at);
//   - gorm.Expr("CURRENT_TIMESTAMP") style values: not a call ending in UTC, so reported;
//   - data flow: tracing is textual and per function, as in the sibling;
//   - code outside the core family, and every other timestamp field (CreatedAt, UsedAt, ...).
// An exception that no longer matches any hit fails too.
//
// Report-only on its first day (docs/guard-rollout.d/TestEveryExpiryAssignmentAndColumnWriteInCoreIsUTC.tsv).

package guards

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/guardrules"
	"github.com/keyorixhq/keyorix/internal/testutil/srcpath"
)

// timeWriteExceptions: "file.go:Func:Target" -> why the write is safe or tracked. Filled by
// registerTimeWriteException from init() in a utc_time_write_exceptions_test.go, one row each
// (the file is absent while the table is empty).
var timeWriteExceptions = map[string]string{}

func registerTimeWriteException(key, reason string) {
	if _, dup := timeWriteExceptions[key]; dup {
		panic("duplicate time-write UTC exception " + key)
	}
	timeWriteExceptions[key] = reason
}

type timeWrite struct {
	File, Func, Target, Form string
	Line                     int
	UTC                      bool
}

func (w timeWrite) key() string { return w.File + ":" + w.Func + ":" + w.Target }

func isGuardedTimeField(name string) bool {
	return isExpiryFieldName(name) || name == "LastUsedAt" || name == "LastSeenAt"
}

func isGuardedTimeColumn(col string) bool {
	return col == "expires_at" || strings.HasSuffix(col, "_expires_at") || col == "expiration" ||
		col == "last_used_at" || col == "last_seen_at"
}

func isNilIdent(e ast.Expr) bool {
	id, ok := stripExpr(e).(*ast.Ident)
	return ok && id.Name == "nil"
}

func stringLit(e ast.Expr) (string, bool) {
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	s, err := strconv.Unquote(lit.Value)
	return s, err == nil
}

// scanTimeWrites returns every guarded assignment and column write in f.
func scanTimeWrites(fset *token.FileSet, f *ast.File, file string) []timeWrite {
	var out []timeWrite
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		add := func(pos token.Pos, target, form string, val ast.Expr) {
			if isNilIdent(val) {
				return
			}
			out = append(out, timeWrite{
				File: file, Func: fn.Name.Name, Target: target, Form: form,
				Line: fset.Position(pos).Line, UTC: tracesToUTC(val, fn.Body, 0),
			})
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.AssignStmt:
				if x.Tok != token.ASSIGN || len(x.Lhs) != len(x.Rhs) {
					return true
				}
				for i, lhs := range x.Lhs {
					if sel, ok := lhs.(*ast.SelectorExpr); ok && isGuardedTimeField(sel.Sel.Name) {
						add(sel.Pos(), sel.Sel.Name, "assignment", x.Rhs[i])
					}
				}
			case *ast.CallExpr:
				sel, ok := x.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				switch sel.Sel.Name {
				case "Update", "UpdateColumn":
					if len(x.Args) != 2 {
						return true
					}
					if col, ok := stringLit(x.Args[0]); ok && isGuardedTimeColumn(col) {
						add(x.Args[0].Pos(), col, sel.Sel.Name, x.Args[1])
					}
				case "Updates", "UpdateColumns":
					if len(x.Args) != 1 {
						return true
					}
					lit, ok := x.Args[0].(*ast.CompositeLit)
					if !ok {
						return true
					}
					if _, isMap := lit.Type.(*ast.MapType); !isMap {
						return true
					}
					for _, el := range lit.Elts {
						kv, ok := el.(*ast.KeyValueExpr)
						if !ok {
							continue
						}
						if col, ok := stringLit(kv.Key); ok && isGuardedTimeColumn(col) {
							add(kv.Pos(), col, sel.Sel.Name+"(map)", kv.Value)
						}
					}
				}
			}
			return true
		})
	}
	return out
}

func scanTimeWritesInSource(t testing.TB, file, src string) []timeWrite {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, src, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
	return scanTimeWrites(fset, f, filepath.Base(file))
}

// Planted shapes, red then green: "a guard nobody has watched fail is not a guard".
func TestTimeWriteScanner_Calibration(t *testing.T) {
	for name, src := range map[string]string{
		"assignment, local clock":     "package core\nfunc f(r *models.T) {\n\tr.ExpiresAt = c.now().Add(ttl)\n}",
		"assignment, client value":    "package core\nfunc f(r *models.T, e time.Time) {\n\tr.AbsoluteExpiresAt = e\n}",
		"assignment last_used":        "package core\nfunc f(r *models.T) {\n\tr.LastUsedAt = c.now()\n}",
		"assignment last_seen":        "package core\nfunc f(r *models.T) {\n\tr.LastSeenAt = &now\n}",
		"UpdateColumn":                "package core\nfunc f(db *gorm.DB) {\n\tdb.UpdateColumn(\"last_used_at\", c.now())\n}",
		"Update with column":          "package core\nfunc f(db *gorm.DB) {\n\tdb.Model(m).Update(\"expires_at\", exp)\n}",
		"Updates map":                 "package core\nfunc f(db *gorm.DB) {\n\tdb.Updates(map[string]any{\"last_seen_at\": c.now(), \"x\": 1})\n}",
		"Updates map, suffix column":  "package core\nfunc f(db *gorm.DB) {\n\tdb.Updates(map[string]interface{}{\"one_time_password_expires_at\": exp})\n}",
		"gorm.Expr is not UTC-traced": "package core\nfunc f(db *gorm.DB) {\n\tdb.UpdateColumn(\"last_used_at\", gorm.Expr(\"CURRENT_TIMESTAMP\"))\n}",
	} {
		got := scanTimeWritesInSource(t, "calibration_input", src)
		if len(got) != 1 || got[0].UTC {
			t.Errorf("%s: want one non-UTC write, got %+v", name, got)
		}
	}

	for name, src := range map[string]string{
		"assignment inline UTC": "package core\nfunc f(r *models.T) {\n\tr.ExpiresAt = c.now().Add(ttl).UTC()\n}",
		"assignment via var":    "package core\nfunc f(r *models.T) {\n\tnow := c.now().UTC()\n\tr.LastUsedAt = &now\n}",
		"UpdateColumn UTC":      "package core\nfunc f(db *gorm.DB) {\n\tdb.UpdateColumn(\"last_used_at\", c.now().UTC())\n}",
		"Updates map UTC":       "package core\nfunc f(db *gorm.DB) {\n\tnow := c.now().UTC()\n\tdb.Updates(map[string]any{\"last_seen_at\": now})\n}",
		"column cleared to nil": "package core\nfunc f(db *gorm.DB) {\n\tdb.Update(\"expires_at\", nil)\n}",
		"field cleared to nil":  "package core\nfunc f(r *models.T) {\n\tr.ExpiresAt = nil\n}",
	} {
		got := scanTimeWritesInSource(t, "calibration_input", src)
		switch {
		case strings.HasPrefix(name, "column cleared") || strings.HasPrefix(name, "field cleared"):
			if len(got) != 0 {
				t.Errorf("%s: want no write, got %+v", name, got)
			}
		case len(got) != 1 || !got[0].UTC:
			t.Errorf("%s: want one UTC-traced write, got %+v", name, got)
		}
	}

	// Names and columns the guard does not own.
	for name, src := range map[string]string{
		"other field":         "package core\nfunc f(r *models.T) {\n\tr.CreatedAt = c.now()\n}",
		"other column":        "package core\nfunc f(db *gorm.DB) {\n\tdb.UpdateColumn(\"used_at\", c.now())\n}",
		"counter named Expir": "package core\nfunc f(r *models.T) {\n\tr.ExpiredPATs = 3\n}",
		"non-map Updates":     "package core\nfunc f(db *gorm.DB) {\n\tdb.Updates(models.T{Name: \"x\"})\n}",
		"define, not assign":  "package core\nfunc f() {\n\tx := c.now()\n\t_ = x\n}",
	} {
		if got := scanTimeWritesInSource(t, "calibration_input", src); len(got) != 0 {
			t.Errorf("%s: want no write, got %+v", name, got)
		}
	}
}

func TestRegisterTimeWriteException_RejectsADuplicateKey(t *testing.T) {
	const key = "auth.go:Probe:ExpiresAt"
	registerTimeWriteException(key, "first")
	t.Cleanup(func() { delete(timeWriteExceptions, key) })
	defer func() {
		if r := recover(); r != "duplicate time-write UTC exception "+key {
			t.Errorf("want the duplicate-key panic, got %v", r)
		}
		if timeWriteExceptions[key] != "first" {
			t.Errorf("duplicate overwrote the first reason: %q", timeWriteExceptions[key])
		}
	}()
	registerTimeWriteException(key, "second")
}

func TestEveryExpiryAssignmentAndColumnWriteInCoreIsUTC(t *testing.T) {
	g := guardrules.Rollout(t)
	var all, hits []timeWrite
	for _, path := range coreFamilySources(t) {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, w := range scanTimeWrites(fset, f, srcpath.CoreFamilyRel(path)) {
			all = append(all, w)
			if !w.UTC {
				hits = append(hits, w)
			}
		}
	}
	// A floor, so a scanner that silently matches nothing fails loudly.
	if len(all) < 3 {
		g.Fatalf("scanner found only %d guarded assignment/column writes in the whole core family; it has stopped matching", len(all))
	}

	used := map[string]bool{}
	var msgs []string
	for _, w := range hits {
		if _, ok := timeWriteExceptions[w.key()]; ok {
			used[w.key()] = true
			continue
		}
		msgs = append(msgs, fmt.Sprintf("%s:%d in %s writes %s (%s) without .UTC()", w.File, w.Line, w.Func, w.Target, w.Form))
	}
	sort.Strings(msgs)
	for _, m := range msgs {
		g.Errorf("%s: on SQLite a non-UTC time is stored as text that neither scans back nor orders against the UTC \"now\" bound, "+
			"and gorm runs no BeforeSave hook on UpdateColumn. Normalise at the write (`x = x.UTC()`, or `now := c.now().UTC()`), or add a "+
			"utc_time_write_exceptions_test.go registerTimeWriteException row with the reason it is safe", m)
	}
	for key, why := range timeWriteExceptions {
		if !used[key] {
			g.Errorf("exception %q (%s) matches no hit any more: delete its row", key, why)
		}
	}
}
