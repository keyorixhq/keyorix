// store_utc_write_guard_test.go -- UTC-STORE-SCAN-1 item 1, the internal/storage/store half of
// TestEveryUnhookedExpiryWriteInCoreIsUTC / TestEveryExpiryAssignmentAndColumnWriteInCoreIsUTC.
//
// The class is the core guards' class: a time.Time with a non-UTC zone reaches an SQLite column,
// where it is stored as text with the caller's offset that neither scans back nor orders against
// the UTC "now" / cutoff bound the expiry and staleness queries use (on Postgres it is an instant
// and harmless). The store layer is where the write happens, so the store cannot rely on its
// callers having normalised: gorm runs no BeforeSave hook and no NowFunc on UpdateColumn(s) and
// on a map passed to Updates.
//
// What it recognises (the enumeration, stated so a reviewer can check it), in every non-test .go
// file of internal/storage/store, inside a function that makes at least one gorm write call
// (Update, UpdateColumn, Updates, UpdateColumns, Exec):
//   - `.Update("col", v)` and `.UpdateColumn("col", v)` with a literal time column;
//   - a map composite literal `map[string]...{"col": v}` with a literal time column key (the
//     argument of Updates / UpdateColumns, or a `cols := map...` built first);
//   - an index assignment `m["col"] = v` with a literal time column key (`cols["updated_at"] = v`);
//   - `.Exec("<sql>", args...)` whose SQL literal names a time column and that has bind arguments.
//
// A time column is a literal name ending in _at, _until or _after, or named expiration, or
// containing "expires". The value is accepted when it is nil (a NULL), a gorm.Expr (evaluated by
// the database, no Go zone), a utcPtr(...) call, or traceably UTC by tracesToUTC
// (client_time_utc_guard_test.go): a call chain ending in `.UTC()`, or an identifier the same
// function assigns from one (`usedAt = usedAt.UTC()`), at most 4 hops.
//
// What it does NOT catch:
//   - Updates(structValue) / Save(structValue): those run the model's BeforeSave, which the
//     core guard's hook inventory (modelHookInventory) reports per field; this guard does not;
//   - a column name built at runtime, a map passed in as a parameter, a value built by a helper
//     whose name does not end in UTC (`utcPtr` is the one known exception);
//   - data flow: tracing is textual and per function;
//   - writes outside internal/storage/store, and Create of a struct (its time fields are covered
//     by the models' BeforeSave hooks and by the core guards for literals).
// An exception that no longer matches any hit fails too.
//
// Report-only on its first day (docs/guard-rollout.d/TestEveryStoreTimeColumnWriteIsUTC.tsv).

package guards

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/guardrules"
)

// storeTimeWriteExceptions: "file.go:Func:column" -> why the write is safe or tracked. Filled by
// registerStoreTimeWriteException from init() in store_utc_write_exceptions_test.go.
var storeTimeWriteExceptions = map[string]string{}

func registerStoreTimeWriteException(key, reason string) {
	if _, dup := storeTimeWriteExceptions[key]; dup {
		panic("duplicate store time-write UTC exception " + key)
	}
	storeTimeWriteExceptions[key] = reason
}

// storeScanSkippedFiles: store file -> "owner issue: why", for files another session owns and
// that this guard therefore does not scan. Filled by init() in store_utc_write_exceptions_test.go.
// A skipped file that no longer exists fails the guard, so the row cannot outlive its file.
var storeScanSkippedFiles = map[string]string{}

func registerStoreScanSkip(file, owner string) {
	if _, dup := storeScanSkippedFiles[file]; dup {
		panic("duplicate store scan skip " + file)
	}
	storeScanSkippedFiles[file] = owner
}

func TestRegisterStoreTimeWriteException_RejectsADuplicateKey(t *testing.T) {
	const key = "local_users.go:Probe:updated_at"
	registerStoreTimeWriteException(key, "first")
	t.Cleanup(func() { delete(storeTimeWriteExceptions, key) })
	require.PanicsWithValue(t, "duplicate store time-write UTC exception "+key, func() {
		registerStoreTimeWriteException(key, "second")
	})
	require.Equal(t, "first", storeTimeWriteExceptions[key])
}

type storeTimeWrite struct {
	File, Func, Column, Form string
	Line                     int
	UTC                      bool
}

func (w storeTimeWrite) key() string { return w.File + ":" + w.Func + ":" + w.Column }

func isStoreTimeColumn(col string) bool {
	return strings.HasSuffix(col, "_at") || strings.HasSuffix(col, "_until") || strings.HasSuffix(col, "_after") ||
		col == "expiration" || strings.Contains(col, "expires")
}

// storeUTCHelpers are calls that return a UTC time by their own contract: utcPtr (utc_timestamp.go)
// and models.PurgeAtFor ("computed in UTC", models.go). A database-evaluated gorm.Expr has no Go
// zone at all.
func isUTCHelperCall(e ast.Expr) bool {
	call, ok := stripExpr(e).(*ast.CallExpr)
	if !ok {
		return false
	}
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		return fn.Name == "utcPtr"
	case *ast.SelectorExpr:
		if id, ok := fn.X.(*ast.Ident); ok {
			return id.Name == "gorm" && fn.Sel.Name == "Expr" || id.Name == "models" && fn.Sel.Name == "PurgeAtFor"
		}
	}
	return false
}

// storeValueIsUTC: nil, a UTC helper call, a value the function assigns from one (`x := gorm.Expr(..)`,
// `x.F = &u` with `u := t.UTC()`), or traceably UTC by tracesToUTC.
func storeValueIsUTC(val ast.Expr, body *ast.BlockStmt) bool {
	return storeValueIsUTCDepth(val, body, 0)
}

func storeValueIsUTCDepth(val ast.Expr, body *ast.BlockStmt, depth int) bool {
	if isNilIdent(val) || isUTCHelperCall(val) || tracesToUTC(val, body, 0) {
		return true
	}
	if depth > 4 {
		return false
	}
	// `x` or `x.F` assigned elsewhere in the function from a value that is itself accepted.
	want := exprText(stripExpr(val))
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok || len(as.Lhs) != len(as.Rhs) {
			return !found
		}
		for i, lhs := range as.Lhs {
			if exprText(lhs) == want && exprText(stripExpr(as.Rhs[i])) != want && storeValueIsUTCDepth(as.Rhs[i], body, depth+1) {
				found = true
			}
		}
		return !found
	})
	return found
}

func exprText(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.SelectorExpr:
		return exprText(x.X) + "." + x.Sel.Name
	}
	return ""
}

// looksLikeTimeArg: an Exec bind argument that is a time by shape, not an id or a count: a clock
// call (`time.Now()`, `c.now()`) or a name ending in At, Time, Until, Cutoff, Expiry ...
func looksLikeTimeArg(e ast.Expr) bool {
	e = stripExpr(e)
	if call, ok := e.(*ast.CallExpr); ok {
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
			switch sel.Sel.Name {
			case "UTC", "Add", "AddDate", "Round", "Truncate", "In", "Local":
				return looksLikeTimeArg(sel.X) // a time method: judge its receiver
			}
			return strings.EqualFold(sel.Sel.Name, "now") || looksLikeTimeName(sel.Sel.Name)
		}
		return false
	}
	switch x := e.(type) {
	case *ast.Ident:
		return looksLikeTimeName(x.Name)
	case *ast.SelectorExpr:
		return looksLikeTimeName(x.Sel.Name)
	}
	return false
}

func looksLikeTimeName(n string) bool {
	for _, suf := range []string{"At", "Time", "Until", "After", "Cutoff", "Expiry", "Expires", "Deadline", "Since", "Now"} {
		if strings.HasSuffix(n, suf) {
			return true
		}
	}
	return false
}

func isGormWriteCall(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	switch sel.Sel.Name {
	case "Update", "UpdateColumn", "Updates", "UpdateColumns", "Exec":
		return len(call.Args) > 0
	}
	return false
}

// scanStoreTimeWrites returns every recognised time-column write in f.
func scanStoreTimeWrites(fset *token.FileSet, f *ast.File, file string) []storeTimeWrite {
	var out []storeTimeWrite
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		writes := false
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok && isGormWriteCall(call) {
				writes = true
			}
			return !writes
		})
		if !writes {
			continue
		}
		add := func(pos token.Pos, col, form string, val ast.Expr) {
			out = append(out, storeTimeWrite{
				File: file, Func: fn.Name.Name, Column: col, Form: form,
				Line: fset.Position(pos).Line, UTC: storeValueIsUTC(val, fn.Body),
			})
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.CallExpr:
				sel, ok := x.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				switch sel.Sel.Name {
				case "Update", "UpdateColumn":
					if len(x.Args) == 2 {
						if col, ok := stringLit(x.Args[0]); ok && isStoreTimeColumn(col) {
							add(x.Args[0].Pos(), col, sel.Sel.Name, x.Args[1])
						}
					}
				case "Exec":
					if len(x.Args) > 1 {
						if sql, ok := stringLit(x.Args[0]); ok && sqlNamesTimeColumn(sql) {
							// Every bind argument must be UTC-traceable; one report per statement.
							utc, timeArgs := true, 0
							for _, a := range x.Args[1:] {
								if looksLikeTimeArg(a) {
									timeArgs++
									utc = utc && storeValueIsUTC(a, fn.Body)
								}
							}
							if timeArgs == 0 {
								return true
							}
							out = append(out, storeTimeWrite{
								File: file, Func: fn.Name.Name, Column: "exec:" + shortSQL(sql), Form: "Exec",
								Line: fset.Position(x.Pos()).Line, UTC: utc,
							})
						}
					}
				}
			case *ast.CompositeLit:
				if _, isMap := x.Type.(*ast.MapType); !isMap {
					return true
				}
				for _, el := range x.Elts {
					if kv, ok := el.(*ast.KeyValueExpr); ok {
						if col, ok := stringLit(kv.Key); ok && isStoreTimeColumn(col) {
							add(kv.Pos(), col, "map", kv.Value)
						}
					}
				}
			case *ast.AssignStmt:
				if x.Tok != token.ASSIGN || len(x.Lhs) != len(x.Rhs) {
					return true
				}
				for i, lhs := range x.Lhs {
					if ix, ok := lhs.(*ast.IndexExpr); ok {
						if col, ok := stringLit(ix.Index); ok && isStoreTimeColumn(col) {
							add(ix.Pos(), col, "index", x.Rhs[i])
						}
					}
				}
			}
			return true
		})
	}
	return out
}

// sqlNamesTimeColumn: a bind-argument statement that SETs or compares a time column.
func sqlNamesTimeColumn(sql string) bool {
	s := strings.ToLower(sql)
	if !strings.Contains(s, "?") {
		return false
	}
	for w := range strings.FieldsFuncSeq(s, func(r rune) bool { return !(r == '_' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9') }) {
		if isStoreTimeColumn(w) {
			return true
		}
	}
	return false
}

func shortSQL(sql string) string {
	f := strings.Fields(sql)
	if len(f) > 4 {
		f = f[:4]
	}
	return strings.Join(f, " ")
}

func scanStoreTimeWritesInSource(t testing.TB, file, src string) []storeTimeWrite {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, src, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
	return scanStoreTimeWrites(fset, f, filepath.Base(file))
}

// Planted shapes, red then green: "a guard nobody has watched fail is not a guard".
func TestStoreTimeWriteScanner_Calibration(t *testing.T) {
	for name, src := range map[string]string{
		"UpdateColumn param as sent":  "package store\nfunc (ls *L) F(at time.Time) error {\n\treturn ls.db.UpdateColumn(\"last_login_at\", at).Error\n}",
		"Update param as sent":        "package store\nfunc (ls *L) F(at time.Time) error {\n\treturn ls.db.Update(\"decided_at\", at).Error\n}",
		"map value as sent":           "package store\nfunc (ls *L) F(at time.Time) error {\n\treturn ls.db.Updates(map[string]any{\"password_changed_at\": at}).Error\n}",
		"cols map as sent":            "package store\nfunc (ls *L) F(at time.Time) error {\n\tcols := map[string]any{\"updated_at\": at}\n\treturn ls.db.Updates(cols).Error\n}",
		"index assignment as sent":    "package store\nfunc (ls *L) F(at time.Time) error {\n\tcols := map[string]any{}\n\tcols[\"updated_at\"] = at\n\treturn ls.db.Updates(cols).Error\n}",
		"pointer expiry as sent":      "package store\nfunc (ls *L) F(e *time.Time) error {\n\treturn ls.db.Updates(map[string]any{\"one_time_password_expires_at\": e}).Error\n}",
		"local clock not UTC":         "package store\nfunc (ls *L) F() error {\n\tnow := time.Now()\n\treturn ls.db.Updates(map[string]any{\"last_state_at\": now}).Error\n}",
		"UTC only to format":          "package store\nfunc (ls *L) F(at time.Time) error {\n\t_ = at.UTC().Format(time.RFC3339)\n\treturn ls.db.Update(\"anchored_at\", at).Error\n}",
		"Exec with a time bind":       "package store\nfunc (ls *L) F(purgeAt time.Time) error {\n\treturn ls.db.Exec(\"UPDATE t SET purge_at = ? WHERE id = 1\", purgeAt).Error\n}",
		"cutoff column (login_until)": "package store\nfunc (ls *L) F(u *time.Time) error {\n\treturn ls.db.Updates(map[string]any{\"login_locked_until\": u}).Error\n}",
	} {
		got := scanStoreTimeWritesInSource(t, "calibration_input", src)
		if len(got) != 1 || got[0].UTC {
			t.Errorf("%s: want one non-UTC write, got %+v", name, got)
		}
	}

	for name, src := range map[string]string{
		"inline UTC":         "package store\nfunc (ls *L) F(at time.Time) error {\n\treturn ls.db.UpdateColumn(\"last_login_at\", at.UTC()).Error\n}",
		"param then UTC":     "package store\nfunc (ls *L) F(at time.Time) error {\n\tat = at.UTC()\n\treturn ls.db.Updates(map[string]any{\"decided_at\": at}).Error\n}",
		"now via UTC":        "package store\nfunc (ls *L) F() error {\n\tnow := time.Now().UTC()\n\treturn ls.db.Updates(map[string]any{\"updated_at\": now}).Error\n}",
		"cols index UTC":     "package store\nfunc (ls *L) F(f T) error {\n\tcols := map[string]any{}\n\tcols[\"updated_at\"] = f.UpdatedAt.UTC()\n\treturn ls.db.Updates(cols).Error\n}",
		"utcPtr helper":      "package store\nfunc (ls *L) F(p *time.Time) error {\n\treturn ls.db.Updates(map[string]any{\"revoked_at\": utcPtr(p)}).Error\n}",
		"cleared to nil":     "package store\nfunc (ls *L) F() error {\n\treturn ls.db.Update(\"deleted_at\", nil).Error\n}",
		"database-evaluated": "package store\nfunc (ls *L) F() error {\n\treturn ls.db.Updates(map[string]any{\"cascade_suspended_at\": gorm.Expr(sqlDeletedAt, id)}).Error\n}",
		"Exec with UTC bind": "package store\nfunc (ls *L) F(purgeAt time.Time) error {\n\treturn ls.db.Exec(\"UPDATE t SET purge_at = ? WHERE id = 1\", purgeAt.UTC()).Error\n}",
	} {
		got := scanStoreTimeWritesInSource(t, "calibration_input", src)
		if len(got) != 1 || !got[0].UTC {
			t.Errorf("%s: want one UTC-traced write, got %+v", name, got)
		}
	}

	// Columns the guard does not own, a map outside a writing function, an Exec with no bind.
	for name, src := range map[string]string{
		"not a time column":    "package store\nfunc (ls *L) F() error {\n\treturn ls.db.Update(\"activated\", true).Error\n}",
		"counter column":       "package store\nfunc (ls *L) F() error {\n\treturn ls.db.Updates(map[string]any{\"attempts\": 3, \"last_error\": \"x\"}).Error\n}",
		"map without a write":  "package store\nfunc F(at time.Time) map[string]any {\n\treturn map[string]any{\"updated_at\": at}\n}",
		"Exec without a bind":  "package store\nfunc (ls *L) F() error {\n\treturn ls.db.Exec(\"UPDATE t SET purge_at = NULL WHERE id = 1\").Error\n}",
		"Exec, no time column": "package store\nfunc (ls *L) F(id uint) error {\n\treturn ls.db.Exec(\"UPDATE t SET holder = ? WHERE id = 1\", id).Error\n}",
	} {
		if got := scanStoreTimeWritesInSource(t, "calibration_input", src); len(got) != 0 {
			t.Errorf("%s: want no write, got %+v", name, got)
		}
	}
}

func TestEveryStoreTimeColumnWriteIsUTC(t *testing.T) {
	g := guardrules.Rollout(t)
	var all, hits []storeTimeWrite
	seen := map[string]bool{}
	for _, path := range storeSourceFiles(t) {
		seen[filepath.Base(path)] = true
		if owner, skip := storeScanSkippedFiles[filepath.Base(path)]; skip {
			t.Logf("skipped %s (%s)", filepath.Base(path), owner)
			continue
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, w := range scanStoreTimeWrites(fset, f, filepath.Base(path)) {
			all = append(all, w)
			if !w.UTC {
				hits = append(hits, w)
			}
		}
	}
	// A floor, so a scanner that silently matches nothing fails loudly.
	if len(all) < 30 {
		g.Fatalf("scanner found only %d store time-column writes; it has stopped matching", len(all))
	}

	for file, owner := range storeScanSkippedFiles {
		if !seen[file] {
			g.Errorf("skipped file %q (%s) no longer exists in internal/storage/store: delete its row", file, owner)
		}
	}

	used := map[string]bool{}
	var msgs []string
	for _, w := range hits {
		if _, ok := storeTimeWriteExceptions[w.key()]; ok {
			used[w.key()] = true
			continue
		}
		msgs = append(msgs, fmt.Sprintf("%s:%d in %s writes %s (%s) without .UTC()", w.File, w.Line, w.Func, w.Column, w.Form))
	}
	sort.Strings(msgs)
	for _, m := range msgs {
		g.Errorf("%s: a non-UTC time reaches an SQLite column as text with the caller's offset that neither scans back nor orders against "+
			"the UTC \"now\"/cutoff bound, and gorm runs no hook or NowFunc on UpdateColumn(s) or a map Updates. Normalise in the store "+
			"(`x = x.UTC()`, or utcPtr for a pointer), or add a store_utc_write_exceptions_test.go registerStoreTimeWriteException row "+
			"with the reason it is safe", m)
	}
	for key, why := range storeTimeWriteExceptions {
		if !used[key] {
			g.Errorf("exception %q (%s) matches no hit any more: delete its row", key, why)
		}
	}
}
