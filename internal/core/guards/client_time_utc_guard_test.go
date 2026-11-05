// client_time_utc_guard_test.go -- SQLITE-TIME-TAILS-1 item 3.
//
// The class: a core write path stores a time.Time that carries a non-UTC zone. On the production
// SQLite dialect (modernc) a time with a non-UTC zone is stored as text that (a) does not scan
// back into a *time.Time ("unsupported Scan, storing driver.Value type string into type
// *time.Time", so the list endpoint 500s) and (b) does not order against the UTC "now" bound
// parameters the expiry queries use. PostgreSQL stores an instant, so the same code is fine there.
// SQLITE-TIME-TAILS-1 found it live for risk-exception and connect-ref-grant expires_at (the
// client's RFC3339 offset reached the column as sent) and for invitation / access-request expiry
// (derived from the server clock in the host's zone).
//
// The repo's primary defence is a BeforeSave hook on the model that normalises the field (see
// internal/storage/models: PersonalAccessToken, MachineIdentityCredential, ShareRecord, ...). This
// guard covers the models that have NO such hook for a field: every write of such a field from
// internal/core must be traceably UTC.
//
// What it recognises (the enumeration, stated so a reviewer can check it):
//   - the hook inventory is derived from internal/storage/models at test time: a model type T
//     normalises field F when T has a BeforeSave method that assigns `<recv>.F = ...`;
//   - a write is a keyed field of a composite literal `models.T{... F: expr ...}` (also `&models.T{}`)
//     in the core family (srcpath.CoreFamilyGoFiles), for F named Expiration or ending in ExpiresAt;
//   - the write is accepted when expr is traceably UTC: a call chain ending in `.UTC()`; or an
//     identifier (optionally behind `&`) that the same function assigns from such a chain; or an
//     identifier assigned from a chain rooted at another identifier that is itself traceably UTC
//     (`now := c.now().UTC(); expires := now.Add(ttl)`; `u := exp.UTC(); exp = &u`; at most 4
//     hops). A `.UTC()` call that only formats a value (an audit string) does not count.
//
// UTC-GUARD-KEK-TAILS-1 item 4 widened the recognised writes beyond composite literals, which is
// why the login session mint and the Touch* stampers were never listed:
//   - an assignment `x.F = v` (also `a.F, b.F = v, w`) for F named Expiration, ending in ExpiresAt,
//     or LastUsedAt / LastSeenAt. The receiver's model type is resolved textually, only when the
//     function declares it (a `*models.T` parameter, `var x models.T`, `x := &models.T{}` or
//     `new(models.T)`); a receiver whose type is not declared that way is reported as type
//     "unknown" and is not exempted by a hook, so it needs `.UTC()` or an exception row.
//     Assigning `nil` is not a time and is accepted;
//   - a column write: `UpdateColumn("last_used_at", v)`, `Update(...)`, `Updates(map[string]any{
//     "expires_at": v})` (also UpdateColumns) with a string-literal column named expires_at,
//     *_expires_at, expiration, last_used_at or last_seen_at. The Type is "column".
// LastUsedAt / LastSeenAt are now tracked in composite literals and assignments too.
//
// What it does NOT catch:
//   - a column write whose column name is not a string literal in the call or in a map literal
//     passed to it (a map built earlier and passed by name), a GORM clause.Assignments, a raw SQL
//     string, and literals built through a helper or a copy of another struct;
//   - a time handed to a function that stores it (`TouchPAT(ctx, id, t)`): the store layer owns the
//     write and sits outside the core family;
//   - data flow: the identifier tracing is textual and per-function, so `.UTC()` applied to a
//     different variable with the same name in another branch satisfies it;
//   - fields that are not named Expiration / *ExpiresAt / LastUsedAt / LastSeenAt (CreatedAt, UpdatedAt, ResolvedAt, ...), and GORM's
//     auto-timestamps, which NowFunc fills in the host zone after every hook has run;
//   - code outside the core family (server layers, CLI).
// Wrong-reason exemptions are checked too: an exception that no longer matches any hit fails.
//
// The widening is report-only on its first day (docs/guard-rollout.d/TestEveryUnhookedExpiryWriteInCoreIsUTC.tsv).

package guards

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/guardrules"
	"github.com/keyorixhq/keyorix/internal/testutil/srcpath"
)

// clientTimeUTCExceptions: "file.go:Func:Type.Field" -> why the write is safe or tracked. Filled
// by registerClientTimeUTCException from init() in a client_time_utc_exceptions_test.go (one row
// each; the file is absent while the table is empty, as since SQLITE-UTC-NOWFUNC-1 item 3).
var clientTimeUTCExceptions = map[string]string{}

func registerClientTimeUTCException(key, reason string) {
	if _, dup := clientTimeUTCExceptions[key]; dup {
		panic("duplicate client-time-UTC exception " + key)
	}
	clientTimeUTCExceptions[key] = reason
}

// A duplicate row is a programming error that must not silently overwrite a reason.
func TestRegisterClientTimeUTCException_RejectsADuplicateKey(t *testing.T) {
	const key = "auth.go:Probe:T.F"
	registerClientTimeUTCException(key, "first")
	t.Cleanup(func() { delete(clientTimeUTCExceptions, key) })
	require.PanicsWithValue(t, "duplicate client-time-UTC exception "+key, func() {
		registerClientTimeUTCException(key, "second")
	})
	require.Equal(t, "first", clientTimeUTCExceptions[key])
}

// hookInventory maps a models type to the set of fields its BeforeSave assigns.
func hookInventory(fset *token.FileSet, files []*ast.File) map[string]map[string]bool {
	inv := map[string]map[string]bool{}
	for _, f := range files {
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || fn.Name.Name != "BeforeSave" || fn.Body == nil || len(fn.Recv.List) != 1 {
				continue
			}
			typ := recvTypeName(fn.Recv.List[0].Type)
			if typ == "" || len(fn.Recv.List[0].Names) == 0 {
				continue
			}
			recv := fn.Recv.List[0].Names[0].Name
			fields := inv[typ]
			if fields == nil {
				fields = map[string]bool{}
				inv[typ] = fields
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				as, ok := n.(*ast.AssignStmt)
				if !ok {
					return true
				}
				for _, lhs := range as.Lhs {
					if sel, ok := lhs.(*ast.SelectorExpr); ok {
						if id, ok := sel.X.(*ast.Ident); ok && id.Name == recv {
							fields[sel.Sel.Name] = true
						}
					}
				}
				return true
			})
		}
	}
	_ = fset
	return inv
}

func recvTypeName(e ast.Expr) string {
	if star, ok := e.(*ast.StarExpr); ok {
		e = star.X
	}
	if id, ok := e.(*ast.Ident); ok {
		return id.Name
	}
	return ""
}

type expiryWrite struct {
	File, Func, Type, Field string
	Line                    int
	UTC                     bool
}

func (w expiryWrite) key() string { return w.File + ":" + w.Func + ":" + w.Type + "." + w.Field }

// scanExpiryWrites returns every tracked time write in f (composite-literal keys, field
// assignments and column writes), for T and field pairs the hook inventory does not normalise.
func scanExpiryWrites(fset *token.FileSet, f *ast.File, file string, inv map[string]map[string]bool) []expiryWrite {
	out := scanExpiryLiteralWrites(fset, f, file, inv)
	for _, decl := range f.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Body != nil {
			out = append(out, scanAssignedAndColumnWrites(fset, fn, file, inv)...)
		}
	}
	return out
}

// scanExpiryLiteralWrites returns every keyed tracked-field write to a models.T literal in f.
func scanExpiryLiteralWrites(fset *token.FileSet, f *ast.File, file string, inv map[string]map[string]bool) []expiryWrite {
	var out []expiryWrite
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			sel, ok := lit.Type.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "models" {
				return true
			}
			typ := sel.Sel.Name
			for _, el := range lit.Elts {
				kv, ok := el.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				key, ok := kv.Key.(*ast.Ident)
				if !ok || !isUTCTrackedField(key.Name) || inv[typ][key.Name] {
					continue
				}
				out = append(out, expiryWrite{
					File: file, Func: fn.Name.Name, Type: typ, Field: key.Name,
					Line: fset.Position(kv.Pos()).Line,
					UTC:  tracesToUTC(kv.Value, fn.Body, 0),
				})
			}
			return true
		})
	}
	return out
}

// isExpiryFieldName: the time-valued expiry fields (ExpiresAt, AbsoluteExpiresAt,
// OneTimePasswordExpiresAt, Expiration). A bare "contains Expir" also matched the integer
// HygieneTrendSnapshot.ExpiredPATs.
func isExpiryFieldName(name string) bool {
	return name == "Expiration" || strings.HasSuffix(name, "ExpiresAt")
}

// isUTCTrackedField: the expiry fields plus the activity stamps compared against the UTC "now".
func isUTCTrackedField(name string) bool {
	return isExpiryFieldName(name) || name == "LastUsedAt" || name == "LastSeenAt"
}

// isUTCTrackedColumn is the column-name spelling of isUTCTrackedField.
func isUTCTrackedColumn(col string) bool {
	return col == "expiration" || col == "expires_at" || strings.HasSuffix(col, "_expires_at") ||
		col == "last_used_at" || col == "last_seen_at"
}

// modelsTypeName is T for `models.T`, `*models.T`, `&models.T{...}`, `models.T{...}` and
// `new(models.T)`, else "".
func modelsTypeName(e ast.Expr) string {
	switch x := stripExpr(e).(type) {
	case *ast.SelectorExpr:
		if pkg, ok := x.X.(*ast.Ident); ok && pkg.Name == "models" {
			return x.Sel.Name
		}
	case *ast.CompositeLit:
		if x.Type != nil {
			return modelsTypeName(x.Type)
		}
	case *ast.CallExpr:
		if fun, ok := x.Fun.(*ast.Ident); ok && fun.Name == "new" && len(x.Args) == 1 {
			return modelsTypeName(x.Args[0])
		}
	}
	return ""
}

// declaredModelTypes maps a local identifier to the models type the function declares it as
// (parameter, `var x models.T`, `x := &models.T{}` / `new(models.T)`). Anything else is absent.
func declaredModelTypes(fn *ast.FuncDecl) map[string]string {
	types := map[string]string{}
	addParams := func(ft *ast.FuncType) {
		if ft == nil || ft.Params == nil {
			return
		}
		for _, p := range ft.Params.List {
			if typ := modelsTypeName(p.Type); typ != "" {
				for _, n := range p.Names {
					types[n.Name] = typ
				}
			}
		}
	}
	addParams(fn.Type)
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.FuncLit:
			addParams(x.Type)
		case *ast.ValueSpec:
			if typ := modelsTypeName(x.Type); typ != "" && x.Type != nil {
				for _, name := range x.Names {
					types[name.Name] = typ
				}
			}
		case *ast.AssignStmt:
			if len(x.Lhs) == len(x.Rhs) {
				for i, lhs := range x.Lhs {
					if id, ok := lhs.(*ast.Ident); ok {
						typ := modelsTypeName(x.Rhs[i])
						if rhs, ok := stripExpr(x.Rhs[i]).(*ast.Ident); ok && typ == "" {
							typ = types[rhs.Name] // `next := *cur` copies cur's declared type
						}
						if typ != "" {
							types[id.Name] = typ
						}
					}
				}
			}
		}
		return true
	})
	return types
}

var columnWriteMethods = map[string]bool{"Update": true, "UpdateColumn": true, "Updates": true, "UpdateColumns": true}

// scanAssignedAndColumnWrites finds `x.F = v` assignments and UpdateColumn / Updates column writes
// of the tracked fields in fn (see the file comment for what is and is not recognised).
func scanAssignedAndColumnWrites(fset *token.FileSet, fn *ast.FuncDecl, file string, inv map[string]map[string]bool) []expiryWrite {
	var out []expiryWrite
	declared := declaredModelTypes(fn)
	add := func(pos token.Pos, typ, field string, value ast.Expr) {
		out = append(out, expiryWrite{
			File: file, Func: fn.Name.Name, Type: typ, Field: field,
			Line: fset.Position(pos).Line,
			UTC:  tracesToUTC(value, fn.Body, 0),
		})
	}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.AssignStmt:
			if len(x.Lhs) != len(x.Rhs) {
				return true
			}
			for i, lhs := range x.Lhs {
				sel, ok := lhs.(*ast.SelectorExpr)
				if !ok || !isUTCTrackedField(sel.Sel.Name) || isNilIdent(x.Rhs[i]) {
					continue
				}
				typ := "unknown"
				if root, ok := sel.X.(*ast.Ident); ok && declared[root.Name] != "" {
					typ = declared[root.Name]
				}
				if inv[typ][sel.Sel.Name] {
					continue
				}
				add(sel.Pos(), typ, sel.Sel.Name, x.Rhs[i])
			}
		case *ast.CallExpr:
			sel, ok := x.Fun.(*ast.SelectorExpr)
			if !ok || !columnWriteMethods[sel.Sel.Name] {
				return true
			}
			for i, arg := range x.Args {
				if lit, ok := arg.(*ast.BasicLit); ok && lit.Kind == token.STRING && i+1 < len(x.Args) {
					if col := strings.Trim(lit.Value, "`\""); isUTCTrackedColumn(col) {
						add(lit.Pos(), "column", col, x.Args[i+1])
					}
				}
				m, ok := arg.(*ast.CompositeLit)
				if !ok {
					continue
				}
				if _, isMap := m.Type.(*ast.MapType); !isMap {
					continue
				}
				for _, el := range m.Elts {
					kv, ok := el.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					if k, ok := kv.Key.(*ast.BasicLit); ok && k.Kind == token.STRING {
						if col := strings.Trim(k.Value, "`\""); isUTCTrackedColumn(col) {
							add(k.Pos(), "column", col, kv.Value)
						}
					}
				}
			}
		}
		return true
	})
	return out
}

func stripExpr(e ast.Expr) ast.Expr {
	for {
		switch x := e.(type) {
		case *ast.ParenExpr:
			e = x.X
		case *ast.UnaryExpr:
			e = x.X
		case *ast.StarExpr:
			e = x.X
		default:
			return e
		}
	}
}

func endsInUTC(e ast.Expr) bool {
	call, ok := stripExpr(e).(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	return ok && sel.Sel.Name == "UTC"
}

// rootIdent walks a selector/call chain down to its first identifier (`now` in `now.Add(x)`).
func rootIdent(e ast.Expr) *ast.Ident {
	for {
		switch x := stripExpr(e).(type) {
		case *ast.Ident:
			return x
		case *ast.CallExpr:
			e = x.Fun
		case *ast.SelectorExpr:
			e = x.X
		default:
			return nil
		}
	}
}

// tracesToUTC reports whether expr is traceably UTC within body (see the file comment).
func tracesToUTC(expr ast.Expr, body *ast.BlockStmt, depth int) bool {
	if endsInUTC(expr) {
		return true
	}
	if depth > 4 {
		return false
	}
	root := rootIdent(expr)
	if root == nil {
		return false
	}
	// The identifier is assigned from a chain that is itself traceably UTC: `x = x.UTC()`,
	// `exp := t.UTC()`, `x = &u` with `u := t.UTC()`, or `expires := now.Add(ttl)` with a UTC `now`.
	// A `.UTC()` used only to format (`x.UTC().Format(...)` in an audit string) is not an assignment
	// and does not count: CreateRiskException did exactly that while storing the client offset as sent.
	traced := false
	ast.Inspect(body, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok || len(as.Lhs) != len(as.Rhs) {
			return true
		}
		for i, lhs := range as.Lhs {
			id, ok := lhs.(*ast.Ident)
			if !ok || id.Name != root.Name {
				continue
			}
			rhsRoot := rootIdent(as.Rhs[i])
			if endsInUTC(as.Rhs[i]) || (rhsRoot != nil && rhsRoot.Name != root.Name && tracesToUTC(as.Rhs[i], body, depth+1)) {
				traced = true
			}
		}
		return !traced
	})
	return traced
}

func scanExpiryWritesInSource(t testing.TB, file, src string, inv map[string]map[string]bool) []expiryWrite {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, src, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
	return scanExpiryWrites(fset, f, filepath.Base(file), inv)
}

// The planted shapes. Each must be found (red) and the safe ones must not be: "a guard nobody has
// watched fail is not a guard", and one that always fails is as useless.
func TestExpiryWriteScanner_Calibration(t *testing.T) {
	inv := map[string]map[string]bool{"PersonalAccessToken": {"ExpiresAt": true}}
	scan := func(src string) []expiryWrite { return scanExpiryWritesInSource(t, "calibration_input", src, inv) }

	for name, src := range map[string]string{
		"client value as sent":   "package core\nfunc f(expiresAt time.Time) {\n\t_ = &models.RiskException{ExpiresAt: expiresAt}\n}",
		"client pointer as sent": "package core\nfunc f(expiresAt *time.Time) {\n\t_ = &models.ConnectRefGrant{ExpiresAt: expiresAt}\n}",
		"server clock, local":    "package core\nfunc f() {\n\tnow := c.now()\n\texpires := now.Add(ttl)\n\t_ = &models.ProjectInvitation{ExpiresAt: &expires}\n}",
		"inline server clock":    "package core\nfunc f() {\n\t_ = models.SSOLoginState{ExpiresAt: c.now().Add(ttl)}\n}",
		"UTC only to format":     "package core\nfunc f(expiresAt time.Time) {\n\t_ = expiresAt.UTC().Format(time.RFC3339)\n\t_ = &models.RiskException{ExpiresAt: expiresAt}\n}",
	} {
		got := scan(src)
		if len(got) != 1 || got[0].UTC {
			t.Errorf("%s: want one non-UTC write, got %+v", name, got)
		}
	}

	for name, src := range map[string]string{
		"inline UTC":      "package core\nfunc f() {\n\t_ = models.SSOLoginState{ExpiresAt: c.now().Add(ttl).UTC()}\n}",
		"value then UTC":  "package core\nfunc f(expiresAt time.Time) {\n\texpiresAt = expiresAt.UTC()\n\t_ = &models.RiskException{ExpiresAt: expiresAt}\n}",
		"pointer via u":   "package core\nfunc f(expiresAt *time.Time) {\n\tif expiresAt != nil {\n\t\tu := expiresAt.UTC()\n\t\texpiresAt = &u\n\t}\n\t_ = &models.ConnectRefGrant{ExpiresAt: expiresAt}\n}",
		"now then derive": "package core\nfunc f() {\n\tnow := c.now().UTC()\n\texpires := now.Add(ttl)\n\t_ = &models.ProjectInvitation{ExpiresAt: &expires}\n}",
	} {
		got := scan(src)
		if len(got) != 1 || !got[0].UTC {
			t.Errorf("%s: want one UTC-traced write, got %+v", name, got)
		}
	}

	// UTC-GUARD-KEK-TAILS-1 item 4: assignments and column writes. Red then green for each shape.
	for name, src := range map[string]string{
		"assign pointer as minted":  "package core\nfunc f(s *models.Session) {\n\texp := c.now().Add(ttl)\n\ts.ExpiresAt = &exp\n}",
		"assign last_used field":    "package core\nfunc f(p *models.PersonalAccessToken, t time.Time) {\n\tp.LastUsedAt = &t\n}",
		"assign undeclared type":    "package core\nfunc f(t time.Time) {\n\tx, _ := c.load()\n\tx.LastSeenAt = &t\n}",
		"UpdateColumn last_used_at": "package core\nfunc f(db *gorm.DB) {\n\tdb.UpdateColumn(\"last_used_at\", time.Now())\n}",
		"Updates map expires_at":    "package core\nfunc f(db *gorm.DB, e time.Time) {\n\tdb.Updates(map[string]any{\"expires_at\": e})\n}",
		"Update last_seen_at":       "package core\nfunc f(db *gorm.DB) {\n\tdb.Update(\"last_seen_at\", c.now())\n}",
	} {
		got := scan(src)
		if len(got) != 1 || got[0].UTC {
			t.Errorf("%s: want one non-UTC write, got %+v", name, got)
		}
	}
	for name, src := range map[string]string{
		"assign pointer UTC":        "package core\nfunc f(s *models.Session) {\n\texp := c.now().Add(ttl).UTC()\n\ts.ExpiresAt = &exp\n}",
		"assign last_used UTC":      "package core\nfunc f(p *models.PersonalAccessToken, t time.Time) {\n\tu := t.UTC()\n\tp.LastUsedAt = &u\n}",
		"UpdateColumn UTC":          "package core\nfunc f(db *gorm.DB) {\n\tdb.UpdateColumn(\"last_used_at\", time.Now().UTC())\n}",
		"Updates map UTC":           "package core\nfunc f(db *gorm.DB, e time.Time) {\n\tdb.Updates(map[string]any{\"expires_at\": e.UTC()})\n}",
		"copy of a declared struct": "package core\nfunc f(cur *models.Session, e *time.Time) {\n\tn := *cur\n\tn.ExpiresAt = e\n}",
	} {
		got := scan(src)
		switch name {
		case "copy of a declared struct":
			// Session has no hook in the calibration inventory, so the copy is a (non-UTC) write.
			if len(got) != 1 || got[0].UTC || got[0].Type != "Session" {
				t.Errorf("%s: want one non-UTC Session write, got %+v", name, got)
			}
		default:
			if len(got) != 1 || !got[0].UTC {
				t.Errorf("%s: want one UTC-traced write, got %+v", name, got)
			}
		}
	}
	// A hooked model's assignment (declared type, copy of it), a nil assignment, an unrelated column
	// and an unrelated method are not writes the guard owns.
	for name, src := range map[string]string{
		"hooked assign":       "package core\nfunc f(p *models.PersonalAccessToken, e *time.Time) {\n\tp.ExpiresAt = e\n}",
		"hooked copy":         "package core\nfunc f(cur *models.PersonalAccessToken, e *time.Time) {\n\tn := *cur\n\tn.ExpiresAt = e\n}",
		"nil assign":          "package core\nfunc f(s *models.Session) {\n\ts.ExpiresAt = nil\n}",
		"other column":        "package core\nfunc f(db *gorm.DB) {\n\tdb.UpdateColumn(\"revoked_at\", time.Now())\n}",
		"non-update method":   "package core\nfunc f(db *gorm.DB) {\n\tdb.Where(\"expires_at\", time.Now())\n}",
		"untracked field set": "package core\nfunc f(s *models.Session) {\n\ts.CreatedAt = time.Now()\n}",
	} {
		if got := scan(src); len(got) != 0 {
			t.Errorf("%s: want no write, got %+v", name, got)
		}
	}

	// A hooked field is not the guard's business; a non-expiry field is not recognised.
	if got := scan("package core\nfunc f(e *time.Time) {\n\t_ = &models.PersonalAccessToken{ExpiresAt: e}\n}"); len(got) != 0 {
		t.Errorf("hooked field: want no write, got %+v", got)
	}
	if got := scan("package core\nfunc f() {\n\t_ = &models.RiskException{CreatedAt: c.now()}\n}"); len(got) != 0 {
		t.Errorf("non-expiry field: want no write, got %+v", got)
	}
}

// The hook inventory must see the hooks the repo relies on, so an inventory that silently reads
// nothing cannot turn every write into a hit (or, worse, none).
func TestHookInventory_SeesTheRealHooks(t *testing.T) {
	inv := modelHookInventory(t)
	for typ, field := range map[string]string{
		"PersonalAccessToken":       "ExpiresAt",
		"MachineIdentityCredential": "ExpiresAt",
		"ShareRecord":               "ExpiresAt",
		"BreakGlassActivation":      "ExpiresAt",
		"SecretNode":                "Expiration",
	} {
		if !inv[typ][field] {
			t.Errorf("hook inventory does not see %s.%s normalised in BeforeSave", typ, field)
		}
	}
	// And the gap this guard exists for: these have no hook for the field.
	for typ, field := range map[string]string{"ProjectInvitation": "ExpiresAt", "RiskException": "ExpiresAt", "ConnectRefGrant": "ExpiresAt", "AccessRequest": "ExpiresAt"} {
		if inv[typ][field] {
			t.Errorf("%s.%s now has a BeforeSave hook: remove its core-side .UTC() exemption need or update this list", typ, field)
		}
	}
}

func modelHookInventory(t testing.TB) map[string]map[string]bool {
	t.Helper()
	dir := filepath.Join(srcpath.RepoRoot(), "internal", "storage", "models")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var files []*ast.File
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, e.Name()), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", e.Name(), err)
		}
		files = append(files, f)
	}
	return hookInventory(fset, files)
}

func TestEveryUnhookedExpiryWriteInCoreIsUTC(t *testing.T) {
	g := guardrules.Rollout(t)
	inv := modelHookInventory(t)
	var all, hits []expiryWrite
	for _, path := range coreFamilySources(t) {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, w := range scanExpiryWrites(fset, f, srcpath.CoreFamilyRel(path), inv) {
			all = append(all, w)
			if !w.UTC {
				hits = append(hits, w)
			}
		}
	}
	// A floor, so a scanner that silently matches nothing fails loudly: today the unhooked
	// expiry writes are the invitation, access-request, risk-exception, connect-grant,
	// MFA-reset and SSO-state literals.
	if len(all) < 8 {
		g.Fatalf("scanner found only %d unhooked expiry writes in the whole core family; it has stopped matching", len(all))
	}

	used := map[string]bool{}
	var msgs []string
	for _, w := range hits {
		if _, ok := clientTimeUTCExceptions[w.key()]; ok {
			used[w.key()] = true
			continue
		}
		msgs = append(msgs, fmt.Sprintf("%s:%d in %s stores %s.%s without .UTC()", w.File, w.Line, w.Func, w.Type, w.Field))
	}
	sort.Strings(msgs)
	for _, m := range msgs {
		g.Errorf("%s: on SQLite a non-UTC time is stored as text that neither scans back nor orders against the UTC \"now\" bound. "+
			"Normalise at the write (`x = x.UTC()`, or `now := c.now().UTC()`), give the model a BeforeSave hook for the field, or add a "+
			"client_time_utc_exceptions_test.go registerClientTimeUTCException row with the reason it is safe", m)
	}
	for key, why := range clientTimeUTCExceptions {
		if !used[key] {
			g.Errorf("exception %q (%s) matches no hit any more: delete its file", key, why)
		}
	}
}
