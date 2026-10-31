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
// What it does NOT catch:
//   - assignments outside a composite literal (`x.ExpiresAt = v`, `Updates(map[string]any{...})`),
//     and literals built through a helper or a copy of another struct;
//   - data flow: the identifier tracing is textual and per-function, so `.UTC()` applied to a
//     different variable with the same name in another branch satisfies it;
//   - fields that are not named Expiration / *ExpiresAt (CreatedAt, UpdatedAt, ResolvedAt, ...), and GORM's
//     auto-timestamps, which NowFunc fills in the host zone after every hook has run;
//   - code outside the core family (server layers, CLI).
// Wrong-reason exemptions are checked too: an exception that no longer matches any hit fails.
//
// Report-only on its first day (docs/guard-rollout.d/TestEveryUnhookedExpiryWriteInCoreIsUTC.tsv).

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

	"github.com/keyorixhq/keyorix/internal/guardrules"
	"github.com/keyorixhq/keyorix/internal/testutil/srcpath"
)

// clientTimeUTCExceptions: "file.go:Func:Type.Field" -> why the write is safe or tracked. Filled
// by registerClientTimeUTCException from init() in client_time_utc_exceptions_test.go.
var clientTimeUTCExceptions = map[string]string{}

func registerClientTimeUTCException(key, reason string) {
	if _, dup := clientTimeUTCExceptions[key]; dup {
		panic("duplicate client-time-UTC exception " + key)
	}
	clientTimeUTCExceptions[key] = reason
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

// scanExpiryWrites returns every keyed Expir* field write to a models.T literal in f, for T and
// field pairs the hook inventory does not normalise.
func scanExpiryWrites(fset *token.FileSet, f *ast.File, file string, inv map[string]map[string]bool) []expiryWrite {
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
				if !ok || !isExpiryFieldName(key.Name) || inv[typ][key.Name] {
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
