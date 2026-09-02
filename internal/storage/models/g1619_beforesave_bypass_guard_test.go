// g1619_beforesave_bypass_guard_test.go — guards #1619: a raw .Update()/
// .Updates()/.UpdateColumn()/.UpdateColumns() call targeting a column a
// BeforeSave hook owns bypasses that hook entirely. The hook mutates its
// receiver's own field (e.g. ShareRecord.BeforeSave: `s.ExpiresAt =
// s.ExpiresAt.UTC()`), but GORM builds the SET clause for these four methods
// from the column/value pair or map/struct passed directly to the call, not
// by re-reading the struct after the hook runs — so the hook's mutation is
// simply never picked up. Only Save()/Create() (full-struct writes) route the
// hook's own mutated field back into the SQL. #1619 found the original
// instance of this (ShareRecord.ExpiresAt, TestListShares_ExcludeExpiredIncludeActive
// — a fixture wrote an un-normalized local time straight to the column,
// producing a row the production write path can never produce; fixed pre-#1619
// in #1606) and swept the whole test suite for every other instance, both
// directions: a bypass that makes a test fail on a state production can't
// reach (loud), and, worse, one that makes a test PASS over that same
// unreachable state (quiet — the assertion proves nothing).
//
// The hook inventory below is derived from models.go's own AST at test time,
// not hand-listed — per #1619's own verification requirement: a hand-list
// goes stale silently the next time a BeforeSave hook is added or a hook body
// starts touching a new field. Adding either is picked up automatically the
// next time this test runs.
//
// Scope — this guard recognizes exactly two call shapes, and only these two:
//
//  1. `<chain ending in .Model(&models.X{...}) or .Model(v) where v was
//     assigned &models.X{...} earlier in the same function>.
//     {Update,UpdateColumn}("snake_case_col", val)` — string-literal column name.
//  2. `...{Updates,UpdateColumns}(map[string]interface{}{"col": val, ...})` —
//     map literal, string keys. `Updates`/`UpdateColumns` called with a struct
//     literal instead of a map is also recognized, matched by Go field name
//     directly rather than a snake_case column string.
//
// A raw `db.Exec("UPDATE ... SET col = ...")` string is NOT covered — the one
// instance of it in this repo at the time of #1619's sweep
// (factory_rbac_pk_rebuild_test.go) operates on a bespoke pre-migration schema
// built by the test itself, below the model layer entirely (that table lacks
// several of UserRole's real columns), not a real model row; it was examined
// by hand during the sweep and found benign. A future raw-SQL test that writes
// a hooked column against a REAL model's table would not be caught here — a
// known, stated boundary, not a silent gap.
package models

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// bypassSite is one call site where a raw Update/Updates/UpdateColumn/
// UpdateColumns targets a column a BeforeSave hook on that model owns.
type bypassSite struct {
	File      string
	Line      int
	ModelType string
	Field     string
	Method    string
}

func itoa(n int) string { return strconv.Itoa(n) }

// beforeSaveHookedFields derives, from models.go's own AST, a map of model
// type name -> set of Go field names that model's own hook (BeforeSave,
// BeforeCreate, or BeforeUpdate — this repo currently has only BeforeSave
// hooks, but the guard is not hardcoded to that one hook name) assigns to.
// A field only counts if the hook body itself writes `<receiver>.<Field> = ...`
// somewhere, at any nesting depth (covers the common `if x.Field != nil {
// u := x.Field.UTC(); x.Field = &u }` shape alongside unconditional ones).
func beforeSaveHookedFields(t *testing.T, fset *token.FileSet) map[string]map[string]bool {
	t.Helper()
	path := filepath.Join(repoRootG1619(), "internal", "storage", "models", "models.go")
	file, err := parser.ParseFile(fset, path, nil, 0)
	require.NoError(t, err, "parsing models.go")

	hooked := map[string]map[string]bool{}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv == nil || len(fn.Recv.List) != 1 || fn.Body == nil {
			continue
		}
		switch fn.Name.Name {
		case "BeforeSave", "BeforeCreate", "BeforeUpdate":
		default:
			continue
		}
		star, ok := fn.Recv.List[0].Type.(*ast.StarExpr)
		if !ok || len(fn.Recv.List[0].Names) != 1 {
			continue
		}
		recvType, ok := star.X.(*ast.Ident)
		if !ok {
			continue
		}
		recvName := fn.Recv.List[0].Names[0].Name

		fields := hooked[recvType.Name]
		if fields == nil {
			fields = map[string]bool{}
			hooked[recvType.Name] = fields
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			assign, ok := n.(*ast.AssignStmt)
			if !ok {
				return true
			}
			for _, lhs := range assign.Lhs {
				sel, ok := lhs.(*ast.SelectorExpr)
				if !ok {
					continue
				}
				if id, ok := sel.X.(*ast.Ident); ok && id.Name == recvName {
					fields[sel.Sel.Name] = true
				}
			}
			return true
		})
	}
	return hooked
}

// repoRootG1619 locates the repository root relative to this file's own
// location on disk, so the guard works regardless of the test runner's
// working directory.
func repoRootG1619() string {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		panic("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "..")
}

// toSnakeCaseG1619 converts a Go CamelCase field name to GORM's default
// snake_case column name. Sufficient for this repo's current hook-owned
// fields (ExpiresAt, CreatedAt, ClosedAt, DetectedAt, EventTime, ResolvedAt,
// AttemptedAt, InvitedAt, AccessTime, Expiration — no acronym runs among
// them); does not attempt GORM's acronym-aware initialism handling.
func toSnakeCaseG1619(s string) string {
	var b strings.Builder
	runes := []rune(s)
	for i, r := range runes {
		if r >= 'A' && r <= 'Z' {
			if i > 0 {
				prev := runes[i-1]
				nextLower := i+1 < len(runes) && runes[i+1] >= 'a' && runes[i+1] <= 'z'
				prevLowerOrDigit := (prev >= 'a' && prev <= 'z') || (prev >= '0' && prev <= '9')
				prevUpper := prev >= 'A' && prev <= 'Z'
				if prevLowerOrDigit || (prevUpper && nextLower) {
					b.WriteByte('_')
				}
			}
			b.WriteRune(r - 'A' + 'a')
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// findModelArgG1619 walks a GORM call chain's receiver expression looking for
// a `.Model(arg)` call anywhere along it (e.g. through `.Where(...)`,
// `.WithContext(...)`) and returns that call's single argument.
func findModelArgG1619(expr ast.Expr) (ast.Expr, bool) {
	for {
		call, ok := expr.(*ast.CallExpr)
		if !ok {
			return nil, false
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return nil, false
		}
		if sel.Sel.Name == "Model" && len(call.Args) == 1 {
			return call.Args[0], true
		}
		expr = sel.X
	}
}

// modelTypeNameFromArgG1619 resolves a `.Model(...)` argument (or, during
// local-variable-map construction, an assignment's RHS) to the models.X type
// name it constructs, handling `&models.X{...}`, bare `models.X{...}`, and a
// local variable previously bound to either of those shapes.
func modelTypeNameFromArgG1619(arg ast.Expr, localVars map[string]string) (string, bool) {
	switch e := arg.(type) {
	case *ast.UnaryExpr:
		if e.Op == token.AND {
			return modelTypeNameFromArgG1619(e.X, localVars)
		}
	case *ast.CompositeLit:
		if sel, ok := e.Type.(*ast.SelectorExpr); ok {
			if id, ok := sel.X.(*ast.Ident); ok && id.Name == "models" {
				return sel.Sel.Name, true
			}
		}
	case *ast.Ident:
		if t, ok := localVars[e.Name]; ok {
			return t, true
		}
	}
	return "", false
}

// touchedFieldG1619 is one column/field a raw write targets. IsSnakeCase
// marks whether Name is a snake_case DB column string (Update/UpdateColumn,
// or Updates/UpdateColumns with a map) that must be converted before
// comparing against the hook's Go field names, or a Go field name taken
// directly from a struct-literal argument to Updates/UpdateColumns.
type touchedFieldG1619 struct {
	Name        string
	IsSnakeCase bool
}

func touchedFieldsG1619(call *ast.CallExpr, methodName string) []touchedFieldG1619 {
	if len(call.Args) == 0 {
		return nil
	}
	switch methodName {
	case "Update", "UpdateColumn":
		if lit, ok := call.Args[0].(*ast.BasicLit); ok && lit.Kind == token.STRING {
			if s, err := strconv.Unquote(lit.Value); err == nil {
				return []touchedFieldG1619{{Name: s, IsSnakeCase: true}}
			}
		}
	case "Updates", "UpdateColumns":
		arg := call.Args[0]
		if unary, ok := arg.(*ast.UnaryExpr); ok && unary.Op == token.AND {
			arg = unary.X
		}
		lit, ok := arg.(*ast.CompositeLit)
		if !ok {
			return nil
		}
		var out []touchedFieldG1619
		switch lit.Type.(type) {
		case *ast.MapType:
			for _, elt := range lit.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				bl, ok := kv.Key.(*ast.BasicLit)
				if !ok || bl.Kind != token.STRING {
					continue
				}
				if s, err := strconv.Unquote(bl.Value); err == nil {
					out = append(out, touchedFieldG1619{Name: s, IsSnakeCase: true})
				}
			}
		default:
			// Struct-literal Updates(models.X{Field: val}) / Updates(&models.X{...}):
			// keys are Go field identifiers, not column strings.
			for _, elt := range lit.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				if id, ok := kv.Key.(*ast.Ident); ok {
					out = append(out, touchedFieldG1619{Name: id.Name, IsSnakeCase: false})
				}
			}
		}
		return out
	}
	return nil
}

var rawWriteMethodsG1619 = map[string]bool{
	"Update": true, "Updates": true, "UpdateColumn": true, "UpdateColumns": true,
}

// scanFileForBypassesG1619 finds every raw Update/Updates/UpdateColumn/
// UpdateColumns call in file that targets a column a hooked model's own
// BeforeSave-family hook owns.
func scanFileForBypassesG1619(fset *token.FileSet, file *ast.File, hooked map[string]map[string]bool) []bypassSite {
	var sites []bypassSite
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}

		// Pass 1: collect `name := &models.X{...}` (or bare models.X{...})
		// local bindings anywhere in the function body.
		localVars := map[string]string{}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			assign, ok := n.(*ast.AssignStmt)
			if !ok || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
				return true
			}
			id, ok := assign.Lhs[0].(*ast.Ident)
			if !ok {
				return true
			}
			if t, ok := modelTypeNameFromArgG1619(assign.Rhs[0], nil); ok {
				localVars[id.Name] = t
			}
			return true
		})

		// Pass 2: find raw-write calls and resolve their .Model(...) target.
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || !rawWriteMethodsG1619[sel.Sel.Name] {
				return true
			}
			modelArg, ok := findModelArgG1619(sel.X)
			if !ok {
				return true
			}
			modelType, ok := modelTypeNameFromArgG1619(modelArg, localVars)
			if !ok {
				return true
			}
			hookedFields, ok := hooked[modelType]
			if !ok {
				return true
			}
			for _, tf := range touchedFieldsG1619(call, sel.Sel.Name) {
				for goField := range hookedFields {
					match := tf.Name == goField
					if tf.IsSnakeCase {
						match = tf.Name == toSnakeCaseG1619(goField)
					}
					if match {
						pos := fset.Position(call.Pos())
						sites = append(sites, bypassSite{
							File: pos.Filename, Line: pos.Line,
							ModelType: modelType, Field: goField, Method: sel.Sel.Name,
						})
					}
				}
			}
			return true
		})
	}
	return sites
}

// beforeSaveBypassAllowlistG1619 is the file:line-pinned registry of raw
// writes to a hooked column that #1619's sweep examined and found benign —
// each entry's value is a receipt of the reasoning, not just a pass. A raw
// write found here that is NOT in this allowlist fails the test; an allowlist
// entry with no matching call site (moved, deleted, or the fixture rewritten
// to route through the hook) also fails it — this registry must track the
// live set exactly, in both directions, the same discipline as
// remote_wire_route_coverage_test.go's knownUnresolvedWireCalls.
var beforeSaveBypassAllowlistG1619 = map[string]string{
	"internal/storage/store/local_sharing_test.go:325": "ShareRecord.ExpiresAt — #1619's original known case " +
		"(TestListShares_ExcludeExpiredIncludeActive), fixed pre-#1619 in #1606: `past` is time.Now().UTC().Add(...), " +
		"already canonical, so BeforeSave's normalization would be a no-op; the raw write is a deliberate " +
		"\"simulate a not-yet-swept expiry\" fixture technique, commented in place as such.",
	"internal/storage/store/local_sharing_test.go:340": "ShareRecord.ExpiresAt — second occurrence in the same " +
		"test (expiredGroup), same `past` value, same reasoning as line 325.",
	"internal/storage/store/rotation_risk_batch_test.go:104": "ShareRecord.ExpiresAt — same pattern as " +
		"local_sharing_test.go, `past := time.Now().UTC().Add(-time.Hour)`, already canonical, commented in place " +
		"citing local_sharing_test.go's fuller reasoning.",
	"server/middleware/g18_cache_hit_revocation_test.go:101": "PersonalAccessToken.ExpiresAt — `past := " +
		"time.Now().Add(-time.Hour)` is NOT pre-normalized, but this is still benign: the read path " +
		"(ValidatePATToken -> IsPATExpired) fetches this one row by hash (GetPersonalAccessTokenByHash, not a " +
		"range query) and compares via Go's Location-independent now.After(*pat.ExpiresAt) " +
		"(pat_expiry_enforce.go) — never a SQLite string range comparison, so BeforeSave's UTC normalization " +
		"has nothing to protect on this read path regardless of what Location the raw write left in place.",
	"internal/storage/store/stale_accounts_test.go:35": "User.CreatedAt — `createdAt` is derived from " +
		"`now := time.Now().UTC()` two lines above the mk() helper, already canonical, so BeforeSave's " +
		"normalization would be a no-op. (This model's OWN read path, ListUsersInStateBefore, IS a real SQL " +
		"range query — unlike the PAT case above, this one is benign because the value is canonical, not " +
		"because the query is immune.)",
	"internal/core/break_glass_external_test.go:413": "UserRole.ExpiresAt — the value is " +
		"`time.Now().UTC().Add(-time.Hour)`, already canonical. This test (TestBreakGlass_ExpiredGrantDeniesAuthorization) " +
		"deliberately exercises the real SQL-range-query path (Authorize -> GetUserRoleIDsAt's expires_at filter, " +
		"per its own doc comment) — protected because the value is canonical, not because the read path is immune.",
	"internal/core/break_glass_external_test.go:515": "UserRole.ExpiresAt — `past := " +
		"time.Now().UTC().Add(-time.Minute)` (declared a few lines above, shared with the " +
		"BreakGlassActivation.ExpiresAt entry below), already canonical (#1653: this test previously used a " +
		"non-UTC `past`, which this same reopening fixed — see this file's own comment immediately above the " +
		"declaration). This test (TestActivateBreakGlass_ReactivatesAfterNaturalExpiry) never exercises " +
		"GetUserRoleIDsAt's SQL range query against this row: the only downstream check that reads it is " +
		"assignUserRole's existing-row guard (local_rbac.go), a single-row fetch by composite key compared via " +
		"Go's Location-independent existing.ExpiresAt.After(time.Now()) — doubly protected, both because the " +
		"value is canonical and because the read path is immune.",
	"internal/core/break_glass_external_test.go:518": "BreakGlassActivation.ExpiresAt — same " +
		"`past := time.Now().UTC().Add(-time.Minute)` as the UserRole.ExpiresAt entry immediately above (one " +
		"variable, two raw writes in TestActivateBreakGlass_ReactivatesAfterNaturalExpiry), already canonical. " +
		"#1653 reopened added a real SQL range-query read path for this exact column " +
		"(ReconcileExpiredBreakGlassActivation, local_break_glass.go: `WHERE ... expires_at <= ?`, called from " +
		"ActivateBreakGlass) — this site is exactly the one that motivated adding ExpiresAt to " +
		"BreakGlassActivation.BeforeSave's normalization in the first place; protected because the value is " +
		"canonical, not because this read path is immune (it is not).",
}

// TestBeforeSaveBypassGuard_NoUnrecognizedRawWritesToHookedColumns is #1619's
// structural guard: no test in this repo may raw-write a column a BeforeSave
// hook owns without either routing through the hook (Save/Create) or being an
// explicit, reasoned allowlist entry above.
func TestBeforeSaveBypassGuard_NoUnrecognizedRawWritesToHookedColumns(t *testing.T) {
	fset := token.NewFileSet()
	hooked := beforeSaveHookedFields(t, fset)
	require.NotEmpty(t, hooked, "sanity: models.go must have at least one BeforeSave hook for this guard to mean anything")

	root := repoRootG1619()
	var found []bypassSite
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "web", ".scratch", ".task", ".semgrep":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			// Not expected in a repo that builds, but don't let one
			// unparseable fixture hide the rest of the sweep.
			t.Logf("skipping unparseable file %s: %v", path, perr)
			return nil
		}
		found = append(found, scanFileForBypassesG1619(fset, file, hooked)...)
		return nil
	})
	require.NoError(t, err)

	rel := func(f string) string {
		r, err := filepath.Rel(root, f)
		if err != nil {
			return f
		}
		return filepath.ToSlash(r)
	}

	seen := map[string]bool{}
	for _, site := range found {
		key := rel(site.File) + ":" + itoa(site.Line)
		seen[key] = true
		if _, ok := beforeSaveBypassAllowlistG1619[key]; ok {
			continue
		}
		t.Errorf("unallowlisted BeforeSave bypass: %s writes %s.%s via %s, bypassing its BeforeSave hook — "+
			"either route the write through Save()/Create() so the hook runs, or add a reasoned entry to "+
			"beforeSaveBypassAllowlistG1619 in g1619_beforesave_bypass_guard_test.go explaining why the raw "+
			"write is safe (value already canonical, or the read path never range-queries this column in SQL)",
			key, site.ModelType, site.Field, site.Method)
	}
	for key, reason := range beforeSaveBypassAllowlistG1619 {
		if !seen[key] {
			t.Errorf("stale allowlist entry %s (%s): no matching raw-write call site found — "+
				"the fixture was likely fixed to route through the hook (good, remove this entry) or moved "+
				"(update the key)", key, reason)
		}
	}
}

// TestBeforeSaveBypassGuard_FiresOnADeliberateViolation is Task 5's own
// verification requirement: the guard must be shown catching a real
// violation, not just staying quiet on today's (already-benign) call sites.
// This constructs a synthetic source file — never written to disk, never
// compiled into the build — with a raw write matching #1619's exact original
// bug shape (a Save-eligible model with an ExpiresAt-owning hook, written via
// .Update("expires_at", ...) instead of Save()) and asserts the scanner
// flags it.
func TestBeforeSaveBypassGuard_FiresOnADeliberateViolation(t *testing.T) {
	const src = `package examplepkg

import "github.com/keyorixhq/keyorix/internal/storage/models"

func poison(db *gorm.DB, id uint, past time.Time) error {
	return db.Model(&models.ShareRecord{}).Where("id = ?", id).Update("expires_at", past).Error
}
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "synthetic_violation.go", src, 0)
	require.NoError(t, err)

	hooked := beforeSaveHookedFields(t, fset)
	sites := scanFileForBypassesG1619(fset, file, hooked)
	require.Len(t, sites, 1, "the guard must flag the deliberately-introduced ShareRecord.ExpiresAt raw write")
	require.Equal(t, "ShareRecord", sites[0].ModelType)
	require.Equal(t, "ExpiresAt", sites[0].Field)
	require.Equal(t, "Update", sites[0].Method)
}
