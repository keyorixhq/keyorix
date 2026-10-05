// role_permission_generation_guard_test.go — item 4's role_permissions half:
// every writer of role_permissions must bump the cache generation IN ITS OWN
// TRANSACTION, so a reader can never observe the new grant/revoke under the
// old generation (or the new generation with the old rows).
//
// # Why this is a different check from the secret-cache one
//
// secret_metadata_cache_generation_test.go checks the OTHER shape of the same
// rule: there the generation is DERIVED from the cached columns, so the
// question is "does any hook-bypassing write touch a column no generation
// observes". Here the generation is an EXPLICIT counter in system_metadata, so
// the question is "does any writer forget to bump it, or bump it outside the
// write's transaction". Two mechanisms, two checks; neither covers the other,
// and saying so is the point (a check named for more than it verifies is worse
// than no check).
//
// # What this recognises, and what it does not
//
// Recognised: inside a non-test file of this package, a `Create`/`Delete` call
// whose single argument resolves to models.RolePermission — either an inline
// composite literal (`tx.Delete(&models.RolePermission{…})`) or a local
// assigned one and passed by pointer (`rp := models.RolePermission{…};
// tx.Create(&rp)`). For each enclosing top-level func/method, it requires BOTH
// a call to bumpRolePermissionsGenerationTx AND that both the write and the
// bump sit inside the SAME `Transaction(func(tx *gorm.DB) error { … })`
// closure.
//
// The second argument shape is there because the first version of this
// scanner knew only the first and silently missed AssignPermissionToRole.
// The calibration assertion caught it before this test was ever committed —
// which is the whole reason that assertion exists, and the reason this comment
// lists the shapes rather than leaving them implicit.
//
// NOT recognised, stated rather than assumed:
//   - raw `db.Exec` SQL that writes role_permissions (the same stated boundary
//     as INV-STORE-18's scanner);
//   - a model reached through more than one level of indirection, a struct
//     field, or a function return value;
//   - a write split across two functions, where one does the write and the
//     other the bump (there is none today; all three writers are
//     self-contained);
//   - the `WithTransaction(ctx, func(tx storage.Storage) error …)` form — not
//     used for role_permissions today, and the scanner says so rather than
//     silently accepting it;
//   - any writer outside package store.
//
// Vacuity: the test asserts it still finds all three known writers. A scanner
// that recognises nothing passes for free, which is the failure mode this
// repo has been bitten by five times (CLAUDE.md, "an enumeration is only as
// complete as the idioms it knows about").
package store

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
)

const rolePermissionBumpFunc = "bumpRolePermissionsGenerationTx"

func TestRolePermissionWriters_BumpTheGenerationInTheSameTransaction(t *testing.T) {
	t.Parallel()
	entries, err := os.ReadDir(".")
	require.NoError(t, err)
	fset := token.NewFileSet()

	type writer struct {
		fn                  string
		file                string
		line                int
		bumpsAnywhere       bool
		sharesOneTxWithBump bool
	}
	var writers []writer

	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, perr := parser.ParseFile(fset, filepath.Join(".", name), nil, 0)
		require.NoError(t, perr)

		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			writePos, writes := rolePermissionWritePos(fn.Body)
			if !writes {
				continue
			}
			writers = append(writers, writer{
				fn:                  fn.Name.Name,
				file:                name,
				line:                fset.Position(writePos).Line,
				bumpsAnywhere:       callsNamed(fn.Body, rolePermissionBumpFunc),
				sharesOneTxWithBump: someTransactionClosureHasBoth(fn.Body),
			})
		}
	}

	sort.Slice(writers, func(i, j int) bool { return writers[i].fn < writers[j].fn })

	var problems []string
	var names []string
	for _, w := range writers {
		names = append(names, w.fn)
		switch {
		case !w.bumpsAnywhere:
			problems = append(problems, fmt.Sprintf(
				"%s:%d: %s writes role_permissions but never calls %s — a grant or revoke that does not invalidate the cache answering for it keeps the previous decision live until some unrelated edit. See role_permission_cache.go.",
				w.file, w.line, w.fn, rolePermissionBumpFunc))
		case !w.sharesOneTxWithBump:
			problems = append(problems, fmt.Sprintf(
				"%s:%d: %s calls %s, but not inside the same Transaction(func(tx *gorm.DB) error {…}) closure as its role_permissions write. Two separate transactions leave a window where a reader sees the new rows under the old generation (or the reverse).",
				w.file, w.line, w.fn, rolePermissionBumpFunc))
		}
	}

	require.Empty(t, problems, "role_permissions generation coverage:\n%s", strings.Join(problems, "\n"))

	// Calibration against the known writer set. If this list shrinks, the
	// scanner has stopped recognising the write idiom rather than the code
	// having stopped writing.
	require.ElementsMatch(t,
		[]string{"AssignPermissionToRole", "DeleteRole", "RemovePermissionFromRole"},
		names,
		"the recognised role_permissions writer set changed; if a writer was legitimately added or removed, update this list in the same commit (and give it a race row in read_path_cache_race_test.go)")
}

// rolePermissionWritePos finds a Create/Delete call writing a
// models.RolePermission and returns its position.
//
// Two argument shapes are recognised, because the first version of this
// scanner knew only the first and therefore missed AssignPermissionToRole
// entirely — caught by the calibration assertion above, which is exactly what
// it is there for:
//
//	tx.Delete(&models.RolePermission{…})   // a composite literal, inline
//	rp := models.RolePermission{…}         // a local, then
//	tx.Create(&rp)                         //   passed by pointer
func rolePermissionWritePos(body *ast.BlockStmt) (token.Pos, bool) {
	locals := localModelTypes(body)
	var pos token.Pos
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) != 1 {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || (sel.Sel.Name != "Create" && sel.Sel.Name != "Delete") {
			return true
		}
		if modelArgTypeName(call.Args[0], locals) != "RolePermission" {
			return true
		}
		if !found {
			pos = call.Pos()
		}
		found = true
		return true
	})
	return pos, found
}

// localModelTypes maps a local variable name to the models.X type it was
// assigned or declared as, within body. Only the two forms that appear in this
// package are resolved (`x := models.X{…}` and `var x models.X`); anything
// else leaves the name unresolved, which makes modelArgTypeName return "" —
// an unresolvable argument is never silently treated as a non-write, it simply
// is not recognised, and the calibration assertion is what catches that.
func localModelTypes(body *ast.BlockStmt) map[string]string {
	out := map[string]string{}
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			if len(node.Lhs) != len(node.Rhs) {
				return true
			}
			for i, lhs := range node.Lhs {
				id, ok := lhs.(*ast.Ident)
				if !ok {
					continue
				}
				if name := compositeLiteralTypeName(node.Rhs[i]); name != "" {
					out[id.Name] = name
				}
			}
		case *ast.ValueSpec:
			name := ""
			if sel, ok := node.Type.(*ast.SelectorExpr); ok {
				name = sel.Sel.Name
			}
			for i, id := range node.Names {
				if name != "" {
					out[id.Name] = name
					continue
				}
				if i < len(node.Values) {
					if lit := compositeLiteralTypeName(node.Values[i]); lit != "" {
						out[id.Name] = lit
					}
				}
			}
		}
		return true
	})
	return out
}

// modelArgTypeName resolves a Create/Delete argument to a models.X type name,
// through one level of `&` and one level of local-variable indirection.
func modelArgTypeName(arg ast.Expr, locals map[string]string) string {
	if unary, ok := arg.(*ast.UnaryExpr); ok && unary.Op == token.AND {
		arg = unary.X
	}
	if name := compositeLiteralTypeName(arg); name != "" {
		return name
	}
	if id, ok := arg.(*ast.Ident); ok {
		return locals[id.Name]
	}
	return ""
}

// compositeLiteralTypeName returns "RolePermission" for both
// `models.RolePermission{…}` and `&models.RolePermission{…}`.
func compositeLiteralTypeName(arg ast.Expr) string {
	if unary, ok := arg.(*ast.UnaryExpr); ok && unary.Op == token.AND {
		arg = unary.X
	}
	lit, ok := arg.(*ast.CompositeLit)
	if !ok {
		return ""
	}
	sel, ok := lit.Type.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	return sel.Sel.Name
}

func callsNamed(n ast.Node, name string) bool {
	found := false
	ast.Inspect(n, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		if id, ok := call.Fun.(*ast.Ident); ok && id.Name == name {
			found = true
		}
		return true
	})
	return found
}

// someTransactionClosureHasBoth reports whether any `…Transaction(func(…){…})`
// closure in body contains BOTH a role_permissions write and a generation
// bump. That is the structural form of "in the same transaction" available to
// an AST scan.
func someTransactionClosureHasBoth(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Transaction" || len(call.Args) != 1 {
			return true
		}
		lit, ok := call.Args[0].(*ast.FuncLit)
		if !ok || lit.Body == nil {
			return true
		}
		if _, writes := rolePermissionWritePos(lit.Body); writes && callsNamed(lit.Body, rolePermissionBumpFunc) {
			found = true
		}
		return true
	})
	return found
}
