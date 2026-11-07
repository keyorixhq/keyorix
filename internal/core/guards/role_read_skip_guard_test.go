// role_read_skip_guard_test.go -- AUTHZ-GROUPROLE-TAILS-1 item 1 (#3988).
//
// The class: `if _, err := c.storage.GetRole(ctx, g.RoleID); err != nil { continue }` inside a
// loop over a group's or an invitation's roles. The skip exists for a role that is positively
// gone (it confers nothing), but written this way it also skips the role on a transient storage
// fault, and the ceiling, separation-of-duties or scope check that role needed never runs: the
// grant goes through on exactly the request where nothing could be verified. validateGroupJoinRoles
// had it (#3988), and the sweep for the shape found three siblings (the group-join SoD set, the
// invitation scope check, the outside-scope invitation report). Every one now skips only on
// isPositiveNotFound and returns the storage-unavailable error otherwise.
//
// What it recognises (the enumeration, stated so a reviewer can check it):
//   - an `if` statement whose body is exactly one `continue`, and whose condition contains
//     `<ident> != nil` (alone or as an operand of ||/&&), where <ident> was assigned from ONE
//     call of a method whose name starts with GetRole (GetRole, GetRoleByName,
//     GetRolePermissions, ...) on any receiver, either in the if statement's own init or in the
//     statement directly before it in the same block.
//
// What it does NOT catch:
//   - `return nil` / `return true` / `break` instead of `continue` (a fail-open return out of the
//     whole check), or a body that does more than skip (a log line then continue);
//   - the error assigned further up than the previous statement, or passed through a helper;
//   - role reads not named GetRole* (ListRoles, a permission-set helper, a storage call through a
//     stored func value);
//   - code outside the core family (srcpath.CoreFamilyGoFiles).
// An exception that no longer matches a hit fails, so a stale reason cannot linger.
//
// Report-only on its first day (docs/guard-rollout.d/TestNoRoleReadErrorSkippedAsGone.tsv,
// docs/guard-rollout-contract.md).

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

	"github.com/keyorixhq/keyorix/internal/guardrules"
	"github.com/keyorixhq/keyorix/internal/testutil/srcpath"
)

// roleReadSkipExceptions: "file.go:FuncName" -> why skipping on any role-read error is safe.
// Filled one file per row by registerRoleReadSkipException from
// role_read_skip_exception_*_test.go.
var roleReadSkipExceptions = map[string]string{}

func registerRoleReadSkipException(key, reason string) {
	if _, dup := roleReadSkipExceptions[key]; dup {
		panic("duplicate role-read-skip exception " + key)
	}
	roleReadSkipExceptions[key] = reason
}

type roleReadSkip struct {
	File, Func, Callee string
	Line               int
}

func (r roleReadSkip) key() string { return r.File + ":" + r.Func }

// roleReadErrVar returns the error identifier and callee when stmt assigns the last result of
// one GetRole* call to an identifier.
func roleReadErrVar(stmt ast.Stmt) (errName, callee string) {
	as, ok := stmt.(*ast.AssignStmt)
	if !ok || len(as.Rhs) != 1 || len(as.Lhs) < 2 {
		return "", ""
	}
	call, ok := as.Rhs[0].(*ast.CallExpr)
	if !ok {
		return "", ""
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || !strings.HasPrefix(sel.Sel.Name, "GetRole") {
		return "", ""
	}
	id, ok := as.Lhs[len(as.Lhs)-1].(*ast.Ident)
	if !ok || id.Name == "_" {
		return "", ""
	}
	return id.Name, sel.Sel.Name
}

// condTestsNotNil reports whether cond is `name != nil`, or contains it as an operand of a
// logical operator.
func condTestsNotNil(cond ast.Expr, name string) bool {
	be, ok := ast.Unparen(cond).(*ast.BinaryExpr)
	if !ok {
		return false
	}
	switch be.Op {
	case token.LOR, token.LAND:
		return condTestsNotNil(be.X, name) || condTestsNotNil(be.Y, name)
	case token.NEQ:
		id, ok := be.X.(*ast.Ident)
		nl, ok2 := be.Y.(*ast.Ident)
		return ok && ok2 && id.Name == name && nl.Name == "nil"
	}
	return false
}

func isLoneContinue(body *ast.BlockStmt) bool {
	if body == nil || len(body.List) != 1 {
		return false
	}
	br, ok := body.List[0].(*ast.BranchStmt)
	return ok && br.Tok == token.CONTINUE && br.Label == nil
}

func scanRoleReadSkips(fset *token.FileSet, f *ast.File, file string) []roleReadSkip {
	var out []roleReadSkip
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			blk, ok := n.(*ast.BlockStmt)
			if !ok {
				return true
			}
			for i, stmt := range blk.List {
				ifs, ok := stmt.(*ast.IfStmt)
				if !ok || !isLoneContinue(ifs.Body) || ifs.Else != nil {
					continue
				}
				var errName, callee string
				if ifs.Init != nil {
					errName, callee = roleReadErrVar(ifs.Init)
				}
				if errName == "" && i > 0 {
					errName, callee = roleReadErrVar(blk.List[i-1])
				}
				if errName != "" && condTestsNotNil(ifs.Cond, errName) {
					out = append(out, roleReadSkip{File: file, Func: fn.Name.Name, Callee: callee, Line: fset.Position(ifs.Pos()).Line})
				}
			}
			return true
		})
	}
	return out
}

func scanRoleReadSkipsInSource(t testing.TB, file, src string) []roleReadSkip {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, src, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
	return scanRoleReadSkips(fset, f, filepath.Base(file))
}

// The planted shapes, both directions: the #3988 line and its variants must be found, the fixed
// forms must not be.
func TestRoleReadSkipScanner_Calibration(t *testing.T) {
	for name, src := range map[string]string{
		// The exact line origin/main had in validateGroupJoinRoles.
		"if-init, #3988": `package core
func (c *K) validateGroupJoinRoles() {
	for _, g := range grants {
		if _, err := c.storage.GetRole(ctx, g.RoleID); err != nil {
			continue
		}
	}
}`,
		"previous statement, sod": `package core
func requireX() {
	for _, g := range grants {
		role, err := st.GetRole(ctx, g.RoleID)
		if err != nil {
			continue
		}
		_ = role
	}
}`,
		"folded into ||": `package core
func list() {
	for _, g := range grants {
		r, err := c.storage.GetRoleByName(ctx, g.role)
		if err != nil || r == nil {
			continue
		}
	}
}`,
	} {
		if got := scanRoleReadSkipsInSource(t, "groups.go", src); len(got) != 1 {
			t.Errorf("%s: want exactly one hit, got %+v", name, got)
		}
	}

	for name, src := range map[string]string{
		"fixed form": `package core
func (c *K) validateGroupJoinRoles() {
	for _, g := range grants {
		if _, err := c.storage.GetRole(ctx, g.RoleID); err != nil {
			if isPositiveNotFound(err) {
				continue
			}
			return classifyReadError(err, "role not found")
		}
	}
}`,
		"not a role read": `package core
func f() {
	for _, g := range grants {
		u, err := c.storage.GetUser(ctx, g.ID)
		if err != nil {
			continue
		}
		_ = u
	}
}`,
		"error returned": `package core
func f() {
	for _, g := range grants {
		r, err := st.GetRole(ctx, g.RoleID)
		if err != nil {
			return err
		}
		_ = r
	}
}`,
		"read further up": `package core
func f() {
	for _, g := range grants {
		r, err := st.GetRole(ctx, g.RoleID)
		_ = r
		if err != nil {
			continue
		}
	}
}`,
	} {
		if got := scanRoleReadSkipsInSource(t, "groups.go", src); len(got) != 0 {
			t.Errorf("%s: want no hit, got %+v", name, got)
		}
	}
}

func TestNoRoleReadErrorSkippedAsGone(t *testing.T) {
	g := guardrules.Rollout(t)
	var hits []roleReadSkip
	for _, path := range coreFamilySources(t) {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		hits = append(hits, scanRoleReadSkips(fset, f, srcpath.CoreFamilyRel(path))...)
	}
	// A floor, so a matcher that silently stops matching fails loudly instead of staying green:
	// ReconcileRBACPermissions' two skips are registered exceptions and must still be seen.
	if len(hits) < 2 {
		t.Fatalf("scanner found only %d role-read skips in the core family; it has stopped matching", len(hits))
	}

	used := map[string]bool{}
	var msgs []string
	for _, h := range hits {
		if _, ok := roleReadSkipExceptions[h.key()]; ok {
			used[h.key()] = true
			continue
		}
		msgs = append(msgs, fmt.Sprintf("%s:%d in %s skips the role on ANY %s error", h.File, h.Line, h.Func, h.Callee))
	}
	sort.Strings(msgs)
	for _, m := range msgs {
		g.Errorf("%s: a storage fault is not a deleted role, and skipping it skips the check that role needed (#3988). "+
			"Skip only when isPositiveNotFound(err) and return classifyReadError(err, ...) otherwise, or add a "+
			"role_read_skip_exception_<name>_test.go calling registerRoleReadSkipException with the reason it is safe", m)
	}
	for key, why := range roleReadSkipExceptions {
		if !used[key] {
			g.Errorf("exception %q (%s) matches no hit any more: delete its file", key, why)
		}
	}
}
