package handlers

// authorize_outage_family_guard_test.go — AUTHZ-OUTAGE-HANDLERS-1 item 3 (#3857):
// every `err != nil || !allowed` branch over a permission lookup that refuses with
// 403 / PermissionDenied must tell a storage outage (core.IsAuthorizeTransient:
// 503 / Unavailable) from a denial. #3853 fixed the middleware gates and the gRPC
// services; the in-handler checks kept answering 403 during a database outage.
//
// What it recognises (the list is the guard's contract; anything else is invisible
// to it):
//   - Population: a non-test Go file in server/http/handlers (and its
//     handlerFamilySubdirs) or server/grpc/services.
//   - A permission lookup: the enclosing top-level function calls a method whose
//     name starts with Authorize, HoldsPermission or AuthorizedAt. (A bare
//     `err != nil || !live` over a session or account read is not one.)
//   - The shape: an if whose condition is a `||` chain holding `<err ident> != nil`
//     (an identifier containing "err", case-insensitive) and a `!<ident or
//     selector>` operand.
//   - A refusal: the if body mentions http.StatusForbidden or codes.PermissionDenied.
//   - Mapped: a call to one of authorizeOutageMappers (core.IsAuthorizeTransient,
//     authorizeRefusal, refuseUnlessAuthorized) in the same if statement or in an
//     earlier statement of the same block.
//
// What it does NOT see: a refusal that is returned as an error and turned into a
// 403 by a caller (users_crud.go authorizeUserCreationAssignments), a lookup whose
// error is dropped (`allowed, _ :=`), and checks written as `err == nil && ok`
// with the refusal in the else branch (secrets_list.go's human scoped listing,
// which degrades to the owned/ACL list rather than refusing). The population
// tripwire only proves the scan finds permission lookups at all.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/guardrules"
)

var authorizeOutageMappers = map[string]bool{
	"IsAuthorizeTransient":   true,
	"authorizeRefusal":       true,
	"refuseUnlessAuthorized": true,
}

// authorizeOutageExempt names functions ("file.go:Func") whose raw
// `err != nil || !allowed` refusal is not yet mapped, each for a stated reason.
var authorizeOutageExempt = map[string]string{
	"catalog.go:UpdateProject": "roles.assign check on the MFA-requirement change; catalog.go is outside " +
		"AUTHZ-OUTAGE-HANDLERS-1's paths (LEFTOVERS)",
	"invitations.go:CreateGlobalInvitation": "roles.assign checks on invitation roles; invitations.go is outside " +
		"AUTHZ-OUTAGE-HANDLERS-1's paths (LEFTOVERS)",
	"rotation_policies_handler.go:Create": "secrets.write check on policy create; rotation_policies_handler.go is outside " +
		"AUTHZ-OUTAGE-HANDLERS-1's paths (LEFTOVERS)",
}

func authorizeOutageIsLookupName(name string) bool {
	return strings.HasPrefix(name, "Authorize") || strings.HasPrefix(name, "HoldsPermission")
}

func authorizeOutageCalls(n ast.Node, match func(name string) bool) bool {
	found := false
	ast.Inspect(n, func(x ast.Node) bool {
		call, ok := x.(*ast.CallExpr)
		if !ok {
			return !found
		}
		switch fn := call.Fun.(type) {
		case *ast.Ident:
			found = found || match(fn.Name)
		case *ast.SelectorExpr:
			found = found || match(fn.Sel.Name)
		}
		return !found
	})
	return found
}

// authorizeOutageShape reports whether cond is a `||` chain holding `<err> != nil`
// and a negated identifier or selector.
func authorizeOutageShape(cond ast.Expr) bool {
	var errNeq, negated bool
	var walk func(e ast.Expr)
	walk = func(e ast.Expr) {
		switch x := e.(type) {
		case *ast.ParenExpr:
			walk(x.X)
		case *ast.BinaryExpr:
			if x.Op == token.LOR {
				walk(x.X)
				walk(x.Y)
				return
			}
			if id, ok := x.X.(*ast.Ident); ok && x.Op == token.NEQ && strings.Contains(strings.ToLower(id.Name), "err") {
				if nilID, ok := x.Y.(*ast.Ident); ok && nilID.Name == "nil" {
					errNeq = true
				}
			}
		case *ast.UnaryExpr:
			if x.Op == token.NOT {
				switch x.X.(type) {
				case *ast.Ident, *ast.SelectorExpr:
					negated = true
				}
			}
		}
	}
	walk(cond)
	return errNeq && negated
}

func authorizeOutageRefuses(body ast.Node) bool {
	refuses := false
	ast.Inspect(body, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if pkg, ok := sel.X.(*ast.Ident); ok &&
			((pkg.Name == "http" && sel.Sel.Name == "StatusForbidden") || (pkg.Name == "codes" && sel.Sel.Name == "PermissionDenied")) {
			refuses = true
		}
		return !refuses
	})
	return refuses
}

// authorizeOutageViolations returns "file:func" for each unmapped refusing check in
// dir's Go sources, and how many permission-lookup calls it saw. Every exempt key
// that excused a finding is recorded in used (when non-nil), so a stale exemption
// can be reported.
func authorizeOutageViolations(t *testing.T, dir string, exempt map[string]string, used map[string]bool) (violations []string, lookups int) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			hasLookup := authorizeOutageCalls(fd.Body, authorizeOutageIsLookupName)
			if !hasLookup {
				continue
			}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				if call, ok := n.(*ast.CallExpr); ok {
					if sel, ok := call.Fun.(*ast.SelectorExpr); ok && authorizeOutageIsLookupName(sel.Sel.Name) {
						lookups++
					}
				}
				var stmts []ast.Stmt
				switch b := n.(type) {
				case *ast.BlockStmt:
					stmts = b.List
				case *ast.CaseClause:
					stmts = b.Body
				}
				for i, s := range stmts {
					ifs, ok := s.(*ast.IfStmt)
					if !ok || !authorizeOutageShape(ifs.Cond) || !authorizeOutageRefuses(ifs.Body) {
						continue
					}
					mapped := authorizeOutageCalls(ifs, func(n string) bool { return authorizeOutageMappers[n] })
					for _, prev := range stmts[:i] {
						mapped = mapped || authorizeOutageCalls(prev, func(n string) bool { return authorizeOutageMappers[n] })
					}
					if mapped {
						continue
					}
					key := name + ":" + fd.Name.Name
					if _, ok := exempt[key]; ok {
						if used != nil {
							used[key] = true
						}
						continue
					}
					violations = append(violations, key)
				}
				return true
			})
		}
	}
	slices.Sort(violations)
	return slices.Compact(violations), lookups
}

// TestEveryRefusingPermissionCheckMapsAStorageOutage scans server/http/handlers,
// its handlerFamilySubdirs and server/grpc/services. It reports through
// guardrules.Rollout: report-only on pull requests while
// docs/guard-rollout.d/TestEveryRefusingPermissionCheckMapsAStorageOutage.tsv
// exists (docs/guard-rollout-contract.md rule 2). The population tripwire stays
// blocking.
func TestEveryRefusingPermissionCheckMapsAStorageOutage(t *testing.T) {
	g := guardrules.Rollout(t)
	dirs := []string{"."}
	dirs = append(dirs, handlerFamilySubdirs...)
	dirs = append(dirs, "../../grpc/services")
	var violations []string
	lookups := 0
	used := map[string]bool{}
	for _, dir := range dirs {
		v, n := authorizeOutageViolations(t, dir, authorizeOutageExempt, used)
		for _, x := range v {
			violations = append(violations, filepath.ToSlash(filepath.Join(dir, x)))
		}
		lookups += n
	}
	if lookups < 20 {
		t.Fatalf("saw only %d permission-lookup calls: the scan is broken", lookups)
	}
	// An exemption that excuses nothing is stale (the site was fixed, renamed or
	// never matched): remove it, so the list only ever names real gaps. Blocking,
	// not report-only: it is a defect in this test's own table.
	for key := range authorizeOutageExempt {
		if !used[key] {
			t.Errorf("authorizeOutageExempt[%q] excuses no finding: remove it (the site is mapped, renamed or never matched)", key)
		}
	}
	if len(violations) > 0 {
		g.Errorf("these functions refuse with 403 / PermissionDenied on `err != nil || !allowed` without telling a "+
			"storage outage from a denial: route the result through refuseUnlessAuthorized (REST) or authorizeRefusal "+
			"(gRPC), or call core.IsAuthorizeTransient first (503 / Unavailable), or add a reasoned exemption to "+
			"authorizeOutageExempt:\n  %s", strings.Join(violations, "\n  "))
	}
}

// TestAuthorizeOutageGuardCatchesAnUnmappedCheck is the guard's self-test, both
// directions: the raw refusal is reported; a mapped one, one whose mapper sits in
// an earlier statement, an exempt one, a non-permission `err != nil || !live`, and
// a lookup with no refusal are not.
func TestAuthorizeOutageGuardCatchesAnUnmappedCheck(t *testing.T) {
	dir := t.TempDir()
	src := `package x
func (h *H) Bad(w W, r R) {
	if ok, err := h.core.AuthorizePrincipal(); err != nil || !ok { sendError(w, http.StatusForbidden); return }
}
func (h *H) BadGRPC(ctx C) error {
	allowed, aerr := cs.AuthorizeSecretPrincipal()
	if aerr != nil || !allowed { return status.Error(codes.PermissionDenied, "no") }
	return nil
}
func (h *H) GoodHelper(w W, r R) {
	ok, err := h.core.AuthorizePrincipal()
	if refuseUnlessAuthorized(w, r, ok, err, f) { return }
}
func (h *H) GoodEarlier(ctx C) error {
	allowed, aerr := cs.AuthorizeSecretPrincipal()
	if aerr != nil && core.IsAuthorizeTransient(ctx, aerr) { return status.Error(codes.Unavailable, "x") }
	if aerr != nil || !allowed { return status.Error(codes.PermissionDenied, "no") }
	return nil
}
func (h *H) GoodInside(ctx C) error {
	allowed, err := cs.AuthorizePrincipal()
	if err != nil || !allowed { return authorizeRefusal(ctx, err, "m") }
	return nil
}
func (h *H) Skip(w W) {
	if ok, err := h.core.AuthorizePrincipal(); err != nil || !ok { sendError(w, http.StatusForbidden) }
}
func (h *H) NotPermission(ctx C) error {
	live, err := s.core.SessionStillLive()
	if err != nil || !live { return status.Error(codes.PermissionDenied, "x") }
	return nil
}
func (h *H) NoRefusal(r R) {
	if ok, aerr := h.core.AuthorizeSecretPrincipal(); aerr != nil || !ok { d.Degraded = false }
}
`
	if err := os.WriteFile(filepath.Join(dir, "synthetic.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	used := map[string]bool{}
	violations, lookups := authorizeOutageViolations(t, dir, map[string]string{"synthetic.go:Skip": "test"}, used)
	if !used["synthetic.go:Skip"] {
		t.Fatalf("self-test: the Skip exemption excused a finding but was not recorded as used")
	}
	want := []string{"synthetic.go:Bad", "synthetic.go:BadGRPC"}
	if !slices.Equal(violations, want) || lookups != 7 {
		t.Fatalf("self-test: violations=%v lookups=%d, want %v and 7 lookups", violations, lookups, want)
	}
}
