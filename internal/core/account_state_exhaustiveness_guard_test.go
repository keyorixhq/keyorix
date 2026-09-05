// account_state_exhaustiveness_guard_test.go — a structural guard, in the
// same family as server/http's raw_storage_bypass_guard_test.go, statically
// proving every ADR-025 account-state constant declared in account_state.go
// is explicitly listed in AccountLoginBlocked's switch statement.
//
// This is what makes "a future account state added without updating this
// switch" (the scenario AccountLoginBlocked's own doc names as the reason a
// blanket fail-open default used to seem safer) impossible to ship silently:
// a state that falls through to AccountLoginBlocked's default case gets
// blocked, not silently allowed -- but ONLY if a developer actually intended
// that. This test forces the decision to be explicit and visible in the
// diff, not an accident of switch-statement omission.
package core

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// TestAccountLoginBlocked_ExhaustsStateRegistry parses account_state.go,
// collects every top-level `AccountXxx = "..."` constant declared there, then
// confirms each one is referenced as a case value somewhere in
// AccountLoginBlocked's switch statement (either the "not blocked" or the
// "blocked" case group). Adding a new AccountXxx constant without adding it
// to one of those two groups fails this test.
func TestAccountLoginBlocked_ExhaustsStateRegistry(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "account_state.go", nil, 0)
	if err != nil {
		t.Fatalf("parsing account_state.go: %v", err)
	}

	constants := accountStateConstants(f)
	if len(constants) == 0 {
		t.Fatal("found zero AccountXxx constants in account_state.go -- the const-collection logic itself is broken")
	}

	switchCases := accountLoginBlockedSwitchCaseIdents(f)
	if switchCases == nil {
		t.Fatal("could not find AccountLoginBlocked's switch statement in account_state.go")
	}

	var missing []string
	for _, c := range constants {
		if !switchCases[c] {
			missing = append(missing, c)
		}
	}
	if len(missing) > 0 {
		t.Errorf("AccountLoginBlocked's switch does not explicitly list: %v -- add each to either the "+
			"not-blocked or blocked case group (never rely on the default case for a real, valid state)", missing)
	}
}

// accountStateConstants returns every top-level constant identifier declared
// in f whose name starts with "Account" (matching AccountActive,
// AccountSuspended, etc.) and whose value is a string literal.
func accountStateConstants(f *ast.File) []string {
	var names []string
	for _, decl := range f.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, name := range vs.Names {
				if len(vs.Values) <= i {
					continue
				}
				if _, ok := vs.Values[i].(*ast.BasicLit); !ok {
					continue
				}
				if len(name.Name) > 7 && name.Name[:7] == "Account" {
					names = append(names, name.Name)
				}
			}
		}
	}
	return names
}

// accountLoginBlockedSwitchCaseIdents finds AccountLoginBlocked's func decl
// and returns the set of identifier names referenced in any of its switch
// statement's (non-default) case clauses. Returns nil if the function or its
// switch statement can't be found.
func accountLoginBlockedSwitchCaseIdents(f *ast.File) map[string]bool {
	var fd *ast.FuncDecl
	for _, decl := range f.Decls {
		cand, ok := decl.(*ast.FuncDecl)
		if ok && cand.Name.Name == "AccountLoginBlocked" {
			fd = cand
			break
		}
	}
	if fd == nil {
		return nil
	}

	var sw *ast.SwitchStmt
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		if s, ok := n.(*ast.SwitchStmt); ok {
			sw = s
			return false
		}
		return true
	})
	if sw == nil {
		return nil
	}

	idents := map[string]bool{}
	for _, stmt := range sw.Body.List {
		cc, ok := stmt.(*ast.CaseClause)
		if !ok || cc.List == nil { // nil List is the default case
			continue
		}
		for _, expr := range cc.List {
			if id, ok := expr.(*ast.Ident); ok {
				idents[id.Name] = true
			}
		}
	}
	return idents
}
