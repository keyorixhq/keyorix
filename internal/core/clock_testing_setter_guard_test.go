package core

// clock_testing_setter_guard_test.go — KeyorixCore.SetClockForTesting
// (service.go) and OIDCVerifier.setClock (oidc.go) exist ONLY to let a test
// pin the single clock a verification reads (#1983's "one clock per
// verification" fix hinges on being able to inject one consistent `now` —
// see jwt_one_clock_per_verify_test.go). Production code must never call
// either: doing so would let something other than a test retarget every
// time-based check the affected type makes (session/PAT/token expiry, JWT
// exp/nbf/iat via jwt.WithTimeFunc, SSO state TTLs, ...) — exactly the kind
// of clock hazard #1983 fixed. This parses every non-_test.go file in this
// package and fails if either name appears as a call.
//
// New file only.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestClockOverridesNotCalledOutsideTests(t *testing.T) {
	t.Parallel()

	forbidden := map[string]bool{"SetClockForTesting": true, "setClock": true}

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading package directory: %v", err)
	}

	fset := token.NewFileSet()
	checked := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		checked++

		f, perr := parser.ParseFile(fset, filepath.Join(".", name), nil, 0)
		if perr != nil {
			t.Fatalf("parsing %s: %v", name, perr)
		}

		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			var funcName string
			switch fn := call.Fun.(type) {
			case *ast.SelectorExpr:
				funcName = fn.Sel.Name
			case *ast.Ident:
				funcName = fn.Name
			}
			if forbidden[funcName] {
				pos := fset.Position(call.Pos())
				t.Errorf("%s:%d: production code must not call %s -- test-only clock override (#1983)", name, pos.Line, funcName)
			}
			return true
		})
	}

	if checked == 0 {
		t.Fatal("no non-_test.go files found to check -- guard is vacuous, something is wrong with the scan")
	}
}
