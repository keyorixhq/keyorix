package core

// sweep_time_now_guard_test.go — #1983-c: the two JIT-expiry sweep
// entrypoints RemoveExpiredShares (jit_access.go) and RevokeExpiredLeases
// (dynamic_secrets.go) already take an explicit `before time.Time` parameter
// rather than resolving "now" themselves -- server/main.go's scheduler loops
// compute it once per tick and thread it through. This parses those two
// files and fails if either function's body contains a time.Now() call,
// guarding against a future edit quietly reintroducing an internal clock
// read into a sweep entrypoint that's supposed to be fully caller-driven
// (same discipline as TestNoInternalTimeNowInShareExpiryChecks,
// internal/storage/store/local_sharing_time_now_guard_test.go, for the
// storage-layer half of this series).
//
// New file only.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

func TestNoInternalTimeNowInSweepEntrypoints(t *testing.T) {
	t.Parallel()

	targets := map[string]string{
		"jit_access.go":      "RemoveExpiredShares",
		"dynamic_secrets.go": "RevokeExpiredLeases",
	}

	fset := token.NewFileSet()
	checked := 0
	for file, fnName := range targets {
		f, err := parser.ParseFile(fset, file, nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", file, err)
		}
		found := false
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || fn.Name.Name != fnName {
				continue
			}
			found = true
			checked++
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "Now" {
					return true
				}
				pkg, ok := sel.X.(*ast.Ident)
				if !ok || pkg.Name != "time" {
					return true
				}
				pos := fset.Position(call.Pos())
				t.Errorf("%s:%d: (*KeyorixCore).%s must not call time.Now() internally -- it already takes `before time.Time` as an explicit parameter (#1983-c)", file, pos.Line, fnName)
				return true
			})
		}
		if !found {
			t.Fatalf("%s: function %s not found -- it was renamed or removed, update this guard", file, fnName)
		}
	}

	if checked != len(targets) {
		t.Fatalf("expected to check %d sweep entrypoints, found %d", len(targets), checked)
	}
}
