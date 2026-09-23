package store

// local_sharing_time_now_guard_test.go — #1983-c: local_sharing.go's 7 share-
// expiry read/check methods (ListSharesBySecret, ListSharesBySecretIDs,
// ListSharesByUser, ListSharesByOwner, ListSharesByGroup, ListSharedSecrets,
// CheckSharePermission) each take an explicit `now time.Time` parameter
// instead of calling time.Now() internally (see interface.go's doc comment on
// ListSharesBySecret). This parses local_sharing.go and fails if any of
// those 7 function bodies contains a time.Now() call -- zero exceptions, so a
// future edit can't quietly reintroduce the internal-clock hazard #1983
// closed (see docs/findings referenced from jwt/impersonation clock fixes
// earlier in this series for the same bug class). local_sharing.go's OTHER
// time.Now() calls (UpdatedAt bookkeeping stamps in CreateShareRecord/
// UpdateShareRecord) are intentionally out of scope and not checked here.
//
// New file only.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

func TestNoInternalTimeNowInShareExpiryChecks(t *testing.T) {
	t.Parallel()

	guarded := map[string]bool{
		"ListSharesBySecret":    true,
		"ListSharesBySecretIDs": true,
		"ListSharesByUser":      true,
		"ListSharesByOwner":     true,
		"ListSharesByGroup":     true,
		"ListSharedSecrets":     true,
		"CheckSharePermission":  true,
	}

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "local_sharing.go", nil, 0)
	if err != nil {
		t.Fatalf("parsing local_sharing.go: %v", err)
	}

	checked := 0
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv == nil || !guarded[fn.Name.Name] {
			continue
		}
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
			t.Errorf("local_sharing.go:%d: (*LocalStorage).%s must not call time.Now() internally -- take it as an explicit now parameter (#1983-c)", pos.Line, fn.Name.Name)
			return true
		})
	}

	if checked != len(guarded) {
		t.Fatalf("expected to check %d guarded methods on LocalStorage, found %d -- a method was renamed or removed, update this guard's list", len(guarded), checked)
	}
}
