// local_sharing_no_bare_clock_test.go — #1983: local_sharing.go's seven
// share-listing methods (ListSharesBySecret, ListSharesBySecretIDs,
// ListSharesByUser, ListSharesByOwner, ListSharesByGroup, ListSharedSecrets,
// CheckSharePermission) each take an explicit now time.Time parameter
// specifically so they never read the real wall clock themselves — every
// caller sources now from the SAME clock its own active-share check already
// uses (KeyorixCore.shareEffectiveNow), closing the "split clock in series"
// gap this investigation found. A bare time.Now() reintroduced inside any of
// these seven method bodies would silently reopen that gap without touching
// the function signature, so this guard checks the actual body source, not
// just that the parameter exists. Scoped to these seven specifically (not
// the whole file): CreateShareRecord/UpdateShareRecord legitimately call
// time.Now() for UpdatedAt bookkeeping, an unrelated concern.
package store

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"testing"
)

var localSharingClockParamMethods = map[string]bool{
	"ListSharesBySecret":    true,
	"ListSharesBySecretIDs": true,
	"ListSharesByUser":      true,
	"ListSharesByOwner":     true,
	"ListSharesByGroup":     true,
	"ListSharedSecrets":     true,
	"CheckSharePermission":  true,
}

// TestLocalSharingClockParamMethodsNeverCallBareClock fails if any of the
// seven methods above contains a time.Now() call anywhere in its own body.
func TestLocalSharingClockParamMethodsNeverCallBareClock(t *testing.T) {
	const path = "local_sharing.go"
	src, err := os.ReadFile(path) // #nosec G304 -- fixed repo-internal path, not external input
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, 0)
	if err != nil {
		t.Fatalf("parsing %s: %v", path, err)
	}

	seen := map[string]bool{}
	var violations []string
	for _, decl := range f.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || !localSharingClockParamMethods[fd.Name.Name] {
			continue
		}
		seen[fd.Name.Name] = true
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Now" {
				return true
			}
			pkgIdent, ok := sel.X.(*ast.Ident)
			if !ok || pkgIdent.Name != "time" {
				return true
			}
			violations = append(violations, fd.Name.Name)
			return true
		})
	}
	if len(violations) > 0 {
		t.Fatalf("these local_sharing.go methods must never call time.Now() directly -- every "+
			"share-active decision must be parameterized on the caller's own clock: %v", violations)
	}
	for name := range localSharingClockParamMethods {
		if !seen[name] {
			t.Errorf("expected method %s not found in local_sharing.go -- guard is stale, update "+
				"localSharingClockParamMethods or investigate why the method moved/was removed", name)
		}
	}
}
