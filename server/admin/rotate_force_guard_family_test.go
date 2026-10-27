package admin

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// TestEveryDEKRotatingAdminCommandRefusesForce: the family guard for
// rotate_force_cross_replica_postgres_test.go (REVIEW-3750-DEEP-1 F1: the guard
// had been added to `admin encryption rotate` only, and `admin encryption
// auth-encryption rotate --force` still ran the same RotateDEKWithSweep next to
// live replicas). Every function in this package's non-test files that calls,
// directly or through internal/encryption or internal/encryptionops, anything
// that reaches Service.RotateDEKWithSweep must call refuseForcedDEKRotation
// before that call.
//
// Reachability is by function/method NAME across the non-test files of those
// two packages, so it over-approximates (a name collision adds a site, it never
// hides one). Not seen: a call through a function value or an interface method
// whose name differs from the implementation's.
func TestEveryDEKRotatingAdminCommandRefusesForce(t *testing.T) {
	reach := namesReaching(t, "RotateDEKWithSweep",
		filepath.Join("..", "..", "internal", "encryption"),
		filepath.Join("..", "..", "internal", "encryptionops"))

	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var sites []string
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Body == nil || fn.Name.Name == "refuseForcedDEKRotation" {
				continue
			}
			var firstRotate, firstRefuse token.Pos
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				switch name := calleeName(call); {
				case name == "refuseForcedDEKRotation":
					if !firstRefuse.IsValid() || call.Pos() < firstRefuse {
						firstRefuse = call.Pos()
					}
				case reach[name]:
					if _, isSel := call.Fun.(*ast.SelectorExpr); !isSel {
						return true // a same-package helper of that name is not one of theirs
					}
					if !firstRotate.IsValid() || call.Pos() < firstRotate {
						firstRotate = call.Pos()
					}
				}
				return true
			})
			if !firstRotate.IsValid() {
				continue
			}
			sites = append(sites, fn.Name.Name)
			if !firstRefuse.IsValid() || firstRefuse > firstRotate {
				t.Errorf("%s: %s reaches RotateDEKWithSweep at %s without calling refuseForcedDEKRotation(cfg, dryRun) before it: --force would rotate the DEK next to live replicas on PostgreSQL",
					fset.Position(fn.Pos()), fn.Name.Name, fset.Position(firstRotate))
			}
		}
	}
	sort.Strings(sites)
	t.Logf("DEK-rotating admin functions: %v", sites)
	// Keep the guard from going vacuous: both known DEK-rotating commands must
	// be found by the scan above.
	for _, want := range []string{"runAuthRotate", "runEncRotate"} {
		if i := sort.SearchStrings(sites, want); i == len(sites) || sites[i] != want {
			t.Errorf("the scan did not find %s among the DEK-rotating functions (%v): the reachability analysis is broken", want, sites)
		}
	}
}

// namesReaching returns the set of function and method names, declared in the
// non-test files of dirs, that call target directly or transitively (by name),
// plus target itself.
func namesReaching(t *testing.T, target string, dirs ...string) map[string]bool {
	t.Helper()
	calls := map[string]map[string]bool{}
	fset := token.NewFileSet()
	for _, dir := range dirs {
		files, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		if len(files) == 0 {
			t.Fatalf("no Go files in %s", dir)
		}
		for _, name := range files {
			if strings.HasSuffix(name, "_test.go") {
				continue
			}
			f, err := parser.ParseFile(fset, name, nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			for _, d := range f.Decls {
				fn, ok := d.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				set := calls[fn.Name.Name]
				if set == nil {
					set = map[string]bool{}
					calls[fn.Name.Name] = set
				}
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					if call, ok := n.(*ast.CallExpr); ok {
						if c := calleeName(call); c != "" {
							set[c] = true
						}
					}
					return true
				})
			}
		}
	}
	reach := map[string]bool{target: true}
	for changed := true; changed; {
		changed = false
		for fn, callees := range calls {
			if reach[fn] {
				continue
			}
			for c := range callees {
				if reach[c] {
					reach[fn], changed = true, true
					break
				}
			}
		}
	}
	return reach
}

func calleeName(call *ast.CallExpr) string {
	switch f := call.Fun.(type) {
	case *ast.Ident:
		return f.Name
	case *ast.SelectorExpr:
		return f.Sel.Name
	}
	return ""
}
