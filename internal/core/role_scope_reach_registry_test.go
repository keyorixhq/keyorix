package core

// role_scope_reach_registry_test.go — #3554 review follow-up 5: which exported
// core methods can return a role-scope refusal (ErrRoleScopeInvalid)?
//
// A transport handler that calls one of them must map the refusal to HTTP 400 /
// gRPC InvalidArgument; before this, project-member add, access-request
// approval, break-glass, invitations and others let it fall through to 500.
// The set is DERIVED here, not hand-listed, and written to
// testdata/role_scope_reaching_methods.txt; the transport guards
// (server/http/handlers/role_scope_error_mapping_guard_test.go,
// server/grpc/services/role_scope_error_mapping_guard_test.go) read that file.
// Regenerate with
//
//	KEYORIX_UPDATE_ROLE_SCOPE_REACH=1 go test ./internal/core -run TestRoleScopeReachingMethodsFileIsCurrent
//
// What it recognises: in every non-test file of package core, a function or
// method F "calls" G when F's body contains a call `G(...)` or `X.G(...)` for
// any X. That is name-based and over-approximates (a storage method sharing a
// core method's name links them), which can only ADD methods to the set: a
// handler then maps a refusal it can never get, which is harmless. It does not
// see a call through a func value (a callback passed as an argument is seen
// where it is written, as a call inside the enclosing function, so the usual
// closure shape IS covered) or reflection; package core has neither on these
// paths.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const roleScopeReachFile = "testdata/role_scope_reaching_methods.txt"

// roleScopeRefusalRoots are the functions that construct a *RoleScopeError.
var roleScopeRefusalRoots = []string{"validateRoleScope", "requireScopeValidForRoleName"}

// deriveRoleScopeReachingMethods returns the sorted exported KeyorixCore
// methods from which a root is reachable.
func deriveRoleScopeReachingMethods(t *testing.T, dir string) []string {
	t.Helper()
	fset := token.NewFileSet()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	callers := map[string]map[string]bool{} // callee -> callers
	coreMethods := map[string]bool{}
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
			if isKeyorixCoreReceiver(fd) {
				coreMethods[fd.Name.Name] = true
			}
			caller := fd.Name.Name
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				var callee string
				switch fn := call.Fun.(type) {
				case *ast.Ident:
					callee = fn.Name
				case *ast.SelectorExpr:
					callee = fn.Sel.Name
				}
				if callee != "" {
					if callers[callee] == nil {
						callers[callee] = map[string]bool{}
					}
					callers[callee][caller] = true
				}
				return true
			})
		}
	}
	reach := map[string]bool{}
	queue := slices.Clone(roleScopeRefusalRoots)
	for len(queue) > 0 {
		n := queue[0]
		queue = queue[1:]
		if reach[n] {
			continue
		}
		reach[n] = true
		for c := range callers[n] {
			queue = append(queue, c)
		}
	}
	var out []string
	for m := range reach {
		if coreMethods[m] && ast.IsExported(m) {
			out = append(out, m)
		}
	}
	slices.Sort(out)
	return out
}

func isKeyorixCoreReceiver(fd *ast.FuncDecl) bool {
	if fd.Recv == nil || len(fd.Recv.List) != 1 {
		return false
	}
	star, ok := fd.Recv.List[0].Type.(*ast.StarExpr)
	if !ok {
		return false
	}
	id, ok := star.X.(*ast.Ident)
	return ok && id.Name == "KeyorixCore"
}

func TestRoleScopeReachingMethodsFileIsCurrent(t *testing.T) {
	got := deriveRoleScopeReachingMethods(t, ".")
	// Population tripwire: the grant entry points themselves must be found, or
	// the derivation is broken (an empty set would pass every transport guard).
	for _, must := range []string{"AssignUserRole", "AssignRoleToGroup", "AssignMachineRole", "AddProjectMember", "SetUserRoles"} {
		if !slices.Contains(got, must) {
			t.Fatalf("derivation lost %s (got %d methods): the call-graph scan is broken", must, len(got))
		}
	}
	want := strings.Join(got, "\n") + "\n"
	if os.Getenv("KEYORIX_UPDATE_ROLE_SCOPE_REACH") == "1" {
		if err := os.WriteFile(roleScopeReachFile, []byte(want), 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	have, err := os.ReadFile(roleScopeReachFile)
	if err != nil {
		t.Fatalf("%v: regenerate with KEYORIX_UPDATE_ROLE_SCOPE_REACH=1", err)
	}
	if string(have) != want {
		t.Fatalf("%s is stale: the set of exported core methods that can return a role-scope refusal changed. "+
			"Regenerate with KEYORIX_UPDATE_ROLE_SCOPE_REACH=1 go test ./internal/core -run %s, then make every "+
			"transport handler calling a new method map the refusal (the transport guards will name them).",
			roleScopeReachFile, t.Name())
	}
}
