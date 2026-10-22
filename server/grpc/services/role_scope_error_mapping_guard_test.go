package services

// role_scope_error_mapping_guard_test.go — #3554 review follow-up 5, gRPC side
// of server/http/handlers/role_scope_error_mapping_guard_test.go: every service
// method that calls a core method able to return a role-scope refusal maps it
// to InvalidArgument, instead of the generic Internal.
//
// The reaching-method set is derived in internal/core
// (role_scope_reach_registry_test.go) and read from its testdata file. The
// MAPPER set is derived here too: every function in this package whose body
// calls core.RoleScopeClientMessage (mapRoleError, mapUserError,
// breakGlassError, ...).
//
// What it recognises: a call `X.core.M(...)` (services reach core through a
// core field) with M reaching, inside a top-level function; that function must
// call a mapper or RoleScopeClientMessage itself, directly.

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

const roleScopeReachingMethodsFile = "../../../internal/core/testdata/role_scope_reaching_methods.txt"

func readRoleScopeReachingMethods(t *testing.T) map[string]bool {
	t.Helper()
	b, err := os.ReadFile(roleScopeReachingMethodsFile)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for line := range strings.SplitSeq(strings.TrimSpace(string(b)), "\n") {
		out[strings.TrimSpace(line)] = true
	}
	if len(out) < 10 {
		t.Fatalf("%s lists %d methods: the derivation is broken", roleScopeReachingMethodsFile, len(out))
	}
	return out
}

type grpcFuncCalls struct {
	file, name    string
	reachingCalls []string
	calls         map[string]bool // every called name (Ident or Sel)
}

func scanGRPCFuncs(t *testing.T, dir string, reaching map[string]bool) []grpcFuncCalls {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var out []grpcFuncCalls
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
			fc := grpcFuncCalls{file: name, name: fd.Name.Name, calls: map[string]bool{}}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				switch fn := call.Fun.(type) {
				case *ast.Ident:
					fc.calls[fn.Name] = true
				case *ast.SelectorExpr:
					fc.calls[fn.Sel.Name] = true
					if recv, ok := fn.X.(*ast.SelectorExpr); ok && recv.Sel.Name == "core" && reaching[fn.Sel.Name] {
						fc.reachingCalls = append(fc.reachingCalls, fn.Sel.Name)
					}
				}
				return true
			})
			out = append(out, fc)
		}
	}
	return out
}

func grpcRoleScopeMappingViolations(funcs []grpcFuncCalls) (violations []string, seen int, mappers map[string]bool) {
	mappers = map[string]bool{"RoleScopeClientMessage": true}
	for _, f := range funcs {
		if f.calls["RoleScopeClientMessage"] {
			mappers[f.name] = true
		}
	}
	for _, f := range funcs {
		if len(f.reachingCalls) == 0 {
			continue
		}
		seen += len(f.reachingCalls)
		mapped := false
		for c := range f.calls {
			if mappers[c] {
				mapped = true
				break
			}
		}
		if !mapped {
			violations = append(violations, f.file+":"+f.name+" -> "+strings.Join(f.reachingCalls, ","))
		}
	}
	slices.Sort(violations)
	return violations, seen, mappers
}

func TestEveryRoleScopeReachingRPCMapsTheRefusal(t *testing.T) {
	violations, seen, mappers := grpcRoleScopeMappingViolations(scanGRPCFuncs(t, ".", readRoleScopeReachingMethods(t)))
	// Population tripwires: the known grant RPCs and mappers must be seen.
	if seen < 3 {
		t.Fatalf("saw only %d core calls of a reaching method: the scan is broken", seen)
	}
	for _, m := range []string{"mapRoleError", "mapUserError", "breakGlassError"} {
		if !mappers[m] {
			t.Fatalf("mapper %s not derived: the scan is broken, or %s stopped mapping role-scope refusals", m, m)
		}
	}
	if len(violations) > 0 {
		t.Fatalf("these RPCs call a core method that can return a role-scope refusal (#3546) without mapping it "+
			"to InvalidArgument (core.RoleScopeClientMessage, or a mapper that calls it):\n  %s", strings.Join(violations, "\n  "))
	}
}

// TestRoleScopeRPCMappingGuardCatchesAnUnmappedRPC is the guard's self-test.
func TestRoleScopeRPCMappingGuardCatchesAnUnmappedRPC(t *testing.T) {
	dir := t.TempDir()
	src := `package services
func mapX(err error) error { if m, ok := core.RoleScopeClientMessage(err); ok { _ = m }; return err }
func (s *S) Bad()  error { return wrap(s.core.AssignUserRole()) }
func (s *S) Good() error { return mapX(s.core.AssignUserRole()) }
`
	if err := os.WriteFile(filepath.Join(dir, "synthetic.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	violations, seen, mappers := grpcRoleScopeMappingViolations(scanGRPCFuncs(t, dir, map[string]bool{"AssignUserRole": true}))
	if seen != 2 || !mappers["mapX"] || !slices.Equal(violations, []string{"synthetic.go:Bad -> AssignUserRole"}) {
		t.Fatalf("self-test: seen=%d mappers=%v violations=%v", seen, mappers, violations)
	}
}
