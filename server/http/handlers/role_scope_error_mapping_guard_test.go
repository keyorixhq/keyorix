package handlers

// role_scope_error_mapping_guard_test.go — #3554 review follow-up 5: every HTTP
// handler that calls a core method able to return a role-scope refusal
// (core.ErrRoleScopeInvalid) maps it, instead of letting a caller-fixable 400
// fall through to the handler's generic 500.
//
// The method set is DERIVED in internal/core (role_scope_reach_registry_test.go)
// and read here from its testdata file, so a new grant path reaching the check
// shows up without anyone remembering to list it.
//
// What it recognises: a call `X.coreService.M(...)` (every handler reaches core
// through a coreService field) with M in the derived set, inside a top-level
// function or method; the enclosing function must call sendRoleScopeError or
// ssoRoleScopeErrorMessage. It does not follow the error into a helper the
// handler hands it to; such a handler needs the call itself or an exemption.

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

var roleScopeMappers = map[string]bool{"sendRoleScopeError": true, "ssoRoleScopeErrorMessage": true}

// roleScopeMappingExempt names handlers that call a reaching method without
// mapping the refusal, each for a stated reason.
var roleScopeMappingExempt = map[string]string{
	"ConsumeSetup": "unauthenticated setup-link endpoint: every refusal is the same generic 400 by design " +
		"(no account-existence or internal-error oracle); the role-scope reason is audited as " +
		"setup_token.consume_failed by core's completeInvitationAccept (v0.96 has no LogSetupConsumeFailure)",
}

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

// roleScopeMappingViolations returns, for the Go source files in dir, each
// "file:func -> M" whose function calls a reaching method M through coreService
// without calling a mapper, and how many reaching calls it saw.
func roleScopeMappingViolations(t *testing.T, dir string, reaching map[string]bool) (violations []string, seen int) {
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
			var calls []string
			mapped := false
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				switch fn := call.Fun.(type) {
				case *ast.Ident:
					if roleScopeMappers[fn.Name] {
						mapped = true
					}
				case *ast.SelectorExpr:
					if recv, ok := fn.X.(*ast.SelectorExpr); ok && recv.Sel.Name == "coreService" && reaching[fn.Sel.Name] {
						calls = append(calls, fn.Sel.Name)
					}
				}
				return true
			})
			seen += len(calls)
			if len(calls) == 0 || mapped {
				continue
			}
			if _, ok := roleScopeMappingExempt[fd.Name.Name]; ok {
				continue
			}
			violations = append(violations, name+":"+fd.Name.Name+" -> "+strings.Join(calls, ","))
		}
	}
	slices.Sort(violations)
	return violations, seen
}

func TestEveryRoleScopeReachingHandlerMapsTheRefusal(t *testing.T) {
	violations, seen := roleScopeMappingViolations(t, ".", readRoleScopeReachingMethods(t))
	// Population tripwire: the grant handlers themselves must be seen.
	if seen < 15 {
		t.Fatalf("saw only %d coreService calls of a reaching method: the scan is broken", seen)
	}
	if len(violations) > 0 {
		t.Fatalf("these handlers call a core method that can return a role-scope refusal (#3546) without "+
			"mapping it: call sendRoleScopeError(w, err) first in the error branch (400), or add a reasoned "+
			"exemption to roleScopeMappingExempt:\n  %s", strings.Join(violations, "\n  "))
	}
}

// TestRoleScopeMappingGuardCatchesAnUnmappedHandler is the guard's self-test:
// a synthetic handler calling a reaching method with no mapper is reported, and
// the same handler with sendRoleScopeError is not.
func TestRoleScopeMappingGuardCatchesAnUnmappedHandler(t *testing.T) {
	dir := t.TempDir()
	src := `package handlers
func (h *H) Bad(w W, r R)  { if err := h.coreService.AddProjectMember(); err != nil { sendError(w) } }
func (h *H) Good(w W, r R) { if err := h.coreService.AddProjectMember(); err != nil { if sendRoleScopeError(w, err) { return } } }
`
	if err := os.WriteFile(filepath.Join(dir, "synthetic.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	violations, seen := roleScopeMappingViolations(t, dir, map[string]bool{"AddProjectMember": true})
	if seen != 2 || !slices.Equal(violations, []string{"synthetic.go:Bad -> AddProjectMember"}) {
		t.Fatalf("self-test: seen=%d violations=%v, want 2 and exactly the Bad handler", seen, violations)
	}
}
