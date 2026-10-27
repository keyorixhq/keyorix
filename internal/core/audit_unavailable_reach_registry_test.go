package core

// audit_unavailable_reach_registry_test.go — AUDIT-503-MAP-1: which exported core
// methods can return ErrMutationAuditUnavailable?
//
// A transport handler that calls one of them must answer the refusal with a
// retryable 503 / gRPC Unavailable (code audit_unavailable), not the generic 500
// it used to fall through to. The set is DERIVED here, not hand-listed, and
// written to testdata/audit_unavailable_reaching_methods.txt; the transport guards
// (server/http/handlers/audit_unavailable_mapping_guard_test.go,
// server/grpc/services/audit_unavailable_mapping_guard_test.go) read that file.
// Regenerate with
//
//	KEYORIX_UPDATE_AUDIT_UNAVAILABLE_REACH=1 go test ./internal/core -run TestAuditUnavailableReachingMethodsFileIsCurrent
//
// What it recognises: a root is any function or method whose body mentions the
// identifier ErrMutationAuditUnavailable, or one of the fail-closed audit
// wrappers (withAuditedMutation, mutationTx, auditedByDirection,
// withAuditedOrOwedMutation, failClosedAuditResult). A function F "calls" G when
// F's body contains `G(...)` or `c.G(...)` where c is F's own KeyorixCore
// receiver. That is name-based and still over-approximates (a core method that
// swallows the error is listed), which can only ADD methods to the set: a handler
// then maps a refusal it can never get, which is harmless. Calls on storage
// handles (tx.G, c.storage.G) and methods of other types are not followed. It does not see a call through a func value
// stored in a field or reflection; a callback written in the enclosing function
// IS seen. It does not decide whether the caller returns the error: a method
// that swallows it is still listed.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/testutil/srcpath"
)

const auditUnavailableReachFile = "testdata/audit_unavailable_reaching_methods.txt"

// auditUnavailableRoots are the fail-closed audit wrappers; the sentinel's own
// identifier is added to the root set by name wherever a body mentions it.
var auditUnavailableRoots = []string{
	"withAuditedMutation", "mutationTx", "auditedByDirection",
	"withAuditedOrOwedMutation", "failClosedAuditResult",
}

// deriveAuditUnavailableReachingMethods returns the sorted exported KeyorixCore
// methods from which a root is reachable, over the given non-test .go files.
func deriveAuditUnavailableReachingMethods(t *testing.T, paths []string) []string {
	t.Helper()
	fset := token.NewFileSet()
	callers := map[string]map[string]bool{} // callee -> callers
	coreMethods := map[string]bool{}
	queue := slices.Clone(auditUnavailableRoots)
	for _, path := range paths {
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			recvName := ""
			switch {
			case isKeyorixCoreReceiver(fd):
				coreMethods[fd.Name.Name] = true
				if names := fd.Recv.List[0].Names; len(names) == 1 {
					recvName = names[0].Name
				}
			case fd.Recv != nil:
				// A method of another type (auditTarget, a sink): not a node of the
				// graph. The audited mutation reaches it only through the wrappers.
				continue
			}
			caller := fd.Name.Name
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.Ident:
					if x.Name == "ErrMutationAuditUnavailable" {
						queue = append(queue, caller)
					}
				case *ast.CallExpr:
					var callee string
					switch fn := x.Fun.(type) {
					case *ast.Ident:
						callee = fn.Name
					case *ast.SelectorExpr:
						// Only a call on the core receiver itself (c.M): tx.M and
						// c.storage.M are storage calls that merely share a name.
						if id, ok := fn.X.(*ast.Ident); ok && recvName != "" && id.Name == recvName {
							callee = fn.Sel.Name
						}
					}
					if callee != "" {
						if callers[callee] == nil {
							callers[callee] = map[string]bool{}
						}
						callers[callee][caller] = true
					}
				}
				return true
			})
		}
	}
	reach := map[string]bool{}
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

func TestAuditUnavailableReachingMethodsFileIsCurrent(t *testing.T) {
	paths, err := srcpath.CoreFamilyGoFiles()
	if err != nil {
		t.Fatal(err)
	}
	got := deriveAuditUnavailableReachingMethods(t, paths)
	// Population tripwire: the audited grant entry points must be found, or the
	// derivation is broken (an empty set would pass every transport guard).
	for _, must := range []string{"AssignUserRole", "AddProjectMember", "SetUserRoles", "ActivateBreakGlass"} {
		if !slices.Contains(got, must) {
			t.Fatalf("derivation lost %s (got %d methods): the call-graph scan is broken", must, len(got))
		}
	}
	want := strings.Join(got, "\n") + "\n"
	if os.Getenv("KEYORIX_UPDATE_AUDIT_UNAVAILABLE_REACH") == "1" {
		if err := os.WriteFile(auditUnavailableReachFile, []byte(want), 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	have, err := os.ReadFile(auditUnavailableReachFile)
	if err != nil {
		t.Fatalf("%v: regenerate with KEYORIX_UPDATE_AUDIT_UNAVAILABLE_REACH=1", err)
	}
	if string(have) != want {
		t.Fatalf("%s is stale: the set of exported core methods that can return ErrMutationAuditUnavailable "+
			"changed. Regenerate with KEYORIX_UPDATE_AUDIT_UNAVAILABLE_REACH=1 go test ./internal/core -run %s, "+
			"then make every transport handler calling a new method map the refusal (the transport guards will name them).",
			auditUnavailableReachFile, t.Name())
	}
}

// TestAuditUnavailableReachFollowsCoreFamily: a method in a package added to the
// core family that reaches the sentinel is derived like one in internal/core.
func TestAuditUnavailableReachFollowsCoreFamily(t *testing.T) {
	dir := t.TempDir()
	src := "package leaf\nfunc (c *KeyorixCore) MovedGrant(ctx context.Context) error {\n\treturn c.withAuditedMutation(ctx, nil)\n}\n"
	if err := os.WriteFile(filepath.Join(dir, "leaf.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	srcpath.AddCoreFamilyDirForTesting(t, dir)
	paths, err := srcpath.CoreFamilyGoFiles()
	if err != nil {
		t.Fatal(err)
	}
	if got := deriveAuditUnavailableReachingMethods(t, paths); !slices.Contains(got, "MovedGrant") {
		t.Fatalf("a sentinel-reaching method in a core family dir outside internal/core was not derived: %v", got)
	}
}
