package core

// grant_ceiling_reach_registry_test.go — #3979: which exported core methods can
// refuse with the grant ceiling (ErrPermissionDenied, "cannot grant this role")?
//
// A transport handler that calls one must answer the refusal 403, not fall
// through to its generic 500 (POST /user-roles did, while group assign answered
// 403). The set is DERIVED, not hand-listed, and written to
// testdata/grant_ceiling_reaching_methods.txt; the HTTP guard
// (server/http/handlers/grant_ceiling_mapping_guard_test.go) reads it.
// Regenerate with
//
//	KEYORIX_UPDATE_GRANT_CEILING_REACH=1 go test ./internal/core -run TestGrantCeilingReachingMethodsFileIsCurrent
//
// Roots: every function or method whose body contains a string literal with
// grantCeilingPhrase (TestEveryGrantCeilingRefusalIsTyped makes each such literal
// a typed ErrPermissionDenied refusal), so a new sibling ceiling is a root without
// anyone listing it. The walk is deriveCoreMethodsReaching
// (audit_unavailable_reach_registry_test.go), with the same call forms followed,
// the same blind spots, and the same harmless over-approximation by name. A
// ceiling refused with other wording is not a root.

import (
	"go/ast"
	"go/token"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/guardrules"
	"github.com/keyorixhq/keyorix/internal/testutil/srcpath"
)

const grantCeilingReachFile = "testdata/grant_ceiling_reaching_methods.txt"

func deriveGrantCeilingReachingMethods(t *testing.T, paths []string) []string {
	t.Helper()
	return deriveCoreMethodsReaching(t, paths, nil, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		return ok && lit.Kind == token.STRING && strings.Contains(lit.Value, grantCeilingPhrase)
	})
}

// TestGrantCeilingReachingMethodsFileIsCurrent reports a stale or missing file
// through guardrules.Rollout (docs/guard-rollout-contract.md rule 2); the
// population tripwire stays blocking.
func TestGrantCeilingReachingMethodsFileIsCurrent(t *testing.T) {
	g := guardrules.Rollout(t)
	paths, err := srcpath.CoreFamilyGoFiles()
	if err != nil {
		t.Fatal(err)
	}
	got := deriveGrantCeilingReachingMethods(t, paths)
	// Population tripwire: the grant entry points must be found, or the derivation
	// is broken (an empty set would pass the transport guard).
	for _, must := range []string{"AssignUserRole", "AssignUserRoleWithExpiry", "AssignRoleToGroup", "AssignMachineRole", "AddProjectMember"} {
		if !slices.Contains(got, must) {
			t.Fatalf("derivation lost %s (got %d methods): the call-graph scan is broken", must, len(got))
		}
	}
	want := strings.Join(got, "\n") + "\n"
	if os.Getenv("KEYORIX_UPDATE_GRANT_CEILING_REACH") == "1" {
		if err := os.WriteFile(grantCeilingReachFile, []byte(want), 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	have, err := os.ReadFile(grantCeilingReachFile)
	if err != nil {
		g.Fatalf("%v: regenerate with KEYORIX_UPDATE_GRANT_CEILING_REACH=1", err)
	}
	if string(have) != want {
		g.Errorf("%s is stale: the set of exported core methods that can refuse with the grant ceiling changed. "+
			"Regenerate with KEYORIX_UPDATE_GRANT_CEILING_REACH=1 go test ./internal/core -run %s, then make every "+
			"HTTP handler calling a new method answer core.ErrPermissionDenied 403 (the handler guard names them).",
			grantCeilingReachFile, t.Name())
	}
}
