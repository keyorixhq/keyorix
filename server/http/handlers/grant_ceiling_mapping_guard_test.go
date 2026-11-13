package handlers

// grant_ceiling_mapping_guard_test.go — #3979: every HTTP handler that calls a
// core method able to refuse with the grant ceiling (core.ErrPermissionDenied, "a
// role the actor cannot grant") must classify that refusal, so it is answered 403
// and not the handler's generic 500. POST /user-roles fell through to 500 while
// group assign answered 403, and the hand-listed runtime family
// (TestEveryGrantRouteMapsTheCeilingRefusalTo403) did not list it.
//
// The method set is DERIVED in internal/core (grant_ceiling_reach_registry_test.go)
// and read from its testdata file. The walk is mappingScan / mappingViolations
// (audit_unavailable_mapping_guard_test.go), with the same one-hop helper rule and
// the same call forms followed and not followed. What counts as mapping: the
// function, or a one-hop helper it calls, mentions core.ErrPermissionDenied
// (sendGrantCeilingRefusal, sendMachineRefusal, isPermissionRefusal and inline
// errors.Is all do). It is NOT checked that the mention is on the error path,
// answers 403, or sees the error the core call returned: the runtime family test
// is what proves the status for the routes it drives.

import (
	"go/ast"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/guardrules"
)

const grantCeilingReachingMethodsFile = "../../../internal/core/testdata/grant_ceiling_reaching_methods.txt"

// grantCeilingMappingExempt names handlers ("file.go:Func") that call a granting
// method without classifying the ceiling refusal, each for a stated reason.
var grantCeilingMappingExempt = map[string]string{
	"auth.go:ConsumeSetup": "unauthenticated setup-link endpoint: every refusal is the same generic 400 by design " +
		"(no internal-error oracle); setup handlers are owned by FIX-3277",
	"bulk_access_requests.go:BulkApproveAccessRequests": "never a request error: core reports a refused item " +
		"in the 200 body's failed list (BulkApproveAccessRequests appends approveErr per item)",
	// #4154: these answer the ceiling 500 today. Remove each row when its handler maps it.
	"invitations.go:CreateInvitation":             "#4154: answers the ceiling 500; map it with sendGrantCeilingRefusal",
	"invitations.go:CreateGlobalInvitation":       "#4154: answers the ceiling 500 past its two 403 pre-checks; map it with sendGrantCeilingRefusal",
	"invitations.go:ResolveAccessRequest":         "#4154: answers the ceiling 500; map it with sendGrantCeilingRefusal",
	"project_memberships.go:TransitionMembership": "#4154: answers the ceiling 500; map it with sendGrantCeilingRefusal",
}

// mentionsPermissionDenied is the mapper predicate: a reference to
// core.ErrPermissionDenied.
func mentionsPermissionDenied(n ast.Node) bool {
	sel, ok := n.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "ErrPermissionDenied" {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == "core"
}

func readGrantCeilingReachingMethods(t *testing.T) map[string]bool {
	t.Helper()
	b, err := os.ReadFile(grantCeilingReachingMethodsFile)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for line := range strings.SplitSeq(strings.TrimSpace(string(b)), "\n") {
		out[strings.TrimSpace(line)] = true
	}
	if len(out) < 10 {
		t.Fatalf("%s lists %d methods: the derivation is broken", grantCeilingReachingMethodsFile, len(out))
	}
	return out
}

// TestEveryGrantingHandlerMapsTheCeilingRefusal scans this package and every
// handlerFamilySubdirs subpackage. It reports through guardrules.Rollout
// (docs/guard-rollout-contract.md rule 2); the population tripwire stays blocking.
func TestEveryGrantingHandlerMapsTheCeilingRefusal(t *testing.T) {
	g := guardrules.Rollout(t)
	reaching := readGrantCeilingReachingMethods(t)
	var violations []string
	seen := 0
	for _, dir := range append([]string{"."}, handlerFamilySubdirs...) {
		v, n := mappingViolations(t, dir, reaching, mentionsPermissionDenied, grantCeilingMappingExempt)
		for _, x := range v {
			violations = append(violations, filepath.ToSlash(filepath.Join(dir, x)))
		}
		seen += n
	}
	// Population tripwire: the grant routes themselves must be seen.
	if seen < 10 {
		t.Fatalf("saw only %d coreService calls of a granting method: the scan is broken", seen)
	}
	if len(violations) > 0 {
		g.Errorf("these handlers call a core method that can refuse with the grant ceiling without classifying "+
			"core.ErrPermissionDenied: answer it 403 (sendGrantCeilingRefusal(w, err)) before the generic 500, or "+
			"add a reasoned exemption to grantCeilingMappingExempt:\n  %s", strings.Join(violations, "\n  "))
	}
}

// TestGrantCeilingMappingGuardCalibration: an unmapped handler and one routed
// through a helper that does not classify the refusal are reported; inline
// errors.Is, a helper that does, and an exempted handler are not. This is the
// shape #3979 had: POST /user-roles handed the error to nothing that knew the
// sentinel.
func TestGrantCeilingMappingGuardCalibration(t *testing.T) {
	dir := t.TempDir()
	src := `package handlers
func sendCeiling(w W, err error) bool { if errors.Is(err, core.ErrPermissionDenied) { sendError(w); return true }; return false }
func sendOther(w W, err error) bool   { if errors.Is(err, storage.ErrRoleAlreadyAssigned) { sendError(w); return true }; return false }
func (h *H) Bad(w W, r R)        { if err := h.coreService.AssignUserRole(); err != nil { sendError(w) } }
func (h *H) ViaOther(w W, r R)   { if err := h.coreService.AssignUserRole(); err != nil { if sendOther(w, err) { return }; sendError(w) } }
func (h *H) WrongPkg(w W, r R)   { if err := h.coreService.AssignUserRole(); err != nil { if errors.Is(err, other.ErrPermissionDenied) { return } } }
func (h *H) Inline(w W, r R)     { if err := h.coreService.AssignUserRole(); err != nil { if errors.Is(err, core.ErrPermissionDenied) { return } } }
func (h *H) ViaHelper(w W, r R)  { if err := h.coreService.AssignUserRole(); err != nil { if sendCeiling(w, err) { return } } }
func (h *H) Skip(w W, r R)       { _ = h.coreService.AssignUserRole() }
`
	if err := os.WriteFile(filepath.Join(dir, "synthetic.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	violations, seen := mappingViolations(t, dir, map[string]bool{"AssignUserRole": true}, mentionsPermissionDenied,
		map[string]string{"synthetic.go:Skip": "test"})
	want := []string{
		"synthetic.go:Bad -> AssignUserRole",
		"synthetic.go:ViaOther -> AssignUserRole",
		"synthetic.go:WrongPkg -> AssignUserRole",
	}
	if seen != 6 || !slices.Equal(violations, want) {
		t.Fatalf("calibration: seen=%d violations=%v, want 6 and exactly %v", seen, violations, want)
	}
}
