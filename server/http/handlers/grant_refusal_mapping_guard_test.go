package handlers

// grant_refusal_mapping_guard_test.go — FIX-ERRMAP-STRUCT-1 item 4 (#3979): every REST
// handler that calls a GRANTING core method (one that enforces a grant ceiling:
// requireGranterHoldsRolePermissions and its siblings, derived by
// guardrules.GrantCeilingMethods from internal/core) maps core.ErrPermissionDenied to
// 403, so a ceiling refusal is never a 500. #3950/#3965 fixed AssignRoleToGroup alone
// and left POST /user-roles on its `default: 500`; this is the guard that fix lacked.
// The gRPC twin is server/grpc/services/grant_refusal_mapping_guard_test.go, over the
// same derived set.
//
// What it recognises (the contract; anything else is invisible to it):
//   - Population: a non-test Go file of this package and handlerFamilySubdirs; a
//     top-level function or method whose body calls `X.coreService.M(...)` with M in
//     the derived set.
//   - Mapped: the enclosing function, or a one-hop helper it calls (a package-level
//     function, or a method on the enclosing receiver, whose own body is mapped),
//     calls one of grantRefusalMappers (the shared classifier adapter or a
//     mapper that classifies ErrPermissionDenied), or evaluates
//     `errors.Is(_, core.ErrPermissionDenied)` / `isPermissionRefusal(_)`.
//   - Not followed: two hops, another receiver's method, a helper passed as a value,
//     a refusal check written against a different sentinel.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/guardrules"
)

// grantRefusalMappers are the calls that answer core.ErrPermissionDenied with 403.
var grantRefusalMappers = map[string]bool{
	"answerCoreError":          true, // the shared classifier adapter (server/errclass)
	"sendMachineRefusal":       true, // classifier-backed text layer of the machine routes
	"isPermissionRefusal":      true,
	"sendPolicyRefusal":        true,
	"refuseWithAuthorizeError": true,
	"sendMFAResetError":        true,
}

// grantRefusalMappingExempt names handlers ("file.go:Func") that call a granting
// method without mapping the refusal, each for a stated reason.
var grantRefusalMappingExempt = map[string]string{
	// The ceiling-refusal-403 change for these files belongs to AUTHZDIFF-TAILS-1 /
	// REFRESH-FAULT-TAILS-1 (in flight on 2026-11-13); FIX-ERRMAP-STRUCT-1 does not edit
	// them (coordinator's instruction). Delete these rows when that PR merges: the guard
	// then fails if its mapping ever drifts back (the finding of #3979).
	"rbac.go:AssignRole":                    "POST /user-roles still answers the ceiling refusal 500 (#3979); owned by AUTHZDIFF-TAILS-1",
	"catalog.go:RestoreProject":             "reinstating a project's grants checks the actor's authority (#161); 403 mapping owned by AUTHZDIFF-TAILS-1",
	"catalog.go:RestoreEnvironment":         "same ceiling as RestoreProject; owned by AUTHZDIFF-TAILS-1",
	"invitations.go:CreateInvitation":       "invite ceiling refusal mapping owned by AUTHZDIFF-TAILS-1",
	"invitations.go:CreateGlobalInvitation": "invite ceiling refusal mapping owned by AUTHZDIFF-TAILS-1",
	"invitations.go:ResolveAccessRequest":   "approval ceiling refusal mapping owned by AUTHZDIFF-TAILS-1",
}

// grantRefusalMapped reports whether call is a mapper call or an
// errors.Is(_, core.ErrPermissionDenied) evaluation.
func grantRefusalMapped(call *ast.CallExpr, funcHelpers map[string]bool, recvName, recvType string, methodHelpers map[string]bool) bool {
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		return grantRefusalMappers[fn.Name] || funcHelpers[fn.Name]
	case *ast.SelectorExpr:
		if id, ok := fn.X.(*ast.Ident); ok {
			if id.Name == "errors" && fn.Sel.Name == "Is" {
				for _, a := range call.Args {
					if sel, ok := a.(*ast.SelectorExpr); ok && sel.Sel.Name == "ErrPermissionDenied" {
						return true
					}
				}
			}
			if recvName != "" && id.Name == recvName && methodHelpers[recvType+"."+fn.Sel.Name] {
				return true
			}
		}
	}
	return false
}

func grantRefusalScan(fd *ast.FuncDecl, granting, funcHelpers, methodHelpers map[string]bool) (calls []string, mapped bool) {
	recvName, recvType := "", receiverTypeName(fd)
	if recvType != "" && len(fd.Recv.List[0].Names) == 1 {
		recvName = fd.Recv.List[0].Names[0].Name
	}
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
			if recv, ok := sel.X.(*ast.SelectorExpr); ok && recv.Sel.Name == "coreService" && granting[sel.Sel.Name] {
				calls = append(calls, sel.Sel.Name)
			}
		}
		if grantRefusalMapped(call, funcHelpers, recvName, recvType, methodHelpers) {
			mapped = true
		}
		return true
	})
	return calls, mapped
}

// grantRefusalMappingViolations returns, for the Go files in dir, each "file:func -> M"
// whose function calls a granting method M without mapping the refusal (directly or
// through a one-hop helper), and how many granting calls it saw.
func grantRefusalMappingViolations(t *testing.T, dir string, granting map[string]bool, exempt map[string]string) (violations []string, seen int) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	type parsed struct {
		name string
		file *ast.File
	}
	var files []parsed
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, parsed{name, f})
	}
	funcHelpers := map[string]bool{}
	methodHelpers := map[string]bool{}
	for _, pf := range files {
		for _, d := range pf.file.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			if _, mapped := grantRefusalScan(fd, granting, nil, nil); !mapped {
				continue
			}
			if recvType := receiverTypeName(fd); recvType != "" {
				methodHelpers[recvType+"."+fd.Name.Name] = true
			} else if fd.Recv == nil {
				funcHelpers[fd.Name.Name] = true
			}
		}
	}
	for _, pf := range files {
		for _, d := range pf.file.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			calls, mapped := grantRefusalScan(fd, granting, funcHelpers, methodHelpers)
			seen += len(calls)
			if len(calls) == 0 || mapped {
				continue
			}
			if _, ok := exempt[pf.name+":"+fd.Name.Name]; ok {
				continue
			}
			violations = append(violations, pf.name+":"+fd.Name.Name+" -> "+strings.Join(calls, ","))
		}
	}
	slices.Sort(violations)
	return violations, seen
}

func grantingMethodSet(t *testing.T) map[string]bool {
	t.Helper()
	names, err := guardrules.GrantCeilingMethods(filepath.Join("..", "..", "..", "internal", "core"))
	if err != nil {
		t.Fatal(err)
	}
	set := map[string]bool{}
	for _, n := range names {
		set[n] = true
	}
	if len(set) < 8 {
		t.Fatalf("derived only %d granting methods: the derivation is broken (%v)", len(set), names)
	}
	return set
}

// TestEveryGrantingHandlerMapsPermissionDenied reports through guardrules.Rollout:
// report-only on pull requests while docs/guard-rollout.d/<this test>.tsv exists.
// The population tripwire stays blocking.
func TestEveryGrantingHandlerMapsPermissionDenied(t *testing.T) {
	g := guardrules.Rollout(t)
	granting := grantingMethodSet(t)
	var violations []string
	seen := 0
	for _, dir := range append([]string{"."}, handlerFamilySubdirs...) {
		v, n := grantRefusalMappingViolations(t, dir, granting, grantRefusalMappingExempt)
		for _, x := range v {
			violations = append(violations, filepath.ToSlash(filepath.Join(dir, x)))
		}
		seen += n
	}
	if seen < 8 {
		t.Fatalf("saw only %d coreService calls of a granting method: the scan is broken", seen)
	}
	if len(violations) > 0 {
		g.Errorf("these handlers call a granting core method without mapping core.ErrPermissionDenied to 403 "+
			"(a grant-ceiling refusal would be a 500): route the error through answerCoreError, or add a "+
			"reasoned exemption to grantRefusalMappingExempt:\n  %s", strings.Join(violations, "\n  "))
	}
}

// TestGrantRefusalMappingGuardCalibration: a handler with no mapping is reported; one
// using the adapter, one evaluating errors.Is on the sentinel, one routed through a
// mapped helper, and an exempted one are not; a helper that does not map, two hops
// and another receiver's helper still fail.
func TestGrantRefusalMappingGuardCalibration(t *testing.T) {
	dir := t.TempDir()
	src := `package handlers
func (h *H) Bad(w W, r R)      { if err := h.coreService.AssignUserRole(); err != nil { sendError(w) } }
func (h *H) Adapter(w W, r R)  { if err := h.coreService.AssignUserRole(); err != nil { answerCoreError(w, r, err, coreErrorAnswer{}) } }
func (h *H) Sentinel(w W, r R) { if err := h.coreService.AssignUserRole(); err != nil { if errors.Is(err, core.ErrPermissionDenied) { sendError(w) } } }
func (h *H) ViaHelper(w W, r R) { if err := h.coreService.AssignUserRole(); err != nil { sendGrant(w, err) } }
func (h *H) ViaMethod(w W, r R) { if err := h.coreService.AssignUserRole(); err != nil { h.reply(w, err) } }
func (h *H) ViaUnmapped(w W, r R) { if err := h.coreService.AssignUserRole(); err != nil { sendPlain(w, err) } }
func (h *H) ViaTwoHops(w W, r R)  { if err := h.coreService.AssignUserRole(); err != nil { sendTwo(w, err) } }
func (h *H) ViaOther(w W, r R, o *O) { if err := h.coreService.AssignUserRole(); err != nil { o.reply(w, err) } }
func (h *H) Skip(w W, r R)     { _ = h.coreService.AssignUserRole() }
func (h *H) NotGranting(w W, r R) { if err := h.coreService.GetProject(); err != nil { sendError(w) } }
func sendGrant(w W, err error) { if isPermissionRefusal(err) { sendError(w) } }
func sendPlain(w W, err error) { sendError(w) }
func sendTwo(w W, err error)   { sendGrant(w, err) }
func (h *H) reply(w W, err error) { answerCoreError(w, nil, err, coreErrorAnswer{}) }
func (o *O) reply(w W, err error) { answerCoreError(w, nil, err, coreErrorAnswer{}) }
`
	if err := os.WriteFile(filepath.Join(dir, "synthetic.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	violations, seen := grantRefusalMappingViolations(t, dir, map[string]bool{"AssignUserRole": true}, map[string]string{"synthetic.go:Skip": "test"})
	want := []string{
		"synthetic.go:Bad -> AssignUserRole",
		"synthetic.go:ViaOther -> AssignUserRole",
		"synthetic.go:ViaTwoHops -> AssignUserRole",
		"synthetic.go:ViaUnmapped -> AssignUserRole",
	}
	if seen != 9 || !slices.Equal(violations, want) {
		t.Fatalf("calibration: seen=%d violations=%v, want 9 and exactly %v", seen, violations, want)
	}
}
