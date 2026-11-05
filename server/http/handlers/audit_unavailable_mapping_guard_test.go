package handlers

// audit_unavailable_mapping_guard_test.go — AUDIT-503-MAP-1: every HTTP handler
// that calls a core method able to return core.ErrMutationAuditUnavailable maps
// it (sendAuditUnavailable: 503, Retry-After, code audit_unavailable) instead of
// letting a retryable audit-log outage fall through to the handler's generic 500.
//
// The method set is DERIVED in internal/core
// (audit_unavailable_reach_registry_test.go) and read here from its testdata file,
// so a new audited mutation shows up without anyone remembering to list it.
//
// What it recognises: a call `X.coreService.M(...)` (every handler reaches core
// through a coreService field) with M in the derived set, inside a top-level
// function or method; the enclosing function must call sendAuditUnavailable (or
// a mapper in auditUnavailableMappers), or hand the error to a one-hop helper.
// A one-hop helper is a function or method of the same directory (package)
// whose own body calls a mapper directly. Call forms followed: `helper(...)` to
// a package-level function, and `h.helper(...)` where h is the enclosing
// method's own receiver and helper is a method of that receiver type (also
// inside defer/go statements and closures within the handler). Call forms NOT
// followed: a helper that only reaches a mapper through a second helper (two
// hops), a helper in another package, a call through a function value, field
// or interface, `x.helper(...)` on anything but the enclosing receiver, and a
// helper passed as an argument. Those handlers need the mapper call itself or a
// reasoned exemption. A helper counts if it calls a mapper anywhere in its body
// (it is not checked that the call is on the error path or that the handler
// passes it the error). The derivation over-approximates by name, so a listed
// handler may map an outage its core call can never return; that is harmless.

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

const auditUnavailableReachingMethodsFile = "../../../internal/core/testdata/audit_unavailable_reaching_methods.txt"

var auditUnavailableMappers = map[string]bool{"sendAuditUnavailable": true}

// auditUnavailableMappingExempt names handlers ("file.go:Func") that call a
// reaching method without mapping the outage, each for a stated reason.
var auditUnavailableMappingExempt = map[string]string{
	"auth.go:ConsumeSetup": "unauthenticated setup-link endpoint: every refusal is the same generic 400 by design " +
		"(no internal-error oracle); setup handlers are owned by FIX-3277",
	"auth.go:UpdateProfile":       "auth.go is owned by FIX-3277 while it is in flight; map it there (LEFTOVERS)",
	"sso.go:CompleteSSO":          "login callback: answers with a redirect, not a status; login handlers are owned by FIX-3277",
	"saml.go:CompleteSAML":        "login callback: answers with a redirect, not a status; login handlers are owned by FIX-3277",
	"scim.go:CreateUser":          "SCIM answers in RFC 7644 error bodies; the SCIM handlers are owned by SCIM-TAILS-1",
	"scim.go:PatchUser":           "SCIM answers in RFC 7644 error bodies; the SCIM handlers are owned by SCIM-TAILS-1",
	"scim.go:ReplaceUser":         "SCIM answers in RFC 7644 error bodies; the SCIM handlers are owned by SCIM-TAILS-1",
	"scim_groups.go:CreateGroup":  "SCIM answers in RFC 7644 error bodies; the SCIM handlers are owned by SCIM-TAILS-1",
	"scim_groups.go:PatchGroup":   "SCIM answers in RFC 7644 error bodies; the SCIM handlers are owned by SCIM-TAILS-1",
	"scim_groups.go:ReplaceGroup": "SCIM answers in RFC 7644 error bodies; the SCIM handlers are owned by SCIM-TAILS-1",
	// MSG-ACCURACY-1 (#3912): core.BulkDeleteSecrets never returns the sentinel as a request
	// error; bulkDeleteFailureMessage turns it into a per-item entry with
	// core.MutationAuditUnavailableMessage. This handler passes an untagged r.Context(), so
	// today DeleteSecret writes no audit row in its transaction and the sentinel cannot
	// arise here (the post-commit audit is best effort; INV-CORE-secret-mutation-audit-same-tx
	// "Not covered").
	"secrets_bulk_delete.go:BulkDeleteSecrets": "never a request error: core reports it per item in the 200 body; this handler's untagged context does not reach it today",
}

func readAuditUnavailableReachingMethods(t *testing.T) map[string]bool {
	t.Helper()
	b, err := os.ReadFile(auditUnavailableReachingMethodsFile)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for line := range strings.SplitSeq(strings.TrimSpace(string(b)), "\n") {
		out[strings.TrimSpace(line)] = true
	}
	if len(out) < 10 {
		t.Fatalf("%s lists %d methods: the derivation is broken", auditUnavailableReachingMethodsFile, len(out))
	}
	return out
}

// receiverTypeName returns the receiver's type name ("H" for *H or H), or ""
// for a plain function or an unnamed/unusual receiver.
func receiverTypeName(fd *ast.FuncDecl) string {
	if fd.Recv == nil || len(fd.Recv.List) != 1 {
		return ""
	}
	t := fd.Recv.List[0].Type
	if star, ok := t.(*ast.StarExpr); ok {
		t = star.X
	}
	if id, ok := t.(*ast.Ident); ok {
		return id.Name
	}
	return ""
}

// auditUnavailableScan walks fd's body and returns the reaching coreService
// calls it makes and whether it calls a mapper directly or (given non-nil
// helper sets) a one-hop helper in funcHelpers / methodHelpers.
func auditUnavailableScan(fd *ast.FuncDecl, reaching, funcHelpers, methodHelpers map[string]bool) (calls []string, mapped bool) {
	recvName, recvType := "", receiverTypeName(fd)
	if recvType != "" && len(fd.Recv.List[0].Names) == 1 {
		recvName = fd.Recv.List[0].Names[0].Name
	}
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch fn := call.Fun.(type) {
		case *ast.Ident:
			if auditUnavailableMappers[fn.Name] || funcHelpers[fn.Name] {
				mapped = true
			}
		case *ast.SelectorExpr:
			if recv, ok := fn.X.(*ast.SelectorExpr); ok && recv.Sel.Name == "coreService" && reaching[fn.Sel.Name] {
				calls = append(calls, fn.Sel.Name)
			}
			if id, ok := fn.X.(*ast.Ident); ok && recvName != "" && id.Name == recvName && methodHelpers[recvType+"."+fn.Sel.Name] {
				mapped = true
			}
		}
		return true
	})
	return calls, mapped
}

// auditUnavailableMappingViolations returns, for the Go source files in dir, each
// "file:func -> M" whose function calls a reaching method M through coreService
// without calling a mapper or a one-hop helper, and how many reaching calls it saw.
func auditUnavailableMappingViolations(t *testing.T, dir string, reaching map[string]bool, exempt map[string]string) (violations []string, seen int) {
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
	// First pass: the one-hop helpers of this directory (see the doc comment).
	funcHelpers := map[string]bool{}
	methodHelpers := map[string]bool{} // "RecvType.name"
	for _, pf := range files {
		for _, d := range pf.file.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			if _, mapped := auditUnavailableScan(fd, reaching, nil, nil); !mapped {
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
			calls, mapped := auditUnavailableScan(fd, reaching, funcHelpers, methodHelpers)
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

// TestEveryAuditUnavailableReachingHandlerMapsTheOutage scans this package and
// every handlerFamilySubdirs subpackage (httpx, reports), so a handler moved out
// of this directory stays covered. It reports its findings through
// guardrules.Rollout: report-only on pull requests while
// docs/guard-rollout.d/TestEveryAuditUnavailableReachingHandlerMapsTheOutage.tsv
// exists (docs/guard-rollout-contract.md rule 2). The population tripwire stays
// blocking.
func TestEveryAuditUnavailableReachingHandlerMapsTheOutage(t *testing.T) {
	g := guardrules.Rollout(t)
	reaching := readAuditUnavailableReachingMethods(t)
	var violations []string
	seen := 0
	for _, dir := range append([]string{"."}, handlerFamilySubdirs...) {
		v, n := auditUnavailableMappingViolations(t, dir, reaching, auditUnavailableMappingExempt)
		for _, x := range v {
			violations = append(violations, filepath.ToSlash(filepath.Join(dir, x)))
		}
		seen += n
	}
	// Population tripwire: the audited mutation handlers themselves must be seen.
	if seen < 30 {
		t.Fatalf("saw only %d coreService calls of a reaching method: the scan is broken", seen)
	}
	if len(violations) > 0 {
		g.Errorf("these handlers call a core method that can return ErrMutationAuditUnavailable without "+
			"mapping it: call sendAuditUnavailable(w, err) first in the error branch (503 + Retry-After), or "+
			"add a reasoned exemption to auditUnavailableMappingExempt:\n  %s", strings.Join(violations, "\n  "))
	}
}

// TestAuditUnavailableMappingGuardCatchesAnUnmappedHandler is the guard's
// self-test: a synthetic handler calling a reaching method with no mapper is
// reported, the same handler with sendAuditUnavailable is not, and an exempted
// one is not.
func TestAuditUnavailableMappingGuardCatchesAnUnmappedHandler(t *testing.T) {
	dir := t.TempDir()
	src := `package handlers
func (h *H) Bad(w W, r R)  { if err := h.coreService.AddProjectMember(); err != nil { sendError(w) } }
func (h *H) Good(w W, r R) { if err := h.coreService.AddProjectMember(); err != nil { if sendAuditUnavailable(w, err) { return } } }
func (h *H) Skip(w W, r R) { _ = h.coreService.AddProjectMember() }
`
	if err := os.WriteFile(filepath.Join(dir, "synthetic.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	violations, seen := auditUnavailableMappingViolations(t, dir, map[string]bool{"AddProjectMember": true}, map[string]string{"synthetic.go:Skip": "test"})
	if seen != 3 || !slices.Equal(violations, []string{"synthetic.go:Bad -> AddProjectMember"}) {
		t.Fatalf("self-test: seen=%d violations=%v, want 3 and exactly the Bad handler", seen, violations)
	}
}

// TestAuditUnavailableMappingGuardFollowsOneHopHelpers is the calibration of the
// helper hop: a handler routed through a helper that calls the mapper passes
// (green), one routed through a helper that does not map the outage fails (red),
// and the forms the guard documents as not followed (two hops, another
// receiver's method, a helper only named as a value) still fail. A same-name
// method that maps only on a different receiver type also fails, so the
// helper key must include the receiver type, not just the method name.
func TestAuditUnavailableMappingGuardFollowsOneHopHelpers(t *testing.T) {
	dir := t.TempDir()
	helpers := `package handlers
func sendMapped(w W, err error)   { if sendAuditUnavailable(w, err) { return }; sendError(w) }
func sendUnmapped(w W, err error) { sendError(w) }
func sendTwoHops(w W, err error)  { sendMapped(w, err) }
func (h *H) replyMapped(w W, err error)   { if sendAuditUnavailable(w, err) { return } }
func (h *H) replyUnmapped(w W, err error) { sendError(w) }
func (o *Other) replyMapped(w W, err error) { sendAuditUnavailable(w, err) }
func (h *H) replyShared(w W, err error)     { sendAuditUnavailable(w, err) }
func (o *Other) replyShared(w W, err error) { sendError(w) }
`
	handlers := `package handlers
func (h *H) ViaFunc(w W, r R)        { if err := h.coreService.AddProjectMember(); err != nil { sendMapped(w, err) } }
func (h *H) ViaMethod(w W, r R)      { if err := h.coreService.AddProjectMember(); err != nil { h.replyMapped(w, err) } }
func (h *H) ViaDefer(w W, r R)       { err := h.coreService.AddProjectMember(); defer func() { sendMapped(w, err) }() }
func (h *H) ViaUnmappedFunc(w W, r R)   { if err := h.coreService.AddProjectMember(); err != nil { sendUnmapped(w, err) } }
func (h *H) ViaUnmappedMethod(w W, r R) { if err := h.coreService.AddProjectMember(); err != nil { h.replyUnmapped(w, err) } }
func (h *H) ViaTwoHops(w W, r R)        { if err := h.coreService.AddProjectMember(); err != nil { sendTwoHops(w, err) } }
func (h *H) ViaOtherReceiver(w W, r R, o *Other) { if err := h.coreService.AddProjectMember(); err != nil { o.replyMapped(w, err) } }
func (h *H) ViaValue(w W, r R)          { if err := h.coreService.AddProjectMember(); err != nil { fn := sendMapped; _ = fn } }
func (o *Other) NotMine(w W, r R)       { if err := o.coreService.AddProjectMember(); err != nil { o.replyUnmapped(w, err) } }
func (o *Other) ViaSameNameOtherType(w W, r R) { if err := o.coreService.AddProjectMember(); err != nil { o.replyShared(w, err) } }
`
	for name, src := range map[string]string{"helpers.go": helpers, "handlers.go": handlers} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	violations, seen := auditUnavailableMappingViolations(t, dir, map[string]bool{"AddProjectMember": true}, nil)
	want := []string{
		"handlers.go:NotMine -> AddProjectMember",
		"handlers.go:ViaOtherReceiver -> AddProjectMember",
		"handlers.go:ViaSameNameOtherType -> AddProjectMember",
		"handlers.go:ViaTwoHops -> AddProjectMember",
		"handlers.go:ViaUnmappedFunc -> AddProjectMember",
		"handlers.go:ViaUnmappedMethod -> AddProjectMember",
		"handlers.go:ViaValue -> AddProjectMember",
	}
	if seen != 10 || !slices.Equal(violations, want) {
		t.Fatalf("self-test: seen=%d violations=%v, want 10 and exactly %v", seen, violations, want)
	}
}
