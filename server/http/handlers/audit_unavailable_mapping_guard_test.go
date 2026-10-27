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
// a mapper in auditUnavailableMappers). It does not follow the error into a
// helper the handler hands it to; such a handler needs the call itself or a
// reasoned exemption. The derivation over-approximates by name, so a listed
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

// auditUnavailableMappingViolations returns, for the Go source files in dir, each
// "file:func -> M" whose function calls a reaching method M through coreService
// without calling a mapper, and how many reaching calls it saw.
func auditUnavailableMappingViolations(t *testing.T, dir string, reaching map[string]bool, exempt map[string]string) (violations []string, seen int) {
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
					if auditUnavailableMappers[fn.Name] {
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
			if _, ok := exempt[name+":"+fd.Name.Name]; ok {
				continue
			}
			violations = append(violations, name+":"+fd.Name.Name+" -> "+strings.Join(calls, ","))
		}
	}
	slices.Sort(violations)
	return violations, seen
}

// TestEveryAuditUnavailableReachingHandlerMapsTheOutage scans this package and
// every handlerFamilySubdirs subpackage (httpx, reports), so a handler moved out
// of this directory stays covered.
func TestEveryAuditUnavailableReachingHandlerMapsTheOutage(t *testing.T) {
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
		t.Fatalf("these handlers call a core method that can return ErrMutationAuditUnavailable without "+
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
