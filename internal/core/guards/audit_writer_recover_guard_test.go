package guards

// audit_writer_recover_guard_test.go — INVARIANT-GUARDS-1 observation 4, the family
// guard (INV-CORE-audit-writer-recovers-own-build). emitAudit/emitAuditOn recover a
// panic only once control reaches them; a writer that BUILDS a models.AuditEvent
// first (from ctx, from its own arguments) runs that construction in its own frame,
// where a panic escapes to a caller whose answer is already decided.
// writeAuditEventDiffOn (#2561) and writeAuditEventFailed recover it themselves;
// this pins that every such writer does, or is named below with why not.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"testing"

	"github.com/keyorixhq/keyorix/internal/guardrules"
	"github.com/keyorixhq/keyorix/internal/testutil/srcpath"
)

// auditWriterRecoverExempt: "file.go:Func" functions that build a models.AuditEvent
// literal without recovering in their own frame, each with why that is right. The
// guard fails on a stale entry.
var auditWriterRecoverExempt = map[string]string{
	"audit.go:buildAuditEventOutcome": "pure builder: writeAuditEventDiffOn calls it under its own recover, and " +
		"SuspendSecret (via buildAuditEvent) builds before anything commits, so a panic there fails the suspend " +
		"with nothing written",
	"audit.go:LogSecretReadWithProject": "audit-before-disclosure: the caller must not disclose unless this " +
		"returns nil, so a panic propagating (no value disclosed) is the fail-closed outcome; a recover would " +
		"return nil and disclose with no audit row",
	"audit.go:logSecretMetadataAccess": "audit-before-disclosure, as LogSecretReadWithProject: the caller must " +
		"not send the listing unless this returns nil, and a recover would return nil",
	"impersonation.go:writeImpersonationDeniedEvent": "OPEN: impersonation.go is owned by FIX-3277; review " +
		"(recover or reason) after it lands",
	"impersonation.go:writeImpersonationEvent": "OPEN: impersonation.go is owned by FIX-3277; review " +
		"(recover or reason) after it lands",
}

// TestAuditEventWritersRecoverTheirOwnPanic: every core family function whose own
// frame contains a models.AuditEvent composite literal defers a recover —
// `defer func(){ ... recover() ... }()` without a re-panic, or
// `defer besteffort.RunRecover(...)()` — or is listed in auditWriterRecoverExempt.
//
// Population and blind spots: every non-test .go file of the core family
// (coreFamilySources). Function literals are skipped (a literal's defer protects
// only the literal), so a builder inside a closure is attributed to nobody; an event
// built by a helper outside the family, or as a non-literal (new(models.AuditEvent)
// then field writes), is not seen.
func TestAuditEventWritersRecoverTheirOwnPanic(t *testing.T) {
	g := guardrules.Rollout(t)
	builders := map[string]bool{}
	var unprotected []string
	for _, path := range coreFamilySources(t) {
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		rel := srcpath.CoreFamilyRel(path)
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			builds, recovers := false, false
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				switch v := n.(type) {
				case *ast.FuncLit:
					return false
				case *ast.CompositeLit:
					builds = builds || isModelsAuditEvent(v.Type)
				case *ast.DeferStmt:
					recovers = recovers || deferRecovers(v)
				}
				return true
			})
			if !builds {
				continue
			}
			key := rel + ":" + fd.Name.Name
			builders[key] = true
			if _, ok := auditWriterRecoverExempt[key]; !ok && !recovers {
				unprotected = append(unprotected, key)
			}
		}
	}
	sort.Strings(unprotected)
	for _, key := range unprotected {
		g.Errorf("%s builds a models.AuditEvent in its own frame with no recover: a panic there escapes to a "+
			"caller whose answer is already decided. Add `defer besteffort.RunRecover(\"audit.<name>\")()` "+
			"(logs and counts it) or list the function in auditWriterRecoverExempt with why", key)
	}

	for _, want := range []string{"audit.go:writeAuditEventFailed", "audit.go:buildAuditEventOutcome"} {
		if !builders[want] {
			g.Errorf("%s is no longer seen building an AuditEvent; the guard's population drifted", want)
		}
	}
	var stale []string
	for key := range auditWriterRecoverExempt {
		if !builders[key] {
			stale = append(stale, key)
		}
	}
	sort.Strings(stale)
	for _, key := range stale {
		g.Errorf("auditWriterRecoverExempt entry %q no longer builds an AuditEvent; remove it", key)
	}
}

func isModelsAuditEvent(x ast.Expr) bool {
	sel, ok := x.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "AuditEvent" {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && id.Name == "models"
}

// deferRecovers mirrors internal/besteffortguard's two recognised shapes.
func deferRecovers(ds *ast.DeferStmt) bool {
	if inner, ok := ds.Call.Fun.(*ast.CallExpr); ok {
		if sel, ok := inner.Fun.(*ast.SelectorExpr); ok {
			if x, ok := sel.X.(*ast.Ident); ok && x.Name == "besteffort" && sel.Sel.Name == "RunRecover" {
				return true
			}
		}
	}
	lit, ok := ds.Call.Fun.(*ast.FuncLit)
	if !ok {
		return false
	}
	recovers, rePanics := false, false
	ast.Inspect(lit.Body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if id, ok := call.Fun.(*ast.Ident); ok {
				switch id.Name {
				case "recover":
					recovers = true
				case "panic":
					rePanics = true
				}
			}
		}
		return true
	})
	return recovers && !rePanics
}
