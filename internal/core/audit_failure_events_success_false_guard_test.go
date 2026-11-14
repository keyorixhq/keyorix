// audit_failure_events_success_false_guard_test.go — #3363 (AUTH-2 item 5):
// an audit event whose NAME says it records a failure must be stored with
// Success=false. mfa.failed and webauthn.failed were written through
// writeAuditEventFull, which always stores Success=true, so a wrong TOTP code or
// a failed passkey assertion was invisible to every success=false query (SIEM
// rules, exports, the dashboard counters).
//
// The guard parses this package's non-test sources and finds every call that
// writes through a SUCCESS writer: writeAuditEvent, writeAuditEventFull(On),
// writeAuditEventDiff(On), plus any function that forwards one of its own
// parameters as such a writer's event type (found to a fixpoint, so a wrapper
// like auditProjectScoped counts). For each call whose event type is a string
// literal or a package-level string constant, a name ending in one of
// failureEventSuffixes fails the test unless the call site is listed in
// failureNamedSuccessEvents with a reason.
//
// What it does NOT see, by construction: an event type built at run time (a
// variable or a fmt call — reported in the log with a count, so a drop to zero
// matches is visible), an AuditEvent literal handed straight to emitAudit, and
// writers outside internal/core.
package core

import (
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/testutil/srcpath"
)

// failureEventName: the last segment of an event name (after the final '.'
// or '_') that means "this records a failure".
var failureEventName = regexp.MustCompile(`[._](failed|error|denied|refused|rejected|panicked|unresolved)$`)

// failureNamedSuccessEvents: "<enclosing func>:<event type>" written with
// Success=true on purpose. Keep the reason honest.
var failureNamedSuccessEvents = map[string]string{
	"RejectAccessRequest:access_request.rejected": "records an approver's successful decision to reject a request; the action itself succeeded",
}

// successAuditWriters maps a success writer to the index of its event-type
// argument.
var successAuditWriters = map[string]int{
	"writeAuditEvent":       1,
	"writeAuditEventFull":   1,
	"writeAuditEventFullOn": 2,
	"writeAuditEventDiff":   1,
	"writeAuditEventDiffOn": 2,
}

// failureScan is what scanFailureNamedSuccessEvents found in a set of parsed
// sources.
type failureScan struct {
	violations []string
	matched    int // success-writer calls whose event type resolved to a string
	unresolved int // success-writer calls whose event type is built at run time
	writers    int // success writers incl. wrappers
	seen       map[string]bool
}

// scanFailureNamedSuccessEvents is the guard's whole rule, separated from the
// file discovery so the calibration test can run it on synthetic sources: a
// guard nobody has watched go red is not a guard.
func scanFailureNamedSuccessEvents(fset *token.FileSet, files []*ast.File, allowed map[string]string) failureScan {
	consts := map[string]string{}
	for _, f := range files {
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, spec := range gd.Specs {
				vs := spec.(*ast.ValueSpec)
				for i, name := range vs.Names {
					if i < len(vs.Values) {
						if lit, ok := vs.Values[i].(*ast.BasicLit); ok && lit.Kind == token.STRING {
							if v, err := strconv.Unquote(lit.Value); err == nil {
								consts[name.Name] = v
							}
						}
					}
				}
			}
		}
	}

	calleeName := func(call *ast.CallExpr) string {
		switch fun := call.Fun.(type) {
		case *ast.SelectorExpr:
			return fun.Sel.Name
		case *ast.Ident:
			return fun.Name
		}
		return ""
	}

	// Wrappers: a function that passes one of its own parameters as a success
	// writer's event type is itself a success writer, at that parameter's index.
	writers := maps.Clone(successAuditWriters)
	for changed := true; changed; {
		changed = false
		for _, f := range files {
			for _, decl := range f.Decls {
				fd, ok := decl.(*ast.FuncDecl)
				if !ok || fd.Body == nil {
					continue
				}
				if _, known := writers[fd.Name.Name]; known {
					continue
				}
				params := map[string]int{}
				idx := 0
				for _, field := range fd.Type.Params.List {
					for _, n := range field.Names {
						params[n.Name] = idx
						idx++
					}
				}
				ast.Inspect(fd.Body, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					argIdx, ok := writers[calleeName(call)]
					if !ok || argIdx >= len(call.Args) {
						return true
					}
					if id, ok := call.Args[argIdx].(*ast.Ident); ok {
						if pi, isParam := params[id.Name]; isParam {
							writers[fd.Name.Name] = pi
							changed = true
							return false
						}
					}
					return true
				})
			}
		}
	}

	out := failureScan{seen: map[string]bool{}, writers: len(writers)}
	for _, f := range files {
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				argIdx, ok := writers[calleeName(call)]
				if !ok || argIdx >= len(call.Args) {
					return true
				}
				var event string
				switch a := call.Args[argIdx].(type) {
				case *ast.BasicLit:
					if a.Kind == token.STRING {
						event, _ = strconv.Unquote(a.Value)
					}
				case *ast.Ident:
					event = consts[a.Name]
				}
				if event == "" {
					out.unresolved++
					return true
				}
				out.matched++
				if !failureEventName.MatchString(event) {
					return true
				}
				key := fd.Name.Name + ":" + event
				if _, ok := allowed[key]; ok {
					out.seen[key] = true
					return true
				}
				out.violations = append(out.violations, fset.Position(call.Pos()).String()+" "+key+" (via "+calleeName(call)+")")
				return true
			})
		}
	}
	sort.Strings(out.violations)
	return out
}

func TestFailureNamedAuditEvents_AreWrittenWithSuccessFalse(t *testing.T) {
	t.Parallel()
	paths, err := srcpath.CoreFamilyGoFiles()
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var files []*ast.File
	for _, path := range paths {
		src, err := os.ReadFile(path) // #nosec G304 -- core family source file from srcpath.CoreFamilyGoFiles
		if err != nil {
			t.Fatal(err)
		}
		f, err := parser.ParseFile(fset, path, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, f)
	}
	if len(files) < 50 {
		t.Fatalf("parsed only %d source files: the glob no longer finds this package", len(files))
	}

	res := scanFailureNamedSuccessEvents(fset, files, failureNamedSuccessEvents)
	t.Logf("success-writer calls: %d with a resolvable event type, %d built at run time (not checked); %d writers incl. wrappers", res.matched, res.unresolved, res.writers)
	if res.matched < 100 {
		t.Fatalf("resolved only %d success-writer calls: the scan no longer matches how audit events are written, so it would pass vacuously", res.matched)
	}
	for _, v := range res.violations {
		t.Errorf("failure-named audit event written with Success=true: %s -- use writeAuditEventFailed (Success=false), or list the site in failureNamedSuccessEvents with a reason", v)
	}
	for key := range failureNamedSuccessEvents {
		if !res.seen[key] {
			t.Errorf("stale failureNamedSuccessEvents entry %s: no such call site any more", key)
		}
	}
}

// TestFailureNamedAuditEvents_Calibration runs the guard's rule on synthetic
// sources so it cannot go vacuous (AUDIT-FIDELITY-NOV-1 leftover): a violating
// source must be red, a clean one green, and the two ways the scan could
// silently match nothing -- an allowlisted site and a wrapper found to a
// fixpoint -- must behave as the guard's doc says.
func TestFailureNamedAuditEvents_Calibration(t *testing.T) {
	t.Parallel()
	scan := func(t *testing.T, allowed map[string]string, srcs ...string) failureScan {
		t.Helper()
		fset := token.NewFileSet()
		var files []*ast.File
		for i, src := range srcs {
			f, err := parser.ParseFile(fset, "synthetic"+strconv.Itoa(i)+".go", src, 0)
			if err != nil {
				t.Fatal(err)
			}
			files = append(files, f)
		}
		return scanFailureNamedSuccessEvents(fset, files, allowed)
	}

	t.Run("literal failure event through a success writer is red", func(t *testing.T) {
		t.Parallel()
		res := scan(t, nil, `package p
func Login() { writeAuditEvent(ctx, "login.failed") }`)
		if len(res.violations) != 1 {
			t.Fatalf("want exactly 1 violation, got %v", res.violations)
		}
		if !strings.Contains(res.violations[0], "Login:login.failed") {
			t.Fatalf("violation does not name the site: %v", res.violations)
		}
	})

	t.Run("package constant failure event is red", func(t *testing.T) {
		t.Parallel()
		res := scan(t, nil, `package p
const EventMFAFailed = "mfa.failed"
func Verify() { writeAuditEventFull(ctx, EventMFAFailed) }`)
		if len(res.violations) != 1 {
			t.Fatalf("want exactly 1 violation, got %v", res.violations)
		}
	})

	t.Run("failure event through a wrapper is red", func(t *testing.T) {
		t.Parallel()
		res := scan(t, nil, `package p
func scoped(ctx, eventType string) { writeAuditEventFull(ctx, eventType) }
func Deny() { scoped(ctx, "access.denied") }`)
		if len(res.violations) != 1 {
			t.Fatalf("a wrapper forwarding its event-type parameter must count as a success writer; got %v", res.violations)
		}
	})

	t.Run("clean source is green and is counted", func(t *testing.T) {
		t.Parallel()
		res := scan(t, nil, `package p
func Create() { writeAuditEvent(ctx, "secret.created") }
func Fail() { writeAuditEventFailed(ctx, "login.failed") }`)
		if len(res.violations) != 0 {
			t.Fatalf("clean source reported violations: %v", res.violations)
		}
		if res.matched != 1 {
			t.Fatalf("the clean success-writer call must be counted, got matched=%d", res.matched)
		}
	})

	t.Run("allowlisted site is green and marked seen", func(t *testing.T) {
		t.Parallel()
		res := scan(t, map[string]string{"Reject:request.rejected": "decision succeeded"}, `package p
func Reject() { writeAuditEvent(ctx, "request.rejected") }`)
		if len(res.violations) != 0 {
			t.Fatalf("allowlisted site reported: %v", res.violations)
		}
		if !res.seen["Reject:request.rejected"] {
			t.Fatal("an allowlisted site that exists must be marked seen, or the stale-entry check fires on a live entry")
		}
	})

	t.Run("allowlist entry with no call site is not seen", func(t *testing.T) {
		t.Parallel()
		res := scan(t, map[string]string{"Gone:old.failed": "x"}, `package p
func Create() { writeAuditEvent(ctx, "secret.created") }`)
		if res.seen["Gone:old.failed"] {
			t.Fatal("a stale allowlist entry must stay unseen so the guard reports it")
		}
	})

	t.Run("run-time event type is reported unresolved, not matched", func(t *testing.T) {
		t.Parallel()
		res := scan(t, nil, `package p
func Dyn(name string) { writeAuditEvent(ctx, "x."+name) }`)
		if res.matched != 0 || res.unresolved != 1 {
			t.Fatalf("matched=%d unresolved=%d, want 0 and 1", res.matched, res.unresolved)
		}
	})
}
