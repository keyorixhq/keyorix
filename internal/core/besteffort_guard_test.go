// besteffort_guard_test.go — GUARD-1's structural guard (the real deliverable
// of QA-1's "fixed one call site at a time, 12+ times" finding): fails when a
// non-test function in internal/core discards an error or result from a call
// (`_ = f(...)` / `_, _ = f(...)`) that textually follows a storage-write call
// in the same function, UNLESS that discard is itself protected -- wrapped in
// a call to goSafe(...) or besteffort.Run(...), or inside a function whose
// body already defers besteffort.RunRecover(...)() -- or is a reviewed entry
// in docs/besteffort-exempt.tsv.
//
// Same AST-walk, control-flow-blind, human-classifies-the-hit shape as
// atomicity_guard_test.go (an unrecognized hit is either a genuine new
// instance of the bug class QA-1 found 12+ times -- a panic in the discarded
// call can escape past an already-committed write and misreport success as
// failure -- or needs a reviewed exemption entry explaining why the discarded
// call's OWN callee already recovers internally, same as this file's own
// corpus: evictUserSessionCache, deleteSessionsForUserAndEvict,
// notifyBreakGlassAdmins, revokeProjectDynamicSecretLeases,
// seedProjectEnvironment, evictMachineIdentityCacheOrFlush, emitAudit all
// recover their OWN panic already, so a caller discarding their result needs
// no additional protection -- but that protection lives in the callee, not
// visible to this caller-side AST walk, hence the exemption).
//
// A branch on a mutually-exclusive if/else or switch is flagged exactly like
// a true sequential case -- the same caveat atomicity_guard_test.go documents
// for its own write-count scan.
package core

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

var besteffortGuardWriteVerbRe = regexp.MustCompile(`^(Create|Update|Delete|Assign|Unassign|Set|Remove|Add|Revoke|Insert|Upsert|Save|Mark|Record|Increment|Rotate|Restore|Purge|Archive|Grant|Link|Unlink|Replace|Put|Store|Clear|Reset|Enable|Disable|Lock|Unlock|Consume|Approve|Reject|Expire|Touch|Bump|Append|Move|Rename|Transfer|Finalize|Complete|Cancel|Provision|Deprovision|Patch|Activate|Deactivate|Issue|Open|Close|Withdraw)`)

type besteffortDiscardHit struct {
	fn          string
	file        string
	writeLine   int
	writeCall   string
	discardLine int
	discardCall string
}

// scanBestEffortDiscardHits walks every non-test, non-generated *.go file
// directly under root (not subpackages) for a function containing a
// blank-identifier discard statement that textually follows a write-verb
// call in the same function body, and is not lexically protected (see
// besteffortIsProtectedCall / besteffortFuncHasRunRecoverGuard below).
func scanBestEffortDiscardHits(t *testing.T, root string) []besteffortDiscardHit {
	t.Helper()
	var hits []besteffortDiscardHit
	fset := token.NewFileSet()
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("besteffort guard: cannot read %s: %v", root, err)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") || strings.Contains(name, "generated") {
			continue
		}
		p := filepath.Join(root, name)
		f, perr := parser.ParseFile(fset, p, nil, 0)
		if perr != nil {
			t.Fatalf("besteffort guard: cannot parse %s: %v", p, perr)
		}
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			fnName := besteffortFuncLabel(fd)

			if besteffortFuncHasRunRecoverGuard(fd.Body) {
				continue // the whole function recovers any panic in itself
			}

			var lastWrite token.Pos
			var lastWriteName string
			var discards []struct {
				pos  token.Pos
				name string
			}

			var walk func(n ast.Node, protected bool)
			walk = func(n ast.Node, protected bool) {
				ast.Inspect(n, func(m ast.Node) bool {
					call, ok := m.(*ast.CallExpr)
					if ok && besteffortIsProtectingCall(call) {
						for _, a := range call.Args {
							walk(a, true)
						}
						return false
					}
					if assign, ok := m.(*ast.AssignStmt); ok && besteffortIsBlankDiscard(assign) {
						callName := besteffortDiscardCallName(assign)
						if !protected {
							discards = append(discards, struct {
								pos  token.Pos
								name string
							}{pos: assign.Pos(), name: callName})
						}
						return true
					}
					if ok {
						if sel, ok := call.Fun.(*ast.SelectorExpr); ok && besteffortGuardWriteVerbRe.MatchString(sel.Sel.Name) {
							if call.Pos() > lastWrite {
								lastWrite, lastWriteName = call.Pos(), sel.Sel.Name
							}
						}
					}
					return true
				})
			}
			walk(fd.Body, false)

			if lastWrite == 0 {
				continue
			}
			for _, disc := range discards {
				if disc.pos > lastWrite {
					hits = append(hits, besteffortDiscardHit{
						fn: fnName, file: name,
						writeLine: fset.Position(lastWrite).Line, writeCall: lastWriteName,
						discardLine: fset.Position(disc.pos).Line, discardCall: disc.name,
					})
				}
			}
		}
	}
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].fn != hits[j].fn {
			return hits[i].fn < hits[j].fn
		}
		return hits[i].discardLine < hits[j].discardLine
	})
	return hits
}

// besteffortIsProtectingCall reports whether call is goSafe(...) or
// besteffort.Run(...) -- both take a func literal whose body is already
// panic-protected, so a discard inside that literal needs no further
// protection.
func besteffortIsProtectingCall(call *ast.CallExpr) bool {
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		return fn.Name == "goSafe"
	case *ast.SelectorExpr:
		x, ok := fn.X.(*ast.Ident)
		return ok && x.Name == "besteffort" && fn.Sel.Name == "Run"
	}
	return false
}

// besteffortFuncHasRunRecoverGuard reports whether body contains, as a defer
// statement, a call shaped like besteffort.RunRecover("...")() -- the
// function-wide guard shape (used by goSafe's own goroutine body) that
// recovers a panic anywhere later in the same function, not just inside a
// nested closure.
func besteffortFuncHasRunRecoverGuard(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		ds, ok := n.(*ast.DeferStmt)
		if !ok {
			return true
		}
		inner, ok := ds.Call.Fun.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := inner.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		x, ok := sel.X.(*ast.Ident)
		if ok && x.Name == "besteffort" && sel.Sel.Name == "RunRecover" {
			found = true
		}
		return true
	})
	return found
}

// besteffortIsBlankDiscard reports whether assign is `_ = f(...)` or
// `_, _ = f(...)` -- every Lhs identifier is the blank identifier, and the
// Rhs is (at least one) call expression.
func besteffortIsBlankDiscard(assign *ast.AssignStmt) bool {
	if len(assign.Lhs) == 0 || len(assign.Rhs) == 0 {
		return false
	}
	for _, l := range assign.Lhs {
		id, ok := l.(*ast.Ident)
		if !ok || id.Name != "_" {
			return false
		}
	}
	for _, r := range assign.Rhs {
		if _, ok := r.(*ast.CallExpr); !ok {
			return false
		}
	}
	return true
}

func besteffortDiscardCallName(assign *ast.AssignStmt) string {
	call, ok := assign.Rhs[0].(*ast.CallExpr)
	if !ok {
		return "?"
	}
	switch fn := call.Fun.(type) {
	case *ast.SelectorExpr:
		return besteffortExprStr(fn.X) + "." + fn.Sel.Name
	case *ast.Ident:
		return fn.Name
	}
	return "?"
}

func besteffortExprStr(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.StarExpr:
		return "*" + besteffortExprStr(t.X)
	case *ast.Ident:
		return t.Name
	case *ast.SelectorExpr:
		return besteffortExprStr(t.X) + "." + t.Sel.Name
	}
	return "?"
}

func besteffortFuncLabel(fd *ast.FuncDecl) string {
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
		return fd.Name.Name
	}
	return "(" + besteffortExprStr(fd.Recv.List[0].Type) + ")." + fd.Name.Name
}

// besteffortExemptKey is this package's prefix for docs/besteffort-exempt.tsv
// entries -- disambiguates internal/core's "(*KeyorixCore).Foo" from an
// identically-named function in another scanned package.
const besteffortExemptKey = "internal/core"

// loadBestEffortExemptions reads docs/besteffort-exempt.tsv
// ("<package>:<function>\treason", '#'-prefixed and blank lines ignored)
// into the set of function names exempted for THIS package.
func loadBestEffortExemptions(t *testing.T, path, pkgPrefix string) map[string]bool {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("besteffort guard: cannot read %s: %v", path, err)
	}
	out := map[string]bool{}
	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.SplitN(line, "\t", 2)
		if len(fields) < 2 {
			t.Fatalf("besteffort guard: %s:%d: expected 2 tab-separated fields (package:function, reason), got %q", path, i+1, line)
		}
		key := fields[0]
		prefix := pkgPrefix + ":"
		if strings.HasPrefix(key, prefix) {
			out[strings.TrimPrefix(key, prefix)] = true
		}
	}
	return out
}

// TestBestEffortGuard_UnprotectedPostWriteDiscard is GUARD-1's lint guard:
// every internal/core function that discards a call's result/error after a
// storage write, without routing it through goSafe/besteffort.Run (or a
// function-wide besteffort.RunRecover defer), must have a reviewed entry in
// docs/besteffort-exempt.tsv. An unclassified hit is either a genuine
// instance of QA-1's "panic masks an already-committed write" bug class (fix
// it: wrap the discarded call in besteffort.Run), or a call whose OWN callee
// already recovers internally (classify it: add the "internal/core:<fn>"
// entry with a one-line reason).
func TestBestEffortGuard_UnprotectedPostWriteDiscard(t *testing.T) {
	hits := scanBestEffortDiscardHits(t, ".")
	exempt := loadBestEffortExemptions(t, "../../docs/besteffort-exempt.tsv", besteffortExemptKey)

	seenFn := map[string]bool{}
	var unclassified []string
	for _, h := range hits {
		if exempt[h.fn] || seenFn[h.fn] {
			continue
		}
		seenFn[h.fn] = true
		unclassified = append(unclassified, fmt.Sprintf("%s (%s): discard %s@%d follows write %s@%d",
			h.fn, h.file, h.discardCall, h.discardLine, h.writeCall, h.writeLine))
	}
	if len(unclassified) > 0 {
		t.Fatalf("besteffort guard: %d function(s) discard a call's result/error after a storage write, with no "+
			"reviewed \"internal/core:<fn>\" entry in docs/besteffort-exempt.tsv. Either route the discarded call "+
			"through besteffort.Run (see internal/besteffort), or add a reviewed exemption explaining why the "+
			"callee already recovers internally. Unclassified:\n  %s", len(unclassified), strings.Join(unclassified, "\n  "))
	}
}
