package store

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// remoteUnsupportedStatus categorizes why a RemoteStorage method is
// structurally a stub — it never reaches the network (see
// actualRemoteUnsupportedStubs below for exactly what "structurally" means).
type remoteUnsupportedStatus int

const (
	// statusIntentional means the stub is permanent by design — verified (not
	// assumed) to have no reachable caller under storage.type: remote, to be
	// already superseded by a different mechanism, OR to be deliberately kept
	// despite a reachable caller because implementing it would be the wrong
	// fix (G80 Wave 0c / ADR-086: a client-side authorization primitive whose
	// real fix is hub-side evaluation, not a wire implementation — cite the
	// ADR/issue in Reason). See Reason for the specific citation in every case.
	statusIntentional remoteUnsupportedStatus = iota
	// statusKnownGap means the stub is a confirmed, currently-reachable bug —
	// something breaks under storage.type: remote today. Tracked in
	// docs/security/HARDENING-BACKLOG.md; see Reason for the finding reference.
	//
	// Round 119's entire genuine-gap list is closed as of #531, so no allowlist
	// entry currently uses this value — kept (not deleted) since the NEXT stub a
	// future round finds needs it immediately; deleting and re-adding it every
	// time the count round-trips through zero would just be churn.
	statusKnownGap //nolint:unused
	// statusUnverified means the entry is classified by structural shape and a
	// PRE-EXISTING code comment's claim (or a fast, single-pass reachability
	// check — e.g. "does any CLI command call this," not the deeper "trace
	// every core caller through Wave 0's idiom set" rigor), not by the same
	// individual-method verification depth Wave 0 applied to the original
	// 13-method partition. Honest label, not a downgrade: an entry here is a
	// real classification with a real (if less exhaustively checked) reason,
	// distinct from having no entry at all. Promote to statusIntentional (or
	// reclassify to statusKnownGap) once independently re-verified — see the
	// entry's Reason for exactly what verification is still missing.
	statusUnverified
)

type remoteUnsupportedEntry struct {
	status remoteUnsupportedStatus
	reason string
}

// remoteUnsupportedAllowlist is the exhaustive, reasoned inventory of every
// RemoteStorage method that is structurally a stub (see
// actualRemoteUnsupportedStubs). Entries are populated via
// addRemoteUnsupported() called from init() functions in per-feature
// *_completeness_test.go files alongside each remote_*.go, so parallel
// feature branches never conflict on a shared registry file.
//
// The initial population lives in remote_unsupported_registry_test.go; the
// G80 Wave 1 widening (#1576 — 96 structurally-stub methods that predated
// this guard's coverage) lives in remote_unsupported_widened_registry_test.go.
// New features: create remote_<feature>_completeness_test.go and call
// addRemoteUnsupported in an init() there — do NOT edit either registry file.
//
// TestRemoteUnsupportedStubsAreAllowlisted below asserts this map is an EXACT
// match against the current source: a PR that adds a new unlisted stub-shaped
// method fails immediately; a PR that fixes a listed method but forgets to
// remove its entry also fails.
var remoteUnsupportedAllowlist = map[string]remoteUnsupportedEntry{}

// addRemoteUnsupported merges entries into remoteUnsupportedAllowlist. Called
// from init() functions in per-feature *_completeness_test.go files.
func addRemoteUnsupported(entries map[string]remoteUnsupportedEntry) {
	maps.Copy(remoteUnsupportedAllowlist, entries)
}

// remoteStorageStubSourceFiles lists every source file that can define a
// *RemoteStorage method. Not just files matching "remote_*.go": entry.go
// defines NewRemoteStorage AND several *RemoteStorage methods (e.g.
// putConditionalTransition) — a G80 Wave 1 scanner bug (caught and fixed
// before this landed) missed it on a first pass, silently treating every
// method that delegates to a helper defined there as a false-positive stub.
// If a future file defines *RemoteStorage methods outside this list, the
// completeness check below will simply never see those methods at all —
// there is no guard against THAT failure mode short of re-deriving this list
// (`rg -l 'func \(rs \*RemoteStorage\)' internal/storage/store/*.go` and
// diffing against this slice) whenever a new remote_*.go-adjacent file is
// added. This is the one acknowledged residual blind spot; see the package
// doc note below for why it can't be closed further within this test.
func remoteStorageStubSourceFiles(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading internal/storage/store: %v", err)
	}
	var files []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		if strings.HasPrefix(name, "remote_") || name == "entry.go" {
			files = append(files, name)
		}
	}
	sort.Strings(files)
	return files
}

// actualRemoteUnsupportedStubs is the completeness guard's population:
// structural, not textual.
//
// G80 Wave 0 found 13 RemoteStorage methods returning a raw
// fmt.Errorf("not supported in remote storage") that the ORIGINAL version of
// this scanner's regex — matching only the remoteUnsupported("MethodName")
// helper-call shape — never saw (#1576). G80 Wave 1 re-derived the problem
// from scratch instead of just widening the regex to also match that one
// extra literal: a text-pattern search is only ever as complete as the list
// of patterns it knows about, and this package turned out to use AT LEAST
// five distinct stub-signaling shapes (remoteUnsupported("X"), a raw
// fmt.Errorf with "not supported in remote storage", a raw fmt.Errorf with
// "<Method> not available in remote mode", a shared package-level
// errUnsupportedRemote variable, and a silent no-op `return nil`/`return nil,
// nil`) — discovered by cross-checking two INDEPENDENT structural scans (an
// AST-based call-graph walk, and a brace-matched text scan) that agreed on
// every method except a fully-explained set of delegation-only wrappers (see
// remote_unsupported_widened_registry_test.go's own doc comment for that
// diff). A sixth shape existing tomorrow, with yet another novel error
// string, would be invisible to a regex no matter how many patterns it lists.
//
// So instead of matching text, this asks the only question that actually
// defines "stub" for this package: does calling this method EVER reach the
// network? A *RemoteStorage method is stub-shaped if its body — followed
// transitively through same-package method calls AND package-level helper
// function calls (e.g. postRetentionBeforeCountResp, which several real,
// fully-functional proxy methods delegate to) — never references
// `<something>.client.<Verb>(...)`. This is exactly the definition a human
// reviewer uses when asked "does this actually talk to the hub," made
// mechanical. A method matching this shape, whatever text its return
// statement uses (or doesn't — a silent `return nil` matches too), MUST have
// an allowlist entry or this test fails: there is no third state where a
// method is neither classified nor caught.
func actualRemoteUnsupportedStubs(t *testing.T) map[string]bool {
	t.Helper()
	fset := token.NewFileSet()
	// funcs holds every top-level func/method declared in the stub-source
	// files, keyed by name — methods AND package-level helpers together, so
	// a call from a method to a free function (not just to another method)
	// is resolvable in the same lookup.
	funcs := map[string]*ast.FuncDecl{}
	rsMethods := map[string]bool{}

	for _, name := range remoteStorageStubSourceFiles(t) {
		file, err := parser.ParseFile(fset, filepath.Join(".", name), nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			funcs[fn.Name.Name] = fn
			if fn.Recv != nil && len(fn.Recv.List) > 0 && exprString(fn.Recv.List[0].Type) == "*RemoteStorage" {
				rsMethods[fn.Name.Name] = true
			}
		}
	}

	visiting := map[string]bool{}
	memo := map[string]bool{}
	var reachesClient func(name string) bool
	reachesClient = func(name string) bool {
		if v, ok := memo[name]; ok {
			return v
		}
		if visiting[name] {
			return false // cycle guard — a stub can't prove itself non-stub via its own recursion
		}
		visiting[name] = true
		defer delete(visiting, name)

		fn, ok := funcs[name]
		if !ok || fn.Body == nil {
			memo[name] = false
			return false
		}
		found := false
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if found {
				return false
			}
			switch expr := n.(type) {
			case *ast.SelectorExpr:
				// <anything>.client.Verb(...) — direct client call, any receiver var name.
				if outer, ok := expr.X.(*ast.SelectorExpr); ok && exprString(outer.Sel) == "client" {
					found = true
					return false
				}
				// <recv>.OtherMethodOrHelper(...) selector call — recurse.
				if callee := expr.Sel.Name; callee != name && funcs[callee] != nil {
					if reachesClient(callee) {
						found = true
						return false
					}
				}
			case *ast.CallExpr:
				// Bare package-level function call: helperFn(ctx, rs, ...).
				if ident, ok := expr.Fun.(*ast.Ident); ok {
					if callee := ident.Name; callee != name && funcs[callee] != nil {
						if reachesClient(callee) {
							found = true
							return false
						}
					}
				}
			}
			return true
		})
		memo[name] = found
		return found
	}

	found := map[string]bool{}
	for name := range rsMethods {
		if !reachesClient(name) {
			found[name] = true
		}
	}
	return found
}

func exprString(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return "*" + exprString(t.X)
	case *ast.SelectorExpr:
		return exprString(t.X) + "." + t.Sel.Name
	default:
		return fmt.Sprintf("%T", e)
	}
}

// TestRemoteUnsupportedStubsAreAllowlisted is the completeness guard: every
// structurally-stub RemoteStorage method (actualRemoteUnsupportedStubs —
// never reaches the network, by any means, regardless of what error text or
// return shape it uses) must be an EXACT match against
// remoteUnsupportedAllowlist above — no more, no less. This is the guard's
// own denominator assertion: a method matching the broad structural shape is
// either classified here or this test is red. There is no third state.
//
//   - A method that becomes a NEW unconditional stub (or is discovered and never
//     classified) fails this test immediately, forcing the same real-caller-
//     tracing investigation this list was built from before it can be merged —
//     preventing the silent, piecemeal rediscovery this campaign has repeated
//     for ~10 rounds (#503-class, #513, #517-520, round-119's 55, and #1576's
//     96 — see remote_unsupported_widened_registry_test.go).
//   - A method that gets FIXED (proxied for real) but whose allowlist entry is
//     forgotten also fails this test, keeping the list from accumulating stale
//     "known gap" entries that no longer reflect reality — remove the entry in
//     the same PR that lands the fix.
func TestRemoteUnsupportedStubsAreAllowlisted(t *testing.T) {
	actual := actualRemoteUnsupportedStubs(t)

	var missingFromAllowlist []string // real stub, no allowlist entry — a new/forgotten gap
	for name := range actual {
		if _, ok := remoteUnsupportedAllowlist[name]; !ok {
			missingFromAllowlist = append(missingFromAllowlist, name)
		}
	}
	sort.Strings(missingFromAllowlist)

	var staleAllowlistEntries []string // allowlisted, but no longer structurally a stub — fixed and forgotten
	for name := range remoteUnsupportedAllowlist {
		if !actual[name] {
			staleAllowlistEntries = append(staleAllowlistEntries, name)
		}
	}
	sort.Strings(staleAllowlistEntries)

	if len(missingFromAllowlist) > 0 {
		t.Errorf("found %d RemoteStorage method(s) that never reach the network (see "+
			"actualRemoteUnsupportedStubs' doc comment for the exact structural definition) with NO "+
			"allowlist entry in remoteUnsupportedAllowlist "+
			"(internal/storage/store/remote_unsupported_completeness_test.go): %v\n"+
			"Every such method must be classified as statusIntentional (verified permanent, with a real "+
			"reason), statusKnownGap (a real, currently-reachable bug, referencing a backlog finding), or "+
			"statusUnverified (classified by structural shape and a fast check, not full individual "+
			"verification — say exactly what's still unchecked) before it can be merged — trace the "+
			"method's actual internal/core caller(s) and CLI/HTTP/gRPC reachability under storage.type: "+
			"remote, don't guess.", len(missingFromAllowlist), missingFromAllowlist)
	}
	if len(staleAllowlistEntries) > 0 {
		t.Errorf("found %d remoteUnsupportedAllowlist entr(y/ies) that no longer reach the network check "+
			"the same way (they were fixed, or now delegate to a real client call): %v\n"+
			"Remove these entries from remoteUnsupportedAllowlist — if the fix closed a tracked backlog "+
			"finding, this test failing is your reminder to also update docs/security/BUGS.md.", len(staleAllowlistEntries), staleAllowlistEntries)
	}
}
