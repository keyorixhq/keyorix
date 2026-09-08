// remote_proxy_correctness_audit_test.go — issue #1786 part 2, tranche 1.
//
// remote_reachability_registry_test.go answers "is this structurally-stub
// RemoteStorage method reachable" — a question about the methods that never
// touch the network. This file answers a different question over a different
// population: for the methods that DO reach the network (the real proxies),
// is the proxy itself correct — does it forward every input, propagate every
// error, forward the caller's own context, and never report success on a
// failed or skipped remote call?
//
// Both questions are decidable by machine because remote_invitations.go's own
// header documents (and this file's TestRealProxiesAreThinPassthroughs
// spot-checks) that these methods are thin passthroughs: one client call,
// forwarding the method's own inputs, returning the method's own error. A
// method that fits that shape is checkable by static analysis alone — no
// server needed. The differential conformance harness (actually calling
// RemoteStorage.M(x) and LocalStorage.M(x) side by side) is a separate, later
// tranche: reachability, static-shape correctness, and behavioral equivalence
// are three different questions, over three different (though overlapping)
// populations, and conflating them is exactly the kind of fan-out-of-
// judgments this file exists to avoid.
//
// Population derivation deliberately reuses actualRemoteUnsupportedStubs
// (remote_unsupported_completeness_test.go) rather than reimplementing the
// stub definition — two independent definitions of "stub" would drift, which
// is the same lesson remote_unsupported_widened_registry_test.go already
// paid for once (five distinct stub-signaling shapes, found by cross-checking
// two independent scans).
//
// # KNOWN NON-COVERAGE (read before trusting a green result)
//
// A historical-positive validation (run after this file's checks first
// merged, PR #1800) searched this repository's own git history for real,
// already-fixed defects in this exact proxy population. It found 9
// candidates and replayed the checks below against the pre-fix tree for
// each: 1 was directly executed and missed; the other 8 were established by
// code inspection but were not replayable (the checks depend on scanner
// helpers introduced later than those commits — see the validation report
// for the full methodology). The checks below caught ZERO of the 9.
//
// Seven defect classes came out of that search, none of which the checks in
// this file can see:
//
//  1. wrong response-envelope assumption — Health checked resp.Success on
//     /health, a route with no {success,data} envelope at all. No check
//     here inspects response semantics.
//  2. blank-identifier parameter drop — RemoveRoleFromGroup's scope
//     parameter was declared `_`. NOW COVERED — see check 5 below, added
//     directly from this evidence (issue #1786 part 3).
//  3. wire-struct field omission — AllowedCIDRs, ParentID: a struct-typed
//     parameter is referenced in full (so check 1 sees it as "used"), but
//     only some of its fields are copied into the wire type. Field-level
//     completeness is not identifier-level presence.
//  4. wrong endpoint string — LogAuditEvent, GetAuditLogs,
//     GetRBACAuditLogs, GetSecretByName all 404'd against routes that were
//     never registered server-side. No check here inspects a URL/path
//     literal's validity.
//  5. whole-struct JSON-tag mismatch — CreateUser/CreateSecret/UpdateSecret
//     marshaled a raw, untagged Go struct; encoding/json silently dropped
//     every underscore-named field. The struct IS referenced, in full —
//     invisible to any identifier-presence check by construction.
//  6. cache staleness against a compare-and-swap need — LockUserForUpdate
//     delegated to GetUser, inheriting its 5-minute response cache and
//     defeating the anti-TOCTOU recheck the method exists for. A runtime
//     behavior, not a source shape.
//  7. context lifetime, not identity — LogAuditEvent forwarded the
//     triggering request's own cancellable context into an audit write
//     instead of detaching. Check 3 does not merely miss this class: check
//     3's condition for "correct" is that ctx IS forwarded verbatim, so on
//     an audit-emitting endpoint where forwarding is exactly the bug,
//     check 3 CERTIFIES the defect as correct. A green check-3 result on an
//     audit-emitting path is not neutral silence about context lifetime —
//     it is an affirmative, and here wrong, verdict.
//
// Classes 1, 3, 4, 5, 6, and 7 are behavioral, not structural — they need a
// differential conformance harness (RemoteStorage.M(x) vs LocalStorage.M(x)
// through a real server) to see, not a smarter static check. See issue
// #1808 for that harness, using this same seven-class list as its test
// plan. Do NOT add static checks for classes 1, 3, 4, 5, or 6 here: a
// static check that appears to cover a behavioral class is worse than no
// check, because it looks like coverage without being coverage — exactly
// the framing mistake this file's own history (issue #1786) was filed
// over. A green TestLayer1StaticFindingsAreAllowlisted result means exactly
// one thing: no unexplained hit on five narrow, syntactic properties.
// Nothing more — it is not evidence these proxies are correct.
package store

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// methodInfo is one method declaration found on a receiver type, with enough
// position information to report findings against real source locations.
type methodInfo struct {
	Name string
	File string
	Line int
	Decl *ast.FuncDecl
}

// receiverMethods parses EVERY non-test .go file in the package directory
// (not a hand-maintained list of "remote_*.go"-shaped filenames — see
// remoteStorageStubSourceFiles's own doc comment for why a filename-prefix
// assumption is exactly the kind of enumeration gap this campaign keeps
// finding) and returns every top-level method declared on the given pointer
// receiver type (e.g. "*RemoteStorage"), keyed by method name.
//
// This is a full re-scan rather than a reuse of remoteStorageStubSourceFiles
// on purpose: that list is scoped to "files that CAN define *RemoteStorage
// methods" for the stub-completeness check's own purposes, and asserting our
// independently-derived population agrees with it (see
// TestPopulationMatchesStubScannerFileList) is itself a soundness check on
// both lists, not a reason to skip deriving this one from scratch.
func receiverMethods(t *testing.T, receiver string) map[string]methodInfo {
	t.Helper()
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading package directory: %v", err)
	}

	out := map[string]methodInfo{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(".", name), nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || len(fn.Recv.List) == 0 {
				continue
			}
			if exprString(fn.Recv.List[0].Type) != receiver {
				continue
			}
			pos := fset.Position(fn.Pos())
			if existing, dup := out[fn.Name.Name]; dup {
				t.Fatalf("method %s declared twice on %s: %s:%d and %s:%d — Go doesn't allow this, "+
					"parser or receiver-matching bug", fn.Name.Name, receiver, existing.File, existing.Line, name, pos.Line)
			}
			out[fn.Name.Name] = methodInfo{Name: fn.Name.Name, File: name, Line: pos.Line, Decl: fn}
		}
	}
	return out
}

func remoteStorageMethods(t *testing.T) map[string]methodInfo {
	return receiverMethods(t, "*RemoteStorage")
}
func localStorageMethods(t *testing.T) map[string]methodInfo {
	return receiverMethods(t, "*LocalStorage")
}

// TestPopulationMatchesStubScannerFileList is the soundness check
// receiverMethods' own doc comment promises: actualRemoteUnsupportedStubs
// only ever looks inside remoteStorageStubSourceFiles' file list
// (remote_unsupported_completeness_test.go's own doc comment names this its
// "one acknowledged residual blind spot"). If a file OUTSIDE that list ever
// gained a real *RemoteStorage method, actualRemoteUnsupportedStubs would
// silently never see it — realProxyMethods would then wrongly classify a
// true stub as a real proxy (or vice versa) with no test catching it. This
// fails loudly instead, the moment a new file needs adding to that list.
func TestPopulationMatchesStubScannerFileList(t *testing.T) {
	allowed := map[string]bool{}
	for _, f := range remoteStorageStubSourceFiles(t) {
		allowed[f] = true
	}
	var outside []string
	for _, info := range remoteStorageMethods(t) {
		if !allowed[info.File] {
			outside = append(outside, info.File+":"+info.Name)
		}
	}
	sort.Strings(outside)
	if len(outside) > 0 {
		t.Errorf("%d *RemoteStorage method(s) declared outside remoteStorageStubSourceFiles' file list — "+
			"actualRemoteUnsupportedStubs cannot see these files at all, so it can neither confirm nor deny "+
			"they're stubs: %v. Add the file to remoteStorageStubSourceFiles "+
			"(remote_unsupported_completeness_test.go).", len(outside), outside)
	}
}

// exported reports whether a Go identifier is exported (starts with an
// uppercase letter) — used to separate interface-facing proxy methods from
// unexported same-package helpers (putConditionalTransition,
// fetchNotifications, getAccessActivity, listEnvironmentsByProject) that
// exist to be called BY proxy methods, not to themselves implement one
// storage.Storage operation each.
func exported(name string) bool {
	return len(name) > 0 && name[0] >= 'A' && name[0] <= 'Z'
}

// realProxyMethods is this tranche's population: every EXPORTED
// *RemoteStorage method that is NOT structurally a stub (actualRemoteUnsupportedStubs).
// Unexported helpers are excluded — they aren't independently-callable
// storage.Storage operations, and every one of their call sites is itself an
// exported method already in this set, so nothing is silently skipped by
// excluding them; they get exercised transitively through their callers.
func realProxyMethods(t *testing.T) map[string]methodInfo {
	t.Helper()
	all := remoteStorageMethods(t)
	stubs := actualRemoteUnsupportedStubs(t)

	out := map[string]methodInfo{}
	for name, info := range all {
		if !exported(name) {
			continue
		}
		if stubs[name] {
			continue
		}
		out[name] = info
	}
	return out
}

// TestReportRemoteStorageProxyPopulation is step 1's report: the denominator
// and selection criterion for everything this file's checker examines, plus
// the LocalStorage/RemoteStorage method-set diff in both directions. Always
// passes — it is a report, not a gate; run with `-v` to see it.
func TestReportRemoteStorageProxyPopulation(t *testing.T) {
	all := remoteStorageMethods(t)
	stubs := actualRemoteUnsupportedStubs(t)
	unexportedHelpers := map[string]methodInfo{}
	for name, info := range all {
		if !exported(name) {
			unexportedHelpers[name] = info
		}
	}
	proxies := realProxyMethods(t)
	locals := localStorageMethods(t)

	var undetermined []string
	for name := range all {
		_, isStub := stubs[name]
		_, isProxy := proxies[name]
		_, isHelper := unexportedHelpers[name]
		if !isStub && !isProxy && !isHelper {
			undetermined = append(undetermined, name)
		}
	}

	onlyOnRemote := diffNames(all, locals)
	onlyOnLocal := diffNames(locals, all)

	t.Logf("=== RemoteStorage proxy population (method used: go/ast, receiver-typed FuncDecl scan over every non-test .go file in internal/storage/store) ===")
	t.Logf("total *RemoteStorage methods (all receivers, exported+unexported): %d", len(all))
	t.Logf("  structurally-stub (actualRemoteUnsupportedStubs, reused not reimplemented): %d", len(stubs))
	t.Logf("  unexported same-package helpers (not independently-callable proxy methods): %d -> %v", len(unexportedHelpers), sortedKeys(unexportedHelpers))
	t.Logf("  real-proxy set (exported, not structurally stub) — THIS TRANCHE'S POPULATION: %d", len(proxies))
	t.Logf("  undetermined (resisted classification — see selection criterion above): %d -> %v", len(undetermined), undetermined)
	t.Logf("selection criterion: exported == name[0] is uppercase; stub == actualRemoteUnsupportedStubs' structural reachesClient()==false; " +
		"a method must land in exactly one of {stub, unexported-helper, real-proxy} or it is reported as undetermined, never silently bucketed")
	t.Logf("total *LocalStorage methods: %d", len(locals))
	t.Logf("methods on RemoteStorage but not LocalStorage (%d): %v", len(onlyOnRemote), onlyOnRemote)
	t.Logf("methods on LocalStorage but not RemoteStorage (%d): %v", len(onlyOnLocal), onlyOnLocal)

	if len(undetermined) > 0 {
		t.Errorf("%d RemoteStorage method(s) resist classification into {stub, helper, proxy}: %v — "+
			"this must be zero; investigate and extend the selection criterion, don't bucket silently", len(undetermined), undetermined)
	}
}

func diffNames(a, b map[string]methodInfo) []string {
	var out []string
	for name := range a {
		if _, ok := b[name]; !ok {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

func sortedKeys(m map[string]methodInfo) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// clientVerbs is the exhaustive set of HTTPClient methods a proxy can call to
// reach the network — the same verb set actualRemoteUnsupportedStubs' own
// reachesClient() looks for via the "<x>.client" selector shape, but named
// here explicitly (Get/Post/Put/Delete plus the raw Request escape hatch used
// by 3 call sites that need a verb or method the four verb helpers don't
// cover) because the checks below need to inspect the CALL itself (its
// arguments, its assignment targets), not just prove one exists.
var clientVerbs = map[string]bool{"Get": true, "Post": true, "Put": true, "Delete": true, "Request": true}

// isClientCall reports whether call is a direct "<recv>.client.<Verb>(...)"
// call — any receiver variable name, matching the same shape
// actualRemoteUnsupportedStubs' reachesClient() recognizes (see that
// function's own SelectorExpr case), not hardcoded to the receiver being
// literally named "rs" (it always is today, but matching the shape rather
// than the name is what makes this resilient to a future rename).
func isClientCall(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || !clientVerbs[sel.Sel.Name] {
		return false
	}
	outer, ok := sel.X.(*ast.SelectorExpr)
	return ok && outer.Sel.Name == "client"
}

// receiverName returns fn's receiver variable name (e.g. "rs"), or "" if it
// has none/is blank.
func receiverName(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) == 0 || len(fn.Recv.List[0].Names) == 0 {
		return ""
	}
	return fn.Recv.List[0].Names[0].Name
}

// isDelegateCall reports whether call invokes ANOTHER method on the same
// RemoteStorage receiver — either one of the 4 unexported same-package
// helpers, or a peer exported proxy method. The peer case was found live,
// not assumed: TestRealProxiesAreThinPassthroughs' first run (against a
// helper-name-only allowlist) missed GetSecretsByIDs (fans out to
// rs.GetSecret in a loop), ListSharesBySecretIDs (fans out to
// rs.ListSharesBySecret in a loop), GetSecretVersions/HealthCheck/
// LockWebAuthnCredentialForUpdate (single-line aliases to rs.ListSecretVersions/
// rs.Health/rs.GetWebAuthnCredentialByCredID) — a THIRD delegation shape this
// package uses, beyond "direct client call" and "shared unexported helper".
// allMethods is every *RemoteStorage method name (remoteStorageMethods' keys)
// so this recognizes a delegate call to ANY sibling method, not a hand-
// maintained list of the ones already found.
func isDelegateCall(call *ast.CallExpr, recv string, allMethods map[string]bool) (name string, ok bool) {
	if recv == "" {
		return "", false
	}
	sel, isSel := call.Fun.(*ast.SelectorExpr)
	if !isSel {
		return "", false
	}
	id, isIdent := sel.X.(*ast.Ident)
	if !isIdent || id.Name != recv {
		return "", false
	}
	if allMethods[sel.Sel.Name] {
		return sel.Sel.Name, true
	}
	return "", false
}

// proxyCallSite is one client or delegate call found in a proxy method's
// body, with enough context to classify the method's overall shape. Named
// distinctly from checkthencreate_race_completeness_test.go's own unrelated
// callSite type in this same package.
type proxyCallSite struct {
	Call       *ast.CallExpr
	IsClient   bool   // true: direct rs.client.<Verb>(...); false: delegate to a sibling method
	DelegateTo string // set when !IsClient
	InLoop     bool   // lexically inside a for/range statement within this function
}

// directCallSites walks fn's body (not descending into nested func literals —
// none of the 214 real proxy methods declare one) and returns every client
// call and every delegate call found at any depth in the statement tree, in
// the order they'd execute for a single call to fn (loop bodies visited once,
// flagged via InLoop — the loop's own iteration count is a runtime fact this
// static walk can't and doesn't need to know).
func directCallSites(fn *ast.FuncDecl, allMethods map[string]bool) []proxyCallSite {
	if fn.Body == nil {
		return nil
	}
	recv := receiverName(fn)
	var sites []proxyCallSite

	// ast.Inspect calls f(nil) immediately after finishing a node's children
	// (in LIFO order matching the depth-first walk), so a plain stack of
	// per-node flags — pushed on entry, popped on that f(nil) — is enough to
	// track "am I inside a loop" / "am I inside a closure" without hand-
	// rolled recursion. Always returning true keeps every push matched by
	// exactly one pop; funcLitDepth only gates whether a call gets recorded,
	// it never skips descending (there's nothing to skip: no closure among
	// the 214 real proxy methods contains a client or delegate call anyway —
	// this guards the future, not a case observed today).
	type frame struct{ isLoop, isFuncLit bool }
	var stack []frame
	loopDepth, funcLitDepth := 0, 0
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if n == nil {
			top := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if top.isLoop {
				loopDepth--
			}
			if top.isFuncLit {
				funcLitDepth--
			}
			return true
		}
		_, isFor := n.(*ast.ForStmt)
		_, isRange := n.(*ast.RangeStmt)
		_, isFuncLit := n.(*ast.FuncLit)
		stack = append(stack, frame{isLoop: isFor || isRange, isFuncLit: isFuncLit})
		if isFor || isRange {
			loopDepth++
		}
		if isFuncLit {
			funcLitDepth++
		}
		if call, ok := n.(*ast.CallExpr); ok && funcLitDepth == 0 {
			if isClientCall(call) {
				sites = append(sites, proxyCallSite{Call: call, IsClient: true, InLoop: loopDepth > 0})
			} else if name, ok := isDelegateCall(call, recv, allMethods); ok {
				sites = append(sites, proxyCallSite{Call: call, IsClient: false, DelegateTo: name, InLoop: loopDepth > 0})
			}
		}
		return true
	})
	return sites
}

// TestRealProxiesAreThinPassthroughs verifies remote_invitations.go's
// documented premise — "these are thin passthroughs onto server-side routes
// that call the same storage.Storage methods LocalStorage implements" — holds
// across the WHOLE real-proxy population, not just the invitations file it
// was written for. Three delegation shapes exist in this package (found by
// running this check, not assumed in advance — the first version only knew
// about the 4 unexported helpers and missed a real fifth shape, peer-method
// delegation, on GetSecretsByIDs/ListSharesBySecretIDs/GetSecretVersions/
// HealthCheck/LockWebAuthnCredentialForUpdate): a direct client call, a call
// to one of the 4 shared unexported helpers, or a call to another exported
// RemoteStorage method (a single-line alias, or a fan-out loop over a
// collection). This is the premise the four static checks below rely on:
// a method with exactly one call site is checkable by "is this call's error
// propagated / is this call's context forwarded" directly; a fan-out loop
// needs that same question asked about the loop's own error policy instead.
//
// Always passes — it's a report of the shape distribution, not a gate, since
// "not single-call" is a fact to know about (and the checks below account
// for), not automatically a defect.
func TestRealProxiesAreThinPassthroughs(t *testing.T) {
	proxies := realProxyMethods(t)
	all := remoteStorageMethods(t)
	allNames := make(map[string]bool, len(all))
	for name := range all {
		allNames[name] = true
	}

	var single, delegateSingle, delegateLoop, multiCall, noCallFound []string
	for name, info := range proxies {
		sites := directCallSites(info.Decl, allNames)
		switch {
		case len(sites) == 0:
			// Reaches the network only via some indirection directCallSites
			// doesn't walk — actualRemoteUnsupportedStubs already proved this
			// method IS reachable (it's not in the stub set), so this bucket
			// means the premise does NOT hold for this method and it needs
			// individual attention, not silent inclusion in "single".
			noCallFound = append(noCallFound, name)
		case len(sites) == 1 && sites[0].IsClient:
			single = append(single, name)
		case len(sites) == 1 && !sites[0].IsClient && !sites[0].InLoop:
			delegateSingle = append(delegateSingle, name)
		case len(sites) == 1 && !sites[0].IsClient && sites[0].InLoop:
			delegateLoop = append(delegateLoop, name)
		default:
			multiCall = append(multiCall, name)
		}
	}
	sort.Strings(single)
	sort.Strings(delegateSingle)
	sort.Strings(delegateLoop)
	sort.Strings(multiCall)
	sort.Strings(noCallFound)

	t.Logf("=== thin-passthrough premise check over %d real proxy methods ===", len(proxies))
	t.Logf("single direct client call (the documented shape): %d", len(single))
	t.Logf("single delegate call to a helper or peer method, straight-line: %d -> %v", len(delegateSingle), delegateSingle)
	t.Logf("single delegate call to a peer method inside a fan-out loop (own error policy, reviewed individually): %d -> %v", len(delegateLoop), delegateLoop)
	t.Logf("multiple call sites in one method (premise does NOT hold, needs individual review): %d -> %v", len(multiCall), multiCall)
	t.Logf("no call site found by this walk despite being reachable (indirection undetected): %d -> %v", len(noCallFound), noCallFound)

	if len(noCallFound) > 0 {
		t.Errorf("%d real-proxy method(s) reach the network by some means directCallSites can't see: %v — "+
			"the checks below would silently skip these; extend directCallSites' walk before relying on it", len(noCallFound), noCallFound)
	}
	if len(multiCall) > 0 {
		t.Logf("NOTE: %d method(s) have more than one call site — not a failure, but the 4 checks below "+
			"apply to EACH call site individually for these, not just 'the' call", len(multiCall))
	}
}

// ============================================================================
// Layer 1 static checks (issue #1786 parts 2 and 3).
//
// Five checks, each scoped to what it can decide SOUNDLY from source text
// alone, over one proxyCallSite at a time (checks 1-4 from part 2; check 5
// from part 3, see the KNOWN NON-COVERAGE section above for why it exists):
//
//   1. dropped input   — a method parameter never referenced anywhere in the
//      body cannot possibly be part of the request; this is a hard fact, not
//      a heuristic (the reverse — "referenced somewhere" — does not prove the
//      request actually carries it forward correctly; see the doc comment on
//      unusedParams for the acknowledged asymmetry).
//   2. swallowed error — the call's own error result is checked with a
//      `<errVar> != nil` guard, and that guard's block ends in a return.
//   3. context substitution — the call's first argument is literally the
//      method's own context.Context parameter, not a freshly minted one.
//   4. silent zero return — a failure guard's return statement returns a
//      literal `nil` in the error position, contradicting the guard's own
//      condition.
//   5. blank-identifier parameter — a parameter declared `_` in a real
//      proxy method's own signature. Derived from a confirmed historical
//      defect (RemoveRoleFromGroup, #1394), not from imagination — see
//      blankParams' own doc comment.
//
// Each is validated red-then-green in remote_proxy_correctness_checks_test.go
// against small in-memory source snippets (not real files) before this file's
// findings are trusted — see that file's own doc comment.
// ============================================================================

// methodParams returns the method's context.Context parameter name (empty if
// none — none of the 214 real proxies lack one, but this doesn't assume that)
// and every other parameter name, "_" excluded.
func methodParams(fn *ast.FuncDecl) (ctxParam string, others []string) {
	if fn.Type.Params == nil {
		return "", nil
	}
	for _, field := range fn.Type.Params.List {
		isCtx := exprString(field.Type) == "context.Context"
		if len(field.Names) == 0 {
			continue // unnamed param — nothing to check for usage
		}
		for _, n := range field.Names {
			if n.Name == "_" {
				continue
			}
			if isCtx {
				ctxParam = n.Name
			} else {
				others = append(others, n.Name)
			}
		}
	}
	return ctxParam, others
}

// identUsed reports whether name appears as an *ast.Ident anywhere in body.
//
// This is a sound over-approximation for "used", not an exact one: it can't
// distinguish a real use from an unrelated identifier that happens to share
// the parameter's name (e.g. a struct field access `.Email` matching a
// parameter also named Email would NOT false-match, since Sel is checked as
// an Ident as well and this only compares Name strings — a struct FIELD named
// identically to the parameter, e.g. `w.email` where the param is also
// `email`, WOULD false-match). The direction that matters is preserved
// though: it can only make an unused parameter look used, never the reverse —
// so a "dropped input" finding from this check is always a real finding
// (zero occurrences of the name anywhere means the value provably never
// leaves the function), while a clean result is a weaker guarantee ("this
// name occurs somewhere", not "the request forwards it"). Documented instead
// of silently treated as exact, per this file's own standing instruction not
// to ship an approximation that reads as full coverage.
func identUsed(body *ast.BlockStmt, name string) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if found {
			return false
		}
		if id, ok := n.(*ast.Ident); ok && id.Name == name {
			found = true
			return false
		}
		return true
	})
	return found
}

// droppedInputs is check 1: every parameter with zero references anywhere in
// the body — provably never forwarded, since it is provably never used at
// all.
func droppedInputs(fn *ast.FuncDecl) []string {
	if fn.Body == nil {
		return nil
	}
	_, params := methodParams(fn)
	var dropped []string
	for _, p := range params {
		if !identUsed(fn.Body, p) {
			dropped = append(dropped, p)
		}
	}
	return dropped
}

// blankParams is check 5 (issue #1786 part 3): every parameter declared with
// the blank identifier `_` in a real proxy method's signature — added
// directly from a confirmed historical defect, not from imagination:
// RemoteStorage.RemoveRoleFromGroup (#1394) declared its scope parameter
// `_ storage.Scope`, so it satisfied storage.Storage's interface, compiled
// clean, and never sent the value anywhere. Check 1 (droppedInputs) cannot
// see this BY CONSTRUCTION: methodParams skips blank names before
// droppedInputs ever runs (there is no identifier for identUsed to search
// for) — this check looks at the declaration itself instead of at usage,
// which is the only way to see a value the language itself lets a method
// discard without comment.
func blankParams(fn *ast.FuncDecl) []string {
	if fn.Type.Params == nil {
		return nil
	}
	var blanks []string
	for _, field := range fn.Type.Params.List {
		for _, n := range field.Names {
			if n.Name == "_" {
				blanks = append(blanks, exprString(field.Type))
			}
		}
	}
	return blanks
}

// contextSubstituted is check 3: reports a description of site's first
// argument when it is NOT the method's own ctx parameter forwarded verbatim —
// e.g. "context.Background()" or a differently-named identifier. Returns ""
// when the call correctly forwards ctx.
func contextSubstituted(fn *ast.FuncDecl, site proxyCallSite) string {
	ctxParam, _ := methodParams(fn)
	if len(site.Call.Args) == 0 {
		return "call takes no arguments at all (expected ctx as arg 0)"
	}
	arg0 := site.Call.Args[0]
	if id, ok := arg0.(*ast.Ident); ok {
		if id.Name == ctxParam {
			return ""
		}
		return fmt.Sprintf("forwards identifier %q instead of the method's own ctx param %q", id.Name, ctxParam)
	}
	return "arg 0 is not a forwarded identifier at all: " + exprString2(arg0)
}

// exprString2 is a tiny local formatting helper kept separate from
// exprString (remote_unsupported_completeness_test.go) so a future edit to
// that shared helper's Ident/SelectorExpr cases can't silently change this
// file's finding text.
func exprString2(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.CallExpr:
		return exprString2(t.Fun) + "(...)"
	case *ast.SelectorExpr:
		return exprString2(t.X) + "." + t.Sel.Name
	default:
		return "<non-identifier expression>"
	}
}

// callAssignment describes how a call site's results are consumed: either a
// bare tail return (the enclosing statement is `return <call>(...)`, which
// Go's type system guarantees forwards every result — including any error —
// verbatim, needing no guard at all), or an assignment binding named result
// identifiers the checker can then trace guards against.
type callAssignment struct {
	isTailReturn bool
	resultNames  []string // LHS identifiers, in order; "" for a blank "_"
	block        []ast.Stmt
	index        int // index of the assignment/return statement within block
}

// locateAssignment finds the statement that directly contains site.Call and
// classifies it. Searches fn.Body recursively through if/for/range bodies
// (see childBlocksOf) so a call site nested one level inside a fan-out loop —
// GetSecretsByIDs, ListSharesBySecretIDs — is found in the loop's OWN
// statement list, not the function's top-level one.
func locateAssignment(fn *ast.FuncDecl, site proxyCallSite) (callAssignment, bool) {
	block, index, ok := findContainingStatement(fn.Body, site.Call)
	if !ok {
		return callAssignment{}, false
	}
	switch stmt := block[index].(type) {
	case *ast.ReturnStmt:
		if len(stmt.Results) == 1 {
			if _, isCall := stmt.Results[0].(*ast.CallExpr); isCall {
				return callAssignment{isTailReturn: true, block: block, index: index}, true
			}
		}
		return callAssignment{}, false // call is an argument/operand of a larger return expr, not a bare tail call
	case *ast.AssignStmt:
		if len(stmt.Rhs) != 1 {
			return callAssignment{}, false // multi-value RHS list, not "one call assigned"
		}
		names := make([]string, len(stmt.Lhs))
		for i, lhs := range stmt.Lhs {
			if id, ok := lhs.(*ast.Ident); ok {
				names[i] = id.Name
			}
		}
		return callAssignment{resultNames: names, block: block, index: index}, true
	default:
		return callAssignment{}, false
	}
}

// findContainingStatement returns the innermost statement list and index
// whose statement directly contains target — recursing into if/for/range
// bodies FIRST so the innermost enclosing block wins, matching how Go scopes
// actually nest.
func findContainingStatement(root *ast.BlockStmt, target *ast.CallExpr) ([]ast.Stmt, int, bool) {
	for i, stmt := range root.List {
		for _, child := range childBlocksOf(stmt) {
			if list, idx, ok := findContainingStatement(child, target); ok {
				return list, idx, true
			}
		}
		if containsDirectly(stmt, target) {
			return root.List, i, true
		}
	}
	return nil, 0, false
}

// childBlocksOf returns the nested *ast.BlockStmt bodies a statement can
// carry. Switch/select bodies are deliberately not handled — none of the 214
// real proxy methods use one (TestRealProxiesAreThinPassthroughs found 0
// multi-call/undetected methods), so adding that case now would be untested
// code; extend here if a future proxy method needs it.
func childBlocksOf(stmt ast.Stmt) []*ast.BlockStmt {
	switch s := stmt.(type) {
	case *ast.IfStmt:
		blocks := []*ast.BlockStmt{s.Body}
		if elseBlock, ok := s.Else.(*ast.BlockStmt); ok {
			blocks = append(blocks, elseBlock)
		}
		return blocks
	case *ast.ForStmt:
		return []*ast.BlockStmt{s.Body}
	case *ast.RangeStmt:
		return []*ast.BlockStmt{s.Body}
	}
	return nil
}

// containsDirectly reports whether target occurs within stmt without
// crossing into a nested block already handled by childBlocksOf (so a call
// inside an if/for nested in stmt is NOT counted as "directly" in stmt —
// findContainingStatement already recursed into it separately).
func containsDirectly(stmt ast.Stmt, target *ast.CallExpr) bool {
	found := false
	ast.Inspect(stmt, func(n ast.Node) bool {
		if found {
			return false
		}
		if n == target {
			found = true
			return false
		}
		if block, ok := n.(*ast.BlockStmt); ok && ast.Node(stmt) != ast.Node(block) {
			return false
		}
		return true
	})
	return found
}

// failureGuard is one `if <errVar> != nil` or `if !<respVar>.Success` guard
// found following a call's assignment, with its own return statement (if
// any) for check 4 to inspect.
type failureGuard struct {
	kind      string // "error" or "resp.Success"
	ifStmt    *ast.IfStmt
	terminal  *ast.ReturnStmt // last statement of the guard body, if it is one
	hasReturn bool
}

// findFailureGuards scans every statement AFTER assign.index in assign.block
// for an if-statement testing the call's own error variable, or (for a
// client call) the response's Success field.
func findFailureGuards(assign callAssignment, errVar, respVar string) []failureGuard {
	var guards []failureGuard
	for _, stmt := range assign.block[assign.index+1:] {
		ifStmt, ok := stmt.(*ast.IfStmt)
		if !ok {
			continue
		}
		kind := guardKind(ifStmt.Cond, errVar, respVar)
		if kind == "" {
			continue
		}
		g := failureGuard{kind: kind, ifStmt: ifStmt}
		if n := len(ifStmt.Body.List); n > 0 {
			if ret, ok := ifStmt.Body.List[n-1].(*ast.ReturnStmt); ok {
				g.terminal = ret
				g.hasReturn = true
			}
		}
		guards = append(guards, g)
	}
	return guards
}

// guardKind classifies an if-condition as an error guard, a resp.Success
// guard, or neither ("").
func guardKind(cond ast.Expr, errVar, respVar string) string {
	if errVar != "" {
		if bin, ok := cond.(*ast.BinaryExpr); ok && bin.Op == token.NEQ {
			if isIdentNamed(bin.X, errVar) && isIdentNil(bin.Y) {
				return "error"
			}
			if isIdentNamed(bin.Y, errVar) && isIdentNil(bin.X) {
				return "error"
			}
		}
	}
	if respVar != "" {
		// !resp.Success
		if un, ok := cond.(*ast.UnaryExpr); ok && un.Op == token.NOT {
			if isSelector(un.X, respVar, "Success") {
				return "resp.Success"
			}
		}
		// resp.Success == false
		if bin, ok := cond.(*ast.BinaryExpr); ok && bin.Op == token.EQL {
			if isSelector(bin.X, respVar, "Success") && isIdentFalse(bin.Y) {
				return "resp.Success"
			}
		}
	}
	return ""
}

func isIdentNamed(e ast.Expr, name string) bool {
	id, ok := e.(*ast.Ident)
	return ok && id.Name == name
}
func isIdentNil(e ast.Expr) bool   { return isIdentNamed(e, "nil") }
func isIdentFalse(e ast.Expr) bool { return isIdentNamed(e, "false") }
func isSelector(e ast.Expr, xName, selName string) bool {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && id.Name == xName && sel.Sel.Name == selName
}

// proxyFinding is one static-check hit against one call site.
type proxyFinding struct {
	Method string
	File   string
	Line   int
	Check  string // "dropped-input" | "swallowed-error" | "context-substitution" | "silent-zero-return" | "blank-identifier-param"
	Detail string
}

// checkCallSite runs all 5 checks against one proxy method + its one call
// site, returning every finding. Called once per proxyCallSite — for the two
// fan-out-loop methods this still means once (each has exactly one call
// site, per TestRealProxiesAreThinPassthroughs), evaluated with the
// understanding that a guard here runs once per loop ITERATION at runtime,
// not once per method call — noted in the finding detail, not hidden.
func checkCallSite(info methodInfo, site proxyCallSite) []proxyFinding {
	fn := info.Decl
	var findings []proxyFinding
	add := func(check, detail string) {
		findings = append(findings, proxyFinding{Method: info.Name, File: info.File, Line: info.Line, Check: check, Detail: detail})
	}

	// Check 1: dropped inputs.
	for _, p := range droppedInputs(fn) {
		add("dropped-input", "parameter "+p+" is never referenced anywhere in the method body")
	}

	// Check 5: blank-identifier parameters (issue #1786 part 3).
	for _, typ := range blankParams(fn) {
		add("blank-identifier-param", "a parameter of type "+typ+" is declared with the blank identifier _ — "+
			"guaranteed unused by construction, and invisible to the dropped-input check above")
	}

	// Check 3: context substitution.
	if msg := contextSubstituted(fn, site); msg != "" {
		add("context-substitution", msg)
	}

	// Checks 2 and 4 need to know how the call's results are consumed.
	assign, ok := locateAssignment(fn, site)
	if !ok {
		add("swallowed-error", "could not locate a recognizable assignment or tail-return for this call site — "+
			"needs manual review, not silently assumed clean")
		return findings
	}
	if assign.isTailReturn {
		// `return <call>(...)` — Go's type system forwards every result,
		// including any error, verbatim. Sound by construction: no guard to
		// check, and no way for a zero+nil substitution to occur here.
		return findings
	}
	if len(assign.resultNames) == 0 {
		return findings
	}
	errVar := assign.resultNames[len(assign.resultNames)-1]
	if errVar == "_" {
		add("swallowed-error", "the call's error result is explicitly discarded with _")
		return findings
	}
	var respVar string
	if site.IsClient && len(assign.resultNames) >= 1 {
		respVar = assign.resultNames[0]
	}

	guards := findFailureGuards(assign, errVar, respVar)
	loopNote := ""
	if site.InLoop {
		loopNote = " (call site is inside a fan-out loop — this guard runs once per iteration, not once per method call)"
	}

	sawErrorGuard := false
	for _, g := range guards {
		if g.kind == "error" {
			sawErrorGuard = true
		}
		if !g.hasReturn {
			add("swallowed-error", g.kind+" guard does not end its block in a return — a later statement could "+
				"treat this as success"+loopNote)
			continue
		}
		if n := len(g.terminal.Results); n > 0 {
			if isIdentNil(g.terminal.Results[n-1]) {
				add("silent-zero-return", g.kind+" guard returns a literal nil error — contradicts the guard's own "+
					"condition, reports failure as success"+loopNote)
			}
		}
	}
	if !sawErrorGuard {
		add("swallowed-error", "call's error result ("+errVar+") has no `if "+errVar+" != nil` guard anywhere "+
			"in the rest of the block"+loopNote)
	}
	return findings
}

// runProxyCorrectnessAudit runs the full Layer 1 static audit over the real
// proxy population and returns every finding, sorted for stable output.
func runProxyCorrectnessAudit(t *testing.T) []proxyFinding {
	t.Helper()
	proxies := realProxyMethods(t)
	all := remoteStorageMethods(t)
	allNames := make(map[string]bool, len(all))
	for name := range all {
		allNames[name] = true
	}

	var findings []proxyFinding
	for _, info := range proxies {
		sites := directCallSites(info.Decl, allNames)
		for _, site := range sites {
			findings = append(findings, checkCallSite(info, site)...)
		}
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].File != findings[j].File {
			return findings[i].File < findings[j].File
		}
		return findings[i].Line < findings[j].Line
	})
	return findings
}

// TestRemoteProxyStaticAuditReport runs the Layer 1 static audit and reports
// every finding, unconditionally passing. Kept alongside the real gate below
// (TestLayer1StaticFindingsAreAllowlisted) purely so `go test -v -run
// TestRemoteProxyStaticAuditReport` gives a human a full findings dump
// without needing to fail a test to see it.
func TestRemoteProxyStaticAuditReport(t *testing.T) {
	findings := runProxyCorrectnessAudit(t)
	t.Logf("=== Layer 1 static audit: %d finding(s) across the 214-method real-proxy population ===", len(findings))
	for _, f := range findings {
		t.Logf("%s:%d %s [%s]: %s", f.File, f.Line, f.Method, f.Check, f.Detail)
	}
}

// proxyCorrectnessAllowlist is the exhaustive, reasoned inventory of every
// Layer 1 static-check finding reviewed and confirmed NOT a bug — mirroring
// remoteUnsupportedAllowlist's own shape (same file, same completeness-guard
// idiom): a finding not listed here fails TestLayer1StaticFindingsAreAllowlisted
// immediately; an entry that stops firing (fixed, or the checker regressed)
// also fails it, so this can't accumulate stale "known issue" entries that no
// longer reflect reality. Keyed by "Method:Check".
var proxyCorrectnessAllowlist = map[string]string{
	"GetSecretsByIDs:swallowed-error": "deliberate, documented fan-out policy (remote_secrets.go's own doc " +
		"comment on GetSecretsByIDs): an ID whose lookup fails is skipped rather than failing the whole batch. " +
		"The one caller (the rotation planner's risk-scoring batch, #409) already treats an ID missing from " +
		"the result the same conservative way a single GetSecret error is treated for that ID — never a " +
		"silent zero-risk score — so skipping here loses no safety margin. Reviewed, not a bug.",

	// The 8 entries below are check 5's first real run (issue #1786 part 3) —
	// found live, not hypothesized, and every one is the OPPOSITE shape from
	// the RemoveRoleFromGroup defect the check was built to catch: there, a
	// value the SERVER needed was silently blanked and never sent. Here, the
	// blanked value is one the server must NOT trust from the client at all
	// (a caller-supplied clock, or a caller-supplied identity the server
	// already derives authoritatively from the request's own auth context) —
	// blanking it is the correct, secure choice, kept only for interface
	// parity with LocalStorage's signature. Each already had a doc comment
	// saying so before this check existed.
	"ConsumeMFAChallenge:blank-identifier-param": "the blanked time.Time is \"now\": remote_mfa.go's own doc " +
		"comment says the upstream server ignores any caller-supplied current time and always uses its own " +
		"clock (mfaChallengeLookupWire) — accepting a client clock here would let a compromised/skewed client " +
		"manipulate expiry checks. Kept only for interface parity with LocalStorage. Reviewed, not a bug.",
	"GetActiveMFAChallenge:blank-identifier-param": "same reasoning and doc comment as ConsumeMFAChallenge " +
		"above (remote_mfa.go) — the blanked time.Time is a caller-supplied \"now\" the server must not trust. " +
		"Reviewed, not a bug.",
	"GetActiveMFAStepUpGrant:blank-identifier-param": "remote_mfa_stepup_grant.go's own doc comment: \"now is " +
		"accepted only for interface parity with LocalStorage — the upstream server ignores any caller-" +
		"supplied current time and always uses its own clock.\" Reviewed, not a bug.",
	"ConsumeWebAuthnSession:blank-identifier-param": "remote_webauthn.go's own doc comment: same \"now ignored, " +
		"server uses its own clock\" reasoning as the MFA challenge methods above (webAuthnSessionConsumeWire). " +
		"Reviewed, not a bug.",
	"ListNotifications:blank-identifier-param": "remote_notifications.go's own doc comment: GET /notifications " +
		"is self-scoped by the caller's authenticated session — \"userID is implicit in the endpoint\" " +
		"(fetchNotifications). A caller-supplied userID here would be a confused-deputy risk if the server " +
		"trusted it instead; blanking it is correct. Kept only for interface parity with LocalStorage. " +
		"Reviewed, not a bug.",
	"CountUnreadNotifications:blank-identifier-param": "same self-scoped-by-session reasoning as " +
		"ListNotifications above (remote_notifications.go, fetchNotifications). Reviewed, not a bug.",
	"MarkNotificationRead:blank-identifier-param": "remote_notifications.go's own doc comment: \"the server " +
		"scopes the mark to the authenticated user ... so userID is implicit in the endpoint.\" Same reasoning " +
		"as ListNotifications above. Reviewed, not a bug.",
	"MarkAllNotificationsRead:blank-identifier-param": "same self-scoped-by-session reasoning as " +
		"MarkNotificationRead above (remote_notifications.go). Reviewed, not a bug.",
}

// TestLayer1StaticFindingsAreAllowlisted is the CI gate (issue #1786 parts 2
// and 3): every Layer 1 finding across the 214-method real-proxy population
// must be explained by proxyCorrectnessAllowlist above, or this fails and
// forces the same real investigation this tranche did — trace the method,
// read its doc comment and callers, decide whether it's a genuine gap —
// before it can be merged. No new CI workflow wiring is needed for this: it
// runs as part of the existing `go test ./...` leg for this package, the
// same way every other completeness guard in this file already does.
//
// Renamed from TestRemoteProxyStaticAuditIsClean (issue #1786 part 2): that
// name's own word "Audit" and "IsClean" read as "the proxies were audited
// and found correct." They were not — see this file's own KNOWN NON-COVERAGE
// section above. What this test actually verifies is narrower and stated
// directly in the new name: every finding the five checks above produce is
// EXPLAINED (allowlisted, with a reason), nothing more. A green result here
// says "no unexplained hit on five narrow syntactic properties" — it does
// not say "these proxies are correct," and a name implying otherwise is
// exactly the framing mistake issue #1786 was filed to fix.
func TestLayer1StaticFindingsAreAllowlisted(t *testing.T) {
	findings := runProxyCorrectnessAudit(t)

	seen := map[string]bool{}
	var unexplained []proxyFinding
	for _, f := range findings {
		key := f.Method + ":" + f.Check
		if _, ok := proxyCorrectnessAllowlist[key]; ok {
			seen[key] = true
			continue
		}
		unexplained = append(unexplained, f)
	}

	if len(unexplained) > 0 {
		var lines []string
		for _, f := range unexplained {
			lines = append(lines, fmt.Sprintf("%s:%d %s [%s]: %s", f.File, f.Line, f.Method, f.Check, f.Detail))
		}
		t.Errorf("%d unexplained Layer 1 static-check finding(s) — trace each method's real caller(s) and "+
			"decide: fix it, or add a reasoned proxyCorrectnessAllowlist entry citing why it's safe:\n%s",
			len(unexplained), strings.Join(lines, "\n"))
	}

	var stale []string
	for key, reason := range proxyCorrectnessAllowlist {
		if !seen[key] {
			stale = append(stale, key+" ("+reason+")")
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		t.Errorf("%d proxyCorrectnessAllowlist entr(y/ies) no longer fire — remove them if fixed, or "+
			"investigate why the checker stopped seeing them: %v", len(stale), stale)
	}
}
