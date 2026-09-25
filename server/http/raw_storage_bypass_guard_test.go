// raw_storage_bypass_guard_test.go — #1542's guard: a node-credential-gated
// proxy handler that calls h.coreService.Storage().X(...) directly, when
// internal/core ALSO has an exported KeyorixCore method that calls
// c.storage.X(...) itself, is exactly the shape that let AssignRoleWithExpiryProxy/
// AssignRoleToGroupWithExpiryProxy/AssignMachineRoleProxy/RemoveAllProjectRoleGrantsProxy
// bypass every real ceiling (requireGranterHoldsRolePermissions, requireAuthorityForRole,
// guardLastProjectAdmin) for any system.write holder, human or machine -- the
// handler wasn't taking the storage-primitive-name-matches-a-core-method-name
// coincidence as a signal that a real policy path exists for that operation.
//
// Scope: EVERY route in router.go (extractAllRouterRoutes), repo-wide -- not the
// 18-route classifiedNodeCredentialRoutes subset this guard originally shipped
// with, and not the /api/v1/system-only scope it was later widened to. That
// narrower 18-route scope was #1547's own finding: a repo-wide re-run of this
// exact detection logic found 149 flagged call sites (an estimate later corrected
// to 145 -- see docs/g80-raw-storage-bypass-enumeration.md for the reproducible
// count and why the original 149/59 figures don't hold up), 87 of them read-shaped
// (Get*/List*/Count*/Export*, mechanically excludable -- a read confers no new
// access, so there's no ceiling to bypass) and 58 write-shaped. #1545 and #1546
// were both found BY HAND in code the 18-route scope didn't watch -- direct
// evidence the narrowing lost real coverage.
//
// G80 Wave 1 (#1547): widened from /system-only to every route in router.go.
// Re-running the SAME detection logic (exportedCoreStorageWrappers +
// handlerStorageCalls + isReadShapedStorageMethod) against all 504 distinct
// handlers repo-wide (extractAllRouterRoutes, 527 total route registrations)
// found exactly ONE handler outside /system flagged: ConsumeMFAChallenge
// (users.write-gated, router.go:874) -- already independently triaged and
// verified safe (docs/g80-raw-storage-bypass-triage.md, "VERIFIED
// 2026-08-25... holds": consuming the MFA challenge alone yields only an
// unguessable UserID/expiry pair, real assertion/crypto verification runs
// AFTER consume, and the route requires an already-authenticated
// users.write-holding principal to reach at all). Added to
// rawStorageBypassAllowlist below. No other repo-wide handler was newly
// flagged -- the /system-scoped classification below already covers every
// OTHER write-shaped wrapped call site that exists anywhere in the router.
//
// An overnight session (2026-08-23/24) individually triaged all 58: full results
// in docs/g80-raw-storage-bypass-triage.md. One of the 58 (ConsumeMFAChallenge)
// turned out to be registered OUTSIDE the /system group entirely (users.write-gated,
// router.go:874) and is not tracked by this guard -- it stays documented purely in
// the triage doc. The other 57 are ALL within /system and are grandfathered below,
// split into two lists with different meanings:
//
//   - rawStorageBypassAllowlist: REVIEWED AND SAFE. No real gap -- either no
//     independent ceiling exists to bypass, or a deliberate, reasoned exception.
//     Adding an entry here is a claim the call site is fine, not a promise to fix
//     it later.
//   - knownUnfixedRawStorageBypasses: REVIEWED AND NOT SAFE. A genuine ceiling
//     bypass, confirmed real and (for all but one) human-reachable, tracked but
//     NOT yet fixed. Grandfathered so this guard can go live immediately without
//     waiting for all 10+1 to be remediated first -- exactly the
//     knownUnresolvedWireCalls / knownMissingRoutes pattern
//     (internal/storage/store/remote_wire_route_coverage_test.go): name every
//     known-bad instance explicitly so instance #58 (a NEW bypass) cannot be added
//     silently while the existing backlog is worked down, and so a listed entry
//     that gets fixed and forgotten shows up as stale instead of just staying
//     silently correct forever.
//
// Update 2026-08-25 (ADR-085, Accepted): the node-credential OR-arm these
// counts assumed as a permanent second axis is removed -- every
// knownUnfixedRawStorageBypasses entry whose ONLY remaining gap was "STILL
// OPEN for a node-credential caller" is now either moved to
// rawStorageBypassAllowlist (CreateSetupTokenProxy,
// CreateMachineIdentityCredentialProxy: still make a flagged raw call, but
// the real check now runs unconditionally) or removed outright
// (CreateOIDCBindingProxy, DeleteOIDCBindingProxy,
// RemoveGlobalAdminRoleGuardedProxy, RevokeAllPersonalAccessTokensForUserProxy,
// DeleteSessionsForUserExceptProxy: now routed through the wrapping core
// method instead of a raw storage call, so they no longer trip this guard at
// all). RevokeMachineIdentityCredentialProxy stays in
// knownUnfixedRawStorageBypasses -- #1551's cross-tenant gap is unaffected;
// only the node-credential axis into it closed.
//
// TestNoUnjustifiedRawStorageBypass fails on: (a) any /system handler with an
// unreviewed write-shaped raw storage call, wrapped or not (a brand new
// instance of the #1542 shape, or ADR-088's "no wrapper" shape -- see below),
// (b) any listed entry whose handler no longer exists under /system, or (c)
// any listed entry whose handler no longer makes ANY flagged write-shaped
// call (fixed and forgotten -- remove it from whichever list it's in, or
// move it from knownUnfixedRawStorageBypasses to rawStorageBypassAllowlist
// with a reason if the fix landed here first).
//
// Recognized call forms (G80 Wave 2, closing this guard's two known blind
// spots -- ADR-088): this guard has two halves, each with its own doc
// comment naming exactly what it recognizes and why that list is complete --
// directStorageCalls below (the internal/core side, building the `wrapped`
// set: recv.storage.X(...), a one-hop unexported sibling, and any
// storage.Storage-typed identifier including a WithTransaction closure's
// `tx` parameter, to any nesting depth) and handlerStorageCalls further down
// (the server/http/handlers side, building what a given handler calls:
// h.coreService.Storage().X(...) and the local-alias form, with the
// struct-field-wrapper and parameterized-helper forms confirmed absent by
// grep rather than assumed). Read those two comments for the full
// derivation before changing either function.
package http

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
)

// routerRoute and normalizeRouterPath originated in
// node_credential_route_classification_test.go (deleted with the ADR-108
// Phase 6 /system proxy tier removal, along with extractSystemGroupRoutes,
// its /system-scoped route extractor); kept here since this file's own
// repo-wide extractAllRouterRoutes still needs them.
type routerRoute struct {
	Method  string
	Path    string
	Handler string // e.g. "AssignRoleWithExpiryProxy" -- the handler method name, not the receiver
}

func unquoteRouterLit(lit string) (string, bool) {
	if len(lit) >= 2 && lit[0] == '"' {
		return lit[1 : len(lit)-1], true
	}
	return "", false
}

func normalizeRouterPath(p string) string {
	// #1511's guard also collapses {param} to "*" for wire-call comparison;
	// this guard keeps params literal (chi's own {id}/{roleId} names) since
	// it only ever compares router.go against itself, never against a
	// client-side Sprintf-built path.
	if len(p) > 1 && strings.HasSuffix(p, "/") {
		p = p[:len(p)-1]
	}
	return p
}

// extractAllRouterRoutes returns every (method, path, handler) registration
// anywhere in router.go. G80 Wave 1 (#1547): re-measuring
// TestNoUnjustifiedRawStorageBypass's detection logic against every handler in
// server/http/handlers (not just the /system group's ~194 routes) found
// exactly ONE new candidate outside what the /system-scoped guard already
// covers — ConsumeMFAChallenge (users.write-gated, router.go, outside
// /system) — already independently triaged and verified safe
// (docs/g80-raw-storage-bypass-triage.md line 100, "VERIFIED 2026-08-25...
// holds"), now added to rawStorageBypassAllowlist below. The other 503
// distinct handlers repo-wide either don't call a wrapped write-shaped
// storage method at all, or are already covered by the existing /system
// classification. This function drives TestNoUnjustifiedRawStorageBypass's
// permanent repo-wide scope; it originated as the /system-scoped guard's
// repo-wide sibling, but the /system-scoped guard itself is gone (ADR-108
// Phase 6) — this is now the only route extractor in this package.
func extractAllRouterRoutes(t *testing.T, path string) []routerRoute {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parsing %s: %v", path, err)
	}

	constPaths := map[string]string{}
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok || len(vs.Names) != 1 || len(vs.Values) != 1 {
				continue
			}
			lit, ok := vs.Values[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				continue
			}
			if s, ok := unquoteRouterLit(lit.Value); ok {
				constPaths[vs.Names[0].Name] = s
			}
		}
	}

	var resolvePathArg func(arg ast.Expr) (string, bool)
	resolvePathArg = func(arg ast.Expr) (string, bool) {
		switch e := arg.(type) {
		case *ast.BasicLit:
			if e.Kind != token.STRING {
				return "", false
			}
			return unquoteRouterLit(e.Value)
		case *ast.Ident:
			s, ok := constPaths[e.Name]
			return s, ok
		case *ast.BinaryExpr:
			if e.Op != token.ADD {
				return "", false
			}
			l, lok := resolvePathArg(e.X)
			r, rok := resolvePathArg(e.Y)
			if !lok || !rok {
				return "", false
			}
			return l + r, true
		}
		return "", false
	}

	var routes []routerRoute
	httpMethods := map[string]string{"Get": "GET", "Post": "POST", "Put": "PUT", "Patch": "PATCH", "Delete": "DELETE"}

	var walkBlock func(prefix string, body *ast.BlockStmt, depth int)
	var walkCall func(prefix string, expr ast.Expr, depth int)

	walkBlock = func(prefix string, body *ast.BlockStmt, depth int) {
		if body == nil {
			return
		}
		for _, stmt := range body.List {
			exprStmt, ok := stmt.(*ast.ExprStmt)
			if !ok {
				continue
			}
			walkCall(prefix, exprStmt.X, depth)
		}
	}

	walkCall = func(prefix string, expr ast.Expr, depth int) {
		call, ok := expr.(*ast.CallExpr)
		if !ok {
			return
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return
		}
		switch sel.Sel.Name {
		case "Route", "Group":
			var sub *ast.FuncLit
			var subPrefix string
			if sel.Sel.Name == "Route" {
				if len(call.Args) != 2 {
					return
				}
				p, ok := resolvePathArg(call.Args[0])
				if !ok {
					return
				}
				subPrefix = prefix + p
				lit, ok := call.Args[1].(*ast.FuncLit)
				if !ok {
					return
				}
				sub = lit
			} else {
				if len(call.Args) != 1 {
					return
				}
				lit, ok := call.Args[0].(*ast.FuncLit)
				if !ok {
					return
				}
				sub = lit
				subPrefix = prefix
			}
			walkBlock(subPrefix, sub.Body, depth+1)
		case "Get", "Post", "Put", "Patch", "Delete":
			if len(call.Args) < 2 {
				return
			}
			p, ok := resolvePathArg(call.Args[0])
			if !ok {
				return
			}
			handlerName := ""
			if hsel, ok := call.Args[1].(*ast.SelectorExpr); ok {
				handlerName = hsel.Sel.Name
			}
			routes = append(routes, routerRoute{Method: httpMethods[sel.Sel.Name], Path: normalizeRouterPath(prefix + p), Handler: handlerName})
		}
		if _, known := httpMethods[sel.Sel.Name]; !known && sel.Sel.Name != "Route" && sel.Sel.Name != "Group" {
			// r.With(mw...).Post(...) -- recurse into the X of the outer selector
			// as if it were its own call chain root, so the wrapped call is
			// still found regardless of how many With(...) links precede it.
			if inner, ok := sel.X.(*ast.CallExpr); ok {
				walkCall(prefix, inner, depth)
			}
			return
		}
	}

	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		walkBlock("", fn.Body, 0)
	}

	// Threshold lowered from 400 (router.go registered 500+) with the ADR-108
	// Phase 6 /system proxy tier deletion (~151 routes removed); router.go
	// now registers ~350-380. Kept well below that, not raised to a tight
	// bound, so this sanity check still does its one job -- catching a
	// silently-broken AST walk (which would find close to zero) -- without
	// needing another edit on every ordinary future route addition/removal.
	if len(routes) < 300 {
		t.Fatalf("extractAllRouterRoutes found only %d routes -- the AST walk likely broke silently "+
			"(router.go registers 350+); fix the walker before trusting this guard", len(routes))
	}
	return routes
}

// keyorixCoreMethod is one (c *KeyorixCore) method's declaration plus the name
// its receiver is bound to (varies per method, e.g. "c" almost everywhere but
// not guaranteed) -- needed to recognize both c.storage.X(...) and c.foo(...)
// calls correctly regardless of which identifier the method happens to use.
type keyorixCoreMethod struct {
	fd       *ast.FuncDecl
	recvName string
}

// keyorixCoreMethods indexes every (c *KeyorixCore) method in internal/core
// (exported or not) by name, for the one-hop same-package call-graph walk
// exportedCoreStorageWrappers needs.
func keyorixCoreMethods(t *testing.T) map[string]keyorixCoreMethod {
	t.Helper()
	fset := token.NewFileSet()
	methods := map[string]keyorixCoreMethod{}
	dir := filepath.Join("..", "..", "internal", "core")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading internal/core: %v", err)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Recv == nil || len(fd.Recv.List) != 1 || fd.Body == nil {
				continue
			}
			star, ok := fd.Recv.List[0].Type.(*ast.StarExpr)
			if !ok {
				continue
			}
			id, ok := star.X.(*ast.Ident)
			if !ok || id.Name != "KeyorixCore" || len(fd.Recv.List[0].Names) == 0 {
				continue
			}
			methods[fd.Name.Name] = keyorixCoreMethod{fd: fd, recvName: fd.Recv.List[0].Names[0].Name}
		}
	}
	return methods
}

func identSel(e ast.Expr) (recv, sel string, ok bool) {
	se, isSel := e.(*ast.SelectorExpr)
	if !isSel {
		return "", "", false
	}
	id, isIdent := se.X.(*ast.Ident)
	if !isIdent {
		return "", "", false
	}
	return id.Name, se.Sel.Name, true
}

// storageTypedParamNames returns the names of every parameter in fl declared
// with the exact type storage.Storage. This is ONE fact spelled two ways in
// this codebase: a WithTransaction closure's own parameter
// (func(tx storage.Storage) error) and a named helper's transaction-handle
// parameter (transitionMachineInTx(ctx context.Context, tx storage.Storage,
// ...), scimUpdateUserTx, persistAuditRetentionAnchor) are both "an
// identifier bound to a storage.Storage value," so both are recognized by
// this one function rather than two separate special cases.
func storageTypedParamNames(fl *ast.FieldList) map[string]bool {
	names := map[string]bool{}
	if fl == nil {
		return names
	}
	for _, field := range fl.List {
		sel, ok := field.Type.(*ast.SelectorExpr)
		if !ok {
			continue
		}
		pkgIdent, ok := sel.X.(*ast.Ident)
		if !ok || pkgIdent.Name != "storage" || sel.Sel.Name != "Storage" {
			continue
		}
		for _, n := range field.Names {
			names[n.Name] = true
		}
	}
	return names
}

// directStorageCalls returns every storage method name reachable from fd's
// body through a storage.Storage-typed identifier. Three call forms collapse
// into one mechanism here (see this file's "Recognized call forms" comment
// above TestNoUnjustifiedRawStorageBypass for the full derivation):
//
//   - `<recvName>.storage.<Method>(...)` -- the receiver's own storage field.
//   - `<param>.<Method>(...)` where <param> is one of fd's OWN parameters
//     declared storage.Storage -- the transitionMachineInTx/scimUpdateUserTx/
//     persistAuditRetentionAnchor shape: a same-receiver helper that
//     receives a transaction handle rather than reading c.storage itself.
//   - `<param>.<Method>(...)` where <param> is the parameter of a nested
//     `func(tx storage.Storage) error` literal passed to WithTransaction --
//     the ActivateMFA/DisableMFA/RegenerateMFARecoveryCodes/
//     PurgeExpiredSoftDeletes shape: the closure body IS the call site, no
//     separate named helper exists to find as a "sibling."
//
// All three are the same underlying fact (an identifier of type
// storage.Storage), tracked uniformly by walking the body with a live set of
// such identifiers that gets EXTENDED (not replaced -- Go closures capture
// the enclosing scope) on entering a nested FuncLit, recursively, to any
// depth. No depth limit is imposed here, unlike the one-hop sibling-method
// limit in exportedCoreStorageWrappers below: that limit exists to bound a
// call-GRAPH search across many methods, which is a real combinatorial
// concern; this is a lexical-scope walk within a single function body, which
// is not.
func directStorageCalls(fd *ast.FuncDecl, recvName string) []string {
	var found []string
	walkForStorageCalls(fd.Body, recvName, storageTypedParamNames(fd.Type.Params), &found)
	return found
}

// walkForStorageCalls implements directStorageCalls' walk (see its doc
// comment) as a standalone function so it can recurse into nested FuncLits
// with an extended identifier set without re-deriving fd's own parameters.
func walkForStorageCalls(n ast.Node, recvName string, storageIdents map[string]bool, found *[]string) {
	ast.Inspect(n, func(node ast.Node) bool {
		if lit, ok := node.(*ast.FuncLit); ok {
			nested := storageIdents
			if params := storageTypedParamNames(lit.Type.Params); len(params) > 0 {
				nested = make(map[string]bool, len(storageIdents)+len(params))
				for k := range storageIdents {
					nested[k] = true
				}
				for k := range params {
					nested[k] = true
				}
			}
			walkForStorageCalls(lit.Body, recvName, nested, found)
			return false // walked manually above with the (possibly extended) set; don't double-visit
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if innerRecv, innerSel, ok := identSel(sel.X); ok && innerRecv == recvName && innerSel == "storage" {
			*found = append(*found, sel.Sel.Name)
			return true
		}
		if id, ok := sel.X.(*ast.Ident); ok && storageIdents[id.Name] {
			*found = append(*found, sel.Sel.Name)
		}
		return true
	})
}

// calledSiblingMethods returns the names of every same-receiver KeyorixCore
// method called as `<recvName>.<name>(...)` in fd's body (both exported and
// unexported -- the caller decides which to follow further).
func calledSiblingMethods(fd *ast.FuncDecl, recvName string, all map[string]keyorixCoreMethod) []string {
	var found []string
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		id, ok := sel.X.(*ast.Ident)
		if !ok || id.Name != recvName {
			return true
		}
		if _, exists := all[sel.Sel.Name]; exists {
			found = append(found, sel.Sel.Name)
		}
		return true
	})
	return found
}

// exportedCoreStorageWrappers returns every storage.Storage method name
// reachable from an EXPORTED (c *KeyorixCore) method within ONE hop through
// an UNEXPORTED same-receiver sibling method -- i.e., a real, reachable
// core-level path exists for that storage primitive, not just an incidental
// reference from an unexported helper no handler could ever be near.
//
// G80 Wave 1 (#1547): rewritten from a regex/brace-depth line scan (which
// only ever looked at an exported method's OWN body) to a real AST walk with
// one-hop delegation-following, porting the fix
// scripts/analysis/raw_storage_bypass_enumerate.go already had (added
// 2026-08-25, G80 documented-exception re-verification sweep) into the
// LIVE, CI-enforced guard, which never received it -- the guard was passing
// green on a wrapped-method set that missed core.InviteMember ->
// inviteMemberWithMode (unexported) -> c.storage.CreateProjectMembership,
// so CreateMembershipProxy's raw call to that exact primitive was invisible
// to this test the whole time it existed, not classified either way. One hop
// only, deliberately: docs/g80-raw-storage-bypass-enumeration.md measured an
// unlimited-depth variant against the same tree and found zero additional
// write-shaped candidates beyond one hop (11 more read-shaped methods only,
// already excluded regardless of depth) -- a second hop would add real
// implementation cost (cycle detection for mutually-recursive unexported
// helpers) for zero additional security-relevant findings today.
func exportedCoreStorageWrappers(t *testing.T) map[string]bool {
	t.Helper()
	all := keyorixCoreMethods(t)
	wrapped := map[string]bool{}
	for name, m := range all {
		if !isExportedCoreMethodName(name) {
			continue
		}
		for _, method := range directStorageCalls(m.fd, m.recvName) {
			wrapped[method] = true
		}
		for _, siblingName := range calledSiblingMethods(m.fd, m.recvName, all) {
			if isExportedCoreMethodName(siblingName) {
				continue // one hop only -- an exported sibling is scanned on its own as a top-level entry anyway
			}
			sibling := all[siblingName]
			for _, method := range directStorageCalls(sibling.fd, sibling.recvName) {
				wrapped[method] = true
			}
		}
	}
	return wrapped
}

func isExportedCoreMethodName(name string) bool {
	return len(name) > 0 && name[0] >= 'A' && name[0] <= 'Z'
}

// handlerStorageCalls returns the set of storage.Storage method names called
// from within the named handler method's body, searched across every
// non-test *.go file in server/http/handlers. Rewritten from a regex/brace-
// depth line scan to an AST walk (G80 Wave 2, guard blind-spot closure): a
// regex can't state what it does NOT match, an AST walk's recognized node
// shapes can be named and reviewed. Two forms are recognized:
//
//   - `h.coreService.Storage().X(...)` -- the chained form every real
//     handler in this codebase currently uses.
//   - `v := h.coreService.Storage(); v.X(...)` -- a local alias, then a call
//     through it.
//
// No third form exists today: confirmed by two independent checks -- a
// literal grep for the alias-assignment shape (`:= h.coreService.Storage()`)
// across server/http/handlers found zero hits, and this same AST walk (which
// would catch it structurally, not by pattern-matching the specific spelling)
// also finds zero. storage.Storage is never used as an explicit parameter or
// struct field anywhere in server/http/handlers either (confirmed by grep),
// so the transaction-handle and struct-field forms tracked on the
// internal/core side (see directStorageCalls above) have no handler-side
// counterpart to track. If a handler is ever written using either, this
// function will not see it -- tracked here as a stated, checked absence, not
// an unstated assumption.
// handlerStorageCallsOnce/Cache/Err memoize buildHandlerStorageCallsIndex: both
// TestNoUnjustifiedRawStorageBypass and TestNoProxyCallsUnsafeSiblingWhenSafeExists
// call handlerStorageCalls once per distinct handler (504 of them, per this file's
// own doc comment) — a naive per-call re-parse of the whole handlers directory made
// those two tests server/http's single largest cost (181.7s + 112.3s of a 1417.9s
// package run, see reports/CI.md). Parsing the directory is deterministic and pure
// (same files, same AST, same per-handler result every call), so hoisting it to run
// once per test-binary process changes nothing about what either test checks.
var (
	handlerStorageCallsOnce  sync.Once
	handlerStorageCallsCache map[string][]string
	handlerStorageCallsErr   error
)

func handlerStorageCalls(t *testing.T, handlerName string) []string {
	t.Helper()
	handlerStorageCallsOnce.Do(func() {
		handlerStorageCallsCache, handlerStorageCallsErr = buildHandlerStorageCallsIndex()
	})
	if handlerStorageCallsErr != nil {
		// Every caller re-checks and Fatalf's itself (rather than caching a fatal
		// inside the Once body) so a build failure is correctly attributed to
		// whichever test is running, not silently swallowed by Once after the
		// first caller's t.Fatalf unwinds via runtime.Goexit.
		t.Fatalf("building handler storage-call index: %v", handlerStorageCallsErr)
	}
	return handlerStorageCallsCache[handlerName]
}

// buildHandlerStorageCallsIndex parses every non-test .go file in
// server/http/handlers exactly once and maps each method's name to the
// write-shaped-eligible storage calls found in its body (accumulating across
// files/decls if more than one method shares a name, matching this index's prior
// per-call behavior exactly).
func buildHandlerStorageCallsIndex() (map[string][]string, error) {
	dir := filepath.Join("..", "..", "server", "http", "handlers")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading server/http/handlers: %w", err)
	}
	fset := token.NewFileSet()
	index := map[string][]string{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if err != nil {
			return nil, fmt.Errorf("parsing %s: %w", name, err)
		}
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Recv == nil || fd.Body == nil {
				continue
			}
			calls := handlerBodyStorageCalls(fd.Body)
			if len(calls) > 0 {
				index[fd.Name.Name] = append(index[fd.Name.Name], calls...)
			}
		}
	}
	return index, nil
}

// handlerBodyStorageCalls recognizes the two forms documented on
// handlerStorageCalls above within a single handler body.
func handlerBodyStorageCalls(body *ast.BlockStmt) []string {
	var found []string
	aliases := map[string]bool{}
	ast.Inspect(body, func(n ast.Node) bool {
		if assign, ok := n.(*ast.AssignStmt); ok && len(assign.Lhs) == len(assign.Rhs) {
			for i, rhs := range assign.Rhs {
				call, ok := rhs.(*ast.CallExpr)
				if !ok {
					continue
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "Storage" {
					continue
				}
				if id, ok := assign.Lhs[i].(*ast.Ident); ok {
					aliases[id.Name] = true
				}
			}
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if inner, ok := sel.X.(*ast.CallExpr); ok {
			if innerSel, ok := inner.Fun.(*ast.SelectorExpr); ok && innerSel.Sel.Name == "Storage" {
				found = append(found, sel.Sel.Name)
				return true
			}
		}
		if id, ok := sel.X.(*ast.Ident); ok && aliases[id.Name] {
			found = append(found, sel.Sel.Name)
		}
		return true
	})
	return found
}

// readShapedStoragePrefixes are storage-method name prefixes mechanically
// excluded as read-shaped: a read confers no new access, so there's no ceiling
// to bypass. This is a pure naming heuristic with known gaps in both directions
// -- see docs/g80-raw-storage-bypass-blind-spots.md category (d) -- accepted for
// this guard's scope rather than re-litigated here.
var readShapedStoragePrefixes = []string{"Get", "List", "Count", "Export"}

func isReadShapedStorageMethod(method string) bool {
	for _, p := range readShapedStoragePrefixes {
		if strings.HasPrefix(method, p) {
			return true
		}
	}
	return false
}

// rawStorageBypassAllowlist is the exhaustive, reasoned inventory of every
// /system handler that calls h.coreService.Storage().X(...) directly for a
// write-shaped storage method X that ALSO has an exported internal/core
// wrapper, and has been individually reviewed as SAFE -- i.e., every currently-
// accepted "the wrapper exists but this call site deliberately doesn't use it,
// and that's fine" case. Each entry needs a reason; TestNoUnjustifiedRawStorageBypass
// fails if a route not in this list (or in knownUnfixedRawStorageBypasses) is
// found calling a wrapped storage method (the #1542 shape recurring), or if a
// listed entry no longer applies (fixed and forgotten).
// rawStorageBypassAllowlist retired its 31 /system-proxy-handler entries with
// the ADR-108 Phase 6 /system proxy tier deletion -- each one's target
// handler no longer exists, so the raw-storage-bypass question this map
// answers ("is this handler's ceiling actually correct?") no longer applies.
// The detailed per-entry security reasoning (escalation-delta tests, fix
// commits, adversarial checks) is preserved in git history for this file, not
// lost -- see the pre-Phase-6 revision if any of it is ever needed again.
// ConsumeMFAChallenge is kept: it is NOT a /system proxy (a human-facing
// route gated by Authentication + users.write, router.go) and is unaffected.
var rawStorageBypassAllowlist = map[string]string{
	// G80 Wave 1 (#1547): the one new candidate the repo-wide extension found,
	// outside /system. VERIFIED 2026-08-25 (G80 documented-exception
	// re-verification sweep, escalation-delta test), docs/g80-raw-storage-
	// bypass-triage.md line 100: consuming the MFA challenge alone yields only
	// UserID/expiry (generateSecureToken-minted, crypto/rand, unguessable) --
	// the real assertion/crypto verification and session binding all run in
	// FinishWebAuthnLogin/VerifyMFACredentials, AFTER consume. Atomicity
	// confirmed at the storage layer (local_mfa.go:123-148, a genuine
	// conditional UPDATE ... WHERE used_at IS NULL AND expires_at > ?, not a
	// plain unconditional write). Reach: gated by the full /api/v1
	// Authentication middleware (server/middleware/auth.go:253) PLUS
	// users.write (router.go:300,874), both of which run BEFORE this handler
	// -- a user mid-login holds only the ephemeral MFA-challenge secret, not
	// a session/PAT/machine/OIDC credential, so they cannot reach this route
	// at all. Reachable only by an already-fully-authenticated,
	// users.write-holding principal (machine-only in the intended hub-spoke
	// design), not human-mid-login-reachable despite the name suggesting
	// otherwise.
	"ConsumeMFAChallenge": "holds: consume alone yields only an unguessable UserID/expiry pair; real crypto/" +
		"assertion verification runs downstream in FinishWebAuthnLogin/VerifyMFACredentials; storage-layer " +
		"atomicity confirmed (local_mfa.go:123-148, conditional UPDATE); gated by full Authentication middleware " +
		"+ users.write, both running before this handler, so a mid-login (unauthenticated) caller cannot reach it.",
}

// knownUnfixedRawStorageBypasses retired both its entries (CreateMembershipProxy,
// IngestAuditEventProxy) with the ADR-108 Phase 6 /system proxy tier deletion --
// both handlers no longer exist. See git history for the full per-entry
// severity/reachability reasoning.
var knownUnfixedRawStorageBypasses = map[string]string{}

// TestNoUnjustifiedRawStorageBypass is #1542's guard, widened by #1547 to cover
// every route in router.go, repo-wide (not just the 18-route subset this guard
// originally shipped with, and not just the /api/v1/system group it was later
// widened to): for every such route, if its handler calls
// h.coreService.Storage().X(...) for a write-shaped storage method X, that
// handler must have an entry in rawStorageBypassAllowlist (reviewed safe) or
// knownUnfixedRawStorageBypasses (reviewed real, tracked, not yet fixed)
// explaining why. A newly-added route (or a regression in an already-fixed
// one) that reintroduces this shape fails immediately, instead of waiting for
// the next manual audit round to notice -- and neither list can silently
// drift from reality: a stale entry (handler gone, or the flagged call site
// no longer reproduces) fails too.
//
// Second blind spot closed (G80 Wave 2, ADR-088): this test used to skip a
// storage method entirely when wrapped[storageMethod] was false -- "no
// exported core wrapper exists for this" was read as "nothing to bypass, so
// nothing to review." That inference is false. ADR-088's #1585/#1586/#1587
// are exactly the counter-examples: internal/core deliberately offers no
// wrapper for the raw shape those three handlers use, BECAUSE the safe
// operation looks different (a conditional transition, not a blind write) --
// the absence of a wrapper was core correctly refusing an unsafe primitive,
// and the proxies calling that unsafe primitive directly were the bug. A
// handler calling storage with no wrapper in sight is not safer than one
// calling a wrapped method without going through the wrapper -- it is more
// direct, and it still needs someone to say why that's fine. So every
// write-shaped raw call now requires a list entry, wrapped or not; the two
// lists' existing "no-independent-ceiling" reasoning already covers the
// unwrapped case (it was always framed as "there's nothing for this call to
// bypass," which doesn't logically depend on a wrapper existing) -- only the
// SKIP was wrong, not the classification vocabulary.
func TestNoUnjustifiedRawStorageBypass(t *testing.T) {
	wrapped := exportedCoreStorageWrappers(t)
	routerPath := filepath.Join(".", "router.go")
	actual := extractAllRouterRoutes(t, routerPath)

	// handlerFlagged[handler] = true iff that handler currently makes at least one
	// write-shaped raw storage call, wrapped or not (see the blind-spot-2 note above).
	handlerFlagged := map[string]bool{}
	seenHandlers := map[string]bool{}
	var flagged []string
	for _, r := range actual {
		if r.Handler == "" || seenHandlers[r.Handler] {
			continue
		}
		seenHandlers[r.Handler] = true
		for _, storageMethod := range handlerStorageCalls(t, r.Handler) {
			if isReadShapedStorageMethod(storageMethod) {
				continue
			}
			handlerFlagged[r.Handler] = true
			_, safe := rawStorageBypassAllowlist[r.Handler]
			_, unfixed := knownUnfixedRawStorageBypasses[r.Handler]
			if safe || unfixed {
				continue
			}
			reason := "internal/core has an exported method that also wraps " + storageMethod
			if !wrapped[storageMethod] {
				reason = "internal/core has NO exported wrapper for " + storageMethod + " at all -- absence of a " +
					"wrapper is not evidence of safety, it means nobody has stated why this raw call needs no ceiling"
			}
			flagged = append(flagged, r.Handler+" calls Storage()."+storageMethod+"(...) directly, but "+reason)
		}
	}
	sort.Strings(flagged)

	if len(flagged) > 0 {
		t.Errorf("found %d handler(s) making an unreviewed write-shaped raw storage call (the #1542 shape, "+
			"wrapped or not -- see this test's own doc comment for why unwrapped calls are in scope too): %v\n"+
			"Either route the handler through a core method that applies the right ceiling, or add a reasoned "+
			"entry to rawStorageBypassAllowlist (if genuinely safe) or knownUnfixedRawStorageBypasses (if it's a "+
			"real, tracked, not-yet-fixed gap) in this file.", len(flagged), flagged)
	}

	// Staleness: an allowlist/unfixed-list entry is stale if its handler is no
	// longer registered under /system at all, or if it no longer makes any
	// flagged write-shaped wrapped call (fixed and forgotten).
	checkStale := func(listName string, m map[string]string) {
		var stale []string
		for handler := range m {
			found := false
			for _, r := range actual {
				if r.Handler == handler {
					found = true
					break
				}
			}
			if !found {
				stale = append(stale, handler+" (no longer registered anywhere in router.go)")
				continue
			}
			if !handlerFlagged[handler] {
				stale = append(stale, handler+" (no longer makes a flagged write-shaped wrapped storage call)")
			}
		}
		sort.Strings(stale)
		if len(stale) > 0 {
			t.Errorf("%s entr(y/ies) no longer reproduce: %v\nRemove the entry, or move it to the other list if "+
				"its status changed (e.g. a real gap just got fixed).", listName, stale)
		}
	}
	checkStale("rawStorageBypassAllowlist", rawStorageBypassAllowlist)
	checkStale("knownUnfixedRawStorageBypasses", knownUnfixedRawStorageBypasses)
}
