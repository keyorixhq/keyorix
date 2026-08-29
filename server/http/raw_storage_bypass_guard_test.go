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
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// extractAllRouterRoutes is extractSystemGroupRoutes' repo-wide sibling: every
// (method, path, handler) registration anywhere in router.go, not just inside
// r.Route("/system", ...). G80 Wave 1 (#1547): re-measuring
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
// permanent repo-wide scope going forward — extractSystemGroupRoutes stays,
// unchanged, for node_credential_route_classification_test.go's narrower
// 18-route node-credential classification, which is a different question
// (is this route reachable by a bare node credential) than this guard's (does
// this handler bypass a wrapped core ceiling).
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

	if len(routes) < 400 {
		t.Fatalf("extractAllRouterRoutes found only %d routes -- the AST walk likely broke silently "+
			"(router.go registers 500+); fix the walker before trusting this guard", len(routes))
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
func handlerStorageCalls(t *testing.T, handlerName string) []string {
	t.Helper()
	dir := filepath.Join("..", "..", "server", "http", "handlers")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading server/http/handlers: %v", err)
	}
	fset := token.NewFileSet()
	var calls []string
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
			if !ok || fd.Name.Name != handlerName || fd.Recv == nil || fd.Body == nil {
				continue
			}
			calls = append(calls, handlerBodyStorageCalls(fd.Body)...)
		}
	}
	return calls
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
var rawStorageBypassAllowlist = map[string]string{
	// G80 Wave 2 (#1572, ADR-088): the raw Storage().UpdateUserIfActiveStateMatches
	// call is the deliberate CAS-conditional write this route exists to
	// provide (same "conditional write, not full delegation" shape ADR-088
	// costs for every /system proxy) -- what made it unjustified was that it
	// skipped two of the three things core.UpdateUser's deactivating branch
	// does around that same write: the last-admin guard (fixed 2026-08-24,
	// core.GuardLastAdminDeactivation) and PAT/session revocation (fixed here
	// via core.RevokeAllPersonalAccessTokensForUser/core.DeleteSessionsForUserExcept,
	// called in-process immediately after a matched true->false transition).
	// With both bolted on, this handler now performs every check and side
	// effect core.UpdateUser's deactivating branch does, in the same order,
	// around the same conditional write -- it just doesn't re-derive the row
	// from a fresh GetUser/diff the way full delegation to core.UpdateUser
	// would (which ADR-088 rejects for this route: full delegation would lose
	// the FromActive CAS precondition the route exists to provide). Verified
	// red/green in users_active_transition_proxy_credential_revoke_test.go.
	"UpdateUserIfActiveStateMatchesProxy": "no-independent-ceiling once both bolt-ons are in place: " +
		"GuardLastAdminDeactivation (fixed 2026-08-24) and RevokeAllPersonalAccessTokensForUser/" +
		"DeleteSessionsForUserExcept (fixed here, #1572) replicate every check and side effect " +
		"core.UpdateUser's deactivating branch applies around the same conditional write.",
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
	// G80 Wave 1 (#1547 one-hop interprocedural fix, 2026-08-27): the 8 entries
	// below were newly surfaced when exportedCoreStorageWrappers gained
	// one-hop delegation-following (previously only inspected an exported
	// method's OWN body, missing storage calls made by an unexported sibling
	// it calls -- see that function's doc comment). Each verified individually
	// against the actual unexported wrapper's body, not assumed from the
	// pattern alone.
	"AdvanceWebAuthnCredentialCounterProxy": "no-independent-ceiling: persistUpdatedCredential " +
		"(internal/core/webauthn.go:566-576) is a marshal + mutex + the SAME storage.AdvanceWebAuthnCredentialCounter " +
		"call, no additional check -- the proxy's own extensive doc comment already establishes the atomic " +
		"row-locked CAS property (the actual security-relevant invariant) is preserved exactly.",
	"CreateWebAuthnSessionProxy": "no-independent-ceiling: storeWebAuthnSession (internal/core/webauthn.go:87-101) " +
		"is a marshal + token-generation + the SAME storage.CreateWebAuthnSession call, no additional check -- " +
		"session data isn't privilege-bearing until consumed (same shape as the already-verified " +
		"CreateSSOLoginStateProxy: identity is anchored at consume time, not creation time).",
	"UpdateWebAuthnCredentialProxy": "no-independent-ceiling: the proxy's own doc comment establishes it backs " +
		"rejectIfCloned's best-effort 'mark disabled' write -- a defensive, capability-REDUCING action (disabling " +
		"a suspected-cloned credential), not an authorization gate to bypass.",
	"CreateRole": "no-independent-ceiling: the exported wrapper reachable via one hop is bootstrapSystemLocked " +
		"(internal/core/auth_bootstrap.go:226-292, called only from system-init bootstrap), which creates a FIXED, " +
		"hardcoded set of default roles -- unrelated in content to this HTTP route's actual authorization gate " +
		"(RequirePermission(permRolesWrite), router.go:962), which already independently governs arbitrary " +
		"caller-supplied role creation.",
	"ExpireSetupTokenProxy": "no-independent-ceiling: marking a setup token expired only REDUCES future capability " +
		"(revokes an outstanding token early) -- there is no privilege to gain by skipping whatever ceiling " +
		"inspectActiveSetupToken's lazy-expiry path would otherwise apply, since expiry is itself the safe " +
		"direction.",
	// VERIFIED 2026-08-27 (G80 Wave 1): both self-attribution gaps this entry
	// depends on were already independently found and fixed by name in a
	// PRIOR round (2026-08-25, G80 documented-exception re-verification
	// sweep) -- re-read directly against current source, not assumed from
	// this entry's own age. approver_id is forced to the authenticated
	// caller (access_request_proxy.go:389-396); the remaining "who may
	// approve at all has no authority ceiling" gap is explicitly named in
	// the handler's own doc comment as pre-existing and out of scope for
	// that fix, not something the raw storage call itself introduces.
	"CreateAccessRequestApprovalProxy": "no-independent-ceiling (fixed 2026-08-25): approver_id is forced to the " +
		"authenticated caller, closing the maker-checker/fabricated-approver bypass; the residual 'no ceiling on " +
		"who may approve' is a named, pre-existing, out-of-scope gap unrelated to this raw call specifically.",
	"UpdateAccessReviewItemProxy": "no-independent-ceiling (fixed 2026-08-25, ARC-005): decided_by is forced to " +
		"the authenticated caller and self-certification is explicitly rejected; persistItemDecision " +
		"(internal/core/access_review_campaign.go:234-249) applies no additional authority ceiling beyond the " +
		"item-pending + campaign-open atomic CAS this proxy already replicates exactly.",
	"CreateConnectorProjectBindingProxy": "no-independent-ceiling: the flagged LogAuditEvent call " +
		"(connector_project_bindings_proxy.go:152-160) is entirely server-constructed -- EventType, ProjectID, " +
		"Description, Success, EventTime, and ActorType are all hardcoded/derived server-side, zero caller-" +
		"controlled content. Different call site, different question from IngestAuditEventProxy's LogAuditEvent " +
		"below (knownUnfixedRawStorageBypasses) -- that one persists a caller-supplied event wholesale.",
	"ClearProjectSecretOwnershipProxy": "false positive: the exported core wrapper (RemoveProjectMember) calls this " +
		"storage method only as a best-effort CLEANUP side effect of removing a member, not as its own gated " +
		"operation -- there is no independent ceiling for 'clear ownership' alone to bypass.",
	"DeleteSecretACLsByUserAndProjectProxy": "false positive: same shape as ClearProjectSecretOwnershipProxy above " +
		"-- a best-effort cleanup side effect inside RemoveProjectMember, not an independently-gated operation.",
	"DeleteExpiredRoleGrantsProxy": "false positive: the exported core wrapper (RemoveExpiredRoleGrants) has no " +
		"actor ceiling either -- an unconditional, time-bounded system sweep. Its only extra value over the raw " +
		"call is per-grant audit-event writing, an audit-completeness gap (#1529 territory), not a policy bypass.",
	// VERIFIED 2026-08-25 (G80 documented-exception re-verification sweep,
	// escalation-delta test): this is the highest-suspicion item in the whole
	// bucket -- "create a user AND grant roles atomically" is structurally the
	// closest sibling to #1552 (AssignRoleWithExpiryProxy's node branch, a bare
	// node credential granting ANY role including admin-tier with zero ceiling).
	// Gate: system.write. Ceiling requireAuthorityForRole would apply for an
	// admin-tier grant. Adversarial checks performed, not assumed: (1) node-
	// credential bypass -- grepped the whole file for isNodeCredentialRequest:
	// ZERO matches. ValidateRoleGrantAuthority (users.go:315-331) runs
	// unconditionally for EVERY caller, human or machine, with no special-case
	// branch. (2) per-grant enforcement -- ValidateRoleGrantAuthority loops over
	// EVERY grant in the request (users.go:325), not just the first, calling
	// requireAuthorityForRole per grant, then requireGrantSetNoSoDViolation over
	// the full set (users.go:330) -- byte-identical to CreateUserWithAssignments'
	// own enforcement (users.go:228,297), confirmed by direct code comparison.
	// (3) actorID==0 (a node credential's UserID) -- requireAuthorityForRole ->
	// requireAdminAuthorityAt (invitations.go:61-90) queries actual role
	// assignments for ID 0, finds none, fails closed for any admin-tier grant --
	// the OPPOSITE of #1552's shape (there the raw call skipped the ceiling
	// entirely; here the ceiling runs and correctly denies actorID 0).
	// (4) ADR-028 atomicity -- LocalStorage.CreateUserWithRoleGrants
	// (internal/storage/store/local_users.go:80-105) wraps the user insert +
	// every grant insert in ONE real gorm.DB.Transaction; remote_users.go's own
	// doc explicitly reasons about the RemoteStorage.WithTransaction-no-op trap
	// this campaign found elsewhere and explains why this design (one
	// server-side POST) avoids it -- a correct, load-bearing choice, not blind
	// reuse of an unrelated precedent. Residual, NOT specific to this handler:
	// requireAuthorityForRole only ceilings hardcoded admin role NAMES
	// (isAdminRoleName) -- a custom-named role bundling equivalent admin
	// permissions passes with no ceiling check, identically in both this proxy
	// and its human-facing sibling. Pre-existing, shared characteristic of the
	// whole requireAuthorityForRole design, not a gap this handler introduces.
	"CreateUserWithRoleGrantsProxy": "holds: ValidateRoleGrantAuthority (users.go:315-331) runs unconditionally " +
		"for every caller (grepped -- zero isNodeCredentialRequest branches in this file), per-grant, and fails " +
		"closed for actorID 0 via requireAdminAuthorityAt (invitations.go:61-90) -- the opposite of #1552's " +
		"shape. ADR-028 atomicity is real (local_users.go:80-105, one gorm.DB.Transaction), not a WithTransaction-" +
		"no-op trap.",
	// CORRECTED 2026-08-25 (G80 documented-exception re-verification sweep): the
	// prior reason here ("same reasoning as RemoveGlobalAdminRoleGuardedProxy --
	// no real transaction spans the HTTP hop") was FALSE, not just imprecise --
	// it borrowed an atomicity argument that doesn't apply to this call at all.
	// This handler backs core.DeleteProject's force=TRUE path (see its own doc
	// comment, project_catalog_proxy.go), which internal/core/catalog.go:186-191
	// documents as intentionally skipping the guard+cascade atomicity problem
	// entirely -- force=true has never had a guard to make atomic; it's a plain
	// unconditional cascade with zero actor-authority check in core.DeleteProject
	// either. The real, verified reason this route is safe: no-independent-
	// ceiling -- there is nothing for the raw call to bypass, because
	// core.DeleteProject(force=true) doesn't check anything beyond what
	// already-runs storage.DeleteProject does. (RemoveGlobalAdminRoleGuardedProxy's
	// atomicity story is real for THAT handler -- storage.RemoveGlobalAdminRoleGuarded
	// genuinely folds a check-then-delete into one atomic call -- it just never
	// applied here.)
	"DeleteProjectProxy": "no-independent-ceiling: core.DeleteProject(force=true) (internal/core/catalog.go:186-191) " +
		"intentionally skips the force=false guard+cascade atomicity problem entirely and calls the plain, " +
		"unconditional storage.DeleteProject cascade -- no actor-authority check of any kind exists at the core " +
		"layer for this path, so there's nothing for the raw call to bypass.",
	// VERIFIED 2026-08-25 (G80 documented-exception re-verification sweep,
	// escalation-delta test): gate is system.write; ceiling is "zero secrets"
	// before deleting a non-forced project, which core.DeleteProject(force=false)
	// would otherwise check via a WithTransaction-wrapped guard-then-cascade
	// pair -- broken under storage.type: remote (RemoteStorage.WithTransaction
	// is a no-op) per #528's own commit message (b6e46050, 2026-07-07, "Closes
	// #528": "the guard-count and the cascade... would have reopened a TOCTOU
	// window" as a plain two-call pair). Adversarial check: is
	// DeleteProjectIfEmpty ACTUALLY atomic, or just named "atomic"? Confirmed at
	// internal/storage/store/local_secrets.go:272-290 -- the secret-count check
	// and deleteProjectCascade both run inside ONE .Transaction() call, no
	// separate earlier read. core.DeleteProject's force=false branch
	// (catalog.go:192-199) does nothing beyond calling this primitive and
	// checking the returned blocking count -- no additional ceiling is skipped
	// by the raw call.
	"DeleteProjectIfEmptyProxy": "holds: internal/storage/store/local_secrets.go:272-290 runs the secret-count " +
		"guard and the cascade delete inside ONE .Transaction() call, no TOCTOU window across the HTTP hop -- " +
		"purpose-built for exactly this (#528, commit b6e46050) after the WithTransaction-wrapped two-call " +
		"version proved unsafe under storage.type: remote; core.DeleteProject(force=false) adds nothing beyond " +
		"calling this same primitive.",
	// The following 9 were classified no-independent-ceiling in the 2026-08-23/24
	// overnight triage (docs/g80-raw-storage-bypass-triage.md has full evidence per
	// entry; reasons here are condensed, not abbreviated to the point of losing the
	// falsifiable claim).
	"MarkTOTPStepUsedProxy": "no-independent-ceiling: the core callers (ActivateMFA/VerifyMFACredentials/" +
		"verifyMFAStepUpCode) invoke this only AFTER cryptographic TOTP validation already passed -- it's a pure " +
		"post-validation anti-replay CAS, not an authorization gate, applied identically by every caller.",
	"DeleteEnvironmentProxy": "no-independent-ceiling: core.DeleteEnvironment is a literal 1-line passthrough to " +
		"storage with no check of its own.",
	"TouchMachineIdentityCredentialProxy": "no-independent-ceiling: TouchMachineTokenLastUsed does no authz/" +
		"ownership check even in core -- explicitly best-effort, a target-state-invariant liveness timestamp " +
		"identical regardless of caller.",
	"DeleteExpiredShareRecordsProxy": "no-independent-ceiling: RemoveExpiredShares is an unconditional time-bound " +
		"sweep, same shape as DeleteExpiredRoleGrantsProxy above; its only extra value is a per-row audit event " +
		"(completeness gap, not a policy bypass).",
	"TransitionSecretStatusProxy": "no-independent-ceiling, CONFIRMED BY READING THE CODE (not just the doc's " +
		"framing): SuspendSecret/ResumeSecret enforce only a CAS race guard + audit; permission itself is " +
		"explicitly NOT a core-layer check by design (the transport must enforce scoped secrets.write). The " +
		"handler faithfully reproduces the same CAS (re-fetch, apply only Status/UpdatedAt, call with fromStatus) " +
		"-- this is the correct-pattern precedent docs/g80-remediation-notes.md's follow-up section points to.",
	"SupersedeSetupTokensProxy": "no-independent-ceiling: the IssueSetupToken step this backs " +
		"(SupersedeActiveSetupTokens) has no caller-authorization gate of its own -- an unconditional exact-match " +
		"(purpose, email[, project]) bulk state-flip.",
	// VERIFIED 2026-08-25 (G80 documented-exception re-verification sweep, escalation-
	// delta test): gate is system.write (this route group's baseline); the ceiling
	// OpenAccessReviewCampaign would otherwise apply is "lifecycle fields must start
	// fresh" -- not an authority check at all, so there is no delta to test. Adversarial
	// check performed: does the handler actually FORCE those fields, or just claim to?
	// access_review_campaigns_proxy.go:230-235 unconditionally overwrites State/
	// ClosedBy/ClosedAt/ForcedIncomplete on the decoded body before persisting,
	// regardless of what the caller sent -- confirmed by reading the code, not the
	// comment. That hardening landed in commit 778a027e (2026-07-27, PR #1175, r128,
	// "fabricated campaigns, pre-decided items, self-certification"), with regression
	// tests TestCreateAccessReviewCampaignProxy_IgnoresClosedState_R128/
	// ..._IgnoresForcedIncomplete_R128 (access_review_campaigns_proxy_r128_test.go) --
	// this is a tested property, not an assertion. Residual, non-blocking gap: the
	// `CreatedBy` field is NOT stripped (toModel(), line 113) -- a caller can attribute
	// a campaign to an arbitrary user ID. The real audit event (AuditCampaignCreated,
	// line 244-245) correctly uses the authenticated caller's own actorID(r), so the
	// audit trail itself isn't spoofable; only the campaign row's cosmetic `created_by`
	// display field is. No authorization decision reads CreatedBy back -- not a
	// privilege escalation, worth a low-priority follow-up ticket if that field is
	// ever trusted for anything beyond display.
	"CreateAccessReviewCampaignProxy": "holds: OpenAccessReviewCampaign is explicitly NOT gated on a human actor " +
		"(ARC-003) -- the only caller-relevant invariant is that lifecycle fields (State/ClosedBy/ClosedAt/" +
		"ForcedIncomplete) start fresh, and access_review_campaigns_proxy.go:230-235 unconditionally forces all " +
		"four before persisting (tested: TestCreateAccessReviewCampaignProxy_IgnoresClosedState_R128). Residual, " +
		"non-blocking: CreatedBy is not stripped (cosmetic attribution only, no authz decision reads it back).",
	// VERIFIED 2026-08-25 (G80 documented-exception re-verification sweep, escalation-
	// delta test): same gate (system.write), same "no independent authority check to
	// bypass" shape as the campaign-create row above -- OpenAccessReviewCampaign's
	// item-generation step has no actor-dependent decision, only a fresh-item-state
	// invariant (ARC-004). Adversarial check: access_review_campaigns_proxy.go:358-360
	// unconditionally overwrites Decision/DecidedBy/DecidedAt on every item before
	// persisting (tested: TestCreateAccessReviewItemsProxy_StripsDecisionFields_R128,
	// same 778a027e/#1175/r128 commit as the campaign-create fix -- this file's prior
	// version, 793f702fc, had NO stripping at all, so this is a real, verified fix, not
	// a stale assertion). All OTHER item fields (PrincipalType/PrincipalID/RoleID/
	// AccessLevel/EnvironmentID/SecretID) remain fully caller-controlled, matching the
	// package doc's own explicit disclosure that no campaign-lifecycle POLICY decision
	// is made here -- fabricated item content can't itself grant/revoke access (that
	// logic lives entirely downstream, out of reach of this route), so this doesn't
	// widen what system.write already permits in this group.
	"CreateAccessReviewItemsProxy": "holds: the only caller-relevant invariant (a fresh item starts " +
		"Decision=pending/DecidedBy=0/DecidedAt=nil) is unconditionally forced server-side " +
		"(access_review_campaigns_proxy.go:358-360, tested: TestCreateAccessReviewItemsProxy_StripsDecisionFields_R128) " +
		"-- other item fields are caller-controlled by design (package doc), but fabricated content can't itself " +
		"grant/revoke access, so this introduces no new privilege beyond the route's own system.write gate.",
	// CORRECTED 2026-08-25 (G80 documented-exception re-verification sweep): the
	// prior "documented-exception" reason here was FALSE. The claimed "separate
	// proxied call chain" (core.RevokeBreakGlass's RemoveUserRole step) does not
	// exist end-to-end: for a project-scoped role it resolves to POST
	// /api/v1/rbac/remove-role, a route that was never registered
	// (remote_wire_route_coverage_test.go's knownMissingRoutes, #1511) --
	// confirmed checked in BEFORE this classification was originally written.
	// Under storage.type: remote, this raw proxy was the ONLY path that could
	// ever complete a revoke with a live grant, and it left the role grant LIVE
	// in user_roles with no audit event. FIXED: the handler is now
	// self-contained (state guard, RemoveUserRole, conditional revoke, new
	// LogBreakGlassRevoked audit call) -- see its own doc comment
	// (break_glass_proxy.go) for the full reasoning, including why it does NOT
	// call core.RevokeBreakGlass directly (would break this route's own wire
	// error-code contract).
	"RevokeBreakGlassActivationProxy": "FIXED: was a false documented-exception (the offsetting role-removal " +
		"chain it claimed to travel through never existed end-to-end, #1511) -- now self-contained (state guard " +
		"+ RemoveUserRole + conditional revoke + LogBreakGlassRevoked audit), see the FIXED comment immediately " +
		"above this entry.",
	// RecordLoginAttemptProxy: FIXED 2026-08-25 (G80 documented-exception
	// re-verification sweep) -- was a FALSE documented-exception (ip/at were
	// completely unvalidated, enabling cross-namespace rate-limit poisoning and
	// a permanent future-timestamp lockout; see internal/core/rate_limit.go's
	// RecordLoginAttemptRelay doc comment for the full finding). Entry removed
	// (not moved) -- the handler now routes through core.RecordLoginAttemptRelay
	// instead of calling Storage().RecordLoginAttempt directly, so this guard's
	// AST scan no longer flags it at all.
	// VERIFIED 2026-08-25 (G80 documented-exception re-verification sweep,
	// escalation-delta test): gate is system.write; there is no actor-authority
	// ceiling for BeginSSO/BeginSAML to bypass (pre-login CSRF-state creation is
	// not gated on identity in the local path either), so the real question is
	// injection, not authority. Adversarial check performed: models.SSOLoginState
	// (internal/storage/models/models.go:174-182) carries State (random CSRF
	// token)/Nonce/Provider/ReturnTo/ExpiresAt/CreatedAt -- NO user/session-
	// identity field of any kind. Identity is bound only at CONSUME time via
	// IdP-signed crypto: verifyIDToken (sso.go:839-867, issuer-pinned JWKS,
	// RS256/ES256/PS256) for OIDC, a vetted SAML-assertion-signature library for
	// SAML. So even a caller who fully controls this create call's fields cannot
	// forge a login for another user -- they would still need a genuine,
	// IdP-signed assertion. No injection path found; file unmodified since
	// introduction (efd0abdc, 2026-07-07).
	"CreateSSOLoginStateProxy": "holds: SSOLoginState carries no identity-binding field " +
		"(internal/storage/models/models.go:174-182) -- identity is anchored entirely by IdP-signed crypto at " +
		"consume time (sso.go:839-867 for OIDC id_token/JWKS, SAML assertion-signature verification for SAML), " +
		"so a caller controlling this create call's fields still cannot forge a login for another user.",
	// VERIFIED 2026-08-25 (G80 documented-exception re-verification sweep,
	// escalation-delta test): same gate; adversarial check on the "atomic
	// read-then-conditional-delete" claim, which is the load-bearing property
	// here (a non-atomic version would reopen a double-consume race). Confirmed
	// at internal/storage/store/local_sso.go:44-54: a genuine conditional
	// `DELETE ... WHERE id = ? AND state = ?` + RowsAffected check, i.e. a real
	// CAS, not a plain delete-by-ID -- and the proxy calls this SAME function
	// rather than reimplementing read+delete over HTTP, so the guarantee is
	// inherited unchanged. Provider/expiry re-validation confirmed to run
	// downstream on EVERY path, independent of caller: validateSSOLoginState
	// (sso.go:172-177) and CompleteSAML (sso.go:316-321) each re-check
	// Provider/ExpiresAt on the row consume returns.
	"ConsumeSSOLoginStateProxy": "holds: internal/storage/store/local_sso.go:44-54 is a genuine conditional " +
		"DELETE+RowsAffected CAS (not a plain delete-by-ID) -- the proxy calls this same function rather than " +
		"reimplementing read+delete, so the single-use guarantee is inherited unchanged; provider/expiry checks " +
		"re-run downstream on every path (sso.go:172-177, sso.go:316-321), independent of caller.",
	// VERIFIED 2026-08-25 (G80 documented-exception re-verification sweep,
	// escalation-delta test): same gate; this file ALSO contains three sibling
	// handlers (CreateWebAuthnCredentialProxy/DeleteWebAuthnCredentialProxy/
	// SetUserWebAuthnEnabledProxy) already confirmed REAL, SEVERE bugs in this
	// same campaign -- extra scrutiny applied here for that reason. Adversarial
	// checks: (1) atomicity -- internal/storage/store/local_webauthn.go:160-176
	// is a genuine transactional conditional UPDATE (WHERE used_at IS NULL AND
	// expires_at > ?) + RowsAffected check, re-read inside the SAME transaction;
	// the proxy makes exactly one call to this primitive, no TOCTOU reopened.
	// (2) injection -- the consume call's only body field is `token_hash` (a
	// lookup key, not data); the session's UserID/Data (WebAuthn challenge) were
	// populated earlier by CreateWebAuthnSession, itself only ever called by
	// this server's own storeWebAuthnSession during Begin*, not by this consume
	// call. (3) crypto ordering -- FinishWebAuthnLogin additionally cross-checks
	// sess.UserID != ch.UserID (webauthn.go:321, an independently-established
	// MFA-challenge identity) BEFORE any signature check, and ValidateLogin/
	// CreateCredential/ValidatePasskeyLogin all verify against credentials
	// freshly reloaded from storage for the real user -- an attacker without
	// the victim's authenticator private key cannot produce a valid signature
	// regardless of what the session Data contains. Caveat carried forward: the
	// comment's own cited "#510 precedent" (ConsumeSetupTokenProxy) is NOT
	// actually present in either guard-test map -- it evaded detection because
	// its raw storage call is inside an UNEXPORTED core helper
	// (consumeInspectedToken, internal/core/setup_token.go:210-214), which this
	// guard's AST scan only inspects EXPORTED KeyorixCore method bodies for
	// (exportedCoreStorageWrappers, this file). Verified independently here on
	// ConsumeWebAuthnSessionProxy's own code, not by trusting that citation.
	"ConsumeWebAuthnSessionProxy": "holds: local_webauthn.go:160-176 is a genuine transactional conditional " +
		"UPDATE+RowsAffected CAS, re-read in the same transaction -- no TOCTOU reopened across the HTTP hop; the " +
		"consume call's only caller-controlled field (token_hash) is a lookup key, not injectable session data, " +
		"and FinishWebAuthnLogin cross-checks sess.UserID != ch.UserID (webauthn.go:321) before any crypto check.",
	// FIXED 2026-08-24 (G80 overnight campaign, Tier 1 Group A #1, was in
	// knownUnfixedRawStorageBypasses): the raw conditional write is still here
	// deliberately (preserves the atomic CAS across the HTTP hop, same reasoning as
	// TransitionSecretStatusProxy's precedent), but it's now preceded by
	// core.IsValidMachineTransition(fromState, m.State) -- the same transition-table
	// legality check (machine_identities.go:64-71, revoked is terminal) that
	// core.TransitionMachineIdentity's transaction body enforces, exported
	// specifically for this call site. That check needs only the (from, to) pair,
	// both already on the wire, so this closes the gap with no RemoteStorage
	// wire-protocol change and no risk to existing downstream callers (verified in
	// the overnight session's RemoteStorage impact check before this landed). The
	// cross-project guard and cache eviction TransitionMachineIdentity also applies
	// are NOT re-derived here: the cross-project guard is a caller-side check (does
	// the acting session's own project scope match this machine) that already ran on
	// whichever server's core.TransitionMachineIdentity initiated the relayed call --
	// the wire carries no caller-asserted project scope for the hub to re-check
	// against. Cache eviction is a best-effort, single-process mechanism even in the
	// correct path (each server only evicts its own in-memory auth cache); adding it
	// here would only help hub-originated requests and wasn't the security-relevant
	// gap this fix closes -- left as a known, pre-existing, unrelated limitation.
	"TransitionMachineIdentityStateProxy": "FIXED: preceded by core.IsValidMachineTransition -- see the FIXED " +
		"comment immediately above this entry for the full reasoning (kept as a map comment, not a value, since " +
		"Go doesn't support per-key doc comments on map literals).",
	// FIXED 2026-08-24 (G80 overnight campaign, Tier 1 Group A #2, was in
	// knownUnfixedRawStorageBypasses): the raw call is still here, but it no longer
	// accepts a full caller-supplied replacement row. The handler now fetches the
	// EXISTING credential and applies only Classification from the wire body,
	// matching core.ClassifyMachineToken's actual behavior exactly (confirmed the
	// ONLY exported core caller of this storage primitive by grep before this fix
	// landed -- it never touches TokenHash/Revoked/ExpiresAt). No RemoteStorage
	// wire-protocol change was needed: the only real caller only ever sends a
	// classification change, so narrowing what the hub acts on breaks nothing
	// (verified in the overnight session's RemoteStorage impact check). The route
	// carries no caller-asserted project/machine scope to re-derive
	// ClassifyMachineToken's own machineInProject check against -- same reasoning as
	// TransitionMachineIdentityStateProxy's cross-project guard above; that check is
	// a caller-side concern already satisfied before the relayed call reached here.
	"UpdateMachineIdentityCredentialProxy": "FIXED: narrowed to fetch-existing + apply-Classification-only -- see " +
		"the FIXED comment immediately above this entry for the full reasoning.",
	// FIXED 2026-08-24 (G80 Phase 2, #1529 re-triage): CreateInvitationProxy now
	// re-derives InviteToProject's/InviteGlobal's own requireAuthorityForRole
	// escalation-by-proxy ceiling for every role the wire body can carry (the
	// project-scoped Role, the global SystemRole, and each project assignment
	// bundled into AssignmentsJSON) -- newly exported core.RequireAuthorityForRole,
	// since the /system proxy layer can't call unexported KeyorixCore methods
	// across the package boundary. UpdateInvitationProxy now re-fetches the
	// existing row and applies only State/AcceptedAt/RevokedAt from the wire
	// (the AR-001 field-narrowing pattern, mirroring UpdateAccessRequestProxy):
	// every real caller of storage.UpdateProjectInvitation
	// (completeInvitationAccept/RevokeInvitation/expireInvitationIfOverdue) only
	// ever mutates those three fields on the row it already fetched, never
	// Email/Role/SystemRole/InvitedBy/ProjectID, which are set once at creation.
	"CreateInvitationProxy": "FIXED: re-derives requireAuthorityForRole for Role/SystemRole/each AssignmentsJSON " +
		"entry -- see the FIXED comment immediately above this entry for the full reasoning.",
	"UpdateInvitationProxy": "FIXED: re-fetches the existing row and applies only State/AcceptedAt/RevokedAt from " +
		"the wire -- see the FIXED comment immediately above this entry for the full reasoning.",
	// FIXED 2026-08-24 (G80 Phase 2, #1529 re-triage): CreateAccessRequestProxy no
	// longer accepts a caller-supplied non-pending State -- every legitimate
	// creation path (RequestProjectAccess/RequestSecretAccess) always creates
	// with State=pending, so rejecting anything else needed no RemoteStorage
	// wire-protocol change (the only real caller never sent anything else in the
	// first place). UpdateAccessRequestProxy now re-derives, at the hub, the SAME
	// ceiling the matching core method already applies before ever reaching this
	// storage primitive locally: maker≠checker plus admin authority
	// (core.RequireAdminAuthorityAt, secret-scoped, mirroring
	// ApproveSecretAccessRequest) or role-grant authority
	// (core.RequireAuthorityForRole, project/role-scoped, mirroring
	// ApproveAccessRequestWithExpiry's own ceiling call) -- both newly exported
	// from internal/core since the /system proxy layer can't call unexported
	// KeyorixCore methods across the package boundary. Only the "approved"
	// transition is gated: core.RejectAccessRequest has no actor-authority check
	// of its own (any project member may reject), and core.WithdrawAccessRequest's
	// self-only check has no wire-carried actor field distinct from ResolvedBy to
	// re-derive against here -- left as-is, not silently narrowed.
	"CreateAccessRequestProxy": "FIXED: State is forced to \"pending\" at creation -- see the FIXED comment " +
		"immediately above this entry for the full reasoning.",
	"UpdateAccessRequestProxy": "FIXED: re-derives maker≠checker + admin/role-grant authority on the \"approved\" " +
		"transition -- see the FIXED comment immediately above this entry for the full reasoning.",
	// #1589: CreateNotificationProxy calls storage.CreateNotification directly.
	// Verified RED then GREEN locally before this entry existed: without it,
	// TestNoUnjustifiedRawStorageBypass failed naming exactly this handler
	// ("CreateNotificationProxy calls Storage().CreateNotification(...)
	// directly, but internal/core has an exported method that also wraps
	// CreateNotification") -- proof the guard scans newly-added handler
	// files correctly, not a blind spot for new code.
	//
	// No-independent-ceiling (same shape as unsafe_sibling_write_guard_test.go's
	// UpdateWebAuthnCredentialProxy/DeleteProjectProxy entries): internal/core
	// applies NO ceiling to notification creation at all -- there is no
	// authorization decision for this proxy to skip. models.Notification
	// carries no actor, sender, or origin field; UserID is the recipient, not
	// an actor a caller could misattribute. There is nothing to derive from
	// the authenticated caller and nothing for a system.write holder to forge.
	//
	// The exported wrapper this guard finds (internal/core's notify()/
	// notifyWithSeverity() call chain, reached one hop from the scheduler
	// entrypoints -- SendExpiryReminders, ScanLicenseExpiry, CheckReadQuotas,
	// CheckRoleExpiry, SendRotationReminders, CheckTokenExpiry, and
	// ValidatePATToken's emitPATExpiredNotification) is the WRONG thing to
	// route this proxy through, not an oversight: those are the CALLING
	// server's own event-driven notification triggers (an access request
	// created, a reminder due, a PAT expired), each already deciding
	// recipient/type/title/message with its own authorized context before
	// ever making this HTTP call. Routing the proxy back through
	// notifyWithSeverity server-side would re-run a scheduler tick or
	// mis-attribute the notification to the hub's own service identity,
	// exactly the double-apply/misattribution problem
	// access_request_proxy.go's package doc names for the identical shape.
	// See notification_proxy.go's package doc for the fuller reasoning.
	"CreateNotificationProxy": "no-independent-ceiling: internal/core applies no authorization ceiling to " +
		"notification creation at all, and models.Notification carries no actor/origin field to forge -- see the " +
		"comment immediately above this entry for the full reasoning, including why routing through internal/core's " +
		"notify()/notifyWithSeverity() chain would be wrong, not merely unwrapped.",
	// FIXED 2026-08-25 (ADR-085, Accepted): CreateSetupTokenProxy derives its
	// ceiling from the operation itself -- minting a setup token for user X is
	// equivalent to taking control of X, and every other admin-facing route that
	// mints one (POST /api/v1/users, POST /api/v1/users/{id}/resend-setup-link,
	// router.go, RequirePermission(permUsersWrite)) already requires users.write
	// -- via AuthorizePrincipal(users.write, global scope), now enforced
	// unconditionally for every caller (the isNodeCredentialRequest branch that
	// used to route a node-typed caller around this check entirely is removed;
	// ADR-085 found the "genuine relay" topology it assumed cannot exist in this
	// codebase). See system_write_ceiling_table_test.go's CreateSetupTokenProxy
	// rows (human and node-credential) for the live, asserted evidence, and
	// handlers_s4_test.go's TestCreateSetupTokenProxy_InvitationAccept_HappyPath/
	// ..._RefusesEmailMismatch for the invitation_accept branch's previously-zero
	// coverage.
	"CreateSetupTokenProxy": "FIXED: AuthorizePrincipal(users.write, global scope) now enforced unconditionally " +
		"for every caller -- see the FIXED comment immediately above this entry for the full reasoning.",
	// FIXED 2026-08-25 (ADR-085, Accepted): CreateMachineIdentityCredentialProxy's
	// core.RequireMachinePrivilegeCeiling check (MACH-001, denying a caller from
	// minting a credential for a machine identity with a higher role tier than
	// its own) now runs unconditionally for every caller. The isNodeCredentialRequest
	// branch that used to route a node-typed caller around it entirely -- letting
	// a bare node credential forge a working credential for an admin-tier
	// machine identity, the campaign's original "MOST SEVERE FINDING" (#1552) --
	// is removed; ADR-085 found the "genuine relay already ran this check
	// downstream" theory it rested on cannot hold (no wire field attests which
	// human/decision a relayed action traces to, and the topology itself cannot
	// exist in this codebase per ADR-083's validateRemoteStorageNotServer). See
	// system_write_ceiling_table_test.go's CreateMachineIdentityCredentialProxy
	// rows (human and node-credential) for the live, asserted evidence.
	"CreateMachineIdentityCredentialProxy": "FIXED: core.RequireMachinePrivilegeCeiling now enforced " +
		"unconditionally for every caller -- see the FIXED comment immediately above this entry for the full " +
		"reasoning.",
	// G80 Wave 2 (blind-spot-2 fix, ADR-088): newly IN SCOPE because this test no
	// longer skips a storage method with no exported core wrapper at all --
	// previously "no wrapper" meant "not considered," which is exactly the
	// inference ADR-088's own #1585/#1586/#1587 findings disproved. These 5 are
	// the benign side of that widened scope: verified individually below, not
	// assumed safe by pattern-matching the shape.
	"AcquireSchedulerLockProxy": "no-independent-ceiling: scheduler_lock_proxy.go's own doc comment establishes " +
		"this is pure distributed-lock coordination infrastructure (ADR-039), not a policy decision -- " +
		"TryAcquireSchedulerLock performs its entire acquire-or-renew-or-reclaim decision atomically server-side, " +
		"with no actor-authority dimension to bypass (which key, how long to hold it, is decided entirely by the " +
		"CALLING server's own WithSchedulerLock, not by this raw call).",
	"ReleaseSchedulerLockProxy": "no-independent-ceiling: same reasoning as AcquireSchedulerLockProxy immediately " +
		"above -- a release-iff-still-owned is a no-op for a non-owning holder, no capability to gain by calling it.",
	"DeleteMFAStepUpGrantsForProxy": "no-independent-ceiling: removes step-up grants for a user (session " +
		"revocation / incident response) -- capability-REDUCING, same shape as ExpireSetupTokenProxy/" +
		"DeleteExpiredRoleGrantsProxy above. No privilege to gain by skipping whatever ceiling a wrapper might " +
		"otherwise apply, since revocation is itself the safe direction.",
	// UpdateRole/DeleteRole are NOT /system proxies -- they're the original
	// human-facing RBAC handlers (server/http/handlers/rbac.go, registered at
	// PUT/DELETE /api/v1/roles/{id}, gated by RequirePermission(permRolesWrite),
	// router.go:974-975), newly flagged by this guard's repo-wide scope now that
	// "no wrapper" no longer means "not considered." internal/core has no
	// exported wrapper for role update/delete at all -- there is no separate
	// operation for this raw call to bypass, matching the existing "CreateRole"
	// entry above exactly (same file, same absence of a core-level equivalent,
	// same reasoning). Each handler carries its own built-in-role protection
	// inline (core.IsBuiltinRole check, rbac.go:328/426) and, for UpdateRole,
	// its own permission-bundling authorization (authorizeAndCollectPermissions,
	// rbac.go:374-391) before ever reaching the raw call.
	"UpdateRole": "no-independent-ceiling: internal/core has no exported wrapper for role update at all (same " +
		"absence as the existing \"CreateRole\" entry above) -- this route (PUT /api/v1/roles/{id}, " +
		"RequirePermission(permRolesWrite)) IS the authoritative implementation, with its own built-in-role guard " +
		"(rbac.go:328) and permission-bundling authorization (rbac.go:374-391) already inline.",
	"DeleteRole": "no-independent-ceiling: same reasoning as UpdateRole immediately above -- no core-level " +
		"equivalent exists to bypass; this route's own built-in-role guard (rbac.go:426) already runs inline.",
}

// knownUnfixedRawStorageBypasses is the set of /system handlers confirmed, by
// individual review (docs/g80-raw-storage-bypass-triage.md), to bypass a REAL
// ceiling -- i.e. the #1542 shape, not yet fixed. Grandfathered so this guard can
// be blocking from today without requiring all of these to be fixed first. This
// is NOT a claim of safety -- the opposite: every entry here is a known, tracked
// gap. TestNoUnjustifiedRawStorageBypass still fails if an entry stops
// reproducing (fixed -- move it to rawStorageBypassAllowlist with a reason, or
// delete the entry) or if its handler is removed from /system entirely.
//
// 10 of these 11 were independently re-verified against an escalation-delta test
// (does an actor holding ONLY the route's gating permission gain a capability the
// gate did not already authorize, traced to a real human auth path) on a 5-item
// sample the same night this list was built; all 5 held up. The reach column
// noted per entry is human-reachable for all but TransitionMembershipProxy
// (reach genuinely unresolved, tracked separately as #1546). (The other 23
// originally-listed entries were deleted outright — G80 liveness sweep found no
// live caller for any of them; see docs/g80-remediation-notes.md.)
var knownUnfixedRawStorageBypasses = map[string]string{
	// G80 Wave 1 (#1547 repo-wide extension + one-hop interprocedural fix,
	// 2026-08-27): REAL, HIGH-severity escalation-by-proxy bypass, same class
	// as #1552 (AssignRoleWithExpiryProxy's original finding). The exported
	// wrapper chain (InviteMember -> inviteMemberWithMode,
	// internal/core/membership_lifecycle.go:169-172) applies a real ceiling
	// BEFORE persisting: `requireAuthorityForRole(ctx, invitedBy, projectID,
	// role)` -- "onboarding a member as an admin role requires the inviter to
	// hold admin authority at the project." CreateMembershipProxy
	// (server/http/handlers/project_memberships_proxy.go:102) calls
	// Storage().CreateProjectMembership directly with the wire body's Role and
	// State as-is -- no role-authority check of any kind. A caller holding
	// only this route's system.write gate can POST an arbitrary UserID with
	// an admin-tier Role AND State:"active" (bypassing whatever
	// invite/accept state-machine gating initialMembershipStateForMode would
	// otherwise apply) and grant instant, active, admin-tier project
	// membership to any user. Filed as #1578.
	"CreateMembershipProxy": "REAL, human-reachable, HIGH severity: bypasses requireAuthorityForRole entirely " +
		"(membership_lifecycle.go:172) -- any system.write holder can grant an arbitrary user an active admin-tier " +
		"project membership via a single POST, with Role and State fully caller-controlled. Filed as #1578.",
	// G80 Wave 1 (#1547 repo-wide extension, 2026-08-27): REAL bypass, narrow
	// impact (availability, not escalation). consumeInspectedToken
	// (internal/core/setup_token.go:210-213) checks `tok.Purpose !=
	// expectedPurpose` before calling storage.MarkSetupTokenConsumed;
	// ConsumeSetupTokenProxy (server/http/handlers/setup_tokens_proxy.go:309)
	// relays the same storage primitive directly, keyed only on token ID, with
	// no purpose parameter on the wire at all. Any system.write holder who can
	// enumerate/guess an active setup-token ID can consume it regardless of
	// its intended purpose (burning a legitimate password-reset/invitation-
	// accept token before the real recipient uses it) -- a targeted DoS
	// primitive against account-provisioning flows, not a privilege
	// escalation (consuming alone confers no access; MarkSetupTokenConsumed
	// is a bare state-transition CAS, not a credential grant). Filed as
	// #1579.
	"ConsumeSetupTokenProxy": "REAL, human-reachable, narrow: consume is purpose-blind (no purpose parameter on " +
		"the wire), so a system.write holder can burn any active setup token by ID regardless of intended use -- " +
		"availability/DoS against provisioning flows, not an escalation. Filed as #1579.",
	// G80 Wave 1 (#1547 repo-wide extension, 2026-08-27): REAL bypass,
	// reference-confusion class (explicitly not a value-leak, per
	// core.CreateDynamicSecretConfig's own doc comment,
	// internal/core/dynamic_secrets.go:225-242). That exported method checks
	// `env.ProjectID != req.ProjectID` before persisting -- a config's
	// EnvironmentID must actually belong to its own ProjectID.
	// CreateDynamicSecretConfigProxy
	// (server/http/handlers/dynamic_secrets_proxy.go:216) persists the wire
	// body directly with no cross-reference check, so a caller-supplied
	// (ProjectID, EnvironmentID) pair naming DIFFERENT projects persists
	// without error. Downstream reads/leases stay keyed off the config's own
	// stored ProjectID (confirmed in the core method's own doc comment), so
	// this is not a cross-project secret-value leak -- it's a config an
	// operator believes is scoped to (A, envX) actually referencing an
	// environment belonging to a project the creator may have no visibility
	// into. Filed as #1580.
	"CreateDynamicSecretConfigProxy": "REAL, human-reachable, reference-confusion class (not a value leak per the " +
		"core method's own doc comment): skips the EnvironmentID-belongs-to-ProjectID cross-reference check " +
		"(dynamic_secrets.go:238-241), so a config can be created referencing an environment from a different, " +
		"possibly invisible-to-the-caller project. Filed as #1580.",
	// Pre-existing, already fully documented and deferred -- not a new G80
	// Wave 1 finding, just newly VISIBLE to this guard (the one-hop fix
	// surfaced LogAuditEvent as a wrapped method for the first time). See
	// server/http/handlers/audit_ingest_proxy.go's own #G79 doc comment
	// (lines 46-60): LogAuditEvent computes EntryHash over whatever fields
	// it's given, so a system.write holder reaching this endpoint directly
	// (bypassing the emitting server's own core.KeyorixCore.emitAudit
	// decision) can submit a fully fabricated, self-consistent event (wrong
	// actor, wrong description, wrong outcome) that passes VerifyAuditChain --
	// a hash chain detects tampering with entries already written, not that a
	// NEW entry's content is genuine. Closing this fully needs a way to
	// attest the submitter is a legitimate downstream node (a node-identity
	// credential distinct from the RBAC permission tier), explicitly deferred
	// to "Wave 4" in the existing comment. What IS already closed: clock-skew
	// bounding and required-field validation reject the cruder abuse (an
	// arbitrary event_time planting a forged entry at an arbitrary forensic
	// timeline point).
	"IngestAuditEventProxy": "REAL, already documented and deferred (audit_ingest_proxy.go's own #G79 comment): a " +
		"system.write holder can submit a fully fabricated, self-consistent audit event that passes " +
		"VerifyAuditChain -- closing this needs node-identity attestation infrastructure, deferred to Wave 4. " +
		"Not a new finding; newly visible to this guard because the one-hop fix (G80 Wave 1) surfaced " +
		"LogAuditEvent as a wrapped storage method for the first time.",
	// HALF-FIXED 2026-08-25 (G80 documented-exception re-verification sweep) --
	// do NOT move to rawStorageBypassAllowlist. Was classified documented-
	// exception on the theory that the handler's own #G79 comment "re-derives
	// and closes the gap" (an internal invitation/user cross-reference check
	// before persisting). That check is real and correctly written for what it
	// explicitly validates (existence + case-insensitive email match) -- but it
	// enforces internal CONSISTENCY between the caller-supplied fields, not
	// caller AUTHORIZATION to target the account those fields name. Confirmed
	// exploitable: a caller holding only system.write who already knew (or
	// guessed) a real target's email/user-ID could mint a fully-valid,
	// immediately-redeemable takeover token via the public POST
	// /auth/setup/consume -- overwriting the target's real password and, for a
	// non-MFA account, receiving a live session AS them.
	//
	// Rejected fix: narrowing to the node-credential arm only. Liveness-checked
	// first (per this sweep's own standing method): RemoteStorage.CreateSetupToken
	// (internal/storage/store/remote_auth.go:211) is a genuine implementation
	// invoked by ordinary product flows (every project invite/resend, every
	// admin create-user/resend-setup-link action, the self-service forgot-
	// password flow) -- not dead code, so node-only would not have been a
	// no-op restriction. More importantly: per #1552, a bare node credential can
	// already grant ANY role including admin-tier -- the single most widely
	// distributed credential class in a deployment (ADR-085) -- so gatekeeping
	// on "is this a node credential" would LOWER the effective bar, not raise
	// it, for an account-takeover primitive.
	//
	// TransitionMembershipProxy is FIXED (#1546, Wave 2, ADR-088) -- entry
	// removed. Liveness re-trace found the "undetermined" question above (did a
	// spoke already relay the role-grant separately?) resolves to "no spoke
	// exists at all": core.TransitionMembership's only caller repo-wide is the
	// human-facing HTTP route (unreachable from any process with
	// storage.type: remote, since validateRemoteStorageNotServer rejects that
	// for every server), and no CLI command calls it either. With no live
	// spoke, ADR-088's duplication concern for full delegation is moot, so the
	// handler now fully delegates to core.TransitionMembership instead of the
	// narrow bolt-on ADR-088 costed -- it no longer makes any raw
	// wrapped-storage call at all (moved to actorID(r)-derived,
	// core.TransitionMembership-routed logic;
	// server/http/handlers/project_memberships_proxy.go).
	// UpdateLoginLockoutStateProxy's route was deleted (G80 23-handler no-caller
	// deletion) -- entry removed, no longer applicable.
	// CreateMachineIdentityProxy is FIXED (moved to rawStorageBypassAllowlist);
	// CreateMachineIdentityCredentialProxy is HALF-FIXED (see its entry below) --
	// neither belongs here with its original pre-fix text.
	// #1551 cross-tenant half FIXED 2026-08-29 (Wave 2, ADR-088):
	// storage.Storage.RevokeMachineIdentityCredential now takes a projectID
	// parameter, enforced in the WHERE clause (LocalStorage) and carried on
	// the wire (RemoteStorage/RevokeMachineIdentityCredentialProxy) --
	// deriving the existing core.machineInProject ownership-check *shape*
	// rather than inventing a new authorization primitive: a caller-claimed
	// project_id is now verified against the credential's real owning
	// project before the write, the same claim-vs-ground-truth pattern
	// already used for wire-supplied actors elsewhere in this package.
	// Verified red/green via a real upstream/downstream integration test
	// (server/http/remote_storage_machine_identities_test.go,
	// TestRemoteStorageMachineIdentities_RevokeCredential_CrossTenantRejected_RealServer).
	// Audit + cache-eviction hand-off remain a SEPARATE, still-open residual
	// (unchanged by this fix, not silently dropped): this raw call still
	// doesn't log an audit event or return the token hash for auth-cache
	// eviction the way core.RevokeMachineToken's caller-side eviction
	// contract expects -- and unlike the tenant check, that gap isn't closed
	// by a wire parameter alone (it needs either an audit call here or a
	// wire-carried hash in the response), so still belongs in this list under
	// its own remaining half.
	"RevokeMachineIdentityCredentialProxy": "PARTIALLY FIXED 2026-08-29 (#1551, Wave 2): cross-tenant revoke is " +
		"now rejected (project_id required on the wire, enforced in the storage layer's WHERE clause). Still " +
		"open: no audit event, no token-hash returned for auth-cache eviction (core.RevokeMachineToken's own " +
		"caller-side eviction contract is unmet by this raw passthrough) -- narrower residual, not an " +
		"escalation, not part of #1551's stated cross-tenant scope. " +
		"ADR-085 (Accepted, 2026-08-25) closed the node-credential axis specifically: the /system group's own " +
		"gate now requires system.write for every caller (see " +
		"TestSystemWriteCeiling_RevokeMachineIdentityCredentialProxy_NodeCredential_DeniedAtGate, " +
		"system_write_ceiling_table_test.go) -- irrelevant to the tenant check either way, since that check now " +
		"runs for every caller regardless of credential class.",
	// UpsertMFASecretProxy, CreateMFAStepUpGrantProxy, UpdateProjectProxy,
	// RestoreProjectProxy, DeleteAnomalyAlertsBeforeProxy,
	// DeleteClosedAccessReviewsBeforeProxy, DeleteExpiredBreakGlassBeforeProxy,
	// DeleteResolvedAccessRequestsBeforeProxy, DeleteSecretDependencyProxy: all
	// deleted (G80 23-handler no-caller deletion) -- entries removed, no longer
	// applicable.
	// UpdateUserIfActiveStateMatchesProxy is FIXED (#1572, Wave 2, ADR-088) --
	// entry removed. Recap: the last-admin-lockout half was fixed 2026-08-24
	// (core.GuardLastAdminDeactivation). RemoteStorage.RevokeAllPersonalAccessTokensForUser/
	// DeleteSessionsForUserExcept were un-stubbed 2026-08-25 via two new proxy
	// routes (RevokeAllPersonalAccessTokensForUserProxy/DeleteSessionsForUserExceptProxy),
	// which closed the gap for the LEGITIMATE flow (a CLI running
	// core.UpdateUser under storage.type: remote, whose deactivating branch
	// calls those two operations as separate HTTP round-trips). What remained
	// open: a caller reaching THIS route directly, bypassing core.UpdateUser
	// entirely, could deactivate a user via this route alone without ever
	// triggering the other two -- PAT/session revocation was skippable, not a
	// guaranteed side effect of deactivation the way it is for the legitimate
	// path. Per ADR-088's own costing for #1572 ("the fix is calling those
	// same two already-safe internal/core operations directly, in sequence...
	// no new primitive needed"), this handler now calls
	// core.RevokeAllPersonalAccessTokensForUser/core.DeleteSessionsForUserExcept
	// itself (in-process, not a second HTTP hop) immediately after a matched
	// true->false transition, best-effort and non-fatal like core.UpdateUser's
	// own deactivating branch. Verified red before / green after in
	// server/http/handlers/users_active_transition_proxy_credential_revoke_test.go.
	// G80 Wave 2 (tx.X() blind-spot fix, ADR-088): the 9 MFA-management
	// (ActivateMFASecretProxy/SetUserMFAEnabledProxy/CreateMFARecoveryCodesProxy/
	// DeleteMFAForUserProxy/DeleteMFARecoveryCodesProxy) and retention-purge
	// (PurgeDeletedUsersBeforeProxy/PurgeDeletedProjectsBeforeProxy/
	// PurgeDeletedEnvironmentsBeforeProxy/PurgeDeletedSecretsBeforeProxy)
	// entries that were here were DELETED (#1593,
	// docs/adr-089-mfa-purge-relay-deletion.md), not fixed: a liveness check
	// found no caller could ever legitimately reach any of the 9 (the
	// server-side paths that are the only callers of the corresponding
	// internal/core methods cannot run against RemoteStorage at all --
	// validateRemoteStorageNotServer rejects storage.type: remote for ANY
	// server process unconditionally -- and the CLI, the only process that
	// CAN construct a RemoteStorage-backed core, has no MFA or
	// retention/purge command). See the ADR for why this took three
	// liveness passes to get right, and what reviving any of these 9 would
	// require before it's safe to.
}

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
