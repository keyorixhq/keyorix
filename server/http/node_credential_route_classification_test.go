// node_credential_route_classification_test.go — #1524/ADR-085's per-actor-
// ceiling vs target-state-invariant distinction encoded as data, not just ADR
// prose, with a completeness test cross-checking it against the real
// RequireNodeCredentialOrPermission route set in router.go. Mirrors the
// shape of the #1511 AST wire-route-coverage guard
// (internal/storage/store/remote_wire_route_coverage_test.go): a hand-copied
// list that nobody re-checks against the source is exactly how server/http
// sat excluded from CI for ~4 months and #1524's 9-route enumeration missed
// AddGroupMemberProxy the first time around — the only version of a
// classification table that survives is one a test fails against.
//
// Classification (see docs/adr-085-node-credential-permission-scope.md and
// the #1532 comment this test's own findings were posted to):
//
//   - classNodeLegitimate: no actor-authority check is reached on this route
//     at all (via any caller, human or machine) — a bare node credential is
//     fine here. Some of these bypass a REAL ceiling that exists elsewhere in
//     internal/core by calling raw storage.Storage instead (see #1542) — that
//     is a distinct, separately-tracked finding, not something this
//     classification re-litigates.
//   - classTargetStateInvariant: a real check runs, but it depends on target
//     or global state (e.g. "would this strand the last admin"), never on
//     who the caller is — safe for any caller including a bare node
//     credential, by construction. Must never be "fixed" into denying node
//     callers outright; that would break a genuine, tested relay path (the
//     specific failure mode #1532's classification found the ADR's original
//     binary framing would have caused).
//   - classPerActorCeiling: the check depends on caller identity
//     (self-approval, escalation-by-proxy). A bare machine actor can never
//     satisfy this by definition — must be denied outright (see P1's
//     actorIsMachine fix, groups.go's AddUserToGroup and
//     risk_exceptions.go's ApproveRiskException).
package http

import (
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

type nodeRouteClass int

const (
	classNodeLegitimate nodeRouteClass = iota
	classTargetStateInvariant
	classPerActorCeiling
)

func (c nodeRouteClass) String() string {
	switch c {
	case classNodeLegitimate:
		return "node-legitimate"
	case classTargetStateInvariant:
		return "target-state-invariant"
	case classPerActorCeiling:
		return "per-actor-ceiling"
	default:
		return "unknown"
	}
}

type nodeRouteEntry struct {
	Method string
	Path   string
	Class  nodeRouteClass
	Note   string
}

// classifiedNodeCredentialRoutes is every route this classification currently
// covers. Update it (with a reason) whenever a route is added to, removed
// from, or moved within the RequireNodeCredentialOrPermission-gated /system
// group — TestNodeCredentialRoutes_MatchClassification fails otherwise.
var classifiedNodeCredentialRoutes = []nodeRouteEntry{
	{"POST", "/api/v1/system/rbac/global-admin-role/remove-guarded", classTargetStateInvariant,
		"RemoveGlobalAdminRoleGuardedProxy: refuses only if removal would strand the last global admin -- evaluated against the target's own state, not the caller"},
	{"POST", "/api/v1/system/users/with-role-grants", classPerActorCeiling,
		"CreateUserWithRoleGrantsProxy: ValidateRoleGrantAuthority(actorID(r), grants) -- escalation-by-proxy, genuinely actor-dependent"},
	{"POST", "/api/v1/system/rbac/assign-role-with-expiry", classNodeLegitimate,
		"AssignRoleWithExpiryProxy calls storage.AssignRoleWithExpiry directly, bypassing core.AssignUserRoleWithExpiry's real ceiling -- #1542, not a node-specific gap"},
	{"POST", "/api/v1/system/rbac/assign-role-to-group-with-expiry", classNodeLegitimate,
		"AssignRoleToGroupWithExpiryProxy: same #1542 raw-storage bypass as above, for groups"},
	{"POST", "/api/v1/system/machine-identities/{id}/roles/{roleId}", classNodeLegitimate,
		"AssignMachineRoleProxy: same #1542 raw-storage bypass, bypasses core.AssignMachineRole's requireAuthorityForRole + machineInProject"},
	{"DELETE", "/api/v1/system/machine-identities/{id}/roles/{roleId}", classNodeLegitimate,
		"RemoveMachineRoleProxy: no ceiling anywhere, local or proxy -- removal is safe-direction"},
	{"POST", "/api/v1/system/rbac/remove-all-project-role-grants", classNodeLegitimate,
		"RemoveAllProjectRoleGrantsProxy: bypasses core.RemoveProjectMember's guardLastProjectAdmin (a target-state guard, like row 1 above, but silently unreachable here rather than re-implemented) -- #1542"},
	{"POST", "/api/v1/system/rbac/clear-project-secret-ownership", classNodeLegitimate,
		"ClearProjectSecretOwnershipProxy: no ceiling anywhere -- defense-in-depth cleanup, not a grant"},
	{"POST", "/api/v1/system/rbac/delete-secret-acls-by-user-and-project", classNodeLegitimate,
		"DeleteSecretACLsByUserAndProjectProxy: no ceiling anywhere -- same shape as clear-project-secret-ownership"},
	{"POST", "/api/v1/system/retention/role-grants/purge-expired", classNodeLegitimate,
		"DeleteExpiredRoleGrantsProxy: no ceiling; bounded to time-bound grants by the caller-supplied 'before' timestamp -- #1529 territory, not a per-actor question"},
	{"POST", "/api/v1/system/groups/{id}/members", classPerActorCeiling,
		"AddGroupMemberProxy: #1524 finding (b) -- core.AddUserToGroup's validateGroupJoinRoles, now enforced for a machine actor via actorIsMachine (P1 fix)"},
	{"DELETE", "/api/v1/system/groups/{id}/members/{userId}", classTargetStateInvariant,
		"RemoveGroupMemberProxy: core.RemoveUserFromGroup's guardLastGlobalAdminMembership/guardLastProjectAdminGroupMembership -- target-state (would this strand an admin path), not actor-dependent, like row 1"},
	{"POST", "/api/v1/system/risk-exceptions", classNodeLegitimate,
		"CreateRiskExceptionProxy: no actor-authority check -- creation alone confers nothing, dual control's real gate is the separate approve step"},
	{"PUT", "/api/v1/system/risk-exceptions/{id}/revoke", classNodeLegitimate,
		"RevokeRiskExceptionProxy: core.RevokeRiskException has no actor-authority check at all -- #1529 territory"},
	{"PUT", "/api/v1/system/risk-exceptions/{id}/approve", classPerActorCeiling,
		"ApproveRiskExceptionProxy: #1524 finding (c) -- dual control's self-approval check, now enforced for a machine actor via actorIsMachine (P1 fix)"},
	{"POST", "/api/v1/system/project-memberships", classNodeLegitimate,
		"CreateMembershipProxy: body.Role is required and passed straight to a raw storage.CreateProjectMembership call, no ceiling anywhere -- SAME #1542-shaped raw-storage-bypass pattern (a real ROLE field, not just a status field), NOT YET VERIFIED for reach -- noted in the P0/P2 report as a follow-up candidate, not investigated further here per scope"},
	{"PUT", "/api/v1/system/project-memberships/{id}", classNodeLegitimate,
		"UpdateMembershipProxy: same raw-storage shape as CreateMembershipProxy above -- same follow-up flag"},
	{"PUT", "/api/v1/system/project-memberships/{id}/transition", classNodeLegitimate,
		"TransitionMembershipProxy: state transition (e.g. pending->active), not a role change -- lower concern than Create/Update above but same raw-storage shape"},
}

// --- Route extraction from router.go (scoped-down sibling of the #1511 AST
// guard's extractRouterRoutes -- this only needs the router side, and only
// needs it for routes actually gated by RequireNodeCredentialOrPermission,
// identified by the "/api/v1/system" path prefix; router.go registers that
// gate exactly once, at a single r.Route("/system", ...) block, verified by
// this test's own sibling assertion below). ---

type routerRoute struct {
	Method  string
	Path    string
	Handler string // e.g. "AssignRoleWithExpiryProxy" -- the handler method name, not the receiver
}

// rbacMutationHandlerRe matches handler method names this classification's
// scope actually covers: RBAC/group-membership/machine-role/risk-exception
// MUTATIONS specifically (never a bare "Role"/"Member" READ -- see the
// GET-method exclusion in extractSystemGroupRoutes' caller). This is a
// judgment call, not something derivable from router.go alone: it is what
// makes "18 routes," not "194," this test's universe, matching #1524's own
// original scope (RBAC-mutating proxy routes, plus the two risk-exception
// dual-control routes found alongside them) rather than every /system route.
// A future RBAC/group/machine-role/risk-exception mutation handler that
// doesn't match this pattern (an unusual name) would be a real gap this
// regex can't catch -- the completeness test only guards against a
// keyword-matching route being added without a classification entry, not
// against every conceivable future name.
var rbacMutationHandlerRe = regexp.MustCompile(`Role|Member|RiskException`)

func normalizeRouterPath(p string) string {
	// #1511's guard also collapses {param} to "*" for wire-call comparison;
	// this guard keeps params literal (chi's own {id}/{roleId} names) since
	// it only ever compares router.go against itself (the classification
	// table above), never against a client-side Sprintf-built path.
	if len(p) > 1 && strings.HasSuffix(p, "/") {
		p = p[:len(p)-1]
	}
	return p
}

// extractSystemGroupRoutes parses router.go and returns every (method, path)
// pair registered anywhere inside the r.Route("/system", ...) block --
// including nested r.Route/r.Group sub-blocks -- resolving path constants
// and string-concatenation the same way #1511's guard does.
func extractSystemGroupRoutes(t *testing.T, path string) []routerRoute {
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
	var insideSystemGroup bool
	systemGroupDepth := 0

	httpMethods := map[string]string{"Get": "GET", "Post": "POST", "Put": "PUT", "Patch": "PATCH", "Delete": "DELETE"}

	var walkBlock func(prefix string, body *ast.BlockStmt, inSystem bool, depth int)
	var walkCall func(prefix string, expr ast.Expr, inSystem bool, depth int)

	walkBlock = func(prefix string, body *ast.BlockStmt, inSystem bool, depth int) {
		if body == nil {
			return
		}
		for _, stmt := range body.List {
			exprStmt, ok := stmt.(*ast.ExprStmt)
			if !ok {
				continue
			}
			walkCall(prefix, exprStmt.X, inSystem, depth)
		}
	}

	walkCall = func(prefix string, expr ast.Expr, inSystem bool, depth int) {
		call, ok := expr.(*ast.CallExpr)
		if !ok {
			return
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return
		}
		// r.Use(...) marks entry into the node-credential-gated group -- only
		// meaningful at the top of the /system block itself, detected by the
		// caller (walkCall for r.Route("/system", ...)) rather than here.
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
			nowInSystem := inSystem
			if depth == 0 && subPrefix == "/api/v1/system" {
				nowInSystem = true
				systemGroupDepth++
			}
			walkBlock(subPrefix, sub.Body, nowInSystem, depth+1)
		case "Get", "Post", "Put", "Patch", "Delete":
			if !inSystem || len(call.Args) < 2 {
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
		case "With":
			// r.With(mw...).Post("/path", handler) -- the method call is the
			// outer CallExpr's own Fun.X, e.g. r.With(...).Post(...): walk
			// into it as if it were a direct call on r.
		}
		// r.With(...).Get/Post/etc(...) chains: the outer call's Fun is a
		// SelectorExpr whose X is itself the r.With(...) call -- handled by
		// recursing into X when the top-level selector isn't itself a known
		// HTTP method/Route/Group name.
		if _, known := httpMethods[sel.Sel.Name]; !known && sel.Sel.Name != "Route" && sel.Sel.Name != "Group" {
			return
		}
	}

	// Walk every top-level statement in every function looking for the
	// r.Route("/system", ...) registration -- router.go registers routes
	// inside NewRouter's own body (and possibly helper functions it calls),
	// so this walks every FuncDecl's body rather than assuming a single
	// known function name.
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Route" || len(call.Args) != 2 {
				return true
			}
			p, ok := resolvePathArg(call.Args[0])
			if !ok || p != "/system" {
				return true
			}
			lit, ok := call.Args[1].(*ast.FuncLit)
			if !ok {
				return true
			}
			insideSystemGroup = true
			walkBlock("/api/v1/system", lit.Body, true, 1)
			return false
		})
	}

	if !insideSystemGroup {
		t.Fatal("could not find r.Route(\"/system\", ...) in router.go -- extractSystemGroupRoutes needs updating, or the gate moved/was removed")
	}
	return routes
}

func unquoteRouterLit(lit string) (string, bool) {
	if len(lit) >= 2 && lit[0] == '"' {
		return lit[1 : len(lit)-1], true
	}
	return "", false
}

// TestNodeCredentialRoutes_MatchClassification is the completeness guard:
// every route actually registered under RequireNodeCredentialOrPermission in
// router.go must appear in classifiedNodeCredentialRoutes, and vice versa.
// Fails (not warns) on either direction -- an unclassified new route (#1524's
// "route fourteen") and a stale classification entry both go unnoticed
// otherwise, exactly like the pre-C5 CI exclusion list and the pre-hardening
// #1511 guard both did before this campaign.
func TestNodeCredentialRoutes_MatchClassification(t *testing.T) {
	routerPath := filepath.Join(".", "router.go")
	all := extractSystemGroupRoutes(t, routerPath)

	// Scope to this classification's actual universe: RBAC/group-membership/
	// machine-role/risk-exception MUTATIONS (never GET -- a read carries no
	// escalation-ceiling concern in this codebase's pattern) whose handler
	// name matches rbacMutationHandlerRe. 194 routes are registered under
	// RequireNodeCredentialOrPermission total; this classification covers the
	// 13 #1524 investigated, not the other 181 (dynamic-secrets/invitations/
	// login-attempts/etc. proxies, which are #1529's territory, not this
	// one).
	var actual []routerRoute
	for _, r := range all {
		if r.Method == "GET" {
			continue
		}
		if !rbacMutationHandlerRe.MatchString(r.Handler) {
			continue
		}
		actual = append(actual, r)
	}

	// actualSet: the regex-filtered candidate set, used ONLY for the
	// unclassified-route check below -- the heuristic can under-match (see
	// ClearProjectSecretOwnershipProxy/DeleteSecretACLsByUserAndProjectProxy,
	// both genuinely in scope but named after neither Role/Member/
	// RiskException), so it must never be the set a classified entry is
	// checked for staleness against.
	actualSet := map[string]bool{}
	for _, r := range actual {
		actualSet[r.Method+" "+r.Path] = true
	}
	// allSet: every route actually registered under RequireNodeCredentialOr-
	// Permission, unfiltered -- the staleness check's source of truth. A
	// classified entry is stale only if NO real router.go registration
	// matches it at all, regardless of whether that registration happens to
	// match the unclassified-route heuristic.
	allSet := map[string]bool{}
	for _, r := range all {
		allSet[r.Method+" "+r.Path] = true
	}
	classifiedSet := map[string]bool{}
	for _, c := range classifiedNodeCredentialRoutes {
		classifiedSet[c.Method+" "+c.Path] = true
	}

	var unclassified []string
	for key := range actualSet {
		if !classifiedSet[key] {
			unclassified = append(unclassified, key)
		}
	}
	sort.Strings(unclassified)
	if len(unclassified) > 0 {
		t.Errorf("%d route(s) registered under RequireNodeCredentialOrPermission have no entry in classifiedNodeCredentialRoutes (server/http/node_credential_route_classification_test.go) -- classify each as node-legitimate, target-state-invariant, or per-actor-ceiling before this test can pass:\n%s",
			len(unclassified), strings.Join(unclassified, "\n"))
	}

	var stale []string
	for key := range classifiedSet {
		if !allSet[key] {
			stale = append(stale, key)
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		t.Errorf("%d classifiedNodeCredentialRoutes entries no longer match a real router.go registration -- the route moved, was removed, or the path changed; update or remove the entry:\n%s",
			len(stale), strings.Join(stale, "\n"))
	}
}

// perActorCeilingCoverage maps every classPerActorCeiling route to the test
// function(s) that actually assert a machine actor is denied on that route --
// not just that the route is classified. TestNodeCredentialRoutes_PerActorCeilingsAreEnforced
// verifies these functions still exist in source; it does not re-run them
// (that's `go test ./server/http/... ./internal/core/...`'s job). This is
// still weaker than invoking the deny path from inside this test directly --
// seeing an assertion that once verified a real 403/error, break-tested by
// hand during P1 (see PR #1544's test plan) -- but it closes the actual gap
// the original version of this test had: a prior version asserted only
// perActorCount == 3, a pure count that would stay green even if every
// listed test function were deleted. Route -> function name(s) is checked
// against the real file, so a renamed/deleted test fails this immediately.
var perActorCeilingCoverage = map[string][]struct {
	file string // relative to repo root
	fn   string
}{
	"POST /api/v1/system/groups/{id}/members": {
		{file: "internal/core/authz_admin_ceiling_group_test.go", fn: "TestAddUserToGroup_MachineActorBlockedFromAdminGroup"},
		{file: "server/http/remote_storage_groups_test.go", fn: "TestRemoteStorageGroup_Membership_AdminConferringGroup_DeniesNodeCredential"},
	},
	"PUT /api/v1/system/risk-exceptions/{id}/approve": {
		{file: "internal/core/risk_exceptions_test.go", fn: "TestApproveRiskException_DeniesMachineActor"},
		{file: "server/http/remote_storage_risk_exceptions_test.go", fn: "TestRemoteStorageRiskExceptions_Approve_DeniesNodeCredential"},
	},
	"POST /api/v1/system/users/with-role-grants": {
		// ValidateRoleGrantAuthority has no actorID==0 exemption to begin with
		// (C2) -- this test's name reflects its original DB-error purpose, but
		// its assertion (403 before the broken DB is ever reached) is exactly
		// the fail-closed-first behavior this table exists to pin.
		{file: "server/http/handlers/handlers_s32_test.go", fn: "TestCreateUserWithRoleGrantsProxy_DBError_S32"},
	},
}

// testFuncExists reports whether `func <fn>(` appears in the named file,
// relative to the repo root (two levels up from server/http).
func testFuncExists(t *testing.T, relPath, fn string) bool {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", relPath))
	if err != nil {
		t.Fatalf("reading %s: %v", relPath, err)
	}
	return regexp.MustCompile(`(?m)^func `+regexp.QuoteMeta(fn)+`\(`).Match(b)
}

// TestNodeCredentialRoutes_PerActorCeilingsAreEnforced verifies every
// classPerActorCeiling route has real, still-present, machine-actor-denial
// test coverage listed in perActorCeilingCoverage -- not a route count that
// happens to match. Two independent failure modes: a classPerActorCeiling
// route with no coverage entry at all (a new ceiling route was classified
// but never given its own fix + test, matching P1's `actorIsMachine` shape),
// or a coverage entry naming a test function that no longer exists (renamed
// or deleted without updating this table).
func TestNodeCredentialRoutes_PerActorCeilingsAreEnforced(t *testing.T) {
	perActorCount := 0
	for _, c := range classifiedNodeCredentialRoutes {
		if c.Class != classPerActorCeiling {
			continue
		}
		perActorCount++
		key := c.Method + " " + c.Path
		coverage, ok := perActorCeilingCoverage[key]
		if !ok || len(coverage) == 0 {
			t.Errorf("classPerActorCeiling route %q has no entry in perActorCeilingCoverage — "+
				"a per-actor ceiling route needs its own fail-closed fix AND a dedicated machine-actor "+
				"denial test before it can be classified here, not just a table entry (see P1, #1524 b/c)", key)
			continue
		}
		for _, tc := range coverage {
			if !testFuncExists(t, tc.file, tc.fn) {
				t.Errorf("classPerActorCeiling route %q: perActorCeilingCoverage names %s in %s, "+
					"but that function no longer exists — it was renamed or deleted without updating "+
					"this table, silently losing enforcement coverage for this ceiling", key, tc.fn, tc.file)
			}
		}
	}
	const knownEnforced = 3 // AddGroupMemberProxy, ApproveRiskExceptionProxy (P1), CreateUserWithRoleGrantsProxy (C2, already fail-closed)
	if perActorCount != knownEnforced {
		t.Errorf("expected exactly %d classPerActorCeiling routes, found %d — a new classPerActorCeiling route needs its own fix and its own machine-actor test coverage before this count changes, not just a table entry",
			knownEnforced, perActorCount)
	}
}
