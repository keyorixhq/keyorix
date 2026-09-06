// permission_sweep_test.go — the CP-001/CP-008 disclosure-family guard, structural
// counterpart to deployment_disclosure_family_test.go's behavioral regression tests.
//
// admin_usage.go and admin_billing.go were the 7th+ confirmed instance of the same
// mistake: gating a deployment-wide, cross-project/cross-user disclosure report on
// system.read (RequirePermission(permSystemRead) or
// RequireScopedPermission(permSystemRead, ...)) in server/http/router.go, when
// system.read is the universal system_viewer baseline auto-assigned to every user at
// creation (CreateUser), every SSO/JIT-provisioned user, and every SCIM-provisioned
// user — see control_framework.go, compliance_posture.go, deployment_hygiene.go,
// machine_token_hygiene.go, pat_hygiene.go, secrets_name_conformance_deployment.go,
// dashboard.go, admin_usage.go, and admin_billing.go's own header comments for the
// full list of prior instances.
//
// This is an AST sweep over server/http/router.go's source text (not the compiled
// package — the point is to catch a regression in the router WIRING itself, before
// any test that spins up the router even runs), asserting that every
// RequirePermission(permSystemRead)/RequireScopedPermission(permSystemRead, ...) call
// site found is explicitly reviewed and justified in the allowlist below. Mirrors
// internal/cli/writeguard's allowlist-with-reasoning convention: a call site the sweep
// finds must either not exist (gated on something stronger instead) or be justified
// here with a written reason, not just a line number. An empty justification, or an
// allowlist entry whose call site the sweep can no longer find, fails the test — see
// TestPermissionSweepAllowlistJustificationsAreNonEmpty and
// TestPermissionSweepAllowlistEntriesStillExist below.
//
// Verified RED against a reverted admin_usage.go/admin_billing.go fix (both routes
// put back on permSystemRead) — TestNoUnjustifiedSystemReadOnlyGates failed with both
// call sites reported as unallowed; GREEN once the fix (audit.read) was restored.
package http

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// permissionSweepAllowlist maps "server/http/router.go:LINE" (the line of the
// RequirePermission/RequireScopedPermission call itself) to a written justification
// for why that route is safe to leave gated on the universal system_viewer baseline
// (system.read) alone, reviewed as part of the admin/usage + admin/billing/report fix.
// Every entry here was traced to its handler (and, where relevant, its core-layer
// implementation) to confirm it returns no cross-tenant/cross-user disclosure that
// system.read's universal grant would expose.
var permissionSweepAllowlist = map[string]string{
	"server/http/router.go:381": "GET /notification-channels/{id}/retry-policy returns only " +
		"max_retries/retry_backoff_ms for one channel ID -- numeric tuning knobs, no secret " +
		"values, no PII, no cross-tenant project/user enumeration. Weaker than the parent " +
		"resource's own read (system.write), a pre-existing minor inconsistency, but not the " +
		"cross-tenant-disclosure bug shape this sweep guards against.",
	"server/http/router.go:404": "GET /dashboard/stats is the caller's OWN home dashboard. " +
		"core.GetDashboardStats (internal/core/dashboard.go) separately scopes the " +
		"deployment-wide aggregate fields (active users, audit-event counts, failed-auth " +
		"counts) to audit.read INSIDE the handler -- a baseline caller gets their own numbers " +
		"with the org-wide aggregates zeroed, not the real deployment-wide figures. See " +
		"TestDashboardStats_PermissionTiers in deployment_disclosure_family_test.go.",
	"server/http/router.go:414": "GET /system/auth-config returns a deliberately redacted, " +
		"non-per-tenant summary of server-wide auth config (session TTLs, password policy " +
		"shape, SSO provider names/types). No secrets (client secrets/SAML metadata/OIDC " +
		"details excluded by MakeAuthConfigHandler's own doc comment), no per-user or " +
		"per-project data to disclose cross-tenant.",
	"server/http/router.go:415": "GET /system/encryption-config returns a deliberately " +
		"redacted, non-per-tenant summary (encryption enabled + KEK provider TYPE only). Key " +
		"material locations (file paths, exec commands, env var names, KMS key IDs) are " +
		"explicitly excluded by MakeEncryptionConfigHandler's own doc comment.",
	"server/http/router.go:422": "GET /system/info returns server version/build/runtime info " +
		"(no per-tenant data) -- the same deployment-wide, non-disclosure-sensitive shape as " +
		"auth-config/encryption-config above.",
	"server/http/router.go:423": "GET /system/metrics returns process-level runtime metrics " +
		"(memory/GC/goroutines) with HTTP/Database/Secrets counters explicitly zeroed (not " +
		"instrumented at this layer per GetMetrics's own comment) -- no per-tenant data.",
	"server/http/router.go:1062": "GET /audit/anomalies sits inside r.Route(\"/audit\", ...) " +
		"which calls r.Use(RequirePermission(permAuditRead)) as a GROUP-level middleware " +
		"(router.go:1044). chi's With() on a route registered inside that group ADDS to, " +
		"never replaces, the group's Use() middleware (verified against go-chi/chi/v5's " +
		"Mux.With/Route/handle: the group's non-inline Mux builds its own handler chain via " +
		"updateRouteHandler, and every route registered inside it -- inline or not -- is " +
		"dispatched through that chain first). So this route actually requires BOTH " +
		"audit.read AND system.read (AND, not OR) -- effectively gated at audit.read, the " +
		"stronger requirement, exactly as router.go's own ANOMALY-04 comment there intends. " +
		"Not a case of \"solely permSystemRead\" despite the literal string match.",
	"server/http/router.go:2069": "GET /license/status returns deployment-wide license " +
		"metadata (plan/features/seat count/expiry) -- not scoped to any tenant/project/user, " +
		"nothing to cross-tenant-disclose.",
	"server/http/router.go:2165": "GET /sod/policies returns policy DEFINITIONS (name + the " +
		"permission-a/permission-b pair) only -- no PII, no violator names. router.go's own " +
		"adjacent comment is explicit that this stays baseline while /sod/violations (which " +
		"DOES disclose violator names/emails) is separately gated on audit.read.",
	"server/http/router.go:2212": "GET /admin/anomaly-config returns the DB-persisted anomaly " +
		"detection THRESHOLDS (config), not any user/project/alert data -- deployment-wide " +
		"config in the same non-disclosure-sensitive family as auth-config/encryption-config " +
		"above. Actual alert data (which does disclose SecretName/AccessedBy/IPAddress " +
		"deployment-wide) is the separate /audit/anomalies route (line 1062 above), already " +
		"gated at effective audit.read.",
}

// site is one RequirePermission(permSystemRead)/RequireScopedPermission(permSystemRead,
// ...) call site found in server/http/router.go.
type site struct {
	line int
	fn   string // "RequirePermission" or "RequireScopedPermission"
}

func (s site) key() string { return "server/http/router.go:" + strconv.Itoa(s.line) }

// repoRoot resolves the repository root relative to THIS test file's own location (not
// the process cwd), so the sweep works regardless of how `go test` is invoked.
func permissionSweepRepoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	require.True(t, ok, "runtime.Caller must resolve this test file's path")
	// this file lives at server/http/permission_sweep_test.go
	root, err := filepath.Abs(filepath.Join(filepath.Dir(thisFile), "..", ".."))
	require.NoError(t, err)
	return root
}

// scanRouterForSystemReadOnlyGates parses server/http/router.go's AST and returns
// every call site where customMiddleware.RequirePermission or
// customMiddleware.RequireScopedPermission is invoked with permSystemRead as its first
// argument (by AST inspection, not string/regex matching, so it isn't fooled by the
// identifier appearing in a comment or string literal).
func scanRouterForSystemReadOnlyGates(t *testing.T, routerGoPath string) map[string]site {
	t.Helper()
	src, err := os.ReadFile(routerGoPath) // #nosec G304 -- fixed repo-internal path, not external input
	require.NoError(t, err)

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, routerGoPath, src, 0)
	require.NoError(t, err)

	found := map[string]site{}
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkgIdent, ok := sel.X.(*ast.Ident)
		if !ok || pkgIdent.Name != "customMiddleware" {
			return true
		}
		if sel.Sel.Name != "RequirePermission" && sel.Sel.Name != "RequireScopedPermission" {
			return true
		}
		if len(call.Args) == 0 {
			return true
		}
		argIdent, ok := call.Args[0].(*ast.Ident)
		if !ok || argIdent.Name != "permSystemRead" {
			return true
		}
		pos := fset.Position(call.Pos())
		s := site{line: pos.Line, fn: sel.Sel.Name}
		found[s.key()] = s
		return true
	})
	return found
}

// TestNoUnjustifiedSystemReadOnlyGates is the guard itself: every
// RequirePermission(permSystemRead)/RequireScopedPermission(permSystemRead, ...) call
// site in server/http/router.go must appear in permissionSweepAllowlist. Reverting the
// admin_usage.go/admin_billing.go fix (putting either route back on permSystemRead)
// must fail this test -- verified RED against exactly that revert; see this file's
// package doc comment.
func TestNoUnjustifiedSystemReadOnlyGates(t *testing.T) {
	routerGoPath := filepath.Join(permissionSweepRepoRoot(t), "server", "http", "router.go")
	found := scanRouterForSystemReadOnlyGates(t, routerGoPath)

	var unallowed []string
	for key, s := range found {
		if _, ok := permissionSweepAllowlist[key]; !ok {
			unallowed = append(unallowed, key+" ("+s.fn+"(permSystemRead))")
		}
	}
	sort.Strings(unallowed)
	assert.Empty(t, unallowed,
		"server/http/router.go gates a route SOLELY on permSystemRead (the universal "+
			"system_viewer baseline every user holds) with no reviewed justification -- "+
			"either require a stricter permission (audit.read for any deployment-wide/"+
			"cross-tenant disclosure -- see admin_usage.go's header comment for why) or add "+
			"a reviewed allowlist entry here with a written justification: %v", unallowed)
}

// TestPermissionSweepAllowlistEntriesStillExist is the flip side of the guard above: an
// allowlist entry for a call site that no longer exists (renamed, deleted, or --
// worse -- silently regressed back onto permSystemRead at a DIFFERENT line, which
// would leave the OLD line's stale entry masking the fact that the sweep no longer
// covers the real site) would hide a regression. A stale entry doesn't fail the sweep
// above (which only checks found-but-unallowed sites), so it's checked here
// explicitly.
func TestPermissionSweepAllowlistEntriesStillExist(t *testing.T) {
	routerGoPath := filepath.Join(permissionSweepRepoRoot(t), "server", "http", "router.go")
	found := scanRouterForSystemReadOnlyGates(t, routerGoPath)

	var stale []string
	for key := range permissionSweepAllowlist {
		if _, ok := found[key]; !ok {
			stale = append(stale, key)
		}
	}
	sort.Strings(stale)
	assert.Empty(t, stale,
		"allowlist entry no longer matches any real RequirePermission(permSystemRead)/"+
			"RequireScopedPermission(permSystemRead, ...) call site in server/http/router.go "+
			"(the code moved, was fixed, or regressed at a different line, without updating "+
			"this list): %v", stale)
}

// TestPermissionSweepAllowlistJustificationsAreNonEmpty guards against an allowlist
// entry added with an empty/placeholder reason, per this campaign's standing rule that
// an exemption needs a written justification, not just a line number.
func TestPermissionSweepAllowlistJustificationsAreNonEmpty(t *testing.T) {
	for key, reason := range permissionSweepAllowlist {
		assert.NotEmpty(t, reason, "allowlist entry %q has no justification", key)
	}
}

// TestPermissionSweepScannerDetectsSystemReadOnlyGates is a self-check on the AST
// sweep itself: a guard that has never been observed to fail on a genuinely bad input
// is not a guard (a test asserting emptiness of a possibly-always-empty scan would
// pass even if the AST matching logic were broken, e.g. matching the wrong selector or
// missing RequireScopedPermission entirely). This proves the scanner actually detects
// both flagged call shapes when present, and does NOT flag permAuditRead or an
// unrelated call, independent of router.go's current contents.
func TestPermissionSweepScannerDetectsSystemReadOnlyGates(t *testing.T) {
	dir := t.TempDir()
	src := `package fixture

type mw struct{}

func (mw) RequirePermission(perm string) func() {return nil}
func (mw) RequireScopedPermission(perm string, scoper func()) func() {return nil}

var customMiddleware mw
var permSystemRead = "system.read"
var permAuditRead = "audit.read"

func bad1() { customMiddleware.RequirePermission(permSystemRead) }
func bad2() { customMiddleware.RequireScopedPermission(permSystemRead, nil) }
func fine1() { customMiddleware.RequirePermission(permAuditRead) }
func fine2() { customMiddleware.RequireScopedPermission(permAuditRead, nil) }
`
	path := filepath.Join(dir, "fixture.go")
	require.NoError(t, os.WriteFile(path, []byte(src), 0o600))

	found := scanRouterForSystemReadOnlyGates(t, path)

	require.Len(t, found, 2, "scanner must find exactly the two permSystemRead call sites, not the two permAuditRead ones")
	var fns []string
	for _, s := range found {
		fns = append(fns, s.fn)
	}
	sort.Strings(fns)
	assert.Equal(t, []string{"RequirePermission", "RequireScopedPermission"}, fns,
		"scanner must detect both RequirePermission and RequireScopedPermission call shapes")
}
