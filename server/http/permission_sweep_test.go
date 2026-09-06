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
	"bytes"
	"go/ast"
	"go/parser"
	"go/printer"
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

// ---------------------------------------------------------------------------
// Broader guard: every registered route must have SOME permission check, not
// just "not solely permSystemRead". Closes the gap the sweep above does not
// cover: a route added with NO RequirePermission/RequireScopedPermission/
// RequireScopedSecretPermission/RequireScopedSecretRefPermission call anywhere
// in its middleware chain -- neither directly on the route nor via r.Use() at
// an enclosing r.Route(...)/r.Group(...) group level -- is a strictly WORSE
// version of the same under-gating shape admin_usage.go/admin_billing.go had
// (gated on nothing beats gated on a universal baseline), and nothing caught
// it before this.
//
// This does NOT replace TestNoUnjustifiedSystemReadOnlyGates above: that sweep
// catches a route gated on SOME permission that turns out to be baseline-
// equivalent (looks administrative, is actually granted to everyone); this one
// only catches a route gated on NO permission at all. A route solely on
// permSystemRead has a non-empty middleware chain, so this broader check sees
// "some permission check present" and passes it through silently -- it would
// NOT have caught the admin_usage.go/admin_billing.go bug this file was
// originally written for. The two checks are complementary, not redundant;
// both run.
//
// Scope: this scanner walks only the NewRouter function's own body (found by
// name in the parsed AST), not the whole file. registerWebUI (this file's
// other route-registering function) wires the SPA's static-asset host
// (/assets/*, /static/*, /sw.js, /manifest.json, /favicon.ico) and the
// client-side-routing NotFound fallback through its own serveStatic closure
// (`rr := r.With(mws...)`), an indirection this AST sweep does not attempt to
// resolve. Those routes serve pre-built, non-per-tenant static files (JS/CSS/
// HTML shell) with no permission concept -- the same public-by-design
// category as /health, /readyz, and /status -- and are out of scope by
// construction rather than silently passed.
//
// Recognizes two things as "some permission check applies", beyond the four
// literal middleware names:
//   - customMiddleware.SCIMToken(...) applied via r.Use() on the /scim/v2
//     group: RFC 7644 SCIM provisioning's own authentication+authorization
//     mechanism is a static shared-secret bearer token, not a per-user RBAC
//     permission grant -- there is no "permission" to check for a machine
//     credential that IS the authorization boundary by design. Every route
//     under /scim/v2 inherits this group-level gate; without recognizing it,
//     all twelve SCIM routes would need individually-repeated allowlist
//     entries pointing at the same one architectural fact.
//   - Group-level r.Use(...) middleware, exactly like the existing sweep's
//     ANOMALY-04 handling of GET /audit/anomalies (router.go:1062 in the
//     allowlist above): chi's With() on a route registered inside a group
//     ADDS to, never replaces, the group's own Use() middleware, and a
//     group's Use() middleware wraps every route dispatched through that
//     group's Mux -- inline or registered via a nested r.Route/r.Group --
//     because the wrapping happens in the Mux's own handler chain before
//     dispatch, not per individual route registration. This sweep reuses
//     that exact reasoning generically: it walks router.go's nesting
//     (r.Route/r.Group closures, and r.Use(...) calls found textually within
//     each) and computes, for every route-registration call
//     (Get/Post/Put/Delete/Patch/Head/Options/Connect/Trace/Handle/Mount),
//     the union of (a) every enclosing group's Use() middleware, walking
//     outward, and (b) every .With(...) call chained directly onto that one
//     route (including a multi-link chain like
//     .With(a).With(b).Post(...), collected by walking the CallExpr's
//     receiver chain back to its base). A route with an empty union in
//     both categories is "no permission check at all".
const (
	// justPreAuthOnboarding covers every route inside the top-level r.Group(...)
	// at router.go:173-213: login itself, MFA/WebAuthn/passkey login second
	// steps, human SSO/SAML flows, and credential-delivery setup links. No
	// session/principal exists yet at any of these -- that IS the point of the
	// route -- so there is no permission to check. The group has no r.Use() at
	// all (see its own header comment), unlike every authenticated group below
	// it.
	justPreAuthOnboarding = "Pre-authentication: no session/principal exists yet at this call (that is the " +
		"route's purpose -- minting one, or a step toward minting one). This whole " +
		"r.Group(...) (router.go:173-213) deliberately has no r.Use() at all -- see the " +
		"group's own header comment -- so every route inside it is unauthenticated by " +
		"design, not an oversight."

	// justPublicInfra covers the unauthenticated liveness/readiness/status/docs
	// family: no per-tenant data, explicitly documented as unauthenticated by
	// each route's own adjacent comment.
	justPublicInfra = "Unauthenticated liveness/readiness/status/docs endpoint, no per-tenant data -- " +
		"see the route's own adjacent comment for why it stays outside both authentication " +
		"and permission checks."

	// justSelfServiceOwnAccount covers the My Account / MFA / WebAuthn /
	// sessions / PAT / notifications family inside /api/v1: authenticated (the
	// group's Authentication/RequireCSRF/EnforceAccountRestriction/
	// EnforceMFAEnrollment middleware all still apply), but acts ONLY on the
	// calling principal's OWN account/session/token/notification, so no RBAC
	// permission concept applies -- ADR-021/ADR-024/ADR-027 establish this
	// whole family as authenticated-but-not-permission-gated by design.
	justSelfServiceOwnAccount = "Self-service: authenticated (this whole route sits inside the /api/v1 group's " +
		"Authentication/RequireCSRF/EnforceAccountRestriction/EnforceMFAEnrollment " +
		"middleware -- see router.go:304-325), but acts ONLY on the calling principal's " +
		"OWN account/session/token/notification. ADR-021/ADR-024/ADR-027 establish this " +
		"whole family (My Account, MFA/WebAuthn self-enrolment, session/PAT self-service, " +
		"in-app notifications) as authenticated-but-not-permission-gated by design -- every " +
		"user manages their own, with no administrative reach into anyone else's. See the " +
		"route's own adjacent comment."
)

// noPermissionGateAllowlist maps "server/http/router.go:LINE" (the line of the
// route-registration call itself) to a written justification for why that
// specific route is safe to leave with no permission-gating middleware
// anywhere in its chain. Every entry was traced to its handler (and, for the
// two in-handler-authorized entries, the actual authorization call inside it)
// to confirm the route is genuinely safe unauthorized/self-scoped, not merely
// unexamined.
var noPermissionGateAllowlist = map[string]string{
	"server/http/router.go:174": justPreAuthOnboarding + " POST /auth/login mints the session itself.",
	"server/http/router.go:180": justPreAuthOnboarding + " POST /auth/logout accepts both session-cookie and " +
		"Bearer callers by design (see its own RequireCSRF-only With(), router.go:180) -- ending a " +
		"session needs no permission on the session's own contents.",
	"server/http/router.go:181": justPreAuthOnboarding + " POST /auth/refresh mints a new access token from a " +
		"still-valid refresh token -- the refresh token itself is the credential.",
	"server/http/router.go:182": justPreAuthOnboarding + " POST /auth/password-reset is the pre-login reset-" +
		"request step (a reset link is emailed, not returned) -- no session to authorize against.",
	"server/http/router.go:185": justPreAuthOnboarding + " POST /auth/mfa/verify's bearer is the single-use " +
		"login challenge issued by /auth/login, not a session.",
	"server/http/router.go:188": justPreAuthOnboarding + " POST /auth/webauthn/login/begin's bearer is the same " +
		"single-use login challenge.",
	"server/http/router.go:189": justPreAuthOnboarding + " POST /auth/webauthn/login/finish completes the same " +
		"unauthenticated ceremony as login/begin immediately above.",
	"server/http/router.go:192": justPreAuthOnboarding + " POST /auth/webauthn/passwordless/begin is the " +
		"usernameless passkey login's first step (ADR-036 addendum) -- no session exists.",
	"server/http/router.go:193": justPreAuthOnboarding + " POST /auth/webauthn/passwordless/finish completes " +
		"the same ceremony as passwordless/begin immediately above.",
	"server/http/router.go:194": justPreAuthOnboarding + " POST /system/init bootstraps the FIRST admin " +
		"account/credentials on an empty deployment -- by definition no principal, let alone a " +
		"permission, exists yet.",
	"server/http/router.go:198": justPreAuthOnboarding + " GET /auth/setup/{token}'s bearer is the single-use " +
		"setup token in the URL (ADR-028), not a session.",
	"server/http/router.go:199": justPreAuthOnboarding + " POST /auth/setup/consume's bearer is the same setup " +
		"token, consumed to mint the account's first real credentials.",
	"server/http/router.go:205": justPreAuthOnboarding + " GET /auth/sso/providers lists configured SSO " +
		"providers for the (pre-login) login page to render.",
	"server/http/router.go:206": justPreAuthOnboarding + " GET /auth/sso/{provider}/login redirects to the " +
		"IdP -- the IdP is the authenticator, not this server.",
	"server/http/router.go:207": justPreAuthOnboarding + " GET /auth/sso/{provider}/callback is the IdP's " +
		"redirect back after IT authenticated the user.",
	"server/http/router.go:210": justPreAuthOnboarding + " GET /auth/saml/{provider}/metadata serves this SP's " +
		"own public SAML metadata document for the IdP admin to configure -- no user context at all.",
	"server/http/router.go:211": justPreAuthOnboarding + " GET /auth/saml/{provider}/login redirects to the " +
		"IdP's AuthnRequest endpoint, same as the OIDC login redirect above.",
	"server/http/router.go:212": justPreAuthOnboarding + " POST /auth/saml/{provider}/acs is the SAML " +
		"Assertion Consumer Service -- the IdP's assertion IS the authentication, same trust model as " +
		"the OIDC callback above.",

	"server/http/router.go:217":  justPublicInfra + " GET /health is a liveness probe (no DB touch).",
	"server/http/router.go:221":  justPublicInfra + " GET /readyz is a readiness probe (DB reachability only).",
	"server/http/router.go:240":  justPublicInfra + " /metrics is Prometheus scrape target; optionally protected by a separate static-bearer-token check (cfg.Server.HTTP.MetricsToken) when configured -- a deployment-perimeter control, not RBAC.",
	"server/http/router.go:243":  justPublicInfra + " GET /status serves the public status dashboard (or falls back to the health check).",
	"server/http/router.go:259":  justPublicInfra + " GET /status-es is the Spanish-language mirror of /status immediately above.",
	"server/http/router.go:2223": justPublicInfra + " Swagger UI is gated by cfg.Server.HTTP.SwaggerEnabled (a deployment config flag, not a per-caller permission) -- see the adjacent comment; the machine-readable API surface it exposes is the same shape /openapi.yaml exposes below.",
	"server/http/router.go:2224": justPublicInfra + " GET /openapi.yaml is the raw OpenAPI spec, gated by the same cfg.Server.HTTP.SwaggerEnabled flag as the Swagger UI immediately above (#224 fixed the two having diverging on/off behavior; they must stay paired).",

	"server/http/router.go:330": justSelfServiceOwnAccount + " GET/PUT /auth/profile.",
	"server/http/router.go:331": justSelfServiceOwnAccount + " GET/PUT /auth/profile.",
	"server/http/router.go:332": justSelfServiceOwnAccount + " POST /auth/change-password changes only the caller's own password.",
	"server/http/router.go:337": justSelfServiceOwnAccount + " POST /auth/mfa/enroll starts enrolling the caller's OWN second factor; blocked under impersonation (BlockWhenImpersonating) so an admin acting as a user cannot plant a durable credential.",
	"server/http/router.go:338": justSelfServiceOwnAccount + " POST /auth/mfa/activate activates the caller's OWN pending enrolment; same impersonation block as enroll above.",
	"server/http/router.go:339": justSelfServiceOwnAccount + " POST /auth/mfa/disable disables only the caller's OWN MFA; same impersonation block.",
	"server/http/router.go:340": justSelfServiceOwnAccount + " GET /auth/mfa/recovery-codes/status reads only the caller's OWN recovery-code status.",
	"server/http/router.go:341": justSelfServiceOwnAccount + " POST recovery-codes/regenerate regenerates only the caller's OWN codes; same impersonation block.",
	"server/http/router.go:346": justSelfServiceOwnAccount + " POST /auth/mfa/stepup re-verifies the caller's OWN TOTP/recovery code to open their own restricted-secret read window; same impersonation block.",
	"server/http/router.go:348": justSelfServiceOwnAccount + " POST webauthn/register/begin registers a passkey for the caller's OWN account; same impersonation block.",
	"server/http/router.go:349": justSelfServiceOwnAccount + " POST webauthn/register/finish completes the same ceremony as register/begin above.",
	"server/http/router.go:350": justSelfServiceOwnAccount + " GET webauthn/credentials lists only the caller's OWN passkeys.",
	"server/http/router.go:355": justSelfServiceOwnAccount + " DELETE webauthn/credentials/{id} deletes only the caller's OWN passkey (there is no admin API to remove another user's passkey); same impersonation block, since deleting the last passkey is the same durable MFA-downgrade /auth/mfa/disable is blocked from doing.",
	"server/http/router.go:356": justSelfServiceOwnAccount + " GET /auth/sessions lists only the caller's OWN sessions.",
	"server/http/router.go:357": justSelfServiceOwnAccount + " DELETE /auth/sessions/{id} revokes only one of the caller's OWN sessions.",
	"server/http/router.go:358": justSelfServiceOwnAccount + " GET /auth/tokens lists only the caller's OWN PATs.",
	"server/http/router.go:361": justSelfServiceOwnAccount + " POST /auth/tokens mints a PAT for the caller's OWN account; blocked under impersonation so an admin acting as a user cannot plant a durable token.",
	"server/http/router.go:362": justSelfServiceOwnAccount + " DELETE /auth/tokens/{id} revokes only one of the caller's OWN PATs.",
	"server/http/router.go:364": justSelfServiceOwnAccount + " GET tokens/expired lists only the caller's OWN expired PATs.",
	"server/http/router.go:365": justSelfServiceOwnAccount + " DELETE tokens/expired bulk-revokes only the caller's OWN expired PATs.",
	"server/http/router.go:367": justSelfServiceOwnAccount + " POST /auth/end-impersonation ends only the CALLER'S OWN impersonation session.",
	"server/http/router.go:370": justSelfServiceOwnAccount + " GET /notifications lists only the caller's OWN in-app notifications (ADR-024).",
	"server/http/router.go:371": justSelfServiceOwnAccount + " POST notifications/read-all marks only the caller's OWN notifications read.",
	"server/http/router.go:372": justSelfServiceOwnAccount + " POST notifications/{id}/read marks one of the caller's OWN notifications read.",

	"server/http/router.go:499": "Self-service (ADR-024): POST /projects/{id}/access-requests lets an " +
		"authenticated user request access to a project THEY DO NOT YET HAVE -- by definition they " +
		"cannot hold a project-scoped permission on it yet, so no permission check can gate the " +
		"request itself (core.RequestProjectAccess scopes the created row to the caller's own " +
		"user ID). See router.go's own adjacent comment (\"requesting + withdrawing are self-" +
		"service\") and handlers/invitations.go's CreateAccessRequest.",
	"server/http/router.go:501": "Self-service (ADR-024): POST access-requests/{requestId}/withdraw withdraws " +
		"only the CALLER'S OWN pending request (core.WithdrawAccessRequest scopes to the requester). " +
		"Same reasoning as CreateAccessRequest immediately above.",
	"server/http/router.go:517": "Self-service by design: POST /projects/{id}/break-glass activates " +
		"emergency access the caller currently LACKS -- the entire point of break-glass is bypassing " +
		"the normal grant path, so gating it on a permission would defeat its purpose. Controlled " +
		"instead by deployment config + a mandatory justification + full audit trail + automatic " +
		"expiry (NIS2/DORA incident response). Blocked under impersonation (BlockWhenImpersonating) " +
		"so an admin acting as a user cannot mint a durable emergency role grant attributed to the " +
		"target. See router.go's own adjacent comment.",

	"server/http/router.go:610": "GET /secrets (ListSecrets) performs its own authorization INSIDE the " +
		"handler so a project-scoped reader gets the union of their accessible scopes rather than a " +
		"403 on an unfiltered request -- see router.go's own adjacent comment and secrets_list.go. " +
		"An unscoped/no-permission caller still only ever sees the empty-or-narrowed result their " +
		"own scopes permit, never another caller's secrets.",
	"server/http/router.go:612": "GET /secrets/policy returns the deployment's ACTIVE create-time naming/" +
		"value policy -- deployment-wide, non-per-tenant configuration every authenticated caller " +
		"needs visibility into before they can even attempt a create (the same policy a create " +
		"request would be validated against). No secret values, no per-tenant data. See router.go's " +
		"own adjacent comment (\"any authenticated caller\").",
	"server/http/router.go:706": "POST /secrets (CreateSecret) is authorized INSIDE the handler: scope " +
		"(project/environment) comes from the request body, not a URL path param a scope resolver " +
		"middleware could resolve ahead of the handler. See router.go's own adjacent comment " +
		"(\"Create: authorized inside the handler (scope comes from the body)\").",
	"server/http/router.go:727": "DELETE /secrets/{id}/self-share (RemoveSelfFromShare) removes only the " +
		"CALLER'S OWN direct share (core only removes a share whose RecipientID == the caller) -- " +
		"self-service on the caller's own grant, needs just authentication. See router.go's own " +
		"adjacent comment.",
	"server/http/router.go:752": "POST /folders (CreateFolder) is authorized INSIDE the handler: scope " +
		"comes from the request body, the same in-handler-authorization pattern as CreateSecret " +
		"above. See router.go's own adjacent comment (\"Create authorizes in-handler (scope from the " +
		"body)\").",
	"server/http/router.go:774": "POST /rotation-policies (Create) is authorized INSIDE the handler: scope " +
		"comes from the request body, the same in-handler pattern as CreateSecret/CreateFolder above. " +
		"See router.go's own adjacent comment (\"create authorizes in-handler against the body\").",
	"server/http/router.go:803": "POST /dynamic-secrets/configs (CreateConfig) is authorized INSIDE the " +
		"handler -- traced to the actual code, not just the group's header comment: " +
		"DynamicSecretHandler.CreateConfig (server/http/handlers/dynamic_secrets.go) calls " +
		"h.authorize(r, permSecretsWrite, scope) itself before creating the config.",
	"server/http/router.go:804": "GET /dynamic-secrets/configs (ListConfigs) is authorized INSIDE the " +
		"handler -- traced to the actual code: DynamicSecretHandler.ListConfigs " +
		"(server/http/handlers/dynamic_secrets.go) calls h.authorize(r, permSecretsRead, " +
		"core.Scope{ProjectID: projectID, EnvironmentID: environmentID}) itself before listing.",
}

// permissionGateMiddleware is every customMiddleware function name recognized
// as satisfying "some permission check applies" for the broader sweep below.
// The four permission-check shapes match this file's own package doc
// (RequirePermission/RequireScopedPermission/RequireScopedSecretPermission/
// RequireScopedSecretRefPermission). RequireNodeCredential is included for
// forward compatibility only -- it exists in server/middleware/node_credential.go
// but router.go does not currently call it anywhere (the /system group's node-
// credential arm, RequireNodeCredentialOrPermission, was removed by ADR-085;
// see router.go's own header comment on the /system group) -- if a future
// change reintroduces a node-credential gate, this sweep should recognize it
// without needing its own follow-up patch.
var permissionGateMiddleware = map[string]bool{
	"RequirePermission":                 true,
	"RequireScopedPermission":           true,
	"RequireScopedSecretPermission":     true,
	"RequireScopedSecretRefPermission":  true,
	"RequireNodeCredential":             true,
	"RequireNodeCredentialOrPermission": true,
	// SCIMToken is not permission-shaped (no `permission string` argument) but
	// is the sole, deliberate authentication+authorization mechanism for the
	// whole /scim/v2 group -- see the package doc above.
	"SCIMToken": true,
}

// chiRouteRegistrationMethods is every chi.Router method this sweep treats as
// registering a reachable route that needs authorization. "Route" and "Group"
// are handled separately (they open a new nested scope, not a route).
var chiRouteRegistrationMethods = map[string]bool{
	"Get": true, "Post": true, "Put": true, "Delete": true, "Patch": true,
	"Head": true, "Options": true, "Connect": true, "Trace": true,
	"Handle": true, "HandleFunc": true, "Mount": true,
}

// ungatedRoute is one route-registration call site in router.go's NewRouter
// function found to have no applicable permission-gating middleware, from
// neither a direct .With(...) chain on the call nor any enclosing group's
// r.Use(...).
type ungatedRoute struct {
	line    int
	method  string
	pattern string
}

func (u ungatedRoute) key() string { return "server/http/router.go:" + strconv.Itoa(u.line) }

// isPermissionGateCall reports whether expr is a call of the shape
// customMiddleware.<one of permissionGateMiddleware>(...). Bare identifiers/
// selectors passed without being called (e.g. customMiddleware.
// BlockWhenImpersonating, which takes no config argument) are deliberately
// NOT matched -- every real permission-check middleware in this codebase
// takes at least a permission-string argument, so it is always invoked, never
// passed bare.
func isPermissionGateCall(expr ast.Expr) bool {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkgIdent, ok := sel.X.(*ast.Ident)
	if !ok || pkgIdent.Name != "customMiddleware" {
		return false
	}
	return permissionGateMiddleware[sel.Sel.Name]
}

// collectWithArgs walks a chi call-chain receiver expression backward through
// any number of chained .With(...) calls (e.g. r.With(a).With(b), or the
// single-call r.With(a, b) form), collecting every argument passed to every
// With() found, and returns them alongside the chain's base expression (the
// router variable itself, e.g. the Ident "r").
func collectWithArgs(expr ast.Expr) (withArgs []ast.Expr, base ast.Expr) {
	for {
		call, ok := expr.(*ast.CallExpr)
		if !ok {
			return withArgs, expr
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return withArgs, expr
		}
		if sel.Sel.Name != "With" {
			return withArgs, expr
		}
		withArgs = append(withArgs, call.Args...)
		expr = sel.X
	}
}

// exprSourceText renders an AST expression back to source text (e.g. a string
// literal, a named path constant like pathGroups, or a "/x/" + pathIDRestore
// concatenation) for a readable failure message, without needing to evaluate
// string constants.
func exprSourceText(fset *token.FileSet, expr ast.Expr) string {
	var buf bytes.Buffer
	if err := printer.Fprint(&buf, fset, expr); err != nil {
		return "<unresolvable>"
	}
	return buf.String()
}

// scanBlockForUngatedRoutes walks stmts (one block's statements -- the body of
// NewRouter itself, or the FuncLit body passed to an r.Route(...)/r.Group(...)
// call) looking for route-registration calls with no applicable permission
// gate. inherited is the union of every enclosing group's own r.Use(...)
// permission-gate middleware (empty at NewRouter's top level). Nested
// r.Route/r.Group closures recurse with inherited widened by this block's own
// r.Use(...) calls, mirroring how a chi group's Use() middleware wraps every
// request dispatched into that group's Mux, at any nesting depth.
func scanBlockForUngatedRoutes(fset *token.FileSet, stmts []ast.Stmt, inherited bool, found *[]ungatedRoute) {
	blockGated := inherited
	for _, stmt := range stmts {
		exprStmt, ok := stmt.(*ast.ExprStmt)
		if !ok {
			continue
		}
		call, ok := exprStmt.X.(*ast.CallExpr)
		if !ok {
			continue
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Use" {
			continue
		}
		for _, arg := range call.Args {
			if isPermissionGateCall(arg) {
				blockGated = true
			}
		}
	}

	for _, stmt := range stmts {
		switch s := stmt.(type) {
		case *ast.ExprStmt:
			scanExprForUngatedRoute(fset, s.X, blockGated, found)
		case *ast.IfStmt:
			if s.Body != nil {
				scanBlockForUngatedRoutes(fset, s.Body.List, blockGated, found)
			}
			if elseBlock, ok := s.Else.(*ast.BlockStmt); ok {
				scanBlockForUngatedRoutes(fset, elseBlock.List, blockGated, found)
			}
		}
	}
}

// scanExprForUngatedRoute inspects one top-level statement expression. It
// recurses into r.Route(pattern, func(r chi.Router) {...}) and
// r.Group(func(r chi.Router) {...}) closures as nested scopes; for a chi
// route-registration call (Get/Post/.../Mount), it determines the union of
// this block's inherited group gate and any .With(...) chained directly onto
// the call, and records the call site if that union is empty.
func scanExprForUngatedRoute(fset *token.FileSet, expr ast.Expr, blockGated bool, found *[]ungatedRoute) {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return
	}

	switch sel.Sel.Name {
	case "Route":
		if len(call.Args) >= 2 {
			if fn, ok := call.Args[1].(*ast.FuncLit); ok && fn.Body != nil {
				scanBlockForUngatedRoutes(fset, fn.Body.List, blockGated, found)
			}
		}
		return
	case "Group":
		if len(call.Args) >= 1 {
			if fn, ok := call.Args[0].(*ast.FuncLit); ok && fn.Body != nil {
				scanBlockForUngatedRoutes(fset, fn.Body.List, blockGated, found)
			}
		}
		return
	}

	if !chiRouteRegistrationMethods[sel.Sel.Name] {
		return
	}

	withArgs, _ := collectWithArgs(sel.X)
	gated := blockGated
	for _, arg := range withArgs {
		if isPermissionGateCall(arg) {
			gated = true
		}
	}
	if gated {
		return
	}
	if len(call.Args) == 0 {
		return
	}
	pos := fset.Position(call.Pos())
	*found = append(*found, ungatedRoute{
		line:    pos.Line,
		method:  sel.Sel.Name,
		pattern: exprSourceText(fset, call.Args[0]),
	})
}

// findNewRouterFunc locates the top-level `func NewRouter(...)` declaration in
// the parsed file. The sweep is deliberately scoped to this one function --
// see the package doc above for why registerWebUI is out of scope.
func findNewRouterFunc(f *ast.File) *ast.FuncDecl {
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if ok && fn.Name.Name == "NewRouter" && fn.Body != nil {
			return fn
		}
	}
	return nil
}

// scanRouterForUngatedRoutes parses server/http/router.go's AST and returns
// every route-registration call within NewRouter that has no applicable
// permission-gating middleware, keyed by call-site line.
func scanRouterForUngatedRoutes(t *testing.T, routerGoPath string) map[string]ungatedRoute {
	t.Helper()
	src, err := os.ReadFile(routerGoPath) // #nosec G304 -- fixed repo-internal path, not external input
	require.NoError(t, err)

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, routerGoPath, src, 0)
	require.NoError(t, err)

	newRouter := findNewRouterFunc(f)
	require.NotNil(t, newRouter, "server/http/router.go must declare func NewRouter(...)")

	var found []ungatedRoute
	scanBlockForUngatedRoutes(fset, newRouter.Body.List, false, &found)

	byKey := map[string]ungatedRoute{}
	for _, u := range found {
		byKey[u.key()] = u
	}
	return byKey
}

// TestNoUngatedRoutes is the broader guard itself: every route registered in
// NewRouter must have some applicable permission check (see the package doc
// above for exactly what counts), or a reviewed allowlist entry here
// justifying why that specific route is safe to leave unauthorized (a public,
// pre-authentication, or genuinely self-service route) or authorizes itself
// a different way (in-handler, e.g. ListSecrets/CreateSecret's own
// authorization -- see secrets_list.go / secret_create.go).
func TestNoUngatedRoutes(t *testing.T) {
	routerGoPath := filepath.Join(permissionSweepRepoRoot(t), "server", "http", "router.go")
	found := scanRouterForUngatedRoutes(t, routerGoPath)

	var unallowed []string
	for key, u := range found {
		if _, ok := noPermissionGateAllowlist[key]; !ok {
			unallowed = append(unallowed, key+" ("+u.method+" "+u.pattern+")")
		}
	}
	sort.Strings(unallowed)
	assert.Empty(t, unallowed,
		"server/http/router.go registers a route with NO permission check anywhere in its "+
			"middleware chain (neither directly on the route nor via r.Use() at an enclosing "+
			"group) -- a strictly worse version of the admin_usage.go/admin_billing.go bug "+
			"(gated on nothing, not just gated on the universal baseline). Either add a "+
			"RequirePermission/RequireScopedPermission/RequireScopedSecretPermission/"+
			"RequireScopedSecretRefPermission gate (directly or via the enclosing group's "+
			"r.Use()), or add a reviewed allowlist entry here with a written justification: %v",
		unallowed)
}

// TestNoPermissionGateAllowlistEntriesStillExist mirrors
// TestPermissionSweepAllowlistEntriesStillExist above: an allowlist entry
// whose call site no longer exists (moved, deleted, or regressed onto a
// DIFFERENT now-ungated line) would silently stop covering anything.
func TestNoPermissionGateAllowlistEntriesStillExist(t *testing.T) {
	routerGoPath := filepath.Join(permissionSweepRepoRoot(t), "server", "http", "router.go")
	found := scanRouterForUngatedRoutes(t, routerGoPath)

	var stale []string
	for key := range noPermissionGateAllowlist {
		if _, ok := found[key]; !ok {
			stale = append(stale, key)
		}
	}
	sort.Strings(stale)
	assert.Empty(t, stale,
		"allowlist entry no longer matches any real ungated route-registration call site in "+
			"server/http/router.go (the code moved, gained a permission gate, or regressed at a "+
			"different line, without updating this list): %v", stale)
}

// TestNoPermissionGateAllowlistJustificationsAreNonEmpty mirrors
// TestPermissionSweepAllowlistJustificationsAreNonEmpty above.
func TestNoPermissionGateAllowlistJustificationsAreNonEmpty(t *testing.T) {
	for key, reason := range noPermissionGateAllowlist {
		assert.NotEmpty(t, reason, "allowlist entry %q has no justification", key)
	}
}

// TestUngatedRouteScannerDetectsMissingPermissionChecks is the broader
// sweep's self-check, mirroring
// TestPermissionSweepScannerDetectsSystemReadOnlyGates above: proves the
// scanner actually flags a genuinely ungated route, does NOT flag a route
// gated directly via .With(...), does NOT flag a route gated only via an
// enclosing group's r.Use(...), correctly follows a chained
// .With(a).With(b) call, and correctly treats a nested r.Route(...) group
// inside another group as inheriting the OUTER group's gate too.
func TestUngatedRouteScannerDetectsMissingPermissionChecks(t *testing.T) {
	dir := t.TempDir()
	src := `package fixture

type mw struct{}

func (mw) RequirePermission(perm string) func() { return nil }
func (mw) BlockWhenImpersonating() {}

var customMiddleware mw
var permSecretsRead = "secrets.read"
var permSecretsWrite = "secrets.write"

type fakeRouter struct{}

func (fakeRouter) Use(mws ...func())                              {}
func (fakeRouter) With(mws ...func()) fakeRouter                  { return fakeRouter{} }
func (fakeRouter) Get(pattern string, h func())                   {}
func (fakeRouter) Post(pattern string, h func())                  {}
func (fakeRouter) Route(pattern string, fn func(r fakeRouter))    {}
func (fakeRouter) Group(fn func(r fakeRouter))                    {}

func NewRouter() {
	r := fakeRouter{}

	// (1) ungated: no With(), no enclosing group Use().
	r.Get("/ungated", nil)

	// (2) gated directly.
	r.With(customMiddleware.RequirePermission(permSecretsRead)).Get("/gated-direct", nil)

	// (3) NOT gated: With() present but only a non-permission middleware.
	r.With(customMiddleware.BlockWhenImpersonating).Post("/self-service-not-gated", nil)

	// (4) gated via a chained multi-With call.
	r.With(customMiddleware.BlockWhenImpersonating).With(customMiddleware.RequirePermission(permSecretsWrite)).Post("/gated-chained", nil)

	r.Route("/group", func(r fakeRouter) {
		r.Use(customMiddleware.RequirePermission(permSecretsRead))
		// (5) gated via the enclosing group's Use(), no direct With() at all.
		r.Get("/group/inherited", nil)

		r.Route("/nested", func(r fakeRouter) {
			// (6) gated via the OUTER group's Use(), two levels up.
			r.Get("/group/nested/still-inherited", nil)
		})
	})
}
`
	path := filepath.Join(dir, "fixture.go")
	require.NoError(t, os.WriteFile(path, []byte(src), 0o600))

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	require.NoError(t, err)
	newRouter := findNewRouterFunc(f)
	require.NotNil(t, newRouter)

	var found []ungatedRoute
	scanBlockForUngatedRoutes(fset, newRouter.Body.List, false, &found)

	var patterns []string
	for _, u := range found {
		patterns = append(patterns, u.pattern)
	}
	sort.Strings(patterns)
	assert.Equal(t, []string{`"/self-service-not-gated"`, `"/ungated"`}, patterns,
		"scanner must flag exactly the two routes with no applicable permission gate, and "+
			"none of the four gated ones (direct, chained-With, group-inherited, "+
			"nested-group-inherited)")
}
