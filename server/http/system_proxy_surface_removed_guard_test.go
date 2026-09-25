// system_proxy_surface_removed_guard_test.go asserts every route the deleted
// /system RemoteStorage proxy tier (ADR-108 Phase 6, 14c-1/14c-2) used to
// register now 404s on a real router, not just that the source files are
// gone. This replaces the job the deleted authz-ceiling guards
// (system_write_ceiling_walk_test.go, role_grant_authority_guard_test.go,
// system_proxy_g3_gap_probes_test.go, and others) used to do for this
// surface: proving it can't silently come back. Those guards asserted "every
// /system route has a correct authority ceiling"; this one asserts the
// simpler, now-correct claim: "no /system route exists at all" (except the
// handful of genuinely live, non-proxy routes listed in liveSystemPrefixedRoutes
// below, which were always registered separately, outside the deleted
// r.Route("/system", ...) block, and are asserted present, not absent).
//
// The 149 routes below were extracted mechanically from router.go as it
// existed immediately before the 14c-1 deletion (an AST walk over
// r.Route("/system", ...), resolving path constants the same way
// raw_storage_bypass_guard_test.go's extractAllRouterRoutes does), not
// hand-transcribed -- see reports/CLI-RELEASE.md's Phase 6 step 5 inventory
// for the full route -> class -> consumer-evidence table this list is drawn
// from. A path parameter placeholder ({id}, {roleId}, etc.) is substituted
// with a fixed literal before the request, since chi routing needs a
// concrete path segment; the placeholder value never matters for a route
// that no longer exists at all.
package http

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
)

// splitRouteLine splits a "METHOD /path" entry into its two parts.
func splitRouteLine(t *testing.T, route string) (method, path string) {
	t.Helper()
	parts := strings.SplitN(route, " ", 2)
	if len(parts) != 2 {
		t.Fatalf("malformed route entry: %q", route)
	}
	return parts[0], parts[1]
}

// deletedSystemProxyRoutes is every (method, path) pair registered anywhere
// inside router.go's now-deleted r.Route("/system", ...) block.
var deletedSystemProxyRoutes = []string{
	"DELETE /api/v1/system/environments/{id}",
	"DELETE /api/v1/system/groups/{id}",
	"DELETE /api/v1/system/groups/{id}/members/{userId}",
	"DELETE /api/v1/system/machine-identities/{id}/roles/{roleId}",
	"DELETE /api/v1/system/machine-oidc-bindings/{id}",
	"DELETE /api/v1/system/projects/{id}",
	"DELETE /api/v1/system/sod-policies/{id}",
	"GET /api/v1/system/access-activity/role-management",
	"GET /api/v1/system/access-activity/secret",
	"GET /api/v1/system/access-activity/secret-deletion",
	"GET /api/v1/system/access-activity/secret-read",
	"GET /api/v1/system/access-activity/secret-write",
	"GET /api/v1/system/access-requests",
	"GET /api/v1/system/access-requests/{id}",
	"GET /api/v1/system/access-requests/{id}/approvals",
	"GET /api/v1/system/access-review-campaigns",
	"GET /api/v1/system/access-review-campaigns/items/{itemID}",
	"GET /api/v1/system/access-review-campaigns/latest-closed",
	"GET /api/v1/system/access-review-campaigns/open",
	"GET /api/v1/system/access-review-campaigns/{id}",
	"GET /api/v1/system/access-review-campaigns/{id}/items",
	"GET /api/v1/system/access-review-campaigns/{id}/items/pending-count",
	"GET /api/v1/system/break-glass",
	"GET /api/v1/system/break-glass/{id}",
	"GET /api/v1/system/connect-grants",
	"GET /api/v1/system/connect-grants/by-connector/{connector}",
	"GET /api/v1/system/dynamic-secrets/configs",
	"GET /api/v1/system/dynamic-secrets/configs/classification-counts",
	"GET /api/v1/system/dynamic-secrets/configs/{id}",
	"GET /api/v1/system/dynamic-secrets/leases",
	"GET /api/v1/system/dynamic-secrets/leases/active-count",
	"GET /api/v1/system/dynamic-secrets/leases/expired",
	"GET /api/v1/system/dynamic-secrets/leases/{leaseID}",
	"GET /api/v1/system/environments",
	"GET /api/v1/system/environments/{id}",
	"GET /api/v1/system/groups",
	"GET /api/v1/system/groups/members-by-ids",
	"GET /api/v1/system/groups/page",
	"GET /api/v1/system/groups/{id}",
	"GET /api/v1/system/groups/{id}/members",
	"GET /api/v1/system/invitations",
	"GET /api/v1/system/invitations/{id}",
	"GET /api/v1/system/legal-hold/active",
	"GET /api/v1/system/login-attempts/count",
	"GET /api/v1/system/machine-credentials/active",
	"GET /api/v1/system/machine-credentials/by-hash/{hash}",
	"GET /api/v1/system/machine-credentials/classification-counts",
	"GET /api/v1/system/machine-credentials/{id}",
	"GET /api/v1/system/machine-identities",
	"GET /api/v1/system/machine-identities/all",
	"GET /api/v1/system/machine-identities/classification-counts",
	"GET /api/v1/system/machine-identities/{id}",
	"GET /api/v1/system/machine-identities/{id}/credentials",
	"GET /api/v1/system/machine-identities/{id}/oidc-bindings",
	"GET /api/v1/system/machine-identities/{id}/roles",
	"GET /api/v1/system/machine-identities/{id}/roles/ids",
	"GET /api/v1/system/machine-oidc-bindings/by-subject",
	"GET /api/v1/system/machine-oidc-bindings/{id}",
	"GET /api/v1/system/mfa/recovery-codes/count",
	"GET /api/v1/system/mfa/secrets",
	"GET /api/v1/system/project-memberships",
	"GET /api/v1/system/project-memberships/active",
	"GET /api/v1/system/project-memberships/by-user/{userID}",
	"GET /api/v1/system/project-memberships/counts",
	"GET /api/v1/system/project-memberships/stale",
	"GET /api/v1/system/project-memberships/{id}",
	"GET /api/v1/system/projects",
	"GET /api/v1/system/projects/with-counts",
	"GET /api/v1/system/projects/{id}",
	"GET /api/v1/system/projects/{id}/environments",
	"GET /api/v1/system/projects/{id}/members",
	"GET /api/v1/system/rbac/groups/{groupID}/role-assignments",
	"GET /api/v1/system/rbac/groups/{groupID}/role-grants",
	"GET /api/v1/system/rbac/project-machine-role-assignments",
	"GET /api/v1/system/rbac/project-role-assignments",
	"GET /api/v1/system/retention/users/stale",
	"GET /api/v1/system/risk-exceptions",
	"GET /api/v1/system/risk-exceptions/{id}",
	"GET /api/v1/system/secret-dependencies",
	"GET /api/v1/system/secret-dependencies/{id}",
	"GET /api/v1/system/secrets/{id}/including-deleted",
	"GET /api/v1/system/setup-tokens/by-hash/{hash}",
	"GET /api/v1/system/setup-tokens/count",
	"GET /api/v1/system/shares/by-owner/{ownerID}",
	"GET /api/v1/system/shares/by-user/{userID}",
	"GET /api/v1/system/sod-policies",
	"GET /api/v1/system/sod-policies/{id}",
	"GET /api/v1/system/users/{id}/groups",
	"GET /api/v1/system/webauthn/credentials",
	"GET /api/v1/system/webauthn/credentials/count",
	"GET /api/v1/system/webauthn/credentials/lookup",
	"PATCH /api/v1/system/webauthn/credentials/advance-counter",
	"POST /api/v1/system/access-requests",
	"POST /api/v1/system/access-requests/{id}/approvals",
	"POST /api/v1/system/access-review-campaigns",
	"POST /api/v1/system/access-review-campaigns/{id}/items",
	"POST /api/v1/system/audit/event",
	"POST /api/v1/system/break-glass/{id}/revoke",
	"POST /api/v1/system/groups",
	"POST /api/v1/system/groups/{id}/members",
	"POST /api/v1/system/groups/{id}/restore",
	"POST /api/v1/system/invitations",
	"POST /api/v1/system/legal-hold",
	"POST /api/v1/system/login-attempts",
	"POST /api/v1/system/login-attempts/prune",
	"POST /api/v1/system/machine-credentials",
	"POST /api/v1/system/machine-credentials/{id}/revoke",
	"POST /api/v1/system/machine-credentials/{id}/touch",
	"POST /api/v1/system/machine-identities",
	"POST /api/v1/system/machine-identities/{id}/roles/{roleId}",
	"POST /api/v1/system/machine-oidc-bindings",
	"POST /api/v1/system/mfa/stepup-grants/active",
	"POST /api/v1/system/mfa/stepup-grants/prune",
	"POST /api/v1/system/mfa/totp-step-used",
	"POST /api/v1/system/notifications",
	"POST /api/v1/system/project-memberships",
	"POST /api/v1/system/projects/{id}/delete-if-empty",
	"POST /api/v1/system/rbac/assign-role-to-group-with-expiry",
	"POST /api/v1/system/rbac/assign-role-with-expiry",
	"POST /api/v1/system/rbac/clear-project-secret-ownership",
	"POST /api/v1/system/rbac/delete-secret-acls-by-user-and-project",
	"POST /api/v1/system/rbac/global-admin-role/remove-guarded",
	"POST /api/v1/system/rbac/remove-all-project-role-grants",
	"POST /api/v1/system/retention/role-grants/purge-expired",
	"POST /api/v1/system/retention/share-records/purge-expired",
	"POST /api/v1/system/risk-exceptions",
	"POST /api/v1/system/secret-dependencies/exclusive",
	"POST /api/v1/system/setup-tokens",
	"POST /api/v1/system/setup-tokens/supersede",
	"POST /api/v1/system/setup-tokens/{id}/expire",
	"POST /api/v1/system/sod-policies",
	"POST /api/v1/system/sso-state",
	"POST /api/v1/system/sso-state/consume",
	"POST /api/v1/system/users/with-role-grants",
	"POST /api/v1/system/users/{id}/personal-access-tokens/revoke-all",
	"POST /api/v1/system/users/{id}/sessions/delete-except",
	"POST /api/v1/system/webauthn/sessions",
	"POST /api/v1/system/webauthn/sessions/consume",
	"PUT /api/v1/system/access-requests/{id}",
	"PUT /api/v1/system/access-review-campaigns/items/{itemID}",
	"PUT /api/v1/system/groups/{id}",
	"PUT /api/v1/system/invitations/{id}",
	"PUT /api/v1/system/legal-hold/{id}",
	"PUT /api/v1/system/machine-credentials/{id}",
	"PUT /api/v1/system/machine-identities/{id}/transition",
	"PUT /api/v1/system/project-memberships/{id}/transition",
	"PUT /api/v1/system/secrets/{id}/transition-status",
	"PUT /api/v1/system/users/{id}/active-transition",
	"PUT /api/v1/system/webauthn/credentials/{id}",
}

// liveSystemPrefixedRoutes are the /system-prefixed routes that were ALWAYS
// registered outside the deleted r.Route("/system", ...) block and must stay
// reachable -- the inverse check, so this file can't be satisfied by a router
// that accidentally 404s everything under /system.
var liveSystemPrefixedRoutes = []string{
	"GET /api/v1/system/info",
	"GET /api/v1/system/metrics",
	"GET /api/v1/system/auth-config",
	"GET /api/v1/system/encryption-config",
}

var pathParamRe = regexp.MustCompile(`\{[^}]+\}`)

func TestDeletedSystemProxyRoutesReturn404(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	cfg := &config.Config{}
	testCore := newTestCore(t)
	router, err := NewRouter(cfg, testCore)
	require.NoError(t, err)
	server := httptest.NewServer(router)
	defer server.Close()

	// An authenticated, admin-tier token: without one, an unmatched-route 404
	// is indistinguishable from a blanket Authentication-middleware 401 --
	// this guard needs to positively prove the ROUTE is gone, not just that
	// an unauthenticated caller is refused (which a live, still-registered
	// route would also do).
	token := createTestToken(t, testCore)

	client := &http.Client{Timeout: 10 * time.Second}
	do := func(method, path string) *http.Response {
		req, err := http.NewRequest(method, server.URL+path, nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(req)
		require.NoError(t, err)
		t.Cleanup(func() { _ = resp.Body.Close() })
		return resp
	}

	for _, route := range deletedSystemProxyRoutes {
		method, path := splitRouteLine(t, route)
		resolved := pathParamRe.ReplaceAllString(path, "1")
		t.Run(method+"_"+path, func(t *testing.T) {
			resp := do(method, resolved)
			assert.Equal(t, http.StatusNotFound, resp.StatusCode,
				"%s %s used to be a /system proxy route (deleted ADR-108 Phase 6); it must 404, not silently "+
					"come back", method, path)
		})
	}
}

// TestLiveSystemPrefixedRoutesStillReachable is the inverse check: the
// handful of genuinely live /system-prefixed routes (registered outside the
// deleted block) must stay reachable -- this guard's job is proving the dead
// surface stays dead, not proving the whole /system prefix is gone.
func TestLiveSystemPrefixedRoutesStillReachable(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	cfg := &config.Config{}
	testCore := newTestCore(t)
	router, err := NewRouter(cfg, testCore)
	require.NoError(t, err)
	server := httptest.NewServer(router)
	defer server.Close()

	client := &http.Client{Timeout: 10 * time.Second}
	for _, route := range liveSystemPrefixedRoutes {
		method, path := splitRouteLine(t, route)
		t.Run(method+"_"+path, func(t *testing.T) {
			req, err := http.NewRequest(method, server.URL+path, nil)
			require.NoError(t, err)
			resp, err := client.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()
			assert.NotEqual(t, http.StatusNotFound, resp.StatusCode,
				"%s %s is a live, non-proxy route -- it must still be registered", method, path)
		})
	}
}
