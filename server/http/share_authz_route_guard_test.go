// share_authz_route_guard_test.go — #2941 guard, HTTP half: every per-secret REST
// operation must be authorized by the share-aware per-secret check
// (core.AuthorizeSecretPrincipalForSecret → AuthorizeSecret, which includes the share
// term). The behavioural proof is share_elevation_2941_test.go; this is the
// family-wide structural guard that stops a new or re-gated route from silently
// falling back to role-only RequireScopedPermission(…, ScopeFromSecretParam), where a
// share-elevated member is denied on that one route (DEMO-WALK-1's "a write share
// didn't let a viewer update" was every route at once).
//
// How the operation list is derived (not hand-listed): buildRouteInventory walks
// router.go's NewRouter AST (the same walker TestRouteInventoryIsCurrent and the
// permission sweep use) and every route whose mounted path starts with
// /api/v1/secrets/{id} is a per-secret operation. Each must name
// RequireScopedSecretPermission in its gate chain, or be listed in
// secretRouteShareGuardExempt with a written reason.
//
// What it does NOT cover: per-secret operations mounted elsewhere (project-scoped bulk
// routes under /projects/{id}/secrets/*, which act on many secrets and are gated by
// project role by design; /shares/{id}, which is share MANAGEMENT and owner-only in
// core). The middleware half — that RequireScopedSecretPermission and
// RequireScopedSecretRefPermission actually call the share-aware core check — is
// TestSecretGates_CallShareAwareCheck below.
package http

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// secretRouteShareGuardExempt: per-secret routes that legitimately do not use
// RequireScopedSecretPermission. Keyed by "<METHOD> <pattern>".
var secretRouteShareGuardExempt = map[string]string{
	"POST /api/v1/secrets/{id}/restore": "a soft-deleted secret is invisible to GetSecret, so scope resolves via " +
		"ScopeFromDeletedSecretParam; restore needs project secrets.write by role. A share on a deleted secret " +
		"deliberately does not authorize restoring it.",
	"DELETE /api/v1/secrets/{id}/self-share": "a recipient removing their OWN share: authenticated only, the core " +
		"removes only a share whose RecipientID is the caller. Gating it on a permission the share itself grants " +
		"would be circular.",
}

func TestEveryPerSecretRoute_UsesShareAwareGate(t *testing.T) {
	root := permissionSweepRepoRoot(t)
	entries := buildRouteInventory(t, filepath.Join(root, "server", "http", "router.go"))

	const prefix = "/api/v1/secrets/{id}"
	seen := map[string]bool{}
	checked := 0
	for _, e := range entries {
		if e.Pattern != prefix && !strings.HasPrefix(e.Pattern, prefix+"/") {
			continue
		}
		key := e.key()
		seen[key] = true
		if _, exempt := secretRouteShareGuardExempt[key]; exempt {
			continue
		}
		checked++
		assert.Contains(t, e.GateFns, "RequireScopedSecretPermission",
			"%s (router.go:%d) is a per-secret operation but is not gated by RequireScopedSecretPermission "+
				"(gates: %v): it would ignore shares (#2941) and per-secret ACLs. Use "+
				"RequireScopedSecretPermission(perm, \"id\"), or add a justified secretRouteShareGuardExempt entry.",
			key, e.Line, e.GateFns)
	}
	// Calibration: the walk must actually find the family (≈45 routes today), so a
	// path-resolution regression cannot turn this into a vacuous pass.
	assert.Greater(t, checked, 30, "expected the per-secret route family; the inventory walk found %d", checked)
	for key := range secretRouteShareGuardExempt {
		assert.True(t, seen[key], "stale exemption %q: no such route in router.go", key)
	}

	var byRef *routeInventoryEntry
	for i := range entries {
		if entries[i].key() == "GET /api/v1/secrets/value" {
			byRef = &entries[i]
		}
	}
	require.NotNil(t, byRef, "GET /api/v1/secrets/value must exist")
	assert.Contains(t, byRef.GateFns, "RequireScopedSecretRefPermission",
		"reading a secret by reference must use the per-secret gate too")
}

// TestSecretGates_CallShareAwareCheck: the two per-secret middleware gates must make
// their decision with core's share-aware per-secret check, never the role-only
// AuthorizePrincipal.
func TestSecretGates_CallShareAwareCheck(t *testing.T) {
	root := permissionSweepRepoRoot(t)
	path := filepath.Join(root, "server", "middleware", "auth.go")
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	require.NoError(t, err)

	for _, fn := range []string{"handleScopedSecretPermissionRequest", "handleScopedSecretRefPermissionRequest"} {
		calls := calledSelectors(f, fn)
		require.NotNil(t, calls, "server/middleware/auth.go must declare %s", fn)
		assert.True(t, calls["AuthorizeSecretPrincipalForSecret"],
			"%s must authorize with core.AuthorizeSecretPrincipalForSecret (role + ACL + share term)", fn)
		assert.False(t, calls["AuthorizePrincipal"],
			"%s must not make a role-only AuthorizePrincipal decision: it ignores shares (#2941)", fn)
	}
}

// calledSelectors returns the set of selector names (x.Name(...)) called inside the
// body of the top-level function named fn, or nil if fn is not declared in f.
func calledSelectors(f *ast.File, fn string) map[string]bool {
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Recv != nil || fd.Name.Name != fn || fd.Body == nil {
			continue
		}
		out := map[string]bool{}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
					out[sel.Sel.Name] = true
				}
			}
			return true
		})
		return out
	}
	return nil
}
