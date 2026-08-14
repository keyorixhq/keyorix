// node_credential.go — #G79 structural fix: the RemoteStorage-sync proxy tree
// (server/http/handlers/*_proxy.go, mounted under /api/v1/system) used to be gated only
// by RequirePermission(system.write) — a plain RBAC permission string, not a check that
// the caller is actually a trusted downstream Keyorix node. system.write is intentionally
// grantable to a narrow, documented custom role (audit checkpoints, legal holds, risk
// exceptions, SoD policies, admin job triggers — see internal/core/auth_bootstrap.go); an
// operator granting that role for its documented purpose was unknowingly also handing the
// grantee the ability to act as a node (mint admin accounts, forge setup tokens, bypass
// dual-control on risk exceptions, etc. — the underlying handlers now route through
// internal/core's own guards, but the router-level gate remained just the permission).
//
// RequireNodeCredential gates on a credential-CLASS check: the caller must be
// authenticated as a machine identity whose IdentityType is core.MachineTypeNode
// (internal/core/machine_identities.go). This is deliberately NOT an RBAC permission — no
// role, including admin/system_admin, grants node status; it can only come from being
// issued that specific credential type.
//
// RequireNodeCredentialOrPermission is the group's actual gate. A sole node-credential
// gate turned out to be too narrow: roughly half of the routes RemoteStorage backs (role/
// user/secret lookups, notifications, login/MFA proxying, legal holds, RBAC catalog, ...)
// sit OUTSIDE the /system proxy tree on their own ordinary RBAC-permission routes, and a
// downstream node's sync credential needs to reach those too — but a machine identity can
// never be granted a role at global scope (only project scope, see AssignMachineRole), so
// a bare node credential can satisfy /system but nothing else, while an admin-style PAT/
// session can satisfy everything else but not the node-only /system gate. No single
// credential could satisfy both. So /system stays reachable by EITHER a node credential OR
// the given permission (typically permSystemWrite) — matching the original plan's "add a
// node-identity credential check ... so a compromised or over-granted RBAC principal still
// can't act as a node" alongside a scoped permission, not a sole-credential replacement of
// it. This does NOT fully close the original concern on its own: adminRoleNames (authz.go)
// unconditionally bypass every permission check, so any admin-tier role holder still
// reaches this surface via the permission arm regardless of what's explicitly bundled into
// that role — narrowing which roles list system.write explicitly only stops accidental
// over-grants to NON-admin custom roles, not the admin bypass itself. Closing that fully
// would mean excluding this permission from the admin bypass, a separate, larger change.
package middleware

import (
	"net/http"

	"github.com/keyorixhq/keyorix/internal/core"
)

// RequireNodeCredential gates a route group on the caller holding a node-type machine
// credential. Rejects session/PAT/OIDC principals and every other machine identity type
// (ci/k8s/service/automation/other) with 403, and an unauthenticated request with 401.
func RequireNodeCredential() func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userCtx := GetUserFromContext(r.Context())
			if userCtx == nil {
				unauthorizedResponse(w, "User context not found")
				return
			}
			if !isNodeCredential(userCtx) {
				forbiddenResponse(w, "this endpoint requires a node credential")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// isNodeCredential reports whether userCtx is a node-type machine identity.
func isNodeCredential(userCtx *UserContext) bool {
	return userCtx.ActorKind() == core.ActorTypeMachine && userCtx.MachineIdentityType == core.MachineTypeNode
}

// RequireNodeCredentialOrPermission gates a route group on EITHER the caller holding a
// node-type machine credential OR the given permission at global scope — see the package
// doc above for why this stays dual-gated instead of node-credential-only.
func RequireNodeCredentialOrPermission(permission string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userCtx, cs, ok := requireUserAndCore(w, r)
			if !ok {
				return
			}
			if isNodeCredential(userCtx) {
				next.ServeHTTP(w, r)
				return
			}
			allowed, err := cs.AuthorizePrincipal(r.Context(), userCtx.ActorKind(), userCtx.PrincipalID(), permission, core.Scope{})
			finishScopedPermissionRequest(next, w, r, cs, core.Scope{}, allowed, err)
		})
	}
}
