// node_credential.go — #G79 structural fix, superseded by ADR-085 (Accepted,
// 2026-08-25): the RemoteStorage-sync proxy tree (server/http/handlers/*_proxy.go,
// mounted under /api/v1/system) used to be gated by RequirePermission(system.write)
// alone, then for a time by RequireNodeCredentialOrPermission — a node-type
// machine credential (core.MachineTypeNode) as an alternative to system.write.
// That OR-arm is REMOVED. ADR-085 found its own foundational premise false: the
// "downstream Keyorix node relaying an already-authorized human action" topology
// it was built to serve cannot exist in this codebase — ADR-083's
// validateRemoteStorageNotServer (internal/config/config.go) rejects
// storage.type: remote unconditionally for any server process (HTTP, gRPC, or
// scheduler-only), so no server-side relay of this shape has ever been
// constructible. A liveness sweep (createNodeToken: test-only in all 21
// references; no Helm chart, compose file, or CLI flow provisions a node
// credential for runtime; docs/REMOTE_CLI_SETUP.md documents a bare node token as
// insufficient for real use) found no live caller for the OR-arm at all. See
// ADR-085 for the full finding and the competitor research (Vault/Conjur/
// OpenBao/Infisical) informing the replacement decision: node-authenticated
// requests get no privileged access; /system requires system.write like every
// other RBAC-gated route in this codebase.
//
// The MachineTypeNode identity type itself is RETAINED (ADR-085's decision) —
// `keyorix machine create --type node` remains a valid, user-facing command, and
// removing the type forecloses a real node component being built properly later.
// What's removed is only the OR-arm that let holding that credential type
// substitute for holding system.write.
package middleware

import (
	"net/http"

	"github.com/keyorixhq/keyorix/internal/core"
)

// RequireNodeCredential gates a route group on the caller holding a node-type machine
// credential. Rejects session/PAT/OIDC principals and every other machine identity type
// (ci/k8s/service/automation/other) with 403, and an unauthenticated request with 401.
//
// Pre-existing, unrelated to the ADR-085 change above: this sole-credential gate
// has never been used to gate any real route (router.go never calls it; the
// group's gate was RequireNodeCredentialOrPermission, now plain RequirePermission)
// — a leftover from an earlier, already-reverted design iteration (see router.go's
// own "a pure node-credential-only gate was tried and reverted" history). Left in
// place, not deleted, since removing it is unrelated to this change and it is
// exercised by its own unit tests below.
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
// Kept for RequireNodeCredential above (its only remaining caller).
func isNodeCredential(userCtx *UserContext) bool {
	return userCtx.ActorKind() == core.ActorTypeMachine && userCtx.MachineIdentityType == core.MachineTypeNode
}
