// role_removal_cross_transport_test.go — GRPC track backlog step 2's "state
// change on one transport, check on the other" shape, applied to role removal
// (the machine-identity leg of this shape is covered by
// machine_identity_transition_cache_invalidation_test.go and
// machine_identity_revoke_token_cache_invalidation_test.go).
//
// A user's global role is removed via the real gRPC RoleService.RemoveRole
// RPC; a real HTTP request through the real middleware (Authentication +
// RequireScopedPermission) with that user's SAME session token must reflect
// the removal on the very next request, not the up-to-30s positive
// auth-cache window. internal/core.removeUserRoleUnguarded already calls
// evictUserSessionCache (transport-agnostic, like TransitionMachineIdentity's
// #r124), so no server/grpc code change is expected here — this closes the
// "not given a dedicated cross-transport gRPC-entry-point test" gap noted in
// the 2026-09-26 report entry for the RevokeMachineToken investigation.
package services

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/testhelper"
	customMiddleware "github.com/keyorixhq/keyorix/server/middleware"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
)

// sessionPermissionProbe drives a session-token bearer request through the
// REAL middleware.Authentication + middleware.RequireScopedPermission chain
// (global scope), exactly the gate a REST list/read/write route uses.
func sessionPermissionProbe(c *core.KeyorixCore, token, permission string) int {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	h := customMiddleware.Authentication(c)(
		customMiddleware.RequireScopedPermission(permission, customMiddleware.ScopeGlobal)(
			http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			}),
		),
	)
	h.ServeHTTP(rec, req)
	return rec.Code
}

// TestGRPCRemoveRole_ReflectsInHTTPPermissionCheckImmediately drives the REAL
// gRPC RoleService.RemoveRole RPC to remove a user's global "viewer" role
// (grants secrets.read), then asserts the SAME session token is denied
// access over HTTP on the very next request rather than being served from
// the middleware's up-to-30s positive auth-cache entry. Unlike the
// machine-token case (serveAuthCacheHit re-validates a machine/PAT token's
// OWN restriction fresh on every hit — see
// machine_identity_revoke_token_cache_invalidation_test.go), a session
// token's cache-hit path does NOT re-check the user's roles/permissions —
// only account state and session liveness — so this genuinely depends on
// removeUserRoleUnguarded's active evictUserSessionCache call.
//
// #2423: evictUserSessionCache now uses ClearTokenCacheIfCached (delete-
// only-if-cached), not InvalidateTokenCacheByHash's negative tombstone —
// the credential itself is still perfectly valid after a role removal, only
// its PRIVILEGES changed, so writing a new negative tombstone would be wrong
// (the exact bug FuzzAuthCacheDifferential/G5/#2402 found: a token that was
// never cached yet got spuriously tombstoned). So the observed result here
// is 403, a fresh per-request permission recheck that correctly sees the
// role already gone — NOT 401 from a negative-cache hit. The outcome that
// matters is still proven: access with this token is denied immediately
// (the stale POSITIVE cache entry populated by the probe above is cleared,
// not served for up to invalidTokenTTL), just via a fresh deny rather than a
// blanket token-level tombstone.
func TestGRPCRemoveRole_ReflectsInHTTPPermissionCheckImmediately(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	t.Cleanup(h.Cleanup)
	h.CoreService.SetTokenCacheInvalidator(customMiddleware.InvalidateTokenCacheByHash)

	// Admin actor (role 1 = super_admin, bypasses_permission_checks) drives the
	// real gRPC RemoveRole RPC.
	h.AssignUserRole(t, 1, 1, nil)
	adminCtx := authCtx(1, "admin")

	// Target user holds role 4 ("viewer": secrets.read, users.read) at global
	// scope — an ordinary, non-admin role removal, not the last-admin-guard path.
	const targetUserID = 2
	require.NoError(t, h.DB.Create(&models.User{
		ID: targetUserID, Username: "viewer2", UsernameFolded: "viewer2",
		Email: "viewer2@test.com", EmailFolded: "viewer2@test.com",
		IsActive: true, AccountState: core.AccountActive,
	}).Error)
	h.AssignUserRole(t, targetUserID, 4, nil)

	expiry := time.Now().Add(time.Hour)
	sess, err := h.Storage.CreateSession(context.Background(), &models.Session{
		UserID: targetUserID, SessionToken: "role-removal-probe-token", ExpiresAt: &expiry,
	})
	require.NoError(t, err)
	token := sess.SessionToken // plaintext, restored by CreateSession for the caller

	// Populate the positive cache and confirm the grant is honored before removal.
	require.Equal(t, http.StatusOK, sessionPermissionProbe(h.CoreService, token, "secrets.read"),
		"viewer role should grant secrets.read before removal")

	// Remove the role via the REAL gRPC entry point.
	svc := NewRoleService(h.CoreService)
	_, err = svc.RemoveRole(adminCtx, &pb.RemoveRoleRequest{UserId: targetUserID, RoleId: 4})
	require.NoError(t, err)

	// Immediately (no sleep, no 30s wait): HTTP must deny it, not serve the
	// stale positive cache entry that still carries the (now-revoked) grant.
	// 403, not 401: eviction clears the stale positive entry (see doc comment
	// above) so this is a fresh per-request permission recheck, not a
	// negative-cache hit.
	assert.Equal(t, http.StatusForbidden, sessionPermissionProbe(h.CoreService, token, "secrets.read"),
		"a role removed via gRPC RemoveRole must be reflected by HTTP immediately, not served from the positive auth cache")
}
