// users_active_transition_proxy_credential_revoke_test.go — G80 Wave 2
// (#1572, ADR-088). UpdateUserIfActiveStateMatchesProxy could deactivate a
// user (flip is_active to false) without ever revoking their live personal
// access tokens or sessions — a caller reaching this raw /system proxy
// directly (bypassing core.UpdateUser, which performs both as part of the
// same deactivating transaction) got a deactivated account with fully live
// credentials. Fixed by calling core.RevokeAllPersonalAccessTokensForUser/
// core.DeleteSessionsForUserExcept in-process immediately after a matched
// true->false transition, best-effort and non-fatal like core.UpdateUser's
// own deactivating branch.
package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/server/middleware"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestUpdateUserIfActiveStateMatchesProxy_DeactivationRevokesCredentials_RealServer
// is the #1572 exploit shape: a target user holds a live PAT and a live
// session. A caller with real users.write authority deactivates them through
// the raw proxy alone (never touching core.UpdateUser or the two dedicated
// credential-revocation proxies). Both credentials must come back revoked —
// before the fix, neither would have.
func TestUpdateUserIfActiveStateMatchesProxy_DeactivationRevokesCredentials_RealServer(t *testing.T) {
	cs, _ := freshCoreS12WithAdmin(t)
	h, err := NewUserHandler(cs)
	require.NoError(t, err)
	ctx := context.Background()

	admin, err := cs.GetUserByUsername(ctx, "testuser_s12")
	require.NoError(t, err)

	target, err := cs.CreateUser(ctx, &core.CreateUserRequest{
		Username: "g80-1572-target", Email: "g80-1572-target@example.com",
		DisplayName: "G80 1572 Target", Password: "NotArealpassword123!",
	})
	require.NoError(t, err)

	pat, err := cs.Storage().CreatePersonalAccessToken(ctx, &models.PersonalAccessToken{
		UserID: target.ID, Name: "ci", TokenHash: "hash-1572-pat", TokenPrefix: "kx_pat_1572",
	})
	require.NoError(t, err)

	session, err := cs.Storage().CreateSession(ctx, &models.Session{
		UserID: target.ID, SessionToken: "hash-1572-session", CreatedAt: time.Now(),
	})
	require.NoError(t, err)

	// Sanity: both are live before deactivation.
	pats, err := cs.Storage().ListPersonalAccessTokensByUser(ctx, target.ID)
	require.NoError(t, err)
	require.Len(t, pats, 1)
	require.False(t, pats[0].Revoked)

	hashes, err := cs.Storage().ListSessionTokenHashesForUser(ctx, target.ID)
	require.NoError(t, err)
	require.Len(t, hashes, 1, "target must have exactly one live session before deactivation")

	body, err := json.Marshal(map[string]interface{}{
		"username":    target.Username,
		"email":       target.Email,
		"active":      false,
		"updated_at":  time.Now(),
		"from_active": true,
	})
	require.NoError(t, err)
	req := httptest.NewRequest("PUT", "/", bytes.NewReader(body))
	uc := &middleware.UserContext{UserID: admin.ID, Username: admin.Username, Email: admin.Email}
	req = req.WithContext(context.WithValue(req.Context(), middleware.GetUserContextKey(), uc))
	req = withChiParams(req, map[string]string{"id": machineUintToStr(target.ID)})
	w := httptest.NewRecorder()
	h.UpdateUserIfActiveStateMatchesProxy(w, req)
	require.Equal(t, 200, w.Code, "deactivation itself must still succeed: %s", w.Body.String())

	reloaded, err := cs.Storage().GetUser(ctx, target.ID)
	require.NoError(t, err)
	assert.False(t, reloaded.IsActive)

	patAfter, err := cs.Storage().GetPersonalAccessTokenByHash(ctx, "hash-1572-pat")
	require.NoError(t, err)
	assert.True(t, patAfter.Revoked, "the target's PAT must be revoked as a side effect of deactivation via this route")
	assert.Equal(t, pat.ID, patAfter.ID)

	hashesAfter, err := cs.Storage().ListSessionTokenHashesForUser(ctx, target.ID)
	require.NoError(t, err)
	assert.Empty(t, hashesAfter, "the target's session must be deleted as a side effect of deactivation via this route")
	_ = session
}

// TestUpdateUserIfActiveStateMatchesProxy_DeactivationRevokesCredentialsEvenWithoutUsersWrite_RealServer
// is #1572 corrected 2026-09-03: the original fix called
// core.RevokeAllPersonalAccessTokensForUser/core.DeleteSessionsForUserExcept,
// which gate on requireUserCredentialsRevokeAuthority (users.write) — the
// RIGHT ceiling for a caller invoking revocation as its OWN standalone
// action, but the WRONG one here, since this /system route's own gate is the
// broader system.write every /system proxy accepts, not users.write
// specifically. A caller reaching this route holding system.write but NOT
// users.write hit that ceiling on every deactivation, had the revocation
// failure logged and swallowed as "best-effort," and left the deactivated
// user's PAT/session live and warm-cache-usable. This drives the exact
// scenario with a caller who does not hold users.write and confirms both
// credentials come back revoked anyway — proving core.RevokeUserCredentialsForDeactivation
// no longer re-authorizes the caller for what is a mandatory consequence of
// an already-committed deactivation, not an independent decision.
func TestUpdateUserIfActiveStateMatchesProxy_DeactivationRevokesCredentialsEvenWithoutUsersWrite_RealServer(t *testing.T) {
	cs, _ := freshCoreS12WithAdmin(t)
	h, err := NewUserHandler(cs)
	require.NoError(t, err)
	ctx := context.Background()

	// A caller with system.write but explicitly NO users.write anywhere —
	// requireUserCredentialsRevokeAuthority would refuse this actor outright.
	caller, err := cs.CreateUser(ctx, &core.CreateUserRequest{
		Username: "g80-1572-caller", Email: "g80-1572-caller@example.com",
		DisplayName: "G80 1572 Caller", Password: "NotArealpassword123!",
	})
	require.NoError(t, err)

	target, err := cs.CreateUser(ctx, &core.CreateUserRequest{
		Username: "g80-1572-target2", Email: "g80-1572-target2@example.com",
		DisplayName: "G80 1572 Target 2", Password: "NotArealpassword123!",
	})
	require.NoError(t, err)

	pat, err := cs.Storage().CreatePersonalAccessToken(ctx, &models.PersonalAccessToken{
		UserID: target.ID, Name: "ci", TokenHash: "hash-1572b-pat", TokenPrefix: "kx_pat_1572b",
	})
	require.NoError(t, err)
	_, err = cs.Storage().CreateSession(ctx, &models.Session{
		UserID: target.ID, SessionToken: "hash-1572b-session", CreatedAt: time.Now(),
	})
	require.NoError(t, err)
	hashes, err := cs.Storage().ListSessionTokenHashesForUser(ctx, target.ID)
	require.NoError(t, err)
	require.Len(t, hashes, 1, "target must have exactly one live session before deactivation")

	body, err := json.Marshal(map[string]interface{}{
		"username": target.Username, "email": target.Email,
		"active": false, "updated_at": time.Now(), "from_active": true,
	})
	require.NoError(t, err)
	req := httptest.NewRequest("PUT", "/", bytes.NewReader(body))
	// caller holds no roles at all -- not even users.write, let alone
	// roles.assign -- deliberately, to prove revocation no longer depends on
	// the caller's own permission set.
	uc := &middleware.UserContext{UserID: caller.ID, Username: caller.Username, Email: caller.Email}
	req = req.WithContext(context.WithValue(req.Context(), middleware.GetUserContextKey(), uc))
	req = withChiParams(req, map[string]string{"id": machineUintToStr(target.ID)})
	w := httptest.NewRecorder()
	h.UpdateUserIfActiveStateMatchesProxy(w, req)
	require.Equal(t, 200, w.Code, "deactivation itself must still succeed: %s", w.Body.String())

	reloaded, err := cs.Storage().GetUser(ctx, target.ID)
	require.NoError(t, err)
	assert.False(t, reloaded.IsActive)

	patAfter, err := cs.Storage().GetPersonalAccessTokenByHash(ctx, "hash-1572b-pat")
	require.NoError(t, err)
	assert.True(t, patAfter.Revoked, "the target's PAT must be revoked even though the caller holds no users.write grant")
	assert.Equal(t, pat.ID, patAfter.ID)

	hashesAfter, err := cs.Storage().ListSessionTokenHashesForUser(ctx, target.ID)
	require.NoError(t, err)
	assert.Empty(t, hashesAfter, "the target's session must be deleted even though the caller holds no users.write grant")
}

// TestUpdateUserIfActiveStateMatchesProxy_ReactivationDoesNotRevoke_RealServer
// is the control: flipping IsActive from false->true (or any non-deactivating
// call) must never trigger a revocation attempt -- only a real true->false
// transition should.
func TestUpdateUserIfActiveStateMatchesProxy_ReactivationDoesNotRevoke_RealServer(t *testing.T) {
	cs, _ := freshCoreS12WithAdmin(t)
	h, err := NewUserHandler(cs)
	require.NoError(t, err)
	ctx := context.Background()

	admin, err := cs.GetUserByUsername(ctx, "testuser_s12")
	require.NoError(t, err)

	target, err := cs.CreateUser(ctx, &core.CreateUserRequest{
		Username: "g80-1572-reactivate", Email: "g80-1572-reactivate@example.com",
		DisplayName: "G80 1572 Reactivate", Password: "NotArealpassword123!",
	})
	require.NoError(t, err)
	target.IsActive = false
	target.UpdatedAt = time.Now()
	_, err = cs.Storage().UpdateUser(ctx, target)
	require.NoError(t, err)

	pat, err := cs.Storage().CreatePersonalAccessToken(ctx, &models.PersonalAccessToken{
		UserID: target.ID, Name: "ci", TokenHash: "hash-1572-reactivate-pat", TokenPrefix: "kx_pat_reac",
	})
	require.NoError(t, err)

	body, err := json.Marshal(map[string]interface{}{
		"username":    target.Username,
		"email":       target.Email,
		"active":      true,
		"updated_at":  time.Now(),
		"from_active": false,
	})
	require.NoError(t, err)
	req := httptest.NewRequest("PUT", "/", bytes.NewReader(body))
	uc := &middleware.UserContext{UserID: admin.ID, Username: admin.Username, Email: admin.Email}
	req = req.WithContext(context.WithValue(req.Context(), middleware.GetUserContextKey(), uc))
	req = withChiParams(req, map[string]string{"id": machineUintToStr(target.ID)})
	w := httptest.NewRecorder()
	h.UpdateUserIfActiveStateMatchesProxy(w, req)
	require.Equal(t, 200, w.Code, "reactivation must still succeed: %s", w.Body.String())

	patAfter, err := cs.Storage().GetPersonalAccessTokenByHash(ctx, "hash-1572-reactivate-pat")
	require.NoError(t, err)
	assert.False(t, patAfter.Revoked, "reactivating a user must not revoke their PAT")
	assert.Equal(t, pat.ID, patAfter.ID)
}
