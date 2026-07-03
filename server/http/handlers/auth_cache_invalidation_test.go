// auth_cache_invalidation_test.go — regression coverage for #248 (the PAT/
// suspend leg of the sessions/machine-token/PAT cache-invalidation family): a
// revoked PAT or a suspended account must stop authenticating on the very NEXT
// request, not linger in the middleware's 30s positive auth cache. Both fixes
// were already present in the tree (RevokeOwnPAT returns the token hash for the
// handler to evict; setAccountState evicts session + PAT hashes on any
// login-blocking transition) but lacked an end-to-end test that actually drives
// the real middleware.Authentication cache — this locks that behaviour in.
package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/server/middleware"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// newCacheTestCore builds a real KeyorixCore over an in-memory SQLite DB, wired
// with the same HTTP-auth-cache invalidator server/main.go wires at startup
// (SetTokenCacheInvalidator -> middleware.InvalidateTokenCacheByHash). Without
// this wiring, core-layer revocation (PAT revoke, suspend/reactivate) cannot
// evict the middleware's positive cache — mirroring production exactly is the
// point of these tests.
func newCacheTestCore(t *testing.T) *core.KeyorixCore {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.PersonalAccessToken{}, &models.Session{}, &models.AuditEvent{},
	))
	c := core.NewKeyorixCore(store.NewLocalStorage(db))
	c.SetTokenCacheInvalidator(middleware.InvalidateTokenCacheByHash)
	return c
}

// authProbe drives a bearer-token request through the REAL Authentication
// middleware (a genuine *core.KeyorixCore, not a fake validator), so the test
// exercises the exact cache-hit/miss/eviction logic production traffic uses.
func authProbe(c *core.KeyorixCore, token string) int {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	h := middleware.Authentication(c)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	h.ServeHTTP(rec, req)
	return rec.Code
}

// TestRevokePAT_EvictsFromAuthCacheImmediately drives the real RevokePAT HTTP
// handler (not a mock), so the exact production call — RevokeOwnPAT returning
// the token hash, then middleware.InvalidateTokenCacheByHash(tokenHash) — is
// what's under test. Before either half of that existed, a revoked PAT kept
// authenticating from the positive cache for up to validTokenTTL (30s).
func TestRevokePAT_EvictsFromAuthCacheImmediately(t *testing.T) {
	c := newCacheTestCore(t)
	ctx := context.Background()

	user, err := c.CreateUser(ctx, &core.CreateUserRequest{
		Username: "alice", Email: "alice@example.com", DisplayName: "Alice", Password: "Sup3r$ecretPassw0rd!",
	})
	require.NoError(t, err)

	result, err := c.CreateOwnPAT(ctx, user.ID, "ci", nil, nil, 0, 0, nil)
	require.NoError(t, err)

	// Populate the positive cache with a real request.
	require.Equal(t, http.StatusOK, authProbe(c, result.PlainToken), "PAT should authenticate before revocation")

	// Revoke via the real HTTP handler — the exact code path #248 concerned.
	h := NewPATHandler(c)
	idStr := strconv.FormatUint(uint64(result.Token.ID), 10)
	req := httptest.NewRequest(http.MethodDelete, "/auth/tokens/"+idStr, nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.GetUserContextKey(), &middleware.UserContext{UserID: user.ID}))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", idStr)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rec := httptest.NewRecorder()
	h.RevokePAT(rec, req)
	require.Equal(t, http.StatusNoContent, rec.Code)

	// Immediately (no sleep, no 30s wait): the cache must reject it, not serve
	// the stale positive entry.
	assert.Equal(t, http.StatusUnauthorized, authProbe(c, result.PlainToken),
		"revoked PAT must be rejected immediately, not served from the positive auth cache")
}

// TestSuspendUser_EvictsCachedSessionAndPATImmediately is the end-to-end
// regression for the setAccountState leg of #248: suspending a user must evict
// BOTH their session and their PAT from the shared positive auth cache, so a
// suspended user's already-cached credentials stop working on the very next
// request rather than lingering for the cache TTL.
func TestSuspendUser_EvictsCachedSessionAndPATImmediately(t *testing.T) {
	c := newCacheTestCore(t)
	ctx := context.Background()

	user, err := c.CreateUser(ctx, &core.CreateUserRequest{
		Username: "bob", Email: "bob@example.com", DisplayName: "Bob", Password: "Sup3r$ecretPassw0rd!",
	})
	require.NoError(t, err)

	session, _, err := c.Login(ctx, &core.LoginRequest{Username: "bob", Password: "Sup3r$ecretPassw0rd!"})
	require.NoError(t, err)

	pat, err := c.CreateOwnPAT(ctx, user.ID, "ci", nil, nil, 0, 0, nil)
	require.NoError(t, err)

	// Populate the positive cache for both credential kinds with real requests.
	require.Equal(t, http.StatusOK, authProbe(c, session.SessionToken), "session should authenticate before suspension")
	require.Equal(t, http.StatusOK, authProbe(c, pat.PlainToken), "PAT should authenticate before suspension")

	require.NoError(t, c.SuspendUser(ctx, 1 /* admin */, user.ID))

	// Immediately (no 30s wait): both must be rejected, not served from cache.
	assert.Equal(t, http.StatusUnauthorized, authProbe(c, session.SessionToken),
		"session token must be rejected immediately after suspension, not served from cache")
	assert.Equal(t, http.StatusUnauthorized, authProbe(c, pat.PlainToken),
		"PAT must be rejected immediately after suspension, not served from cache")
}
