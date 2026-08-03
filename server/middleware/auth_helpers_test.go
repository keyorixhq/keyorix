package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGetCoreServiceFromContext verifies the helper returns nil when the key is absent.
func TestGetCoreServiceFromContext(t *testing.T) {
	ctx := context.Background()
	assert.Nil(t, GetCoreServiceFromContext(ctx), "absent key must return nil")
}

// TestInvalidateTokenCache exercises the InvalidateTokenCache code path so the
// cache-key computation and tombstone write are covered.
// The tombstone written by InvalidateTokenCache replaces the positive entry with a
// negative one (userCtx nil, short TTL) — cacheGet still returns the entry as "found"
// (a negative-cache hit) but with a nil userCtx, so the caller knows the token is bad.
func TestInvalidateTokenCache(t *testing.T) {
	// Add a positive entry.
	key := tokenKey("tok-to-evict")
	cacheSet(key, tokenCacheEntry{
		userCtx:   &UserContext{UserID: 42},
		expiresAt: time.Now().Add(time.Minute),
	})
	entry, ok := cacheGet(key)
	require.True(t, ok)
	require.NotNil(t, entry.userCtx, "should be a positive entry before invalidation")

	// Evict it — writes a negative tombstone.
	InvalidateTokenCache("tok-to-evict")

	// The tombstone entry must carry a nil userCtx (negative cache hit), signalling
	// the token is invalid. The expiry is short (invalidTokenTTL), so cacheGet still
	// returns it as found (its TTL has not elapsed yet).
	entry, ok = cacheGet(key)
	if ok {
		// A tombstone-hit: entry is found but must have nil userCtx.
		assert.Nil(t, entry.userCtx, "tombstone entry must have nil userCtx (negative cache)")
	}
	// Either found-with-nil or not-found is acceptable: both signal "invalid".
}

// TestActorKindAndPrincipalID verifies UserContext helper methods for edge cases.
func TestActorKindAndPrincipalID(t *testing.T) {
	// A regular user.
	uc := &UserContext{UserID: 7}
	assert.Equal(t, "user", uc.ActorKind())
	assert.Equal(t, uint(7), uc.PrincipalID())

	// A machine identity.
	mid := uint(99)
	mc := &UserContext{MachineIdentityID: &mid, ActorType: "machine_identity"}
	assert.Equal(t, "machine_identity", mc.ActorKind())
	assert.Equal(t, uint(99), mc.PrincipalID())
}

// TestUnauthorizedAndForbiddenHelpers verifies the response helper functions return the
// right status codes and content-type.
func TestUnauthorizedAndForbiddenHelpers(t *testing.T) {
	t.Run("unauthorizedResponse", func(t *testing.T) {
		rr := httptest.NewRecorder()
		unauthorizedResponse(rr, "test message")
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
		assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))
		assert.Contains(t, rr.Body.String(), "Unauthorized")
	})

	t.Run("forbiddenResponse", func(t *testing.T) {
		rr := httptest.NewRecorder()
		forbiddenResponse(rr, "test message")
		assert.Equal(t, http.StatusForbidden, rr.Code)
		assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))
		assert.Contains(t, rr.Body.String(), "Forbidden")
	})

	t.Run("notFoundResponse", func(t *testing.T) {
		rr := httptest.NewRecorder()
		notFoundResponse(rr, "test message")
		assert.Equal(t, http.StatusNotFound, rr.Code)
		assert.Contains(t, rr.Body.String(), "NotFound")
	})

	t.Run("badRequestResponse", func(t *testing.T) {
		rr := httptest.NewRecorder()
		badRequestResponse(rr, "test message")
		assert.Equal(t, http.StatusBadRequest, rr.Code)
		assert.Contains(t, rr.Body.String(), "BadRequest")
	})
}

// TestWriteProjectMFARequired verifies the exported wrapper delegates to the same 403
// body as the internal projectMFARequiredResponse.
func TestWriteProjectMFARequired(t *testing.T) {
	rr := httptest.NewRecorder()
	WriteProjectMFARequired(rr)
	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), "ProjectMFARequired")
}

// TestScopeGlobal verifies that ScopeGlobal always returns an empty scope.
func TestScopeGlobal(t *testing.T) {
	scope, err := ScopeGlobal(httptest.NewRequest(http.MethodGet, "/", nil), nil)
	require.NoError(t, err)
	assert.Equal(t, uint(0), scope.ProjectID)
	assert.Equal(t, uint(0), scope.EnvironmentID)
}

// TestScopeFromQuery verifies optional project_id/environment_id query params.
func TestScopeFromQuery(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/?project_id=5&environment_id=12", nil)
	scope, err := ScopeFromQuery(req, nil)
	require.NoError(t, err)
	assert.Equal(t, uint(5), scope.ProjectID)
	assert.Equal(t, uint(12), scope.EnvironmentID)
}

// TestScopeFromQuery_Missing verifies that absent params default to 0.
func TestScopeFromQuery_Missing(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	scope, err := ScopeFromQuery(req, nil)
	require.NoError(t, err)
	assert.Equal(t, uint(0), scope.ProjectID)
	assert.Equal(t, uint(0), scope.EnvironmentID)
}

// TestDerefUint covers the nil-pointer branch.
func TestDerefUint(t *testing.T) {
	assert.Equal(t, uint(0), derefUint(nil))
	v := uint(42)
	assert.Equal(t, uint(42), derefUint(&v))
}
