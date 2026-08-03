// pat_expiry_handler_test.go — unit tests for PATExpiryHandler.
//
// Uses freshCoreS12 (pre-migrated in-memory SQLite) and withUserCtx from the
// existing handlers test helpers (rotation_policies_simple_test.go /
// handlers_s12_test.go) — none are redeclared here.
package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	customMiddleware "github.com/keyorixhq/keyorix/server/middleware"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// withUserCtxForExpiry injects a UserContext with the given userID into the request.
func withUserCtxForExpiry(r *http.Request, userID uint) *http.Request {
	uc := &customMiddleware.UserContext{
		UserID:   userID,
		Username: "testuser",
		Email:    "testuser@example.com",
	}
	return r.WithContext(context.WithValue(r.Context(), customMiddleware.GetUserContextKey(), uc))
}

// seedExpiredPAT inserts a non-revoked, expired PAT for userID directly into the
// core's underlying DB by calling CreateOwnPAT with a past ExpiresAt.
// Returns the inserted PAT result.
func seedExpiredPAT(t *testing.T, h *PATExpiryHandler, userID uint) {
	t.Helper()
	past := time.Now().Add(-24 * time.Hour)
	_, err := h.coreService.CreateOwnPAT(context.Background(), userID, "expired-token", &past, nil, 0, 0, nil)
	require.NoError(t, err)
}

// seedActivePAT inserts a non-revoked, non-expired PAT for userID.
func seedActivePAT(t *testing.T, h *PATExpiryHandler, userID uint) {
	t.Helper()
	future := time.Now().Add(24 * time.Hour)
	_, err := h.coreService.CreateOwnPAT(context.Background(), userID, "active-token", &future, nil, 0, 0, nil)
	require.NoError(t, err)
}

// ── ListExpiredPATs ───────────────────────────────────────────────────────────

func TestPATExpiry_ListExpiredPATs_Unauthenticated_Returns401(t *testing.T) {
	h := NewPATExpiryHandler(freshCoreS12(t))
	req := httptest.NewRequest(http.MethodGet, "/auth/tokens/expired", nil)
	w := httptest.NewRecorder()
	h.ListExpiredPATs(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestPATExpiry_ListExpiredPATs_NoExpiredPATs_ReturnsEmpty(t *testing.T) {
	h := NewPATExpiryHandler(freshCoreS12(t))
	req := withUserCtxForExpiry(httptest.NewRequest(http.MethodGet, "/auth/tokens/expired", nil), 1)
	w := httptest.NewRecorder()
	h.ListExpiredPATs(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	// Response should be a JSON array (empty).
	assert.Contains(t, w.Body.String(), "[]")
}

func TestPATExpiry_ListExpiredPATs_WithExpiredPAT_ReturnsList(t *testing.T) {
	c := freshCoreS12(t)
	h := NewPATExpiryHandler(c)

	// Seed an expired PAT for user 1.
	seedExpiredPAT(t, h, 1)
	// Also seed an active PAT — must not appear in the result.
	seedActivePAT(t, h, 1)

	req := withUserCtxForExpiry(httptest.NewRequest(http.MethodGet, "/auth/tokens/expired", nil), 1)
	w := httptest.NewRecorder()
	h.ListExpiredPATs(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.Contains(t, body, "expired-token")
	assert.NotContains(t, body, "active-token")
}

func TestPATExpiry_ListExpiredPATs_OnlyOwnTokens(t *testing.T) {
	h := NewPATExpiryHandler(freshCoreS12(t))

	// User 2's expired PAT — must not appear when user 1 queries.
	seedExpiredPAT(t, h, 2)

	req := withUserCtxForExpiry(httptest.NewRequest(http.MethodGet, "/auth/tokens/expired", nil), 1)
	w := httptest.NewRecorder()
	h.ListExpiredPATs(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "[]")
}

// ── BulkRevokeExpiredPATs ─────────────────────────────────────────────────────

func TestPATExpiry_BulkRevokeExpiredPATs_Unauthenticated_Returns401(t *testing.T) {
	h := NewPATExpiryHandler(freshCoreS12(t))
	req := httptest.NewRequest(http.MethodDelete, "/auth/tokens/expired", nil)
	w := httptest.NewRecorder()
	h.BulkRevokeExpiredPATs(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestPATExpiry_BulkRevokeExpiredPATs_NoneExpired_Returns204(t *testing.T) {
	h := NewPATExpiryHandler(freshCoreS12(t))
	req := withUserCtxForExpiry(httptest.NewRequest(http.MethodDelete, "/auth/tokens/expired", nil), 1)
	w := httptest.NewRecorder()
	h.BulkRevokeExpiredPATs(w, req)
	assert.Equal(t, http.StatusNoContent, w.Code)
}

func TestPATExpiry_BulkRevokeExpiredPATs_RevokesExpiredTokens(t *testing.T) {
	h := NewPATExpiryHandler(freshCoreS12(t))
	ctx := context.Background()

	// Seed two expired PATs for user 1, then bulk-revoke.
	seedExpiredPAT(t, h, 1)
	seedExpiredPAT(t, h, 1)

	req := withUserCtxForExpiry(httptest.NewRequest(http.MethodDelete, "/auth/tokens/expired", nil), 1)
	w := httptest.NewRecorder()
	h.BulkRevokeExpiredPATs(w, req)
	assert.Equal(t, http.StatusNoContent, w.Code)

	// After bulk-revoke, listing expired PATs should return empty.
	tokens, err := h.coreService.ListExpiredOwnPATs(ctx, 1)
	require.NoError(t, err)
	assert.Empty(t, tokens)
}

// ── Error paths via cancelled context ────────────────────────────────────────

func cancelledCtxReqForPAT(method, target string) *http.Request {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return httptest.NewRequest(method, target, nil).WithContext(ctx)
}

func TestPATExpiry_ListExpiredPATs_StorageError_Returns500(t *testing.T) {
	h := NewPATExpiryHandler(freshCoreS12(t))
	// A cancelled context makes the storage query fail.
	req := withUserCtxForExpiry(cancelledCtxReqForPAT(http.MethodGet, "/auth/tokens/expired"), 1)
	w := httptest.NewRecorder()
	h.ListExpiredPATs(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestPATExpiry_BulkRevokeExpiredPATs_StorageError_Returns500(t *testing.T) {
	h := NewPATExpiryHandler(freshCoreS12(t))
	// A cancelled context makes the storage query fail.
	req := withUserCtxForExpiry(cancelledCtxReqForPAT(http.MethodDelete, "/auth/tokens/expired"), 1)
	w := httptest.NewRecorder()
	h.BulkRevokeExpiredPATs(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ── PATResponse DTO ─────────────────────────────────────────────────────────

func TestToPATResponse_ExpiredPAT_PopulatesExpiresAt(t *testing.T) {
	past := time.Now().Add(-time.Hour).UTC()
	pat := &models.PersonalAccessToken{
		ID:          1,
		Name:        "old",
		TokenPrefix: "kx_pat_ab",
		ExpiresAt:   &past,
	}
	resp := toPATResponse(pat)
	require.NotNil(t, resp.ExpiresAt)
	assert.Contains(t, *resp.ExpiresAt, "Z") // RFC3339 UTC
}
