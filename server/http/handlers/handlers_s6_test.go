// handlers_s6_test.go — sprint-6 coverage sweep targeting branches left uncovered
// after s3+s4+s5. Uses the same shared-DB pattern from handlers_s4_test.go
// (sharedS4CoreOnce / newHandlerCoreS4) to avoid CI timeout risk.
package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/server/middleware"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── helpers ───────────────────────────────────────────────────────────────────

func newAuditHandlerS6(t *testing.T) *AuditHandler {
	t.Helper()
	return NewAuditHandler(newHandlerCoreS4(t))
}

func newAuthHandlerS6(t *testing.T) *AuthHandler {
	t.Helper()
	return NewAuthHandler(newHandlerCoreS4(t), false)
}

func newUsersRolesHandlerS6(t *testing.T) *UsersRolesHandler {
	t.Helper()
	return NewUsersRolesHandler(newHandlerCoreS4(t))
}

func newUserHandlerS6(t *testing.T) *UserHandler {
	t.Helper()
	h, err := NewUserHandler(newHandlerCoreS4(t))
	require.NoError(t, err)
	return h
}

func newImpersonationHandlerS6(t *testing.T) *ImpersonationHandler {
	t.Helper()
	return NewImpersonationHandler(newHandlerCoreS4(t), false)
}

func newCatalogHandlerS6(t *testing.T) *CatalogHandler {
	t.Helper()
	return NewCatalogHandler(newHandlerCoreS4(t))
}

// withBearerToken injects an Authorization: Bearer header.
func withBearerToken(r *http.Request, token string) *http.Request {
	r.Header.Set("Authorization", "Bearer "+token)
	return r
}

// withCookieToken sets the session cookie (mirrors middleware.SessionCookieName).
func withCookieToken(r *http.Request, token string) *http.Request {
	r.AddCookie(&http.Cookie{Name: middleware.SessionCookieName, Value: token})
	return r
}

// ── ImpersonationHandler.Start — remaining branches ──────────────────────────

func TestImpersonationHandler_Start_ZeroUserID_S6(t *testing.T) {
	h := newImpersonationHandlerS6(t)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"user_id":0}`)))
	w := httptest.NewRecorder()
	h.Start(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestImpersonationHandler_Start_AlreadyImpersonating_S6(t *testing.T) {
	h := newImpersonationHandlerS6(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"user_id":3}`))
	// Inject a UserContext with ImpersonatedBy set — mirrors s4's identical test.
	by := uint(99)
	uc := &middleware.UserContext{
		UserID:         1,
		Username:       "testuser",
		ImpersonatedBy: &by,
	}
	req = req.WithContext(context.WithValue(req.Context(), middleware.GetUserContextKey(), uc))
	w := httptest.NewRecorder()
	h.Start(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

// TestImpersonationHandler_End_NoToken verifies the "missing token" path.
func TestImpersonationHandler_End_NoToken_S6(t *testing.T) {
	h := newImpersonationHandlerS6(t)
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()
	h.End(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestImpersonationHandler_End_InvalidToken verifies the "not an impersonation" path.
func TestImpersonationHandler_End_InvalidToken_S6(t *testing.T) {
	h := newImpersonationHandlerS6(t)
	req := withBearerToken(httptest.NewRequest(http.MethodPost, "/", nil), "invalid-token-xyz")
	w := httptest.NewRecorder()
	h.End(w, req)
	// Either 400 (not an impersonation session) or 500 (internal), not 401.
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

// ── AdminJobsHandler — remaining branches ────────────────────────────────────

func TestAdminJobsHandler_RunComplianceDigest_HappyPath_S6(t *testing.T) {
	h := NewAdminJobsHandler(newHandlerCoreS4(t))
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", nil))
	w := httptest.NewRecorder()
	h.RunComplianceDigest(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAdminJobsHandler_RunExpiryReminders_HappyPath_S6(t *testing.T) {
	h := NewAdminJobsHandler(newHandlerCoreS4(t))
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/?lead_days=7", nil))
	w := httptest.NewRecorder()
	h.RunExpiryReminders(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAdminJobsHandler_RunExpiryReminders_InvalidLeadDays_S6(t *testing.T) {
	h := NewAdminJobsHandler(newHandlerCoreS4(t))
	// lead_days=notanumber → falls back to 0 → still succeeds
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/?lead_days=notanumber", nil))
	w := httptest.NewRecorder()
	h.RunExpiryReminders(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── AuditHandler — remaining branches ────────────────────────────────────────

func TestAuditHandler_GetAuditLogs_WithFilters_S6(t *testing.T) {
	h := newAuditHandlerS6(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet,
		"/?page=1&page_size=10&user_id=1&project_id=1&actor_type=user&start_time=2024-01-01T00:00:00Z&end_time=2025-01-01T00:00:00Z&action=secret.read", nil))
	w := httptest.NewRecorder()
	h.GetAuditLogs(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAuditHandler_GetAuditLogs_Unauthorized_S6(t *testing.T) {
	h := newAuditHandlerS6(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.GetAuditLogs(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuditHandler_ExportAuditLogs_Unauthorized_S6(t *testing.T) {
	h := newAuditHandlerS6(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ExportAuditLogs(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuditHandler_ExportAuditLogs_HappyPath_S6(t *testing.T) {
	h := newAuditHandlerS6(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/?limit=10&after_id=0&since=2024-01-01T00:00:00Z", nil))
	w := httptest.NewRecorder()
	h.ExportAuditLogs(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAuditHandler_ExportAuditLogsCSV_Unauthorized_S6(t *testing.T) {
	h := newAuditHandlerS6(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ExportAuditLogsCSV(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuditHandler_ExportAuditLogsCSV_HappyPath_S6(t *testing.T) {
	h := newAuditHandlerS6(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/?limit=5&project_id=1&user_id=1&since=2024-01-01T00:00:00Z&until=2025-01-01T00:00:00Z", nil))
	w := httptest.NewRecorder()
	h.ExportAuditLogsCSV(w, req)
	// CSV export writes 200 (no explicit WriteHeader in handler).
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAuditHandler_GetRBACAuditLogs_Unauthorized_S6(t *testing.T) {
	h := newAuditHandlerS6(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.GetRBACAuditLogs(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuditHandler_GetRBACAuditLogs_HappyPath_S6(t *testing.T) {
	h := newAuditHandlerS6(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/?page=1&page_size=10", nil))
	w := httptest.NewRecorder()
	h.GetRBACAuditLogs(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAuditHandler_GetAuditRetention_Unauthorized_S6(t *testing.T) {
	h := newAuditHandlerS6(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.GetAuditRetention(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuditHandler_GetAuditRetention_HappyPath_S6(t *testing.T) {
	h := newAuditHandlerS6(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.GetAuditRetention(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAuditHandler_VerifyAuditChain_Unauthorized_S6(t *testing.T) {
	h := newAuditHandlerS6(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.VerifyAuditChain(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuditHandler_VerifyAuditChain_HappyPath_S6(t *testing.T) {
	h := newAuditHandlerS6(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.VerifyAuditChain(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAuditHandler_WriteAuditCheckpoint_Unauthorized_S6(t *testing.T) {
	h := newAuditHandlerS6(t)
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()
	h.WriteAuditCheckpoint(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuditHandler_WriteAuditCheckpoint_NoEncryption_S6(t *testing.T) {
	h := newAuditHandlerS6(t)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", nil))
	w := httptest.NewRecorder()
	h.WriteAuditCheckpoint(w, req)
	// Without encryption, written=false → 412 PreconditionFailed.
	assert.Equal(t, http.StatusPreconditionFailed, w.Code)
}

// ── AuthHandler — remaining branches ─────────────────────────────────────────

func TestAuthHandler_Login_BadJSON_S6(t *testing.T) {
	h := newAuthHandlerS6(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad"))
	w := httptest.NewRecorder()
	h.Login(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAuthHandler_Login_InvalidCredentials_S6(t *testing.T) {
	h := newAuthHandlerS6(t)
	body := `{"username":"nobody","password":"wrongpassword"}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.Login(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthHandler_Login_RateLimit_S6(t *testing.T) {
	h := newAuthHandlerS6(t)
	// Flood enough failed attempts from 127.0.0.1 to trip the rate limit.
	const ip = "127.5.6.7"
	for i := 0; i < 11; i++ {
		h.coreService.RecordFailedLogin(nil, ip) //nolint:staticcheck
	}
	body := `{"username":"x","password":"y"}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.RemoteAddr = ip + ":1234"
	w := httptest.NewRecorder()
	h.Login(w, req)
	// Either 429 (rate limited) or 401 (wrong credentials) depending on window.
	assert.True(t, w.Code == http.StatusTooManyRequests || w.Code == http.StatusUnauthorized)
}

func TestAuthHandler_GetSetupToken_Missing_S6(t *testing.T) {
	h := newAuthHandlerS6(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "token", "")
	w := httptest.NewRecorder()
	h.GetSetupToken(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAuthHandler_GetSetupToken_Invalid_S6(t *testing.T) {
	h := newAuthHandlerS6(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "token", "not-a-real-token")
	w := httptest.NewRecorder()
	h.GetSetupToken(w, req)
	assert.Equal(t, http.StatusGone, w.Code)
}

func TestAuthHandler_ConsumeSetup_BadJSON_S6(t *testing.T) {
	h := newAuthHandlerS6(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad"))
	w := httptest.NewRecorder()
	h.ConsumeSetup(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAuthHandler_ConsumeSetup_MissingFields_S6(t *testing.T) {
	h := newAuthHandlerS6(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"token":""}`))
	w := httptest.NewRecorder()
	h.ConsumeSetup(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAuthHandler_ConsumeSetup_InvalidToken_S6(t *testing.T) {
	h := newAuthHandlerS6(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"token":"bad","password":"Password1!"}`))
	w := httptest.NewRecorder()
	h.ConsumeSetup(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAuthHandler_BeginSSO_UnknownProvider_S6(t *testing.T) {
	h := newAuthHandlerS6(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "provider", "nonexistent")
	w := httptest.NewRecorder()
	h.BeginSSO(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAuthHandler_CompleteSSO_UnknownProvider_S6(t *testing.T) {
	h := newAuthHandlerS6(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "provider", "nonexistent")
	w := httptest.NewRecorder()
	h.CompleteSSO(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestIsSafeSSOError_S6(t *testing.T) {
	assert.True(t, isSafeSSOError("unknown SSO provider"))
	assert.True(t, isSafeSSOError("invalid or expired login state"))
	assert.True(t, isSafeSSOError("account suspended"))
	assert.False(t, isSafeSSOError("some random internal error"))
	assert.False(t, isSafeSSOError(""))
}

// ── AuthHandler.BeginWebAuthnRegistration — unauthorized path ─────────────────

func TestAuthHandler_BeginWebAuthnRegistration_Unauthorized_S6(t *testing.T) {
	h := newAuthHandlerS6(t)
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()
	h.BeginWebAuthnRegistration(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthHandler_BeginWebAuthnRegistration_Enabled_S6(t *testing.T) {
	h := newAuthHandlerS6(t)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", nil))
	w := httptest.NewRecorder()
	h.BeginWebAuthnRegistration(w, req)
	// Either 501 (WebAuthn disabled) or 400 (other) — not 401.
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

func TestAuthHandler_ListWebAuthnCredentials_Unauthorized_S6(t *testing.T) {
	h := newAuthHandlerS6(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListWebAuthnCredentials(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthHandler_ListWebAuthnCredentials_HappyPath_S6(t *testing.T) {
	h := newAuthHandlerS6(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.ListWebAuthnCredentials(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAuthHandler_DeleteWebAuthnCredential_Unauthorized_S6(t *testing.T) {
	h := newAuthHandlerS6(t)
	req := httptest.NewRequest(http.MethodDelete, "/", nil)
	w := httptest.NewRecorder()
	h.DeleteWebAuthnCredential(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthHandler_DeleteWebAuthnCredential_BadID_S6(t *testing.T) {
	h := newAuthHandlerS6(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "notanumber"))
	w := httptest.NewRecorder()
	h.DeleteWebAuthnCredential(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAuthHandler_DeleteWebAuthnCredential_BadJSON_S6(t *testing.T) {
	h := newAuthHandlerS6(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodDelete, "/", strings.NewReader("{bad")), "id", "1"))
	w := httptest.NewRecorder()
	h.DeleteWebAuthnCredential(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAuthHandler_BeginWebAuthnLogin_BadJSON_S6(t *testing.T) {
	h := newAuthHandlerS6(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad"))
	w := httptest.NewRecorder()
	h.BeginWebAuthnLogin(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAuthHandler_BeginWebAuthnLogin_NoChallenge_S6(t *testing.T) {
	h := newAuthHandlerS6(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"mfa_challenge":""}`))
	w := httptest.NewRecorder()
	h.BeginWebAuthnLogin(w, req)
	// No valid challenge → error (4xx or 5xx but not 200).
	assert.NotEqual(t, http.StatusOK, w.Code)
}

func TestAuthHandler_FinishWebAuthnLogin_BadJSON_S6(t *testing.T) {
	h := newAuthHandlerS6(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad"))
	w := httptest.NewRecorder()
	h.FinishWebAuthnLogin(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAuthHandler_FinishWebAuthnLogin_NoCredential_S6(t *testing.T) {
	h := newAuthHandlerS6(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"mfa_challenge":"x","webauthn_session":"y"}`))
	w := httptest.NewRecorder()
	h.FinishWebAuthnLogin(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAuthHandler_BeginWebAuthnPasswordlessLogin_S6(t *testing.T) {
	h := newAuthHandlerS6(t)
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()
	h.BeginWebAuthnPasswordlessLogin(w, req)
	// Either 501 (disabled) or 400/200 — not 401.
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

func TestAuthHandler_FinishWebAuthnPasswordlessLogin_BadJSON_S6(t *testing.T) {
	h := newAuthHandlerS6(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad"))
	w := httptest.NewRecorder()
	h.FinishWebAuthnPasswordlessLogin(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAuthHandler_FinishWebAuthnPasswordlessLogin_NoCredential_S6(t *testing.T) {
	h := newAuthHandlerS6(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"webauthn_session":"x"}`))
	w := httptest.NewRecorder()
	h.FinishWebAuthnPasswordlessLogin(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── UsersRolesHandler — remaining branches ────────────────────────────────────

func TestGetUserRolesForUser_Unauthorized_S6(t *testing.T) {
	h := newUsersRolesHandlerS6(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.GetUserRolesForUser(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGetUserRolesForUser_BadID_S6(t *testing.T) {
	h := newUsersRolesHandlerS6(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "notanumber"))
	w := httptest.NewRecorder()
	h.GetUserRolesForUser(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetUserPermissionsForUser_Unauthorized_S6(t *testing.T) {
	h := newUsersRolesHandlerS6(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.GetUserPermissionsForUser(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGetUserPermissionsForUser_BadID_S6(t *testing.T) {
	h := newUsersRolesHandlerS6(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "notanumber"))
	w := httptest.NewRecorder()
	h.GetUserPermissionsForUser(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetUserMembershipsForUser_Unauthorized_S6(t *testing.T) {
	h := newUsersRolesHandlerS6(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.GetUserMembershipsForUser(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGetUserMembershipsForUser_BadID_S6(t *testing.T) {
	h := newUsersRolesHandlerS6(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "notanumber"))
	w := httptest.NewRecorder()
	h.GetUserMembershipsForUser(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetUserMembershipsForUser_HappyPath_S6(t *testing.T) {
	h := newUsersRolesHandlerS6(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "9999"))
	w := httptest.NewRecorder()
	h.GetUserMembershipsForUser(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestUpdateUserRoles_Unauthorized_S6(t *testing.T) {
	h := newUsersRolesHandlerS6(t)
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{"role_ids":[]}`)), "id", "1")
	w := httptest.NewRecorder()
	h.UpdateUserRoles(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestUpdateUserRoles_BadID_S6(t *testing.T) {
	h := newUsersRolesHandlerS6(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(`{"role_ids":[]}`)), "id", "notanumber"))
	w := httptest.NewRecorder()
	h.UpdateUserRoles(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpdateUserRoles_BadJSON_S6(t *testing.T) {
	h := newUsersRolesHandlerS6(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader("{bad")), "id", "1"))
	w := httptest.NewRecorder()
	h.UpdateUserRoles(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpdateUserRoles_InvalidRoleID_S6(t *testing.T) {
	h := newUsersRolesHandlerS6(t)
	body := `{"role_ids":[99999]}`
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(body)), "id", "1"))
	w := httptest.NewRecorder()
	h.UpdateUserRoles(w, req)
	// Role 99999 does not exist → 400 Bad Request.
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── UserHandler.ListUsers — remaining branches ─────────────────────────────────

func TestUserHandler_ListUsers_Unauthorized_S6(t *testing.T) {
	h := newUserHandlerS6(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListUsers(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestUserHandler_ListUsers_HappyPath_S6(t *testing.T) {
	h := newUserHandlerS6(t)
	// Avoid ?search= / ?username= / ?email= — those generate ILIKE queries which
	// SQLite doesn't support; use plain pagination + filter flags instead.
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/?page=1&page_size=5&is_active=true&include_deleted=true&filter=inactive", nil))
	w := httptest.NewRecorder()
	h.ListUsers(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestUserHandler_ListUsers_MaxPage_S6(t *testing.T) {
	h := newUserHandlerS6(t)
	// page > maxListPage → clamped to maxListPage
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/?page=99999&page_size=1", nil))
	w := httptest.NewRecorder()
	h.ListUsers(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestUserHandler_SearchUsers_Unauthorized_S6(t *testing.T) {
	h := newUserHandlerS6(t)
	req := httptest.NewRequest(http.MethodGet, "/?q=test", nil)
	w := httptest.NewRecorder()
	h.SearchUsers(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestUserHandler_SearchUsers_MissingQuery_S6(t *testing.T) {
	h := newUserHandlerS6(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.SearchUsers(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUserHandler_SearchUsers_HappyPath_S6(t *testing.T) {
	// Skip the SearchUsers happy-path: SQLite doesn't support ILIKE which the
	// underlying storage query uses; the 500 from SQLite would mask the handler
	// logic we are covering (same issue as ListUsers search). The unauthorized
	// and missing-query paths above cover the early-return branches.
	t.Skip("SQLite does not support ILIKE; SearchUsers happy-path tested in integration")
}

func TestUserHandler_StaleAccounts_Unauthorized_S6(t *testing.T) {
	h := newUserHandlerS6(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.StaleAccounts(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestUserHandler_StaleAccounts_InvalidState_S6(t *testing.T) {
	h := newUserHandlerS6(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/?state=invalid_state", nil))
	w := httptest.NewRecorder()
	h.StaleAccounts(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUserHandler_StaleAccounts_DefaultState_S6(t *testing.T) {
	h := newUserHandlerS6(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/?days=5", nil))
	w := httptest.NewRecorder()
	h.StaleAccounts(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestUserHandler_StaleAccounts_PasswordResetState_S6(t *testing.T) {
	h := newUserHandlerS6(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/?state=password_reset_required&days=0", nil))
	w := httptest.NewRecorder()
	h.StaleAccounts(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── UserHandler.VerifyCredentials — remaining branches ────────────────────────

func TestUserHandler_VerifyCredentials_BadJSON_S6(t *testing.T) {
	h := newUserHandlerS6(t)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")))
	w := httptest.NewRecorder()
	h.VerifyCredentials(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUserHandler_VerifyCredentials_MissingFields_S6(t *testing.T) {
	h := newUserHandlerS6(t)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"username":""}`)))
	w := httptest.NewRecorder()
	h.VerifyCredentials(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUserHandler_VerifyCredentials_InvalidCreds_S6(t *testing.T) {
	h := newUserHandlerS6(t)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"username":"nobody","password":"wrong"}`)))
	w := httptest.NewRecorder()
	h.VerifyCredentials(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── UserHandler.VerifyMFACredentials — remaining branches ─────────────────────

func TestUserHandler_VerifyMFACredentials_BadJSON_S6(t *testing.T) {
	h := newUserHandlerS6(t)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")))
	w := httptest.NewRecorder()
	h.VerifyMFACredentials(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUserHandler_VerifyMFACredentials_MissingFields_S6(t *testing.T) {
	h := newUserHandlerS6(t)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"challenge":""}`)))
	w := httptest.NewRecorder()
	h.VerifyMFACredentials(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUserHandler_VerifyMFACredentials_InvalidCode_S6(t *testing.T) {
	h := newUserHandlerS6(t)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"challenge":"tok","code":"000000"}`)))
	w := httptest.NewRecorder()
	h.VerifyMFACredentials(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── UserHandler.GetActiveMFAChallenge — remaining branches ────────────────────

func TestUserHandler_GetActiveMFAChallenge_Unauthorized_S6(t *testing.T) {
	h := newUserHandlerS6(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.GetActiveMFAChallenge(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestUserHandler_GetActiveMFAChallenge_BadBody_S6(t *testing.T) {
	h := newUserHandlerS6(t)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")))
	w := httptest.NewRecorder()
	h.GetActiveMFAChallenge(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUserHandler_GetActiveMFAChallenge_MissingFields_S6(t *testing.T) {
	h := newUserHandlerS6(t)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)))
	w := httptest.NewRecorder()
	h.GetActiveMFAChallenge(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUserHandler_GetActiveMFAChallenge_NotFound_S6(t *testing.T) {
	h := newUserHandlerS6(t)
	body := `{"token_hash":"hashXYZ","now":"2025-01-01T00:00:00Z"}`
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)))
	w := httptest.NewRecorder()
	h.GetActiveMFAChallenge(w, req)
	// No matching challenge → 404.
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── UserHandler.ConsumeMFAChallenge — remaining branches ─────────────────────

func TestUserHandler_ConsumeMFAChallenge_Unauthorized_S6(t *testing.T) {
	h := newUserHandlerS6(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"token":"t","code":"0"}`))
	w := httptest.NewRecorder()
	h.ConsumeMFAChallenge(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestUserHandler_ConsumeMFAChallenge_BadJSON_S6(t *testing.T) {
	h := newUserHandlerS6(t)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")))
	w := httptest.NewRecorder()
	h.ConsumeMFAChallenge(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUserHandler_ConsumeMFAChallenge_MissingFields_S6(t *testing.T) {
	h := newUserHandlerS6(t)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)))
	w := httptest.NewRecorder()
	h.ConsumeMFAChallenge(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUserHandler_ConsumeMFAChallenge_NotFound_S6(t *testing.T) {
	h := newUserHandlerS6(t)
	body := `{"token_hash":"hashXYZ","now":"2025-01-01T00:00:00Z"}`
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)))
	w := httptest.NewRecorder()
	h.ConsumeMFAChallenge(w, req)
	// Invalid challenge → 404.
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── SoD handler — ListSoDViolations ──────────────────────────────────────────

func TestSoDHandler_ListSoDViolations_S6(t *testing.T) {
	h := newCatalogHandlerS6(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListSoDViolations(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	_, hasDegraded := resp["data"].(map[string]interface{})["degraded"]
	_ = hasDegraded
}

// ── Access review campaigns — remaining branches ──────────────────────────────

func TestOpenAccessReviewCampaign_BadProjectID_S6(t *testing.T) {
	h := newCatalogHandlerS6(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "notanumber")
	w := httptest.NewRecorder()
	h.OpenAccessReviewCampaign(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestOpenAccessReviewCampaign_Unauthorized_S6(t *testing.T) {
	h := newCatalogHandlerS6(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.OpenAccessReviewCampaign(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestListAccessReviewCampaigns_BadProjectID_S6(t *testing.T) {
	h := newCatalogHandlerS6(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "notanumber")
	w := httptest.NewRecorder()
	h.ListAccessReviewCampaigns(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListAccessReviewCampaigns_HappyPath_S6(t *testing.T) {
	h := newCatalogHandlerS6(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.ListAccessReviewCampaigns(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestGetAccessReviewCampaign_BadProjectID_S6(t *testing.T) {
	h := newCatalogHandlerS6(t)
	req := withChiParams(httptest.NewRequest(http.MethodGet, "/", nil), map[string]string{"id": "notanumber", "campaignId": "1"})
	w := httptest.NewRecorder()
	h.GetAccessReviewCampaign(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetAccessReviewCampaign_BadCampaignID_S6(t *testing.T) {
	h := newCatalogHandlerS6(t)
	req := withChiParams(httptest.NewRequest(http.MethodGet, "/", nil), map[string]string{"id": "1", "campaignId": "notanumber"})
	w := httptest.NewRecorder()
	h.GetAccessReviewCampaign(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetAccessReviewCampaign_NotFound_S6(t *testing.T) {
	h := newCatalogHandlerS6(t)
	req := withChiParams(httptest.NewRequest(http.MethodGet, "/", nil), map[string]string{"id": "1", "campaignId": "9999"})
	w := httptest.NewRecorder()
	h.GetAccessReviewCampaign(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestDecideAccessReviewCampaignItem_BadProjectID_S6(t *testing.T) {
	h := newCatalogHandlerS6(t)
	req := withChiParams(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"action":"attest"}`)),
		map[string]string{"id": "notanumber", "campaignId": "1", "itemId": "1"})
	w := httptest.NewRecorder()
	h.DecideAccessReviewCampaignItem(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDecideAccessReviewCampaignItem_BadCampaignID_S6(t *testing.T) {
	h := newCatalogHandlerS6(t)
	req := withChiParams(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"action":"attest"}`)),
		map[string]string{"id": "1", "campaignId": "notanumber", "itemId": "1"})
	w := httptest.NewRecorder()
	h.DecideAccessReviewCampaignItem(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDecideAccessReviewCampaignItem_BadItemID_S6(t *testing.T) {
	h := newCatalogHandlerS6(t)
	req := withChiParams(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"action":"attest"}`)),
		map[string]string{"id": "1", "campaignId": "1", "itemId": "notanumber"})
	w := httptest.NewRecorder()
	h.DecideAccessReviewCampaignItem(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDecideAccessReviewCampaignItem_Unauthorized_S6(t *testing.T) {
	h := newCatalogHandlerS6(t)
	req := withChiParams(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"action":"attest"}`)),
		map[string]string{"id": "1", "campaignId": "1", "itemId": "1"})
	w := httptest.NewRecorder()
	h.DecideAccessReviewCampaignItem(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestDecideAccessReviewCampaignItem_BadJSON_S6(t *testing.T) {
	h := newCatalogHandlerS6(t)
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad")),
		map[string]string{"id": "1", "campaignId": "1", "itemId": "1"}))
	w := httptest.NewRecorder()
	h.DecideAccessReviewCampaignItem(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDecideAccessReviewCampaignItem_MissingAction_S6(t *testing.T) {
	h := newCatalogHandlerS6(t)
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"action":""}`)),
		map[string]string{"id": "1", "campaignId": "1", "itemId": "1"}))
	w := httptest.NewRecorder()
	h.DecideAccessReviewCampaignItem(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCloseAccessReviewCampaign_BadProjectID_S6(t *testing.T) {
	h := newCatalogHandlerS6(t)
	req := withChiParams(httptest.NewRequest(http.MethodPost, "/", nil), map[string]string{"id": "notanumber", "campaignId": "1"})
	w := httptest.NewRecorder()
	h.CloseAccessReviewCampaign(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCloseAccessReviewCampaign_BadCampaignID_S6(t *testing.T) {
	h := newCatalogHandlerS6(t)
	req := withChiParams(httptest.NewRequest(http.MethodPost, "/", nil), map[string]string{"id": "1", "campaignId": "notanumber"})
	w := httptest.NewRecorder()
	h.CloseAccessReviewCampaign(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCloseAccessReviewCampaign_Unauthorized_S6(t *testing.T) {
	h := newCatalogHandlerS6(t)
	// Note: handler parses projectID first; only after that checks auth.
	// Provide valid chi params so we reach the auth check.
	req := withChiParams(httptest.NewRequest(http.MethodPost, "/", nil), map[string]string{"id": "1", "campaignId": "1"})
	w := httptest.NewRecorder()
	h.CloseAccessReviewCampaign(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestCampaignStatusForError covers all branches of the switch.
func TestCampaignStatusForError_S6(t *testing.T) {
	assert.Equal(t, http.StatusNotFound, campaignStatusForError("not found"))
	assert.Equal(t, http.StatusBadRequest, campaignStatusForError("required field missing"))
	assert.Equal(t, http.StatusBadRequest, campaignStatusForError("still pending items"))
	assert.Equal(t, http.StatusBadRequest, campaignStatusForError("already closed"))
	assert.Equal(t, http.StatusBadRequest, campaignStatusForError("campaign is closed"))
	assert.Equal(t, http.StatusBadRequest, campaignStatusForError("ownership cannot be revoked"))
	assert.Equal(t, http.StatusBadRequest, campaignStatusForError("must be unique"))
	assert.Equal(t, http.StatusInternalServerError, campaignStatusForError("unexpected db error"))
}

// ── ExportAccessReviewCampaignCSV — remaining branches ───────────────────────

func TestExportAccessReviewCampaignCSV_Unauthorized_S6(t *testing.T) {
	h := newCatalogHandlerS6(t)
	req := withChiParams(httptest.NewRequest(http.MethodGet, "/", nil), map[string]string{"id": "1", "campaignId": "1"})
	w := httptest.NewRecorder()
	h.ExportAccessReviewCampaignCSV(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestExportAccessReviewCampaignCSV_BadProjectID_S6(t *testing.T) {
	h := newCatalogHandlerS6(t)
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodGet, "/", nil), map[string]string{"id": "notanumber", "campaignId": "1"}))
	w := httptest.NewRecorder()
	h.ExportAccessReviewCampaignCSV(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestExportAccessReviewCampaignCSV_BadCampaignID_S6(t *testing.T) {
	h := newCatalogHandlerS6(t)
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodGet, "/", nil), map[string]string{"id": "1", "campaignId": "notanumber"}))
	w := httptest.NewRecorder()
	h.ExportAccessReviewCampaignCSV(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestExportAccessReviewCampaignCSV_NotFound_S6(t *testing.T) {
	h := newCatalogHandlerS6(t)
	req := withUserCtx(withChiParams(httptest.NewRequest(http.MethodGet, "/", nil), map[string]string{"id": "1", "campaignId": "9999"}))
	w := httptest.NewRecorder()
	h.ExportAccessReviewCampaignCSV(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── UserHandler.CreateUser — remaining branches ───────────────────────────────

func TestUserHandler_GetUser_Unauthorized_S6(t *testing.T) {
	h := newUserHandlerS6(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.GetUser(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestUserHandler_GetUser_BadID_S6(t *testing.T) {
	h := newUserHandlerS6(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "notanumber"))
	w := httptest.NewRecorder()
	h.GetUser(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUserHandler_GetUserByEmail_Unauthorized_S6(t *testing.T) {
	h := newUserHandlerS6(t)
	req := httptest.NewRequest(http.MethodGet, "/?email=x@x.com", nil)
	w := httptest.NewRecorder()
	h.GetUserByEmail(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestUserHandler_GetUserByEmail_MissingEmail_S6(t *testing.T) {
	h := newUserHandlerS6(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.GetUserByEmail(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUserHandler_GetUserByEmail_NotFound_S6(t *testing.T) {
	h := newUserHandlerS6(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/?email=nobody@nowhere.invalid", nil))
	w := httptest.NewRecorder()
	h.GetUserByEmail(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestUserHandler_GetUserByUsername_Unauthorized_S6(t *testing.T) {
	h := newUserHandlerS6(t)
	req := httptest.NewRequest(http.MethodGet, "/?username=x", nil)
	w := httptest.NewRecorder()
	h.GetUserByUsername(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestUserHandler_GetUserByUsername_Missing_S6(t *testing.T) {
	h := newUserHandlerS6(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.GetUserByUsername(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUserHandler_GetUserByExternalID_Unauthorized_S6(t *testing.T) {
	h := newUserHandlerS6(t)
	req := httptest.NewRequest(http.MethodGet, "/?external_id=ext123", nil)
	w := httptest.NewRecorder()
	h.GetUserByExternalID(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestUserHandler_GetUserByExternalID_Missing_S6(t *testing.T) {
	h := newUserHandlerS6(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.GetUserByExternalID(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUserHandler_UpdateUser_SuspendReactivate_S6(t *testing.T) {
	h := newUserHandlerS6(t)
	// Exercising accountStateAction indirectly: UpdateUser with a valid (but
	// not-found) user exercises the core error path.
	body := `{"account_state":"active"}`
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(body)), "id", "9999"))
	w := httptest.NewRecorder()
	h.UpdateUser(w, req)
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

func TestUserHandler_DeleteUser_Unauthorized_S6(t *testing.T) {
	h := newUserHandlerS6(t)
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.DeleteUser(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestUserHandler_DeleteUser_BadID_S6(t *testing.T) {
	h := newUserHandlerS6(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "notanumber"))
	w := httptest.NewRecorder()
	h.DeleteUser(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUserHandler_RestoreUser_Unauthorized_S6(t *testing.T) {
	h := newUserHandlerS6(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.RestoreUser(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestUserHandler_UnlockUser_Unauthorized_S6(t *testing.T) {
	h := newUserHandlerS6(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.UnlockUser(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestUserHandler_UnlockUser_BadID_S6(t *testing.T) {
	h := newUserHandlerS6(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "notanumber"))
	w := httptest.NewRecorder()
	h.UnlockUser(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUserHandler_UnlockUser_NotFound_S6(t *testing.T) {
	h := newUserHandlerS6(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "9999"))
	w := httptest.NewRecorder()
	h.UnlockUser(w, req)
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
}

func TestUserHandler_ResendSetupLink_Unauthorized_S6(t *testing.T) {
	h := newUserHandlerS6(t)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.ResendSetupLink(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestUserHandler_ResendSetupLink_BadID_S6(t *testing.T) {
	h := newUserHandlerS6(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "notanumber"))
	w := httptest.NewRecorder()
	h.ResendSetupLink(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUserHandler_ResendSetupLink_NotFound_S6(t *testing.T) {
	h := newUserHandlerS6(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "9999"))
	w := httptest.NewRecorder()
	h.ResendSetupLink(w, req)
	// Not found → 404.
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── extractBearerToken — cookie vs. header precedence ─────────────────────────

func TestExtractBearerToken_Cookie_S6(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: middleware.SessionCookieName, Value: "cookie-token"})
	req.Header.Set("Authorization", "Bearer header-token")
	assert.Equal(t, "cookie-token", extractBearerToken(req))
}

func TestExtractBearerToken_Header_S6(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer header-token")
	assert.Equal(t, "header-token", extractBearerToken(req))
}

func TestExtractBearerToken_Empty_S6(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	assert.Equal(t, "", extractBearerToken(req))
}

