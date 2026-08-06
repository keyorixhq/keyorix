// handlers_s13_proxy_test.go — coverage sweep for proxy handler error paths in:
//   - login_attempts_proxy.go: bad/missing body fields, missing query params, bad timestamp
//   - login_lockout_proxy.go: bad id param, bad body, not-found
//   - misc_remote_proxy.go: bad project_id, bad id params, missing body fields
//   - retention_proxy.go: missing/zero before fields, bad query params
//   - risk_exceptions_proxy.go: bad id, missing body fields, not-found
//   - risk_exceptions.go: missing user ctx, bad id
//   - scheduler_lock_proxy.go: missing holder, bad ttl
//   - setup_tokens_proxy.go: bad id, missing fields, bad timestamp
//   - sso_state_proxy.go: missing fields, bad state
package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── helpers ───────────────────────────────────────────────────────────────────

func decodeRemoteResp(t *testing.T, w *httptest.ResponseRecorder) remoteAPIResponse {
	t.Helper()
	var resp remoteAPIResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	return resp
}

func freshAuthHandlerS13(t *testing.T) *AuthHandler {
	t.Helper()
	cs := freshCoreS12(t)
	return NewAuthHandler(cs, false)
}

func freshDashboardHandlerS13(t *testing.T) *DashboardHandler {
	t.Helper()
	cs := freshCoreS12(t)
	return NewDashboardHandler(cs)
}

func freshSecretHandlerForProxyS13(t *testing.T) *SecretHandler {
	t.Helper()
	cs := freshCoreS12(t)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)
	return h
}

func freshShareHandlerForProxyS13(t *testing.T) *ShareHandler {
	t.Helper()
	cs := freshCoreS12(t)
	h, err := NewShareHandler(cs)
	require.NoError(t, err)
	return h
}

func freshCatalogHandlerS13(t *testing.T) *CatalogHandler {
	t.Helper()
	cs := freshCoreS12(t)
	return NewCatalogHandler(cs)
}

func freshRBACHandlerS13(t *testing.T) *RBACHandler {
	t.Helper()
	cs := freshCoreS12(t)
	return NewRBACHandler(cs)
}

func freshUserHandlerForProxyS13(t *testing.T) *UserHandler {
	t.Helper()
	cs := freshCoreS12(t)
	h, err := NewUserHandler(cs)
	require.NoError(t, err)
	return h
}

func freshAuditHandlerS13(t *testing.T) *AuditHandler {
	t.Helper()
	cs := freshCoreS12(t)
	return NewAuditHandler(cs)
}

func proxyJSON(v interface{}) *bytes.Buffer {
	b, _ := json.Marshal(v)
	return bytes.NewBuffer(b)
}

// ── login_attempts_proxy.go ───────────────────────────────────────────────────

// TestRecordLoginAttemptProxy_BadBody_S13 — malformed JSON → 400.
func TestRecordLoginAttemptProxy_BadBody_S13(t *testing.T) {
	h := freshAuthHandlerS13(t)
	req := httptest.NewRequest(http.MethodPost, "/system/login-attempts", strings.NewReader("{bad"))
	w := httptest.NewRecorder()
	h.RecordLoginAttemptProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.False(t, resp.Success)
	assert.Equal(t, "INVALID_BODY", resp.Error.Code)
}

// TestRecordLoginAttemptProxy_MissingIP_S13 — empty ip field → 400.
func TestRecordLoginAttemptProxy_MissingIP_S13(t *testing.T) {
	h := freshAuthHandlerS13(t)
	body := proxyJSON(map[string]interface{}{"ip": "", "at": time.Now()})
	req := httptest.NewRequest(http.MethodPost, "/system/login-attempts", body)
	w := httptest.NewRecorder()
	h.RecordLoginAttemptProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.False(t, resp.Success)
	assert.Equal(t, "INVALID_BODY", resp.Error.Code)
}

// TestCountLoginAttemptsProxy_MissingParams_S13 — missing ip and since → 400.
func TestCountLoginAttemptsProxy_MissingParams_S13(t *testing.T) {
	h := freshAuthHandlerS13(t)
	req := httptest.NewRequest(http.MethodGet, "/system/login-attempts/count", nil)
	w := httptest.NewRecorder()
	h.CountLoginAttemptsProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.Equal(t, "INVALID_QUERY", resp.Error.Code)
}

// TestCountLoginAttemptsProxy_MissingSince_S13 — ip present but since missing → 400.
func TestCountLoginAttemptsProxy_MissingSince_S13(t *testing.T) {
	h := freshAuthHandlerS13(t)
	req := httptest.NewRequest(http.MethodGet, "/system/login-attempts/count?ip=127.0.0.1", nil)
	w := httptest.NewRecorder()
	h.CountLoginAttemptsProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.Equal(t, "INVALID_QUERY", resp.Error.Code)
}

// TestCountLoginAttemptsProxy_BadSince_S13 — since not RFC3339 → 400.
func TestCountLoginAttemptsProxy_BadSince_S13(t *testing.T) {
	h := freshAuthHandlerS13(t)
	req := httptest.NewRequest(http.MethodGet, "/system/login-attempts/count?ip=127.0.0.1&since=not-a-time", nil)
	w := httptest.NewRecorder()
	h.CountLoginAttemptsProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.Equal(t, "INVALID_QUERY", resp.Error.Code)
}

// TestCountLoginAttemptsProxy_HappyPath_S13 — valid params → 200 success.
func TestCountLoginAttemptsProxy_HappyPath_S13(t *testing.T) {
	h := freshAuthHandlerS13(t)
	since := time.Now().Add(-1 * time.Hour).Format(time.RFC3339Nano)
	// Use query encoding to handle + in RFC3339Nano correctly.
	req := httptest.NewRequest(http.MethodGet, "http://localhost/system/login-attempts/count", nil)
	q := req.URL.Query()
	q.Set("ip", "127.0.0.1")
	q.Set("since", since)
	req.URL.RawQuery = q.Encode()
	w := httptest.NewRecorder()
	h.CountLoginAttemptsProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.True(t, resp.Success)
}

// TestPruneLoginAttemptsProxy_BadBody_S13 — malformed JSON → 400.
func TestPruneLoginAttemptsProxy_BadBody_S13(t *testing.T) {
	h := freshAuthHandlerS13(t)
	req := httptest.NewRequest(http.MethodPost, "/system/login-attempts/prune", strings.NewReader("{bad"))
	w := httptest.NewRecorder()
	h.PruneLoginAttemptsProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.Equal(t, "INVALID_BODY", resp.Error.Code)
}

// TestPruneLoginAttemptsProxy_ZeroBefore_S13 — zero before timestamp → 400.
func TestPruneLoginAttemptsProxy_ZeroBefore_S13(t *testing.T) {
	h := freshAuthHandlerS13(t)
	body := proxyJSON(map[string]interface{}{"before": time.Time{}})
	req := httptest.NewRequest(http.MethodPost, "/system/login-attempts/prune", body)
	w := httptest.NewRecorder()
	h.PruneLoginAttemptsProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.Equal(t, "INVALID_BODY", resp.Error.Code)
}

// TestPruneLoginAttemptsProxy_HappyPath_S13 — valid before → 200 success.
func TestPruneLoginAttemptsProxy_HappyPath_S13(t *testing.T) {
	h := freshAuthHandlerS13(t)
	body := proxyJSON(map[string]interface{}{"before": time.Now()})
	req := httptest.NewRequest(http.MethodPost, "/system/login-attempts/prune", body)
	w := httptest.NewRecorder()
	h.PruneLoginAttemptsProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.True(t, resp.Success)
}

// TestRecordLoginAttemptProxy_HappyPath_S13 — valid body → 200 success.
func TestRecordLoginAttemptProxy_HappyPath_S13(t *testing.T) {
	h := freshAuthHandlerS13(t)
	body := proxyJSON(map[string]interface{}{"ip": "192.168.1.1", "at": time.Now()})
	req := httptest.NewRequest(http.MethodPost, "/system/login-attempts", body)
	w := httptest.NewRecorder()
	h.RecordLoginAttemptProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.True(t, resp.Success)
}

// ── login_lockout_proxy.go ────────────────────────────────────────────────────

// TestUpdateLoginLockoutStateProxy_BadID_S13 — non-numeric id → 400.
func TestUpdateLoginLockoutStateProxy_BadID_S13(t *testing.T) {
	h := freshAuthHandlerS13(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodPut, "/system/users/bad/login-lockout", strings.NewReader("{}")),
		"id", "bad",
	)
	w := httptest.NewRecorder()
	h.UpdateLoginLockoutStateProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.Equal(t, "INVALID_PARAMETER", resp.Error.Code)
}

// TestUpdateLoginLockoutStateProxy_BadBody_S13 — malformed JSON body → 400.
func TestUpdateLoginLockoutStateProxy_BadBody_S13(t *testing.T) {
	h := freshAuthHandlerS13(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodPut, "/system/users/1/login-lockout", strings.NewReader("{bad")),
		"id", "1",
	)
	w := httptest.NewRecorder()
	h.UpdateLoginLockoutStateProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.Equal(t, "INVALID_BODY", resp.Error.Code)
}

// TestUpdateLoginLockoutStateProxy_NotFound_S13 — valid body but user doesn't exist → 404.
func TestUpdateLoginLockoutStateProxy_NotFound_S13(t *testing.T) {
	h := freshAuthHandlerS13(t)
	body := proxyJSON(map[string]interface{}{
		"failed_login_attempts": 0,
		"login_lockout_count":   0,
	})
	req := withChiParam(
		httptest.NewRequest(http.MethodPut, "/system/users/9999/login-lockout", body),
		"id", "9999",
	)
	w := httptest.NewRecorder()
	h.UpdateLoginLockoutStateProxy(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.Equal(t, "NOT_FOUND", resp.Error.Code)
}

// TestUpdateLoginLockoutStateProxy_HappyPath_S13 — valid update on existing user → 200.
func TestUpdateLoginLockoutStateProxy_HappyPath_S13(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h := NewAuthHandler(cs, false)

	// User ID=1 exists (seeded by freshCoreS12WithAdmin).
	_ = db
	body := proxyJSON(map[string]interface{}{
		"failed_login_attempts": 3,
		"login_lockout_count":   1,
	})
	req := withChiParam(
		httptest.NewRequest(http.MethodPut, "/system/users/1/login-lockout", body),
		"id", "1",
	)
	w := httptest.NewRecorder()
	h.UpdateLoginLockoutStateProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.True(t, resp.Success)
}

// ── misc_remote_proxy.go: accessActivityProxy ────────────────────────────────

// TestAccessActivityProxy_MissingProjectID_S13 — no project_id → 400.
func TestAccessActivityProxy_MissingProjectID_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h, err := NewUserHandler(cs)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodGet, "/system/access-activity/secret", nil)
	w := httptest.NewRecorder()
	h.LastUserSecretActivityProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.Equal(t, "INVALID_QUERY", resp.Error.Code)
}

// TestAccessActivityProxy_BadProjectID_S13 — non-numeric project_id → 400.
func TestAccessActivityProxy_BadProjectID_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h, err := NewUserHandler(cs)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodGet, "/system/access-activity/secret?project_id=notanum", nil)
	w := httptest.NewRecorder()
	h.LastUserSecretActivityProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.Equal(t, "INVALID_QUERY", resp.Error.Code)
}

// TestAccessActivityProxy_RoleManagement_MissingProjectID_S13 — covers role-management kind.
func TestAccessActivityProxy_RoleManagement_MissingProjectID_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h, err := NewUserHandler(cs)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodGet, "/system/access-activity/role-management", nil)
	w := httptest.NewRecorder()
	h.LastUserRoleManagementActivityProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestAccessActivityProxy_SecretDeletion_MissingProjectID_S13 — covers secret-deletion kind.
func TestAccessActivityProxy_SecretDeletion_MissingProjectID_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h, err := NewUserHandler(cs)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodGet, "/system/access-activity/secret-deletion", nil)
	w := httptest.NewRecorder()
	h.LastUserSecretDeletionActivityProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestAccessActivityProxy_SecretRead_HappyPath_S13 — valid project_id, happy path.
func TestAccessActivityProxy_SecretRead_HappyPath_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h, err := NewUserHandler(cs)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodGet, "/system/access-activity/secret-read?project_id=1", nil)
	w := httptest.NewRecorder()
	h.LastUserSecretReadActivityProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.True(t, resp.Success)
}

// TestAccessActivityProxy_SecretWrite_HappyPath_S13 — valid project_id, happy path.
func TestAccessActivityProxy_SecretWrite_HappyPath_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h, err := NewUserHandler(cs)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodGet, "/system/access-activity/secret-write?project_id=1", nil)
	w := httptest.NewRecorder()
	h.LastUserSecretWriteActivityProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.True(t, resp.Success)
}

// ── misc_remote_proxy.go: GetSecretIncludingDeletedProxy ─────────────────────

// TestGetSecretIncludingDeletedProxy_BadID_S13 — non-numeric id → 400.
func TestGetSecretIncludingDeletedProxy_BadID_S13(t *testing.T) {
	h := freshSecretHandlerForProxyS13(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/system/secrets/bad/including-deleted", nil),
		"id", "bad",
	)
	w := httptest.NewRecorder()
	h.GetSecretIncludingDeletedProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.Equal(t, "INVALID_PARAMETER", resp.Error.Code)
}

// TestGetSecretIncludingDeletedProxy_NotFound_S13 — valid id, no such secret → 404.
func TestGetSecretIncludingDeletedProxy_NotFound_S13(t *testing.T) {
	h := freshSecretHandlerForProxyS13(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/system/secrets/9999/including-deleted", nil),
		"id", "9999",
	)
	w := httptest.NewRecorder()
	h.GetSecretIncludingDeletedProxy(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.Equal(t, "NOT_FOUND", resp.Error.Code)
}

// ── misc_remote_proxy.go: ListSharesByOwnerProxy ─────────────────────────────

// TestListSharesByOwnerProxy_BadID_S13 — non-numeric ownerID → 400.
func TestListSharesByOwnerProxy_BadID_S13(t *testing.T) {
	h := freshShareHandlerForProxyS13(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/system/shares/by-owner/bad", nil),
		"ownerID", "bad",
	)
	w := httptest.NewRecorder()
	h.ListSharesByOwnerProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.Equal(t, "INVALID_PARAMETER", resp.Error.Code)
}

// TestListSharesByOwnerProxy_HappyPath_S13 — valid ownerID (no data) → 200.
func TestListSharesByOwnerProxy_HappyPath_S13(t *testing.T) {
	h := freshShareHandlerForProxyS13(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/system/shares/by-owner/1", nil),
		"ownerID", "1",
	)
	w := httptest.NewRecorder()
	h.ListSharesByOwnerProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.True(t, resp.Success)
}

// ── misc_remote_proxy.go: ListSharesByUserProxy ──────────────────────────────

// TestListSharesByUserProxy_BadID_S13 — non-numeric userID → 400.
func TestListSharesByUserProxy_BadID_S13(t *testing.T) {
	h := freshShareHandlerForProxyS13(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/system/shares/by-user/bad", nil),
		"userID", "bad",
	)
	w := httptest.NewRecorder()
	h.ListSharesByUserProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.Equal(t, "INVALID_PARAMETER", resp.Error.Code)
}

// TestListSharesByUserProxy_HappyPath_S13 — valid userID (no data) → 200.
func TestListSharesByUserProxy_HappyPath_S13(t *testing.T) {
	h := freshShareHandlerForProxyS13(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/system/shares/by-user/1", nil),
		"userID", "1",
	)
	w := httptest.NewRecorder()
	h.ListSharesByUserProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.True(t, resp.Success)
}

// ── misc_remote_proxy.go: CreateUserWithRoleGrantsProxy ─────────────────────

// TestCreateUserWithRoleGrantsProxy_BadBody_S13 — malformed JSON → 400.
func TestCreateUserWithRoleGrantsProxy_BadBody_S13(t *testing.T) {
	h := freshUserHandlerForProxyS13(t)
	req := httptest.NewRequest(http.MethodPost, "/system/users/with-role-grants", strings.NewReader("{bad"))
	w := httptest.NewRecorder()
	h.CreateUserWithRoleGrantsProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.Equal(t, "INVALID_BODY", resp.Error.Code)
}

// TestCreateUserWithRoleGrantsProxy_MissingFields_S13 — missing username → 400.
func TestCreateUserWithRoleGrantsProxy_MissingFields_S13(t *testing.T) {
	h := freshUserHandlerForProxyS13(t)
	body := proxyJSON(map[string]interface{}{
		"email":         "test@example.com",
		"password_hash": "hash",
		// username missing
	})
	req := httptest.NewRequest(http.MethodPost, "/system/users/with-role-grants", body)
	w := httptest.NewRecorder()
	h.CreateUserWithRoleGrantsProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.Equal(t, "INVALID_BODY", resp.Error.Code)
}

// TestCreateUserWithRoleGrantsProxy_MissingEmail_S13 — missing email → 400.
func TestCreateUserWithRoleGrantsProxy_MissingEmail_S13(t *testing.T) {
	h := freshUserHandlerForProxyS13(t)
	body := proxyJSON(map[string]interface{}{
		"username":      "testuser",
		"password_hash": "hash",
		// email missing
	})
	req := httptest.NewRequest(http.MethodPost, "/system/users/with-role-grants", body)
	w := httptest.NewRecorder()
	h.CreateUserWithRoleGrantsProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.Equal(t, "INVALID_BODY", resp.Error.Code)
}

// TestCreateUserWithRoleGrantsProxy_MissingPasswordHash_S13 — missing password_hash → 400.
func TestCreateUserWithRoleGrantsProxy_MissingPasswordHash_S13(t *testing.T) {
	h := freshUserHandlerForProxyS13(t)
	body := proxyJSON(map[string]interface{}{
		"username": "testuser",
		"email":    "test@example.com",
		// password_hash missing
	})
	req := httptest.NewRequest(http.MethodPost, "/system/users/with-role-grants", body)
	w := httptest.NewRecorder()
	h.CreateUserWithRoleGrantsProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.Equal(t, "INVALID_BODY", resp.Error.Code)
}

// TestCreateUserWithRoleGrantsProxy_HappyPath_S13 — valid body → 200.
func TestCreateUserWithRoleGrantsProxy_HappyPath_S13(t *testing.T) {
	h := freshUserHandlerForProxyS13(t)
	body := proxyJSON(map[string]interface{}{
		"username":      "newproxy_user_s13",
		"email":         "newproxy_s13@example.com",
		"password_hash": "$2a$10$abcdefghijklmnopqrstuvuv",
		"is_active":     true,
		"account_state": "active",
		"grants":        []interface{}{},
	})
	req := httptest.NewRequest(http.MethodPost, "/system/users/with-role-grants", body)
	w := httptest.NewRecorder()
	h.CreateUserWithRoleGrantsProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.True(t, resp.Success)
}

// ── retention_proxy.go: decodeRetentionBeforeBody ───────────────────────────

// TestPurgeDeletedSecretsBeforeProxy_BadBody_S13 — malformed JSON → 400.
func TestPurgeDeletedSecretsBeforeProxy_BadBody_S13(t *testing.T) {
	h := freshSecretHandlerForProxyS13(t)
	req := httptest.NewRequest(http.MethodPost, "/system/retention/secrets/purge", strings.NewReader("{bad"))
	w := httptest.NewRecorder()
	h.PurgeDeletedSecretsBeforeProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.Equal(t, "INVALID_BODY", resp.Error.Code)
}

// TestPurgeDeletedSecretsBeforeProxy_ZeroBefore_S13 — zero before → 400.
func TestPurgeDeletedSecretsBeforeProxy_ZeroBefore_S13(t *testing.T) {
	h := freshSecretHandlerForProxyS13(t)
	body := proxyJSON(map[string]interface{}{"before": time.Time{}})
	req := httptest.NewRequest(http.MethodPost, "/system/retention/secrets/purge", body)
	w := httptest.NewRecorder()
	h.PurgeDeletedSecretsBeforeProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.Equal(t, "INVALID_BODY", resp.Error.Code)
}

// TestPurgeDeletedSecretsBeforeProxy_HappyPath_S13 — valid before → 200.
func TestPurgeDeletedSecretsBeforeProxy_HappyPath_S13(t *testing.T) {
	h := freshSecretHandlerForProxyS13(t)
	body := proxyJSON(map[string]interface{}{"before": time.Now()})
	req := httptest.NewRequest(http.MethodPost, "/system/retention/secrets/purge", body)
	w := httptest.NewRecorder()
	h.PurgeDeletedSecretsBeforeProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.True(t, resp.Success)
}

// TestDeleteAnomalyAlertsBeforeProxy_BadBody_S13 — malformed JSON → 400.
func TestDeleteAnomalyAlertsBeforeProxy_BadBody_S13(t *testing.T) {
	h := freshAuditHandlerS13(t)
	req := httptest.NewRequest(http.MethodPost, "/system/retention/anomaly-alerts/purge", strings.NewReader("{bad"))
	w := httptest.NewRecorder()
	h.DeleteAnomalyAlertsBeforeProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.Equal(t, "INVALID_BODY", resp.Error.Code)
}

// TestDeleteAnomalyAlertsBeforeProxy_HappyPath_S13 — zero timestamps allowed → 200.
func TestDeleteAnomalyAlertsBeforeProxy_HappyPath_S13(t *testing.T) {
	h := freshAuditHandlerS13(t)
	body := proxyJSON(map[string]interface{}{
		"ack_before":    time.Now(),
		"unack_ceiling": time.Now(),
	})
	req := httptest.NewRequest(http.MethodPost, "/system/retention/anomaly-alerts/purge", body)
	w := httptest.NewRecorder()
	h.DeleteAnomalyAlertsBeforeProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.True(t, resp.Success)
}

// TestDeleteClosedAccessReviewsBeforeProxy_BadBody_S13 — bad JSON → 400.
func TestDeleteClosedAccessReviewsBeforeProxy_BadBody_S13(t *testing.T) {
	h := freshCatalogHandlerS13(t)
	req := httptest.NewRequest(http.MethodPost, "/system/retention/access-reviews/purge-closed", strings.NewReader("{bad"))
	w := httptest.NewRecorder()
	h.DeleteClosedAccessReviewsBeforeProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.Equal(t, "INVALID_BODY", resp.Error.Code)
}

// TestDeleteClosedAccessReviewsBeforeProxy_ZeroBefore_S13 — zero before → 400.
func TestDeleteClosedAccessReviewsBeforeProxy_ZeroBefore_S13(t *testing.T) {
	h := freshCatalogHandlerS13(t)
	body := proxyJSON(map[string]interface{}{"before": time.Time{}})
	req := httptest.NewRequest(http.MethodPost, "/system/retention/access-reviews/purge-closed", body)
	w := httptest.NewRecorder()
	h.DeleteClosedAccessReviewsBeforeProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestDeleteClosedAccessReviewsBeforeProxy_HappyPath_S13 — valid before → 200.
func TestDeleteClosedAccessReviewsBeforeProxy_HappyPath_S13(t *testing.T) {
	h := freshCatalogHandlerS13(t)
	body := proxyJSON(map[string]interface{}{"before": time.Now()})
	req := httptest.NewRequest(http.MethodPost, "/system/retention/access-reviews/purge-closed", body)
	w := httptest.NewRecorder()
	h.DeleteClosedAccessReviewsBeforeProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.True(t, resp.Success)
}

// TestDeleteExpiredBreakGlassBeforeProxy_BadBody_S13 — bad JSON → 400.
func TestDeleteExpiredBreakGlassBeforeProxy_BadBody_S13(t *testing.T) {
	h := freshCatalogHandlerS13(t)
	req := httptest.NewRequest(http.MethodPost, "/system/retention/break-glass/purge-expired", strings.NewReader("{bad"))
	w := httptest.NewRecorder()
	h.DeleteExpiredBreakGlassBeforeProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestDeleteExpiredBreakGlassBeforeProxy_HappyPath_S13 — valid before → 200.
func TestDeleteExpiredBreakGlassBeforeProxy_HappyPath_S13(t *testing.T) {
	h := freshCatalogHandlerS13(t)
	body := proxyJSON(map[string]interface{}{"before": time.Now()})
	req := httptest.NewRequest(http.MethodPost, "/system/retention/break-glass/purge-expired", body)
	w := httptest.NewRecorder()
	h.DeleteExpiredBreakGlassBeforeProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.True(t, resp.Success)
}

// TestDeleteResolvedAccessRequestsBeforeProxy_BadBody_S13 — bad JSON → 400.
func TestDeleteResolvedAccessRequestsBeforeProxy_BadBody_S13(t *testing.T) {
	h := freshCatalogHandlerS13(t)
	req := httptest.NewRequest(http.MethodPost, "/system/retention/access-requests/purge-resolved", strings.NewReader("{bad"))
	w := httptest.NewRecorder()
	h.DeleteResolvedAccessRequestsBeforeProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestDeleteResolvedAccessRequestsBeforeProxy_HappyPath_S13 — valid before → 200.
func TestDeleteResolvedAccessRequestsBeforeProxy_HappyPath_S13(t *testing.T) {
	h := freshCatalogHandlerS13(t)
	body := proxyJSON(map[string]interface{}{"before": time.Now()})
	req := httptest.NewRequest(http.MethodPost, "/system/retention/access-requests/purge-resolved", body)
	w := httptest.NewRecorder()
	h.DeleteResolvedAccessRequestsBeforeProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.True(t, resp.Success)
}

// TestPurgeDeletedProjectsBeforeProxy_BadBody_S13 — bad JSON → 400.
func TestPurgeDeletedProjectsBeforeProxy_BadBody_S13(t *testing.T) {
	h := freshCatalogHandlerS13(t)
	req := httptest.NewRequest(http.MethodPost, "/system/retention/projects/purge", strings.NewReader("{bad"))
	w := httptest.NewRecorder()
	h.PurgeDeletedProjectsBeforeProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestPurgeDeletedProjectsBeforeProxy_HappyPath_S13 — valid before → 200.
func TestPurgeDeletedProjectsBeforeProxy_HappyPath_S13(t *testing.T) {
	h := freshCatalogHandlerS13(t)
	body := proxyJSON(map[string]interface{}{"before": time.Now()})
	req := httptest.NewRequest(http.MethodPost, "/system/retention/projects/purge", body)
	w := httptest.NewRecorder()
	h.PurgeDeletedProjectsBeforeProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.True(t, resp.Success)
}

// TestPurgeDeletedEnvironmentsBeforeProxy_BadBody_S13 — bad JSON → 400.
func TestPurgeDeletedEnvironmentsBeforeProxy_BadBody_S13(t *testing.T) {
	h := freshCatalogHandlerS13(t)
	req := httptest.NewRequest(http.MethodPost, "/system/retention/environments/purge", strings.NewReader("{bad"))
	w := httptest.NewRecorder()
	h.PurgeDeletedEnvironmentsBeforeProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestPurgeDeletedEnvironmentsBeforeProxy_HappyPath_S13 — valid before → 200.
func TestPurgeDeletedEnvironmentsBeforeProxy_HappyPath_S13(t *testing.T) {
	h := freshCatalogHandlerS13(t)
	body := proxyJSON(map[string]interface{}{"before": time.Now()})
	req := httptest.NewRequest(http.MethodPost, "/system/retention/environments/purge", body)
	w := httptest.NewRecorder()
	h.PurgeDeletedEnvironmentsBeforeProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.True(t, resp.Success)
}

// TestDeleteExpiredRoleGrantsProxy_BadBody_S13 — bad JSON → 400.
func TestDeleteExpiredRoleGrantsProxy_BadBody_S13(t *testing.T) {
	h := freshRBACHandlerS13(t)
	req := httptest.NewRequest(http.MethodPost, "/system/retention/role-grants/purge-expired", strings.NewReader("{bad"))
	w := httptest.NewRecorder()
	h.DeleteExpiredRoleGrantsProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestDeleteExpiredRoleGrantsProxy_HappyPath_S13 — valid before → 200.
func TestDeleteExpiredRoleGrantsProxy_HappyPath_S13(t *testing.T) {
	h := freshRBACHandlerS13(t)
	body := proxyJSON(map[string]interface{}{"before": time.Now()})
	req := httptest.NewRequest(http.MethodPost, "/system/retention/role-grants/purge-expired", body)
	w := httptest.NewRecorder()
	h.DeleteExpiredRoleGrantsProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.True(t, resp.Success)
}

// TestDeleteExpiredShareRecordsProxy_BadBody_S13 — bad JSON → 400.
func TestDeleteExpiredShareRecordsProxy_BadBody_S13(t *testing.T) {
	h := freshShareHandlerForProxyS13(t)
	req := httptest.NewRequest(http.MethodPost, "/system/retention/share-records/purge-expired", strings.NewReader("{bad"))
	w := httptest.NewRecorder()
	h.DeleteExpiredShareRecordsProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestDeleteExpiredShareRecordsProxy_HappyPath_S13 — valid before → 200.
func TestDeleteExpiredShareRecordsProxy_HappyPath_S13(t *testing.T) {
	h := freshShareHandlerForProxyS13(t)
	body := proxyJSON(map[string]interface{}{"before": time.Now()})
	req := httptest.NewRequest(http.MethodPost, "/system/retention/share-records/purge-expired", body)
	w := httptest.NewRecorder()
	h.DeleteExpiredShareRecordsProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.True(t, resp.Success)
}

// TestPurgeDeletedUsersBeforeProxy_BadBody_S13 — bad JSON → 400.
func TestPurgeDeletedUsersBeforeProxy_BadBody_S13(t *testing.T) {
	h := freshUserHandlerForProxyS13(t)
	req := httptest.NewRequest(http.MethodPost, "/system/retention/users/purge", strings.NewReader("{bad"))
	w := httptest.NewRecorder()
	h.PurgeDeletedUsersBeforeProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestPurgeDeletedUsersBeforeProxy_HappyPath_S13 — valid before → 200.
func TestPurgeDeletedUsersBeforeProxy_HappyPath_S13(t *testing.T) {
	h := freshUserHandlerForProxyS13(t)
	body := proxyJSON(map[string]interface{}{"before": time.Now()})
	req := httptest.NewRequest(http.MethodPost, "/system/retention/users/purge", body)
	w := httptest.NewRecorder()
	h.PurgeDeletedUsersBeforeProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.True(t, resp.Success)
}

// TestListUsersInStateBeforeProxy_MissingState_S13 — missing state → 400.
func TestListUsersInStateBeforeProxy_MissingState_S13(t *testing.T) {
	h := freshUserHandlerForProxyS13(t)
	req := httptest.NewRequest(http.MethodGet, "/system/retention/users/stale", nil)
	w := httptest.NewRecorder()
	h.ListUsersInStateBeforeProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.Equal(t, "INVALID_QUERY", resp.Error.Code)
}

// TestListUsersInStateBeforeProxy_MissingBefore_S13 — missing before → 400.
func TestListUsersInStateBeforeProxy_MissingBefore_S13(t *testing.T) {
	h := freshUserHandlerForProxyS13(t)
	req := httptest.NewRequest(http.MethodGet, "/system/retention/users/stale?state=active", nil)
	w := httptest.NewRecorder()
	h.ListUsersInStateBeforeProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.Equal(t, "INVALID_QUERY", resp.Error.Code)
}

// TestListUsersInStateBeforeProxy_BadBefore_S13 — non-RFC3339 before → 400.
func TestListUsersInStateBeforeProxy_BadBefore_S13(t *testing.T) {
	h := freshUserHandlerForProxyS13(t)
	req := httptest.NewRequest(http.MethodGet, "/system/retention/users/stale?state=active&before=not-a-time", nil)
	w := httptest.NewRecorder()
	h.ListUsersInStateBeforeProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.Equal(t, "INVALID_QUERY", resp.Error.Code)
}

// TestListUsersInStateBeforeProxy_HappyPath_S13 — valid params → 200.
func TestListUsersInStateBeforeProxy_HappyPath_S13(t *testing.T) {
	h := freshUserHandlerForProxyS13(t)
	before := time.Now().Format(time.RFC3339Nano)
	req := httptest.NewRequest(http.MethodGet, "http://localhost/system/retention/users/stale", nil)
	q := req.URL.Query()
	q.Set("state", "active")
	q.Set("before", before)
	req.URL.RawQuery = q.Encode()
	w := httptest.NewRecorder()
	h.ListUsersInStateBeforeProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.True(t, resp.Success)
}

// ── risk_exceptions_proxy.go ─────────────────────────────────────────────────

// TestCreateRiskExceptionProxy_BadBody_S13 — malformed JSON → 400.
func TestCreateRiskExceptionProxy_BadBody_S13(t *testing.T) {
	h := freshDashboardHandlerS13(t)
	req := httptest.NewRequest(http.MethodPost, "/system/risk-exceptions", strings.NewReader("{bad"))
	w := httptest.NewRecorder()
	h.CreateRiskExceptionProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.Equal(t, "INVALID_BODY", resp.Error.Code)
}

// TestCreateRiskExceptionProxy_MissingFields_S13 — missing title and justification → 400.
func TestCreateRiskExceptionProxy_MissingFields_S13(t *testing.T) {
	h := freshDashboardHandlerS13(t)
	body := proxyJSON(map[string]interface{}{"category": "operational"})
	req := httptest.NewRequest(http.MethodPost, "/system/risk-exceptions", body)
	w := httptest.NewRecorder()
	h.CreateRiskExceptionProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.Equal(t, "INVALID_BODY", resp.Error.Code)
}

// TestCreateRiskExceptionProxy_HappyPath_S13 — valid body → 200.
func TestCreateRiskExceptionProxy_HappyPath_S13(t *testing.T) {
	h := freshDashboardHandlerS13(t)
	body := proxyJSON(map[string]interface{}{
		"title":         "Test Exception S13",
		"category":      "operational",
		"justification": "Testing proxy handler",
		"created_by":    1,
		"expires_at":    time.Now().Add(30 * 24 * time.Hour),
	})
	req := httptest.NewRequest(http.MethodPost, "/system/risk-exceptions", body)
	w := httptest.NewRecorder()
	h.CreateRiskExceptionProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.True(t, resp.Success)
}

// TestGetRiskExceptionProxy_BadID_S13 — non-numeric id → 400.
func TestGetRiskExceptionProxy_BadID_S13(t *testing.T) {
	h := freshDashboardHandlerS13(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/system/risk-exceptions/bad", nil),
		"id", "bad",
	)
	w := httptest.NewRecorder()
	h.GetRiskExceptionProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.Equal(t, "INVALID_PARAMETER", resp.Error.Code)
}

// TestGetRiskExceptionProxy_NotFound_S13 — valid id, no such record → 404.
func TestGetRiskExceptionProxy_NotFound_S13(t *testing.T) {
	h := freshDashboardHandlerS13(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/system/risk-exceptions/9999", nil),
		"id", "9999",
	)
	w := httptest.NewRecorder()
	h.GetRiskExceptionProxy(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.Equal(t, "NOT_FOUND", resp.Error.Code)
}

// TestListRiskExceptionsProxy_DefaultFalse_S13 — no active_only param → 200 with all.
func TestListRiskExceptionsProxy_DefaultFalse_S13(t *testing.T) {
	h := freshDashboardHandlerS13(t)
	req := httptest.NewRequest(http.MethodGet, "/system/risk-exceptions", nil)
	w := httptest.NewRecorder()
	h.ListRiskExceptionsProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.True(t, resp.Success)
}

// TestListRiskExceptionsProxy_ActiveOnly_S13 — active_only=true → 200.
func TestListRiskExceptionsProxy_ActiveOnly_S13(t *testing.T) {
	h := freshDashboardHandlerS13(t)
	req := httptest.NewRequest(http.MethodGet, "/system/risk-exceptions?active_only=true", nil)
	w := httptest.NewRecorder()
	h.ListRiskExceptionsProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.True(t, resp.Success)
}

// TestUpdateRiskExceptionProxy_BadID_S13 — non-numeric id → 400.
func TestUpdateRiskExceptionProxy_BadID_S13(t *testing.T) {
	h := freshDashboardHandlerS13(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodPut, "/system/risk-exceptions/bad", strings.NewReader("{}")),
		"id", "bad",
	)
	w := httptest.NewRecorder()
	h.UpdateRiskExceptionProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.Equal(t, "INVALID_PARAMETER", resp.Error.Code)
}

// TestUpdateRiskExceptionProxy_BadBody_S13 — valid id, malformed JSON body → 400.
func TestUpdateRiskExceptionProxy_BadBody_S13(t *testing.T) {
	h := freshDashboardHandlerS13(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodPut, "/system/risk-exceptions/1", strings.NewReader("{bad")),
		"id", "1",
	)
	w := httptest.NewRecorder()
	h.UpdateRiskExceptionProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.Equal(t, "INVALID_BODY", resp.Error.Code)
}

// TestRevokeRiskExceptionProxy_BadID_S13 — non-numeric id → 400.
func TestRevokeRiskExceptionProxy_BadID_S13(t *testing.T) {
	h := freshDashboardHandlerS13(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodPut, "/system/risk-exceptions/bad/revoke", strings.NewReader("{}")),
		"id", "bad",
	)
	w := httptest.NewRecorder()
	h.RevokeRiskExceptionProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.Equal(t, "INVALID_PARAMETER", resp.Error.Code)
}

// TestRevokeRiskExceptionProxy_BadBody_S13 — valid id, malformed JSON body → 400.
func TestRevokeRiskExceptionProxy_BadBody_S13(t *testing.T) {
	h := freshDashboardHandlerS13(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodPut, "/system/risk-exceptions/1/revoke", strings.NewReader("{bad")),
		"id", "1",
	)
	w := httptest.NewRecorder()
	h.RevokeRiskExceptionProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.Equal(t, "INVALID_BODY", resp.Error.Code)
}

// TestRevokeRiskExceptionProxy_LostRace_S13 — a second revoke attempt asserting
// the same (now-stale) revoked=false state as a call that already won must
// report matched:false, not silently re-apply, proving the CAS race closes at
// the HTTP-proxy boundary too (not just LocalStorage).
func TestRevokeRiskExceptionProxy_LostRace_S13(t *testing.T) {
	h := freshDashboardHandlerS13(t)

	createBody := proxyJSON(map[string]interface{}{
		"title":         "Revoke Race S13",
		"category":      "operational",
		"justification": "Testing revoke CAS",
		"created_by":    1,
		"expires_at":    time.Now().Add(30 * 24 * time.Hour),
	})
	createReq := httptest.NewRequest(http.MethodPost, "/system/risk-exceptions", createBody)
	createW := httptest.NewRecorder()
	h.CreateRiskExceptionProxy(createW, createReq)
	require.Equal(t, http.StatusOK, createW.Code)
	createResp := decodeRemoteResp(t, createW)
	created, ok := createResp.Data.(map[string]interface{})
	require.True(t, ok)
	id := uint(created["id"].(float64))
	idStr := strconv.FormatUint(uint64(id), 10)

	revokeBody := func() *bytes.Buffer {
		return proxyJSON(map[string]interface{}{"revoked": true, "revoked_by": 2})
	}

	firstReq := withChiParam(
		httptest.NewRequest(http.MethodPut, "/system/risk-exceptions/"+idStr+"/revoke", revokeBody()),
		"id", idStr,
	)
	firstW := httptest.NewRecorder()
	h.RevokeRiskExceptionProxy(firstW, firstReq)
	assert.Equal(t, http.StatusOK, firstW.Code)
	firstResp := decodeRemoteResp(t, firstW)
	firstData, ok := firstResp.Data.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, true, firstData["matched"], "first revoke must win")

	secondReq := withChiParam(
		httptest.NewRequest(http.MethodPut, "/system/risk-exceptions/"+idStr+"/revoke", revokeBody()),
		"id", idStr,
	)
	secondW := httptest.NewRecorder()
	h.RevokeRiskExceptionProxy(secondW, secondReq)
	assert.Equal(t, http.StatusOK, secondW.Code)
	secondResp := decodeRemoteResp(t, secondW)
	secondData, ok := secondResp.Data.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, false, secondData["matched"], "second (racing) revoke must lose — already revoked")
}

// TestApproveRiskExceptionProxy_BadID_S13 — non-numeric id → 400.
func TestApproveRiskExceptionProxy_BadID_S13(t *testing.T) {
	h := freshDashboardHandlerS13(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodPut, "/system/risk-exceptions/bad/approve", strings.NewReader("{}")),
		"id", "bad",
	)
	w := httptest.NewRecorder()
	h.ApproveRiskExceptionProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.Equal(t, "INVALID_PARAMETER", resp.Error.Code)
}

// TestApproveRiskExceptionProxy_BadBody_S13 — valid id, malformed JSON body → 400.
func TestApproveRiskExceptionProxy_BadBody_S13(t *testing.T) {
	h := freshDashboardHandlerS13(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodPut, "/system/risk-exceptions/1/approve", strings.NewReader("{bad")),
		"id", "1",
	)
	w := httptest.NewRecorder()
	h.ApproveRiskExceptionProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.Equal(t, "INVALID_BODY", resp.Error.Code)
}

// TestApproveRiskExceptionProxy_HappyPath_S13 — a pending (not revoked, not
// approved) exception approves cleanly and reports matched:true.
func TestApproveRiskExceptionProxy_HappyPath_S13(t *testing.T) {
	h := freshDashboardHandlerS13(t)

	createBody := proxyJSON(map[string]interface{}{
		"title":         "Approve Happy S13",
		"category":      "operational",
		"justification": "Testing approve happy path",
		"created_by":    1,
		"expires_at":    time.Now().Add(30 * 24 * time.Hour),
	})
	createReq := httptest.NewRequest(http.MethodPost, "/system/risk-exceptions", createBody)
	createW := httptest.NewRecorder()
	h.CreateRiskExceptionProxy(createW, createReq)
	require.Equal(t, http.StatusOK, createW.Code)
	createResp := decodeRemoteResp(t, createW)
	created, ok := createResp.Data.(map[string]interface{})
	require.True(t, ok)
	id := uint(created["id"].(float64))
	idStr := strconv.FormatUint(uint64(id), 10)

	approveBody := proxyJSON(map[string]interface{}{"approved": true, "approved_by": 2})
	req := withChiParam(
		httptest.NewRequest(http.MethodPut, "/system/risk-exceptions/"+idStr+"/approve", approveBody),
		"id", idStr,
	)
	w := httptest.NewRecorder()
	h.ApproveRiskExceptionProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	resp := decodeRemoteResp(t, w)
	data, ok := resp.Data.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, true, data["matched"])
}

// ── risk_exceptions.go (non-proxy) ───────────────────────────────────────────

// TestListRiskExceptions_HappyPath_S13 — no exceptions → 200 empty list.
func TestListRiskExceptions_HappyPath_S13(t *testing.T) {
	h := freshDashboardHandlerS13(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/risk-exceptions", nil))
	w := httptest.NewRecorder()
	h.ListRiskExceptions(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestListRiskExceptions_AllParam_S13 — ?all=true → 200.
func TestListRiskExceptions_AllParam_S13(t *testing.T) {
	h := freshDashboardHandlerS13(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/risk-exceptions?all=true", nil))
	w := httptest.NewRecorder()
	h.ListRiskExceptions(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestCreateRiskException_NoUserCtx_S13 — missing user context → 401.
func TestCreateRiskException_NoUserCtx_S13(t *testing.T) {
	h := freshDashboardHandlerS13(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/risk-exceptions", strings.NewReader("{}"))
	w := httptest.NewRecorder()
	h.CreateRiskException(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestCreateRiskException_BadJSON_S13 — malformed JSON → 400.
func TestCreateRiskException_BadJSON_S13(t *testing.T) {
	h := freshDashboardHandlerS13(t)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/risk-exceptions", strings.NewReader("{bad")))
	w := httptest.NewRecorder()
	h.CreateRiskException(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestCreateRiskException_BadExpiresAt_S13 — non-RFC3339 expires_at → 400.
func TestCreateRiskException_BadExpiresAt_S13(t *testing.T) {
	h := freshDashboardHandlerS13(t)
	body := `{"title":"T","category":"op","justification":"J","expires_at":"not-a-date"}`
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/risk-exceptions", strings.NewReader(body)))
	w := httptest.NewRecorder()
	h.CreateRiskException(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestApproveRiskException_NoUserCtx_S13 — missing user context → 401.
func TestApproveRiskException_NoUserCtx_S13(t *testing.T) {
	h := freshDashboardHandlerS13(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodPost, "/api/v1/risk-exceptions/1/approve", nil),
		"id", "1",
	)
	w := httptest.NewRecorder()
	h.ApproveRiskException(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestApproveRiskException_BadID_S13 — non-numeric id → 400.
func TestApproveRiskException_BadID_S13(t *testing.T) {
	h := freshDashboardHandlerS13(t)
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPost, "/api/v1/risk-exceptions/bad/approve", nil),
		"id", "bad",
	))
	w := httptest.NewRecorder()
	h.ApproveRiskException(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestRevokeRiskException_NoUserCtx_S13 — missing user context → 401.
func TestRevokeRiskException_NoUserCtx_S13(t *testing.T) {
	h := freshDashboardHandlerS13(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodDelete, "/api/v1/risk-exceptions/1", nil),
		"id", "1",
	)
	w := httptest.NewRecorder()
	h.RevokeRiskException(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestRevokeRiskException_BadID_S13 — non-numeric id → 400.
func TestRevokeRiskException_BadID_S13(t *testing.T) {
	h := freshDashboardHandlerS13(t)
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodDelete, "/api/v1/risk-exceptions/bad", nil),
		"id", "bad",
	))
	w := httptest.NewRecorder()
	h.RevokeRiskException(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── scheduler_lock_proxy.go ───────────────────────────────────────────────────

// TestAcquireSchedulerLockProxy_BadBody_S13 — malformed JSON → 400.
func TestAcquireSchedulerLockProxy_BadBody_S13(t *testing.T) {
	h := freshAuthHandlerS13(t)
	req := httptest.NewRequest(http.MethodPost, "/system/scheduler-lock/acquire", strings.NewReader("{bad"))
	w := httptest.NewRecorder()
	h.AcquireSchedulerLockProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.Equal(t, "INVALID_BODY", resp.Error.Code)
}

// TestAcquireSchedulerLockProxy_MissingHolder_S13 — empty holder → 400.
func TestAcquireSchedulerLockProxy_MissingHolder_S13(t *testing.T) {
	h := freshAuthHandlerS13(t)
	body := proxyJSON(map[string]interface{}{"key": 1, "holder": "", "ttl_millis": 5000})
	req := httptest.NewRequest(http.MethodPost, "/system/scheduler-lock/acquire", body)
	w := httptest.NewRecorder()
	h.AcquireSchedulerLockProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.Equal(t, "INVALID_BODY", resp.Error.Code)
}

// TestAcquireSchedulerLockProxy_ZeroTTL_S13 — ttl_millis=0 → 400.
func TestAcquireSchedulerLockProxy_ZeroTTL_S13(t *testing.T) {
	h := freshAuthHandlerS13(t)
	body := proxyJSON(map[string]interface{}{"key": 1, "holder": "node-1", "ttl_millis": 0})
	req := httptest.NewRequest(http.MethodPost, "/system/scheduler-lock/acquire", body)
	w := httptest.NewRecorder()
	h.AcquireSchedulerLockProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.Equal(t, "INVALID_BODY", resp.Error.Code)
}

// TestAcquireSchedulerLockProxy_NegativeTTL_S13 — ttl_millis=-1 → 400.
func TestAcquireSchedulerLockProxy_NegativeTTL_S13(t *testing.T) {
	h := freshAuthHandlerS13(t)
	body := proxyJSON(map[string]interface{}{"key": 1, "holder": "node-1", "ttl_millis": -1})
	req := httptest.NewRequest(http.MethodPost, "/system/scheduler-lock/acquire", body)
	w := httptest.NewRecorder()
	h.AcquireSchedulerLockProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestAcquireSchedulerLockProxy_HappyPath_S13 — valid body → 200.
func TestAcquireSchedulerLockProxy_HappyPath_S13(t *testing.T) {
	h := freshAuthHandlerS13(t)
	body := proxyJSON(map[string]interface{}{"key": 42, "holder": "node-1", "ttl_millis": 30000})
	req := httptest.NewRequest(http.MethodPost, "/system/scheduler-lock/acquire", body)
	w := httptest.NewRecorder()
	h.AcquireSchedulerLockProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.True(t, resp.Success)
}

// TestReleaseSchedulerLockProxy_BadBody_S13 — malformed JSON → 400.
func TestReleaseSchedulerLockProxy_BadBody_S13(t *testing.T) {
	h := freshAuthHandlerS13(t)
	req := httptest.NewRequest(http.MethodPost, "/system/scheduler-lock/release", strings.NewReader("{bad"))
	w := httptest.NewRecorder()
	h.ReleaseSchedulerLockProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.Equal(t, "INVALID_BODY", resp.Error.Code)
}

// TestReleaseSchedulerLockProxy_MissingHolder_S13 — empty holder → 400.
func TestReleaseSchedulerLockProxy_MissingHolder_S13(t *testing.T) {
	h := freshAuthHandlerS13(t)
	body := proxyJSON(map[string]interface{}{"key": 1, "holder": ""})
	req := httptest.NewRequest(http.MethodPost, "/system/scheduler-lock/release", body)
	w := httptest.NewRecorder()
	h.ReleaseSchedulerLockProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.Equal(t, "INVALID_BODY", resp.Error.Code)
}

// TestReleaseSchedulerLockProxy_HappyPath_S13 — valid body → 200.
func TestReleaseSchedulerLockProxy_HappyPath_S13(t *testing.T) {
	h := freshAuthHandlerS13(t)
	body := proxyJSON(map[string]interface{}{"key": 42, "holder": "node-1"})
	req := httptest.NewRequest(http.MethodPost, "/system/scheduler-lock/release", body)
	w := httptest.NewRecorder()
	h.ReleaseSchedulerLockProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.True(t, resp.Success)
}

// TestAcquireSchedulerLockProxy_StorageError_S13 — a broken storage (no
// scheduler_lock_leases table) must return 500 with a STORAGE_ERROR code.
func TestAcquireSchedulerLockProxy_StorageError_S13(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h := NewAuthHandler(cs, false)
	// Break the storage so TryAcquireSchedulerLock fails.
	require.NoError(t, db.Exec("DROP TABLE IF EXISTS scheduler_lock_leases").Error)
	body := proxyJSON(map[string]interface{}{"key": 1, "holder": "node-1", "ttl_millis": 5000})
	req := httptest.NewRequest(http.MethodPost, "/system/scheduler-lock/acquire", body)
	w := httptest.NewRecorder()
	h.AcquireSchedulerLockProxy(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.Equal(t, "STORAGE_ERROR", resp.Error.Code)
}

// TestReleaseSchedulerLockProxy_StorageError_S13 — a broken storage (no
// scheduler_lock_leases table) must return 500 with a STORAGE_ERROR code.
func TestReleaseSchedulerLockProxy_StorageError_S13(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h := NewAuthHandler(cs, false)
	// Break the storage so ReleaseSchedulerLock fails.
	require.NoError(t, db.Exec("DROP TABLE IF EXISTS scheduler_lock_leases").Error)
	body := proxyJSON(map[string]interface{}{"key": 1, "holder": "node-1"})
	req := httptest.NewRequest(http.MethodPost, "/system/scheduler-lock/release", body)
	w := httptest.NewRecorder()
	h.ReleaseSchedulerLockProxy(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.Equal(t, "STORAGE_ERROR", resp.Error.Code)
}

// ── setup_tokens_proxy.go ─────────────────────────────────────────────────────

// TestCreateSetupTokenProxy_BadBody_S13 — malformed JSON → 400.
func TestCreateSetupTokenProxy_BadBody_S13(t *testing.T) {
	h := freshAuthHandlerS13(t)
	req := httptest.NewRequest(http.MethodPost, "/system/setup-tokens", strings.NewReader("{bad"))
	w := httptest.NewRecorder()
	h.CreateSetupTokenProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.Equal(t, "INVALID_BODY", resp.Error.Code)
}

// TestCreateSetupTokenProxy_MissingFields_S13 — missing token_hash → 400.
func TestCreateSetupTokenProxy_MissingFields_S13(t *testing.T) {
	h := freshAuthHandlerS13(t)
	body := proxyJSON(map[string]interface{}{
		"purpose":       "invite",
		"subject_email": "user@example.com",
		// token_hash missing
	})
	req := httptest.NewRequest(http.MethodPost, "/system/setup-tokens", body)
	w := httptest.NewRecorder()
	h.CreateSetupTokenProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.Equal(t, "INVALID_BODY", resp.Error.Code)
}

// TestCreateSetupTokenProxy_MissingEmail_S13 — missing subject_email → 400.
func TestCreateSetupTokenProxy_MissingEmail_S13(t *testing.T) {
	h := freshAuthHandlerS13(t)
	body := proxyJSON(map[string]interface{}{
		"token_hash": "abc123",
		"purpose":    "invite",
		// subject_email missing
	})
	req := httptest.NewRequest(http.MethodPost, "/system/setup-tokens", body)
	w := httptest.NewRecorder()
	h.CreateSetupTokenProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestCreateSetupTokenProxy_HappyPath_S13 — valid body → 200.
func TestCreateSetupTokenProxy_HappyPath_S13(t *testing.T) {
	h := freshAuthHandlerS13(t)
	body := proxyJSON(map[string]interface{}{
		"token_hash":    "deadbeef1234567890abcdef",
		"purpose":       "invite",
		"subject_email": "newuser@example.com",
		"state":         "active",
		"expires_at":    time.Now().Add(24 * time.Hour),
		"created_by":    1,
	})
	req := httptest.NewRequest(http.MethodPost, "/system/setup-tokens", body)
	w := httptest.NewRecorder()
	h.CreateSetupTokenProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.True(t, resp.Success)
}

// TestGetSetupTokenByHashProxy_EmptyHash_S13 — empty hash → 400.
func TestGetSetupTokenByHashProxy_EmptyHash_S13(t *testing.T) {
	h := freshAuthHandlerS13(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/system/setup-tokens/by-hash/", nil),
		"hash", "",
	)
	w := httptest.NewRecorder()
	h.GetSetupTokenByHashProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.Equal(t, "INVALID_PARAMETER", resp.Error.Code)
}

// TestGetSetupTokenByHashProxy_NotFound_S13 — valid hash, not in DB → 404.
func TestGetSetupTokenByHashProxy_NotFound_S13(t *testing.T) {
	h := freshAuthHandlerS13(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/system/setup-tokens/by-hash/nonexistenthash", nil),
		"hash", "nonexistenthash",
	)
	w := httptest.NewRecorder()
	h.GetSetupTokenByHashProxy(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.Equal(t, "NOT_FOUND", resp.Error.Code)
}

// TestSupersedeSetupTokensProxy_BadBody_S13 — malformed JSON → 400.
func TestSupersedeSetupTokensProxy_BadBody_S13(t *testing.T) {
	h := freshAuthHandlerS13(t)
	req := httptest.NewRequest(http.MethodPost, "/system/setup-tokens/supersede", strings.NewReader("{bad"))
	w := httptest.NewRecorder()
	h.SupersedeSetupTokensProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.Equal(t, "INVALID_BODY", resp.Error.Code)
}

// TestSupersedeSetupTokensProxy_MissingFields_S13 — missing purpose → 400.
func TestSupersedeSetupTokensProxy_MissingFields_S13(t *testing.T) {
	h := freshAuthHandlerS13(t)
	body := proxyJSON(map[string]interface{}{"subject_email": "user@example.com"})
	req := httptest.NewRequest(http.MethodPost, "/system/setup-tokens/supersede", body)
	w := httptest.NewRecorder()
	h.SupersedeSetupTokensProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestSupersedeSetupTokensProxy_HappyPath_S13 — valid body (no active tokens to supersede) → 200.
func TestSupersedeSetupTokensProxy_HappyPath_S13(t *testing.T) {
	h := freshAuthHandlerS13(t)
	body := proxyJSON(map[string]interface{}{"purpose": "invite", "subject_email": "user@example.com"})
	req := httptest.NewRequest(http.MethodPost, "/system/setup-tokens/supersede", body)
	w := httptest.NewRecorder()
	h.SupersedeSetupTokensProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.True(t, resp.Success)
}

// TestConsumeSetupTokenProxy_BadID_S13 — non-numeric id → 400.
func TestConsumeSetupTokenProxy_BadID_S13(t *testing.T) {
	h := freshAuthHandlerS13(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodPost, "/system/setup-tokens/bad/consume", strings.NewReader("{}")),
		"id", "bad",
	)
	w := httptest.NewRecorder()
	h.ConsumeSetupTokenProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.Equal(t, "INVALID_PARAMETER", resp.Error.Code)
}

// TestConsumeSetupTokenProxy_BadBody_S13 — malformed JSON body → 400.
func TestConsumeSetupTokenProxy_BadBody_S13(t *testing.T) {
	h := freshAuthHandlerS13(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodPost, "/system/setup-tokens/1/consume", strings.NewReader("{bad")),
		"id", "1",
	)
	w := httptest.NewRecorder()
	h.ConsumeSetupTokenProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.Equal(t, "INVALID_BODY", resp.Error.Code)
}

// TestConsumeSetupTokenProxy_ZeroConsumedAt_S13 — zero consumed_at → 400.
func TestConsumeSetupTokenProxy_ZeroConsumedAt_S13(t *testing.T) {
	h := freshAuthHandlerS13(t)
	body := proxyJSON(map[string]interface{}{"consumed_at": time.Time{}})
	req := withChiParam(
		httptest.NewRequest(http.MethodPost, "/system/setup-tokens/1/consume", body),
		"id", "1",
	)
	w := httptest.NewRecorder()
	h.ConsumeSetupTokenProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.Equal(t, "INVALID_BODY", resp.Error.Code)
}

// TestConsumeSetupTokenProxy_HappyPath_S13 — valid consume on non-existent token → false (no match).
func TestConsumeSetupTokenProxy_HappyPath_S13(t *testing.T) {
	h := freshAuthHandlerS13(t)
	body := proxyJSON(map[string]interface{}{"consumed_at": time.Now()})
	req := withChiParam(
		httptest.NewRequest(http.MethodPost, "/system/setup-tokens/9999/consume", body),
		"id", "9999",
	)
	w := httptest.NewRecorder()
	h.ConsumeSetupTokenProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.True(t, resp.Success)
}

// TestExpireSetupTokenProxy_BadID_S13 — non-numeric id → 400.
func TestExpireSetupTokenProxy_BadID_S13(t *testing.T) {
	h := freshAuthHandlerS13(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodPost, "/system/setup-tokens/bad/expire", nil),
		"id", "bad",
	)
	w := httptest.NewRecorder()
	h.ExpireSetupTokenProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.Equal(t, "INVALID_PARAMETER", resp.Error.Code)
}

// TestExpireSetupTokenProxy_HappyPath_S13 — valid id (token doesn't exist, no-op) → 200.
func TestExpireSetupTokenProxy_HappyPath_S13(t *testing.T) {
	h := freshAuthHandlerS13(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodPost, "/system/setup-tokens/9999/expire", nil),
		"id", "9999",
	)
	w := httptest.NewRecorder()
	h.ExpireSetupTokenProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.True(t, resp.Success)
}

// TestCountSetupTokensSinceProxy_MissingParams_S13 — all params missing → 400.
func TestCountSetupTokensSinceProxy_MissingParams_S13(t *testing.T) {
	h := freshAuthHandlerS13(t)
	req := httptest.NewRequest(http.MethodGet, "/system/setup-tokens/count", nil)
	w := httptest.NewRecorder()
	h.CountSetupTokensSinceProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.Equal(t, "INVALID_QUERY", resp.Error.Code)
}

// TestCountSetupTokensSinceProxy_BadSince_S13 — invalid since timestamp → 400.
func TestCountSetupTokensSinceProxy_BadSince_S13(t *testing.T) {
	h := freshAuthHandlerS13(t)
	req := httptest.NewRequest(http.MethodGet, "http://localhost/system/setup-tokens/count", nil)
	q := req.URL.Query()
	q.Set("purpose", "invite")
	q.Set("subject_email", "u@x.com")
	q.Set("since", "not-a-time")
	req.URL.RawQuery = q.Encode()
	w := httptest.NewRecorder()
	h.CountSetupTokensSinceProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.Equal(t, "INVALID_QUERY", resp.Error.Code)
}

// TestCountSetupTokensSinceProxy_HappyPath_S13 — valid params → 200.
func TestCountSetupTokensSinceProxy_HappyPath_S13(t *testing.T) {
	h := freshAuthHandlerS13(t)
	since := time.Now().Add(-1 * time.Hour).Format(time.RFC3339Nano)
	// Use net/url to build the query so special chars (@ in email, + in RFC3339Nano) are
	// properly percent-encoded and httptest.NewRequest can parse them correctly.
	u := "http://localhost/system/setup-tokens/count"
	req := httptest.NewRequest(http.MethodGet, u, nil)
	q := req.URL.Query()
	q.Set("purpose", "invite")
	q.Set("subject_email", "u@x.com")
	q.Set("since", since)
	req.URL.RawQuery = q.Encode()
	w := httptest.NewRecorder()
	h.CountSetupTokensSinceProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.True(t, resp.Success)
}

// ── sso_state_proxy.go ────────────────────────────────────────────────────────

// TestCreateSSOLoginStateProxy_BadBody_S13 — malformed JSON → 400.
func TestCreateSSOLoginStateProxy_BadBody_S13(t *testing.T) {
	h := freshAuthHandlerS13(t)
	req := httptest.NewRequest(http.MethodPost, "/system/sso-state", strings.NewReader("{bad"))
	w := httptest.NewRecorder()
	h.CreateSSOLoginStateProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.Equal(t, "INVALID_BODY", resp.Error.Code)
}

// TestCreateSSOLoginStateProxy_MissingFields_S13 — missing state/nonce/provider → 400.
func TestCreateSSOLoginStateProxy_MissingFields_S13(t *testing.T) {
	h := freshAuthHandlerS13(t)
	body := proxyJSON(map[string]interface{}{"state": "abc"}) // missing nonce, provider
	req := httptest.NewRequest(http.MethodPost, "/system/sso-state", body)
	w := httptest.NewRecorder()
	h.CreateSSOLoginStateProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.Equal(t, "INVALID_BODY", resp.Error.Code)
}

// TestCreateSSOLoginStateProxy_HappyPath_S13 — valid body → 200.
func TestCreateSSOLoginStateProxy_HappyPath_S13(t *testing.T) {
	h := freshAuthHandlerS13(t)
	body := proxyJSON(map[string]interface{}{
		"state":      "random-state-token-s13",
		"nonce":      "random-nonce-s13",
		"provider":   "oidc-corp",
		"return_to":  "/dashboard",
		"expires_at": time.Now().Add(5 * time.Minute),
	})
	req := httptest.NewRequest(http.MethodPost, "/system/sso-state", body)
	w := httptest.NewRecorder()
	h.CreateSSOLoginStateProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.True(t, resp.Success)
}

// TestConsumeSSOLoginStateProxy_BadBody_S13 — malformed JSON → 400.
func TestConsumeSSOLoginStateProxy_BadBody_S13(t *testing.T) {
	h := freshAuthHandlerS13(t)
	req := httptest.NewRequest(http.MethodPost, "/system/sso-state/consume", strings.NewReader("{bad"))
	w := httptest.NewRecorder()
	h.ConsumeSSOLoginStateProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.Equal(t, "INVALID_BODY", resp.Error.Code)
}

// TestConsumeSSOLoginStateProxy_MissingState_S13 — empty state → 400.
func TestConsumeSSOLoginStateProxy_MissingState_S13(t *testing.T) {
	h := freshAuthHandlerS13(t)
	body := proxyJSON(map[string]interface{}{"state": ""})
	req := httptest.NewRequest(http.MethodPost, "/system/sso-state/consume", body)
	w := httptest.NewRecorder()
	h.ConsumeSSOLoginStateProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.Equal(t, "INVALID_BODY", resp.Error.Code)
}

// TestConsumeSSOLoginStateProxy_NotFound_S13 — valid state, not in DB → 404.
func TestConsumeSSOLoginStateProxy_NotFound_S13(t *testing.T) {
	h := freshAuthHandlerS13(t)
	body := proxyJSON(map[string]interface{}{"state": "nonexistent-state-xyz"})
	req := httptest.NewRequest(http.MethodPost, "/system/sso-state/consume", body)
	w := httptest.NewRecorder()
	h.ConsumeSSOLoginStateProxy(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.Equal(t, "NOT_FOUND", resp.Error.Code)
}
