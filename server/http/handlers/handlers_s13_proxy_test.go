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
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	coreStorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
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

// TestRecordLoginAttemptProxy_RejectsNonIPKey_S13 is the G80 documented-
// exception fix's regression test (2026-08-25): a caller-supplied "ip" that
// isn't a real IP, or a known rate-limit namespace prefix followed by one,
// must be refused rather than persisted verbatim — the field used to accept
// ANY string with no validation at all.
func TestRecordLoginAttemptProxy_RejectsNonIPKey_S13(t *testing.T) {
	h := freshAuthHandlerS13(t)
	body := proxyJSON(map[string]interface{}{"ip": "not-an-ip-or-known-prefix", "at": time.Now()})
	req := httptest.NewRequest(http.MethodPost, "/system/login-attempts", body)
	w := httptest.NewRecorder()
	h.RecordLoginAttemptProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.False(t, resp.Success)
}

// TestRecordLoginAttemptProxy_AllowsKnownPrefixes_S13 is
// TestRecordLoginAttemptProxy_RejectsNonIPKey_S13's companion control: the two
// namespace prefixes RecordPasswordResetAttempt/RecordSSOBeginAttempt
// legitimately produce ("pwreset:"/"sso:") followed by a real IP must still
// be accepted — the fix must not turn into a blanket rejection of anything
// but a bare IP.
func TestRecordLoginAttemptProxy_AllowsKnownPrefixes_S13(t *testing.T) {
	for _, ip := range []string{"pwreset:203.0.113.9", "sso:203.0.113.9", "203.0.113.9:54321"} {
		h := freshAuthHandlerS13(t)
		body := proxyJSON(map[string]interface{}{"ip": ip, "at": time.Now()})
		req := httptest.NewRequest(http.MethodPost, "/system/login-attempts", body)
		w := httptest.NewRecorder()
		h.RecordLoginAttemptProxy(w, req)
		assert.Equal(t, http.StatusOK, w.Code, "ip=%q must still be accepted", ip)
	}
}

// TestRecordLoginAttemptProxy_RejectsFutureTimestamp_S13 is the fix's second
// regression test: before it, a far-future `at` created a row
// PruneLoginAttempts (clamped to now-LoginWindow) could NEVER become eligible
// to delete — a permanent, unrecoverable lockout of whatever key it targets.
// Independent verification session (2026-08-25): an earlier version of this
// fix silently CLAMPED `at` to now instead of rejecting it outright, which is
// untestable as a rejection (a passing "the row landed near now" assertion
// can't distinguish "correctly clamped" from "accepted verbatim and happened
// to look right"). The fix now returns a hard 400 and persists NOTHING —
// confirmed here by asserting zero rows exist for the key at all, not just
// that none of them are far in the future.
func TestRecordLoginAttemptProxy_RejectsFutureTimestamp_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewAuthHandler(cs, false)
	farFuture := time.Now().AddDate(100, 0, 0)
	body := proxyJSON(map[string]interface{}{"ip": "198.51.100.42", "at": farFuture})
	req := httptest.NewRequest(http.MethodPost, "/system/login-attempts", body)
	w := httptest.NewRecorder()
	h.RecordLoginAttemptProxy(w, req)
	require.Equal(t, http.StatusBadRequest, w.Code,
		"CEILING VIOLATED: a future-dated login attempt must be rejected outright (400), not silently clamped and persisted")

	n, err := cs.Storage().CountRecentLoginAttempts(context.Background(), "198.51.100.42", time.Now().Add(-time.Hour))
	require.NoError(t, err)
	assert.Equal(t, int64(0), n, "a rejected attempt must not be persisted at all, clamped or otherwise")
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
		"password_hash": "$2a$10$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0",
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
		"category":      "other",
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

// UpdateRiskExceptionProxy was removed (#G79) — it accepted a client-supplied
// full row with no auth/business-logic decision and had no legitimate caller.
// See risk_exceptions_proxy.go's removal comment. The tests that used to live
// here (TestUpdateRiskExceptionProxy_BadID_S13/BadBody_S13) are gone with it.

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

// RevokeRiskExceptionProxy no longer decodes a request body at all (#G79) —
// core.KeyorixCore.RevokeRiskException takes only actorID/id and resolves the
// rest itself — so "malformed JSON body" is no longer a meaningful input;
// TestRevokeRiskExceptionProxy_BadBody_S13 is gone with that body decode.

// TestRevokeRiskExceptionProxy_LostRace_S13 — a second revoke attempt against
// an already-revoked exception is a normal outcome on this wire contract, not
// a server error (#1531: RevokeRiskExceptionProxy used to turn
// core.KeyorixCore.RevokeRiskException's already-revoked precondition error
// into a 500 STORAGE_ERROR; it now recognizes
// core.ErrRiskExceptionAlreadyRevoked via errors.Is and reports a clean
// matched:false 200, matching every other conditional-transition wire method
// in this package). Verified red against the pre-fix handler (500) before
// this assertion was written to expect 200/matched:false.
func TestRevokeRiskExceptionProxy_LostRace_S13(t *testing.T) {
	h := freshDashboardHandlerS13(t)

	createBody := proxyJSON(map[string]interface{}{
		"title":         "Revoke Race S13",
		"category":      "other",
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

	firstReq := withChiParam(httptest.NewRequest(http.MethodPut, "/system/risk-exceptions/"+idStr+"/revoke", nil), "id", idStr)
	firstW := httptest.NewRecorder()
	h.RevokeRiskExceptionProxy(firstW, firstReq)
	assert.Equal(t, http.StatusOK, firstW.Code)
	firstResp := decodeRemoteResp(t, firstW)
	firstData, ok := firstResp.Data.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, true, firstData["matched"], "first revoke must win")

	secondReq := withChiParam(httptest.NewRequest(http.MethodPut, "/system/risk-exceptions/"+idStr+"/revoke", nil), "id", idStr)
	secondW := httptest.NewRecorder()
	h.RevokeRiskExceptionProxy(secondW, secondReq)
	assert.Equal(t, http.StatusOK, secondW.Code, "a lost race is a normal outcome, not a server error")
	secondResp := decodeRemoteResp(t, secondW)
	secondData, ok := secondResp.Data.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, false, secondData["matched"], "second (racing) revoke must report matched:false, not win or error")
}

// TestApproveRiskExceptionProxy_LostRace_S13 is the ApproveRiskExceptionProxy
// counterpart — see TestRevokeRiskExceptionProxy_LostRace_S13's doc comment.
// A second approve attempt against an already-approved exception must report
// matched:false, not a 500.
func TestApproveRiskExceptionProxy_LostRace_S13(t *testing.T) {
	h := freshDashboardHandlerS13(t)

	createBody := proxyJSON(map[string]interface{}{
		"title":         "Approve Race S13",
		"category":      "other",
		"justification": "Testing approve CAS",
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

	// CreateRiskExceptionProxy's create request above is a bare httptest
	// request (no withUserCtx), so actorID(r)==0 makes creator 0 — approve as
	// a DIFFERENT actor via withUserCtx (mirrors TestApproveRiskExceptionProxy_HappyPath_S13),
	// satisfying dual control's self-approval check.
	firstReq := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPut, "/system/risk-exceptions/"+idStr+"/approve", nil), "id", idStr))
	firstW := httptest.NewRecorder()
	h.ApproveRiskExceptionProxy(firstW, firstReq)
	require.Equal(t, http.StatusOK, firstW.Code)
	firstResp := decodeRemoteResp(t, firstW)
	firstData, ok := firstResp.Data.(map[string]interface{})
	require.True(t, ok)
	require.Equal(t, true, firstData["matched"], "first approve must win")

	secondReq := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPut, "/system/risk-exceptions/"+idStr+"/approve", nil), "id", idStr))
	secondW := httptest.NewRecorder()
	h.ApproveRiskExceptionProxy(secondW, secondReq)
	assert.Equal(t, http.StatusOK, secondW.Code, "a lost race is a normal outcome, not a server error")
	secondResp := decodeRemoteResp(t, secondW)
	secondData, ok := secondResp.Data.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, false, secondData["matched"], "second (racing) approve must report matched:false, not win or error")
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

// ApproveRiskExceptionProxy no longer decodes a request body at all (#G79) —
// core.KeyorixCore.ApproveRiskException takes only actorID/id and resolves
// the rest itself — so "malformed JSON body" is no longer a meaningful
// input; TestApproveRiskExceptionProxy_BadBody_S13 is gone with that body
// decode.

// TestApproveRiskExceptionProxy_HappyPath_S13 — a pending (not revoked, not
// approved) exception approves cleanly and reports matched:true. The approving
// caller must be a DIFFERENT actor than the creator (dual control,
// core.ApproveRiskException) — the create call below runs with no user
// context (actorID 0), so the approve call uses withUserCtx (actorID 1) to
// satisfy that.
func TestApproveRiskExceptionProxy_HappyPath_S13(t *testing.T) {
	h := freshDashboardHandlerS13(t)

	createBody := proxyJSON(map[string]interface{}{
		"title":         "Approve Happy S13",
		"category":      "other",
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

	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPut, "/system/risk-exceptions/"+idStr+"/approve", nil),
		"id", idStr,
	))
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

// TestCreateSetupTokenProxy_HappyPath_S13 — valid body referencing a real,
// matching-email user (account_setup requires subject_user_id, per #G79) → 200.
func TestCreateSetupTokenProxy_HappyPath_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewAuthHandler(cs, false)
	user, err := cs.Storage().CreateUser(context.Background(), &models.User{
		Username: "newuser_s13", Email: "newuser@example.com", PasswordHash: "x",
	})
	require.NoError(t, err)
	// Minting a setup token requires users.write (ADR-085); seed a caller who
	// holds it via the system_admin adminRoleNames bypass (internal/core/authz.go).
	adminRole, err := cs.Storage().CreateRole(context.Background(), &models.Role{Name: "system_admin", Description: "admin"})
	require.NoError(t, err)
	admin, err := cs.Storage().CreateUser(context.Background(), &models.User{
		Username: "admin_s13", Email: "admin_s13@example.com", PasswordHash: "x",
	})
	require.NoError(t, err)
	require.NoError(t, cs.Storage().AssignRole(context.Background(), admin.ID, adminRole.ID, coreStorage.Scope{}))
	body := proxyJSON(map[string]interface{}{
		"token_hash":      "deadbeef1234567890abcdef",
		"purpose":         "account_setup",
		"subject_email":   "newuser@example.com",
		"subject_user_id": user.ID,
		"state":           "active",
		"expires_at":      time.Now().Add(24 * time.Hour),
		"created_by":      1,
	})
	req := withUserCtxID(httptest.NewRequest(http.MethodPost, "/system/setup-tokens", body), admin.ID, "admin_s13")
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

// ConsumeSetupTokenProxy tests deleted -- #1579 liveness sweep, handler
// removed (no live caller in either topology).

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
