// users_credentials_proxy_test.go — coverage for
// RevokeAllPersonalAccessTokensForUserProxy and DeleteSessionsForUserExceptProxy
// (users_credentials_proxy.go), previously untested (0% coverage). Unlike most
// /system proxies, these DO enforce an in-handler ceiling
// (requireUserCredentialsRevokeAuthority — users.write authority), so each gets
// both an authorized and an unauthorized case.
package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── RevokeAllPersonalAccessTokensForUserProxy ───────────────────────────────

func TestRevokeAllPersonalAccessTokensForUserProxy_InvalidID(t *testing.T) {
	cs, _ := freshCoreS12WithAdmin(t)
	h, err := NewUserHandler(cs)
	require.NoError(t, err)
	r := withChiParam(httptest.NewRequest(http.MethodPost, "/api/v1/system/users/abc/personal-access-tokens/revoke-all", nil), "id", "abc")
	r = withUserCtx(r)
	w := httptest.NewRecorder()
	h.RevokeAllPersonalAccessTokensForUserProxy(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRevokeAllPersonalAccessTokensForUserProxy_Unauthorized(t *testing.T) {
	cs, _ := freshCoreS12WithAdmin(t)
	h, err := NewUserHandler(cs)
	require.NoError(t, err)
	// No user context at all: resolves to actorType "user", actorID 0 — no
	// roles, requireUserCredentialsRevokeAuthority denies.
	r := withChiParam(httptest.NewRequest(http.MethodPost, "/api/v1/system/users/1/personal-access-tokens/revoke-all", nil), "id", "1")
	w := httptest.NewRecorder()
	h.RevokeAllPersonalAccessTokensForUserProxy(w, r)
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "PERMISSION_DENIED")
}

func TestRevokeAllPersonalAccessTokensForUserProxy_StorageError(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h, err := NewUserHandler(cs)
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())

	r := withChiParam(httptest.NewRequest(http.MethodPost, "/api/v1/system/users/1/personal-access-tokens/revoke-all", nil), "id", "1")
	r = withUserCtx(r)
	w := httptest.NewRecorder()
	h.RevokeAllPersonalAccessTokensForUserProxy(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestRevokeAllPersonalAccessTokensForUserProxy_Success(t *testing.T) {
	cs, _ := freshCoreS12WithAdmin(t)
	h, err := NewUserHandler(cs)
	require.NoError(t, err)
	r := withChiParam(httptest.NewRequest(http.MethodPost, "/api/v1/system/users/1/personal-access-tokens/revoke-all", nil), "id", "1")
	r = withUserCtx(r)
	w := httptest.NewRecorder()
	h.RevokeAllPersonalAccessTokensForUserProxy(w, r)
	assert.Equal(t, http.StatusOK, w.Code)

	var resp struct {
		Success bool `json:"success"`
		Data    struct {
			Hashes []string `json:"hashes"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.True(t, resp.Success)
}

// ── DeleteSessionsForUserExceptProxy ────────────────────────────────────────

func TestDeleteSessionsForUserExceptProxy_InvalidID(t *testing.T) {
	cs, _ := freshCoreS12WithAdmin(t)
	h, err := NewUserHandler(cs)
	require.NoError(t, err)
	r := withChiParam(httptest.NewRequest(http.MethodPost, "/api/v1/system/users/abc/sessions/delete-except", nil), "id", "abc")
	r = withUserCtx(r)
	w := httptest.NewRecorder()
	h.DeleteSessionsForUserExceptProxy(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDeleteSessionsForUserExceptProxy_BadJSON(t *testing.T) {
	cs, _ := freshCoreS12WithAdmin(t)
	h, err := NewUserHandler(cs)
	require.NoError(t, err)
	r := withChiParam(httptest.NewRequest(http.MethodPost, "/api/v1/system/users/1/sessions/delete-except",
		bytes.NewReader([]byte("{bad json}"))), "id", "1")
	r = withUserCtx(r)
	w := httptest.NewRecorder()
	h.DeleteSessionsForUserExceptProxy(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDeleteSessionsForUserExceptProxy_Unauthorized(t *testing.T) {
	cs, _ := freshCoreS12WithAdmin(t)
	h, err := NewUserHandler(cs)
	require.NoError(t, err)
	body, _ := json.Marshal(map[string]interface{}{"except_session_id": 0})
	r := withChiParam(httptest.NewRequest(http.MethodPost, "/api/v1/system/users/1/sessions/delete-except",
		bytes.NewReader(body)), "id", "1")
	w := httptest.NewRecorder()
	h.DeleteSessionsForUserExceptProxy(w, r)
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "PERMISSION_DENIED")
}

func TestDeleteSessionsForUserExceptProxy_StorageError(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h, err := NewUserHandler(cs)
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())

	body, _ := json.Marshal(map[string]interface{}{"except_session_id": 0})
	r := withChiParam(httptest.NewRequest(http.MethodPost, "/api/v1/system/users/1/sessions/delete-except",
		bytes.NewReader(body)), "id", "1")
	r = withUserCtx(r)
	w := httptest.NewRecorder()
	h.DeleteSessionsForUserExceptProxy(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestDeleteSessionsForUserExceptProxy_Success(t *testing.T) {
	cs, _ := freshCoreS12WithAdmin(t)
	h, err := NewUserHandler(cs)
	require.NoError(t, err)
	body, _ := json.Marshal(map[string]interface{}{"except_session_id": 0})
	r := withChiParam(httptest.NewRequest(http.MethodPost, "/api/v1/system/users/1/sessions/delete-except",
		bytes.NewReader(body)), "id", "1")
	r = withUserCtx(r)
	w := httptest.NewRecorder()
	h.DeleteSessionsForUserExceptProxy(w, r)
	assert.Equal(t, http.StatusOK, w.Code)

	var resp struct {
		Success bool `json:"success"`
		Data    struct {
			Deleted bool `json:"deleted"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.True(t, resp.Success)
	assert.True(t, resp.Data.Deleted)
}
