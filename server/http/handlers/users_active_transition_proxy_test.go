// users_active_transition_proxy_test.go — tests for
// users_active_transition_proxy.go: UpdateUserIfActiveStateMatchesProxy.
package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestUpdateUserIfActiveStateMatchesProxy_BadID — non-numeric id → 400.
func TestUpdateUserIfActiveStateMatchesProxy_BadID(t *testing.T) {
	h := freshUserHandlerForProxyS13(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodPut, "/system/users/bad/active-transition", strings.NewReader("{}")),
		"id", "bad",
	)
	w := httptest.NewRecorder()
	h.UpdateUserIfActiveStateMatchesProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.Equal(t, "INVALID_PARAMETER", resp.Error.Code)
}

// TestUpdateUserIfActiveStateMatchesProxy_BadBody — malformed JSON → 400.
func TestUpdateUserIfActiveStateMatchesProxy_BadBody(t *testing.T) {
	h := freshUserHandlerForProxyS13(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodPut, "/system/users/1/active-transition", strings.NewReader("{bad")),
		"id", "1",
	)
	w := httptest.NewRecorder()
	h.UpdateUserIfActiveStateMatchesProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.Equal(t, "INVALID_BODY", resp.Error.Code)
}

// TestUpdateUserIfActiveStateMatchesProxy_HappyPath — a conditional write
// against the seeded admin user (id=1, IsActive=true) with a matching
// from_active succeeds and reports matched:true.
func TestUpdateUserIfActiveStateMatchesProxy_HappyPath(t *testing.T) {
	cs, _ := freshCoreS12WithAdmin(t)
	h, err := NewUserHandler(cs)
	require.NoError(t, err)

	body := proxyJSON(map[string]interface{}{
		"username":     "testuser_s12",
		"email":        "testuser_s12@example.com",
		"display_name": "Deactivated Admin",
		"active":       false,
		"from_active":  true,
	})
	req := withChiParam(
		httptest.NewRequest(http.MethodPut, "/system/users/1/active-transition", body),
		"id", "1",
	)
	w := httptest.NewRecorder()
	h.UpdateUserIfActiveStateMatchesProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.True(t, resp.Success)
	data, ok := resp.Data.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, true, data["matched"])

	updated, err := cs.Storage().GetUser(req.Context(), 1)
	require.NoError(t, err)
	assert.False(t, updated.IsActive)
	assert.Equal(t, "Deactivated Admin", updated.DisplayName)
}

// TestUpdateUserIfActiveStateMatchesProxy_LostRace — a second conditional
// write asserting the SAME (now-stale) from_active as a call that already won
// must report matched:false, not silently re-apply over the winner (proves
// the CAS race is closed at the HTTP-proxy boundary too, not just LocalStorage).
func TestUpdateUserIfActiveStateMatchesProxy_LostRace(t *testing.T) {
	cs, _ := freshCoreS12WithAdmin(t)
	h, err := NewUserHandler(cs)
	require.NoError(t, err)

	firstBody := proxyJSON(map[string]interface{}{
		"username":     "testuser_s12",
		"email":        "testuser_s12@example.com",
		"display_name": "First Winner",
		"active":       false,
		"from_active":  true,
	})
	firstReq := withChiParam(
		httptest.NewRequest(http.MethodPut, "/system/users/1/active-transition", firstBody),
		"id", "1",
	)
	w1 := httptest.NewRecorder()
	h.UpdateUserIfActiveStateMatchesProxy(w1, firstReq)
	assert.Equal(t, http.StatusOK, w1.Code)
	resp1 := decodeRemoteResp(t, w1)
	data1, ok := resp1.Data.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, true, data1["matched"], "first call must win")

	// Second call still asserts from_active=true (stale — the row is now false).
	secondBody := proxyJSON(map[string]interface{}{
		"username":     "testuser_s12",
		"email":        "testuser_s12@example.com",
		"display_name": "Should Not Persist",
		"active":       false,
		"from_active":  true,
	})
	secondReq := withChiParam(
		httptest.NewRequest(http.MethodPut, "/system/users/1/active-transition", secondBody),
		"id", "1",
	)
	w2 := httptest.NewRecorder()
	h.UpdateUserIfActiveStateMatchesProxy(w2, secondReq)
	assert.Equal(t, http.StatusOK, w2.Code)
	resp2 := decodeRemoteResp(t, w2)
	data2, ok := resp2.Data.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, false, data2["matched"], "second (racing) call must lose")

	updated, err := cs.Storage().GetUser(secondReq.Context(), 1)
	require.NoError(t, err)
	assert.NotEqual(t, "Should Not Persist", updated.DisplayName)
}
