// secrets_status_proxy_test.go — tests for secrets_status_proxy.go:
// TransitionSecretStatusProxy.
package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// seedSecretForProxyS13 creates a minimal project/environment/secret via the
// core's own storage layer — TransitionSecretStatusProxy is a raw storage
// passthrough (no project-membership/RBAC gate, see the handler's own doc
// comment), so no user/role scaffolding is needed, unlike the heavier
// freshSecretHandlerS14 setup used by handlers exercising the human-facing,
// permission-checked secret routes.
func seedSecretForProxyS13(t *testing.T, h *SecretHandler) *models.SecretNode {
	t.Helper()
	ctx := context.Background()
	st := h.coreService.Storage()
	proj, err := st.CreateProject(ctx, &models.Project{Name: "proj-status-s13"})
	require.NoError(t, err)
	env, err := st.CreateEnvironment(ctx, &models.Environment{Name: "env-status-s13", ProjectID: proj.ID})
	require.NoError(t, err)
	secret, err := st.CreateSecret(ctx, &models.SecretNode{
		Name:          "secret-status-s13",
		ProjectID:     proj.ID,
		EnvironmentID: env.ID,
		Type:          "password",
		OwnerID:       1,
		Status:        "active",
	})
	require.NoError(t, err)
	return secret
}

// TestTransitionSecretStatusProxy_BadID — non-numeric id → 400.
func TestTransitionSecretStatusProxy_BadID(t *testing.T) {
	h := freshSecretHandlerForProxyS13(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodPut, "/system/secrets/bad/transition-status", strings.NewReader("{}")),
		"id", "bad",
	)
	w := httptest.NewRecorder()
	h.TransitionSecretStatusProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.Equal(t, "INVALID_PARAMETER", resp.Error.Code)
}

// TestTransitionSecretStatusProxy_BadBody — malformed JSON → 400.
func TestTransitionSecretStatusProxy_BadBody(t *testing.T) {
	h := freshSecretHandlerForProxyS13(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodPut, "/system/secrets/1/transition-status", strings.NewReader("{bad")),
		"id", "1",
	)
	w := httptest.NewRecorder()
	h.TransitionSecretStatusProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.Equal(t, "INVALID_BODY", resp.Error.Code)
}

// TestTransitionSecretStatusProxy_MissingSecret — valid id, body has no
// "secret" field → 400.
func TestTransitionSecretStatusProxy_MissingSecret(t *testing.T) {
	h := freshSecretHandlerForProxyS13(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodPut, "/system/secrets/1/transition-status", strings.NewReader(`{"from_status":"active"}`)),
		"id", "1",
	)
	w := httptest.NewRecorder()
	h.TransitionSecretStatusProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.Equal(t, "INVALID_BODY", resp.Error.Code)
}

// TestTransitionSecretStatusProxy_MissingFromStatus — valid id and secret,
// missing from_status → 400.
func TestTransitionSecretStatusProxy_MissingFromStatus(t *testing.T) {
	h := freshSecretHandlerForProxyS13(t)
	body := proxyJSON(map[string]interface{}{
		"secret": map[string]interface{}{"status": "suspended"},
	})
	req := withChiParam(
		httptest.NewRequest(http.MethodPut, "/system/secrets/1/transition-status", body),
		"id", "1",
	)
	w := httptest.NewRecorder()
	h.TransitionSecretStatusProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteResp(t, w)
	assert.Equal(t, "INVALID_BODY", resp.Error.Code)
}

// TestTransitionSecretStatusProxy_HappyPath — a conditional write from the
// seeded secret's current "active" status succeeds and reports matched:true.
func TestTransitionSecretStatusProxy_HappyPath(t *testing.T) {
	h := freshSecretHandlerForProxyS13(t)
	secret := seedSecretForProxyS13(t, h)
	idStr := strconv.FormatUint(uint64(secret.ID), 10)

	body := proxyJSON(map[string]interface{}{
		"secret": map[string]interface{}{
			"name":           secret.Name,
			"project_id":     secret.ProjectID,
			"environment_id": secret.EnvironmentID,
			"type":           secret.Type,
			"owner_id":       secret.OwnerID,
			"status":         "suspended",
		},
		"from_status": "active",
	})
	req := withChiParam(
		httptest.NewRequest(http.MethodPut, "/system/secrets/"+idStr+"/transition-status", body),
		"id", idStr,
	)
	w := httptest.NewRecorder()
	h.TransitionSecretStatusProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	resp := decodeRemoteResp(t, w)
	require.True(t, resp.Success)
	data, ok := resp.Data.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, true, data["matched"])
}

// TestTransitionSecretStatusProxy_RefusesFieldRewrite is the #G79 regression:
// TransitionSecretStatusProxy previously persisted the caller's entire
// wire-supplied *models.SecretNode via a Select("*") full-row update, so a
// client claiming a different owner_id/classification alongside the status
// transition silently rewrote those fields too. Only status/updated_at must
// change; every other field must come from the server's own authoritative
// row, not the wire body.
func TestTransitionSecretStatusProxy_RefusesFieldRewrite(t *testing.T) {
	h := freshSecretHandlerForProxyS13(t)
	secret := seedSecretForProxyS13(t, h)
	idStr := strconv.FormatUint(uint64(secret.ID), 10)

	body := proxyJSON(map[string]interface{}{
		"secret": map[string]interface{}{
			"name":           "renamed-by-attacker",
			"project_id":     secret.ProjectID,
			"environment_id": secret.EnvironmentID,
			"type":           secret.Type,
			"owner_id":       secret.OwnerID + 999, // attacker-claimed owner
			"classification": "public",             // attacker-claimed classification
			"status":         "suspended",
		},
		"from_status": "active",
	})
	req := withChiParam(
		httptest.NewRequest(http.MethodPut, "/system/secrets/"+idStr+"/transition-status", body),
		"id", idStr,
	)
	w := httptest.NewRecorder()
	h.TransitionSecretStatusProxy(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	updated, err := h.coreService.Storage().GetSecret(context.Background(), secret.ID)
	require.NoError(t, err)
	assert.Equal(t, "suspended", updated.Status, "the actual transition must still apply")
	assert.Equal(t, secret.OwnerID, updated.OwnerID, "owner_id must not be rewritten by the wire body")
	assert.Equal(t, "secret-status-s13", updated.Name, "name must not be rewritten by the wire body")
}

// TestTransitionSecretStatusProxy_LostRace — a second conditional write still
// asserting the same (now-stale) from_status as a call that already won must
// report matched:false, proving the CAS race closes at the HTTP-proxy
// boundary too (not just LocalStorage).
func TestTransitionSecretStatusProxy_LostRace(t *testing.T) {
	h := freshSecretHandlerForProxyS13(t)
	secret := seedSecretForProxyS13(t, h)
	idStr := strconv.FormatUint(uint64(secret.ID), 10)

	body := func() *strings.Reader {
		return strings.NewReader(`{
			"secret": {"name":"` + secret.Name + `","project_id":` + strconv.FormatUint(uint64(secret.ProjectID), 10) +
			`,"environment_id":` + strconv.FormatUint(uint64(secret.EnvironmentID), 10) +
			`,"type":"password","owner_id":1,"status":"suspended"},
			"from_status": "active"
		}`)
	}

	firstReq := withChiParam(
		httptest.NewRequest(http.MethodPut, "/system/secrets/"+idStr+"/transition-status", body()),
		"id", idStr,
	)
	firstW := httptest.NewRecorder()
	h.TransitionSecretStatusProxy(firstW, firstReq)
	require.Equal(t, http.StatusOK, firstW.Code)
	firstResp := decodeRemoteResp(t, firstW)
	firstData, ok := firstResp.Data.(map[string]interface{})
	require.True(t, ok)
	require.Equal(t, true, firstData["matched"], "first call must win")

	secondReq := withChiParam(
		httptest.NewRequest(http.MethodPut, "/system/secrets/"+idStr+"/transition-status", body()),
		"id", idStr,
	)
	secondW := httptest.NewRecorder()
	h.TransitionSecretStatusProxy(secondW, secondReq)
	assert.Equal(t, http.StatusOK, secondW.Code)
	secondResp := decodeRemoteResp(t, secondW)
	secondData, ok := secondResp.Data.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, false, secondData["matched"], "second (racing) call must lose — status already changed")
}
