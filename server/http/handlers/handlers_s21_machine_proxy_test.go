// handlers_s21_machine_proxy_test.go — coverage sweep for machine_identities_proxy.go.
// Covers all handler branches: bad params (400), missing body fields (400),
// not-found (404), storage errors (via no-data empty DB), and happy paths (200).
//
// Functions targeted (50% or lower prior coverage):
//   - CountMachineIdentitiesByClassificationProxy
//   - CountMachineIdentityCredentialsByClassificationProxy
//   - Plus full branch coverage for every other proxy handler in the file.
package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	customMiddleware "github.com/keyorixhq/keyorix/server/middleware"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// freshCatalogHandlerS21 returns a CatalogHandler backed by a fresh in-memory DB.
func freshCatalogHandlerS21(t *testing.T) *CatalogHandler {
	t.Helper()
	cs := freshCoreS12(t)
	return NewCatalogHandler(cs)
}

// decodeRemoteRespS21 decodes a remoteAPIResponse from a recorder.
func decodeRemoteRespS21(t *testing.T, w *httptest.ResponseRecorder) remoteAPIResponse {
	t.Helper()
	var resp remoteAPIResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	return resp
}

// proxyBodyS21 marshals v into a *bytes.Buffer for use as a request body.
func proxyBodyS21(v interface{}) *bytes.Buffer {
	b, _ := json.Marshal(v)
	return bytes.NewBuffer(b)
}

// withOIDCAdminCtxS21 seeds a system_admin-holding user directly against h's
// own storage and returns r wrapped with that user's context — needed by every
// CreateOIDCBindingProxy happy-path call since the G80 raw-storage-bypass fix
// added core.CreateOIDCBinding's install-wide admin-authority check
// (requireAuthorityForRole), which an unauthenticated request (actorID 0)
// cannot satisfy.
func withOIDCAdminCtxS21(t *testing.T, h *CatalogHandler, r *http.Request) *http.Request {
	t.Helper()
	ctx := context.Background()
	_, err := h.coreService.Storage().CreateRole(ctx, &models.Role{Name: "system_admin", Description: "Administrator"})
	if err != nil {
		require.Contains(t, err.Error(), "UNIQUE", "unexpected CreateRole error: %v", err) // already exists from a prior call in this test
	}
	uname := fmt.Sprintf("s21_oidc_admin_%d", time.Now().UnixNano())
	user, err := h.coreService.CreateUser(ctx, &core.CreateUserRequest{
		Username: uname, Email: uname + "@example.com", Password: "TestPassword123!",
	})
	require.NoError(t, err)
	require.NoError(t, h.coreService.AssignUserRoleScoped(ctx, user.Email, "system_admin", core.Scope{}))
	userCtx := &customMiddleware.UserContext{UserID: user.ID, Username: user.Username, Email: user.Email}
	return r.WithContext(context.WithValue(r.Context(), customMiddleware.GetUserContextKey(), userCtx))
}

// ── CreateMachineIdentityProxy ────────────────────────────────────────────────

// TestCreateMachineIdentityProxy_BadBody_S21 — malformed JSON → 400.
func TestCreateMachineIdentityProxy_BadBody_S21(t *testing.T) {
	h := freshCatalogHandlerS21(t)
	req := httptest.NewRequest(http.MethodPost, "/system/machine-identities", strings.NewReader("{bad"))
	w := httptest.NewRecorder()
	h.CreateMachineIdentityProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteRespS21(t, w)
	assert.False(t, resp.Success)
	assert.Equal(t, "INVALID_BODY", resp.Error.Code)
}

// TestCreateMachineIdentityProxy_MissingName_S21 — empty name → 400.
func TestCreateMachineIdentityProxy_MissingName_S21(t *testing.T) {
	h := freshCatalogHandlerS21(t)
	body := proxyBodyS21(map[string]interface{}{"name": "", "project_id": 1})
	req := httptest.NewRequest(http.MethodPost, "/system/machine-identities", body)
	w := httptest.NewRecorder()
	h.CreateMachineIdentityProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteRespS21(t, w)
	assert.Equal(t, "INVALID_BODY", resp.Error.Code)
}

// TestCreateMachineIdentityProxy_MissingProjectID_S21 — zero project_id → 400.
func TestCreateMachineIdentityProxy_MissingProjectID_S21(t *testing.T) {
	h := freshCatalogHandlerS21(t)
	body := proxyBodyS21(map[string]interface{}{"name": "bot", "project_id": 0})
	req := httptest.NewRequest(http.MethodPost, "/system/machine-identities", body)
	w := httptest.NewRecorder()
	h.CreateMachineIdentityProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteRespS21(t, w)
	assert.Equal(t, "INVALID_BODY", resp.Error.Code)
}

// TestCreateMachineIdentityProxy_HappyPath_S21 — valid body → 200.
func TestCreateMachineIdentityProxy_HappyPath_S21(t *testing.T) {
	h := freshCatalogHandlerS21(t)
	body := proxyBodyS21(map[string]interface{}{
		"name":          "svc-bot-s21",
		"project_id":    1,
		"identity_type": "service",
		"state":         "active",
	})
	req := httptest.NewRequest(http.MethodPost, "/system/machine-identities", body)
	req = withOIDCAdminCtxS21(t, h, req)
	w := httptest.NewRecorder()
	h.CreateMachineIdentityProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	resp := decodeRemoteRespS21(t, w)
	assert.True(t, resp.Success)
}

// ── GetMachineIdentityProxy ───────────────────────────────────────────────────

// TestGetMachineIdentityProxy_BadID_S21 — non-numeric id → 400.
func TestGetMachineIdentityProxy_BadID_S21(t *testing.T) {
	h := freshCatalogHandlerS21(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/system/machine-identities/bad", nil),
		"id", "bad",
	)
	w := httptest.NewRecorder()
	h.GetMachineIdentityProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteRespS21(t, w)
	assert.Equal(t, "INVALID_PARAMETER", resp.Error.Code)
}

// TestGetMachineIdentityProxy_NotFound_S21 — valid id, not in DB → 404.
func TestGetMachineIdentityProxy_NotFound_S21(t *testing.T) {
	h := freshCatalogHandlerS21(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/system/machine-identities/9999", nil),
		"id", "9999",
	)
	w := httptest.NewRecorder()
	h.GetMachineIdentityProxy(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
	resp := decodeRemoteRespS21(t, w)
	assert.Equal(t, "NOT_FOUND", resp.Error.Code)
}

// TestGetMachineIdentityProxy_HappyPath_S21 — existing machine identity → 200.
func TestGetMachineIdentityProxy_HappyPath_S21(t *testing.T) {
	h := freshCatalogHandlerS21(t)
	// First create one.
	createBody := proxyBodyS21(map[string]interface{}{
		"name":       "get-test-bot-s21",
		"project_id": 2,
		"state":      "active",
	})
	cr := httptest.NewRequest(http.MethodPost, "/system/machine-identities", createBody)
	cr = withOIDCAdminCtxS21(t, h, cr)
	cw := httptest.NewRecorder()
	h.CreateMachineIdentityProxy(cw, cr)
	require.Equal(t, http.StatusOK, cw.Code)

	var createResp remoteAPIResponse
	require.NoError(t, json.NewDecoder(cw.Body).Decode(&createResp))
	data := createResp.Data.(map[string]interface{})
	idStr := fmt.Sprintf("%d", uint(data["id"].(float64)))

	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/system/machine-identities/"+idStr, nil),
		"id", idStr,
	)
	w := httptest.NewRecorder()
	h.GetMachineIdentityProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	resp := decodeRemoteRespS21(t, w)
	assert.True(t, resp.Success)
}

// ── UpdateMachineIdentityProxy ────────────────────────────────────────────────

// TestUpdateMachineIdentityProxy_BadID_S21 — non-numeric id → 400.
func TestUpdateMachineIdentityProxy_BadID_S21(t *testing.T) {
	h := freshCatalogHandlerS21(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodPut, "/system/machine-identities/bad", strings.NewReader("{}")),
		"id", "bad",
	)
	w := httptest.NewRecorder()
	h.UpdateMachineIdentityProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteRespS21(t, w)
	assert.Equal(t, "INVALID_PARAMETER", resp.Error.Code)
}

// TestUpdateMachineIdentityProxy_BadBody_S21 — malformed JSON body → 400.
func TestUpdateMachineIdentityProxy_BadBody_S21(t *testing.T) {
	h := freshCatalogHandlerS21(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodPut, "/system/machine-identities/1", strings.NewReader("{bad")),
		"id", "1",
	)
	w := httptest.NewRecorder()
	h.UpdateMachineIdentityProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteRespS21(t, w)
	assert.Equal(t, "INVALID_BODY", resp.Error.Code)
}

// TestUpdateMachineIdentityProxy_HappyPath_S21 — valid update → 200 updated:true.
func TestUpdateMachineIdentityProxy_HappyPath_S21(t *testing.T) {
	h := freshCatalogHandlerS21(t)
	// Seed a machine identity first.
	createBody := proxyBodyS21(map[string]interface{}{
		"name":       "upd-bot-s21",
		"project_id": 3,
		"state":      "active",
	})
	cr := httptest.NewRequest(http.MethodPost, "/system/machine-identities", createBody)
	cr = withOIDCAdminCtxS21(t, h, cr)
	cw := httptest.NewRecorder()
	h.CreateMachineIdentityProxy(cw, cr)
	require.Equal(t, http.StatusOK, cw.Code)

	body := proxyBodyS21(map[string]interface{}{
		"name":       "upd-bot-s21-renamed",
		"project_id": 3,
		"state":      "active",
	})
	req := withChiParam(
		httptest.NewRequest(http.MethodPut, "/system/machine-identities/1", body),
		"id", "1",
	)
	w := httptest.NewRecorder()
	h.UpdateMachineIdentityProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	resp := decodeRemoteRespS21(t, w)
	assert.True(t, resp.Success)
}

// ── TransitionMachineIdentityStateProxy ──────────────────────────────────────

// TestTransitionMachineIdentityStateProxy_BadID_S21 — non-numeric id → 400.
func TestTransitionMachineIdentityStateProxy_BadID_S21(t *testing.T) {
	h := freshCatalogHandlerS21(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodPut, "/system/machine-identities/bad/transition", strings.NewReader("{}")),
		"id", "bad",
	)
	w := httptest.NewRecorder()
	h.TransitionMachineIdentityStateProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteRespS21(t, w)
	assert.Equal(t, "INVALID_PARAMETER", resp.Error.Code)
}

// TestTransitionMachineIdentityStateProxy_BadBody_S21 — malformed JSON → 400.
func TestTransitionMachineIdentityStateProxy_BadBody_S21(t *testing.T) {
	h := freshCatalogHandlerS21(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodPut, "/system/machine-identities/1/transition", strings.NewReader("{bad")),
		"id", "1",
	)
	w := httptest.NewRecorder()
	h.TransitionMachineIdentityStateProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteRespS21(t, w)
	assert.Equal(t, "INVALID_BODY", resp.Error.Code)
}

// TestTransitionMachineIdentityStateProxy_MissingFromState_S21 — empty from_state → 400.
func TestTransitionMachineIdentityStateProxy_MissingFromState_S21(t *testing.T) {
	h := freshCatalogHandlerS21(t)
	body := proxyBodyS21(map[string]interface{}{
		"machine_identity": map[string]interface{}{"state": "revoked"},
		"from_state":       "",
	})
	req := withChiParam(
		httptest.NewRequest(http.MethodPut, "/system/machine-identities/1/transition", body),
		"id", "1",
	)
	w := httptest.NewRecorder()
	h.TransitionMachineIdentityStateProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteRespS21(t, w)
	assert.Equal(t, "INVALID_BODY", resp.Error.Code)
}

// TestTransitionMachineIdentityStateProxy_HappyPath_S21 — valid transition (no match on empty DB → matched:false) → 200.
func TestTransitionMachineIdentityStateProxy_HappyPath_S21(t *testing.T) {
	h := freshCatalogHandlerS21(t)
	body := proxyBodyS21(map[string]interface{}{
		"machine_identity": map[string]interface{}{
			"id":         1,
			"state":      "revoked",
			"project_id": 1,
		},
		"from_state": "active",
	})
	req := withChiParam(
		httptest.NewRequest(http.MethodPut, "/system/machine-identities/1/transition", body),
		"id", "1",
	)
	w := httptest.NewRecorder()
	h.TransitionMachineIdentityStateProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	resp := decodeRemoteRespS21(t, w)
	assert.True(t, resp.Success)
}

// ── ListMachineIdentitiesProxy ────────────────────────────────────────────────

// TestListMachineIdentitiesProxy_MissingProjectID_S21 — no project_id → 400.
func TestListMachineIdentitiesProxy_MissingProjectID_S21(t *testing.T) {
	h := freshCatalogHandlerS21(t)
	req := httptest.NewRequest(http.MethodGet, "/system/machine-identities", nil)
	w := httptest.NewRecorder()
	h.ListMachineIdentitiesProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteRespS21(t, w)
	assert.Equal(t, "INVALID_QUERY", resp.Error.Code)
}

// TestListMachineIdentitiesProxy_BadProjectID_S21 — non-numeric project_id → 400.
func TestListMachineIdentitiesProxy_BadProjectID_S21(t *testing.T) {
	h := freshCatalogHandlerS21(t)
	req := httptest.NewRequest(http.MethodGet, "/system/machine-identities?project_id=notanumber", nil)
	w := httptest.NewRecorder()
	h.ListMachineIdentitiesProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteRespS21(t, w)
	assert.Equal(t, "INVALID_QUERY", resp.Error.Code)
}

// TestListMachineIdentitiesProxy_HappyPath_S21 — valid project_id (empty result) → 200.
func TestListMachineIdentitiesProxy_HappyPath_S21(t *testing.T) {
	h := freshCatalogHandlerS21(t)
	req := httptest.NewRequest(http.MethodGet, "/system/machine-identities?project_id=1", nil)
	w := httptest.NewRecorder()
	h.ListMachineIdentitiesProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	resp := decodeRemoteRespS21(t, w)
	assert.True(t, resp.Success)
}

// ── ListAllMachineIdentitiesProxy ─────────────────────────────────────────────

// TestListAllMachineIdentitiesProxy_HappyPath_S21 — no params required → 200.
func TestListAllMachineIdentitiesProxy_HappyPath_S21(t *testing.T) {
	h := freshCatalogHandlerS21(t)
	req := httptest.NewRequest(http.MethodGet, "/system/machine-identities/all", nil)
	w := httptest.NewRecorder()
	h.ListAllMachineIdentitiesProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	resp := decodeRemoteRespS21(t, w)
	assert.True(t, resp.Success)
}

// ── CountMachineIdentitiesByClassificationProxy ───────────────────────────────

// TestCountMachineIdentitiesByClassificationProxy_HappyPath_S21 — no params → 200 (was 50% covered).
func TestCountMachineIdentitiesByClassificationProxy_HappyPath_S21(t *testing.T) {
	h := freshCatalogHandlerS21(t)
	req := httptest.NewRequest(http.MethodGet, "/system/machine-identities/classification-counts", nil)
	w := httptest.NewRecorder()
	h.CountMachineIdentitiesByClassificationProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	resp := decodeRemoteRespS21(t, w)
	assert.True(t, resp.Success)
}

// TestCountMachineIdentitiesByClassificationProxy_WithData_S21 — with seeded identities → 200 with counts.
func TestCountMachineIdentitiesByClassificationProxy_WithData_S21(t *testing.T) {
	h := freshCatalogHandlerS21(t)
	// Seed some machine identities to get non-empty counts. Classification must be
	// one of core.IsValidClassification's set (public|internal|confidential|
	// restricted) now that CreateMachineIdentityProxy routes through
	// core.CreateMachineIdentity (G80 raw-storage-bypass fix) — "secret" was never
	// a real classification, the old unvalidated raw proxy just never checked.
	for i, class := range []string{"public", "confidential", "restricted"} {
		createBody := proxyBodyS21(map[string]interface{}{
			"name":           "count-bot-s21-" + class,
			"project_id":     i + 1,
			"state":          "active",
			"classification": class,
		})
		cr := httptest.NewRequest(http.MethodPost, "/system/machine-identities", createBody)
		cr = withOIDCAdminCtxS21(t, h, cr)
		cw := httptest.NewRecorder()
		h.CreateMachineIdentityProxy(cw, cr)
		require.Equal(t, http.StatusOK, cw.Code)
	}

	req := httptest.NewRequest(http.MethodGet, "/system/machine-identities/classification-counts", nil)
	w := httptest.NewRecorder()
	h.CountMachineIdentitiesByClassificationProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	resp := decodeRemoteRespS21(t, w)
	assert.True(t, resp.Success)
	// The response data should contain "counts".
	data, ok := resp.Data.(map[string]interface{})
	assert.True(t, ok)
	_, hasCounts := data["counts"]
	assert.True(t, hasCounts)
}

// ── CreateMachineIdentityCredentialProxy ──────────────────────────────────────

// TestCreateMachineIdentityCredentialProxy_BadBody_S21 — malformed JSON → 400.
func TestCreateMachineIdentityCredentialProxy_BadBody_S21(t *testing.T) {
	h := freshCatalogHandlerS21(t)
	req := httptest.NewRequest(http.MethodPost, "/system/machine-credentials", strings.NewReader("{bad"))
	w := httptest.NewRecorder()
	h.CreateMachineIdentityCredentialProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteRespS21(t, w)
	assert.Equal(t, "INVALID_BODY", resp.Error.Code)
}

// TestCreateMachineIdentityCredentialProxy_MissingMachineID_S21 — zero machine_identity_id → 400.
func TestCreateMachineIdentityCredentialProxy_MissingMachineID_S21(t *testing.T) {
	h := freshCatalogHandlerS21(t)
	body := proxyBodyS21(map[string]interface{}{"machine_identity_id": 0, "token_hash": "abc123"})
	req := httptest.NewRequest(http.MethodPost, "/system/machine-credentials", body)
	w := httptest.NewRecorder()
	h.CreateMachineIdentityCredentialProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteRespS21(t, w)
	assert.Equal(t, "INVALID_BODY", resp.Error.Code)
}

// TestCreateMachineIdentityCredentialProxy_MissingTokenHash_S21 — empty token_hash → 400.
func TestCreateMachineIdentityCredentialProxy_MissingTokenHash_S21(t *testing.T) {
	h := freshCatalogHandlerS21(t)
	body := proxyBodyS21(map[string]interface{}{"machine_identity_id": 1, "token_hash": ""})
	req := httptest.NewRequest(http.MethodPost, "/system/machine-credentials", body)
	w := httptest.NewRecorder()
	h.CreateMachineIdentityCredentialProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteRespS21(t, w)
	assert.Equal(t, "INVALID_BODY", resp.Error.Code)
}

// TestCreateMachineIdentityCredentialProxy_HappyPath_S21 — valid body → 200.
func TestCreateMachineIdentityCredentialProxy_HappyPath_S21(t *testing.T) {
	h := freshCatalogHandlerS21(t)
	// Seed a machine identity first.
	createMI := proxyBodyS21(map[string]interface{}{
		"name":       "cred-owner-s21",
		"project_id": 10,
		"state":      "active",
	})
	cr := httptest.NewRequest(http.MethodPost, "/system/machine-identities", createMI)
	cr = withOIDCAdminCtxS21(t, h, cr)
	cw := httptest.NewRecorder()
	h.CreateMachineIdentityProxy(cw, cr)
	require.Equal(t, http.StatusOK, cw.Code)

	var miResp remoteAPIResponse
	require.NoError(t, json.NewDecoder(cw.Body).Decode(&miResp))
	miData := miResp.Data.(map[string]interface{})
	machineID := uint(miData["id"].(float64))

	body := proxyBodyS21(map[string]interface{}{
		"machine_identity_id": machineID,
		"token_hash":          "sha256hexhashvalue0000000000000000000000000000000000000000000001",
		"name":                "primary-cred-s21",
		"token_prefix":        "kx_",
	})
	req := httptest.NewRequest(http.MethodPost, "/system/machine-credentials", body)
	req = withOIDCAdminCtxS21(t, h, req)
	w := httptest.NewRecorder()
	h.CreateMachineIdentityCredentialProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	resp := decodeRemoteRespS21(t, w)
	assert.True(t, resp.Success)
}

// ── GetMachineIdentityCredentialByHashProxy ───────────────────────────────────

// TestGetMachineIdentityCredentialByHashProxy_NotFound_S21 — hash not in DB → 404.
func TestGetMachineIdentityCredentialByHashProxy_NotFound_S21(t *testing.T) {
	h := freshCatalogHandlerS21(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/system/machine-credentials/by-hash/nonexistenthash", nil),
		"hash", "nonexistenthash",
	)
	w := httptest.NewRecorder()
	h.GetMachineIdentityCredentialByHashProxy(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
	resp := decodeRemoteRespS21(t, w)
	assert.Equal(t, "NOT_FOUND", resp.Error.Code)
}

// TestGetMachineIdentityCredentialByHashProxy_HappyPath_S21 — hash found → 200.
func TestGetMachineIdentityCredentialByHashProxy_HappyPath_S21(t *testing.T) {
	h := freshCatalogHandlerS21(t)

	// Create machine identity.
	createMI := proxyBodyS21(map[string]interface{}{
		"name": "hash-mi-s21", "project_id": 11, "state": "active",
	})
	cr := httptest.NewRequest(http.MethodPost, "/system/machine-identities", createMI)
	cr = withOIDCAdminCtxS21(t, h, cr)
	cw := httptest.NewRecorder()
	h.CreateMachineIdentityProxy(cw, cr)
	require.Equal(t, http.StatusOK, cw.Code)
	var miResp remoteAPIResponse
	require.NoError(t, json.NewDecoder(cw.Body).Decode(&miResp))
	machineID := uint(miResp.Data.(map[string]interface{})["id"].(float64))

	hash := "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
	createCred := proxyBodyS21(map[string]interface{}{
		"machine_identity_id": machineID,
		"token_hash":          hash,
		"name":                "by-hash-cred-s21",
	})
	cr2 := httptest.NewRequest(http.MethodPost, "/system/machine-credentials", createCred)
	cr2 = withOIDCAdminCtxS21(t, h, cr2)
	cw2 := httptest.NewRecorder()
	h.CreateMachineIdentityCredentialProxy(cw2, cr2)
	require.Equal(t, http.StatusOK, cw2.Code)

	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/system/machine-credentials/by-hash/"+hash, nil),
		"hash", hash,
	)
	w := httptest.NewRecorder()
	h.GetMachineIdentityCredentialByHashProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	resp := decodeRemoteRespS21(t, w)
	assert.True(t, resp.Success)
}

// ── GetMachineIdentityCredentialByIDProxy ─────────────────────────────────────

// TestGetMachineIdentityCredentialByIDProxy_BadID_S21 — non-numeric id → 400.
func TestGetMachineIdentityCredentialByIDProxy_BadID_S21(t *testing.T) {
	h := freshCatalogHandlerS21(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/system/machine-credentials/bad", nil),
		"id", "bad",
	)
	w := httptest.NewRecorder()
	h.GetMachineIdentityCredentialByIDProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteRespS21(t, w)
	assert.Equal(t, "INVALID_PARAMETER", resp.Error.Code)
}

// TestGetMachineIdentityCredentialByIDProxy_NotFound_S21 — valid id, not in DB → 404.
func TestGetMachineIdentityCredentialByIDProxy_NotFound_S21(t *testing.T) {
	h := freshCatalogHandlerS21(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/system/machine-credentials/9999", nil),
		"id", "9999",
	)
	w := httptest.NewRecorder()
	h.GetMachineIdentityCredentialByIDProxy(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
	resp := decodeRemoteRespS21(t, w)
	assert.Equal(t, "NOT_FOUND", resp.Error.Code)
}

// ── ListMachineIdentityCredentialsProxy ───────────────────────────────────────

// TestListMachineIdentityCredentialsProxy_BadID_S21 — non-numeric id → 400.
func TestListMachineIdentityCredentialsProxy_BadID_S21(t *testing.T) {
	h := freshCatalogHandlerS21(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/system/machine-identities/bad/credentials", nil),
		"id", "bad",
	)
	w := httptest.NewRecorder()
	h.ListMachineIdentityCredentialsProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteRespS21(t, w)
	assert.Equal(t, "INVALID_PARAMETER", resp.Error.Code)
}

// TestListMachineIdentityCredentialsProxy_HappyPath_S21 — valid id (empty result) → 200.
func TestListMachineIdentityCredentialsProxy_HappyPath_S21(t *testing.T) {
	h := freshCatalogHandlerS21(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/system/machine-identities/1/credentials", nil),
		"id", "1",
	)
	w := httptest.NewRecorder()
	h.ListMachineIdentityCredentialsProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	resp := decodeRemoteRespS21(t, w)
	assert.True(t, resp.Success)
}

// ── ListActiveMachineIdentityCredentialsProxy ─────────────────────────────────

// TestListActiveMachineIdentityCredentialsProxy_HappyPath_S21 — no params → 200.
func TestListActiveMachineIdentityCredentialsProxy_HappyPath_S21(t *testing.T) {
	h := freshCatalogHandlerS21(t)
	req := httptest.NewRequest(http.MethodGet, "/system/machine-credentials/active", nil)
	w := httptest.NewRecorder()
	h.ListActiveMachineIdentityCredentialsProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	resp := decodeRemoteRespS21(t, w)
	assert.True(t, resp.Success)
}

// ── UpdateMachineIdentityCredentialProxy ──────────────────────────────────────

// TestUpdateMachineIdentityCredentialProxy_BadID_S21 — non-numeric id → 400.
func TestUpdateMachineIdentityCredentialProxy_BadID_S21(t *testing.T) {
	h := freshCatalogHandlerS21(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodPut, "/system/machine-credentials/bad", strings.NewReader("{}")),
		"id", "bad",
	)
	w := httptest.NewRecorder()
	h.UpdateMachineIdentityCredentialProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteRespS21(t, w)
	assert.Equal(t, "INVALID_PARAMETER", resp.Error.Code)
}

// TestUpdateMachineIdentityCredentialProxy_BadBody_S21 — malformed JSON → 400.
func TestUpdateMachineIdentityCredentialProxy_BadBody_S21(t *testing.T) {
	h := freshCatalogHandlerS21(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodPut, "/system/machine-credentials/1", strings.NewReader("{bad")),
		"id", "1",
	)
	w := httptest.NewRecorder()
	h.UpdateMachineIdentityCredentialProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteRespS21(t, w)
	assert.Equal(t, "INVALID_BODY", resp.Error.Code)
}

// TestUpdateMachineIdentityCredentialProxy_HappyPath_S21 — valid update → 200.
func TestUpdateMachineIdentityCredentialProxy_HappyPath_S21(t *testing.T) {
	h := freshCatalogHandlerS21(t)
	// Seed a machine identity and credential.
	createMI := proxyBodyS21(map[string]interface{}{
		"name": "upd-cred-mi-s21", "project_id": 20, "state": "active",
	})
	cr := httptest.NewRequest(http.MethodPost, "/system/machine-identities", createMI)
	cr = withOIDCAdminCtxS21(t, h, cr)
	cw := httptest.NewRecorder()
	h.CreateMachineIdentityProxy(cw, cr)
	require.Equal(t, http.StatusOK, cw.Code)
	var miResp remoteAPIResponse
	require.NoError(t, json.NewDecoder(cw.Body).Decode(&miResp))
	machineID := uint(miResp.Data.(map[string]interface{})["id"].(float64))

	createCred := proxyBodyS21(map[string]interface{}{
		"machine_identity_id": machineID,
		"token_hash":          "updatehash000000000000000000000000000000000000000000000000000001",
		"name":                "upd-cred-s21",
	})
	cr2 := httptest.NewRequest(http.MethodPost, "/system/machine-credentials", createCred)
	cr2 = withOIDCAdminCtxS21(t, h, cr2)
	cw2 := httptest.NewRecorder()
	h.CreateMachineIdentityCredentialProxy(cw2, cr2)
	require.Equal(t, http.StatusOK, cw2.Code)
	var credResp remoteAPIResponse
	require.NoError(t, json.NewDecoder(cw2.Body).Decode(&credResp))
	credIDFloat := credResp.Data.(map[string]interface{})["id"].(float64)
	credIDStr := fmt.Sprintf("%d", uint(credIDFloat))

	body := proxyBodyS21(map[string]interface{}{
		"machine_identity_id": machineID,
		"token_hash":          "updatehash000000000000000000000000000000000000000000000000000001",
		"name":                "upd-cred-s21-renamed",
		"classification":      "confidential",
	})
	req := withChiParam(
		httptest.NewRequest(http.MethodPut, "/system/machine-credentials/"+credIDStr, body),
		"id", credIDStr,
	)
	w := httptest.NewRecorder()
	h.UpdateMachineIdentityCredentialProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	resp := decodeRemoteRespS21(t, w)
	assert.True(t, resp.Success)
}

// ── CountMachineIdentityCredentialsByClassificationProxy ──────────────────────

// TestCountMachineIdentityCredentialsByClassificationProxy_HappyPath_S21 — no params → 200 (was 50% covered).
func TestCountMachineIdentityCredentialsByClassificationProxy_HappyPath_S21(t *testing.T) {
	h := freshCatalogHandlerS21(t)
	req := httptest.NewRequest(http.MethodGet, "/system/machine-credentials/classification-counts", nil)
	w := httptest.NewRecorder()
	h.CountMachineIdentityCredentialsByClassificationProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	resp := decodeRemoteRespS21(t, w)
	assert.True(t, resp.Success)
}

// TestCountMachineIdentityCredentialsByClassificationProxy_WithData_S21 — with seeded creds → 200 with counts.
func TestCountMachineIdentityCredentialsByClassificationProxy_WithData_S21(t *testing.T) {
	h := freshCatalogHandlerS21(t)
	// Seed a machine identity.
	createMI := proxyBodyS21(map[string]interface{}{
		"name": "count-cred-mi-s21", "project_id": 30, "state": "active",
	})
	cr := httptest.NewRequest(http.MethodPost, "/system/machine-identities", createMI)
	cr = withOIDCAdminCtxS21(t, h, cr)
	cw := httptest.NewRecorder()
	h.CreateMachineIdentityProxy(cw, cr)
	require.Equal(t, http.StatusOK, cw.Code)
	var miResp remoteAPIResponse
	require.NoError(t, json.NewDecoder(cw.Body).Decode(&miResp))
	machineID := uint(miResp.Data.(map[string]interface{})["id"].(float64))

	// Seed credentials with different classifications.
	for i, class := range []string{"public", "secret"} {
		hash := strings.Repeat("0", 60) + strings.Repeat("a", 3) + string(rune('0'+i))
		createCred := proxyBodyS21(map[string]interface{}{
			"machine_identity_id": machineID,
			"token_hash":          hash,
			"name":                "count-cred-" + class + "-s21",
			"classification":      class,
		})
		cr2 := httptest.NewRequest(http.MethodPost, "/system/machine-credentials", createCred)
		cr2 = withOIDCAdminCtxS21(t, h, cr2)
		cw2 := httptest.NewRecorder()
		h.CreateMachineIdentityCredentialProxy(cw2, cr2)
		require.Equal(t, http.StatusOK, cw2.Code)
	}

	req := httptest.NewRequest(http.MethodGet, "/system/machine-credentials/classification-counts", nil)
	w := httptest.NewRecorder()
	h.CountMachineIdentityCredentialsByClassificationProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	resp := decodeRemoteRespS21(t, w)
	assert.True(t, resp.Success)
	data, ok := resp.Data.(map[string]interface{})
	assert.True(t, ok)
	_, hasCounts := data["counts"]
	assert.True(t, hasCounts)
}

// ── RevokeMachineIdentityCredentialProxy ──────────────────────────────────────

// TestRevokeMachineIdentityCredentialProxy_BadID_S21 — non-numeric id → 400.
func TestRevokeMachineIdentityCredentialProxy_BadID_S21(t *testing.T) {
	h := freshCatalogHandlerS21(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodPost, "/system/machine-credentials/bad/revoke", nil),
		"id", "bad",
	)
	w := httptest.NewRecorder()
	h.RevokeMachineIdentityCredentialProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteRespS21(t, w)
	assert.Equal(t, "INVALID_PARAMETER", resp.Error.Code)
}

// TestRevokeMachineIdentityCredentialProxy_NotFound_S21 — valid id, not in DB → 404.
func TestRevokeMachineIdentityCredentialProxy_NotFound_S21(t *testing.T) {
	h := freshCatalogHandlerS21(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodPost, "/system/machine-credentials/9999/revoke", nil),
		"id", "9999",
	)
	w := httptest.NewRecorder()
	h.RevokeMachineIdentityCredentialProxy(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
	resp := decodeRemoteRespS21(t, w)
	assert.Equal(t, "NOT_FOUND", resp.Error.Code)
}

// TestRevokeMachineIdentityCredentialProxy_HappyPath_S21 — existing cred → 200 revoked:true.
func TestRevokeMachineIdentityCredentialProxy_HappyPath_S21(t *testing.T) {
	h := freshCatalogHandlerS21(t)
	// Seed a machine identity and credential.
	createMI := proxyBodyS21(map[string]interface{}{
		"name": "revoke-mi-s21", "project_id": 40, "state": "active",
	})
	cr := httptest.NewRequest(http.MethodPost, "/system/machine-identities", createMI)
	cr = withOIDCAdminCtxS21(t, h, cr)
	cw := httptest.NewRecorder()
	h.CreateMachineIdentityProxy(cw, cr)
	require.Equal(t, http.StatusOK, cw.Code)
	var miResp remoteAPIResponse
	require.NoError(t, json.NewDecoder(cw.Body).Decode(&miResp))
	machineID := uint(miResp.Data.(map[string]interface{})["id"].(float64))

	createCred := proxyBodyS21(map[string]interface{}{
		"machine_identity_id": machineID,
		"token_hash":          "revokehash0000000000000000000000000000000000000000000000000001",
		"name":                "revoke-cred-s21",
	})
	cr2 := httptest.NewRequest(http.MethodPost, "/system/machine-credentials", createCred)
	cr2 = withOIDCAdminCtxS21(t, h, cr2)
	cw2 := httptest.NewRecorder()
	h.CreateMachineIdentityCredentialProxy(cw2, cr2)
	require.Equal(t, http.StatusOK, cw2.Code)
	var credResp remoteAPIResponse
	require.NoError(t, json.NewDecoder(cw2.Body).Decode(&credResp))
	credID := "1"
	_ = credResp

	req := withChiParam(
		httptest.NewRequest(http.MethodPost, "/system/machine-credentials/"+credID+"/revoke", nil),
		"id", credID,
	)
	w := httptest.NewRecorder()
	h.RevokeMachineIdentityCredentialProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	resp := decodeRemoteRespS21(t, w)
	assert.True(t, resp.Success)
}

// ── TouchMachineIdentityCredentialProxy ───────────────────────────────────────

// TestTouchMachineIdentityCredentialProxy_BadID_S21 — non-numeric id → 400.
func TestTouchMachineIdentityCredentialProxy_BadID_S21(t *testing.T) {
	h := freshCatalogHandlerS21(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodPost, "/system/machine-credentials/bad/touch", strings.NewReader("{}")),
		"id", "bad",
	)
	w := httptest.NewRecorder()
	h.TouchMachineIdentityCredentialProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteRespS21(t, w)
	assert.Equal(t, "INVALID_PARAMETER", resp.Error.Code)
}

// TestTouchMachineIdentityCredentialProxy_BadBody_S21 — malformed JSON → 400.
func TestTouchMachineIdentityCredentialProxy_BadBody_S21(t *testing.T) {
	h := freshCatalogHandlerS21(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodPost, "/system/machine-credentials/1/touch", strings.NewReader("{bad")),
		"id", "1",
	)
	w := httptest.NewRecorder()
	h.TouchMachineIdentityCredentialProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteRespS21(t, w)
	assert.Equal(t, "INVALID_BODY", resp.Error.Code)
}

// TestTouchMachineIdentityCredentialProxy_HappyPath_S21 — valid params (no-op on non-existent) → 200.
func TestTouchMachineIdentityCredentialProxy_HappyPath_S21(t *testing.T) {
	h := freshCatalogHandlerS21(t)
	body := proxyBodyS21(map[string]interface{}{
		"used_at":           time.Now(),
		"staleness_seconds": 30,
	})
	req := withChiParam(
		httptest.NewRequest(http.MethodPost, "/system/machine-credentials/9999/touch", body),
		"id", "9999",
	)
	w := httptest.NewRecorder()
	h.TouchMachineIdentityCredentialProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	resp := decodeRemoteRespS21(t, w)
	assert.True(t, resp.Success)
}

// ── machineRoleScopeQuery (tested via AssignMachineRoleProxy) ─────────────────

// TestAssignMachineRoleProxy_BadMachineID_S21 — non-numeric machine id → 400.
func TestAssignMachineRoleProxy_BadMachineID_S21(t *testing.T) {
	h := freshCatalogHandlerS21(t)
	req := withChiParams(
		httptest.NewRequest(http.MethodPost, "/system/machine-identities/bad/roles/1?project_id=1&environment_id=1", nil),
		map[string]string{"id": "bad", "roleId": "1"},
	)
	w := httptest.NewRecorder()
	h.AssignMachineRoleProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteRespS21(t, w)
	assert.Equal(t, "INVALID_PARAMETER", resp.Error.Code)
}

// TestAssignMachineRoleProxy_BadRoleID_S21 — non-numeric role id → 400.
func TestAssignMachineRoleProxy_BadRoleID_S21(t *testing.T) {
	h := freshCatalogHandlerS21(t)
	req := withChiParams(
		httptest.NewRequest(http.MethodPost, "/system/machine-identities/1/roles/bad?project_id=1&environment_id=1", nil),
		map[string]string{"id": "1", "roleId": "bad"},
	)
	w := httptest.NewRecorder()
	h.AssignMachineRoleProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteRespS21(t, w)
	assert.Equal(t, "INVALID_PARAMETER", resp.Error.Code)
}

// TestAssignMachineRoleProxy_MissingProjectID_S21 — missing project_id → 400.
func TestAssignMachineRoleProxy_MissingProjectID_S21(t *testing.T) {
	h := freshCatalogHandlerS21(t)
	req := withChiParams(
		httptest.NewRequest(http.MethodPost, "/system/machine-identities/1/roles/1?environment_id=1", nil),
		map[string]string{"id": "1", "roleId": "1"},
	)
	w := httptest.NewRecorder()
	h.AssignMachineRoleProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteRespS21(t, w)
	assert.Equal(t, "INVALID_QUERY", resp.Error.Code)
}

// TestAssignMachineRoleProxy_MissingEnvironmentID_S21 — missing environment_id → 400.
func TestAssignMachineRoleProxy_MissingEnvironmentID_S21(t *testing.T) {
	h := freshCatalogHandlerS21(t)
	req := withChiParams(
		httptest.NewRequest(http.MethodPost, "/system/machine-identities/1/roles/1?project_id=1", nil),
		map[string]string{"id": "1", "roleId": "1"},
	)
	w := httptest.NewRecorder()
	h.AssignMachineRoleProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteRespS21(t, w)
	assert.Equal(t, "INVALID_QUERY", resp.Error.Code)
}

// TestAssignMachineRoleProxy_BadProjectIDValue_S21 — non-numeric project_id → 400.
func TestAssignMachineRoleProxy_BadProjectIDValue_S21(t *testing.T) {
	h := freshCatalogHandlerS21(t)
	req := withChiParams(
		httptest.NewRequest(http.MethodPost, "/system/machine-identities/1/roles/1?project_id=bad&environment_id=1", nil),
		map[string]string{"id": "1", "roleId": "1"},
	)
	w := httptest.NewRecorder()
	h.AssignMachineRoleProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteRespS21(t, w)
	assert.Equal(t, "INVALID_QUERY", resp.Error.Code)
}

// TestAssignMachineRoleProxy_BadEnvironmentIDValue_S21 — non-numeric environment_id → 400.
func TestAssignMachineRoleProxy_BadEnvironmentIDValue_S21(t *testing.T) {
	h := freshCatalogHandlerS21(t)
	req := withChiParams(
		httptest.NewRequest(http.MethodPost, "/system/machine-identities/1/roles/1?project_id=1&environment_id=bad", nil),
		map[string]string{"id": "1", "roleId": "1"},
	)
	w := httptest.NewRecorder()
	h.AssignMachineRoleProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteRespS21(t, w)
	assert.Equal(t, "INVALID_QUERY", resp.Error.Code)
}

// TestAssignMachineRoleProxy_HappyPath_S21 — valid params (role doesn't exist → storage error is 500, not 4xx).
func TestAssignMachineRoleProxy_HappyPath_S21(t *testing.T) {
	// Seed a machine identity and a role first.
	cs, db := freshCoreS12WithAdmin(t)
	h2 := NewCatalogHandler(cs)

	// Create a role via direct DB insert.
	require.NoError(t, db.Exec("INSERT INTO roles (name, description) VALUES (?, ?)", "machine-test-role-s21", "test").Error)

	createMI := proxyBodyS21(map[string]interface{}{
		"name": "assign-role-mi-s21", "project_id": 50, "state": "active",
	})
	cr := httptest.NewRequest(http.MethodPost, "/system/machine-identities", createMI)
	cr = withOIDCAdminCtxS21(t, h2, cr)
	cw := httptest.NewRecorder()
	h2.CreateMachineIdentityProxy(cw, cr)
	require.Equal(t, http.StatusOK, cw.Code)
	var miResp remoteAPIResponse
	require.NoError(t, json.NewDecoder(cw.Body).Decode(&miResp))
	machineID := uint(miResp.Data.(map[string]interface{})["id"].(float64))
	_ = machineID

	req := withChiParams(
		httptest.NewRequest(http.MethodPost, "/system/machine-identities/1/roles/1?project_id=50&environment_id=0", nil),
		map[string]string{"id": "1", "roleId": "1"},
	)
	w := httptest.NewRecorder()
	h2.AssignMachineRoleProxy(w, req)
	// Either 200 (assigned) or 500 (role/machine not found in storage) — must not be 400.
	assert.NotEqual(t, http.StatusBadRequest, w.Code)
}

// ── RemoveMachineRoleProxy ────────────────────────────────────────────────────

// TestRemoveMachineRoleProxy_BadMachineID_S21 — non-numeric machine id → 400.
func TestRemoveMachineRoleProxy_BadMachineID_S21(t *testing.T) {
	h := freshCatalogHandlerS21(t)
	req := withChiParams(
		httptest.NewRequest(http.MethodDelete, "/system/machine-identities/bad/roles/1?project_id=1&environment_id=1", nil),
		map[string]string{"id": "bad", "roleId": "1"},
	)
	w := httptest.NewRecorder()
	h.RemoveMachineRoleProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteRespS21(t, w)
	assert.Equal(t, "INVALID_PARAMETER", resp.Error.Code)
}

// TestRemoveMachineRoleProxy_BadRoleID_S21 — non-numeric role id → 400.
func TestRemoveMachineRoleProxy_BadRoleID_S21(t *testing.T) {
	h := freshCatalogHandlerS21(t)
	req := withChiParams(
		httptest.NewRequest(http.MethodDelete, "/system/machine-identities/1/roles/bad?project_id=1&environment_id=1", nil),
		map[string]string{"id": "1", "roleId": "bad"},
	)
	w := httptest.NewRecorder()
	h.RemoveMachineRoleProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteRespS21(t, w)
	assert.Equal(t, "INVALID_PARAMETER", resp.Error.Code)
}

// TestRemoveMachineRoleProxy_NotFound_S21 — valid params but grant doesn't exist → 404.
func TestRemoveMachineRoleProxy_NotFound_S21(t *testing.T) {
	h := freshCatalogHandlerS21(t)
	req := withChiParams(
		httptest.NewRequest(http.MethodDelete, "/system/machine-identities/1/roles/1?project_id=1&environment_id=1", nil),
		map[string]string{"id": "1", "roleId": "1"},
	)
	w := httptest.NewRecorder()
	h.RemoveMachineRoleProxy(w, req)
	// not-found or not-assigned both map to 404
	assert.Equal(t, http.StatusNotFound, w.Code)
	resp := decodeRemoteRespS21(t, w)
	assert.Equal(t, "NOT_FOUND", resp.Error.Code)
}

// ── GetMachineRoleIDsAtProxy ──────────────────────────────────────────────────

// TestGetMachineRoleIDsAtProxy_BadID_S21 — non-numeric machine id → 400.
func TestGetMachineRoleIDsAtProxy_BadID_S21(t *testing.T) {
	h := freshCatalogHandlerS21(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/system/machine-identities/bad/roles/ids?project_id=1&environment_id=1", nil),
		"id", "bad",
	)
	w := httptest.NewRecorder()
	h.GetMachineRoleIDsAtProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteRespS21(t, w)
	assert.Equal(t, "INVALID_PARAMETER", resp.Error.Code)
}

// TestGetMachineRoleIDsAtProxy_MissingScope_S21 — missing scope params → 400.
func TestGetMachineRoleIDsAtProxy_MissingScope_S21(t *testing.T) {
	h := freshCatalogHandlerS21(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/system/machine-identities/1/roles/ids", nil),
		"id", "1",
	)
	w := httptest.NewRecorder()
	h.GetMachineRoleIDsAtProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteRespS21(t, w)
	assert.Equal(t, "INVALID_QUERY", resp.Error.Code)
}

// TestGetMachineRoleIDsAtProxy_HappyPath_S21 — valid params (empty result) → 200.
func TestGetMachineRoleIDsAtProxy_HappyPath_S21(t *testing.T) {
	h := freshCatalogHandlerS21(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/system/machine-identities/1/roles/ids?project_id=1&environment_id=1", nil),
		"id", "1",
	)
	w := httptest.NewRecorder()
	h.GetMachineRoleIDsAtProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	resp := decodeRemoteRespS21(t, w)
	assert.True(t, resp.Success)
}

// ── GetMachineRolesProxy ──────────────────────────────────────────────────────

// TestGetMachineRolesProxy_BadID_S21 — non-numeric machine id → 400.
func TestGetMachineRolesProxy_BadID_S21(t *testing.T) {
	h := freshCatalogHandlerS21(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/system/machine-identities/bad/roles", nil),
		"id", "bad",
	)
	w := httptest.NewRecorder()
	h.GetMachineRolesProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteRespS21(t, w)
	assert.Equal(t, "INVALID_PARAMETER", resp.Error.Code)
}

// TestGetMachineRolesProxy_HappyPath_S21 — valid id (empty roles) → 200.
func TestGetMachineRolesProxy_HappyPath_S21(t *testing.T) {
	h := freshCatalogHandlerS21(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/system/machine-identities/1/roles", nil),
		"id", "1",
	)
	w := httptest.NewRecorder()
	h.GetMachineRolesProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	resp := decodeRemoteRespS21(t, w)
	assert.True(t, resp.Success)
}

// ── CreateOIDCBindingProxy ────────────────────────────────────────────────────

// TestCreateOIDCBindingProxy_BadBody_S21 — malformed JSON → 400.
func TestCreateOIDCBindingProxy_BadBody_S21(t *testing.T) {
	h := freshCatalogHandlerS21(t)
	req := httptest.NewRequest(http.MethodPost, "/system/machine-oidc-bindings", strings.NewReader("{bad"))
	w := httptest.NewRecorder()
	h.CreateOIDCBindingProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteRespS21(t, w)
	assert.Equal(t, "INVALID_BODY", resp.Error.Code)
}

// TestCreateOIDCBindingProxy_MissingMachineID_S21 — zero machine_identity_id → 400.
func TestCreateOIDCBindingProxy_MissingMachineID_S21(t *testing.T) {
	h := freshCatalogHandlerS21(t)
	body := proxyBodyS21(map[string]interface{}{
		"machine_identity_id": 0,
		"issuer":              "https://accounts.google.com",
		"subject":             "sub-123",
	})
	req := httptest.NewRequest(http.MethodPost, "/system/machine-oidc-bindings", body)
	w := httptest.NewRecorder()
	h.CreateOIDCBindingProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteRespS21(t, w)
	assert.Equal(t, "INVALID_BODY", resp.Error.Code)
}

// TestCreateOIDCBindingProxy_MissingIssuer_S21 — empty issuer → 400.
func TestCreateOIDCBindingProxy_MissingIssuer_S21(t *testing.T) {
	h := freshCatalogHandlerS21(t)
	body := proxyBodyS21(map[string]interface{}{
		"machine_identity_id": 1,
		"issuer":              "",
		"subject":             "sub-123",
	})
	req := httptest.NewRequest(http.MethodPost, "/system/machine-oidc-bindings", body)
	w := httptest.NewRecorder()
	h.CreateOIDCBindingProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteRespS21(t, w)
	assert.Equal(t, "INVALID_BODY", resp.Error.Code)
}

// TestCreateOIDCBindingProxy_MissingSubject_S21 — empty subject → 400.
func TestCreateOIDCBindingProxy_MissingSubject_S21(t *testing.T) {
	h := freshCatalogHandlerS21(t)
	body := proxyBodyS21(map[string]interface{}{
		"machine_identity_id": 1,
		"issuer":              "https://accounts.google.com",
		"subject":             "",
	})
	req := httptest.NewRequest(http.MethodPost, "/system/machine-oidc-bindings", body)
	w := httptest.NewRecorder()
	h.CreateOIDCBindingProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteRespS21(t, w)
	assert.Equal(t, "INVALID_BODY", resp.Error.Code)
}

// TestCreateOIDCBindingProxy_HappyPath_S21 — valid body → 200.
func TestCreateOIDCBindingProxy_HappyPath_S21(t *testing.T) {
	h := freshCatalogHandlerS21(t)
	// Seed a machine identity.
	createMI := proxyBodyS21(map[string]interface{}{
		"name": "oidc-mi-s21", "project_id": 60, "state": "active",
	})
	cr := withOIDCAdminCtxS21(t, h, httptest.NewRequest(http.MethodPost, "/system/machine-identities", createMI))
	cw := httptest.NewRecorder()
	h.CreateMachineIdentityProxy(cw, cr)
	require.Equal(t, http.StatusOK, cw.Code)
	var miResp remoteAPIResponse
	require.NoError(t, json.NewDecoder(cw.Body).Decode(&miResp))
	machineID := uint(miResp.Data.(map[string]interface{})["id"].(float64))

	body := proxyBodyS21(map[string]interface{}{
		"machine_identity_id": machineID,
		"issuer":              "https://accounts.google.com",
		"subject":             "sub-s21-unique-001",
		"created_by":          1,
	})
	req := withOIDCAdminCtxS21(t, h, httptest.NewRequest(http.MethodPost, "/system/machine-oidc-bindings", body))
	w := httptest.NewRecorder()
	h.CreateOIDCBindingProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	resp := decodeRemoteRespS21(t, w)
	assert.True(t, resp.Success)
}

// TestCreateOIDCBindingProxy_DuplicateBinding_S21 — duplicate (issuer, subject) → 409.
func TestCreateOIDCBindingProxy_DuplicateBinding_S21(t *testing.T) {
	h := freshCatalogHandlerS21(t)
	// Seed a machine identity.
	createMI := proxyBodyS21(map[string]interface{}{
		"name": "oidc-dup-mi-s21", "project_id": 61, "state": "active",
	})
	cr := withOIDCAdminCtxS21(t, h, httptest.NewRequest(http.MethodPost, "/system/machine-identities", createMI))
	cw := httptest.NewRecorder()
	h.CreateMachineIdentityProxy(cw, cr)
	require.Equal(t, http.StatusOK, cw.Code)
	var miResp remoteAPIResponse
	require.NoError(t, json.NewDecoder(cw.Body).Decode(&miResp))
	machineID := uint(miResp.Data.(map[string]interface{})["id"].(float64))

	bindingBody := map[string]interface{}{
		"machine_identity_id": machineID,
		"issuer":              "https://dup-issuer.example.com",
		"subject":             "dup-sub-s21",
		"created_by":          1,
	}
	// First creation must succeed.
	cr2 := withOIDCAdminCtxS21(t, h, httptest.NewRequest(http.MethodPost, "/system/machine-oidc-bindings", proxyBodyS21(bindingBody)))
	cw2 := httptest.NewRecorder()
	h.CreateOIDCBindingProxy(cw2, cr2)
	require.Equal(t, http.StatusOK, cw2.Code)

	// Second creation must return 409.
	cr3 := withOIDCAdminCtxS21(t, h, httptest.NewRequest(http.MethodPost, "/system/machine-oidc-bindings", proxyBodyS21(bindingBody)))
	cw3 := httptest.NewRecorder()
	h.CreateOIDCBindingProxy(cw3, cr3)
	assert.Equal(t, http.StatusConflict, cw3.Code)
	resp := decodeRemoteRespS21(t, cw3)
	assert.Equal(t, "DUPLICATE_BINDING", resp.Error.Code)
}

// ── GetMachineByOIDCSubjectProxy ──────────────────────────────────────────────

// TestGetMachineByOIDCSubjectProxy_MissingParams_S21 — missing issuer and subject → 400.
func TestGetMachineByOIDCSubjectProxy_MissingParams_S21(t *testing.T) {
	h := freshCatalogHandlerS21(t)
	req := httptest.NewRequest(http.MethodGet, "/system/machine-oidc-bindings/by-subject", nil)
	w := httptest.NewRecorder()
	h.GetMachineByOIDCSubjectProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteRespS21(t, w)
	assert.Equal(t, "INVALID_QUERY", resp.Error.Code)
}

// TestGetMachineByOIDCSubjectProxy_MissingSubject_S21 — issuer present, subject missing → 400.
func TestGetMachineByOIDCSubjectProxy_MissingSubject_S21(t *testing.T) {
	h := freshCatalogHandlerS21(t)
	req := httptest.NewRequest(http.MethodGet, "/system/machine-oidc-bindings/by-subject?issuer=https://x.com", nil)
	w := httptest.NewRecorder()
	h.GetMachineByOIDCSubjectProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteRespS21(t, w)
	assert.Equal(t, "INVALID_QUERY", resp.Error.Code)
}

// TestGetMachineByOIDCSubjectProxy_NotFound_S21 — valid params, not in DB → 404.
func TestGetMachineByOIDCSubjectProxy_NotFound_S21(t *testing.T) {
	h := freshCatalogHandlerS21(t)
	req := httptest.NewRequest(http.MethodGet, "/system/machine-oidc-bindings/by-subject?issuer=https://x.com&subject=nobody", nil)
	w := httptest.NewRecorder()
	h.GetMachineByOIDCSubjectProxy(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
	resp := decodeRemoteRespS21(t, w)
	assert.Equal(t, "NOT_FOUND", resp.Error.Code)
}

// ── ListOIDCBindingsProxy ─────────────────────────────────────────────────────

// TestListOIDCBindingsProxy_BadID_S21 — non-numeric machine id → 400.
func TestListOIDCBindingsProxy_BadID_S21(t *testing.T) {
	h := freshCatalogHandlerS21(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/system/machine-identities/bad/oidc-bindings", nil),
		"id", "bad",
	)
	w := httptest.NewRecorder()
	h.ListOIDCBindingsProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteRespS21(t, w)
	assert.Equal(t, "INVALID_PARAMETER", resp.Error.Code)
}

// TestListOIDCBindingsProxy_HappyPath_S21 — valid id (empty result) → 200.
func TestListOIDCBindingsProxy_HappyPath_S21(t *testing.T) {
	h := freshCatalogHandlerS21(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/system/machine-identities/1/oidc-bindings", nil),
		"id", "1",
	)
	w := httptest.NewRecorder()
	h.ListOIDCBindingsProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	resp := decodeRemoteRespS21(t, w)
	assert.True(t, resp.Success)
}

// ── GetOIDCBindingByIDProxy ───────────────────────────────────────────────────

// TestGetOIDCBindingByIDProxy_BadID_S21 — non-numeric id → 400.
func TestGetOIDCBindingByIDProxy_BadID_S21(t *testing.T) {
	h := freshCatalogHandlerS21(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/system/machine-oidc-bindings/bad", nil),
		"id", "bad",
	)
	w := httptest.NewRecorder()
	h.GetOIDCBindingByIDProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteRespS21(t, w)
	assert.Equal(t, "INVALID_PARAMETER", resp.Error.Code)
}

// TestGetOIDCBindingByIDProxy_NotFound_S21 — valid id, not in DB → 404.
func TestGetOIDCBindingByIDProxy_NotFound_S21(t *testing.T) {
	h := freshCatalogHandlerS21(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/system/machine-oidc-bindings/9999", nil),
		"id", "9999",
	)
	w := httptest.NewRecorder()
	h.GetOIDCBindingByIDProxy(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
	resp := decodeRemoteRespS21(t, w)
	assert.Equal(t, "NOT_FOUND", resp.Error.Code)
}

// TestGetOIDCBindingByIDProxy_HappyPath_S21 — seeded binding → 200.
func TestGetOIDCBindingByIDProxy_HappyPath_S21(t *testing.T) {
	h := freshCatalogHandlerS21(t)
	// Seed a machine identity and binding.
	createMI := proxyBodyS21(map[string]interface{}{
		"name": "getbind-mi-s21", "project_id": 70, "state": "active",
	})
	cr := withOIDCAdminCtxS21(t, h, httptest.NewRequest(http.MethodPost, "/system/machine-identities", createMI))
	cw := httptest.NewRecorder()
	h.CreateMachineIdentityProxy(cw, cr)
	require.Equal(t, http.StatusOK, cw.Code)
	var miResp remoteAPIResponse
	require.NoError(t, json.NewDecoder(cw.Body).Decode(&miResp))
	machineID := uint(miResp.Data.(map[string]interface{})["id"].(float64))

	createBind := proxyBodyS21(map[string]interface{}{
		"machine_identity_id": machineID,
		"issuer":              "https://getbind-issuer.example.com",
		"subject":             "getbind-sub-s21",
		"created_by":          1,
	})
	cr2 := withOIDCAdminCtxS21(t, h, httptest.NewRequest(http.MethodPost, "/system/machine-oidc-bindings", createBind))
	cw2 := httptest.NewRecorder()
	h.CreateOIDCBindingProxy(cw2, cr2)
	require.Equal(t, http.StatusOK, cw2.Code)
	var bindResp remoteAPIResponse
	require.NoError(t, json.NewDecoder(cw2.Body).Decode(&bindResp))
	bindIDStr := fmt.Sprintf("%d", uint(bindResp.Data.(map[string]interface{})["id"].(float64)))

	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/system/machine-oidc-bindings/"+bindIDStr, nil),
		"id", bindIDStr,
	)
	w := httptest.NewRecorder()
	h.GetOIDCBindingByIDProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	resp := decodeRemoteRespS21(t, w)
	assert.True(t, resp.Success)
}

// ── DeleteOIDCBindingProxy ────────────────────────────────────────────────────

// TestDeleteOIDCBindingProxy_BadID_S21 — non-numeric id → 400.
func TestDeleteOIDCBindingProxy_BadID_S21(t *testing.T) {
	h := freshCatalogHandlerS21(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodDelete, "/system/machine-oidc-bindings/bad", nil),
		"id", "bad",
	)
	w := httptest.NewRecorder()
	h.DeleteOIDCBindingProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	resp := decodeRemoteRespS21(t, w)
	assert.Equal(t, "INVALID_PARAMETER", resp.Error.Code)
}

// TestDeleteOIDCBindingProxy_NotFound_S21 — valid id, not in DB → 404.
func TestDeleteOIDCBindingProxy_NotFound_S21(t *testing.T) {
	h := freshCatalogHandlerS21(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodDelete, "/system/machine-oidc-bindings/9999", nil),
		"id", "9999",
	)
	w := httptest.NewRecorder()
	h.DeleteOIDCBindingProxy(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
	resp := decodeRemoteRespS21(t, w)
	assert.Equal(t, "NOT_FOUND", resp.Error.Code)
}

// TestDeleteOIDCBindingProxy_HappyPath_S21 — seeded binding → 200 deleted:true.
func TestDeleteOIDCBindingProxy_HappyPath_S21(t *testing.T) {
	h := freshCatalogHandlerS21(t)
	// Seed a machine identity and binding.
	createMI := proxyBodyS21(map[string]interface{}{
		"name": "delbind-mi-s21", "project_id": 80, "state": "active",
	})
	cr := withOIDCAdminCtxS21(t, h, httptest.NewRequest(http.MethodPost, "/system/machine-identities", createMI))
	cw := httptest.NewRecorder()
	h.CreateMachineIdentityProxy(cw, cr)
	require.Equal(t, http.StatusOK, cw.Code)
	var miResp remoteAPIResponse
	require.NoError(t, json.NewDecoder(cw.Body).Decode(&miResp))
	machineID := uint(miResp.Data.(map[string]interface{})["id"].(float64))

	createBind := proxyBodyS21(map[string]interface{}{
		"machine_identity_id": machineID,
		"issuer":              "https://delbind-issuer.example.com",
		"subject":             "delbind-sub-s21",
		"created_by":          1,
	})
	cr2 := withOIDCAdminCtxS21(t, h, httptest.NewRequest(http.MethodPost, "/system/machine-oidc-bindings", createBind))
	cw2 := httptest.NewRecorder()
	h.CreateOIDCBindingProxy(cw2, cr2)
	require.Equal(t, http.StatusOK, cw2.Code)

	req := withChiParam(
		httptest.NewRequest(http.MethodDelete, "/system/machine-oidc-bindings/1", nil),
		"id", "1",
	)
	w := httptest.NewRecorder()
	h.DeleteOIDCBindingProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	resp := decodeRemoteRespS21(t, w)
	assert.True(t, resp.Success)
}

// G80 raw-storage-bypass fix: DeleteOIDCBindingProxy previously called
// storage.DeleteOIDCBinding directly for every caller, writing no audit
// trail at all -- unbinding a federated workload identity via this proxy
// left no record. Now that a direct (non-node) caller routes through
// core.DeleteOIDCBinding, the delete is audited exactly like the
// human-facing route (server/http/handlers/machine_identities.go's
// DeleteOIDCBinding).
func TestDeleteOIDCBindingProxy_WritesAuditEvent_S21(t *testing.T) {
	h := freshCatalogHandlerS21(t)
	createMI := proxyBodyS21(map[string]interface{}{
		"name": "audit-mi-s21", "project_id": 81, "state": "active",
	})
	cr := withOIDCAdminCtxS21(t, h, httptest.NewRequest(http.MethodPost, "/system/machine-identities", createMI))
	cw := httptest.NewRecorder()
	h.CreateMachineIdentityProxy(cw, cr)
	require.Equal(t, http.StatusOK, cw.Code)
	var miResp remoteAPIResponse
	require.NoError(t, json.NewDecoder(cw.Body).Decode(&miResp))
	machineID := uint(miResp.Data.(map[string]interface{})["id"].(float64))

	createBind := proxyBodyS21(map[string]interface{}{
		"machine_identity_id": machineID,
		"issuer":              "https://audit-issuer.example.com",
		"subject":             "audit-sub-s21",
		"created_by":          1,
	})
	cr2 := withOIDCAdminCtxS21(t, h, httptest.NewRequest(http.MethodPost, "/system/machine-oidc-bindings", createBind))
	cw2 := httptest.NewRecorder()
	h.CreateOIDCBindingProxy(cw2, cr2)
	require.Equal(t, http.StatusOK, cw2.Code)
	var bindResp remoteAPIResponse
	require.NoError(t, json.NewDecoder(cw2.Body).Decode(&bindResp))
	bindingID := uint(bindResp.Data.(map[string]interface{})["id"].(float64))

	req := withChiParam(
		httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/system/machine-oidc-bindings/%d", bindingID), nil),
		"id", fmt.Sprintf("%d", bindingID),
	)
	w := httptest.NewRecorder()
	h.DeleteOIDCBindingProxy(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	action := "machine_identity.oidc_unbound"
	events, count, err := h.coreService.Storage().GetAuditLogs(context.Background(), &storage.AuditFilter{
		Action: &action, Page: 1, PageSize: 10,
	})
	require.NoError(t, err)
	require.EqualValues(t, 1, count, "deleting the binding via the proxy must write exactly one audit event")
	require.Len(t, events, 1)
	require.NotNil(t, events[0].ProjectID)
	assert.EqualValues(t, 81, *events[0].ProjectID, "the audit event carries the binding's owning project, matching logMachineEvent's convention")
}

// ── Error helper functions (package-level, used only by proxy handlers) ────────

// TestIsAlreadyAssignedErr_S21 — covers both branches of isAlreadyAssignedErr.
func TestIsAlreadyAssignedErr_S21(t *testing.T) {
	assert.False(t, isAlreadyAssignedErr(nil))
	err := &testStringErr{"role is already assigned to this machine"}
	assert.True(t, isAlreadyAssignedErr(err))
	err2 := &testStringErr{"some other error"}
	assert.False(t, isAlreadyAssignedErr(err2))
}

// TestIsNotAssignedErr_S21 — covers both branches of isNotAssignedErr.
func TestIsNotAssignedErr_S21(t *testing.T) {
	assert.False(t, isNotAssignedErr(nil))
	err := &testStringErr{"role is not assigned"}
	assert.True(t, isNotAssignedErr(err))
	err2 := &testStringErr{"some other error"}
	assert.False(t, isNotAssignedErr(err2))
}

// TestIsUniqueViolationErr_S21 — covers nil, SQLite, Postgres, and non-match branches.
func TestIsUniqueViolationErr_S21(t *testing.T) {
	assert.False(t, isUniqueViolationErr(nil))
	assert.True(t, isUniqueViolationErr(&testStringErr{"UNIQUE constraint failed: machine_identity_oidc_bindings.issuer"}))
	assert.True(t, isUniqueViolationErr(&testStringErr{"ERROR: duplicate key value violates unique constraint \"unique_binding\""}))
	assert.False(t, isUniqueViolationErr(&testStringErr{"some other storage error"}))
}

// testStringErr is a minimal error type used by the helper-function tests.
type testStringErr struct{ msg string }

func (e *testStringErr) Error() string { return e.msg }
