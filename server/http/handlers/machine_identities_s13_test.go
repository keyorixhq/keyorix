// machine_identities_s13_test.go — coverage sweep for uncovered branches in:
//   - machine_identities.go: bad-param, missing user ctx, not-found, invalid
//     action, missing name, invalid role body, invalid binding-id, bad machineId,
//     bad tokenId, bad roleId, bad bindingId
//   - machine_identities_proxy.go: bad-param, missing/invalid body, missing
//     project_id query, missing scope params, not-found, invalid body for
//     transition, missing from_state, bad credential ID, bad hash path
//   - machine_token_hygiene.go: missing user ctx, days cap, happy path
package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// machineHandlerS13 returns a CatalogHandler backed by a fresh admin-seeded core.
func machineHandlerS13(t *testing.T) *CatalogHandler {
	t.Helper()
	cs, _ := freshCoreS12WithAdmin(t)
	return NewCatalogHandler(cs)
}

// machineHandlerWithProjectS13 builds a CatalogHandler and also seeds a
// project row — callers use the returned project ID.
func machineHandlerWithProjectS13(t *testing.T) (*CatalogHandler, uint) {
	t.Helper()
	cs, db := freshCoreS12WithAdmin(t)
	proj := &models.Project{Name: "test-proj-mach-s13"}
	require.NoError(t, db.Create(proj).Error)
	return NewCatalogHandler(cs), proj.ID
}

// machineUintToStr converts a uint to its decimal string representation.
func machineUintToStr(n uint) string {
	return strconv.FormatUint(uint64(n), 10)
}

// ── machine_identities.go: ListMachineIdentities ─────────────────────────────

func TestListMachineIdentities_BadProjectID_S13(t *testing.T) {
	h := machineHandlerS13(t)
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodGet, "/api/v1/projects/notanid/machine-identities", nil),
		"id", "notanid",
	))
	w := httptest.NewRecorder()
	h.ListMachineIdentities(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListMachineIdentities_HappyPath_S13(t *testing.T) {
	h, projID := machineHandlerWithProjectS13(t)
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodGet, "/api/v1/projects/1/machine-identities", nil),
		"id", machineUintToStr(projID),
	))
	w := httptest.NewRecorder()
	h.ListMachineIdentities(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── machine_identities.go: ListStaleMachineIdentities ────────────────────────

func TestListStaleMachineIdentities_BadProjectID_S13(t *testing.T) {
	h := machineHandlerS13(t)
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodGet, "/api/v1/projects/bad/machine-identities/stale", nil),
		"id", "bad",
	))
	w := httptest.NewRecorder()
	h.ListStaleMachineIdentities(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListStaleMachineIdentities_DaysCap_S13(t *testing.T) {
	h, projID := machineHandlerWithProjectS13(t)
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodGet, "/api/v1/projects/1/machine-identities/stale?days=99999", nil),
		"id", machineUintToStr(projID),
	))
	w := httptest.NewRecorder()
	h.ListStaleMachineIdentities(w, req)
	// days capped to 3650 → still a valid call, returns 200
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestListStaleMachineIdentities_InvalidDaysIgnored_S13(t *testing.T) {
	h, projID := machineHandlerWithProjectS13(t)
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodGet, "/api/v1/projects/1/machine-identities/stale?days=notanumber", nil),
		"id", machineUintToStr(projID),
	))
	w := httptest.NewRecorder()
	h.ListStaleMachineIdentities(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── machine_identities.go: CreateMachineIdentity ─────────────────────────────

func TestCreateMachineIdentity_BadProjectID_S13(t *testing.T) {
	h := machineHandlerS13(t)
	body, _ := json.Marshal(map[string]string{"name": "bot"})
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPost, "/api/v1/projects/bad/machine-identities",
			bytes.NewReader(body)),
		"id", "bad",
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateMachineIdentity(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateMachineIdentity_MissingUserCtx_S13(t *testing.T) {
	h := machineHandlerS13(t)
	body, _ := json.Marshal(map[string]string{"name": "bot"})
	req := withChiParam(
		httptest.NewRequest(http.MethodPost, "/api/v1/projects/1/machine-identities",
			bytes.NewReader(body)),
		"id", "1",
	)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateMachineIdentity(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestCreateMachineIdentity_MissingName_S13(t *testing.T) {
	h, projID := machineHandlerWithProjectS13(t)
	body, _ := json.Marshal(map[string]string{"description": "no name"})
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPost, "/api/v1/projects/1/machine-identities",
			bytes.NewReader(body)),
		"id", machineUintToStr(projID),
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateMachineIdentity(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateMachineIdentity_InvalidBody_S13(t *testing.T) {
	h, projID := machineHandlerWithProjectS13(t)
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPost, "/api/v1/projects/1/machine-identities",
			strings.NewReader("not json{{")),
		"id", machineUintToStr(projID),
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateMachineIdentity(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── machine_identities.go: TransitionMachineIdentity ─────────────────────────

func TestTransitionMachineIdentity_BadMachineID_S13(t *testing.T) {
	h, projID := machineHandlerWithProjectS13(t)
	body, _ := json.Marshal(map[string]string{"action": "activate"})
	req := withUserCtx(withChiParams(
		httptest.NewRequest(http.MethodPut, "/", bytes.NewReader(body)),
		map[string]string{"id": machineUintToStr(projID), "machineId": "notanid"},
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.TransitionMachineIdentity(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestTransitionMachineIdentity_InvalidAction_S13(t *testing.T) {
	h, projID := machineHandlerWithProjectS13(t)
	body, _ := json.Marshal(map[string]string{"action": "unknownaction"})
	req := withUserCtx(withChiParams(
		httptest.NewRequest(http.MethodPut, "/", bytes.NewReader(body)),
		map[string]string{"id": machineUintToStr(projID), "machineId": "1"},
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.TransitionMachineIdentity(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestTransitionMachineIdentity_NotFound_S13(t *testing.T) {
	h, projID := machineHandlerWithProjectS13(t)
	body, _ := json.Marshal(map[string]string{"action": "activate"})
	req := withUserCtx(withChiParams(
		httptest.NewRequest(http.MethodPut, "/", bytes.NewReader(body)),
		map[string]string{"id": machineUintToStr(projID), "machineId": "9999"},
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.TransitionMachineIdentity(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── machine_identities.go: IssueMachineToken ─────────────────────────────────

func TestIssueMachineToken_BadMachineID_S13(t *testing.T) {
	h, projID := machineHandlerWithProjectS13(t)
	body, _ := json.Marshal(map[string]string{"name": "mytoken"})
	req := withUserCtx(withChiParams(
		httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body)),
		map[string]string{"id": machineUintToStr(projID), "machineId": "bad"},
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.IssueMachineToken(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestIssueMachineToken_NotFound_S13(t *testing.T) {
	h, projID := machineHandlerWithProjectS13(t)
	body, _ := json.Marshal(map[string]string{"name": "mytoken"})
	req := withUserCtx(withChiParams(
		httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body)),
		map[string]string{"id": machineUintToStr(projID), "machineId": "9999"},
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.IssueMachineToken(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestIssueMachineToken_BadProjectID_S13(t *testing.T) {
	h := machineHandlerS13(t)
	body, _ := json.Marshal(map[string]string{"name": "tok"})
	req := withUserCtx(withChiParams(
		httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body)),
		map[string]string{"id": "bad", "machineId": "1"},
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.IssueMachineToken(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── machine_identities.go: ListMachineTokens ─────────────────────────────────

func TestListMachineTokens_BadMachineID_S13(t *testing.T) {
	h, projID := machineHandlerWithProjectS13(t)
	req := withUserCtx(withChiParams(
		httptest.NewRequest(http.MethodGet, "/", nil),
		map[string]string{"id": machineUintToStr(projID), "machineId": "bad"},
	))
	w := httptest.NewRecorder()
	h.ListMachineTokens(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── machine_identities.go: RevokeMachineToken ────────────────────────────────

func TestRevokeMachineToken_BadProjectID_S13(t *testing.T) {
	h := machineHandlerS13(t)
	req := withUserCtx(withChiParams(
		httptest.NewRequest(http.MethodDelete, "/", nil),
		map[string]string{"id": "bad", "machineId": "1", "tokenId": "1"},
	))
	w := httptest.NewRecorder()
	h.RevokeMachineToken(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRevokeMachineToken_BadMachineID_S13(t *testing.T) {
	h, projID := machineHandlerWithProjectS13(t)
	req := withUserCtx(withChiParams(
		httptest.NewRequest(http.MethodDelete, "/", nil),
		map[string]string{"id": machineUintToStr(projID), "machineId": "bad", "tokenId": "1"},
	))
	w := httptest.NewRecorder()
	h.RevokeMachineToken(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRevokeMachineToken_BadTokenID_S13(t *testing.T) {
	h, projID := machineHandlerWithProjectS13(t)
	req := withUserCtx(withChiParams(
		httptest.NewRequest(http.MethodDelete, "/", nil),
		map[string]string{"id": machineUintToStr(projID), "machineId": "1", "tokenId": "bad"},
	))
	w := httptest.NewRecorder()
	h.RevokeMachineToken(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRevokeMachineToken_NotFound_S13(t *testing.T) {
	h, projID := machineHandlerWithProjectS13(t)
	req := withUserCtx(withChiParams(
		httptest.NewRequest(http.MethodDelete, "/", nil),
		map[string]string{"id": machineUintToStr(projID), "machineId": "9999", "tokenId": "9999"},
	))
	w := httptest.NewRecorder()
	h.RevokeMachineToken(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── machine_identities.go: ClassifyMachineIdentity ───────────────────────────

func TestClassifyMachineIdentity_BadProjectID_S13(t *testing.T) {
	h := machineHandlerS13(t)
	body, _ := json.Marshal(map[string]string{"classification": "public"})
	req := withUserCtx(withChiParams(
		httptest.NewRequest(http.MethodPatch, "/", bytes.NewReader(body)),
		map[string]string{"id": "bad", "machineId": "1"},
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ClassifyMachineIdentity(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestClassifyMachineIdentity_BadMachineID_S13(t *testing.T) {
	h, projID := machineHandlerWithProjectS13(t)
	body, _ := json.Marshal(map[string]string{"classification": "public"})
	req := withUserCtx(withChiParams(
		httptest.NewRequest(http.MethodPatch, "/", bytes.NewReader(body)),
		map[string]string{"id": machineUintToStr(projID), "machineId": "bad"},
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ClassifyMachineIdentity(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestClassifyMachineIdentity_NotFound_S13(t *testing.T) {
	h, projID := machineHandlerWithProjectS13(t)
	body, _ := json.Marshal(map[string]string{"classification": "public"})
	req := withUserCtx(withChiParams(
		httptest.NewRequest(http.MethodPatch, "/", bytes.NewReader(body)),
		map[string]string{"id": machineUintToStr(projID), "machineId": "9999"},
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ClassifyMachineIdentity(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── machine_identities.go: ClassifyMachineToken ──────────────────────────────

func TestClassifyMachineToken_BadTokenID_S13(t *testing.T) {
	h, projID := machineHandlerWithProjectS13(t)
	body, _ := json.Marshal(map[string]string{"classification": "public"})
	req := withUserCtx(withChiParams(
		httptest.NewRequest(http.MethodPatch, "/", bytes.NewReader(body)),
		map[string]string{"id": machineUintToStr(projID), "machineId": "1", "tokenId": "bad"},
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ClassifyMachineToken(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestClassifyMachineToken_NotFound_S13(t *testing.T) {
	h, projID := machineHandlerWithProjectS13(t)
	body, _ := json.Marshal(map[string]string{"classification": "public"})
	req := withUserCtx(withChiParams(
		httptest.NewRequest(http.MethodPatch, "/", bytes.NewReader(body)),
		map[string]string{"id": machineUintToStr(projID), "machineId": "9999", "tokenId": "9999"},
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ClassifyMachineToken(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── machine_identities.go: GrantMachineRole / RemoveMachineRole ──────────────

func TestGrantMachineRole_BadProjectID_S13(t *testing.T) {
	h := machineHandlerS13(t)
	body, _ := json.Marshal(map[string]uint{"role_id": 1})
	req := withUserCtx(withChiParams(
		httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body)),
		map[string]string{"id": "bad", "machineId": "1"},
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.GrantMachineRole(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGrantMachineRole_BadMachineID_S13(t *testing.T) {
	h, projID := machineHandlerWithProjectS13(t)
	body, _ := json.Marshal(map[string]uint{"role_id": 1})
	req := withUserCtx(withChiParams(
		httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body)),
		map[string]string{"id": machineUintToStr(projID), "machineId": "bad"},
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.GrantMachineRole(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGrantMachineRole_MissingRoleID_S13(t *testing.T) {
	h, projID := machineHandlerWithProjectS13(t)
	body, _ := json.Marshal(map[string]string{}) // role_id is 0 / missing
	req := withUserCtx(withChiParams(
		httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body)),
		map[string]string{"id": machineUintToStr(projID), "machineId": "1"},
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.GrantMachineRole(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRemoveMachineRole_BadRoleID_S13(t *testing.T) {
	h, projID := machineHandlerWithProjectS13(t)
	req := withUserCtx(withChiParams(
		httptest.NewRequest(http.MethodDelete, "/", nil),
		map[string]string{"id": machineUintToStr(projID), "machineId": "1", "roleId": "bad"},
	))
	w := httptest.NewRecorder()
	h.RemoveMachineRole(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRemoveMachineRole_NotFound_S13(t *testing.T) {
	h, projID := machineHandlerWithProjectS13(t)
	req := withUserCtx(withChiParams(
		httptest.NewRequest(http.MethodDelete, "/", nil),
		map[string]string{"id": machineUintToStr(projID), "machineId": "9999", "roleId": "9999"},
	))
	w := httptest.NewRecorder()
	h.RemoveMachineRole(w, req)
	// "not assigned" → 409 Conflict or "not found" → 404
	assert.True(t, w.Code == http.StatusNotFound || w.Code == http.StatusConflict)
}

// ── machine_identities.go: CreateOIDCBinding ─────────────────────────────────

func TestCreateOIDCBinding_BadProjectID_S13(t *testing.T) {
	h := machineHandlerS13(t)
	body, _ := json.Marshal(map[string]string{"issuer": "https://id.example", "subject": "sub"})
	req := withUserCtx(withChiParams(
		httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body)),
		map[string]string{"id": "bad", "machineId": "1"},
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateOIDCBinding(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateOIDCBinding_NotFound_S13(t *testing.T) {
	h, projID := machineHandlerWithProjectS13(t)
	body, _ := json.Marshal(map[string]string{"issuer": "https://id.example", "subject": "sub"})
	req := withUserCtx(withChiParams(
		httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body)),
		map[string]string{"id": machineUintToStr(projID), "machineId": "9999"},
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateOIDCBinding(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── machine_identities.go: ListOIDCBindings ──────────────────────────────────

func TestListOIDCBindings_BadProjectID_S13(t *testing.T) {
	h := machineHandlerS13(t)
	req := withUserCtx(withChiParams(
		httptest.NewRequest(http.MethodGet, "/", nil),
		map[string]string{"id": "bad", "machineId": "1"},
	))
	w := httptest.NewRecorder()
	h.ListOIDCBindings(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListOIDCBindings_MachineNotFound_S13(t *testing.T) {
	h, projID := machineHandlerWithProjectS13(t)
	req := withUserCtx(withChiParams(
		httptest.NewRequest(http.MethodGet, "/", nil),
		map[string]string{"id": machineUintToStr(projID), "machineId": "9999"},
	))
	w := httptest.NewRecorder()
	h.ListOIDCBindings(w, req)
	// machine doesn't exist → core returns "not found" → 404
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── machine_identities.go: DeleteOIDCBinding ─────────────────────────────────

func TestDeleteOIDCBinding_BadBindingID_S13(t *testing.T) {
	h, projID := machineHandlerWithProjectS13(t)
	req := withUserCtx(withChiParams(
		httptest.NewRequest(http.MethodDelete, "/", nil),
		map[string]string{"id": machineUintToStr(projID), "machineId": "1", "bindingId": "bad"},
	))
	w := httptest.NewRecorder()
	h.DeleteOIDCBinding(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDeleteOIDCBinding_NotFound_S13(t *testing.T) {
	h, projID := machineHandlerWithProjectS13(t)
	req := withUserCtx(withChiParams(
		httptest.NewRequest(http.MethodDelete, "/", nil),
		map[string]string{"id": machineUintToStr(projID), "machineId": "1", "bindingId": "9999"},
	))
	w := httptest.NewRecorder()
	h.DeleteOIDCBinding(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── machine_token_hygiene.go ─────────────────────────────────────────────────

func TestMachineTokenHygiene_MissingUserCtx_S13(t *testing.T) {
	h := machineHandlerS13(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/machine-token-hygiene", nil)
	// no withUserCtx → GetUserFromContext returns nil
	w := httptest.NewRecorder()
	h.MachineTokenHygiene(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestMachineTokenHygiene_HappyPath_S13(t *testing.T) {
	h := machineHandlerS13(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/machine-token-hygiene", nil))
	w := httptest.NewRecorder()
	h.MachineTokenHygiene(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestMachineTokenHygiene_DaysCap_S13(t *testing.T) {
	h := machineHandlerS13(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/machine-token-hygiene?days=99999", nil))
	w := httptest.NewRecorder()
	h.MachineTokenHygiene(w, req)
	// days capped to 3650 → valid call, returns 200
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestMachineTokenHygiene_InvalidDaysIgnored_S13(t *testing.T) {
	h := machineHandlerS13(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/machine-token-hygiene?days=notanumber", nil))
	w := httptest.NewRecorder()
	h.MachineTokenHygiene(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── machine_identities_proxy.go: CreateMachineIdentityProxy ──────────────────

func TestCreateMachineIdentityProxy_InvalidBody_S13(t *testing.T) {
	h := machineHandlerS13(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/system/machine-identities",
		strings.NewReader("not json{{"))
	w := httptest.NewRecorder()
	h.CreateMachineIdentityProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateMachineIdentityProxy_MissingFields_S13(t *testing.T) {
	h := machineHandlerS13(t)
	body, _ := json.Marshal(map[string]string{"name": "only-name"}) // missing project_id
	req := httptest.NewRequest(http.MethodPost, "/api/v1/system/machine-identities",
		bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.CreateMachineIdentityProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestCreateMachineIdentityProxy_MachineCallerAttributionDistinguishable is
// the #1623 regression for this handler: a machine identity that creates
// ANOTHER machine identity (a machine provisioning a machine) must be
// recorded via CreatedByMachineIdentityID, not stamped into CreatedBy where
// it would be indistinguishable from a real User.ID sharing the same number.
func TestCreateMachineIdentityProxy_MachineCallerAttributionDistinguishable(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	catalog := NewCatalogHandler(cs)
	proj := &models.Project{Name: "test-proj-mach-1623"}
	require.NoError(t, db.Create(proj).Error)

	const callerMachineID = 42
	require.NoError(t, db.AutoMigrate(&models.MachineIdentity{}, &models.MachineIdentityRole{}))
	require.NoError(t, db.Create(&models.MachineIdentity{
		ID: callerMachineID, ProjectID: proj.ID, Name: "provisioner", IdentityType: "automation", State: "active",
	}).Error)

	// Grant the calling machine identity roles.assign at the target project --
	// RequireMachinePrivilegeCeiling's fallback path for a brand-new target
	// (machineID==0, since none exists yet) requires it.
	perm := &models.Permission{}
	if err := db.Where("name = ?", "roles.assign").First(perm).Error; err != nil {
		perm = &models.Permission{Name: "roles.assign", Resource: "roles", Action: "assign"}
		require.NoError(t, db.Create(perm).Error)
	}
	role := &models.Role{Name: "provisioner-role"}
	require.NoError(t, db.Create(role).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: role.ID, PermissionID: perm.ID}).Error)
	require.NoError(t, db.Create(&models.MachineIdentityRole{
		MachineIdentityID: callerMachineID, RoleID: role.ID, ProjectID: proj.ID, EnvironmentID: 0,
	}).Error)

	body, _ := json.Marshal(map[string]interface{}{
		"name":          "proxy-provisioned-bot",
		"project_id":    proj.ID,
		"identity_type": "service",
		"state":         "active",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/system/machine-identities", bytes.NewReader(body))
	req = withMachineCtxID(req, callerMachineID)
	w := httptest.NewRecorder()
	catalog.CreateMachineIdentityProxy(w, req)
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())

	var resp remoteAPIResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	data := resp.Data.(map[string]interface{})
	createdID := uint(data["id"].(float64))

	created, err := cs.Storage().GetMachineIdentity(t.Context(), createdID)
	require.NoError(t, err)
	assert.Zero(t, created.CreatedBy, "must NOT be stamped with the calling machine's raw ID -- that is #1623's exact bug")
	assert.Equal(t, uint(callerMachineID), created.CreatedByMachineIdentityID, "the calling machine's real MachineIdentity.ID")
}

func TestCreateMachineIdentityProxy_HappyPath_S13(t *testing.T) {
	h, projID := machineHandlerWithProjectS13(t)
	// identity_type must be one of core's validMachineTypes (ci|k8s|service|
	// automation|other|node) now that CreateMachineIdentityProxy routes through
	// core.CreateMachineIdentity (G80 raw-storage-bypass fix) instead of trusting
	// the wire body's identity_type/state verbatim — "service_account" was never a
	// real identity_type, the old unvalidated raw proxy just never checked.
	body, _ := json.Marshal(map[string]interface{}{
		"name":          "proxy-bot",
		"project_id":    projID,
		"identity_type": "service",
		"state":         "active",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/system/machine-identities",
		bytes.NewReader(body))
	req = withOIDCAdminCtxS21(t, h, req)
	w := httptest.NewRecorder()
	h.CreateMachineIdentityProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── machine_identities_proxy.go: GetMachineIdentityProxy ─────────────────────

func TestGetMachineIdentityProxy_BadID_S13(t *testing.T) {
	h := machineHandlerS13(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/api/v1/system/machine-identities/bad", nil),
		"id", "bad",
	)
	w := httptest.NewRecorder()
	h.GetMachineIdentityProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetMachineIdentityProxy_NotFound_S13(t *testing.T) {
	h := machineHandlerS13(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/api/v1/system/machine-identities/9999", nil),
		"id", "9999",
	)
	w := httptest.NewRecorder()
	h.GetMachineIdentityProxy(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── machine_identities_proxy.go: TransitionMachineIdentityStateProxy ─────────

func TestTransitionMachineIdentityStateProxy_BadID_S13(t *testing.T) {
	h := machineHandlerS13(t)
	body, _ := json.Marshal(map[string]string{"from_state": "active"})
	req := withChiParam(
		httptest.NewRequest(http.MethodPut, "/", bytes.NewReader(body)),
		"id", "bad",
	)
	w := httptest.NewRecorder()
	h.TransitionMachineIdentityStateProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestTransitionMachineIdentityStateProxy_InvalidBody_S13(t *testing.T) {
	h := machineHandlerS13(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodPut, "/", strings.NewReader("{{bad")),
		"id", "1",
	)
	w := httptest.NewRecorder()
	h.TransitionMachineIdentityStateProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestTransitionMachineIdentityStateProxy_MissingFromState_S13(t *testing.T) {
	h := machineHandlerS13(t)
	body, _ := json.Marshal(map[string]interface{}{
		"machine_identity": map[string]interface{}{"name": "bot"},
		// from_state missing
	})
	req := withChiParam(
		httptest.NewRequest(http.MethodPut, "/", bytes.NewReader(body)),
		"id", "1",
	)
	w := httptest.NewRecorder()
	h.TransitionMachineIdentityStateProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── machine_identities_proxy.go: ListMachineIdentitiesProxy ──────────────────

func TestListMachineIdentitiesProxy_MissingProjectID_S13(t *testing.T) {
	h := machineHandlerS13(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/machine-identities", nil)
	// no project_id query param
	w := httptest.NewRecorder()
	h.ListMachineIdentitiesProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListMachineIdentitiesProxy_InvalidProjectID_S13(t *testing.T) {
	h := machineHandlerS13(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/machine-identities?project_id=bad", nil)
	w := httptest.NewRecorder()
	h.ListMachineIdentitiesProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListMachineIdentitiesProxy_HappyPath_S13(t *testing.T) {
	h, projID := machineHandlerWithProjectS13(t)
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/system/machine-identities?project_id="+machineUintToStr(projID), nil)
	w := httptest.NewRecorder()
	h.ListMachineIdentitiesProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── machine_identities_proxy.go: CreateMachineIdentityCredentialProxy ────────

func TestCreateMachineIdentityCredentialProxy_InvalidBody_S13(t *testing.T) {
	h := machineHandlerS13(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/system/machine-credentials",
		strings.NewReader("{{bad"))
	w := httptest.NewRecorder()
	h.CreateMachineIdentityCredentialProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateMachineIdentityCredentialProxy_MissingFields_S13(t *testing.T) {
	h := machineHandlerS13(t)
	// machine_identity_id is 0, token_hash is empty
	body, _ := json.Marshal(map[string]string{"name": "tok"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/system/machine-credentials",
		bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.CreateMachineIdentityCredentialProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── machine_identities_proxy.go: GetMachineIdentityCredentialByIDProxy ───────

func TestGetMachineIdentityCredentialByIDProxy_BadID_S13(t *testing.T) {
	h := machineHandlerS13(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/api/v1/system/machine-credentials/bad", nil),
		"id", "bad",
	)
	w := httptest.NewRecorder()
	h.GetMachineIdentityCredentialByIDProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetMachineIdentityCredentialByIDProxy_NotFound_S13(t *testing.T) {
	h := machineHandlerS13(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/api/v1/system/machine-credentials/9999", nil),
		"id", "9999",
	)
	w := httptest.NewRecorder()
	h.GetMachineIdentityCredentialByIDProxy(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── machine_identities_proxy.go: GetMachineIdentityCredentialByHashProxy ─────

func TestGetMachineIdentityCredentialByHashProxy_NotFound_S13(t *testing.T) {
	h := machineHandlerS13(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/api/v1/system/machine-credentials/by-hash/deadbeef", nil),
		"hash", "deadbeef",
	)
	w := httptest.NewRecorder()
	h.GetMachineIdentityCredentialByHashProxy(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── machine_identities_proxy.go: ListMachineIdentityCredentialsProxy ─────────

func TestListMachineIdentityCredentialsProxy_BadID_S13(t *testing.T) {
	h := machineHandlerS13(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/api/v1/system/machine-identities/bad/credentials", nil),
		"id", "bad",
	)
	w := httptest.NewRecorder()
	h.ListMachineIdentityCredentialsProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListMachineIdentityCredentialsProxy_HappyPath_S13(t *testing.T) {
	h := machineHandlerS13(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/api/v1/system/machine-identities/9999/credentials", nil),
		"id", "9999",
	)
	w := httptest.NewRecorder()
	h.ListMachineIdentityCredentialsProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── machine_identities_proxy.go: UpdateMachineIdentityCredentialProxy ────────

func TestUpdateMachineIdentityCredentialProxy_BadID_S13(t *testing.T) {
	h := machineHandlerS13(t)
	body, _ := json.Marshal(map[string]string{"name": "updated"})
	req := withChiParam(
		httptest.NewRequest(http.MethodPut, "/api/v1/system/machine-credentials/bad",
			bytes.NewReader(body)),
		"id", "bad",
	)
	w := httptest.NewRecorder()
	h.UpdateMachineIdentityCredentialProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpdateMachineIdentityCredentialProxy_InvalidBody_S13(t *testing.T) {
	h := machineHandlerS13(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodPut, "/api/v1/system/machine-credentials/1",
			strings.NewReader("{{bad")),
		"id", "1",
	)
	w := httptest.NewRecorder()
	h.UpdateMachineIdentityCredentialProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── machine_identities_proxy.go: RevokeMachineIdentityCredentialProxy ────────

func TestRevokeMachineIdentityCredentialProxy_BadID_S13(t *testing.T) {
	h := machineHandlerS13(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodPost, "/api/v1/system/machine-credentials/bad/revoke", nil),
		"id", "bad",
	)
	w := httptest.NewRecorder()
	h.RevokeMachineIdentityCredentialProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRevokeMachineIdentityCredentialProxy_NotFound_S13(t *testing.T) {
	h := machineHandlerS13(t)
	body, _ := json.Marshal(map[string]interface{}{"project_id": 1})
	req := withChiParam(
		httptest.NewRequest(http.MethodPost, "/api/v1/system/machine-credentials/9999/revoke", bytes.NewReader(body)),
		"id", "9999",
	)
	w := httptest.NewRecorder()
	h.RevokeMachineIdentityCredentialProxy(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── machine_identities_proxy.go: TouchMachineIdentityCredentialProxy ─────────

func TestTouchMachineIdentityCredentialProxy_BadID_S13(t *testing.T) {
	h := machineHandlerS13(t)
	body, _ := json.Marshal(map[string]interface{}{"staleness_seconds": 300})
	req := withChiParam(
		httptest.NewRequest(http.MethodPost, "/api/v1/system/machine-credentials/bad/touch",
			bytes.NewReader(body)),
		"id", "bad",
	)
	w := httptest.NewRecorder()
	h.TouchMachineIdentityCredentialProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestTouchMachineIdentityCredentialProxy_InvalidBody_S13(t *testing.T) {
	h := machineHandlerS13(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodPost, "/api/v1/system/machine-credentials/1/touch",
			strings.NewReader("{{bad")),
		"id", "1",
	)
	w := httptest.NewRecorder()
	h.TouchMachineIdentityCredentialProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── machine_identities_proxy.go: machineRoleScopeQuery ───────────────────────

func TestMachineRoleScopeQuery_MissingParams_S13(t *testing.T) {
	h := machineHandlerS13(t)
	// AssignMachineRoleProxy exercises machineRoleScopeQuery internally
	req := withChiParams(
		httptest.NewRequest(http.MethodPost, "/?project_id=1", nil), // missing environment_id
		map[string]string{"id": "1", "roleId": "1"},
	)
	w := httptest.NewRecorder()
	h.AssignMachineRoleProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestMachineRoleScopeQuery_InvalidProjectID_S13(t *testing.T) {
	h := machineHandlerS13(t)
	req := withChiParams(
		httptest.NewRequest(http.MethodPost, "/?project_id=bad&environment_id=0", nil),
		map[string]string{"id": "1", "roleId": "1"},
	)
	w := httptest.NewRecorder()
	h.AssignMachineRoleProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestMachineRoleScopeQuery_InvalidEnvironmentID_S13(t *testing.T) {
	h := machineHandlerS13(t)
	req := withChiParams(
		httptest.NewRequest(http.MethodPost, "/?project_id=1&environment_id=bad", nil),
		map[string]string{"id": "1", "roleId": "1"},
	)
	w := httptest.NewRecorder()
	h.AssignMachineRoleProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── machine_identities_proxy.go: AssignMachineRoleProxy ──────────────────────

func TestAssignMachineRoleProxy_BadMachineID_S13(t *testing.T) {
	h := machineHandlerS13(t)
	req := withChiParams(
		httptest.NewRequest(http.MethodPost, "/?project_id=1&environment_id=0", nil),
		map[string]string{"id": "bad", "roleId": "1"},
	)
	w := httptest.NewRecorder()
	h.AssignMachineRoleProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAssignMachineRoleProxy_BadRoleID_S13(t *testing.T) {
	h := machineHandlerS13(t)
	req := withChiParams(
		httptest.NewRequest(http.MethodPost, "/?project_id=1&environment_id=0", nil),
		map[string]string{"id": "1", "roleId": "bad"},
	)
	w := httptest.NewRecorder()
	h.AssignMachineRoleProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── machine_identities_proxy.go: RemoveMachineRoleProxy ──────────────────────

func TestRemoveMachineRoleProxy_BadMachineID_S13(t *testing.T) {
	h := machineHandlerS13(t)
	req := withChiParams(
		httptest.NewRequest(http.MethodDelete, "/?project_id=1&environment_id=0", nil),
		map[string]string{"id": "bad", "roleId": "1"},
	)
	w := httptest.NewRecorder()
	h.RemoveMachineRoleProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRemoveMachineRoleProxy_BadRoleID_S13(t *testing.T) {
	h := machineHandlerS13(t)
	req := withChiParams(
		httptest.NewRequest(http.MethodDelete, "/?project_id=1&environment_id=0", nil),
		map[string]string{"id": "1", "roleId": "bad"},
	)
	w := httptest.NewRecorder()
	h.RemoveMachineRoleProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRemoveMachineRoleProxy_NotFound_S13(t *testing.T) {
	h := machineHandlerS13(t)
	req := withChiParams(
		httptest.NewRequest(http.MethodDelete, "/?project_id=1&environment_id=0", nil),
		map[string]string{"id": "9999", "roleId": "9999"},
	)
	w := httptest.NewRecorder()
	h.RemoveMachineRoleProxy(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── machine_identities_proxy.go: GetMachineRoleIDsAtProxy ────────────────────

func TestGetMachineRoleIDsAtProxy_BadMachineID_S13(t *testing.T) {
	h := machineHandlerS13(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/?project_id=1&environment_id=0", nil),
		"id", "bad",
	)
	w := httptest.NewRecorder()
	h.GetMachineRoleIDsAtProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetMachineRoleIDsAtProxy_HappyPath_S13(t *testing.T) {
	h := machineHandlerS13(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/?project_id=1&environment_id=0", nil),
		"id", "9999",
	)
	w := httptest.NewRecorder()
	h.GetMachineRoleIDsAtProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── machine_identities_proxy.go: GetMachineRolesProxy ────────────────────────

func TestGetMachineRolesProxy_BadMachineID_S13(t *testing.T) {
	h := machineHandlerS13(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/", nil),
		"id", "bad",
	)
	w := httptest.NewRecorder()
	h.GetMachineRolesProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetMachineRolesProxy_HappyPath_S13(t *testing.T) {
	h := machineHandlerS13(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/", nil),
		"id", "9999",
	)
	w := httptest.NewRecorder()
	h.GetMachineRolesProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── machine_identities_proxy.go: CreateOIDCBindingProxy ──────────────────────

func TestCreateOIDCBindingProxy_InvalidBody_S13(t *testing.T) {
	h := machineHandlerS13(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/system/machine-oidc-bindings",
		strings.NewReader("{{bad"))
	w := httptest.NewRecorder()
	h.CreateOIDCBindingProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateOIDCBindingProxy_MissingFields_S13(t *testing.T) {
	h := machineHandlerS13(t)
	// missing subject
	body, _ := json.Marshal(map[string]interface{}{
		"machine_identity_id": 1,
		"issuer":              "https://id.example",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/system/machine-oidc-bindings",
		bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.CreateOIDCBindingProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── machine_identities_proxy.go: GetMachineByOIDCSubjectProxy ────────────────

func TestGetMachineByOIDCSubjectProxy_MissingParams_S13(t *testing.T) {
	h := machineHandlerS13(t)
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/system/machine-oidc-bindings/by-subject?issuer=https://id.example", nil)
	// subject is missing
	w := httptest.NewRecorder()
	h.GetMachineByOIDCSubjectProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetMachineByOIDCSubjectProxy_NotFound_S13(t *testing.T) {
	h := machineHandlerS13(t)
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/system/machine-oidc-bindings/by-subject?issuer=https://id.example&subject=nosub", nil)
	w := httptest.NewRecorder()
	h.GetMachineByOIDCSubjectProxy(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── machine_identities_proxy.go: ListOIDCBindingsProxy ───────────────────────

func TestListOIDCBindingsProxy_BadMachineID_S13(t *testing.T) {
	h := machineHandlerS13(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/api/v1/system/machine-identities/bad/oidc-bindings", nil),
		"id", "bad",
	)
	w := httptest.NewRecorder()
	h.ListOIDCBindingsProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListOIDCBindingsProxy_HappyPath_S13(t *testing.T) {
	h := machineHandlerS13(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/api/v1/system/machine-identities/9999/oidc-bindings", nil),
		"id", "9999",
	)
	w := httptest.NewRecorder()
	h.ListOIDCBindingsProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── machine_identities_proxy.go: GetOIDCBindingByIDProxy ─────────────────────

func TestGetOIDCBindingByIDProxy_BadID_S13(t *testing.T) {
	h := machineHandlerS13(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/api/v1/system/machine-oidc-bindings/bad", nil),
		"id", "bad",
	)
	w := httptest.NewRecorder()
	h.GetOIDCBindingByIDProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetOIDCBindingByIDProxy_NotFound_S13(t *testing.T) {
	h := machineHandlerS13(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/api/v1/system/machine-oidc-bindings/9999", nil),
		"id", "9999",
	)
	w := httptest.NewRecorder()
	h.GetOIDCBindingByIDProxy(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── machine_identities_proxy.go: DeleteOIDCBindingProxy ──────────────────────

func TestDeleteOIDCBindingProxy_BadID_S13(t *testing.T) {
	h := machineHandlerS13(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodDelete, "/api/v1/system/machine-oidc-bindings/bad", nil),
		"id", "bad",
	)
	w := httptest.NewRecorder()
	h.DeleteOIDCBindingProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDeleteOIDCBindingProxy_NotFound_S13(t *testing.T) {
	h := machineHandlerS13(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodDelete, "/api/v1/system/machine-oidc-bindings/9999", nil),
		"id", "9999",
	)
	w := httptest.NewRecorder()
	h.DeleteOIDCBindingProxy(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}
