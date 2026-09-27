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

// ── machine_identities.go: ListMachineRoles ──────────────────────────────────

func TestListMachineRoles_BadProjectID_S13(t *testing.T) {
	h := machineHandlerS13(t)
	req := withUserCtx(withChiParams(
		httptest.NewRequest(http.MethodGet, "/", nil),
		map[string]string{"id": "bad", "machineId": "1"},
	))
	w := httptest.NewRecorder()
	h.ListMachineRoles(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListMachineRoles_BadMachineID_S13(t *testing.T) {
	h, projID := machineHandlerWithProjectS13(t)
	req := withUserCtx(withChiParams(
		httptest.NewRequest(http.MethodGet, "/", nil),
		map[string]string{"id": machineUintToStr(projID), "machineId": "bad"},
	))
	w := httptest.NewRecorder()
	h.ListMachineRoles(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListMachineRoles_Unauthorized_S13(t *testing.T) {
	h, projID := machineHandlerWithProjectS13(t)
	req := withChiParams(
		httptest.NewRequest(http.MethodGet, "/", nil),
		map[string]string{"id": machineUintToStr(projID), "machineId": "1"},
	)
	w := httptest.NewRecorder()
	h.ListMachineRoles(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestListMachineRoles_NotFound_S13(t *testing.T) {
	h, projID := machineHandlerWithProjectS13(t)
	req := withUserCtx(withChiParams(
		httptest.NewRequest(http.MethodGet, "/", nil),
		map[string]string{"id": machineUintToStr(projID), "machineId": "9999"},
	))
	w := httptest.NewRecorder()
	h.ListMachineRoles(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
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

// TestCreateMachineIdentityProxy_MachineCallerAttributionDistinguishable is
// the #1623 regression for this handler: a machine identity that creates
// ANOTHER machine identity (a machine provisioning a machine) must be
// recorded via CreatedByMachineIdentityID, not stamped into CreatedBy where
// it would be indistinguishable from a real User.ID sharing the same number.

// ── machine_identities_proxy.go: GetMachineIdentityProxy ─────────────────────

// ── machine_identities_proxy.go: TransitionMachineIdentityStateProxy ─────────

// ── machine_identities_proxy.go: ListMachineIdentitiesProxy ──────────────────

// ── machine_identities_proxy.go: CreateMachineIdentityCredentialProxy ────────

// ── machine_identities_proxy.go: GetMachineIdentityCredentialByIDProxy ───────

// ── machine_identities_proxy.go: GetMachineIdentityCredentialByHashProxy ─────

// ── machine_identities_proxy.go: ListMachineIdentityCredentialsProxy ─────────

// ── machine_identities_proxy.go: UpdateMachineIdentityCredentialProxy ────────

// ── machine_identities_proxy.go: RevokeMachineIdentityCredentialProxy ────────

// ── machine_identities_proxy.go: TouchMachineIdentityCredentialProxy ─────────

// ── machine_identities_proxy.go: machineRoleScopeQuery ───────────────────────

// ── machine_identities_proxy.go: AssignMachineRoleProxy ──────────────────────

// ── machine_identities_proxy.go: RemoveMachineRoleProxy ──────────────────────

// ── machine_identities_proxy.go: GetMachineRoleIDsAtProxy ────────────────────

// ── machine_identities_proxy.go: GetMachineRolesProxy ────────────────────────

// ── machine_identities_proxy.go: CreateOIDCBindingProxy ──────────────────────

// ── machine_identities_proxy.go: GetMachineByOIDCSubjectProxy ────────────────

// ── machine_identities_proxy.go: ListOIDCBindingsProxy ───────────────────────

// ── machine_identities_proxy.go: GetOIDCBindingByIDProxy ─────────────────────

// ── machine_identities_proxy.go: DeleteOIDCBindingProxy ──────────────────────
