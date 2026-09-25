// openapi_contract_catalog_test.go — ADR-074 registry population for the Projects +
// Environments catalog operations (API hygiene campaign, catalog_wire.go). Each test
// drives the real handler through a happy path and calls
// contracttest.AssertOpenAPIResponse so the operation moves from "pending" to
// genuinely enforced. Reuses freshSecretFixturePR4 (openapi_contract_pr4_test.go) for
// its project+environment fixture rather than duplicating one.
package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/server/http/handlers/contracttest"
	"github.com/stretchr/testify/require"
)

func TestContractCatalog_CreateProject(t *testing.T) {
	_, cs, _, _, _ := freshSecretFixturePR4(t)
	h := NewCatalogHandler(cs)

	body, _ := json.Marshal(map[string]any{"name": "catalog-create-target"})
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/projects", bytes.NewReader(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateProject(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusCreated, w.Code)
}

func TestContractCatalog_GetProject(t *testing.T) {
	_, cs, _, projID, _ := freshSecretFixturePR4(t)
	h := NewCatalogHandler(cs)

	req := withUserCtx(withChiParamsPR2(
		httptest.NewRequest(http.MethodGet, "/api/v1/projects/1", nil),
		"id", pr4SecretIDStr(projID),
	))
	w := httptest.NewRecorder()
	h.GetProject(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractCatalog_UpdateProject(t *testing.T) {
	_, cs, _, projID, _ := freshSecretFixturePR4(t)
	h := NewCatalogHandler(cs)

	body, _ := json.Marshal(map[string]any{"name": "catalog-update-target", "description": "updated"})
	req := withUserCtx(withChiParamsPR2(
		httptest.NewRequest(http.MethodPut, "/api/v1/projects/1", bytes.NewReader(body)),
		"id", pr4SecretIDStr(projID),
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.UpdateProject(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractCatalog_CreateProjectEnvironment(t *testing.T) {
	_, cs, _, projID, _ := freshSecretFixturePR4(t)
	h := NewCatalogHandler(cs)

	body, _ := json.Marshal(map[string]any{"name": "catalog-new-env"})
	req := withUserCtx(withChiParamsPR2(
		httptest.NewRequest(http.MethodPost, "/api/v1/projects/1/environments", bytes.NewReader(body)),
		"id", pr4SecretIDStr(projID),
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateProjectEnvironment(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusCreated, w.Code)
}

func TestContractCatalog_ListEnvironments(t *testing.T) {
	_, cs, _, _, _ := freshSecretFixturePR4(t)
	h := NewCatalogHandler(cs)

	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/environments", nil))
	w := httptest.NewRecorder()
	h.ListEnvironments(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}
