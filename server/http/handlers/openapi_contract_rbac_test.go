// openapi_contract_rbac_test.go — ADR-074 registry population for the Roles +
// Permissions operations that had no response schema (API hygiene campaign,
// rbac_wire.go). Each test drives the real handler through a happy path and
// calls contracttest.AssertOpenAPIResponse. Reuses freshCoreS12WithAdmin
// (handlers_s12_test.go), matching openapi_contract_pr3_test.go's own
// convention for these handlers.
package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/server/http/handlers/contracttest"
	"github.com/stretchr/testify/require"
)

func TestContractRBAC_CreateRole(t *testing.T) {
	cs, _ := freshCoreS12WithAdmin(t)
	h := NewRBACHandler(cs)

	body, _ := json.Marshal(map[string]any{
		"name": "contract-rbac-create-role", "description": "d", "permissions": []string{"roles.write"},
	})
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/roles", bytes.NewReader(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateRole(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusCreated, w.Code)
}

func TestContractRBAC_GetRole(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h := NewRBACHandler(cs)
	role := &models.Role{Name: "contract-rbac-get-role", Description: "d"}
	require.NoError(t, db.Create(role).Error)

	req := withUserCtx(withChiParamsPR2(
		httptest.NewRequest(http.MethodGet, "/api/v1/roles/1", nil),
		"id", fmt.Sprintf("%d", role.ID),
	))
	w := httptest.NewRecorder()
	h.GetRole(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractRBAC_UpdateRole(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h := NewRBACHandler(cs)
	role := &models.Role{Name: "contract-rbac-update-role", Description: "d"}
	require.NoError(t, db.Create(role).Error)

	body, _ := json.Marshal(map[string]any{"description": "updated"})
	req := withUserCtx(withChiParamsPR2(
		httptest.NewRequest(http.MethodPut, "/api/v1/roles/1", bytes.NewReader(body)),
		"id", fmt.Sprintf("%d", role.ID),
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.UpdateRole(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractRBAC_ListPermissions(t *testing.T) {
	cs, _ := freshCoreS12WithAdmin(t)
	h := NewRBACHandler(cs)

	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/permissions", nil))
	w := httptest.NewRecorder()
	h.ListPermissions(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractRBAC_GetPermission(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h := NewRBACHandler(cs)
	perm := &models.Permission{Name: "contract.rbac.get-permission", Description: "d", Resource: "contract", Action: "rbac"}
	require.NoError(t, db.Create(perm).Error)

	req := withUserCtx(withChiParamsPR2(
		httptest.NewRequest(http.MethodGet, "/api/v1/permissions/1", nil),
		"id", fmt.Sprintf("%d", perm.ID),
	))
	w := httptest.NewRecorder()
	h.GetPermission(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}
