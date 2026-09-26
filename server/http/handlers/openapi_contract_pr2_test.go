// openapi_contract_pr2_test.go — ADR-074 registry population for the operations
// docs/cli-split-inventory.md §7 PR 2 (pat, auth mfa/logout, machine) added response
// schemas for. Each test below drives the real handler through a happy path and
// calls contracttest.AssertOpenAPIResponse so the operation moves from "pending" to
// genuinely enforced -- see CLAUDE.md's "a mechanism must be validated against a
// failure that actually happened" and docs/cli-split-inventory.md §7 PR 2's own test
// requirement. Each test is self-contained (its own fixture) rather than grafted
// onto an existing test, so this batch is auditable as one unit and never risks
// changing an existing test's behavior.
package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/server/http/handlers/contracttest"
)

// withChiParamsPR2 sets any number of chi URL params on the request.
func withChiParamsPR2(r *http.Request, kv ...string) *http.Request {
	rctx := chi.NewRouteContext()
	for i := 0; i+1 < len(kv); i += 2 {
		rctx.URLParams.Add(kv[i], kv[i+1])
	}
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

func TestContractPR2_CreateMachineIdentity(t *testing.T) {
	h, projID := machineHandlerWithProjectS13(t)
	body, _ := json.Marshal(map[string]any{"name": "ci-runner", "identity_type": "ci"})
	req := withUserCtx(withChiParamsPR2(
		httptest.NewRequest(http.MethodPost, "/api/v1/projects/1/machine-identities", bytes.NewReader(body)),
		"id", machineUintToStr(projID),
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateMachineIdentity(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusCreated, w.Code)
}

func TestContractPR2_ListMachineIdentities(t *testing.T) {
	h, projID := machineHandlerWithProjectS13(t)
	req := withUserCtx(withChiParamsPR2(
		httptest.NewRequest(http.MethodGet, "/api/v1/projects/1/machine-identities", nil),
		"id", machineUintToStr(projID),
	))
	w := httptest.NewRecorder()
	h.ListMachineIdentities(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

// machineHandlerWithDB is machineHandlerWithProjectS13 but also returns the *gorm.DB,
// for tests that need to seed a machine identity row directly.
func machineHandlerWithDB(t *testing.T) (*CatalogHandler, *gorm.DB, uint) {
	t.Helper()
	cs, db := freshCoreS12WithAdmin(t)
	proj := &models.Project{Name: "contract-pr2-proj"}
	require.NoError(t, db.Create(proj).Error)
	return NewCatalogHandler(cs), db, proj.ID
}

func TestContractPR2_IssueMachineToken(t *testing.T) {
	h, db, projID := machineHandlerWithDB(t)
	machine := &models.MachineIdentity{ProjectID: projID, Name: "svc-a", IdentityType: "service", State: "active"}
	require.NoError(t, db.Create(machine).Error)

	body, _ := json.Marshal(map[string]any{"name": "primary"})
	req := withUserCtx(withChiParamsPR2(
		httptest.NewRequest(http.MethodPost, "/api/v1/projects/1/machine-identities/1/tokens", bytes.NewReader(body)),
		"id", machineUintToStr(projID), "machineId", machineUintToStr(machine.ID),
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.IssueMachineToken(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusCreated, w.Code)
}

func TestContractPR2_ListMachineTokens(t *testing.T) {
	h, db, projID := machineHandlerWithDB(t)
	machine := &models.MachineIdentity{ProjectID: projID, Name: "svc-b", IdentityType: "service", State: "active"}
	require.NoError(t, db.Create(machine).Error)

	req := withUserCtx(withChiParamsPR2(
		httptest.NewRequest(http.MethodGet, "/api/v1/projects/1/machine-identities/1/tokens", nil),
		"id", machineUintToStr(projID), "machineId", machineUintToStr(machine.ID),
	))
	w := httptest.NewRecorder()
	h.ListMachineTokens(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractPR2_CreateOIDCBinding(t *testing.T) {
	h, db, projID := machineHandlerWithDB(t)
	machine := &models.MachineIdentity{ProjectID: projID, Name: "svc-c", IdentityType: "service", State: "active"}
	require.NoError(t, db.Create(machine).Error)

	body, _ := json.Marshal(map[string]any{"issuer": "https://issuer.example.test", "subject": "system:serviceaccount:ci:runner"})
	req := withUserCtx(withChiParamsPR2(
		httptest.NewRequest(http.MethodPost, "/api/v1/projects/1/machine-identities/1/oidc-bindings", bytes.NewReader(body)),
		"id", machineUintToStr(projID), "machineId", machineUintToStr(machine.ID),
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateOIDCBinding(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusCreated, w.Code)
}

func TestContractPR2_ListOIDCBindings(t *testing.T) {
	h, db, projID := machineHandlerWithDB(t)
	machine := &models.MachineIdentity{ProjectID: projID, Name: "svc-d", IdentityType: "service", State: "active"}
	require.NoError(t, db.Create(machine).Error)
	require.NoError(t, db.Create(&models.MachineIdentityOIDCBinding{
		MachineIdentityID: machine.ID, Issuer: "https://issuer.example.test", Subject: "sub",
	}).Error)

	req := withUserCtx(withChiParamsPR2(
		httptest.NewRequest(http.MethodGet, "/api/v1/projects/1/machine-identities/1/oidc-bindings", nil),
		"id", machineUintToStr(projID), "machineId", machineUintToStr(machine.ID),
	))
	w := httptest.NewRecorder()
	h.ListOIDCBindings(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractPR2_ListMachineRoles(t *testing.T) {
	h, db, projID := machineHandlerWithDB(t)
	machine := &models.MachineIdentity{ProjectID: projID, Name: "svc-e", IdentityType: "service", State: "active"}
	require.NoError(t, db.Create(machine).Error)
	role := &models.Role{Name: "contract-pr2-machine-role", Description: "d"}
	require.NoError(t, db.Create(role).Error)
	require.NoError(t, db.Create(&models.MachineIdentityRole{
		MachineIdentityID: machine.ID, RoleID: role.ID, ProjectID: projID,
	}).Error)

	req := withUserCtx(withChiParamsPR2(
		httptest.NewRequest(http.MethodGet, "/api/v1/projects/1/machine-identities/1/roles", nil),
		"id", machineUintToStr(projID), "machineId", machineUintToStr(machine.ID),
	))
	w := httptest.NewRecorder()
	h.ListMachineRoles(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)

	var body struct {
		Data struct {
			Roles []struct {
				ID   uint   `json:"id"`
				Name string `json:"name"`
			} `json:"roles"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	require.Len(t, body.Data.Roles, 1)
	require.Equal(t, role.ID, body.Data.Roles[0].ID)
	require.Equal(t, role.Name, body.Data.Roles[0].Name)
}

func TestContractPR2_MachineTokenHygiene(t *testing.T) {
	cs, _ := freshCoreS12WithAdmin(t)
	h := NewCatalogHandler(cs)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/machine-token-hygiene", nil))
	w := httptest.NewRecorder()
	h.MachineTokenHygiene(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractPR2_GetMachineAuditReport(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h := NewMachineAuditHandler(cs)
	require.NoError(t, db.Create(&models.MachineIdentity{Name: "svc-audit", State: "active"}).Error)

	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/machine-identities/audit", nil))
	w := httptest.NewRecorder()
	h.GetMachineAuditReport(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractPR2_ListProjects(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h := NewCatalogHandler(cs)
	require.NoError(t, db.Create(&models.Project{Name: "contract-pr2-proj"}).Error)

	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/projects", nil))
	w := httptest.NewRecorder()
	h.ListProjects(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractPR2_CreatePAT(t *testing.T) {
	h := NewPATHandler(freshCoreS12(t))
	body, _ := json.Marshal(map[string]any{"name": "contract-pr2-token"})
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/auth/tokens", bytes.NewReader(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreatePAT(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusCreated, w.Code)
}

func TestContractPR2_ListPATs(t *testing.T) {
	h := NewPATHandler(freshCoreS12(t))
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/auth/tokens", nil))
	w := httptest.NewRecorder()
	h.ListPATs(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractPR2_PATHygiene(t *testing.T) {
	h := NewPATHandler(freshCoreS12(t))
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/pat-hygiene", nil))
	w := httptest.NewRecorder()
	h.PATHygiene(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractPR2_ListExpiredPATs(t *testing.T) {
	c := freshCoreS12(t)
	h := NewPATExpiryHandler(c)
	seedExpiredPAT(t, h, 1)

	req := withUserCtxForExpiry(httptest.NewRequest(http.MethodGet, "/api/v1/auth/tokens/expired", nil), 1)
	w := httptest.NewRecorder()
	h.ListExpiredPATs(w, req)

	contracttest.AssertOpenAPIResponse(t, req, w)
	require.Equal(t, http.StatusOK, w.Code)
}
