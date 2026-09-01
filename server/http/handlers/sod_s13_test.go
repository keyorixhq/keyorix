// sod_s13_test.go — S13 coverage sweep for sod.go and sod_proxy.go.
// Targets uncovered branches: bad-param paths, missing user context, bad JSON,
// validation errors, not-found cases, and proxy 400/404 paths.
package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/identity"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newCatalogHandlerSoDSodS13 returns a CatalogHandler backed by a fresh isolated DB.
func newCatalogHandlerSoDSodS13(t *testing.T) *CatalogHandler {
	t.Helper()
	cs := freshCoreS12(t)
	return NewCatalogHandler(cs)
}

// ── sod.go: ListSoDPolicies ───────────────────────────────────────────────────

// TestListSoDPolicies_EmptyDB_S13 — happy path on an empty DB.
func TestListSoDPolicies_EmptyDB_S13(t *testing.T) {
	h := newCatalogHandlerSoDSodS13(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/sod/policies", nil)
	w := httptest.NewRecorder()
	h.ListSoDPolicies(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── sod.go: CreateSoDPolicy ───────────────────────────────────────────────────

func TestCreateSoDPolicy_NoUserCtx_S13(t *testing.T) {
	h := newCatalogHandlerSoDSodS13(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sod/policies",
		strings.NewReader(`{"name":"p","permission_a":"a","permission_b":"b"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateSoDPolicy(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestCreateSoDPolicy_BadJSON_S13(t *testing.T) {
	h := newCatalogHandlerSoDSodS13(t)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/sod/policies", strings.NewReader("{bad json")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateSoDPolicy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestCreateSoDPolicy_ValidationError_S13 — missing required fields → 400.
func TestCreateSoDPolicy_ValidationError_S13(t *testing.T) {
	h := newCatalogHandlerSoDSodS13(t)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/sod/policies",
		strings.NewReader(`{"name":"","permission_a":"","permission_b":""}`)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateSoDPolicy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestCreateSoDPolicy_SamePermissions_S13 — permission_a == permission_b → 400.
func TestCreateSoDPolicy_SamePermissions_S13(t *testing.T) {
	h := newCatalogHandlerSoDSodS13(t)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/sod/policies",
		strings.NewReader(`{"name":"dup","permission_a":"secrets.read","permission_b":"secrets.read"}`)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateSoDPolicy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── sod.go: DeleteSoDPolicy ───────────────────────────────────────────────────

func TestDeleteSoDPolicy_NoUserCtx_S13(t *testing.T) {
	h := newCatalogHandlerSoDSodS13(t)
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.DeleteSoDPolicy(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestDeleteSoDPolicy_BadID_S13(t *testing.T) {
	h := newCatalogHandlerSoDSodS13(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "notanumber"))
	w := httptest.NewRecorder()
	h.DeleteSoDPolicy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDeleteSoDPolicy_NotFound_S13(t *testing.T) {
	h := newCatalogHandlerSoDSodS13(t)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "999999"))
	w := httptest.NewRecorder()
	h.DeleteSoDPolicy(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── sod.go: ListSoDViolations ─────────────────────────────────────────────────

func TestListSoDViolations_EmptyDB_S13(t *testing.T) {
	h := newCatalogHandlerSoDSodS13(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/sod/violations", nil)
	w := httptest.NewRecorder()
	h.ListSoDViolations(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── sod_proxy.go: CreateSoDPolicyProxy ───────────────────────────────────────

func TestCreateSoDPolicyProxy_BadJSON_S13(t *testing.T) {
	h := newCatalogHandlerSoDSodS13(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad json"))
	w := httptest.NewRecorder()
	h.CreateSoDPolicyProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateSoDPolicyProxy_MissingFields_S13(t *testing.T) {
	h := newCatalogHandlerSoDSodS13(t)
	// name is set but permission_a and permission_b are empty
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"test"}`))
	w := httptest.NewRecorder()
	h.CreateSoDPolicyProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// #1529: CreateSoDPolicy now requires admin-tier authority. freshCoreS12 seeds
// no roles at all, so this seeds a minimal admin role + UserID=1 assignment
// directly (matching withUserCtx's hardcoded UserID=1) rather than pulling in
// a whole new fixture helper for one test.
func TestCreateSoDPolicyProxy_HappyPath_S13(t *testing.T) {
	h := newCatalogHandlerSoDSodS13(t)
	ctx := context.Background()
	systemAdminName, err := identity.NewFoldedName("system_admin")
	require.NoError(t, err)
	adminRole, err := h.coreService.Storage().CreateRole(ctx, systemAdminName, "Administrator")
	require.NoError(t, err)
	require.NoError(t, h.coreService.Storage().AssignRole(ctx, 1, adminRole.ID, storage.Scope{}))

	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/",
		strings.NewReader(`{"name":"proxy-pol","permission_a":"secrets.read","permission_b":"secrets.write"}`)))
	w := httptest.NewRecorder()
	h.CreateSoDPolicyProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── sod_proxy.go: GetSoDPolicyProxy ──────────────────────────────────────────

func TestGetSoDPolicyProxy_BadID_S13(t *testing.T) {
	h := newCatalogHandlerSoDSodS13(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "notanumber")
	w := httptest.NewRecorder()
	h.GetSoDPolicyProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetSoDPolicyProxy_NotFound_S13(t *testing.T) {
	h := newCatalogHandlerSoDSodS13(t)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "999999")
	w := httptest.NewRecorder()
	h.GetSoDPolicyProxy(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── sod_proxy.go: ListSoDPoliciesProxy ───────────────────────────────────────

func TestListSoDPoliciesProxy_EmptyDB_S13(t *testing.T) {
	h := newCatalogHandlerSoDSodS13(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListSoDPoliciesProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── sod_proxy.go: DeleteSoDPolicyProxy ───────────────────────────────────────

func TestDeleteSoDPolicyProxy_BadID_S13(t *testing.T) {
	h := newCatalogHandlerSoDSodS13(t)
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "notanumber")
	w := httptest.NewRecorder()
	h.DeleteSoDPolicyProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDeleteSoDPolicyProxy_NotFound_S13(t *testing.T) {
	h := newCatalogHandlerSoDSodS13(t)
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "999999")
	w := httptest.NewRecorder()
	h.DeleteSoDPolicyProxy(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}
