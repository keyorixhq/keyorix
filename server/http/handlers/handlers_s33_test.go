// handlers_s33_test.go — broken-DB error-path sweep for machine-identity proxy
// functions not yet covered in s29/s30 (credentials by-hash/by-id, machine role
// grants with scope query, OIDC bindings, create/touch/revoke paths).
package handlers

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

var s33DBCounter atomic.Int64

func freshCoreBrokenS33(t *testing.T) *core.KeyorixCore {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	n := s33DBCounter.Add(1)
	dsn := fmt.Sprintf("file:kxhandlers_s33_%d?mode=memory&cache=shared", n)
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.Project{}))
	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())
	return core.NewKeyorixCore(store.NewLocalStorage(db))
}

// ── Machine credential proxy ───────────────────────────────────────────────────

func TestGetMachineIdentityCredentialByHashProxy_DBError_S33(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreBrokenS33(t))
	r := withChiParamS7(httptest.NewRequest(http.MethodGet, "/api/v1/system/machine-credentials/by-hash/abc123", nil), "hash", "abc123")
	w := httptest.NewRecorder()
	h.GetMachineIdentityCredentialByHashProxy(w, r)
	// GetMachineIdentityCredentialByHash wraps First() errors as "not found" → 404
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestGetMachineIdentityCredentialByIDProxy_DBError_S33(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreBrokenS33(t))
	r := withChiParamS7(httptest.NewRequest(http.MethodGet, "/api/v1/system/machine-credentials/1", nil), "id", "1")
	w := httptest.NewRecorder()
	h.GetMachineIdentityCredentialByIDProxy(w, r)
	// G80: GetMachineIdentityCredentialByID used to wrap EVERY First() error as
	// "not found" regardless of cause, so a genuine storage failure (this test's
	// closed DB) was indistinguishable from a real not-found and surfaced as 404.
	// Fixed in local_machine_credentials.go to only report 404 for a genuine
	// gorm.ErrRecordNotFound, matching GetUser's already-correct pattern -- a
	// real storage error now correctly surfaces as 500.
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestListMachineIdentityCredentialsProxy_DBError_S33(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreBrokenS33(t))
	r := withChiParamS7(httptest.NewRequest(http.MethodGet, "/api/v1/system/machine-identities/1/credentials", nil), "id", "1")
	w := httptest.NewRecorder()
	h.ListMachineIdentityCredentialsProxy(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestUpdateMachineIdentityCredentialProxy_DBError_S33(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreBrokenS33(t))
	body := bytes.NewBufferString(`{"machine_identity_id":1,"token_hash":"hash","created_by":1}`)
	r := withChiParamS7(httptest.NewRequest(http.MethodPut, "/api/v1/system/machine-credentials/1", body), "id", "1")
	w := httptest.NewRecorder()
	h.UpdateMachineIdentityCredentialProxy(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestRevokeMachineIdentityCredentialProxy_DBError_S33(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreBrokenS33(t))
	r := withChiParamS7(httptest.NewRequest(http.MethodPost, "/api/v1/system/machine-credentials/1/revoke", nil), "id", "1")
	w := httptest.NewRecorder()
	h.RevokeMachineIdentityCredentialProxy(w, r)
	// RevokeMachineIdentityCredential fails with "ErrorStorageFailed" (not "not found") → 500
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestTouchMachineIdentityCredentialProxy_DBError_S33(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreBrokenS33(t))
	body := bytes.NewBufferString(`{"used_at":"2024-01-01T00:00:00Z","staleness_seconds":60}`)
	r := withChiParamS7(httptest.NewRequest(http.MethodPost, "/api/v1/system/machine-credentials/1/touch", body), "id", "1")
	w := httptest.NewRecorder()
	h.TouchMachineIdentityCredentialProxy(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ── Machine role grant proxy ───────────────────────────────────────────────────

func TestAssignMachineRoleProxy_MissingScopeQuery_S33(t *testing.T) {
	// Exercises machineRoleScopeQuery's missing-params 400 branch.
	t.Parallel()
	h := NewCatalogHandler(freshCoreBrokenS33(t))
	r := withChiParams2_S22(
		httptest.NewRequest(http.MethodPost, "/api/v1/system/machine-identities/1/roles/2", nil),
		"id", "1", "roleId", "2",
	)
	w := httptest.NewRecorder()
	h.AssignMachineRoleProxy(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAssignMachineRoleProxy_DBError_S33(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreBrokenS33(t))
	r := withChiParams2_S22(
		httptest.NewRequest(http.MethodPost, "/api/v1/system/machine-identities/1/roles/2?project_id=1&environment_id=1", nil),
		"id", "1", "roleId", "2",
	)
	w := httptest.NewRecorder()
	h.AssignMachineRoleProxy(w, r)
	// AssignMachineRole: broken DB → First() fails with non-ErrRecordNotFound →
	// wraps as "ErrorInternalServer" (not "already assigned") → 500
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestRemoveMachineRoleProxy_DBError_S33(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreBrokenS33(t))
	r := withChiParams2_S22(
		httptest.NewRequest(http.MethodDelete, "/api/v1/system/machine-identities/1/roles/2?project_id=1&environment_id=1", nil),
		"id", "1", "roleId", "2",
	)
	w := httptest.NewRecorder()
	h.RemoveMachineRoleProxy(w, r)
	// #1542: RemoveMachineRoleProxy now routes through core.RemoveMachineRole,
	// which calls machineInProject FIRST -- machineInProject collapses ANY
	// GetMachineIdentity failure (including this broken-DB case, not just a
	// genuine not-found) into a single "machine identity not found" error, by
	// design (the caller can't distinguish "doesn't exist" from "can't
	// confirm it exists" for authorization purposes, and both should refuse).
	// isNotFoundErr's substring match on that text now maps this route's
	// broken-DB case to 404, not the previous raw-storage-call 500.
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestGetMachineRoleIDsAtProxy_MissingScopeQuery_S33(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreBrokenS33(t))
	r := withChiParamS7(
		httptest.NewRequest(http.MethodGet, "/api/v1/system/machine-identities/1/roles/ids", nil),
		"id", "1",
	)
	w := httptest.NewRecorder()
	h.GetMachineRoleIDsAtProxy(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetMachineRoleIDsAtProxy_DBError_S33(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreBrokenS33(t))
	r := withChiParamS7(
		httptest.NewRequest(http.MethodGet, "/api/v1/system/machine-identities/1/roles/ids?project_id=1&environment_id=1", nil),
		"id", "1",
	)
	w := httptest.NewRecorder()
	h.GetMachineRoleIDsAtProxy(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestGetMachineRolesProxy_DBError_S33(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreBrokenS33(t))
	r := withChiParamS7(httptest.NewRequest(http.MethodGet, "/api/v1/system/machine-identities/1/roles", nil), "id", "1")
	w := httptest.NewRecorder()
	h.GetMachineRolesProxy(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ── OIDC binding proxy ─────────────────────────────────────────────────────────

func TestCreateOIDCBindingProxy_DBError_S33(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreBrokenS33(t))
	body := bytes.NewBufferString(`{"machine_identity_id":1,"issuer":"https://issuer.example.com","subject":"user123"}`)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/system/machine-oidc-bindings", body)
	w := httptest.NewRecorder()
	h.CreateOIDCBindingProxy(w, r)
	// G80 raw-storage-bypass fix: the handler now looks up the machine identity
	// (to derive its real ProjectID for core.CreateOIDCBinding's admin-authority +
	// scope check) BEFORE attempting the create — on this broken DB, that GetMachineIdentity
	// lookup itself fails first, wrapped as "not found" (same isNotFoundErr convention
	// GetMachineIdentityProxy/GetOIDCBindingByIDProxy use elsewhere in this file) → 404,
	// rather than reaching the create call at all.
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestGetMachineByOIDCSubjectProxy_DBError_S33(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreBrokenS33(t))
	r := httptest.NewRequest(http.MethodGet, "/api/v1/system/machine-oidc-bindings/by-subject?issuer=https%3A%2F%2Fissuer.example.com&subject=user123", nil)
	w := httptest.NewRecorder()
	h.GetMachineByOIDCSubjectProxy(w, r)
	// GetMachineByOIDCSubject wraps First() errors as "not found" → 404
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestListOIDCBindingsProxy_DBError_S33(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreBrokenS33(t))
	r := withChiParamS7(httptest.NewRequest(http.MethodGet, "/api/v1/system/machine-identities/1/oidc-bindings", nil), "id", "1")
	w := httptest.NewRecorder()
	h.ListOIDCBindingsProxy(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// G80: GetOIDCBindingByID used to wrap EVERY First() error (not just a real
// gorm.ErrRecordNotFound) as "not found" -> 404, the same pre-existing bug
// TestGetSoDPolicyProxy_DBError_S31 documented for local_sod.go. Surfaced by
// DeleteOIDCBindingProxy's own G80 fix (it now reads the binding before
// deleting), so GetOIDCBindingByID was fixed to distinguish a genuine
// not-found from any other storage error -- a broken DB now correctly
// surfaces as 500 here too.
func TestGetOIDCBindingByIDProxy_DBError_S33(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreBrokenS33(t))
	r := withChiParamS7(httptest.NewRequest(http.MethodGet, "/api/v1/system/machine-oidc-bindings/1", nil), "id", "1")
	w := httptest.NewRecorder()
	h.GetOIDCBindingByIDProxy(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestDeleteOIDCBindingProxy_DBError_S33(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreBrokenS33(t))
	r := withChiParamS7(httptest.NewRequest(http.MethodDelete, "/api/v1/system/machine-oidc-bindings/1", nil), "id", "1")
	w := httptest.NewRecorder()
	h.DeleteOIDCBindingProxy(w, r)
	// DeleteOIDCBinding: broken DB → result.Error != nil → "ErrorStorageFailed" (not "not found") → 500
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}
