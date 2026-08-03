// handlers_s13_connect_dynamic_test.go — coverage sweep for uncovered branches in:
//   - dynamic_secrets.go: ListConfigs (bad scope query), GetConfig (bad id, not-found),
//     ListLeases (bad id, not-found), RevokeLease (missing ctx, not-found, authz),
//     RenewLease (missing ctx, not-found, authz), RevokeAllLeases (bad id),
//     ClassifyConfig (bad id, bad body), SetConfigEnabled (bad id, bad body),
//     CreateConfig (missing ctx, bad body, authz)
//   - connect.go: GetSecret (missing ctx, missing ref, unsafe error),
//     CreateRefGrant (missing ctx, bad body, safe/unsafe error),
//     DeleteRefGrant (missing ctx, bad id, not-found)
//   - connect_grants_proxy.go: ListConnectRefGrantsByConnectorProxy (empty connector),
//     CreateConnectRefGrantProxy (bad body, missing required fields),
//     DeleteConnectRefGrantProxy (bad id)
//   - dynamic_secrets_proxy.go: CreateDynamicSecretConfigProxy (bad body, missing fields),
//     GetDynamicSecretConfigProxy (bad id, not-found),
//     ListDynamicSecretConfigsProxy (missing project_id, bad project_id, bad env_id),
//     UpdateDynamicSecretConfigProxy (bad id, bad body),
//     CreateDynamicSecretLeaseProxy (bad body, missing fields),
//     GetDynamicSecretLeaseProxy (not-found),
//     ListDynamicSecretLeasesProxy (missing config_id, bad config_id),
//     CountActiveLeasesProxy (missing config_id, bad config_id),
//     UpdateDynamicSecretLeaseProxy (bad body),
//     ListExpiredActiveLeasesProxy (missing before, bad before),
//     parseProxyConfigIDQuery (missing / bad config_id)
package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// ── helpers ──────────────────────────────────────────────────────────────────

func newDynamicSecretHandlerS13(t *testing.T) *DynamicSecretHandler {
	t.Helper()
	cs, _ := freshCoreS12WithAdmin(t)
	return NewDynamicSecretHandler(cs)
}

func newConnectHandlerS13(t *testing.T) *ConnectHandler {
	t.Helper()
	cs, _ := freshCoreS12WithAdmin(t)
	return NewConnectHandler(cs)
}

func newAuthHandlerForConnectGrantsS13(t *testing.T) *AuthHandler {
	t.Helper()
	cs, _ := freshCoreS12WithAdmin(t)
	return NewAuthHandler(cs, false)
}

// seedDynamicSecretConfig inserts a minimal DynamicSecretConfig and returns its ID.
func seedDynamicSecretConfig(t *testing.T, h *DynamicSecretHandler) uint {
	t.Helper()
	cfg := &models.DynamicSecretConfig{
		Name:        "test-cfg-s13",
		ProjectID:   1,
		BackendType: "postgres",
	}
	created, err := h.coreService.Storage().CreateDynamicSecretConfig(context.Background(), cfg)
	require.NoError(t, err)
	return created.ID
}

// ── dynamic_secrets.go ────────────────────────────────────────────────────────

// ListConfigs — bad project_id query parameter
func TestDynamic_ListConfigs_BadProjectID_S13(t *testing.T) {
	h := newDynamicSecretHandlerS13(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/dynamic-secrets/configs?project_id=notanint", nil))
	w := httptest.NewRecorder()
	h.ListConfigs(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ListConfigs — bad environment_id query parameter
func TestDynamic_ListConfigs_BadEnvID_S13(t *testing.T) {
	h := newDynamicSecretHandlerS13(t)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/dynamic-secrets/configs?environment_id=bad", nil))
	w := httptest.NewRecorder()
	h.ListConfigs(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ListConfigs — no user context → forbidden (authorize fails, no user ctx in authorize)
func TestDynamic_ListConfigs_NoUserCtx_S13(t *testing.T) {
	h := newDynamicSecretHandlerS13(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/dynamic-secrets/configs?project_id=1", nil)
	w := httptest.NewRecorder()
	h.ListConfigs(w, req)
	// authorize returns false when no user ctx → denyAuthz → 403
	assert.Equal(t, http.StatusForbidden, w.Code)
}

// GetConfig — bad id
func TestDynamic_GetConfig_BadID_S13(t *testing.T) {
	h := newDynamicSecretHandlerS13(t)
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodGet, "/api/v1/dynamic-secrets/configs/notanint", nil),
		"id", "notanint",
	))
	w := httptest.NewRecorder()
	h.GetConfig(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// GetConfig — not found
func TestDynamic_GetConfig_NotFound_S13(t *testing.T) {
	h := newDynamicSecretHandlerS13(t)
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodGet, "/api/v1/dynamic-secrets/configs/99999", nil),
		"id", "99999",
	))
	w := httptest.NewRecorder()
	h.GetConfig(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ListLeases — bad id
func TestDynamic_ListLeases_BadID_S13(t *testing.T) {
	h := newDynamicSecretHandlerS13(t)
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodGet, "/api/v1/dynamic-secrets/configs/notanint/leases", nil),
		"id", "notanint",
	))
	w := httptest.NewRecorder()
	h.ListLeases(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ListLeases — not found config
func TestDynamic_ListLeases_ConfigNotFound_S13(t *testing.T) {
	h := newDynamicSecretHandlerS13(t)
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodGet, "/api/v1/dynamic-secrets/configs/99999/leases", nil),
		"id", "99999",
	))
	w := httptest.NewRecorder()
	h.ListLeases(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// RevokeLease — no user context
func TestDynamic_RevokeLease_NoUserCtx_S13(t *testing.T) {
	h := newDynamicSecretHandlerS13(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodPost, "/api/v1/dynamic-secrets/leases/abc/revoke", nil),
		"leaseID", "abc",
	)
	w := httptest.NewRecorder()
	h.RevokeLease(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// RevokeLease — lease not found
func TestDynamic_RevokeLease_LeaseNotFound_S13(t *testing.T) {
	h := newDynamicSecretHandlerS13(t)
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPost, "/api/v1/dynamic-secrets/leases/nonexistent-lease/revoke", nil),
		"leaseID", "nonexistent-lease",
	))
	w := httptest.NewRecorder()
	h.RevokeLease(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// RenewLease — no user context
func TestDynamic_RenewLease_NoUserCtx_S13(t *testing.T) {
	h := newDynamicSecretHandlerS13(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodPost, "/api/v1/dynamic-secrets/leases/abc/renew", nil),
		"leaseID", "abc",
	)
	w := httptest.NewRecorder()
	h.RenewLease(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// RenewLease — lease not found
func TestDynamic_RenewLease_LeaseNotFound_S13(t *testing.T) {
	h := newDynamicSecretHandlerS13(t)
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPost, "/api/v1/dynamic-secrets/leases/nonexistent-lease/renew", nil),
		"leaseID", "nonexistent-lease",
	))
	w := httptest.NewRecorder()
	h.RenewLease(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// RevokeAllLeases — bad id
func TestDynamic_RevokeAllLeases_BadID_S13(t *testing.T) {
	h := newDynamicSecretHandlerS13(t)
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPost, "/api/v1/dynamic-secrets/configs/notanint/revoke-all", nil),
		"id", "notanint",
	))
	w := httptest.NewRecorder()
	h.RevokeAllLeases(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// RevokeAllLeases — config not found
func TestDynamic_RevokeAllLeases_ConfigNotFound_S13(t *testing.T) {
	h := newDynamicSecretHandlerS13(t)
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPost, "/api/v1/dynamic-secrets/configs/99999/revoke-all", nil),
		"id", "99999",
	))
	w := httptest.NewRecorder()
	h.RevokeAllLeases(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// RevokeAllLeases — happy path (no active leases → 0 revoked)
func TestDynamic_RevokeAllLeases_HappyPath_S13(t *testing.T) {
	h := newDynamicSecretHandlerS13(t)
	cfgID := seedDynamicSecretConfig(t, h)
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPost, "/api/v1/dynamic-secrets/configs/1/revoke-all", nil),
		"id", uintToStrS13(cfgID),
	))
	w := httptest.NewRecorder()
	h.RevokeAllLeases(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ClassifyConfig — bad id
func TestDynamic_ClassifyConfig_BadID_S13(t *testing.T) {
	h := newDynamicSecretHandlerS13(t)
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPatch, "/api/v1/dynamic-secrets/configs/notanint/classification", nil),
		"id", "notanint",
	))
	w := httptest.NewRecorder()
	h.ClassifyConfig(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ClassifyConfig — config not found
func TestDynamic_ClassifyConfig_ConfigNotFound_S13(t *testing.T) {
	h := newDynamicSecretHandlerS13(t)
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPatch, "/api/v1/dynamic-secrets/configs/99999/classification", nil),
		"id", "99999",
	))
	w := httptest.NewRecorder()
	h.ClassifyConfig(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ClassifyConfig — bad body (non-JSON)
func TestDynamic_ClassifyConfig_BadBody_S13(t *testing.T) {
	h := newDynamicSecretHandlerS13(t)
	cfgID := seedDynamicSecretConfig(t, h)
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPatch, "/", bytes.NewBufferString("not-json")),
		"id", uintToStrS13(cfgID),
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ClassifyConfig(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// SetConfigEnabled — bad id
func TestDynamic_SetConfigEnabled_BadID_S13(t *testing.T) {
	h := newDynamicSecretHandlerS13(t)
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPatch, "/api/v1/dynamic-secrets/configs/notanint/enabled", nil),
		"id", "notanint",
	))
	w := httptest.NewRecorder()
	h.SetConfigEnabled(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// SetConfigEnabled — config not found
func TestDynamic_SetConfigEnabled_ConfigNotFound_S13(t *testing.T) {
	h := newDynamicSecretHandlerS13(t)
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPatch, "/api/v1/dynamic-secrets/configs/99999/enabled", nil),
		"id", "99999",
	))
	w := httptest.NewRecorder()
	h.SetConfigEnabled(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// SetConfigEnabled — bad body
func TestDynamic_SetConfigEnabled_BadBody_S13(t *testing.T) {
	h := newDynamicSecretHandlerS13(t)
	cfgID := seedDynamicSecretConfig(t, h)
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPatch, "/", bytes.NewBufferString("not-json")),
		"id", uintToStrS13(cfgID),
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.SetConfigEnabled(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// CreateConfig — no user context
func TestDynamic_CreateConfig_NoUserCtx_S13(t *testing.T) {
	h := newDynamicSecretHandlerS13(t)
	body, _ := json.Marshal(map[string]interface{}{"name": "x", "project_id": 1, "backend_type": "postgres"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/dynamic-secrets/configs", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateConfig(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// CreateConfig — bad body (non-JSON)
func TestDynamic_CreateConfig_BadBody_S13(t *testing.T) {
	h := newDynamicSecretHandlerS13(t)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/dynamic-secrets/configs", bytes.NewBufferString("not-json")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateConfig(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// CreateConfig — authorization denied (no project/env scope found in DB → forbidden)
func TestDynamic_CreateConfig_AuthzDenied_S13(t *testing.T) {
	// Use a core with NO admin seeded — so authorize always fails
	cs := freshCoreS12(t)
	h := NewDynamicSecretHandler(cs)
	body, _ := json.Marshal(map[string]interface{}{
		"name": "cfg-authz-test", "project_id": 1, "backend_type": "postgres",
	})
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/dynamic-secrets/configs", bytes.NewReader(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateConfig(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

// ── connect.go ───────────────────────────────────────────────────────────────

// GetSecret — no user context
func TestConnect_GetSecret_NoUserCtx_S13(t *testing.T) {
	h := newConnectHandlerS13(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/api/v1/connect/vault/secret?ref=path/to/key", nil),
		"name", "vault",
	)
	w := httptest.NewRecorder()
	h.GetSecret(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// GetSecret — missing ref query param
func TestConnect_GetSecret_MissingRef_S13(t *testing.T) {
	h := newConnectHandlerS13(t)
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodGet, "/api/v1/connect/vault/secret", nil),
		"name", "vault",
	))
	w := httptest.NewRecorder()
	h.GetSecret(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "ref query parameter is required")
}

// GetSecret — unknown connector → isSafeConnectError matches → 502 with safe message
func TestConnect_GetSecret_UnknownConnector_S13(t *testing.T) {
	h := newConnectHandlerS13(t)
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodGet, "/api/v1/connect/nonexistent/secret?ref=some/ref", nil),
		"name", "nonexistent",
	))
	w := httptest.NewRecorder()
	h.GetSecret(w, req)
	// "keyorix connect is not enabled" or "unknown connector" — either way ConnectError 502
	assert.Equal(t, http.StatusBadGateway, w.Code)
}

// CreateRefGrant — no user context
func TestConnect_CreateRefGrant_NoUserCtx_S13(t *testing.T) {
	h := newConnectHandlerS13(t)
	body, _ := json.Marshal(map[string]interface{}{"role_id": 1, "connector": "vault", "ref_prefix": "/prod/"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/connect/ref-grants", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateRefGrant(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// CreateRefGrant — bad body (non-JSON)
func TestConnect_CreateRefGrant_BadBody_S13(t *testing.T) {
	h := newConnectHandlerS13(t)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/connect/ref-grants", bytes.NewBufferString("not-json")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateRefGrant(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// CreateRefGrant — valid body with unknown connector → isSafeConnectError path
func TestConnect_CreateRefGrant_UnknownConnector_S13(t *testing.T) {
	h := newConnectHandlerS13(t)
	// role_id=0 triggers "a role is required" safe error from core
	body, _ := json.Marshal(map[string]interface{}{"role_id": 0, "connector": "vault", "ref_prefix": "/prod/"})
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/connect/ref-grants", bytes.NewReader(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateRefGrant(w, req)
	// Safe error path → 400; unsafe path → 500. Either way not 2xx.
	assert.NotEqual(t, http.StatusOK, w.Code)
}

// DeleteRefGrant — no user context
func TestConnect_DeleteRefGrant_NoUserCtx_S13(t *testing.T) {
	h := newConnectHandlerS13(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodDelete, "/api/v1/connect/ref-grants/1", nil),
		"id", "1",
	)
	w := httptest.NewRecorder()
	h.DeleteRefGrant(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// DeleteRefGrant — bad id
func TestConnect_DeleteRefGrant_BadID_S13(t *testing.T) {
	h := newConnectHandlerS13(t)
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodDelete, "/api/v1/connect/ref-grants/notanint", nil),
		"id", "notanint",
	))
	w := httptest.NewRecorder()
	h.DeleteRefGrant(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// DeleteRefGrant — not-found (no such grant) — storage deletes by PK silently succeed
func TestConnect_DeleteRefGrant_NotFound_S13(t *testing.T) {
	h := newConnectHandlerS13(t)
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodDelete, "/api/v1/connect/ref-grants/99999", nil),
		"id", "99999",
	))
	w := httptest.NewRecorder()
	h.DeleteRefGrant(w, req)
	// Storage silently succeeds on a missing row → 200
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── connect_grants_proxy.go ──────────────────────────────────────────────────

// ListConnectRefGrantsByConnectorProxy — empty connector param
func TestConnectGrantsProxy_ListByConnector_EmptyConnector_S13(t *testing.T) {
	h := newAuthHandlerForConnectGrantsS13(t)
	// chi param "connector" is empty string
	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/api/v1/system/connect-grants/by-connector/", nil),
		"connector", "",
	)
	w := httptest.NewRecorder()
	h.ListConnectRefGrantsByConnectorProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ListConnectRefGrantsByConnectorProxy — valid connector → 200
func TestConnectGrantsProxy_ListByConnector_Happy_S13(t *testing.T) {
	h := newAuthHandlerForConnectGrantsS13(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/api/v1/system/connect-grants/by-connector/vault", nil),
		"connector", "vault",
	)
	w := httptest.NewRecorder()
	h.ListConnectRefGrantsByConnectorProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ListConnectRefGrantsProxy — happy path (no grants)
func TestConnectGrantsProxy_List_Happy_S13(t *testing.T) {
	h := newAuthHandlerForConnectGrantsS13(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/connect-grants", nil)
	w := httptest.NewRecorder()
	h.ListConnectRefGrantsProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// CreateConnectRefGrantProxy — bad body
func TestConnectGrantsProxy_Create_BadBody_S13(t *testing.T) {
	h := newAuthHandlerForConnectGrantsS13(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/system/connect-grants", bytes.NewBufferString("not-json"))
	w := httptest.NewRecorder()
	h.CreateConnectRefGrantProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// CreateConnectRefGrantProxy — missing role_id / connector
func TestConnectGrantsProxy_Create_MissingFields_S13(t *testing.T) {
	h := newAuthHandlerForConnectGrantsS13(t)
	// role_id=0, connector="" → validation guard fires
	body, _ := json.Marshal(map[string]interface{}{"ref_prefix": "/prod/"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/system/connect-grants", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateConnectRefGrantProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "role_id and connector are required")
}

// CreateConnectRefGrantProxy — happy path (valid role seeded in DB via admin setup)
func TestConnectGrantsProxy_Create_Happy_S13(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h := NewAuthHandler(cs, false)

	// Seed a role for the grant to reference
	role := &models.Role{Name: "connect-grant-role-s13", Description: "test"}
	require.NoError(t, db.Create(role).Error)

	body, _ := json.Marshal(map[string]interface{}{
		"role_id":    role.ID,
		"connector":  "vault",
		"ref_prefix": "/prod/",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/system/connect-grants", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateConnectRefGrantProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// DeleteConnectRefGrantProxy — bad id
func TestConnectGrantsProxy_Delete_BadID_S13(t *testing.T) {
	h := newAuthHandlerForConnectGrantsS13(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodDelete, "/api/v1/system/connect-grants/notanint", nil),
		"id", "notanint",
	)
	w := httptest.NewRecorder()
	h.DeleteConnectRefGrantProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// DeleteConnectRefGrantProxy — non-existent id → storage silently succeeds
func TestConnectGrantsProxy_Delete_NotFound_S13(t *testing.T) {
	h := newAuthHandlerForConnectGrantsS13(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodDelete, "/api/v1/system/connect-grants/99999", nil),
		"id", "99999",
	)
	w := httptest.NewRecorder()
	h.DeleteConnectRefGrantProxy(w, req)
	// Storage silently succeeds on delete of missing row → 200
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── dynamic_secrets_proxy.go ──────────────────────────────────────────────────

func newDynamicSecretHandlerProxyS13(t *testing.T) *DynamicSecretHandler {
	t.Helper()
	cs, _ := freshCoreS12WithAdmin(t)
	return NewDynamicSecretHandler(cs)
}

// CreateDynamicSecretConfigProxy — bad body
func TestDynProxy_CreateConfig_BadBody_S13(t *testing.T) {
	h := newDynamicSecretHandlerProxyS13(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/system/dynamic-secrets/configs", bytes.NewBufferString("not-json"))
	w := httptest.NewRecorder()
	h.CreateDynamicSecretConfigProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// CreateDynamicSecretConfigProxy — missing name / project_id
func TestDynProxy_CreateConfig_MissingFields_S13(t *testing.T) {
	h := newDynamicSecretHandlerProxyS13(t)
	// Empty name and project_id=0
	body, _ := json.Marshal(map[string]interface{}{"backend_type": "postgres"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/system/dynamic-secrets/configs", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateDynamicSecretConfigProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "name and project_id are required")
}

// CreateDynamicSecretConfigProxy — happy path
func TestDynProxy_CreateConfig_Happy_S13(t *testing.T) {
	h := newDynamicSecretHandlerProxyS13(t)
	body, _ := json.Marshal(map[string]interface{}{
		"name":         "proxy-cfg-s13",
		"project_id":   1,
		"backend_type": "postgres",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/system/dynamic-secrets/configs", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateDynamicSecretConfigProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// GetDynamicSecretConfigProxy — bad id
func TestDynProxy_GetConfig_BadID_S13(t *testing.T) {
	h := newDynamicSecretHandlerProxyS13(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/api/v1/system/dynamic-secrets/configs/notanint", nil),
		"id", "notanint",
	)
	w := httptest.NewRecorder()
	h.GetDynamicSecretConfigProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// GetDynamicSecretConfigProxy — not found
func TestDynProxy_GetConfig_NotFound_S13(t *testing.T) {
	h := newDynamicSecretHandlerProxyS13(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/api/v1/system/dynamic-secrets/configs/99999", nil),
		"id", "99999",
	)
	w := httptest.NewRecorder()
	h.GetDynamicSecretConfigProxy(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// GetDynamicSecretConfigProxy — happy path
func TestDynProxy_GetConfig_Happy_S13(t *testing.T) {
	h := newDynamicSecretHandlerProxyS13(t)
	cfgID := seedDynamicSecretConfig(t, h)
	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/api/v1/system/dynamic-secrets/configs/1", nil),
		"id", uintToStrS13(cfgID),
	)
	w := httptest.NewRecorder()
	h.GetDynamicSecretConfigProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ListDynamicSecretConfigsProxy — missing project_id
func TestDynProxy_ListConfigs_MissingProjectID_S13(t *testing.T) {
	h := newDynamicSecretHandlerProxyS13(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/dynamic-secrets/configs", nil)
	w := httptest.NewRecorder()
	h.ListDynamicSecretConfigsProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "project_id query parameter is required")
}

// ListDynamicSecretConfigsProxy — bad project_id
func TestDynProxy_ListConfigs_BadProjectID_S13(t *testing.T) {
	h := newDynamicSecretHandlerProxyS13(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/dynamic-secrets/configs?project_id=notanint", nil)
	w := httptest.NewRecorder()
	h.ListDynamicSecretConfigsProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ListDynamicSecretConfigsProxy — bad environment_id
func TestDynProxy_ListConfigs_BadEnvID_S13(t *testing.T) {
	h := newDynamicSecretHandlerProxyS13(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/dynamic-secrets/configs?project_id=1&environment_id=notanint", nil)
	w := httptest.NewRecorder()
	h.ListDynamicSecretConfigsProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ListDynamicSecretConfigsProxy — happy path
func TestDynProxy_ListConfigs_Happy_S13(t *testing.T) {
	h := newDynamicSecretHandlerProxyS13(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/dynamic-secrets/configs?project_id=1", nil)
	w := httptest.NewRecorder()
	h.ListDynamicSecretConfigsProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// UpdateDynamicSecretConfigProxy — bad id
func TestDynProxy_UpdateConfig_BadID_S13(t *testing.T) {
	h := newDynamicSecretHandlerProxyS13(t)
	body, _ := json.Marshal(map[string]interface{}{"name": "x", "project_id": 1})
	req := withChiParam(
		httptest.NewRequest(http.MethodPut, "/api/v1/system/dynamic-secrets/configs/notanint", bytes.NewReader(body)),
		"id", "notanint",
	)
	w := httptest.NewRecorder()
	h.UpdateDynamicSecretConfigProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// UpdateDynamicSecretConfigProxy — bad body
func TestDynProxy_UpdateConfig_BadBody_S13(t *testing.T) {
	h := newDynamicSecretHandlerProxyS13(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodPut, "/api/v1/system/dynamic-secrets/configs/1", bytes.NewBufferString("not-json")),
		"id", "1",
	)
	w := httptest.NewRecorder()
	h.UpdateDynamicSecretConfigProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// CreateDynamicSecretLeaseProxy — bad body
func TestDynProxy_CreateLease_BadBody_S13(t *testing.T) {
	h := newDynamicSecretHandlerProxyS13(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/system/dynamic-secrets/leases", bytes.NewBufferString("not-json"))
	w := httptest.NewRecorder()
	h.CreateDynamicSecretLeaseProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// CreateDynamicSecretLeaseProxy — missing config_id / lease_id
func TestDynProxy_CreateLease_MissingFields_S13(t *testing.T) {
	h := newDynamicSecretHandlerProxyS13(t)
	body, _ := json.Marshal(map[string]interface{}{"role_name": "myrole"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/system/dynamic-secrets/leases", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateDynamicSecretLeaseProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "config_id and lease_id are required")
}

// GetDynamicSecretLeaseProxy — not found
func TestDynProxy_GetLease_NotFound_S13(t *testing.T) {
	h := newDynamicSecretHandlerProxyS13(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/api/v1/system/dynamic-secrets/leases/nonexistent-lease-s13", nil),
		"leaseID", "nonexistent-lease-s13",
	)
	w := httptest.NewRecorder()
	h.GetDynamicSecretLeaseProxy(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ListDynamicSecretLeasesProxy — missing config_id
func TestDynProxy_ListLeases_MissingConfigID_S13(t *testing.T) {
	h := newDynamicSecretHandlerProxyS13(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/dynamic-secrets/leases", nil)
	w := httptest.NewRecorder()
	h.ListDynamicSecretLeasesProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "config_id query parameter is required")
}

// ListDynamicSecretLeasesProxy — bad config_id
func TestDynProxy_ListLeases_BadConfigID_S13(t *testing.T) {
	h := newDynamicSecretHandlerProxyS13(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/dynamic-secrets/leases?config_id=notanint", nil)
	w := httptest.NewRecorder()
	h.ListDynamicSecretLeasesProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ListDynamicSecretLeasesProxy — happy path
func TestDynProxy_ListLeases_Happy_S13(t *testing.T) {
	h := newDynamicSecretHandlerProxyS13(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/dynamic-secrets/leases?config_id=1", nil)
	w := httptest.NewRecorder()
	h.ListDynamicSecretLeasesProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// CountActiveLeasesProxy — missing config_id
func TestDynProxy_CountActiveLeases_MissingConfigID_S13(t *testing.T) {
	h := newDynamicSecretHandlerProxyS13(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/dynamic-secrets/leases/active-count", nil)
	w := httptest.NewRecorder()
	h.CountActiveLeasesProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// CountActiveLeasesProxy — bad config_id
func TestDynProxy_CountActiveLeases_BadConfigID_S13(t *testing.T) {
	h := newDynamicSecretHandlerProxyS13(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/dynamic-secrets/leases/active-count?config_id=bad", nil)
	w := httptest.NewRecorder()
	h.CountActiveLeasesProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// CountActiveLeasesProxy — happy path
func TestDynProxy_CountActiveLeases_Happy_S13(t *testing.T) {
	h := newDynamicSecretHandlerProxyS13(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/dynamic-secrets/leases/active-count?config_id=1", nil)
	w := httptest.NewRecorder()
	h.CountActiveLeasesProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// UpdateDynamicSecretLeaseProxy — bad body
func TestDynProxy_UpdateLease_BadBody_S13(t *testing.T) {
	h := newDynamicSecretHandlerProxyS13(t)
	req := withChiParam(
		httptest.NewRequest(http.MethodPut, "/api/v1/system/dynamic-secrets/leases/some-lease", bytes.NewBufferString("not-json")),
		"leaseID", "some-lease",
	)
	w := httptest.NewRecorder()
	h.UpdateDynamicSecretLeaseProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ListExpiredActiveLeasesProxy — missing before
func TestDynProxy_ListExpiredLeases_MissingBefore_S13(t *testing.T) {
	h := newDynamicSecretHandlerProxyS13(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/dynamic-secrets/leases/expired", nil)
	w := httptest.NewRecorder()
	h.ListExpiredActiveLeasesProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "before query parameter is required")
}

// ListExpiredActiveLeasesProxy — bad before (not RFC3339)
func TestDynProxy_ListExpiredLeases_BadBefore_S13(t *testing.T) {
	h := newDynamicSecretHandlerProxyS13(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/dynamic-secrets/leases/expired?before=not-a-date", nil)
	w := httptest.NewRecorder()
	h.ListExpiredActiveLeasesProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "RFC3339")
}

// ListExpiredActiveLeasesProxy — happy path (valid RFC3339)
func TestDynProxy_ListExpiredLeases_Happy_S13(t *testing.T) {
	h := newDynamicSecretHandlerProxyS13(t)
	before := time.Now().UTC().Format(time.RFC3339Nano)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/dynamic-secrets/leases/expired?before="+before, nil)
	w := httptest.NewRecorder()
	h.ListExpiredActiveLeasesProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── utility ───────────────────────────────────────────────────────────────────

// uintToStrS13 converts uint to decimal string.
func uintToStrS13(n uint) string {
	return strconv.FormatUint(uint64(n), 10)
}
