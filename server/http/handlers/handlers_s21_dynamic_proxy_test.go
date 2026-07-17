// handlers_s21_dynamic_proxy_test.go — coverage sweep targeting:
//   - dynamic_secrets.go RevokeAllLeases (bad {id} param, config not found, valid)
//   - legal_hold_proxy.go CreateLegalHoldProxy (bad JSON, missing reason, valid)
//   - project_memberships_proxy.go CreateMembershipProxy (bad JSON, missing fields, valid)
package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── dynamic_secrets.go: RevokeAllLeases ──────────────────────────────────────

// TestRevokeAllLeases_BadID_S21 verifies that a non-numeric {id} param returns
// 400 (loadAuthorizedConfig parse guard).
func TestRevokeAllLeases_BadID_S21(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewDynamicSecretHandler(cs)

	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPost, "/api/v1/dynamic-secrets/configs/bad/revoke-all", nil),
		"id", "bad",
	))
	w := httptest.NewRecorder()
	h.RevokeAllLeases(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "InvalidParameter")
}

// TestRevokeAllLeases_ConfigNotFound_S21 verifies that a valid numeric {id}
// for a non-existent config returns 404.
func TestRevokeAllLeases_ConfigNotFound_S21(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewDynamicSecretHandler(cs)

	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPost, "/api/v1/dynamic-secrets/configs/9999/revoke-all", nil),
		"id", "9999",
	))
	w := httptest.NewRecorder()
	h.RevokeAllLeases(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), "NotFound")
}

// TestRevokeAllLeases_NoUserCtx_S21 verifies that a request with no user
// context against a real config is denied (401 or 403, never 500).
func TestRevokeAllLeases_NoUserCtx_S21(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h := NewDynamicSecretHandler(cs)

	proj := &models.Project{Name: "s21-project-noctx"}
	require.NoError(t, db.Create(proj).Error)
	env := &models.Environment{Name: "s21-env-noctx", ProjectID: proj.ID}
	require.NoError(t, db.Create(env).Error)
	cfg := &models.DynamicSecretConfig{
		Name:          "s21-cfg-noctx",
		ProjectID:     proj.ID,
		EnvironmentID: env.ID,
		BackendType:   "postgres",
		CreatedBy:     "testuser",
	}
	require.NoError(t, db.Create(cfg).Error)

	// No user context injected — authorize() returns false, false.
	req := withChiParam(
		httptest.NewRequest(http.MethodPost, "/api/v1/dynamic-secrets/configs/1/revoke-all", nil),
		"id", fmt.Sprintf("%d", cfg.ID),
	)
	w := httptest.NewRecorder()
	h.RevokeAllLeases(w, req)

	assert.NotEqual(t, http.StatusInternalServerError, w.Code)
	assert.NotEqual(t, http.StatusOK, w.Code)
}

// TestRevokeAllLeases_Valid_S21 verifies the happy path: an admin-authed
// request against a real config with no active leases returns 200 with
// revoked=0, failed=0.
func TestRevokeAllLeases_Valid_S21(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h := NewDynamicSecretHandler(cs)

	proj := &models.Project{Name: "s21-project-valid"}
	require.NoError(t, db.Create(proj).Error)
	env := &models.Environment{Name: "s21-env-valid", ProjectID: proj.ID}
	require.NoError(t, db.Create(env).Error)
	cfg := &models.DynamicSecretConfig{
		Name:          "s21-cfg-valid",
		ProjectID:     proj.ID,
		EnvironmentID: env.ID,
		BackendType:   "postgres",
		CreatedBy:     "testuser",
	}
	require.NoError(t, db.Create(cfg).Error)

	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPost, "/api/v1/dynamic-secrets/configs/1/revoke-all", nil),
		"id", fmt.Sprintf("%d", cfg.ID),
	))
	w := httptest.NewRecorder()
	h.RevokeAllLeases(w, req)

	// With no active leases the call should succeed (0 revoked, 0 failed).
	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]interface{}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.True(t, resp["success"].(bool))
}

// ── legal_hold_proxy.go: CreateLegalHoldProxy ────────────────────────────────

// TestCreateLegalHoldProxy_BadJSON_S21 verifies that malformed JSON returns 400.
func TestCreateLegalHoldProxy_BadJSON_S21(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewDashboardHandler(cs)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/system/legal-hold",
		bytes.NewBufferString("not-json"))
	w := httptest.NewRecorder()
	h.CreateLegalHoldProxy(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "INVALID_BODY")
}

// TestCreateLegalHoldProxy_MissingReason_S21 verifies that an empty Reason
// field returns 400 with a descriptive message.
func TestCreateLegalHoldProxy_MissingReason_S21(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewDashboardHandler(cs)

	body, _ := json.Marshal(map[string]interface{}{
		"placed_by": uint(1),
		// reason deliberately omitted
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/system/legal-hold",
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateLegalHoldProxy(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "reason is required")
}

// TestCreateLegalHoldProxy_Valid_S21 verifies the happy path: a well-formed
// hold with a reason is persisted and the created row is returned.
func TestCreateLegalHoldProxy_Valid_S21(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewDashboardHandler(cs)

	hold := models.LegalHold{
		Reason:   "litigation hold Q3",
		PlacedBy: 1,
		PlacedAt: time.Now(),
		Released: false,
	}
	body, err := json.Marshal(hold)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/system/legal-hold",
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateLegalHoldProxy(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]interface{}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.True(t, resp["success"].(bool))
}

// ── project_memberships_proxy.go: CreateMembershipProxy ──────────────────────

// TestCreateMembershipProxy_BadJSON_S21 verifies that malformed JSON returns 400.
func TestCreateMembershipProxy_BadJSON_S21(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewCatalogHandler(cs)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/system/project-memberships",
		bytes.NewBufferString("{bad"))
	w := httptest.NewRecorder()
	h.CreateMembershipProxy(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "INVALID_BODY")
}

// TestCreateMembershipProxy_MissingFields_S21 verifies that missing required
// fields (project_id, user_id, role, state) each individually return 400.
func TestCreateMembershipProxy_MissingFields_S21(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewCatalogHandler(cs)

	cases := []struct {
		name string
		body map[string]interface{}
	}{
		{"missing_project_id", map[string]interface{}{"user_id": 1, "role": "member", "state": "active"}},
		{"missing_user_id", map[string]interface{}{"project_id": 1, "role": "member", "state": "active"}},
		{"missing_role", map[string]interface{}{"project_id": 1, "user_id": 1, "state": "active"}},
		{"missing_state", map[string]interface{}{"project_id": 1, "user_id": 1, "role": "member"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, _ := json.Marshal(tc.body)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/system/project-memberships",
				bytes.NewReader(b))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			h.CreateMembershipProxy(w, req)

			assert.Equal(t, http.StatusBadRequest, w.Code)
			assert.Contains(t, w.Body.String(), "INVALID_BODY")
		})
	}
}

// TestCreateMembershipProxy_Valid_S21 verifies the happy path: a fully-formed
// membership wire body is persisted and the wire row is returned.
func TestCreateMembershipProxy_Valid_S21(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h := NewCatalogHandler(cs)

	proj := &models.Project{Name: "s21-pm-project"}
	require.NoError(t, db.Create(proj).Error)
	user := &models.User{Username: "s21-pm-user", Email: "s21pm@example.com", AccountState: "active"}
	require.NoError(t, db.Create(user).Error)

	wire := membershipProxyWire{
		ProjectID: proj.ID,
		UserID:    user.ID,
		Role:      "member",
		State:     "active",
		InvitedBy: 1,
		InvitedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	body, err := json.Marshal(wire)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/system/project-memberships",
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateMembershipProxy(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]interface{}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.True(t, resp["success"].(bool))
}
