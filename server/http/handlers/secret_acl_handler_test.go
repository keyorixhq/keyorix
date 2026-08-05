// secret_acl_handler_test.go — integration tests for the per-secret ACL HTTP handlers
// (RBAC Phase 3): GET/POST/DELETE /api/v1/secrets/{id}/acl[/{aclId}].
package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/server/http/handlers/contracttest"
	customMiddleware "github.com/keyorixhq/keyorix/server/middleware"
)

var aclS36Counter atomic.Uint64

// freshCoreACL returns a KeyorixCore + DB for ACL handler tests, with an admin user (ID 1).
func freshCoreACL(t *testing.T) (*core.KeyorixCore, *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	n := aclS36Counter.Add(1)
	dsn := fmt.Sprintf("file:kxhandlers_acl_%d?mode=memory&cache=shared&_timeout=30000", n)
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Role{}, &models.UserRole{}, &models.Permission{},
		&models.RolePermission{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.Project{}, &models.Environment{}, &models.SecretNode{},
		&models.AuditEvent{}, &models.AnomalyAlert{},
		&models.ShareRecord{}, &models.SecretACL{}, &models.SecretAccessLog{},
	))
	// Seed project + environment so secrets can resolve scope.
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "p1"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 1, ProjectID: 1, Name: "env1"}).Error)
	// Make user 1 a global admin so they can call all handlers.
	adminRole := &models.Role{Name: "system_admin", Description: "Administrator"}
	require.NoError(t, db.Create(adminRole).Error)
	// memberRole is a minimal role used to make grant-target users project members.
	memberRole := &models.Role{Name: "member", Description: "Project member"}
	require.NoError(t, db.Create(memberRole).Error)
	require.NoError(t, db.Create(&models.User{Username: "testuser_acl", Email: "testuser_acl@example.com", AccountState: "active"}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: adminRole.ID}).Error)
	// Seed grant-target users used across ACL happy-path tests and give them project membership.
	// GrantSecretACL verifies the target is a project member (IsProjectMember checks project_id).
	for _, uid := range []uint{77, 88, 99, 123} {
		require.NoError(t, db.Create(&models.User{
			ID:       uid,
			Username: fmt.Sprintf("testgrant_%d", uid),
			Email:    fmt.Sprintf("grant%d@example.com", uid),
		}).Error)
		require.NoError(t, db.Create(&models.UserRole{UserID: uid, RoleID: memberRole.ID, ProjectID: 1}).Error)
	}
	return core.NewKeyorixCore(store.NewLocalStorage(db)), db
}

// mkACLHandlerSecret creates a secret in the handler test DB and returns its ID.
func mkACLHandlerSecret(t *testing.T, db *gorm.DB, name string) uint {
	t.Helper()
	s := &models.SecretNode{ProjectID: 1, EnvironmentID: 1, Name: name, IsSecret: true, Status: "active"}
	require.NoError(t, db.Create(s).Error)
	return s.ID
}

// withChiParam2ACL sets two chi URL params on the request.
func withChiParam2ACL(r *http.Request, k1, v1, k2, v2 string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add(k1, v1)
	rctx.URLParams.Add(k2, v2)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

// withUserCtxACL injects a UserContext for user ID 1 into the request context.
func withUserCtxACL(r *http.Request) *http.Request {
	userCtx := &customMiddleware.UserContext{
		UserID:   1,
		Username: "testuser_acl",
		Email:    "testuser_acl@example.com",
	}
	return r.WithContext(context.WithValue(r.Context(), customMiddleware.GetUserContextKey(), userCtx))
}

// ── ListSecretACLs ─────────────────────────────────────────────────────────────

// TestListSecretACLs_NoAuth returns 401 when no user context is present.
func TestListSecretACLs_NoAuth(t *testing.T) {
	t.Parallel()
	cs, _ := freshCoreACL(t)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)

	req := withChiParam(httptest.NewRequest(http.MethodGet, "/api/v1/secrets/1/acl", nil), "id", "1")
	w := httptest.NewRecorder()
	h.ListSecretACLs(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestListSecretACLs_BadParam returns 400 on a non-numeric secret ID.
func TestListSecretACLs_BadParam(t *testing.T) {
	t.Parallel()
	cs, _ := freshCoreACL(t)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)

	req := withUserCtxACL(withChiParam(httptest.NewRequest(http.MethodGet, "/api/v1/secrets/abc/acl", nil), "id", "abc"))
	w := httptest.NewRecorder()
	h.ListSecretACLs(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestListSecretACLs_Empty returns 200 with an empty list when no grants exist.
func TestListSecretACLs_Empty(t *testing.T) {
	t.Parallel()
	cs, db := freshCoreACL(t)
	sid := mkACLHandlerSecret(t, db, "test-secret-list")
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)

	req := withUserCtxACL(withChiParam(
		httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/secrets/%d/acl", sid), nil),
		"id", fmt.Sprintf("%d", sid),
	))
	w := httptest.NewRecorder()
	h.ListSecretACLs(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	contracttest.AssertOpenAPIResponse(t, req, w)
	// Response should contain an empty list (null or []).
	assert.Contains(t, w.Body.String(), "success")
}

// ── GrantSecretACL ─────────────────────────────────────────────────────────────

// TestGrantSecretACL_NoAuth returns 401 when no user context is present.
func TestGrantSecretACL_NoAuth(t *testing.T) {
	t.Parallel()
	cs, _ := freshCoreACL(t)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)

	req := withChiParam(httptest.NewRequest(http.MethodPost, "/api/v1/secrets/1/acl", nil), "id", "1")
	w := httptest.NewRecorder()
	h.GrantSecretACL(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestGrantSecretACL_BadParam returns 400 on non-numeric secret ID.
func TestGrantSecretACL_BadParam(t *testing.T) {
	t.Parallel()
	cs, _ := freshCoreACL(t)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)

	body, _ := json.Marshal(map[string]interface{}{"user_id": 2, "permissions": []string{"secrets.read"}})
	req := withUserCtxACL(withChiParam(
		httptest.NewRequest(http.MethodPost, "/api/v1/secrets/abc/acl", bytes.NewReader(body)),
		"id", "abc",
	))
	w := httptest.NewRecorder()
	h.GrantSecretACL(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestGrantSecretACL_BadJSON returns 400 on invalid JSON body.
func TestGrantSecretACL_BadJSON(t *testing.T) {
	t.Parallel()
	cs, db := freshCoreACL(t)
	sid := mkACLHandlerSecret(t, db, "grant-badjson")
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)

	req := withUserCtxACL(withChiParam(
		httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/v1/secrets/%d/acl", sid), bytes.NewBufferString("{not json")),
		"id", fmt.Sprintf("%d", sid),
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.GrantSecretACL(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestGrantSecretACL_MissingUserID returns 400 when user_id is missing.
func TestGrantSecretACL_MissingUserID(t *testing.T) {
	t.Parallel()
	cs, db := freshCoreACL(t)
	sid := mkACLHandlerSecret(t, db, "grant-nouserid")
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)

	body, _ := json.Marshal(map[string]interface{}{"permissions": []string{"secrets.read"}})
	req := withUserCtxACL(withChiParam(
		httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/v1/secrets/%d/acl", sid), bytes.NewReader(body)),
		"id", fmt.Sprintf("%d", sid),
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.GrantSecretACL(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "user_id")
}

// TestGrantSecretACL_HappyPath grants access and verifies success + list returns it.
func TestGrantSecretACL_HappyPath(t *testing.T) {
	t.Parallel()
	cs, db := freshCoreACL(t)
	sid := mkACLHandlerSecret(t, db, "grant-happy")
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)

	body, _ := json.Marshal(map[string]interface{}{"user_id": 77, "permissions": []string{"secrets.read"}})
	req := withUserCtxACL(withChiParam(
		httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/v1/secrets/%d/acl", sid), bytes.NewReader(body)),
		"id", fmt.Sprintf("%d", sid),
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.GrantSecretACL(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "granted")

	// Verify via ListSecretACLs.
	req2 := withUserCtxACL(withChiParam(
		httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/secrets/%d/acl", sid), nil),
		"id", fmt.Sprintf("%d", sid),
	))
	w2 := httptest.NewRecorder()
	h.ListSecretACLs(w2, req2)
	assert.Equal(t, http.StatusOK, w2.Code)
	// The response data should contain the ACL row with user_id 77.
	body2 := w2.Body.String()
	assert.Contains(t, body2, "77")
	// TestListSecretACLs_Empty (this operation's other exercising test) only
	// ever asserts against an empty array, which JSON Schema validates
	// vacuously -- this call is what actually exercises the SecretACL item
	// schema (registry.go's exercisingTests lists this test for
	// listSecretACLs precisely so a populated response gets checked too).
	contracttest.AssertOpenAPIResponse(t, req2, w2)
}

// ── RevokeSecretACL ────────────────────────────────────────────────────────────

// TestRevokeSecretACL_NoAuth returns 401 when no user context is present.
func TestRevokeSecretACL_NoAuth(t *testing.T) {
	t.Parallel()
	cs, _ := freshCoreACL(t)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)

	req := withChiParam2ACL(
		httptest.NewRequest(http.MethodDelete, "/api/v1/secrets/1/acl/1", nil),
		"id", "1", "aclId", "1",
	)
	w := httptest.NewRecorder()
	h.RevokeSecretACL(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestRevokeSecretACL_BadSecretID returns 400 on non-numeric secret ID.
func TestRevokeSecretACL_BadSecretID(t *testing.T) {
	t.Parallel()
	cs, _ := freshCoreACL(t)
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)

	req := withUserCtxACL(withChiParam2ACL(
		httptest.NewRequest(http.MethodDelete, "/api/v1/secrets/abc/acl/1", nil),
		"id", "abc", "aclId", "1",
	))
	w := httptest.NewRecorder()
	h.RevokeSecretACL(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestRevokeSecretACL_BadACLID returns 400 on non-numeric ACL ID.
func TestRevokeSecretACL_BadACLID(t *testing.T) {
	t.Parallel()
	cs, db := freshCoreACL(t)
	sid := mkACLHandlerSecret(t, db, "revoke-badid")
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)

	req := withUserCtxACL(withChiParam2ACL(
		httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/api/v1/secrets/%d/acl/abc", sid), nil),
		"id", fmt.Sprintf("%d", sid), "aclId", "abc",
	))
	w := httptest.NewRecorder()
	h.RevokeSecretACL(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestRevokeSecretACL_NotFound returns 4xx on a non-existent ACL ID.
func TestRevokeSecretACL_NotFound(t *testing.T) {
	t.Parallel()
	cs, db := freshCoreACL(t)
	sid := mkACLHandlerSecret(t, db, "revoke-notfound")
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)

	req := withUserCtxACL(withChiParam2ACL(
		httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/api/v1/secrets/%d/acl/9999", sid), nil),
		"id", fmt.Sprintf("%d", sid), "aclId", "9999",
	))
	w := httptest.NewRecorder()
	h.RevokeSecretACL(w, req)
	// ACL 9999 doesn't exist → error response (not 200).
	assert.NotEqual(t, http.StatusOK, w.Code)
}

// TestGrantSecretACL_EmptyPermissions returns 400 when permissions slice is empty.
func TestGrantSecretACL_EmptyPermissions(t *testing.T) {
	t.Parallel()
	cs, db := freshCoreACL(t)
	sid := mkACLHandlerSecret(t, db, "grant-emptyperms")
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)

	body, _ := json.Marshal(map[string]interface{}{"user_id": 55, "permissions": []string{}})
	req := withUserCtxACL(withChiParam(
		httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/v1/secrets/%d/acl", sid), bytes.NewReader(body)),
		"id", fmt.Sprintf("%d", sid),
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.GrantSecretACL(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "permissions")
}

// TestGrantSecretACL_InvalidPermission returns an error when an unrecognised permission is used.
func TestGrantSecretACL_InvalidPermission(t *testing.T) {
	t.Parallel()
	cs, db := freshCoreACL(t)
	sid := mkACLHandlerSecret(t, db, "grant-invalidperm")
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)

	body, _ := json.Marshal(map[string]interface{}{"user_id": 66, "permissions": []string{"secrets.admin"}})
	req := withUserCtxACL(withChiParam(
		httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/v1/secrets/%d/acl", sid), bytes.NewReader(body)),
		"id", fmt.Sprintf("%d", sid),
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.GrantSecretACL(w, req)
	// Core rejects invalid permissions — expect 4xx.
	assert.NotEqual(t, http.StatusOK, w.Code)
}

// TestRevokeSecretACL_HappyPath is a standalone targeted test for the revoke success branch.
func TestRevokeSecretACL_HappyPath(t *testing.T) {
	t.Parallel()
	cs, db := freshCoreACL(t)
	sid := mkACLHandlerSecret(t, db, "revoke-happy")
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)

	// Grant first.
	grantBody, _ := json.Marshal(map[string]interface{}{"user_id": 99, "permissions": []string{"secrets.read"}})
	req := withUserCtxACL(withChiParam(
		httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/v1/secrets/%d/acl", sid), bytes.NewReader(grantBody)),
		"id", fmt.Sprintf("%d", sid),
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.GrantSecretACL(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	// Fetch the ACL ID.
	req2 := withUserCtxACL(withChiParam(
		httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/secrets/%d/acl", sid), nil),
		"id", fmt.Sprintf("%d", sid),
	))
	w2 := httptest.NewRecorder()
	h.ListSecretACLs(w2, req2)
	require.Equal(t, http.StatusOK, w2.Code)
	var listResp struct {
		Data []struct {
			ID uint `json:"id"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w2.Body.Bytes(), &listResp))
	require.Len(t, listResp.Data, 1)
	aclID := listResp.Data[0].ID

	// Revoke.
	req3 := withUserCtxACL(withChiParam2ACL(
		httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/api/v1/secrets/%d/acl/%d", sid, aclID), nil),
		"id", fmt.Sprintf("%d", sid), "aclId", fmt.Sprintf("%d", aclID),
	))
	w3 := httptest.NewRecorder()
	h.RevokeSecretACL(w3, req3)
	assert.Equal(t, http.StatusOK, w3.Code)
	assert.Contains(t, w3.Body.String(), "revoked")
}

// TestListSecretACLs_WithACLs returns 200 with ACL data when grants exist.
func TestListSecretACLs_WithACLs(t *testing.T) {
	t.Parallel()
	cs, db := freshCoreACL(t)
	sid := mkACLHandlerSecret(t, db, "list-with-acls")
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)

	// Grant first.
	grantBody, _ := json.Marshal(map[string]interface{}{"user_id": 123, "permissions": []string{"secrets.read"}})
	req := withUserCtxACL(withChiParam(
		httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/v1/secrets/%d/acl", sid), bytes.NewReader(grantBody)),
		"id", fmt.Sprintf("%d", sid),
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.GrantSecretACL(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	// List.
	req2 := withUserCtxACL(withChiParam(
		httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/secrets/%d/acl", sid), nil),
		"id", fmt.Sprintf("%d", sid),
	))
	w2 := httptest.NewRecorder()
	h.ListSecretACLs(w2, req2)
	assert.Equal(t, http.StatusOK, w2.Code)
	body := w2.Body.String()
	assert.Contains(t, body, "success")
	assert.Contains(t, body, "123")
}

// TestAclErrorStatus_Forbidden verifies the 403 branch of aclErrorStatus.
func TestAclErrorStatus_Forbidden(t *testing.T) {
	code := aclErrorStatus("not authorized to perform this action")
	assert.Equal(t, http.StatusForbidden, code)
}

// TestAclErrorStatus_NotFound verifies the 404 branch of aclErrorStatus.
func TestAclErrorStatus_NotFound(t *testing.T) {
	code := aclErrorStatus("record not found")
	assert.Equal(t, http.StatusNotFound, code)
}

// TestAclErrorStatus_BadRequest verifies the 400 branch of aclErrorStatus.
func TestAclErrorStatus_BadRequest(t *testing.T) {
	code := aclErrorStatus("invalid permission value provided")
	assert.Equal(t, http.StatusBadRequest, code)
}

// TestAclErrorStatus_InternalServerError verifies the 500 default branch of aclErrorStatus.
func TestAclErrorStatus_InternalServerError(t *testing.T) {
	code := aclErrorStatus("database connection failed")
	assert.Equal(t, http.StatusInternalServerError, code)
}

// TestGrantRevokeACL_RoundTrip verifies the full grant → list → revoke → list cycle.
func TestGrantRevokeACL_RoundTrip(t *testing.T) {
	t.Parallel()
	cs, db := freshCoreACL(t)
	sid := mkACLHandlerSecret(t, db, "roundtrip-acl")
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)

	// 1. Grant.
	grantBody, _ := json.Marshal(map[string]interface{}{"user_id": 88, "permissions": []string{"secrets.read"}})
	req := withUserCtxACL(withChiParam(
		httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/v1/secrets/%d/acl", sid), bytes.NewReader(grantBody)),
		"id", fmt.Sprintf("%d", sid),
	))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.GrantSecretACL(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	// 2. List — should have 1 entry.
	req2 := withUserCtxACL(withChiParam(
		httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/secrets/%d/acl", sid), nil),
		"id", fmt.Sprintf("%d", sid),
	))
	w2 := httptest.NewRecorder()
	h.ListSecretACLs(w2, req2)
	require.Equal(t, http.StatusOK, w2.Code)

	var resp struct {
		Data []struct {
			ID uint `json:"id"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w2.Body.Bytes(), &resp))
	require.Len(t, resp.Data, 1)
	aclID := resp.Data[0].ID

	// 3. Revoke.
	req3 := withUserCtxACL(withChiParam2ACL(
		httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/api/v1/secrets/%d/acl/%d", sid, aclID), nil),
		"id", fmt.Sprintf("%d", sid), "aclId", fmt.Sprintf("%d", aclID),
	))
	w3 := httptest.NewRecorder()
	h.RevokeSecretACL(w3, req3)
	require.Equal(t, http.StatusOK, w3.Code)

	// 4. List again — should be empty.
	req4 := withUserCtxACL(withChiParam(
		httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/secrets/%d/acl", sid), nil),
		"id", fmt.Sprintf("%d", sid),
	))
	w4 := httptest.NewRecorder()
	h.ListSecretACLs(w4, req4)
	require.Equal(t, http.StatusOK, w4.Code)
	var resp4 struct {
		Data interface{} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w4.Body.Bytes(), &resp4))
	// data should be null or an empty list
	switch v := resp4.Data.(type) {
	case []interface{}:
		assert.Empty(t, v)
	case nil:
		// nil is fine too
	}
}
