package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func mustCreateRole(t *testing.T, db *gorm.DB, name string) *models.Role {
	t.Helper()
	role := &models.Role{Name: name, Description: name + " role"}
	require.NoError(t, db.Create(role).Error)
	return role
}

func mustCreatePermission(t *testing.T, db *gorm.DB, name, resource, action string) *models.Permission {
	t.Helper()
	perm := &models.Permission{Name: name, Resource: resource, Action: action}
	require.NoError(t, db.Create(perm).Error)
	return perm
}

func mustCreateGroup(t *testing.T, db *gorm.DB, name string) *models.Group {
	t.Helper()
	group := &models.Group{Name: name}
	require.NoError(t, db.Create(group).Error)
	return group
}

// openTestDB opens a fresh in-memory SQLite DB and auto-migrates RBAC tables. Makes
// the test user (withUserCtx's UserID 1) a global admin so AssignPermissionToRole's
// #169 self-permission check (via the admin bypass) doesn't block these RBAC-plumbing
// tests, which aren't testing that authorization boundary themselves.
func openTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.Role{},
		&models.Permission{},
		&models.RolePermission{},
		&models.UserRole{},
		&models.Group{},
		&models.UserGroup{},
		&models.GroupRole{},
		&models.User{},
	))
	// A distinct name from any role individual tests create via mustCreateRole (some
	// create their own role literally named "admin" for unrelated purposes) — Role.Name
	// is unique, so this must not collide with those.
	adminRole := &models.Role{Name: "system_admin", Description: "Administrator"}
	require.NoError(t, db.Create(adminRole).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: adminRole.ID}).Error)
	return db
}

// withChiParams sets multiple chi URL params on the request at once.
func withChiParams(r *http.Request, params map[string]string) *http.Request {
	rctx := chi.NewRouteContext()
	for k, v := range params {
		rctx.URLParams.Add(k, v)
	}
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

func setupRBACTestWithDB(t *testing.T) (*RBACHandler, *core.KeyorixCore, *gorm.DB) {
	t.Helper()

	cfg := &config.Config{
		Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
	}
	require.NoError(t, i18n.Initialize(cfg))

	db := openTestDB(t)
	storage := store.NewLocalStorage(db)
	coreService := core.NewKeyorixCore(storage)
	handler := NewRBACHandler(coreService)
	return handler, coreService, db
}

func TestRBACReal_ListRoles200(t *testing.T) {
	handler, _, db := setupRBACTestWithDB(t)
	mustCreateRole(t, db, "viewer")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/roles", nil)
	req = withUserCtx(req)
	w := httptest.NewRecorder()

	handler.ListRoles(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]interface{}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	data, ok := resp["data"].(map[string]interface{})
	require.True(t, ok)
	assert.GreaterOrEqual(t, int(data["total"].(float64)), 1)
}

func TestRBACReal_ListPermissions200(t *testing.T) {
	handler, _, db := setupRBACTestWithDB(t)
	mustCreatePermission(t, db, "secrets.read", "secrets", "read")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/permissions", nil)
	req = withUserCtx(req)
	w := httptest.NewRecorder()

	handler.ListPermissions(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]interface{}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	data := resp["data"].(map[string]interface{})
	assert.GreaterOrEqual(t, int(data["total"].(float64)), 1)
}

func TestRBACReal_GetRolePermissions200(t *testing.T) {
	handler, _, db := setupRBACTestWithDB(t)
	role := mustCreateRole(t, db, "editor")
	perm := mustCreatePermission(t, db, "secrets.write", "secrets", "write")
	require.NoError(t, db.Create(&models.RolePermission{RoleID: role.ID, PermissionID: perm.ID}).Error)

	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/roles/%d/permissions", role.ID), nil)
	req = withUserCtx(withChiParam(req, "id", fmt.Sprintf("%d", role.ID)))
	w := httptest.NewRecorder()

	handler.GetRolePermissions(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRBACReal_AssignPermissionToRole201(t *testing.T) {
	handler, _, db := setupRBACTestWithDB(t)
	role := mustCreateRole(t, db, "admin")
	perm := mustCreatePermission(t, db, "audit.read", "audit", "read")

	body := fmt.Sprintf(`{"permission_id":%d}`, perm.ID)
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/v1/roles/%d/permissions", role.ID),
		bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req = withUserCtx(withChiParam(req, "id", fmt.Sprintf("%d", role.ID)))
	w := httptest.NewRecorder()

	handler.AssignPermissionToRole(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
}

func TestRBACReal_RemovePermissionFromRole204(t *testing.T) {
	handler, _, db := setupRBACTestWithDB(t)
	role := mustCreateRole(t, db, "operator")
	perm := mustCreatePermission(t, db, "users.read", "users", "read")
	require.NoError(t, db.Create(&models.RolePermission{RoleID: role.ID, PermissionID: perm.ID}).Error)

	req := httptest.NewRequest(http.MethodDelete,
		fmt.Sprintf("/api/v1/roles/%d/permissions/%d", role.ID, perm.ID), nil)
	req = withUserCtx(withChiParams(req, map[string]string{
		"id":           fmt.Sprintf("%d", role.ID),
		"permissionId": fmt.Sprintf("%d", perm.ID),
	}))
	w := httptest.NewRecorder()

	handler.RemovePermissionFromRole(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
}

func TestRBACReal_GetGroupRoles200(t *testing.T) {
	handler, _, db := setupRBACTestWithDB(t)
	group := mustCreateGroup(t, db, "dev-team")
	role := mustCreateRole(t, db, "developer")
	require.NoError(t, db.Create(&models.GroupRole{GroupID: group.ID, RoleID: role.ID}).Error)

	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/groups/%d/roles", group.ID), nil)
	req = withUserCtx(withChiParam(req, "id", fmt.Sprintf("%d", group.ID)))
	w := httptest.NewRecorder()

	handler.GetGroupRoles(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]interface{}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	data := resp["data"].(map[string]interface{})
	roles := data["roles"].([]interface{})
	assert.Len(t, roles, 1)
}

// GetGroupRoles surfaces each grant's expiry: a permanent grant omits expires_at,
// a time-bound grant carries it.
func TestRBACReal_GetGroupRoles_CarriesExpiry(t *testing.T) {
	handler, _, db := setupRBACTestWithDB(t)
	group := mustCreateGroup(t, db, "exp-team")
	permRole := mustCreateRole(t, db, "perm-role")
	jitRole := mustCreateRole(t, db, "jit-role-g")
	exp := time.Now().Add(2 * time.Hour)
	require.NoError(t, db.Create(&models.GroupRole{GroupID: group.ID, RoleID: permRole.ID}).Error)
	require.NoError(t, db.Create(&models.GroupRole{GroupID: group.ID, RoleID: jitRole.ID, ExpiresAt: &exp}).Error)

	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/groups/%d/roles", group.ID), nil),
		"id", fmt.Sprintf("%d", group.ID)))
	w := httptest.NewRecorder()

	handler.GetGroupRoles(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]interface{}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	roles := resp["data"].(map[string]interface{})["roles"].([]interface{})
	require.Len(t, roles, 2)

	byName := map[string]map[string]interface{}{}
	for _, r := range roles {
		m := r.(map[string]interface{})
		byName[m["name"].(string)] = m
	}
	_, hasExpiry := byName["perm-role"]["expires_at"]
	assert.False(t, hasExpiry, "a permanent grant omits expires_at")
	assert.NotEmpty(t, byName["jit-role-g"]["expires_at"], "a time-bound grant carries expires_at")
}

func TestRBACReal_AssignRoleToGroup201(t *testing.T) {
	handler, _, db := setupRBACTestWithDB(t)
	group := mustCreateGroup(t, db, "ops-team")
	role := mustCreateRole(t, db, "sre")

	body := fmt.Sprintf(`{"role_id":%d}`, role.ID)
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/v1/groups/%d/roles", group.ID),
		bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req = withUserCtx(withChiParam(req, "id", fmt.Sprintf("%d", group.ID)))
	w := httptest.NewRecorder()

	handler.AssignRoleToGroup(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
}

func TestRBACReal_RemoveRoleFromGroup204(t *testing.T) {
	handler, _, db := setupRBACTestWithDB(t)
	group := mustCreateGroup(t, db, "qa-team")
	role := mustCreateRole(t, db, "tester")
	require.NoError(t, db.Create(&models.GroupRole{GroupID: group.ID, RoleID: role.ID}).Error)

	req := httptest.NewRequest(http.MethodDelete,
		fmt.Sprintf("/api/v1/groups/%d/roles/%d", group.ID, role.ID), nil)
	req = withUserCtx(withChiParams(req, map[string]string{
		"id":     fmt.Sprintf("%d", group.ID),
		"roleId": fmt.Sprintf("%d", role.ID),
	}))
	w := httptest.NewRecorder()

	handler.RemoveRoleFromGroup(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
}

func TestRBACReal_DeleteRole_Builtin_Forbidden(t *testing.T) {
	handler, _, db := setupRBACTestWithDB(t)
	role := mustCreateRole(t, db, "admin")

	req := httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/api/v1/roles/%d", role.ID), nil)
	req = withUserCtx(withChiParam(req, "id", fmt.Sprintf("%d", role.ID)))
	w := httptest.NewRecorder()

	handler.DeleteRole(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestRBACReal_GetRole_NotFound(t *testing.T) {
	handler, _, _ := setupRBACTestWithDB(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/roles/99999", nil)
	req = withUserCtx(withChiParam(req, "id", "99999"))
	w := httptest.NewRecorder()

	handler.GetRole(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestRBACReal_AssignRole_Conflict(t *testing.T) {
	handler, _, db := setupRBACTestWithDB(t)

	user := &models.User{Username: "testuser99", Email: "testuser99@example.com", PasswordHash: "x"}
	require.NoError(t, db.Create(user).Error)
	role := mustCreateRole(t, db, "viewer99")

	body := fmt.Sprintf(`{"user_id":%d,"role_id":%d}`, user.ID, role.ID)
	doAssign := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/user-roles",
			bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		req = withUserCtx(req)
		w := httptest.NewRecorder()
		handler.AssignRole(w, req)
		return w
	}

	assert.Equal(t, http.StatusCreated, doAssign().Code)
	assert.Equal(t, http.StatusConflict, doAssign().Code)
}

// A time-bound user grant (expires_at in the future) is created and persists the
// expiry on the UserRole row, so the JIT sweep can later reclaim it.
func TestRBACReal_AssignRole_TimeBound(t *testing.T) {
	handler, _, db := setupRBACTestWithDB(t)
	user := &models.User{Username: "jit-user", Email: "jit@example.com", PasswordHash: "x"}
	require.NoError(t, db.Create(user).Error)
	role := mustCreateRole(t, db, "jit-role")

	expiry := time.Now().Add(2 * time.Hour).UTC().Format(time.RFC3339)
	body := fmt.Sprintf(`{"user_id":%d,"role_id":%d,"expires_at":%q}`, user.ID, role.ID, expiry)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/user-roles", bytes.NewBufferString(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.AssignRole(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	var ur models.UserRole
	require.NoError(t, db.Where("user_id = ? AND role_id = ?", user.ID, role.ID).First(&ur).Error)
	require.NotNil(t, ur.ExpiresAt, "the grant must carry the expiry")
	assert.True(t, ur.ExpiresAt.After(time.Now()))
}

// An already-past expiry is rejected before any grant is written.
func TestRBACReal_AssignRole_PastExpiry_400(t *testing.T) {
	handler, _, db := setupRBACTestWithDB(t)
	user := &models.User{Username: "past-user", Email: "past@example.com", PasswordHash: "x"}
	require.NoError(t, db.Create(user).Error)
	role := mustCreateRole(t, db, "past-role")

	expiry := time.Now().Add(-1 * time.Hour).UTC().Format(time.RFC3339)
	body := fmt.Sprintf(`{"user_id":%d,"role_id":%d,"expires_at":%q}`, user.ID, role.ID, expiry)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/user-roles", bytes.NewBufferString(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.AssignRole(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var n int64
	// Scoped to the specific (user, role) under test, not a bare table count — openTestDB
	// itself seeds a UserRole granting the test actor admin authority (#169).
	require.NoError(t, db.Model(&models.UserRole{}).Where("user_id = ? AND role_id = ?", user.ID, role.ID).Count(&n).Error)
	assert.Zero(t, n, "no grant should be written when the expiry is rejected")
}

// A time-bound group grant persists the expiry on the GroupRole row.
func TestRBACReal_AssignRoleToGroup_TimeBound(t *testing.T) {
	handler, _, db := setupRBACTestWithDB(t)
	group := mustCreateGroup(t, db, "jit-team")
	role := mustCreateRole(t, db, "jit-team-role")

	expiry := time.Now().Add(3 * time.Hour).UTC().Format(time.RFC3339)
	body := fmt.Sprintf(`{"role_id":%d,"expires_at":%q}`, role.ID, expiry)
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/v1/groups/%d/roles", group.ID), bytes.NewBufferString(body)),
		"id", fmt.Sprintf("%d", group.ID)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.AssignRoleToGroup(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	var gr models.GroupRole
	require.NoError(t, db.Where("group_id = ? AND role_id = ?", group.ID, role.ID).First(&gr).Error)
	require.NotNil(t, gr.ExpiresAt, "the group grant must carry the expiry")
}

// GET /users/{id}/permissions returns the effective permission set (union across the
// user's roles) and excludes permissions granted only through an EXPIRED time-bound role.
func TestRBACReal_GetUserPermissionsForUser(t *testing.T) {
	db := openTestDB(t)
	handler := NewUsersRolesHandler(core.NewKeyorixCore(store.NewLocalStorage(db)))

	user := &models.User{Username: "perm-user", Email: "perm@example.com", PasswordHash: "x"}
	require.NoError(t, db.Create(user).Error)
	role := mustCreateRole(t, db, "reader")
	expiredRole := mustCreateRole(t, db, "temp-writer")
	readPerm := &models.Permission{Name: "secrets.read", Description: "read secrets", Resource: "secrets", Action: "read"}
	writePerm := &models.Permission{Name: "secrets.write", Description: "write secrets", Resource: "secrets", Action: "write"}
	require.NoError(t, db.Create(readPerm).Error)
	require.NoError(t, db.Create(writePerm).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: role.ID, PermissionID: readPerm.ID}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: expiredRole.ID, PermissionID: writePerm.ID}).Error)
	// A live grant of the reader role, plus an already-expired grant of temp-writer.
	past := time.Now().Add(-1 * time.Hour)
	require.NoError(t, db.Create(&models.UserRole{UserID: user.ID, RoleID: role.ID}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: user.ID, RoleID: expiredRole.ID, ExpiresAt: &past}).Error)

	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/users/%d/permissions", user.ID), nil),
		"id", fmt.Sprintf("%d", user.ID)))
	w := httptest.NewRecorder()

	handler.GetUserPermissionsForUser(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]interface{}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	perms := resp["data"].(map[string]interface{})["permissions"].([]interface{})
	names := make([]string, 0, len(perms))
	for _, p := range perms {
		names = append(names, p.(map[string]interface{})["name"].(string))
	}
	assert.Contains(t, names, "secrets.read")
	assert.NotContains(t, names, "secrets.write", "an expired time-bound grant confers no permissions")
}

func TestRBACReal_Unauthorized(t *testing.T) {
	handler, _, _ := setupRBACTestWithDB(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/roles", nil)
	// no user context injected
	w := httptest.NewRecorder()

	handler.ListRoles(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// Verify that AssignRoleToGroup returns 409 when the role is already assigned.
func TestRBACReal_AssignRoleToGroup_Conflict(t *testing.T) {
	handler, _, db := setupRBACTestWithDB(t)
	group := mustCreateGroup(t, db, "infra-team")
	role := mustCreateRole(t, db, "infra-role")
	require.NoError(t, db.Create(&models.GroupRole{GroupID: group.ID, RoleID: role.ID}).Error)

	body := fmt.Sprintf(`{"role_id":%d}`, role.ID)
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/v1/groups/%d/roles", group.ID),
		bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req = withUserCtx(withChiParam(req, "id", fmt.Sprintf("%d", group.ID)))
	w := httptest.NewRecorder()

	handler.AssignRoleToGroup(w, req)

	assert.Equal(t, http.StatusConflict, w.Code)
}
