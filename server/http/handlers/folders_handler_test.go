// folders_handler_test.go — HTTP handler tests for FolderHandler.
//
// Covers:
//   - CreateFolder: happy path (201)
//   - CreateFolder: missing name → 400
//   - CreateFolder: missing project_id → 400
//   - ListFolders: happy path (200)
//   - ListFolders: invalid parent_id → 400
//   - DeleteFolder: happy path (204)
//   - DeleteFolder: invalid id → 400
//   - DeleteFolder: deleting a real secret returns 400 (not a folder)
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

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/server/middleware"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var folderHandlerDBCounter atomic.Int64

// freshFolderFixture creates an isolated in-memory SQLite DB with all required
// schema and seeds: user 1 as system_admin, project 1, environment 10.
// Returns the FolderHandler, core service, and raw DB.
func freshFolderFixture(t *testing.T) (*FolderHandler, *core.KeyorixCore, *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	n := folderHandlerDBCounter.Add(1)
	dsn := fmt.Sprintf("file:kxfolder_%d?mode=memory&cache=shared&_timeout=30000", n)
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)

	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Role{}, &models.UserRole{}, &models.Permission{},
		&models.RolePermission{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.Project{}, &models.Environment{}, &models.SecretNode{},
		&models.AuditEvent{}, &models.SecretVersion{}, &models.SecretAccessLog{},
		&models.ShareRecord{},
	))

	require.NoError(t, db.Create(&models.User{ID: 1, Username: "alice-folder", AccountState: "active"}).Error)
	adminRole := &models.Role{Name: "system_admin"}
	require.NoError(t, db.Create(adminRole).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: adminRole.ID}).Error)

	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "proj-folder"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 10, ProjectID: 1, Name: "prod-folder"}).Error)

	cs := core.NewKeyorixCore(store.NewLocalStorage(db))
	h := NewFolderHandler(cs)
	return h, cs, db
}

// withFolderAdminCtx injects a UserContext for user 1 into the request.
func withFolderAdminCtx(r *http.Request) *http.Request {
	uc := &middleware.UserContext{
		UserID: 1, Username: "alice-folder",
		ActorType: core.ActorTypeUser, SessionAuth: true, MFAEnabled: true,
	}
	return r.WithContext(context.WithValue(r.Context(), middleware.GetUserContextKey(), uc))
}

// ── CreateFolder ─────────────────────────────────────────────────────────────

func TestCreateFolder_HappyPath(t *testing.T) {
	h, _, _ := freshFolderFixture(t)

	body, _ := json.Marshal(map[string]interface{}{
		"name":           "configs",
		"project_id":     1,
		"environment_id": 10,
	})
	r := withFolderAdminCtx(httptest.NewRequest(http.MethodPost, "/api/v1/folders", bytes.NewReader(body)))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateFolder(w, r)

	assert.Equal(t, http.StatusCreated, w.Code)
	var resp SuccessResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.True(t, resp.Success)
}

func TestCreateFolder_MissingName(t *testing.T) {
	h, _, _ := freshFolderFixture(t)

	body, _ := json.Marshal(map[string]interface{}{
		"project_id":     1,
		"environment_id": 10,
	})
	r := withFolderAdminCtx(httptest.NewRequest(http.MethodPost, "/api/v1/folders", bytes.NewReader(body)))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateFolder(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "name is required")
}

func TestCreateFolder_MissingProjectID(t *testing.T) {
	h, _, _ := freshFolderFixture(t)

	body, _ := json.Marshal(map[string]interface{}{
		"name":           "configs",
		"environment_id": 10,
	})
	r := withFolderAdminCtx(httptest.NewRequest(http.MethodPost, "/api/v1/folders", bytes.NewReader(body)))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateFolder(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "project_id is required")
}

func TestCreateFolder_NoUserContext_401(t *testing.T) {
	h, _, _ := freshFolderFixture(t)

	body, _ := json.Marshal(map[string]interface{}{
		"name": "configs", "project_id": 1, "environment_id": 10,
	})
	// No user context injected.
	r := httptest.NewRequest(http.MethodPost, "/api/v1/folders", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateFolder(w, r)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── ListFolders ──────────────────────────────────────────────────────────────

func TestListFolders_HappyPath(t *testing.T) {
	h, cs, _ := freshFolderFixture(t)

	// Create a couple of folders first.
	_, err := cs.CreateFolder(context.Background(), 1, "alpha", 1, 10, nil)
	require.NoError(t, err)
	_, err = cs.CreateFolder(context.Background(), 1, "beta", 1, 10, nil)
	require.NoError(t, err)

	r := withFolderAdminCtx(httptest.NewRequest(http.MethodGet, "/api/v1/folders?project_id=1", nil))
	w := httptest.NewRecorder()
	h.ListFolders(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp SuccessResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.True(t, resp.Success)
}

func TestListFolders_InvalidParentID(t *testing.T) {
	h, _, _ := freshFolderFixture(t)

	r := withFolderAdminCtx(httptest.NewRequest(http.MethodGet, "/api/v1/folders?parent_id=notanumber", nil))
	w := httptest.NewRecorder()
	h.ListFolders(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListFolders_NoUserContext_401(t *testing.T) {
	h, _, _ := freshFolderFixture(t)

	r := httptest.NewRequest(http.MethodGet, "/api/v1/folders", nil)
	w := httptest.NewRecorder()
	h.ListFolders(w, r)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── DeleteFolder ─────────────────────────────────────────────────────────────

func TestDeleteFolder_HappyPath(t *testing.T) {
	h, cs, _ := freshFolderFixture(t)

	folder, err := cs.CreateFolder(context.Background(), 1, "to-delete", 1, 10, nil)
	require.NoError(t, err)

	r := withFolderAdminCtx(withChiParam(
		httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/api/v1/folders/%d", folder.ID), nil),
		"id", fmt.Sprintf("%d", folder.ID),
	))
	w := httptest.NewRecorder()
	h.DeleteFolder(w, r)

	assert.Equal(t, http.StatusNoContent, w.Code)
}

func TestDeleteFolder_InvalidID(t *testing.T) {
	h, _, _ := freshFolderFixture(t)

	r := withFolderAdminCtx(withChiParam(
		httptest.NewRequest(http.MethodDelete, "/api/v1/folders/notanumber", nil),
		"id", "notanumber",
	))
	w := httptest.NewRecorder()
	h.DeleteFolder(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDeleteFolder_IsSecret_Returns400(t *testing.T) {
	h, cs, _ := freshFolderFixture(t)

	// Create a real secret (IsSecret=true) and try to delete it as a folder.
	secret, err := cs.CreateSecret(context.Background(), &core.CreateSecretRequest{
		Name: "real-secret", Value: []byte("val"), ProjectID: 1, EnvironmentID: 10,
		Type: "generic", CreatedBy: "alice-folder", OwnerID: 1,
	})
	require.NoError(t, err)

	r := withFolderAdminCtx(withChiParam(
		httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/api/v1/folders/%d", secret.ID), nil),
		"id", fmt.Sprintf("%d", secret.ID),
	))
	w := httptest.NewRecorder()
	h.DeleteFolder(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "not a folder")
}
