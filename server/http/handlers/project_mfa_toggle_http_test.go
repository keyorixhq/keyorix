// project_mfa_toggle_http_test.go — HTTP-layer happy-path coverage for the
// ADR-037 require_mfa toggle on PUT /api/v1/projects/{id}. The existing
// negative-path tests (handlers_s4_test.go, handlers_s5_test.go) cover the
// 401 (no user context) and 403 (no roles.assign) rejections; this covers
// the authorized success path — an actor holding roles.assign at the
// project scope gets 200 and the flag is actually persisted — which
// exercises the same handler+core wiring the keyorix-web Settings toggle
// (PR keyorix-web#145) calls.
package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// setupProjectMFAToggleTest builds an isolated DB (not the shared s4/s5
// fixture, to avoid any order-dependence on other tests' seeded roles) with
// one project and one user holding roles.assign at that project's scope.
func setupProjectMFAToggleTest(t *testing.T) (*CatalogHandler, *gorm.DB, uint) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Project{}, &models.Environment{}, &models.Role{}, &models.Permission{},
		&models.RolePermission{}, &models.UserRole{}, &models.AuditEvent{},
		&models.Group{}, &models.UserGroup{}, &models.GroupRole{},
	))

	require.NoError(t, db.Create(&models.User{ID: 1, Username: "admin", Email: "admin@example.com"}).Error)
	proj := &models.Project{Name: "default", RequireMFA: false}
	require.NoError(t, db.Create(proj).Error)

	role := &models.Role{Name: "project_admin_test"}
	require.NoError(t, db.Create(role).Error)
	perm := &models.Permission{Name: "roles.assign", Resource: "roles", Action: "assign"}
	require.NoError(t, db.Create(perm).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: role.ID, PermissionID: perm.ID}).Error)
	// Scoped to this project (not global) — roles.assign held only here.
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: role.ID, ProjectID: proj.ID}).Error)

	return NewCatalogHandler(core.NewKeyorixCore(store.NewLocalStorage(db))), db, proj.ID
}

func TestCatalogHandler_UpdateProject_RequireMFA_AuthorizedSucceeds(t *testing.T) {
	h, db, projectID := setupProjectMFAToggleTest(t)

	body := `{"name":"default","require_mfa":true}`
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPut, "/", strings.NewReader(body)), "id", itoa(projectID)))
	w := httptest.NewRecorder()
	h.UpdateProject(w, req)

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var resp struct {
		Data struct {
			RequireMFA bool `json:"RequireMFA"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.True(t, resp.Data.RequireMFA, "response should reflect the toggled value")

	var persisted models.Project
	require.NoError(t, db.First(&persisted, projectID).Error)
	assert.True(t, persisted.RequireMFA, "the flag must actually be persisted, not just echoed back")
}
