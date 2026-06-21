package handlers

import (
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

func newCreateProjectHandler(t *testing.T) (*CatalogHandler, *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.Project{}, &models.Environment{}))
	return NewCatalogHandler(core.NewKeyorixCore(store.NewLocalStorage(db))), db
}

func postCreateProject(t *testing.T, h *CatalogHandler, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/projects", strings.NewReader(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateProject(w, req)
	return w
}

func envNames(t *testing.T, db *gorm.DB, projectID uint) []string {
	t.Helper()
	var envs []models.Environment
	require.NoError(t, db.Where("project_id = ?", projectID).Order("name").Find(&envs).Error)
	names := make([]string, 0, len(envs))
	for _, e := range envs {
		names = append(names, e.Name)
	}
	return names
}

func TestCreateProject_DefaultEnvironments(t *testing.T) {
	h, db := newCreateProjectHandler(t)

	w := postCreateProject(t, h, `{"name":"web"}`)

	require.Equal(t, http.StatusCreated, w.Code)
	var p models.Project
	require.NoError(t, db.Where("name = ?", "web").First(&p).Error)
	// Default set is seeded when no environments are supplied.
	assert.ElementsMatch(t, []string{"development", "staging", "production"}, envNames(t, db, p.ID))
}

func TestCreateProject_CustomEnvironments(t *testing.T) {
	h, db := newCreateProjectHandler(t)

	// Blank entries are dropped; exactly the supplied set is seeded (no defaults).
	w := postCreateProject(t, h, `{"name":"api","environments":["dev","prod","  "]}`)

	require.Equal(t, http.StatusCreated, w.Code)
	var p models.Project
	require.NoError(t, db.Where("name = ?", "api").First(&p).Error)
	assert.ElementsMatch(t, []string{"dev", "prod"}, envNames(t, db, p.ID))
}

func TestCreateProject_BlankEnvironmentsFallBackToDefaults(t *testing.T) {
	h, db := newCreateProjectHandler(t)

	// An environments array of only blanks behaves like omitting it → default set.
	w := postCreateProject(t, h, `{"name":"svc","environments":["  ",""]}`)

	require.Equal(t, http.StatusCreated, w.Code)
	var p models.Project
	require.NoError(t, db.Where("name = ?", "svc").First(&p).Error)
	assert.ElementsMatch(t, []string{"development", "staging", "production"}, envNames(t, db, p.ID))
}
