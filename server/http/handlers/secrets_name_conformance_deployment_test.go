package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestDeploymentSecretNameConformanceHandler(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.SecretNode{}, &models.SecretVersion{}, &models.Project{}, &models.Environment{},
	))
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "alpha"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 1, Name: "production", ProjectID: 1}).Error)
	require.NoError(t, db.Create(&models.SecretNode{
		Name: "db-pass", ProjectID: 1, EnvironmentID: 1, Type: "password", OwnerID: 1, IsSecret: true,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}).Error)

	cs := core.NewKeyorixCore(store.NewLocalStorage(db))
	require.NoError(t, cs.SetSecretNamePolicy(core.SecretNamePolicy{Enabled: true, Pattern: "^[A-Z][A-Z0-9_]*$"}))
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)

	t.Run("reports the violating name tagged with its project", func(t *testing.T) {
		req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/secrets/name-conformance", nil))
		w := httptest.NewRecorder()
		h.DeploymentSecretNameConformance(w, req)

		require.Equal(t, http.StatusOK, w.Code)
		body := w.Body.String()
		assert.Contains(t, body, `"policy_enabled":true`)
		assert.Contains(t, body, `"project_name":"alpha"`)
		assert.Contains(t, body, "db-pass")
	})

	t.Run("requires a user context", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/secrets/name-conformance", nil)
		w := httptest.NewRecorder()
		h.DeploymentSecretNameConformance(w, req)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}
