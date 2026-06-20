package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestDeploymentSecretsInventoryCSV(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.SecretNode{}, &models.SecretVersion{}, &models.User{}, &models.Project{}, &models.Environment{},
	))
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "alice", Email: "a@t.com"}).Error)
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "alpha"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 1, Name: "production", ProjectID: 1}).Error)
	require.NoError(t, db.Create(&models.SecretNode{
		Name: "db-pass", ProjectID: 1, EnvironmentID: 1, Type: "password", OwnerID: 1,
		IsSecret: true, CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}).Error)

	h, err := NewSecretHandler(core.NewKeyorixCore(store.NewLocalStorage(db)))
	require.NoError(t, err)

	t.Run("returns an org-wide CSV with a project column and the secret metadata", func(t *testing.T) {
		req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/secrets/inventory.csv", nil))
		w := httptest.NewRecorder()
		h.DeploymentSecretsInventoryCSV(w, req)

		require.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Header().Get("Content-Type"), "text/csv")
		assert.Contains(t, w.Header().Get("Content-Disposition"), "secret-inventory-all-projects.csv")

		body := w.Body.String()
		lines := strings.Split(strings.TrimSpace(body), "\n")
		require.GreaterOrEqual(t, len(lines), 2)
		assert.Equal(t, "project,id,name,environment,type,classification,owner,created_at,expiration,last_rotated_at", strings.TrimSpace(lines[0]))
		assert.Contains(t, body, "alpha")
		assert.Contains(t, body, "db-pass")
	})

	t.Run("requires a user context", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/secrets/inventory.csv", nil)
		w := httptest.NewRecorder()
		h.DeploymentSecretsInventoryCSV(w, req)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}
