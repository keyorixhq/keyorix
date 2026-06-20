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

func TestSecretNameConformanceHandler(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.SecretNode{}, &models.SecretVersion{}, &models.Project{}, &models.Environment{},
	))
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "p1"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 1, Name: "production", ProjectID: 1}).Error)
	// One conforming name, one created out-of-policy (lowercase + hyphen).
	require.NoError(t, db.Create(&models.SecretNode{
		Name: "DB_PASSWORD", ProjectID: 1, EnvironmentID: 1, Type: "password", OwnerID: 1, IsSecret: true,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}).Error)
	require.NoError(t, db.Create(&models.SecretNode{
		Name: "db-pass", ProjectID: 1, EnvironmentID: 1, Type: "password", OwnerID: 1, IsSecret: true,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}).Error)

	cs := core.NewKeyorixCore(store.NewLocalStorage(db))
	require.NoError(t, cs.SetSecretNamePolicy(core.SecretNamePolicy{Enabled: true, Pattern: "^[A-Z][A-Z0-9_]*$"}))
	h, err := NewSecretHandler(cs)
	require.NoError(t, err)

	t.Run("reports the non-conforming name with the policy enabled", func(t *testing.T) {
		req := withChiParam(withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/projects/1/secrets/name-conformance", nil)), "id", "1")
		w := httptest.NewRecorder()
		h.SecretNameConformance(w, req)

		require.Equal(t, http.StatusOK, w.Code)
		body := w.Body.String()
		assert.Contains(t, body, `"policy_enabled":true`)
		assert.Contains(t, body, `"total_secrets":2`)
		assert.Contains(t, body, "db-pass")
		assert.Contains(t, body, "pattern")
	})

	t.Run("requires a user context", func(t *testing.T) {
		req := withChiParam(httptest.NewRequest(http.MethodGet, "/api/v1/projects/1/secrets/name-conformance", nil), "id", "1")
		w := httptest.NewRecorder()
		h.SecretNameConformance(w, req)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}
