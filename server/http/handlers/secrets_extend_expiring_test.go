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

func TestExtendExpiringSecretsHandler(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.SecretNode{}, &models.SecretVersion{}, &models.Project{}, &models.Environment{},
		&models.AuditEvent{}, &models.SecretAccessLog{}, &models.User{}, &models.Role{}, &models.UserRole{},
	))
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "p1"}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 1, ProjectID: 1}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 1, Name: "production", ProjectID: 1}).Error)
	expired := time.Now().Add(-48 * time.Hour)
	require.NoError(t, db.Create(&models.SecretNode{
		Name: "expired", ProjectID: 1, EnvironmentID: 1, Type: "password", OwnerID: 1, IsSecret: true,
		Expiration: &expired, CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}).Error)

	h, err := NewSecretHandler(core.NewKeyorixCore(store.NewLocalStorage(db)))
	require.NoError(t, err)

	t.Run("renews expiring secrets and returns the count", func(t *testing.T) {
		body := strings.NewReader(`{"within_days":30,"new_window_days":90}`)
		req := withChiParam(withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/projects/1/secrets/extend-expiring", body)), "id", "1")
		w := httptest.NewRecorder()
		h.ExtendExpiringSecrets(w, req)

		require.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), `"extended":1`)
	})

	t.Run("requires a user context", func(t *testing.T) {
		req := withChiParam(httptest.NewRequest(http.MethodPost, "/api/v1/projects/1/secrets/extend-expiring", nil), "id", "1")
		w := httptest.NewRecorder()
		h.ExtendExpiringSecrets(w, req)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}
