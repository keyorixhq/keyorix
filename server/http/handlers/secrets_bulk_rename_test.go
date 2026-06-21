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

func TestBulkRenameSecretsHandler(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.SecretNode{}, &models.SecretVersion{}, &models.Project{}, &models.Environment{},
		&models.AuditEvent{}, &models.SecretAccessLog{}, &models.User{},
	))
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "p1"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 1, Name: "production", ProjectID: 1}).Error)
	require.NoError(t, db.Create(&models.SecretNode{
		ID: 5, Name: "db-password", ProjectID: 1, EnvironmentID: 1, Type: "password", OwnerID: 1,
		IsSecret: true, CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}).Error)

	c := core.NewKeyorixCore(store.NewLocalStorage(db))
	require.NoError(t, c.SetSecretNamePolicy(core.SecretNamePolicy{
		Enabled: true, Pattern: "^[A-Z][A-Z0-9_]*$", MaxLength: 30,
	}))
	h, err := NewSecretHandler(c)
	require.NoError(t, err)

	t.Run("dry run reports without changing anything", func(t *testing.T) {
		body := strings.NewReader(`{"renames":[{"id":5,"new_name":"DB_PASSWORD"}],"dry_run":true}`)
		req := withChiParam(withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/projects/1/secrets/bulk-rename", body)), "id", "1")
		w := httptest.NewRecorder()
		h.BulkRenameSecrets(w, req)

		require.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), `"dry_run":true`)
		assert.Contains(t, w.Body.String(), `"status":"would_rename"`)

		var s models.SecretNode
		require.NoError(t, db.First(&s, 5).Error)
		assert.Equal(t, "db-password", s.Name, "dry run must not persist")
	})

	t.Run("apply renames the secret", func(t *testing.T) {
		body := strings.NewReader(`{"renames":[{"id":5,"new_name":"DB_PASSWORD"}],"dry_run":false}`)
		req := withChiParam(withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/projects/1/secrets/bulk-rename", body)), "id", "1")
		w := httptest.NewRecorder()
		h.BulkRenameSecrets(w, req)

		require.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), `"renamed":1`)
		assert.Contains(t, w.Body.String(), `"status":"renamed"`)

		var s models.SecretNode
		require.NoError(t, db.First(&s, 5).Error)
		assert.Equal(t, "DB_PASSWORD", s.Name)
	})

	t.Run("requires a user context", func(t *testing.T) {
		req := withChiParam(httptest.NewRequest(http.MethodPost, "/api/v1/projects/1/secrets/bulk-rename", nil), "id", "1")
		w := httptest.NewRecorder()
		h.BulkRenameSecrets(w, req)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("invalid body is a 400", func(t *testing.T) {
		body := strings.NewReader(`not json`)
		req := withChiParam(withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/projects/1/secrets/bulk-rename", body)), "id", "1")
		w := httptest.NewRecorder()
		h.BulkRenameSecrets(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("empty renames is a 400", func(t *testing.T) {
		body := strings.NewReader(`{"renames":[]}`)
		req := withChiParam(withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/projects/1/secrets/bulk-rename", body)), "id", "1")
		w := httptest.NewRecorder()
		h.BulkRenameSecrets(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}
