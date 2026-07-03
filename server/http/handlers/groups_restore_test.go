package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
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

func TestRestoreGroupHandler(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.Group{}, &models.UserGroup{}, &models.GroupRole{}, &models.AuditEvent{}, &models.Role{}))
	c := core.NewKeyorixCore(store.NewLocalStorage(db))
	h, err := NewGroupHandler(c)
	require.NoError(t, err)

	g, err := c.CreateGroup(context.Background(), 1, &core.CreateGroupRequest{Name: "ops"})
	require.NoError(t, err)
	require.NoError(t, c.DeleteGroup(context.Background(), 1, g.ID))

	t.Run("restores a soft-deleted group", func(t *testing.T) {
		req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/api/v1/groups/1/restore", nil), "id", "1"))
		w := httptest.NewRecorder()
		h.RestoreGroup(w, req)

		require.Equal(t, http.StatusOK, w.Code)
		_, err := c.GetGroup(context.Background(), g.ID)
		assert.NoError(t, err, "group is retrievable after restore")
	})

	t.Run("restoring a live (not-deleted) group is a 404", func(t *testing.T) {
		req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPost, "/api/v1/groups/1/restore", nil), "id", "1"))
		w := httptest.NewRecorder()
		h.RestoreGroup(w, req)
		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("requires a user context", func(t *testing.T) {
		req := withChiParam(httptest.NewRequest(http.MethodPost, "/api/v1/groups/1/restore", nil), "id", "1")
		w := httptest.NewRecorder()
		h.RestoreGroup(w, req)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}
