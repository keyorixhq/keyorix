package handlers

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/core/storage/storagetest"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// STORE-DEAD-PRIMITIVES-1 item 1: PUT /api/v1/roles/{id} loses a race against a
// concurrent DELETE of the same custom role. #3880 made the storage write answer
// storage.ErrRoleNotFound for that case; the handler did not map it and answered
// 500. The role is deleted right after the handler's own read, so the update
// finds no row.
func TestUpdateRole_RoleDeletedConcurrentlyAnswers404(t *testing.T) {
	require.NoError(t, i18n.Initialize(&config.Config{
		Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
	}))
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.Role{}, &models.Permission{}, &models.RolePermission{}, &models.SystemMetadata{}, &models.AuditEvent{},
		&models.UserRole{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.Project{}, &models.Environment{},
		&models.MachineIdentity{}, &models.MachineIdentityRole{}, &models.ConnectRefGrant{},
	))
	admin := &models.Role{Name: "system_admin", Description: "Administrator", BypassesPermissionChecks: true}
	require.NoError(t, db.Create(admin).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: admin.ID}).Error)
	victim := &models.Role{Name: "doomed-role", Description: "about to be deleted"}
	require.NoError(t, db.Create(victim).Error)

	racing := core.NewKeyorixCore(storagetest.Hooked(store.NewLocalStorage(db), &storagetest.StoreHooks{
		GetRole: func(next corestorage.Storage, ctx context.Context, id uint) (*models.Role, error) {
			role, err := next.GetRole(ctx, id)
			if err == nil && id == victim.ID {
				// The concurrent admin's DELETE commits after our read.
				require.NoError(t, db.Unscoped().Delete(&models.Role{}, victim.ID).Error)
			}
			return role, err
		},
	}))
	handler := NewRBACHandler(racing)

	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/v1/roles/%d", victim.ID),
		bytes.NewBufferString(`{"description":"too late"}`)), "id", fmt.Sprintf("%d", victim.ID)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.UpdateRole(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), errRoleNotFound)
}
