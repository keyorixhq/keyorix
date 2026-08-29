package handlers

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// Role-DEFINITION changes (create/update/delete) must be audited, like role
// assignments — previously they wrote nothing, leaving a governance blind spot.
func TestRBACRoleDefinitionAudit(t *testing.T) {
	require.NoError(t, i18n.Initialize(&config.Config{
		Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
	}))
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.Role{}, &models.Permission{}, &models.RolePermission{}, &models.AuditEvent{},
		&models.UserRole{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.Project{}, &models.Environment{},
	))
	handler := NewRBACHandler(core.NewKeyorixCore(store.NewLocalStorage(db)))
	// CreateRole requires at least one (resolvable) permission name.
	require.NoError(t, db.Create(&models.Permission{Name: "secrets.read", Resource: "secrets", Action: "read"}).Error)
	// #169: CreateRole/UpdateRole now require the actor already hold every permission
	// being bundled — make withUserCtx's actor (UserID 1) a global admin so the bypass
	// applies. Named distinctly from the literal "admin" role a later subtest creates
	// (Role.Name is unique).
	adminRole := &models.Role{Name: "system_admin", Description: "Administrator"}
	require.NoError(t, db.Create(adminRole).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: adminRole.ID}).Error)

	countEvents := func(eventType string) int64 {
		var n int64
		require.NoError(t, db.Model(&models.AuditEvent{}).Where("event_type = ?", eventType).Count(&n).Error)
		return n
	}

	t.Run("create role writes role.created", func(t *testing.T) {
		req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/roles",
			bytes.NewBufferString(`{"name":"auditor-x","description":"reads things","permissions":["secrets.read"]}`)))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handler.CreateRole(w, req)

		require.Equal(t, http.StatusCreated, w.Code)
		assert.Equal(t, int64(1), countEvents(core.EventRoleCreated))
	})

	var roleID uint
	require.NoError(t, db.Model(&models.Role{}).Where("name = ?", "auditor-x").Select("id").Scan(&roleID).Error)

	t.Run("update role writes role.updated", func(t *testing.T) {
		req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/v1/roles/%d", roleID),
			bytes.NewBufferString(`{"description":"reads more things"}`)), "id", fmt.Sprintf("%d", roleID)))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handler.UpdateRole(w, req)

		require.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, int64(1), countEvents(core.EventRoleUpdated))
	})

	t.Run("delete role writes role.deleted", func(t *testing.T) {
		req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/api/v1/roles/%d", roleID),
			nil), "id", fmt.Sprintf("%d", roleID)))
		w := httptest.NewRecorder()
		handler.DeleteRole(w, req)

		require.Equal(t, http.StatusNoContent, w.Code)
		assert.Equal(t, int64(1), countEvents(core.EventRoleDeleted))
	})

	t.Run("a refused built-in delete writes a Success=false event", func(t *testing.T) {
		// #1503: this used to assert the refusal audited NOTHING -- that was
		// the bug the fix closes, not the intended behavior. A denied attempt
		// to delete a built-in role is exactly the kind of event least-
		// privilege evidence should capture; it now writes a second
		// role.deleted row (Success=false) alongside the one earlier
		// successful delete (Success=true), distinguished by the Success flag
		// per this file's countEvents helper not filtering on it.
		require.NoError(t, db.Create(&models.Role{Name: "admin", Description: "built-in"}).Error)
		var adminID uint
		require.NoError(t, db.Model(&models.Role{}).Where("name = ?", "admin").Select("id").Scan(&adminID).Error)

		req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/api/v1/roles/%d", adminID),
			nil), "id", fmt.Sprintf("%d", adminID)))
		w := httptest.NewRecorder()
		handler.DeleteRole(w, req)

		require.Equal(t, http.StatusForbidden, w.Code)
		assert.Equal(t, int64(2), countEvents(core.EventRoleDeleted), "the earlier successful delete plus this refused one")

		var denied models.AuditEvent
		require.NoError(t, db.Where("event_type = ? AND success = ?", core.EventRoleDeleted, false).First(&denied).Error)
		assert.Contains(t, denied.Description, "admin", "the audit description must name the refused target role")
	})
}
