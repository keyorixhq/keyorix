package handlers

import (
	"bytes"
	"context"
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
	customMiddleware "github.com/keyorixhq/keyorix/server/middleware"
)

// #169: the exact escalation the finding describes — an actor holding ONLY
// "roles.write" (a narrower permission that, by name, sounds like "can edit what a
// role contains," not "can hand out admin") must not be able to bundle an
// admin-tier permission like "system.write" into a role's DEFINITION, since that
// role could then be granted to them (or already IS) through an ordinary
// non-admin grant path — bypassing every admin-rank-ceiling check on the GRANT step.
func TestCreateRole_RolesWriteHolderCannotBundleSystemWrite(t *testing.T) {
	require.NoError(t, i18n.Initialize(&config.Config{
		Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
	}))
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.Role{}, &models.Permission{}, &models.RolePermission{}, &models.UserRole{},
		&models.Group{}, &models.UserGroup{}, &models.GroupRole{}, &models.AuditEvent{},
		&models.Project{}, &models.Environment{},
	))

	rolesWritePerm := &models.Permission{Name: "roles.write", Resource: "roles", Action: "write"}
	systemWritePerm := &models.Permission{Name: "system.write", Resource: "system", Action: "write"}
	require.NoError(t, db.Create(rolesWritePerm).Error)
	require.NoError(t, db.Create(systemWritePerm).Error)

	// The attacker's role: ONLY roles.write, nothing else — no system.write, no admin.
	attackerRole := &models.Role{Name: "role-editor"}
	require.NoError(t, db.Create(attackerRole).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: attackerRole.ID, PermissionID: rolesWritePerm.ID}).Error)

	const attackerID = uint(42)
	require.NoError(t, db.Create(&models.UserRole{UserID: attackerID, RoleID: attackerRole.ID}).Error)

	coreService := core.NewKeyorixCore(store.NewLocalStorage(db))
	handler := NewRBACHandler(coreService)

	attackerCtx := &customMiddleware.UserContext{UserID: attackerID, Username: "attacker", Email: "a@x.io"}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/roles",
		bytes.NewBufferString(`{"name":"self-promote","description":"escalation attempt","permissions":["system.write"]}`))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), customMiddleware.GetUserContextKey(), attackerCtx))
	w := httptest.NewRecorder()

	handler.CreateRole(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code, "a roles.write-only actor must not be able to bundle system.write into a role")

	var roleCount int64
	require.NoError(t, db.Model(&models.Role{}).Where("name = ?", "self-promote").Count(&roleCount).Error)
	assert.Zero(t, roleCount, "no role must be created when a bundled permission is refused")

	// Sanity: the SAME actor CAN create a role bundling a permission they DO hold.
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/roles",
		bytes.NewBufferString(`{"name":"role-editor-clone","description":"legit","permissions":["roles.write"]}`))
	req2.Header.Set("Content-Type", "application/json")
	req2 = req2.WithContext(context.WithValue(req2.Context(), customMiddleware.GetUserContextKey(), attackerCtx))
	w2 := httptest.NewRecorder()
	handler.CreateRole(w2, req2)
	assert.Equal(t, http.StatusCreated, w2.Code, "bundling a permission the actor genuinely holds must still succeed")
}

// The UpdateRole path closes the same gap for an ALREADY-EXISTING role: an actor
// must not be able to retroactively add an admin-tier permission to a role's
// definition (which would grant it to every current holder, including themselves)
// without holding that permission.
func TestUpdateRole_RolesWriteHolderCannotAddSystemWrite(t *testing.T) {
	require.NoError(t, i18n.Initialize(&config.Config{
		Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
	}))
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.Role{}, &models.Permission{}, &models.RolePermission{}, &models.UserRole{},
		&models.Group{}, &models.UserGroup{}, &models.GroupRole{}, &models.AuditEvent{},
		&models.Project{}, &models.Environment{},
	))

	rolesWritePerm := &models.Permission{Name: "roles.write", Resource: "roles", Action: "write"}
	systemWritePerm := &models.Permission{Name: "system.write", Resource: "system", Action: "write"}
	require.NoError(t, db.Create(rolesWritePerm).Error)
	require.NoError(t, db.Create(systemWritePerm).Error)

	attackerRole := &models.Role{Name: "role-editor"}
	require.NoError(t, db.Create(attackerRole).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: attackerRole.ID, PermissionID: rolesWritePerm.ID}).Error)

	// The role the attacker will try to retroactively upgrade — one they already hold.
	targetRole := &models.Role{Name: "target"}
	require.NoError(t, db.Create(targetRole).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: targetRole.ID, PermissionID: rolesWritePerm.ID}).Error)

	const attackerID = uint(42)
	require.NoError(t, db.Create(&models.UserRole{UserID: attackerID, RoleID: attackerRole.ID}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: attackerID, RoleID: targetRole.ID}).Error)

	coreService := core.NewKeyorixCore(store.NewLocalStorage(db))
	handler := NewRBACHandler(coreService)

	attackerCtx := &customMiddleware.UserContext{UserID: attackerID, Username: "attacker", Email: "a@x.io"}
	req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/v1/roles/%d", targetRole.ID),
		bytes.NewBufferString(`{"permissions":["roles.write","system.write"]}`))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), customMiddleware.GetUserContextKey(), attackerCtx))
	req = withChiParam(req, "id", fmt.Sprintf("%d", targetRole.ID))
	w := httptest.NewRecorder()

	handler.UpdateRole(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code, "adding system.write to an existing role must be refused")

	var perms []models.Permission
	require.NoError(t, db.Model(&models.Permission{}).
		Joins("JOIN role_permissions ON role_permissions.permission_id = permissions.id").
		Where("role_permissions.role_id = ?", targetRole.ID).Find(&perms).Error)
	require.Len(t, perms, 1, "the role's permission set must be unchanged — still just roles.write")
	assert.Equal(t, "roles.write", perms[0].Name)
}

// #294: a SECOND, independent admin-bypass gap that SURVIVES #169's fix on its own.
// "super_admin" (and "auditor") are pinned as builtin/reserved names (IsBuiltinRole)
// but are never bootstrap-seeded — unlike "admin"/"system_admin"/"project_admin",
// which already exist as DB rows and so collide with the unique(name) constraint on
// any create attempt. Nothing previously stopped a roles.write holder from creating a
// brand-new, EMPTY-PERMISSION role literally named "super_admin": #169's "must already
// hold every bundled permission" check is trivially satisfied by an empty permission
// list, yet roleSetContainsAdmin (authz.go) grants a full admin bypass purely by NAME
// match against the role ID — no permission content is ever consulted. Once created
// and self-assigned (a separate roles.assign step, out of scope for this specific
// test), that role functions as a complete admin-bypass switch.
func TestCreateRole_CannotClaimReservedAdminBypassName(t *testing.T) {
	require.NoError(t, i18n.Initialize(&config.Config{
		Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
	}))
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.Role{}, &models.Permission{}, &models.RolePermission{}, &models.UserRole{},
		&models.Group{}, &models.UserGroup{}, &models.GroupRole{}, &models.AuditEvent{},
		&models.Project{}, &models.Environment{},
	))

	rolesWritePerm := &models.Permission{Name: "roles.write", Resource: "roles", Action: "write"}
	require.NoError(t, db.Create(rolesWritePerm).Error)

	attackerRole := &models.Role{Name: "role-editor"}
	require.NoError(t, db.Create(attackerRole).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: attackerRole.ID, PermissionID: rolesWritePerm.ID}).Error)

	const attackerID = uint(43)
	require.NoError(t, db.Create(&models.UserRole{UserID: attackerID, RoleID: attackerRole.ID}).Error)

	coreService := core.NewKeyorixCore(store.NewLocalStorage(db))
	handler := NewRBACHandler(coreService)
	attackerCtx := &customMiddleware.UserContext{UserID: attackerID, Username: "attacker", Email: "a@x.io"}

	for _, reserved := range []string{"super_admin", "auditor", "admin", "system_admin", "project_admin"} {
		body := fmt.Sprintf(`{"name":%q,"description":"reserved-name attempt","permissions":["roles.write"]}`, reserved)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/roles", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		req = req.WithContext(context.WithValue(req.Context(), customMiddleware.GetUserContextKey(), attackerCtx))
		w := httptest.NewRecorder()

		handler.CreateRole(w, req)

		assert.Equal(t, http.StatusConflict, w.Code, "creating a role named %q must be refused", reserved)

		var roleCount int64
		require.NoError(t, db.Model(&models.Role{}).Where("name = ?", reserved).Count(&roleCount).Error)
		assert.Zero(t, roleCount, "no role named %q must exist after the refused attempt", reserved)
	}

	// Sanity: a non-reserved name still works for the same actor.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/roles",
		bytes.NewBufferString(`{"name":"not-reserved","description":"legit","permissions":["roles.write"]}`))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), customMiddleware.GetUserContextKey(), attackerCtx))
	w := httptest.NewRecorder()
	handler.CreateRole(w, req)
	assert.Equal(t, http.StatusCreated, w.Code, "a non-reserved role name must still be creatable")
}
