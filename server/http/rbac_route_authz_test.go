package http

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// Regression (security review, CRITICAL): PUT /api/v1/users/{id}/roles is a
// privilege grant and must require roles.assign — not the group-wide users.read
// that many non-admin roles hold. Previously a users.read holder could grant
// themselves admin via this route.
func TestUpdateUserRolesRequiresRolesAssign(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Role{}, &models.Permission{}, &models.RolePermission{},
		&models.UserRole{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.AuditEvent{}, &models.Session{},
	))
	now := time.Now()
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "admin", Email: "a@t.com", IsActive: true, CreatedAt: now, UpdatedAt: now}).Error)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "manager", Email: "m@t.com", IsActive: true, CreatedAt: now, UpdatedAt: now}).Error)
	// admin role = privilege-bypass; "usermgr" holds only users.read (NOT roles.assign).
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "admin"}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 2, Name: "usermgr"}).Error)
	require.NoError(t, db.Create(&models.Permission{ID: 1, Name: "users.read", Resource: "users", Action: "read"}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 2, PermissionID: 1}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 1}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 2, RoleID: 2}).Error)
	require.NoError(t, db.Create(&models.Session{UserID: 1, SessionToken: "admin-tok"}).Error)
	require.NoError(t, db.Create(&models.Session{UserID: 2, SessionToken: "mgr-tok"}).Error)

	router, err := NewRouter(&config.Config{}, core.NewKeyorixCore(store.NewLocalStorage(db)))
	require.NoError(t, err)
	server := httptest.NewServer(router)
	defer server.Close()
	client := &http.Client{Timeout: 5 * time.Second}

	put := func(token string) int {
		req, err := http.NewRequest("PUT", server.URL+"/api/v1/users/2/roles", strings.NewReader(`{"role_ids":[1]}`))
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		return resp.StatusCode
	}

	// The fix: users.read alone (no roles.assign) is rejected.
	assert.Equal(t, http.StatusForbidden, put("mgr-tok"),
		"users.read holder without roles.assign must NOT replace roles")
	// An admin (privilege-bypass) passes the gate.
	assert.NotEqual(t, http.StatusForbidden, put("admin-tok"),
		"admin should be allowed past the roles.assign gate")
}
