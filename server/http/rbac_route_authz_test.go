package http

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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
		&models.AuditEvent{}, &models.Session{}, &models.Project{}, &models.Environment{},
	))
	now := time.Now()
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "admin", Email: "a@t.com", IsActive: true, CreatedAt: now, UpdatedAt: now}).Error)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "manager", Email: "m@t.com", IsActive: true, CreatedAt: now, UpdatedAt: now}).Error)
	// admin role = privilege-bypass; "usermgr" holds only users.read (NOT roles.assign).
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "admin", BypassesPermissionChecks: true}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 2, Name: "usermgr"}).Error)
	require.NoError(t, db.Create(&models.Permission{ID: 1, Name: "users.read", Resource: "users", Action: "read"}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 2, PermissionID: 1}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 1}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 2, RoleID: 2}).Error)
	seedSession(t, db, 1, "admin-tok")
	seedSession(t, db, 2, "mgr-tok")

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

// Regression (#141): GET /api/v1/users/{id}/roles must require roles.read, not
// the group-wide users.read that nearly every seeded role holds — otherwise any
// low-privilege project member can enumerate an arbitrary OTHER user's full role
// assignment list (reconnaissance for targeted privilege-escalation attempts).
// This also matches the gRPC RoleService.GetUserRoles gate for the same data.
func TestGetUserRolesRequiresRolesRead(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Role{}, &models.Permission{}, &models.RolePermission{},
		&models.UserRole{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.AuditEvent{}, &models.Session{}, &models.Project{}, &models.Environment{},
	))
	now := time.Now()
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "auditor", Email: "a@t.com", IsActive: true, CreatedAt: now, UpdatedAt: now}).Error)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "viewer", Email: "v@t.com", IsActive: true, CreatedAt: now, UpdatedAt: now}).Error)
	require.NoError(t, db.Create(&models.User{ID: 3, Username: "target", Email: "t@t.com", IsActive: true, CreatedAt: now, UpdatedAt: now}).Error)
	// "auditor" holds roles.read; "viewer" holds only users.read.
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "auditor"}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 2, Name: "viewer"}).Error)
	require.NoError(t, db.Create(&models.Permission{ID: 1, Name: "users.read", Resource: "users", Action: "read"}).Error)
	require.NoError(t, db.Create(&models.Permission{ID: 2, Name: "roles.read", Resource: "roles", Action: "read"}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 1, PermissionID: 1}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 1, PermissionID: 2}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 2, PermissionID: 1}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 1}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 2, RoleID: 2}).Error)
	seedSession(t, db, 1, "auditor-tok")
	seedSession(t, db, 2, "viewer-tok")

	router, err := NewRouter(&config.Config{}, core.NewKeyorixCore(store.NewLocalStorage(db)))
	require.NoError(t, err)
	server := httptest.NewServer(router)
	defer server.Close()
	client := &http.Client{Timeout: 5 * time.Second}

	get := func(token string) int {
		req, err := http.NewRequest("GET", server.URL+"/api/v1/users/3/roles", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		return resp.StatusCode
	}

	assert.Equal(t, http.StatusForbidden, get("viewer-tok"),
		"users.read holder without roles.read must NOT enumerate another user's roles")
	assert.NotEqual(t, http.StatusForbidden, get("auditor-tok"),
		"a roles.read holder should be allowed past the gate")
}

// Regression (#262): GET /api/v1/groups/{id}/roles must require roles.read, not
// the group-wide users.read that the baseline viewer role (and nearly every
// other seeded role) holds — otherwise any low-privilege, globally-assigned
// viewer could enumerate an arbitrary group's full role-grant list across the
// entire deployment, discovering exactly which roles (and therefore which
// permissions) cascade to every member of that group. This mirrors the
// GetUserRolesForUser fix (#141) for the same class of disclosure at group
// granularity, and matches the roles.assign gate already required by this
// route's mutating siblings (AssignRoleToGroup/RemoveRoleFromGroup).
func TestGetGroupRolesRequiresRolesRead(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Role{}, &models.Permission{}, &models.RolePermission{},
		&models.UserRole{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.AuditEvent{}, &models.Session{}, &models.Project{}, &models.Environment{},
	))
	now := time.Now()
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "auditor", Email: "a@t.com", IsActive: true, CreatedAt: now, UpdatedAt: now}).Error)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "viewer", Email: "v@t.com", IsActive: true, CreatedAt: now, UpdatedAt: now}).Error)
	// "auditor" holds roles.read; "viewer" holds only the baseline users.read.
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "auditor"}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 2, Name: "viewer"}).Error)
	require.NoError(t, db.Create(&models.Permission{ID: 1, Name: "users.read", Resource: "users", Action: "read"}).Error)
	require.NoError(t, db.Create(&models.Permission{ID: 2, Name: "roles.read", Resource: "roles", Action: "read"}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 1, PermissionID: 1}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 1, PermissionID: 2}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 2, PermissionID: 1}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 1}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 2, RoleID: 2}).Error)
	// The group whose role grants are being probed — membership is irrelevant to
	// this gate; neither caller belongs to it.
	require.NoError(t, db.Create(&models.Group{ID: 1, Name: "finance-admins"}).Error)
	require.NoError(t, db.Create(&models.GroupRole{GroupID: 1, RoleID: 1}).Error)
	seedSession(t, db, 1, "auditor-tok")
	seedSession(t, db, 2, "viewer-tok")

	router, err := NewRouter(&config.Config{}, core.NewKeyorixCore(store.NewLocalStorage(db)))
	require.NoError(t, err)
	server := httptest.NewServer(router)
	defer server.Close()
	client := &http.Client{Timeout: 5 * time.Second}

	get := func(token string) int {
		req, err := http.NewRequest("GET", server.URL+"/api/v1/groups/1/roles", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		return resp.StatusCode
	}

	assert.Equal(t, http.StatusForbidden, get("viewer-tok"),
		"users.read holder without roles.read must NOT enumerate a group's role grants")
	assert.NotEqual(t, http.StatusForbidden, get("auditor-tok"),
		"a roles.read holder should be allowed past the gate")
}

// ANOMALY-04: GET /api/v1/audit/anomalies must require system.read — NOT merely
// audit.read. The base viewer role holds audit.read, but anomaly alerts expose
// SecretName, AccessedBy, IPAddress, Severity — fields an attacker with a viewer
// credential can use to check whether their own access patterns triggered an alert.
// Raising the gate to system.read restricts the endpoint to operators/admins only.
func TestListAnomalyAlertsRequiresSystemRead(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Role{}, &models.Permission{}, &models.RolePermission{},
		&models.UserRole{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.AuditEvent{}, &models.Session{}, &models.Project{}, &models.Environment{},
		&models.AnomalyAlert{},
	))
	now := time.Now()
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "operator", Email: "op@t.com", IsActive: true, CreatedAt: now, UpdatedAt: now}).Error)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "viewer", Email: "v@t.com", IsActive: true, CreatedAt: now, UpdatedAt: now}).Error)
	// "operator" holds system.read (and audit.read); "viewer" holds only audit.read.
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "operator"}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 2, Name: "viewer"}).Error)
	require.NoError(t, db.Create(&models.Permission{ID: 1, Name: "audit.read", Resource: "audit", Action: "read"}).Error)
	require.NoError(t, db.Create(&models.Permission{ID: 2, Name: "system.read", Resource: "system", Action: "read"}).Error)
	// operator gets both; viewer gets only audit.read
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 1, PermissionID: 1}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 1, PermissionID: 2}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 2, PermissionID: 1}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 1}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 2, RoleID: 2}).Error)
	seedSession(t, db, 1, "operator-tok")
	seedSession(t, db, 2, "viewer-tok")

	router, err := NewRouter(&config.Config{}, core.NewKeyorixCore(store.NewLocalStorage(db)))
	require.NoError(t, err)
	server := httptest.NewServer(router)
	defer server.Close()
	client := &http.Client{Timeout: 5 * time.Second}

	get := func(token string) int {
		req, err := http.NewRequest("GET", server.URL+"/api/v1/audit/anomalies", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		return resp.StatusCode
	}

	// A viewer (audit.read only) must be rejected — they could use the response to
	// check whether their own access patterns were flagged.
	assert.Equal(t, http.StatusForbidden, get("viewer-tok"),
		"audit.read holder without system.read must be forbidden from listing anomaly alerts (ANOMALY-04)")
	// An operator (system.read + audit.read) must be allowed past the gate.
	assert.NotEqual(t, http.StatusForbidden, get("operator-tok"),
		"system.read holder should be allowed to list anomaly alerts")
}
