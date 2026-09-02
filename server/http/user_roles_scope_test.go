package http

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
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

// setupUserRolesScopeCore builds a core with two projects (A=1, B=2), a
// "target" user (3) to have roles granted/removed on them, a "granter" user (2)
// who holds roles.assign scoped ONLY to project A (never globally), and a
// permission-less "grantee" role (3) — so granting/removing it exercises purely
// the roles.assign scope gate under test, not the separate bundled-permission
// ceiling check (requireGranterHoldsRolePermissions, #93/#107/#141).
func setupUserRolesScopeCore(t *testing.T) *core.KeyorixCore {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.Project{}, &models.Environment{}, &models.User{},
		&models.Role{}, &models.Permission{}, &models.RolePermission{},
		&models.UserRole{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.AuditEvent{}, &models.Session{}, &models.SoDPolicy{},
	))

	now := time.Now()
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "project-a"}).Error)
	require.NoError(t, db.Create(&models.Project{ID: 2, Name: "project-b"}).Error)

	require.NoError(t, db.Create(&models.User{ID: 2, Username: "granter", Email: "granter@test.com", IsActive: true, CreatedAt: now, UpdatedAt: now}).Error)
	require.NoError(t, db.Create(&models.User{ID: 3, Username: "target", Email: "target@test.com", IsActive: true, CreatedAt: now, UpdatedAt: now}).Error)

	// "project-manager" bundles only roles.assign; "grantee" bundles nothing.
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "project-manager"}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 2, Name: "grantee"}).Error)
	require.NoError(t, db.Create(&models.Permission{ID: 1, Name: "roles.assign", Resource: "roles", Action: "assign"}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 1, PermissionID: 1}).Error)

	// granter holds roles.assign scoped to project A ONLY — never globally.
	require.NoError(t, db.Create(&models.UserRole{UserID: 2, RoleID: 1, ProjectID: 1}).Error)

	seedSession(t, db, 2, "granter-tok")

	return core.NewKeyorixCore(store.NewLocalStorage(db))
}

// Regression (#342): POST/DELETE /api/v1/user-roles must authorize roles.assign
// at the request body's TARGET scope (project_id/environment_id), exactly like
// RoleGRPCService.AssignRole/RemoveRole already do — not at a flat GLOBAL scope
// that ignores the body entirely. Before the fix, the route's group-level
// RequirePermission("roles.assign") always checked global scope, so a caller
// scoped only to project A could never use this HTTP route at all (even for
// their own project), a functional/authorization parity gap with gRPC that this
// test locks in the corrected direction for: allowed at the caller's own scope,
// refused at a scope they do not hold.
func TestAssignRoleHTTPScopedToTargetProject(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	router, err := NewRouter(&config.Config{}, setupUserRolesScopeCore(t))
	require.NoError(t, err)
	server := httptest.NewServer(router)
	defer server.Close()
	client := &http.Client{Timeout: 5 * time.Second}

	assign := func(t *testing.T, projectID int) int {
		t.Helper()
		body := `{"user_id":3,"role_id":2,"project_id":` + strconv.Itoa(projectID) + `}`
		req, err := http.NewRequest(http.MethodPost, server.URL+"/api/v1/user-roles", strings.NewReader(body))
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer granter-tok")
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		return resp.StatusCode
	}

	// Granter scoped to project A must be REFUSED when the body targets project B.
	assert.Equal(t, http.StatusForbidden, assign(t, 2),
		"a roles.assign holder scoped to project A must not assign a role at project B")
	// Granter scoped to project A must be ALLOWED when the body targets project A.
	assert.Equal(t, http.StatusCreated, assign(t, 1),
		"a roles.assign holder scoped to project A must be allowed to assign a role at project A")
}

// Regression (#342): same scope gate as TestAssignRoleHTTPScopedToTargetProject,
// for the DELETE /api/v1/user-roles route, mirroring RoleGRPCService.RemoveRole.
func TestRemoveRoleHTTPScopedToTargetProject(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	c := setupUserRolesScopeCore(t)
	// Pre-assign the "grantee" role to the target user at BOTH project A and
	// project B (bypassing HTTP, via the core choke point directly with the
	// system pseudo-actor) so the removal attempts below only exercise the
	// roles.assign scope gate, not the assignment step.
	require.NoError(t, c.AssignUserRole(context.Background(), 0, 3, 2, core.Scope{ProjectID: 1}, false))
	require.NoError(t, c.AssignUserRole(context.Background(), 0, 3, 2, core.Scope{ProjectID: 2}, false))

	router, err := NewRouter(&config.Config{}, c)
	require.NoError(t, err)
	server := httptest.NewServer(router)
	defer server.Close()
	client := &http.Client{Timeout: 5 * time.Second}

	remove := func(t *testing.T, projectID int) int {
		t.Helper()
		body := `{"user_id":3,"role_id":2,"project_id":` + strconv.Itoa(projectID) + `}`
		req, err := http.NewRequest(http.MethodDelete, server.URL+"/api/v1/user-roles", strings.NewReader(body))
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer granter-tok")
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		return resp.StatusCode
	}

	// Granter scoped to project A must be REFUSED when the body targets project B.
	assert.Equal(t, http.StatusForbidden, remove(t, 2),
		"a roles.assign holder scoped to project A must not remove a role grant at project B")
	// Granter scoped to project A must be ALLOWED when the body targets project A.
	assert.Equal(t, http.StatusNoContent, remove(t, 1),
		"a roles.assign holder scoped to project A must be allowed to remove a role grant at project A")
}
