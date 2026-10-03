package http

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// setupMachineRoleGrantScopeCore builds a core with one project (A=1) holding
// two environments (dev=10, prod=11), a global-admin user (1, bypass) who
// grants, and an active machine identity (10) with no roles yet.
func setupMachineRoleGrantScopeCore(t *testing.T) *core.KeyorixCore {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.Project{}, &models.Environment{}, &models.User{},
		&models.Role{}, &models.Permission{}, &models.RolePermission{},
		&models.UserRole{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.MachineIdentity{}, &models.MachineIdentityRole{},
		&models.Session{}, &models.AuditEvent{}, &models.SoDPolicy{},
	))

	now := time.Now()
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "project-a"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 10, ProjectID: 1, Name: "dev"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 11, ProjectID: 1, Name: "prod"}).Error)
	require.NoError(t, db.Create(&models.Project{ID: 2, Name: "project-b"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 20, ProjectID: 2, Name: "b-prod"}).Error)

	require.NoError(t, db.Create(&models.User{ID: 1, Username: "admin", Email: "admin@test.com", IsActive: true, CreatedAt: now, UpdatedAt: now}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "admin", BypassesPermissionChecks: true}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 1}).Error)

	require.NoError(t, db.Create(&models.Role{ID: 2, Name: "reader"}).Error)
	require.NoError(t, db.Create(&models.Permission{ID: 1, Name: "secrets.read", Resource: "secrets", Action: "read"}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 2, PermissionID: 1}).Error)

	require.NoError(t, db.Create(&models.MachineIdentity{ID: 10, ProjectID: 1, Name: "vault-approle-ci", IdentityType: "service", State: "active"}).Error)

	seedSession(t, db, 1, "admin-tok")

	return core.NewKeyorixCore(store.NewLocalStorage(db))
}

// Regression (#2542, ADR-114): POST /api/v1/projects/{id}/machine-identities/{machineId}/roles
// previously granted ALWAYS at project scope (environment_id hardcoded to 0/global in the
// handler, regardless of the request body) -- keyorix-migrate's access-model migration needs to
// grant a role scoped to exactly ONE environment, matching what the source Vault policy actually
// granted. Before the fix, this test's "prod must NOT be authorized" assertion failed: a grant
// meant for "dev" only was silently ALSO effective in "prod", a real, live widening of access
// beyond what was requested -- exactly the class of bug ADR-114's "narrower never wider" rule
// exists to prevent. Verified red without the fix (reverted the handler's scope line locally,
// confirmed this test fails at the "prod must not be authorized" assertion), green with it.
func TestGrantMachineRole_ScopedToOneEnvironment(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	coreService := setupMachineRoleGrantScopeCore(t)
	router, err := NewRouter(&config.Config{}, coreService)
	require.NoError(t, err)
	server := httptest.NewServer(router)
	defer server.Close()
	client := &http.Client{Timeout: 5 * time.Second}

	body, err := json.Marshal(map[string]any{"role_id": 2, "environment_id": 10})
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, server.URL+"/api/v1/projects/1/machine-identities/10/roles", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer admin-tok")
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode, "grant request must succeed")

	devAllowed, err := coreService.AuthorizePrincipal(t.Context(), core.ActorTypeMachine, 10, "secrets.read", core.Scope{ProjectID: 1, EnvironmentID: 10})
	require.NoError(t, err)
	require.True(t, devAllowed, "the machine identity must be authorized in the environment it was actually granted (dev)")

	prodAllowed, err := coreService.AuthorizePrincipal(t.Context(), core.ActorTypeMachine, 10, "secrets.read", core.Scope{ProjectID: 1, EnvironmentID: 11})
	require.NoError(t, err)
	require.False(t, prodAllowed, fmt.Sprintf("a grant scoped to environment 10 (dev) must NOT also authorize environment 11 (prod) -- got allowed=%v", prodAllowed))
}

// #2595 review: environment_id is caller-supplied, so a grant naming an environment
// of a DIFFERENT project must be rejected and must store nothing.
func TestGrantMachineRole_CrossProjectEnvironmentRejected(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	coreService := setupMachineRoleGrantScopeCore(t)
	router, err := NewRouter(&config.Config{}, coreService)
	require.NoError(t, err)
	server := httptest.NewServer(router)
	defer server.Close()
	client := &http.Client{Timeout: 5 * time.Second}

	body, err := json.Marshal(map[string]any{"role_id": 2, "environment_id": 20})
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, server.URL+"/api/v1/projects/1/machine-identities/10/roles", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer admin-tok")
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.GreaterOrEqual(t, resp.StatusCode, 400, "a cross-project environment_id must be rejected")
	require.Less(t, resp.StatusCode, 500, "rejection must be a client error, not a server error")

	for _, sc := range []core.Scope{{ProjectID: 1, EnvironmentID: 20}, {ProjectID: 2, EnvironmentID: 20}, {ProjectID: 1}} {
		allowed, err := coreService.AuthorizePrincipal(t.Context(), core.ActorTypeMachine, 10, "secrets.read", sc)
		require.NoError(t, err)
		require.False(t, allowed, fmt.Sprintf("no grant may have been stored; got allowed at %+v", sc))
	}
}
