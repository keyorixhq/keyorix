package core

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// newBootstrappedCore spins up an in-memory store, runs the production
// BootstrapSystem, and returns the core + storage for RBAC assertions.
func newBootstrappedCore(t *testing.T) (*KeyorixCore, *store.LocalStorage) {
	t.Helper()
	require.NoError(t, i18n.Initialize(&config.Config{
		Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
	}))

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Role{}, &models.Permission{}, &models.RolePermission{},
		&models.UserRole{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.Project{}, &models.Environment{}, &models.SystemMetadata{},
		&models.MachineIdentity{}, &models.MachineIdentityRole{},
		&models.PersonalAccessToken{}, &models.Session{}, &models.ShareRecord{},
		&models.AuditEvent{},
		&models.AccessRequest{}, &models.AccessRequestApproval{}, &models.ProjectMembership{},
		&models.SecretNode{}, &models.SecretVersion{}, &models.DynamicSecretConfig{}, &models.SoDPolicy{},
		&models.StatsSnapshot{}, &models.DeploymentStatsSnapshot{},
		&models.MFAStepupToken{}, &models.MFAStepUpGrant{},
		&models.SecretACL{}, &models.PasswordHistory{},
		&models.SecretAccessSchedule{},
	))

	st := store.NewLocalStorage(db)
	c := NewKeyorixCore(st)
	c.SetBootstrapToken("test-bootstrap-token")
	_, err = c.BootstrapSystem(context.Background(), &BootstrapRequest{
		Username: "admin", Email: "admin@example.com", Password: "BootstrapPass123!", DisplayName: "Admin",
		Token: "test-bootstrap-token",
	})
	require.NoError(t, err)
	return c, st
}

// seedUserWithRole creates a fresh user and assigns it roleName at the given
// scope, bypassing core.CreateUser so no default role is attached.
func seedUserWithRole(t *testing.T, st *store.LocalStorage, username, roleName string, scope storage.Scope) uint {
	t.Helper()
	ctx := context.Background()
	u, err := st.CreateUser(ctx, &models.User{Username: username, Email: username + "@example.com", IsActive: true})
	require.NoError(t, err)
	role, err := st.GetRoleByName(ctx, roleName)
	require.NoErrorf(t, err, "role %s must be seeded", roleName)
	require.NoError(t, st.AssignRole(ctx, u.ID, role.ID, scope))
	return u.ID
}

// BootstrapSystem must seed the legacy roles plus the ADR-021 two-tier catalog.
func TestBootstrapSeedsTwoTierRoleCatalog(t *testing.T) {
	c, _ := newBootstrappedCore(t)
	ctx := context.Background()

	for _, name := range []string{
		"admin", "editor", "viewer",
		"system_admin", "system_auditor", "system_viewer",
		"project_admin", "project_developer", "project_viewer", "project_auditor",
	} {
		role, err := c.storage.GetRoleByName(ctx, name)
		require.NoErrorf(t, err, "role %q should be seeded", name)
		assert.Equal(t, name, role.Name)
	}
}

// #227: system.write's catalog description must name its full real footprint —
// audit checkpoints/alerts, legal holds, risk exceptions, SoD policies, and
// admin job triggers — not just the legacy service-account/API-token routes
// (removed as dead code by finding #131). A misleading description here is an
// informed-consent gap for whoever grants this permission on a custom role.
func TestSystemWritePermissionDescriptionMatchesFullFootprint(t *testing.T) {
	for _, def := range defaultPermissions {
		if def.Name != "system.write" {
			continue
		}
		assert.Equal(t, "Manage audit checkpoints/alerts, legal holds, risk exceptions, SoD policies, and admin job triggers", def.Description)
		return
	}
	t.Fatal("system.write not found in defaultPermissions")
}

// Authorize must honour the two-tier scope semantics on the sentinel model:
// system roles assigned globally apply install-wide, project roles apply only
// within their project, and *_admin roles bypass the per-permission check at the
// scope they hold.
func TestAuthorizeTwoTierScopes(t *testing.T) {
	c, st := newBootstrappedCore(t)
	ctx := context.Background()
	const projA, projB = uint(10), uint(20)

	sysAdmin := seedUserWithRole(t, st, "sysadmin", "system_admin", storage.Scope{})
	projAdminA := seedUserWithRole(t, st, "padmin", "project_admin", storage.Scope{ProjectID: projA})
	devA := seedUserWithRole(t, st, "dev", "project_developer", storage.Scope{ProjectID: projA})
	viewerA := seedUserWithRole(t, st, "pviewer", "project_viewer", storage.Scope{ProjectID: projA})
	sysViewer := seedUserWithRole(t, st, "sysviewer", "system_viewer", storage.Scope{})

	allow := func(uid uint, perm string, s storage.Scope) bool {
		ok, err := c.Authorize(ctx, uid, perm, s)
		require.NoError(t, err)
		return ok
	}

	// system_admin (global) bypasses everywhere.
	assert.True(t, allow(sysAdmin, "secrets.write", storage.Scope{ProjectID: projB}),
		"system_admin should bypass in any project")

	// project_admin bypasses within its project, but has nothing in another.
	assert.True(t, allow(projAdminA, "secrets.delete", storage.Scope{ProjectID: projA}),
		"project_admin should bypass within its own project")
	assert.False(t, allow(projAdminA, "secrets.read", storage.Scope{ProjectID: projB}),
		"project_admin must not reach another project")

	// project_developer: read/write within its project, denied elsewhere.
	assert.True(t, allow(devA, "secrets.write", storage.Scope{ProjectID: projA}))
	assert.False(t, allow(devA, "secrets.write", storage.Scope{ProjectID: projB}))

	// project_viewer: read yes, write no, within its project.
	assert.True(t, allow(viewerA, "secrets.read", storage.Scope{ProjectID: projA}))
	assert.False(t, allow(viewerA, "secrets.write", storage.Scope{ProjectID: projA}))

	// system_viewer is a minimal install baseline: system.read but no secrets.
	assert.True(t, allow(sysViewer, "system.read", storage.Scope{ProjectID: projA}))
	assert.False(t, allow(sysViewer, "secrets.read", storage.Scope{ProjectID: projA}),
		"system_viewer must not grant secret access by itself")
}
