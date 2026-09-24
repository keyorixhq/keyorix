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
	"github.com/keyorixhq/keyorix/internal/identity"
	kxstorage "github.com/keyorixhq/keyorix/internal/storage"
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
	// A plain ":memory:" DSN gives every pooled connection its own separate,
	// empty database -- cap the pool at 1 so migration and every later query
	// share the single connection that actually has the schema (see
	// internal/testutil/fuzzworld.OpenSQLite for the same constraint).
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, kxstorage.MigrateExisting(db))

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

// sqliteTableNames returns every user table name (sqlite_% internal tables
// excluded) present in db.
func sqliteTableNames(t *testing.T, db *gorm.DB) []string {
	t.Helper()
	var names []string
	require.NoError(t, db.Raw(
		"SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
	).Scan(&names).Error)
	return names
}

// TestNewBootstrappedCore_SchemaMatchesProductionMigration guards against
// newBootstrappedCore's schema silently drifting from what production
// actually creates -- the failure mode that let it lack the notifications
// table (and others) for as long as it did with a hand-picked AutoMigrate
// list nobody re-diffed against migrateDatabase. newBootstrappedCore now
// delegates to kxstorage.MigrateExisting directly, so this test only fails
// if a future edit reintroduces a hand-picked list or otherwise diverges --
// exactly the case that must fail loudly instead of being swallowed.
func TestNewBootstrappedCore_SchemaMatchesProductionMigration(t *testing.T) {
	_, st := newBootstrappedCore(t)
	got := sqliteTableNames(t, st.DB())

	prodDB, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, kxstorage.MigrateExisting(prodDB))
	want := sqliteTableNames(t, prodDB)

	assert.ElementsMatch(t, want, got,
		"newBootstrappedCore's table set must match production's migration (kxstorage.MigrateExisting) exactly")
}

// seedUserWithRole creates a fresh user and assigns it roleName at the given
// scope, bypassing core.CreateUser so no default role is attached.
func seedUserWithRole(t *testing.T, st *store.LocalStorage, username, roleName string, scope storage.Scope) uint {
	t.Helper()
	ctx := context.Background()
	u, err := st.CreateUser(ctx, foldedTestUser(t, username, username+"@example.com"))
	require.NoError(t, err)
	role, err := st.GetRoleByName(ctx, roleName)
	require.NoErrorf(t, err, "role %s must be seeded", roleName)
	require.NoError(t, st.AssignRole(ctx, u.ID, role.ID, scope))
	return u.ID
}

// foldedTestUser builds a models.User with UsernameFolded/EmailFolded
// populated the same way core.CreateUser does (internal/core/users.go), for
// fixtures that call st.CreateUser directly instead of going through
// core.CreateUser. Without this, every such user gets an empty EmailFolded
// and collides with any other bypass-created active user under the real
// production schema's partial unique index uniq_users_email_folded_active
// (#117) -- invisible before newBootstrappedCore built its schema from a
// hand-picked AutoMigrate list that never created this index.
func foldedTestUser(t *testing.T, username, email string) *models.User {
	t.Helper()
	foldedUsername, err := identity.NewFoldedName(username)
	require.NoError(t, err)
	foldedEmail, err := identity.NewFoldedName(email)
	require.NoError(t, err)
	return &models.User{
		Username:       username,
		UsernameFolded: foldedUsername.Folded(),
		Email:          email,
		EmailFolded:    foldedEmail.Folded(),
		IsActive:       true,
	}
}

// BootstrapSystem must seed the legacy roles plus the ADR-021 two-tier catalog.
func TestBootstrapSeedsTwoTierRoleCatalog(t *testing.T) {
	t.Parallel()
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

// TestBootstrapGrantsConnectPlatformUseToAdminRoles proves a fresh install's
// seeded admin/system_admin roles hold connect.platform.use (ADR-082 branch 4)
// via ordinary BootstrapSystem seeding — no reconcile pass needed on first
// boot. Roles without connect.read at all (editor/viewer/etc.) must not hold
// it either (least privilege — mirrors connect.read's own baseline).
func TestBootstrapGrantsConnectPlatformUseToAdminRoles(t *testing.T) {
	t.Parallel()
	c, _ := newBootstrappedCore(t)
	ctx := context.Background()

	for _, name := range []string{"admin", "system_admin"} {
		role, err := c.storage.GetRoleByName(ctx, name)
		require.NoError(t, err)
		perms, err := c.storage.GetRolePermissions(ctx, role.ID)
		require.NoError(t, err)
		var has bool
		for _, p := range perms {
			if p.Name == "connect.platform.use" {
				has = true
			}
		}
		assert.Truef(t, has, "role %q must hold connect.platform.use on a fresh install", name)
	}

	for _, name := range []string{"editor", "viewer", "system_auditor", "system_viewer", "project_admin"} {
		role, err := c.storage.GetRoleByName(ctx, name)
		require.NoError(t, err)
		perms, err := c.storage.GetRolePermissions(ctx, role.ID)
		require.NoError(t, err)
		for _, p := range perms {
			assert.NotEqualf(t, "connect.platform.use", p.Name, "role %q must not hold connect.platform.use (least privilege — it doesn't hold connect.read either)", name)
		}
	}
}

// #227: system.write's catalog description must name its full real footprint —
// audit checkpoints/alerts, legal holds, risk exceptions, SoD policies, and
// admin job triggers — not just the legacy service-account/API-token routes
// (removed as dead code by finding #131). A misleading description here is an
// informed-consent gap for whoever grants this permission on a custom role.
func TestSystemWritePermissionDescriptionMatchesFullFootprint(t *testing.T) {
	t.Parallel()
	for _, def := range defaultPermissions {
		if def.Name != "system.write" {
			continue
		}
		assert.Equal(t, "Manage audit checkpoints/alerts, legal holds, risk exceptions, SoD policies, and admin job triggers -- also the blanket gate on the entire /api/v1/system RemoteStorage-proxy route tree", def.Description)
		return
	}
	t.Fatal("system.write not found in defaultPermissions")
}

// Authorize must honour the two-tier scope semantics on the sentinel model:
// system roles assigned globally apply install-wide, project roles apply only
// within their project, and *_admin roles bypass the per-permission check at the
// scope they hold.
func TestAuthorizeTwoTierScopes(t *testing.T) {
	t.Parallel()
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
