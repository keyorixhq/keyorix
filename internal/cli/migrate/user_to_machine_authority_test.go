// user_to_machine_authority_test.go — regression coverage for #264: the --by
// actor for `keyorix migrate user-to-machine` must actually hold the authority
// the equivalent HTTP route requires (roles.assign scoped to the project AND
// users.write globally), not merely resolve to SOME user record.
package migrate

import (
	"context"
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

// newTestMigrateCore spins up an in-memory store, runs the production
// BootstrapSystem (seeding the real RBAC role/permission catalog), and returns
// the core + storage for authority assertions — mirrors core.newBootstrappedCore
// (internal/core/auth_bootstrap_rbac_test.go), reimplemented here since that
// helper is unexported to the core package.
func newTestMigrateCore(t *testing.T) (*core.KeyorixCore, *store.LocalStorage) {
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
		&models.PersonalAccessToken{}, &models.Session{}, &models.AuditEvent{},
	))

	st := store.NewLocalStorage(db)
	c := core.NewKeyorixCore(st)
	c.SetBootstrapToken("test-bootstrap-token")
	_, err = c.BootstrapSystem(context.Background(), &core.BootstrapRequest{
		Username: "admin", Email: "admin@example.com", Password: "BootstrapPass123!", DisplayName: "Admin",
		Token: "test-bootstrap-token",
	})
	require.NoError(t, err)
	return c, st
}

// seedUserWithRole creates a user and assigns roleName at scope, returning the
// new user's ID.
func seedUserWithRole(t *testing.T, st *store.LocalStorage, username, roleName string, scope core.Scope) uint {
	t.Helper()
	ctx := context.Background()
	u, err := st.CreateUser(ctx, &models.User{Username: username, Email: username + "@example.com", IsActive: true})
	require.NoError(t, err)
	role, err := st.GetRoleByName(ctx, roleName)
	require.NoErrorf(t, err, "role %s must be seeded", roleName)
	require.NoError(t, st.AssignRole(ctx, u.ID, role.ID, scope))
	return u.ID
}

// #264: an actor holding only a read-only project role (no roles.assign, no
// users.write) must be refused — the CLI must not let --by attribute this
// migration to an unprivileged account.
func TestRequireMigrationAuthority_UnprivilegedActorRejected(t *testing.T) {
	c, st := newTestMigrateCore(t)
	ctx := context.Background()
	actor := seedUserWithRole(t, st, "u2m-viewer", "project_viewer", core.Scope{ProjectID: 1})

	err := requireMigrationAuthority(ctx, c, actor, 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "roles.assign")
}

// #264: an actor holding roles.assign at the project but lacking users.write
// globally must still be refused — the composite operation (create machine
// identity + suspend the source user) needs both, exactly like the HTTP route.
func TestRequireMigrationAuthority_MissingUsersWriteRejected(t *testing.T) {
	c, st := newTestMigrateCore(t)
	ctx := context.Background()
	actor := seedUserWithRole(t, st, "u2m-project-admin", "project_admin", core.Scope{ProjectID: 1})

	err := requireMigrationAuthority(ctx, c, actor, 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "users.write")
}

// #264 positive control: a genuinely authorized actor (holding both
// permissions the HTTP route requires) must still succeed — no regression for
// the legitimate case.
func TestRequireMigrationAuthority_AuthorizedActorAllowed(t *testing.T) {
	c, st := newTestMigrateCore(t)
	ctx := context.Background()
	actor := seedUserWithRole(t, st, "u2m-admin", "admin", core.Scope{})

	require.NoError(t, requireMigrationAuthority(ctx, c, actor, 1))
}

// #264 positive control: the bootstrap admin created by BootstrapSystem itself
// (the realistic legitimate --by actor for this command) must pass too.
func TestRequireMigrationAuthority_BootstrapAdminAllowed(t *testing.T) {
	c, st := newTestMigrateCore(t)
	ctx := context.Background()
	bootstrapAdmin, err := st.GetUserByEmail(ctx, "admin@example.com")
	require.NoError(t, err)

	require.NoError(t, requireMigrationAuthority(ctx, c, bootstrapAdmin.ID, 1))
}
