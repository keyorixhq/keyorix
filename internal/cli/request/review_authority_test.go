// review_authority_test.go — regression coverage for #491 (sibling of #264):
// the --by actor for `keyorix request review` must actually hold the
// authority the equivalent HTTP route requires (roles.assign scoped to the
// project), not merely resolve to SOME user record.
package request

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

// newTestRequestCore spins up an in-memory store, runs the production
// BootstrapSystem (seeding the real RBAC role/permission catalog), and returns
// the core + storage for authority assertions — mirrors
// migrate.newTestMigrateCore (internal/cli/migrate/user_to_machine_authority_test.go),
// reimplemented here since that helper is unexported to this package.
func newTestRequestCore(t *testing.T) (*core.KeyorixCore, *store.LocalStorage) {
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

// #491 (sibling of #264): an actor holding only a read-only project role (no
// roles.assign) must be refused — the CLI must not let --by attribute this
// approval/rejection to an unprivileged account.
func TestRequireReviewAuthority_UnprivilegedActorRejected(t *testing.T) {
	c, st := newTestRequestCore(t)
	ctx := context.Background()
	actor := seedUserWithRole(t, st, "review-viewer", "project_viewer", core.Scope{ProjectID: 1})

	err := requireReviewAuthority(ctx, c, actor, 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "roles.assign")
}

// #491 positive control: an actor holding roles.assign at the project (the
// equivalent HTTP route's requirement) must be allowed through.
func TestRequireReviewAuthority_AuthorizedActorAllowed(t *testing.T) {
	c, st := newTestRequestCore(t)
	ctx := context.Background()
	actor := seedUserWithRole(t, st, "review-admin", "project_admin", core.Scope{ProjectID: 1})

	require.NoError(t, requireReviewAuthority(ctx, c, actor, 1))
}

// #491 positive control: the bootstrap admin created by BootstrapSystem itself
// (the realistic legitimate --by actor for this command) must pass too.
func TestRequireReviewAuthority_BootstrapAdminAllowed(t *testing.T) {
	c, st := newTestRequestCore(t)
	ctx := context.Background()
	bootstrapAdmin, err := st.GetUserByEmail(ctx, "admin@example.com")
	require.NoError(t, err)

	require.NoError(t, requireReviewAuthority(ctx, c, bootstrapAdmin.ID, 1))
}
