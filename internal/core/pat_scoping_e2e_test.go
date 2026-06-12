package core

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// newPATScopingCore bootstraps a real core (admin = global admin) with the PAT
// table migrated, for end-to-end ADR-042 assertions against real RBAC.
func newPATScopingCore(t *testing.T) (*KeyorixCore, *store.LocalStorage) {
	t.Helper()
	require.NoError(t, i18n.Initialize(&config.Config{
		Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
	}))
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Role{}, &models.Permission{}, &models.RolePermission{},
		&models.UserRole{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.Project{}, &models.Environment{}, &models.PersonalAccessToken{},
	))
	st := store.NewLocalStorage(db)
	c := NewKeyorixCore(st)
	_, err = c.BootstrapSystem(context.Background(), &BootstrapRequest{
		Username: "admin", Email: "admin@example.com", Password: "password12345", DisplayName: "Admin",
	})
	require.NoError(t, err)
	return c, st
}

// TestPATScoping_EndToEnd_RealRBAC drives the whole ADR-042 vertical against real
// RBAC: create a scoped PAT, resolve it back through ValidatePATToken, then prove
// the restriction bounds even a GLOBAL ADMIN's authorization — the property mocks
// alone can't fully establish because it must survive the real admin bypass.
func TestPATScoping_EndToEnd_RealRBAC(t *testing.T) {
	ctx := context.Background()
	c, st := newPATScopingCore(t)
	admin, err := st.GetUserByUsername(ctx, "admin")
	require.NoError(t, err)
	proj := Scope{ProjectID: 3}

	t.Run("sanity: an unrestricted admin token may write (admin bypass)", func(t *testing.T) {
		ok, err := c.AuthorizePrincipal(ctx, ActorTypeUser, admin.ID, "secrets.write", proj)
		require.NoError(t, err)
		assert.True(t, ok, "the global admin can write everywhere by default")
	})

	t.Run("permission-scoped PAT bounds the admin to read-only", func(t *testing.T) {
		res, err := c.CreateOwnPAT(ctx, admin.ID, "ci-read", nil, []string{"secrets.read"}, 0)
		require.NoError(t, err)

		user, _, restriction, err := c.ValidatePATToken(ctx, res.PlainToken)
		require.NoError(t, err)
		require.Equal(t, admin.ID, user.ID)
		require.NotNil(t, restriction)

		rctx := WithPATRestriction(ctx, restriction)
		readOK, err := c.AuthorizePrincipal(rctx, ActorTypeUser, admin.ID, "secrets.read", proj)
		require.NoError(t, err)
		assert.True(t, readOK, "the listed permission passes")

		writeOK, err := c.AuthorizePrincipal(rctx, ActorTypeUser, admin.ID, "secrets.write", proj)
		require.NoError(t, err)
		assert.False(t, writeOK, "the admin's own token cannot write — the restriction wins over the admin bypass")
	})

	t.Run("project-scoped PAT is confined to its project", func(t *testing.T) {
		res, err := c.CreateOwnPAT(ctx, admin.ID, "ci-proj3", nil, nil, 3)
		require.NoError(t, err)
		_, _, restriction, err := c.ValidatePATToken(ctx, res.PlainToken)
		require.NoError(t, err)
		require.NotNil(t, restriction)
		rctx := WithPATRestriction(ctx, restriction)

		inProject, err := c.AuthorizePrincipal(rctx, ActorTypeUser, admin.ID, "secrets.write", Scope{ProjectID: 3})
		require.NoError(t, err)
		assert.True(t, inProject, "writes within the token's project still flow through the admin bypass")

		otherProject, err := c.AuthorizePrincipal(rctx, ActorTypeUser, admin.ID, "secrets.write", Scope{ProjectID: 4})
		require.NoError(t, err)
		assert.False(t, otherProject, "a project-3 token cannot touch project 4")

		globalScope, err := c.AuthorizePrincipal(rctx, ActorTypeUser, admin.ID, "users.read", Scope{})
		require.NoError(t, err)
		assert.False(t, globalScope, "a project-scoped token is not a system-wide credential")
	})

	t.Run("unrestricted PAT resolves to no restriction and keeps full inheritance", func(t *testing.T) {
		res, err := c.CreateOwnPAT(ctx, admin.ID, "ci-full", nil, nil, 0)
		require.NoError(t, err)
		_, _, restriction, err := c.ValidatePATToken(ctx, res.PlainToken)
		require.NoError(t, err)
		assert.Nil(t, restriction, "no scopes + no project = unrestricted (back-compat)")
	})
}
