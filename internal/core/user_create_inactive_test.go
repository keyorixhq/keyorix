// user_create_inactive_test.go: an account created inactive must be STORED
// inactive. models.User.IsActive carries `gorm:"default:true"`, and GORM's
// Create skips a zero-valued field that has a default, so a plain
// db.Create(&User{IsActive: false}) wrote is_active=true. SCIM provisioning
// with active=false was masked by account_state=deprovisioned (login stayed
// refused), but is_active was wrong in every list, export and SCIM GET. The
// admin create path (CreateUser, CreateUserWithAssignments) with
// is_active=false had the same defect. These tests read the column back.
package core

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const inactiveTestPassword = "Tr1ckyHorseStaple-9!Zq"

func runCreateInactiveSuite(t *testing.T, c *KeyorixCore) {
	seedDefaultCatalog(t, c)
	ctx := context.Background()

	storedActive := func(t *testing.T, id uint) bool {
		t.Helper()
		u, err := c.storage.GetUser(ctx, id)
		require.NoError(t, err)
		return u.IsActive
	}

	t.Run("scim provision active=false stores is_active=false", func(t *testing.T) {
		u, err := c.ProvisionSCIMUser(ctx, 0, "scim-off", "Scim Off", "scim-off@x.io", "ext-scim-off", false)
		require.NoError(t, err)
		require.Equal(t, AccountDeprovisioned, accountStateOf(t, c, u.ID), "premise: state already fails login closed")
		assert.False(t, u.IsActive, "the returned user")
		assert.False(t, storedActive(t, u.ID), "the stored column")

		got, err := c.GetSCIMUser(ctx, u.ID)
		require.NoError(t, err)
		assert.False(t, got.IsActive, "SCIM GET")
		listed, err := c.ListSCIMUsers(ctx)
		require.NoError(t, err)
		var found bool
		for _, l := range listed {
			if l.ID == u.ID {
				found = true
				assert.False(t, l.IsActive, "SCIM list")
			}
		}
		assert.True(t, found, "provisioned user is listed")
	})

	t.Run("scim provision active=true stays active", func(t *testing.T) {
		u, err := c.ProvisionSCIMUser(ctx, 0, "scim-on", "Scim On", "scim-on@x.io", "ext-scim-on", true)
		require.NoError(t, err)
		assert.True(t, storedActive(t, u.ID))
	})

	t.Run("admin CreateUser is_active=false stores is_active=false", func(t *testing.T) {
		off := false
		u, err := c.CreateUser(ctx, &CreateUserRequest{
			Username: "admin-off", Email: "admin-off@x.io", Password: inactiveTestPassword,
			DisplayName: "Admin Off", IsActive: &off,
		})
		require.NoError(t, err)
		assert.False(t, storedActive(t, u.ID))
	})

	t.Run("admin CreateUser default and explicit true stay active", func(t *testing.T) {
		on := true
		d, err := c.CreateUser(ctx, &CreateUserRequest{
			Username: "admin-def", Email: "admin-def@x.io", Password: inactiveTestPassword, DisplayName: "Admin Def",
		})
		require.NoError(t, err)
		assert.True(t, storedActive(t, d.ID))
		e, err := c.CreateUser(ctx, &CreateUserRequest{
			Username: "admin-on", Email: "admin-on@x.io", Password: inactiveTestPassword,
			DisplayName: "Admin On", IsActive: &on,
		})
		require.NoError(t, err)
		assert.True(t, storedActive(t, e.ID))
	})

	t.Run("CreateUserWithAssignments is_active=false stores is_active=false", func(t *testing.T) {
		off := false
		u, err := c.CreateUserWithAssignments(ctx, &CreateUserRequest{
			Username: "assign-off", Email: "assign-off@x.io", Password: inactiveTestPassword,
			DisplayName: "Assign Off", IsActive: &off,
		}, "system_viewer", nil, 0, false)
		require.NoError(t, err)
		assert.False(t, storedActive(t, u.ID))
	})
}

func TestCreateUserInactive_StoredColumn(t *testing.T) {
	runCreateInactiveSuite(t, newPreFixOrderingCore(t))
}

func TestCreateUserInactive_StoredColumn_Postgres(t *testing.T) {
	base := pgTestDSN(t)
	db := pgOpen(t, pgMigratedDatabaseDSN(t, base))
	require.NoError(t, i18n.Initialize(&config.Config{
		Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
	}))
	runCreateInactiveSuite(t, NewKeyorixCore(store.NewLocalStorage(db)))
}
