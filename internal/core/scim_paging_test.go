package core

import (
	"context"
	"fmt"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// ListSCIMUsersPage returns a bounded window (clamped to SCIMMaxPageSize) plus the true
// total, honouring the 1-based startIndex — so an unfiltered SCIM list can't drain the
// whole directory into one response.
func TestListSCIMUsersPage(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.User{}))
	c := NewKeyorixCore(store.NewLocalStorage(db))
	ctx := context.Background()

	// #G85: ListSCIMUsersPage now filters to scimManaged (ExternalID != "") users
	// only, matching the boundary UpdateSCIMUser/DeprovisionSCIMUser already
	// enforce — see TestListSCIMUsersPage_ExcludesNonSCIMManaged below for that
	// filtering behavior itself. This fixture sets a stored externalId on every
	// seeded user so it continues to exercise pagination/windowing mechanics
	// (this test's actual concern) against a realistic, SCIM-managed directory.
	const n = 25
	for i := 1; i <= n; i++ {
		require.NoError(t, db.Create(&models.User{ID: uint(i), Username: fmt.Sprintf("u%02d", i), Email: fmt.Sprintf("u%02d@x.io", i), ExternalID: fmt.Sprintf("ext-%02d", i)}).Error)
	}

	t.Run("count is clamped to the max page size", func(t *testing.T) {
		users, total, err := c.ListSCIMUsersPage(ctx, 1, 10_000)
		require.NoError(t, err)
		assert.Equal(t, n, total, "total reflects the whole directory")
		assert.LessOrEqual(t, len(users), SCIMMaxPageSize, "returned window is clamped")
		assert.Len(t, users, n) // n < max, so all returned in this case
	})

	t.Run("startIndex + count select a window", func(t *testing.T) {
		users, total, err := c.ListSCIMUsersPage(ctx, 11, 5)
		require.NoError(t, err)
		assert.Equal(t, n, total)
		require.Len(t, users, 5)
		assert.Equal(t, "u11", users[0].Username, "1-based startIndex 11 → 11th user")
	})

	t.Run("count zero returns the total only", func(t *testing.T) {
		users, total, err := c.ListSCIMUsersPage(ctx, 1, 0)
		require.NoError(t, err)
		assert.Equal(t, n, total)
		assert.Empty(t, users)
	})
}

// TestListSCIMUsersPage_ExcludesNonSCIMManaged pins #G85: ListSCIMUsersPage
// previously queried storage.ListUsers with no scimManaged filter at all, so an
// unfiltered SCIM directory listing enumerated EVERY user account — native
// (non-SCIM-managed) accounts included — not just the ones actually under SCIM
// control, unlike UpdateSCIMUser/DeprovisionSCIMUser which already refuse a
// non-SCIM-managed target (#120). Seeds a mix of SCIM-managed (stored externalId)
// and native (no externalId) users and asserts both the returned page AND the
// total/count reflect only the SCIM-managed subset.
func TestListSCIMUsersPage_ExcludesNonSCIMManaged(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.User{}))
	c := NewKeyorixCore(store.NewLocalStorage(db))
	ctx := context.Background()

	require.NoError(t, db.Create(&models.User{ID: 1, Username: "managed1", Email: "managed1@x.io", ExternalID: "okta-1"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "managed2", Email: "managed2@x.io", ExternalID: "okta-2"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 3, Username: "native1", Email: "native1@x.io"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 4, Username: "native2", Email: "native2@x.io"}).Error)

	users, total, err := c.ListSCIMUsersPage(ctx, 1, 200)
	require.NoError(t, err)
	assert.Equal(t, 2, total, "totalResults must count only the SCIM-managed users, not the full 4-user directory")
	require.Len(t, users, 2, "only the SCIM-managed users may be returned")
	for _, u := range users {
		assert.NotEmpty(t, u.ExternalID, "every returned user must be SCIM-managed")
		assert.NotContains(t, []string{"native1", "native2"}, u.Username, "a native account must never appear in a SCIM listing")
	}
}
