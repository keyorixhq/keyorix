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

	const n = 25
	for i := 1; i <= n; i++ {
		require.NoError(t, db.Create(&models.User{ID: uint(i), Username: fmt.Sprintf("u%02d", i), Email: fmt.Sprintf("u%02d@x.io", i)}).Error)
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
