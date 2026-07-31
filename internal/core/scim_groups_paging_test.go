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

// ListSCIMGroupsPage returns a bounded window (clamped to SCIMMaxPageSize) plus the
// true total, honouring the 1-based startIndex, and is backed by an offset-limited
// storage query — so an unfiltered SCIM Groups list can't drain the whole groups
// table into memory the way the plain ListGroups full-scan does.
func TestListSCIMGroupsPage(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.Group{}))
	c := NewKeyorixCore(store.NewLocalStorage(db))
	ctx := context.Background()

	const n = 25
	for i := 1; i <= n; i++ {
		require.NoError(t, db.Create(&models.Group{ID: uint(i), Name: fmt.Sprintf("g%02d", i)}).Error)
	}

	t.Run("count is clamped to the max page size", func(t *testing.T) {
		groups, total, err := c.ListSCIMGroupsPage(ctx, 1, 10_000)
		require.NoError(t, err)
		assert.Equal(t, n, total, "total reflects the whole directory")
		assert.LessOrEqual(t, len(groups), SCIMMaxPageSize, "returned window is clamped")
		assert.Len(t, groups, n) // n < max, so all returned in this case
	})

	t.Run("startIndex + count select a window", func(t *testing.T) {
		groups, total, err := c.ListSCIMGroupsPage(ctx, 11, 5)
		require.NoError(t, err)
		assert.Equal(t, n, total)
		require.Len(t, groups, 5)
		assert.Equal(t, "g11", groups[0].Name, "1-based startIndex 11 → 11th group (name-ordered)")
	})

	t.Run("count zero returns the total only", func(t *testing.T) {
		groups, total, err := c.ListSCIMGroupsPage(ctx, 1, 0)
		require.NoError(t, err)
		assert.Equal(t, n, total)
		assert.Empty(t, groups)
	})
}
