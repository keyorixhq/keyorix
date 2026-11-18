package core_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// seedActiveActors creates an active user row for each id that has none. Core
// refuses a mutation by an actor whose account is missing or not active (#4159), so
// a fixture that acts as these IDs through a mutating core method needs the rows.
func seedActiveActors(t *testing.T, db *gorm.DB, ids ...uint) {
	t.Helper()
	require.NoError(t, db.AutoMigrate(&models.User{}))
	for _, id := range ids {
		var n int64
		require.NoError(t, db.Model(&models.User{}).Where("id = ?", id).Count(&n).Error)
		if n > 0 {
			continue
		}
		name := fmt.Sprintf("fixture-actor-%d", id)
		require.NoError(t, db.Create(&models.User{
			ID: id, Username: name, UsernameFolded: name, Email: name + "@example.test", EmailFolded: name + "@example.test",
			IsActive: true, AccountState: core.AccountActive,
		}).Error)
	}
}

// reviewerIDs is n consecutive actor IDs starting at first.
func reviewerIDs(first uint, n int) []uint {
	ids := make([]uint, n)
	for i := range ids {
		ids[i] = first + uint(i)
	}
	return ids
}
