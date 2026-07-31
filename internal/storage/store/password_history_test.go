package store

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func newPasswordHistoryStore(t *testing.T) *LocalStorage {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.PasswordHistory{}))
	return NewLocalStorage(db)
}

// AddPasswordHistory + RecentPasswordHashes return newest-first; PrunePasswordHistory
// keeps only the newest N rows for the user.
func TestPasswordHistory_RecentAndPrune(t *testing.T) {
	ctx := context.Background()
	ls := newPasswordHistoryStore(t)
	base := time.Date(2026, 6, 4, 9, 0, 0, 0, time.UTC)

	// Insert 4 hashes for user 1 at increasing times, plus one for user 2.
	for i, h := range []string{"h1", "h2", "h3", "h4"} {
		require.NoError(t, ls.AddPasswordHistory(ctx, 1, h, base.Add(time.Duration(i)*time.Minute)))
	}
	require.NoError(t, ls.AddPasswordHistory(ctx, 2, "other", base))

	// Newest-first, limited to 2.
	recent, err := ls.RecentPasswordHashes(ctx, 1, 2)
	require.NoError(t, err)
	assert.Equal(t, []string{"h4", "h3"}, recent)

	// Prune to the newest 2; h1/h2 go.
	require.NoError(t, ls.PrunePasswordHistory(ctx, 1, 2))
	all, err := ls.RecentPasswordHashes(ctx, 1, 10)
	require.NoError(t, err)
	assert.Equal(t, []string{"h4", "h3"}, all)

	// User 2's row is untouched.
	other, err := ls.RecentPasswordHashes(ctx, 2, 10)
	require.NoError(t, err)
	assert.Equal(t, []string{"other"}, other)
}

func TestRecentPasswordHashes_ZeroLimit(t *testing.T) {
	ctx := context.Background()
	ls := newPasswordHistoryStore(t)
	require.NoError(t, ls.AddPasswordHistory(ctx, 1, "h1", time.Now()))
	got, err := ls.RecentPasswordHashes(ctx, 1, 0)
	require.NoError(t, err)
	assert.Empty(t, got)
}
