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

func newUserStore(t *testing.T) *LocalStorage {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.User{}))
	return NewLocalStorage(db)
}

func TestListUsersInStateBefore(t *testing.T) {
	ctx := context.Background()
	ls := newUserStore(t)
	now := time.Now().UTC()

	mk := func(username, state string, createdAt time.Time) {
		t.Helper()
		u := &models.User{Username: username, Email: username + "@x.com", AccountState: state}
		_, err := ls.CreateUser(ctx, u)
		require.NoError(t, err)
		// CreateUser stamps created_at; force it for the cutoff assertions.
		require.NoError(t, ls.db.WithContext(ctx).Model(&models.User{}).
			Where("username = ?", username).UpdateColumn("created_at", createdAt).Error)
	}

	mk("old-pending", "pending_first_login", now.Add(-10*24*time.Hour))   // stale
	mk("new-pending", "pending_first_login", now.Add(-1*24*time.Hour))    // too recent
	mk("old-active", "active", now.Add(-10*24*time.Hour))                 // wrong state
	mk("old-reset", "password_reset_required", now.Add(-10*24*time.Hour)) // other state

	cutoff := now.Add(-7 * 24 * time.Hour)

	pending, err := ls.ListUsersInStateBefore(ctx, "pending_first_login", cutoff)
	require.NoError(t, err)
	require.Len(t, pending, 1, "only the >7d pending account is stale")
	assert.Equal(t, "old-pending", pending[0].Username)

	reset, err := ls.ListUsersInStateBefore(ctx, "password_reset_required", cutoff)
	require.NoError(t, err)
	require.Len(t, reset, 1)
	assert.Equal(t, "old-reset", reset[0].Username)
}
