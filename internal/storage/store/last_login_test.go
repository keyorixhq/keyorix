package store

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func newUserTestStore(t *testing.T) *LocalStorage {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.User{}))
	return NewLocalStorage(db)
}

func TestUpdateLastLogin(t *testing.T) {
	ctx := context.Background()
	ls := newUserTestStore(t)

	u, err := ls.CreateUser(ctx, &models.User{Username: "alice", UsernameFolded: "alice", Email: "a@x.io", EmailFolded: "a@x.io"})
	require.NoError(t, err)
	require.Nil(t, u.LastLoginAt, "new user has never logged in")

	before := u.UpdatedAt
	loginAt := time.Now().UTC().Truncate(time.Second)
	require.NoError(t, ls.UpdateLastLogin(ctx, u.ID, loginAt))

	got, err := ls.GetUser(ctx, u.ID)
	require.NoError(t, err)
	require.NotNil(t, got.LastLoginAt)
	assert.True(t, got.LastLoginAt.Equal(loginAt), "last_login_at should be stamped")
	assert.Equal(t, before.UTC(), got.UpdatedAt.UTC(), "updated_at must not be bumped by a login stamp")
}

func TestListUsersInactiveSince(t *testing.T) {
	ctx := context.Background()
	ls := newUserTestStore(t)
	now := time.Now().UTC()

	// never logged in → inactive
	_, err := ls.CreateUser(ctx, &models.User{Username: "never", UsernameFolded: "never", Email: "n@x.io", EmailFolded: "n@x.io"})
	require.NoError(t, err)
	// logged in 40 days ago → inactive
	stale, err := ls.CreateUser(ctx, &models.User{Username: "stale", UsernameFolded: "stale", Email: "s@x.io", EmailFolded: "s@x.io"})
	require.NoError(t, err)
	require.NoError(t, ls.UpdateLastLogin(ctx, stale.ID, now.Add(-40*24*time.Hour)))
	// logged in yesterday → active
	fresh, err := ls.CreateUser(ctx, &models.User{Username: "fresh", UsernameFolded: "fresh", Email: "f@x.io", EmailFolded: "f@x.io"})
	require.NoError(t, err)
	require.NoError(t, ls.UpdateLastLogin(ctx, fresh.ID, now.Add(-24*time.Hour)))

	cutoff := now.Add(-30 * 24 * time.Hour)
	users, total, err := ls.ListUsers(ctx, &storage.UserFilter{InactiveSince: &cutoff, Page: 1, PageSize: 20})
	require.NoError(t, err)
	assert.Equal(t, int64(2), total, "never + stale are inactive; fresh is not")

	names := map[string]bool{}
	for _, u := range users {
		names[u.Username] = true
	}
	assert.True(t, names["never"])
	assert.True(t, names["stale"])
	assert.False(t, names["fresh"])
}
