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

func newUserTestStore(t *testing.T) *LocalStorage {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
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
