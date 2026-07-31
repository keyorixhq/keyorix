package store

import (
	"context"
	"errors"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func newTxStore(t *testing.T) *LocalStorage {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	// One connection so the tx commit and the follow-up read share the same in-memory DB.
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.User{}))
	return NewLocalStorage(db)
}

func TestLocalStorage_WithTransaction_CommitsOnSuccess(t *testing.T) {
	ls := newTxStore(t)
	ctx := context.Background()

	err := ls.WithTransaction(ctx, func(tx storage.Storage) error {
		_, e := tx.CreateUser(ctx, &models.User{Username: "alice", Email: "a@x.io"})
		return e
	})
	require.NoError(t, err)

	got, err := ls.GetUserByUsername(ctx, "alice")
	require.NoError(t, err)
	assert.Equal(t, "alice", got.Username)
}

func TestLocalStorage_WithTransaction_RollsBackOnError(t *testing.T) {
	ls := newTxStore(t)
	ctx := context.Background()
	sentinel := errors.New("boom")

	err := ls.WithTransaction(ctx, func(tx storage.Storage) error {
		if _, e := tx.CreateUser(ctx, &models.User{Username: "bob", Email: "b@x.io"}); e != nil {
			return e
		}
		// The insert above must be rolled back when fn returns an error.
		return sentinel
	})
	require.ErrorIs(t, err, sentinel)

	_, err = ls.GetUserByUsername(ctx, "bob")
	require.Error(t, err, "bob must not exist after a rolled-back transaction")
}
