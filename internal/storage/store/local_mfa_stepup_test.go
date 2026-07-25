package store

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func newStepupStore(t *testing.T) *LocalStorage {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.MFAStepupToken{}))
	return NewLocalStorage(db)
}

func TestUpsertMFAStepupToken_InsertsNewRow(t *testing.T) {
	s := newStepupStore(t)
	ctx := context.Background()
	exp := time.Now().Add(5 * time.Minute)

	require.NoError(t, s.UpsertMFAStepupToken(ctx, 1, exp))

	var tok models.MFAStepupToken
	require.NoError(t, s.db.First(&tok).Error)
	assert.Equal(t, uint(1), tok.UserID)
	assert.WithinDuration(t, exp, tok.ExpiresAt, time.Second)
}

func TestUpsertMFAStepupToken_UpdatesExistingRow(t *testing.T) {
	s := newStepupStore(t)
	ctx := context.Background()
	first := time.Now().Add(2 * time.Minute)
	second := time.Now().Add(10 * time.Minute)

	require.NoError(t, s.UpsertMFAStepupToken(ctx, 2, first))
	require.NoError(t, s.UpsertMFAStepupToken(ctx, 2, second))

	var count int64
	s.db.Model(&models.MFAStepupToken{}).Count(&count)
	assert.Equal(t, int64(1), count, "upsert must not create a second row")

	var tok models.MFAStepupToken
	require.NoError(t, s.db.First(&tok).Error)
	assert.WithinDuration(t, second, tok.ExpiresAt, time.Second)
}

func TestHasActiveMFAStepup_TrueWhenNotExpired(t *testing.T) {
	s := newStepupStore(t)
	ctx := context.Background()
	exp := time.Now().Add(5 * time.Minute)

	require.NoError(t, s.UpsertMFAStepupToken(ctx, 3, exp))

	ok, err := s.HasActiveMFAStepup(ctx, 3)
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestHasActiveMFAStepup_FalseWhenExpired(t *testing.T) {
	s := newStepupStore(t)
	ctx := context.Background()
	exp := time.Now().Add(-1 * time.Minute)

	require.NoError(t, s.UpsertMFAStepupToken(ctx, 4, exp))

	ok, err := s.HasActiveMFAStepup(ctx, 4)
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestHasActiveMFAStepup_FalseWhenNoRecord(t *testing.T) {
	s := newStepupStore(t)
	ctx := context.Background()

	ok, err := s.HasActiveMFAStepup(ctx, 99)
	require.NoError(t, err)
	assert.False(t, ok)
}
