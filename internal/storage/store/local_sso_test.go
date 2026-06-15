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

func TestSSOLoginState_CreateConsumeIsSingleUse(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.SSOLoginState{}))
	ls := NewLocalStorage(db)
	ctx := context.Background()

	require.NoError(t, ls.CreateSSOLoginState(ctx, &models.SSOLoginState{
		State: "st-1", Nonce: "n-1", Provider: "okta", ExpiresAt: time.Now().Add(10 * time.Minute),
	}))

	got, err := ls.ConsumeSSOLoginState(ctx, "st-1")
	require.NoError(t, err)
	assert.Equal(t, "n-1", got.Nonce)
	assert.Equal(t, "okta", got.Provider)

	// Second consume of the same state fails — it was deleted (no replay).
	_, err = ls.ConsumeSSOLoginState(ctx, "st-1")
	require.Error(t, err)
}
