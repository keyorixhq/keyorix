package store

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
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

// TestSSOLoginState_ConsumeIsAtomicUnderConcurrency pins #95: ConsumeSSOLoginState
// used to be a check-then-delete (SELECT then DELETE-by-ID), so two concurrent SSO
// callbacks racing the SAME state token could both pass the SELECT before either
// completed the DELETE — both minting a session from a single-use login state.
// Firing many concurrent consumers at one state must yield exactly one winner.
func TestSSOLoginState_ConsumeIsAtomicUnderConcurrency(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	require.NoError(t, err)
	db.Exec("PRAGMA journal_mode=WAL")
	require.NoError(t, db.AutoMigrate(&models.SSOLoginState{}))
	ls := NewLocalStorage(db)
	ctx := context.Background()

	require.NoError(t, ls.CreateSSOLoginState(ctx, &models.SSOLoginState{
		State: "race-1", Nonce: "n-1", Provider: "okta", ExpiresAt: time.Now().Add(10 * time.Minute),
	}))

	const attempts = 20
	results := make(chan error, attempts)
	var wg sync.WaitGroup
	wg.Add(attempts)
	for i := 0; i < attempts; i++ {
		go func() {
			defer wg.Done()
			_, err := ls.ConsumeSSOLoginState(ctx, "race-1")
			results <- err
		}()
	}
	wg.Wait()
	close(results)

	successes := 0
	for err := range results {
		if err == nil {
			successes++
		}
	}
	assert.Equal(t, 1, successes, "exactly one concurrent consumer must win the single-use state")
}
